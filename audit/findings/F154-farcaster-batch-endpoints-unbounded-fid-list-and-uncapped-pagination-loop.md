---
id: F154
task: H154
attack_class: untrusted-input-ingress
severity: high
status: draft
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
file_paths:
  - code/hypersnap/src/api/http.rs
related_findings:
  - id: F157
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-05-23T00:00:00Z
---

# F154 — Farcaster v2 batch endpoints: unbounded `fids` array + uncapped pagination loop = asymmetric remote DoS

- Hunt task: H154
- Attack class: untrusted-input-ingress
- Specialist: http-api (api/http.rs scope)
- Severity (draft): High — anonymous, remote, single-request CPU+memory+IO amplification on the public read API
- Status: draft

## Summary

`ApiHttpHandler` exposes six `POST /v2/farcaster/batch/*` endpoints that
deserialize a JSON body of the shape `{ "fids": [u64, u64, ...] }` and
fan the request out to per-FID hub/index queries. The deserializer
applies **no upper bound on the length of `fids`**, and four of the
six endpoints walk RocksDB with **no cap on the work performed per
FID**:

- `/v2/farcaster/batch/cast-interactions` and `/v2/farcaster/batch/cast-bodies`
  run an **unbounded `loop { hub.get_casts_by_fid(fid, 500, page_token, …)
  .await }`** that exhausts every cast in the FID's history before
  moving to the next FID, accumulating one `serde_json::Value` per
  cast in a single per-FID `Vec`, all of which are inserted into a
  single `HashMap` that is JSON-encoded into one monolithic response.
- `/v2/farcaster/batch/following` calls `get_following_with_timestamps(
  fid, None, 10_000)` per FID — 10 000 entries × N FIDs.
- `/v2/farcaster/batch/reactions` calls `get_reactions_by_fid(fid, None,
  10_000)` per FID — same shape.

The `parse_batch_fids` deserializer is a plain `serde_json::from_slice::
<BatchRequest>(body)`; there is no `#[serde(deserialize_with=…)]`
length guard, no post-parse `if fids.len() > MAX { reject }` check,
and the inbound body buffer is itself unbounded (F030 prior art).
Combined with the per-FID amplification, a single accepted request
trivially drives multi-second / multi-minute CPU + multi-GB RocksDB
iteration + multi-100MB heap on the server. The endpoint is
unauthenticated and reachable over the public CORS=`*` Farcaster v2
read API.

This is orthogonal to F030 (byte-count buffer DoS) and F031 (per-IP
rate limiting). Even with both of those fixes in place — a 1 MiB
body cap and a 10 req/s/IP rate limiter — a single accepted body
under the cap still pulls millions of RocksDB records and gigabytes
of memory per request.

## Affected sites

File: `code/hypersnap/src/api/http.rs`

### 1. `parse_batch_fids` — no length cap on input array

Lines 3855–3863:

```rust
fn parse_batch_fids(body: &[u8]) -> Result<Vec<u64>, String> {
    #[derive(serde::Deserialize)]
    struct BatchRequest {
        fids: Vec<u64>,
    }
    serde_json::from_slice::<BatchRequest>(body)
        .map(|r| r.fids)
        .map_err(|e| format!("Invalid JSON body: {}", e))
}
```

A 1 MiB body fits roughly 100 000 base-10 `u64` literals separated by
commas. Every batch endpoint calls this helper as the only validation
step before fanning out.

### 2. `handle_batch_cast_interactions_batch` — unbounded paginated loop

Lines 3944–4006:

```rust
async fn handle_batch_cast_interactions_batch(...) -> ... {
    let fids = match Self::parse_batch_fids(body) { ... };
    ...
    let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
    for fid in fids {
        let mut entries = Vec::new();
        let mut page_token: Option<Vec<u8>> = None;
        loop {                                            // <-- no iteration cap
            match hub.get_casts_by_fid(fid, 500, page_token.clone(), false).await {
                Ok((messages, next_token)) => {
                    for msg in &messages { ... entries.push(...); }
                    match next_token {
                        Some(t) if !t.is_empty() => page_token = Some(t),
                        _ => break,
                    }
                }
                Err(_) => break,
            }
        }
        results.insert(fid, entries);                     // <-- no cap on |entries|
    }
    Ok(Self::json_response(StatusCode::OK, &results))     // <-- serializes the entire map
}
```

There is no upper bound on:

- the number of pages fetched per FID (the loop terminates only when
  the FID's cast history is exhausted or RocksDB returns an empty
  `next_token`);
- the total `entries.len()` per FID;
- the aggregate `results` size across FIDs;
- the time the handler holds the connection open.

For an FID with N casts and FIDs-per-request K, the handler does
`ceil(N / 500) * K` RocksDB iterator operations, allocates K vectors
totalling Θ(K · N) `serde_json::Value`s, and finally serializes the
entire `HashMap<u64, Vec<Value>>` into a single contiguous JSON
string. None of these are streamed to the client.

### 3. `handle_batch_cast_bodies_batch` — same shape, larger entries

Lines 4008–4094. Structurally identical to (2) but each entry includes
the full cast text, mentions list, embeds list, and hash — so the
constant factor on per-entry memory is roughly an order of magnitude
larger. Comment at line 4008–4012 explicitly notes the endpoint exists
to expose more data than `/cast-interactions`, which makes it the more
amplifying of the two.

### 4. `handle_batch_following_batch` and `handle_batch_reactions_batch` — 10 000 × K

Lines 3865–3899 and 3901–3942: each uses `limit = 10_000` per FID.
For K FIDs in the request, work = up to 10 000·K index reads + 10 000·K
`json!` allocations + a final monolithic JSON encode. With K = 100 000
that is a 10⁹-entry result map.

### 5. Dispatch site — body is read in full before any handler runs

Lines 681–698 (`handle()` POST/DELETE/PATCH/PUT block):

```rust
let body_bytes = match req.into_body().collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(_) => { ... 400 ... }
};
let result = match (method, path.as_str()) {
    (Method::POST, "/v2/farcaster/batch/following") =>
        self.handle_batch_following_batch(&body_bytes).await,
    (Method::POST, "/v2/farcaster/batch/reactions") =>
        self.handle_batch_reactions_batch(&body_bytes).await,
    (Method::POST, "/v2/farcaster/batch/cast-interactions") =>
        self.handle_batch_cast_interactions_batch(&body_bytes).await,
    (Method::POST, "/v2/farcaster/batch/cast-bodies") =>
        self.handle_batch_cast_bodies_batch(&body_bytes).await,
    ...
};
```

`req.into_body().collect()` (line 687) is the same unbounded buffer
F030 covers. F154 is downstream of F030: even if F030 is fixed (say
the body is hard-capped to 1 MiB), the resulting body still holds
~100 000 FIDs, which is enough to weaponize the per-FID amplification
in (2)–(4).

## Threat model and authentication posture

- The `/v2/farcaster/*` API is the public Farcaster-compat read surface.
  `can_handle()` accepts all batch endpoints with no auth header
  inspection (no `Authorization`, no `X-API-Key`, no origin filter
  appears anywhere in `http.rs`).
- The dispatch path (`handle()`, lines 600–773) reads no auth context.
- CORS defaults to `*` per docs (see F030 §Aggravators referencing
  `docs\attack-surface.md:34`).
- F031 (rate limiting absent) is the canonical prior art that no
  per-IP / per-FID / per-API-key throttle is wired anywhere upstream
  of these handlers.

The attacker requires only TCP reachability to the public API port.

## Impact

Single-request asymmetric DoS:

- **CPU**: each request triggers Θ(K · N) RocksDB iterator steps + the
  same number of prost decodes (deserializing protobuf `Message` per
  cast) + the same number of `serde_json::json!` allocations + one
  serialize-to-string of the full result. With K = 100 000 and the
  largest active FIDs in the network (10⁴–10⁵ casts), this is 10⁹–10¹⁰
  unit operations per request.
- **Memory**: the entire `HashMap<u64, Vec<Value>>` lives on the heap
  until the response is built. For `/batch/cast-bodies` with K = 100k
  and N = 1k casts per FID, peak heap can reach the multi-GB range —
  enough to OOM-kill a node.
- **Disk IO**: every page fetch is a RocksDB iterator step, evicting
  hot blocks from the block cache and degrading every concurrent
  reader (including consensus-relevant queries that share the same
  RocksDB instance).
- **Holds connection**: the handler does no streaming, so the
  attacker need not maintain bandwidth — fire one POST and the server
  is pinned until the loop terminates or OOM-kills the process.

If the node is also a validator (the snapchain RocksDB is shared with
the consensus engine), this manifests as missed proposals/votes and
slashable downtime in the worst case.

## Reproduction sketch

```
# 1 MiB body, ~100 000 FIDs covering the dense low-FID range
python -c 'print("{\"fids\":[" + ",".join(map(str,range(1,100001))) + "]}")' > body.json
curl -X POST http://NODE:PORT/v2/farcaster/batch/cast-bodies \
     -H "Content-Type: application/json" \
     --data @body.json
# Server pinned for minutes; RSS climbs into multi-GB range.
```

Repeat over 4–8 parallel connections to drive an OOM-kill on
commodity-RAM nodes.

## Recommended fix

1. **Cap `fids.len()` in `parse_batch_fids`** to a small constant
   (256 or 1024) and reject 400 if exceeded. This is the simplest
   single-line fix:

   ```rust
   const MAX_BATCH_FIDS: usize = 256;
   if fids.len() > MAX_BATCH_FIDS { return Err(...); }
   ```

2. **Cap the per-FID iteration in `cast-interactions` / `cast-bodies`**
   to a fixed page budget (e.g. 5 pages × 500 = 2 500 casts), and stop
   paginating beyond that — return a cursor for the caller to continue
   on a subsequent request:

   ```rust
   const MAX_PAGES_PER_FID: usize = 5;
   for _ in 0..MAX_PAGES_PER_FID { ... }
   ```

3. **Lower the `10_000` per-FID `get_following_with_timestamps` /
   `get_reactions_by_fid` limit** to the same per-request budget as
   the GET endpoints (≤100 by default).

4. **Stream the response** rather than building the entire
   `HashMap<u64, Vec<Value>>` in memory. Even better: return paged
   results with an explicit cursor, matching the GET-endpoint
   contract.

5. Compose with the F030 fix (`http_body_util::Limited` at the
   listener) so an attacker cannot defeat (1) by sending an extremely
   long JSON literal whose parse error is cheap but whose buffering
   already exhausted memory.

## Cross-references

- F030 — Unbounded HTTP request body buffer (WATERPROOF). F154 is
  downstream: even at a 1 MiB body cap, F154 still amplifies.
- F031 — No rate limiting on any HTTP/gRPC ingress (WATERPROOF). F154
  remains exploitable even with a per-IP rate limiter, because a
  single accepted request is the unit of amplification.
- F133 (fingerprint-store direct db.put during simulate) — NOT
  applicable here. All POST/DELETE/PATCH write endpoints in `http.rs`
  return `NOT_IMPLEMENTED` (lines 718–764); the file performs no
  direct `db.put` writes. The F133 antipattern was hunted explicitly
  and does not surface in this scope.
- F151 (consensus-codec pre-verify panics) — NOT applicable. The only
  `unwrap()`/`expect()` calls in the handler logic are on
  `RwLock::read()/write()` (lock-poisoning, not user-controlled);
  every hex/serde decode of attacker input is matched and converted
  to a 400 response. No pre-signature-verify panic surface exists in
  this file.

## Notes / open questions for validator

- Confirm whether any of the late-bound subsystems
  (`WebhookManagementHandler`, `NotificationSendHandler`,
  `NotificationWebhookHandler`, `NotificationAppHandler`) consume the
  body inside `http.rs`'s dispatch. They do not — `http.rs` only
  delegates to their `.handle(req)` methods (lines 624–679), so any
  amplification in those handlers belongs to a separate task scope
  (api/notifications/, api/webhooks/). They are out of scope here.
- The two batch endpoints `/batch/signers` and `/batch/id-registrations`
  are bounded by the per-FID `signer_events` / `id-register events`
  history size (typically very small per FID), so they are not the
  primary amplifiers — included for completeness only.
- The 2 GET endpoints that fetch `limit * 10` notifications
  (`handle_channel_notifications`, `handle_parent_url_notifications`,
  lines 2756, 2867) are bounded — `limit` is capped at 100 in the
  request dispatcher (line 783: `.min(100)`), so the worst case is
  1 000. These do not warrant a separate finding.
