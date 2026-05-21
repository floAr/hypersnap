---
id: F157
task: H157
attack_class: untrusted-input-ingress
severity: medium
status: draft
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
file_paths:
  - code/hypersnap/src/api/notifications/send_handler.rs
  - code/hypersnap/src/api/social_graph.rs
---

# F157 — `following_fid` filter on the mini-app send endpoint enumerates an attacker-chosen FID's *entire* follower set per request

- Hunt task: H157
- Attack class: untrusted-input-ingress (algorithmic DoS amplification on a post-auth handler)
- Specialist: untrusted-input-ingress (api/notifications/send_handler.rs scope)
- Severity (draft): Medium — post-auth (any holder of any Farcaster custody key can self-onboard), but single-request amplification is unbounded and the post-auth gate is essentially free
- Status: draft

## Summary

`NotificationSendHandler::resolve_recipients` honors a JSON-body field
called `following_fid` that, when set, scopes the recipient set to "FIDs
that follow `following_fid`". The implementation invokes
`collect_followers(following_fid)` (send_handler.rs:211-228), which
executes an **unbounded `loop { social_graph.get_followers(fid, cursor,
1_000) }`** over the social-graph indexer, **accumulating every
follower of the attacker-chosen FID into a single `Vec<u64>` and then
into a `HashSet<u64>`** before any per-recipient work runs.

Crucially:

- `following_fid` is a `u64` read directly out of the request body
  (`SendNotificationRequest::following_fid`, send_handler.rs:239). It is
  NOT required to be related to the caller's app, the caller's FID, or
  any FID that has interacted with the caller's app. The only gate is
  `> 0`.
- There is no upper bound on the number of pages fetched (no
  `MAX_PAGES_PER_FID`-style cap — directly comparable to the F154
  primitive on the anonymous batch endpoints).
- There is no upper bound on the accumulated `Vec`/`HashSet` size. For
  a popular FID (Farcaster's most-followed accounts have ~10⁵–10⁶
  followers in the current social graph), the `HashSet<u64>`
  allocation alone is multi-MB and the RocksDB iterator pulls
  10²–10³ pages of 1 000 entries each.
- The handler awaits the entire follower-set materialization before
  even checking `store.get(&app_id, fid)` for the much smaller
  per-app enabled-recipient set — so the work is performed
  unconditionally on every request that supplies `following_fid`.

The endpoint is gated by the per-app send-secret (`x-api-key`), but
the per-app send-secret is itself created and rotated by any holder of
any Farcaster FID's custody key via `POST /v2/farcaster/frame/app/`
(`app_handler::handle_create`, H156-ruled-out). The cost of obtaining
credentials to invoke this endpoint is one EIP-712 signature from any
custody address — i.e., any Farcaster user. Per F031 (waterproof),
there is no per-FID, per-IP, per-app, or per-send-secret rate limit
upstream of `handle()`, so the amplification can be invoked at the
attacker's preferred request rate.

This is orthogonal to F154 (anonymous read-API amplification) and to
F031 (no rate limit). F154 covers the unauthenticated
`/v2/farcaster/batch/*` surface; F157 is on the authenticated mini-app
send surface and uses a different RocksDB primitive
(`social_graph.get_followers` rather than `hub.get_casts_by_fid`).
Even if F031's rate limiter were installed, F157 remains exploitable
because a single accepted request is the unit of amplification.

## Affected sites

File: `code/hypersnap/src/api/notifications/send_handler.rs`

### 1. `SendNotificationRequest::following_fid` — attacker-controlled iteration target

Lines 231-250:

```rust
#[derive(Debug, Clone, Deserialize)]
struct SendNotificationRequest {
    notification: NotificationPayload,
    #[serde(default)]
    target_fids: Vec<u64>,
    #[serde(default)]
    exclude_fids: Vec<u64>,
    #[serde(default)]
    following_fid: Option<u64>,
    ...
}
```

No validation, no relation to `auth_headers.fid` or to the app's owner.

### 2. `resolve_recipients` honors the field unconditionally

Lines 194-199:

```rust
// following_fid: keep only FIDs that follow `following_fid`.
if let Some(following_fid) = request.following_fid.filter(|f| *f > 0) {
    let followers = self.collect_followers(following_fid)?;
    let followers_set: HashSet<u64> = followers.into_iter().collect();
    filtered.retain(|fid| followers_set.contains(fid));
}
```

`collect_followers` produces the full follower set BEFORE the retain
narrows it back down to "enabled fids for this app." For an app with
even one enabled FID, the work is performed.

### 3. `collect_followers` — unbounded paginated loop

Lines 211-228:

```rust
fn collect_followers(&self, fid: u64) -> Result<Vec<u64>, String> {
    let Some(sg) = self.social_graph.as_ref() else {
        return Err("following_fid filter requires social_graph indexing to be enabled".into());
    };
    let mut all = Vec::new();
    let mut cursor: Option<u64> = None;
    loop {                                              // <-- no iteration cap
        let (page, next) = sg
            .get_followers(fid, cursor, 1_000)
            .map_err(|e| format!("social_graph error: {e:?}"))?;
        all.extend(page);                               // <-- no |all| cap
        match next {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    Ok(all)
}
```

The loop terminates only when `social_graph.get_followers` returns
`next = None` — i.e., the FID's follower history is exhausted. For
large public FIDs this is hundreds to thousands of 1 000-entry pages,
each of which is a RocksDB iterator step under the same RocksDB
instance that consensus uses.

### 4. `social_graph::get_followers` — bounded per-call, but the wrapper iterates without limit

`code/hypersnap/src/api/social_graph.rs:161-212`

```rust
pub fn get_followers(
    &self,
    fid: u64,
    cursor: Option<u64>,
    limit: usize,
) -> Result<(Vec<u64>, Option<u64>), IndexerError> {
    let prefix = Self::make_follower_prefix(fid);
    let stop_prefix = Self::increment_prefix(&prefix);
    ...
    let page_options = crate::storage::db::PageOptions {
        page_size: Some(limit + 1),
        page_token: None,
        reverse: false,
    };
    ...
}
```

This is the same primitive used by the unauthenticated `/v2/farcaster/
batch/following` endpoint flagged by F154 with `limit = 10_000`. The
amplification factor for F157 vs F154 differs only by the constant
factor of pages per request (10× more pages here, but each page is
10× smaller, so the constant work per request matches; the
**total** work is bounded by "all followers of an attacker-chosen
FID" for both).

## Threat model and authentication posture

- The send endpoint authenticates with the per-app `x-api-key` send
  secret (`pick_active_secret` of the app's `send_secrets` vec).
- The per-app send secret is obtained by creating an app via the
  signed management API. App creation requires:
  - An EIP-712 custody-key signature for any FID, OR
  - The operator-level `X-Admin-Api-Key` (None by default).
- The per-FID app cap (`max_apps_per_owner = 25`, default) limits the
  number of apps any single custody key can create, but does NOT
  limit the rate of subsequent send requests. F031 (waterproof) is
  the canonical statement that no per-FID, per-IP, per-app, or
  per-secret rate limiter exists.
- An attacker therefore needs:
  1. A Farcaster custody key (or possession of one) — barrier: any
     Farcaster account.
  2. One EIP-712-signed `app.create` request to obtain a send secret.
  3. Unlimited send requests, each setting `following_fid` to a
     popular target FID.

Net cost-to-attack: ~$0 (one Farcaster account creation + a few
signed envelopes).

## Impact

Single-request asymmetric DoS:

- **CPU/IO**: each request does Θ(N_followers / 1000) RocksDB
  iterator pages on the social-graph index + extends a single
  `Vec<u64>` to N_followers entries + builds a `HashSet<u64>` of the
  same size. For the most-followed FIDs in the Farcaster social
  graph (which the attacker can enumerate publicly), N_followers is
  in the 10⁵–10⁶ range.
- **Memory**: one `Vec<u64>` + one `HashSet<u64>` of N_followers
  entries, ~24 bytes/entry → tens of MB per request held in heap
  until the response completes. With send_concurrency = 32 (default)
  and per-app HTTP timeout = 10 s (default), a sustained attack can
  pin hundreds of MB.
- **RocksDB block-cache pressure**: every iterator page evicts hot
  blocks, degrading every concurrent reader (including the
  consensus engine, which shares the RocksDB instance).
- **Connection hold**: `fan_out` is awaited synchronously inside
  `handle()`. The connection stays open for the full
  follower-enumeration + per-recipient store lookup + per-URL POST
  rounds.
- **Composes with `exclude_fids`/`target_fids` allocation**: the
  body cap is 32 KiB, which fits ~3 000 `u64` literals comma-
  separated. `target_fids` is capped at 100 explicitly, but
  `exclude_fids` has NO length cap and is also accumulated into a
  `HashSet<u64>` (line 188). Combining a 3 000-entry `exclude_fids`
  with a popular `following_fid` produces the worst-case heap
  footprint.

If the node is a validator (the snapchain RocksDB is shared with the
consensus engine — see F031 ¶ "validator nodes"), this manifests as
missed proposals/votes and slashable downtime in the worst case.

## Reproduction sketch

```bash
# 1. Obtain a send secret for a freshly-created app (one signed envelope).
curl -X POST https://NODE/v2/farcaster/frame/app/ \
     -H "X-Hypersnap-Fid: $MY_FID" \
     -H "X-Hypersnap-Op: app.create" \
     -H "X-Hypersnap-Signed-At: $NOW" \
     -H "X-Hypersnap-Nonce: 0x$RANDOM_32B_HEX" \
     -H "X-Hypersnap-Signature: 0x$EIP712_SIG" \
     -d '{"name":"x","app_url":"https://example.com","signer_fid_allowlist":[]}'
# → returns { app: { app_id: "...", send_secrets: [{ value: "...", ... }] } }

# 2. Send notifications "to followers of FID 3" (Dan Romero — popular target FID).
curl -X POST https://NODE/v2/farcaster/frame/notifications/$APP_ID \
     -H "x-api-key: $SEND_SECRET" \
     -d '{
       "notification": {
         "title": "x",
         "body": "y",
         "target_url": "https://example.com"
       },
       "target_fids": [],
       "following_fid": 3
     }'
# Handler iterates the full follower set of FID 3 from RocksDB
# before discovering that no FID has notifications enabled for
# my-newly-created-app. Returns quickly with success_count = 0
# but pins the server for the duration of the iteration.
```

Repeat over 32 parallel connections (matching `send_concurrency`'s
default semaphore size) to saturate the fan-out worker pool and the
RocksDB block cache.

## Recommended fix

1. **Cap per-call follower enumeration** at a small fixed budget
   (e.g. 5 000 entries / 5 pages), and reject the request with
   `400` or `413` once the cap is hit. The mini-app spec does not
   require this filter to be exhaustive — a "match against top-N
   followers" semantic is acceptable:

   ```rust
   const MAX_FOLLOWERS_PER_FILTER: usize = 5_000;
   fn collect_followers(&self, fid: u64) -> Result<Vec<u64>, String> {
       let Some(sg) = self.social_graph.as_ref() else {
           return Err("following_fid filter requires social_graph indexing".into());
       };
       let mut all = Vec::new();
       let mut cursor: Option<u64> = None;
       loop {
           let (page, next) = sg
               .get_followers(fid, cursor, 1_000)
               .map_err(|e| format!("social_graph error: {e:?}"))?;
           all.extend(page);
           if all.len() >= MAX_FOLLOWERS_PER_FILTER {
               all.truncate(MAX_FOLLOWERS_PER_FILTER);
               break;
           }
           match next {
               Some(c) => cursor = Some(c),
               None => break,
           }
       }
       Ok(all)
   }
   ```

2. **Cap `exclude_fids.len()`** with the same explicit check as
   `target_fids` (currently 100); add the missing length check in
   `validate_request`. This closes the parallel allocation amplifier.

3. **Reorder `resolve_recipients`**: compute the per-app enabled
   recipient set FIRST (it is bounded by the app's actual user
   base), then ask `social_graph.is_following(fid, following_fid)`
   per recipient — turning the cost into Θ(enabled_fids) point
   lookups rather than Θ(N_followers) enumeration. This is the
   architecturally cleanest fix and removes the attacker's ability
   to choose the iteration target.

4. Compose with the F031 fix (per-IP / per-API-key rate limiter at
   the ingress layer) so even if (1) and (3) leak through, the
   sustained attack rate is throttled.

## Cross-references

- **F030** — Unbounded HTTP request body buffer (waterproof). F157
  is downstream: the send_handler has its own 32 KiB cap
  (`MAX_BODY_BYTES`) so F030 is mitigated locally here, but the
  ~3 000-entry `exclude_fids` worst case (see ¶ Impact) is still
  present.
- **F031** — No rate limiting on any HTTP/gRPC ingress (waterproof).
  F157 remains exploitable even with a per-IP rate limiter because
  a single accepted request is the unit of amplification.
- **F154** — Farcaster batch endpoints: unbounded `fids` list +
  uncapped pagination loop. F157 mirrors the F154 amplification
  primitive on a post-auth surface (different code path, different
  RocksDB primitive, different threshold of attacker capability).
  Both should be fixed; one does not subsume the other.
- **F133** — direct-`db.put` from a simulate path. Not applicable
  here; this handler only reads (`store.get`, `social_graph.
  get_followers`) and the writes that happen in `fan_out` (token
  delete via `store.delete` for `invalidTokens`) go through the
  proper `RocksDbTransactionBatch` plumbing in `store.rs`.
- **F151** — codec decode panics on peer wire types. Not
  applicable; this handler uses `serde_json::from_slice` only,
  which returns `Err` on malformed input and surfaces as 400.
- **F138** — proposer pipeline strips signed fields. Not
  applicable; no broadcast on this surface.
- **H156-ruled-out** — app_handler.rs covers the management
  surface used to obtain the send secret in step 1 of the
  reproduction. H156 explicitly notes that the EIP-712 path is
  not itself rate-limited (deferred to F031), which is what makes
  the F157 reproduction cheap.
- **H158** — `webhook_handler.rs` (token registration) is the
  sibling task. Token registration is the inbound side of the
  notification subscription; the SSRF check there is the
  registration-time half of the two-stage SSRF defense, with the
  delivery-time half living in `sender.rs:282`. F157 does NOT
  expose any SSRF — the outbound URL is always one that was
  registered by an honest Farcaster client through `webhook_
  handler.rs`, and the URL is re-checked at delivery time.

## Notes / open questions for validator

- **Severity calibration.** I drafted this as Medium because:
  (a) post-auth — any Farcaster user can self-onboard, but it is
  not anonymous; (b) per-request amplification is large but
  individually bounded by an FID's actual follower count (no
  unbounded composition trick known); (c) `fan_out` itself is
  bounded by `target_fids.len() ≤ 100`, so the secondary
  amplification through fan-out POSTs is not present here — the
  amplification is entirely in the *pre-fan-out* recipient
  resolution path. If the validator weights the "any Farcaster
  user" threshold as "effectively anonymous given the size of
  Farcaster," this rises to High and matches F154's calibration.

- **Is the `following_fid` field actually used by mini-app
  developers?** The serde struct accepts it for "upstream contract
  compatibility" (`minimum_user_score` and `near_location` in the
  same struct are documented as accept-but-do-not-enforce; only
  `following_fid` is actually enforced — see send_handler.rs:194-
  199 vs lines 201-206). If the field is not load-bearing for any
  real client, the simplest fix is to drop the enforcement and
  silently accept-and-ignore the field — mirroring the treatment
  of `minimum_user_score` / `near_location`.

- **Does `social_graph` index any FIDs we have not actively
  followed locally?** If the indexer only populates entries for
  FIDs we have seen via the snapchain hub, the worst-case
  amplification depends on this node's view of the social graph,
  not on the global Farcaster social graph. The reproduction
  assumes the node has indexed a popular FID's follower set —
  which is the normal operational state of a Farcaster hub.

- **No injection / sender-spoofing concerns.** The forwarded
  outbound POST body uses serde_json serialization of
  `title`/`body`/`target_url`/`tokens` fields, all of which are
  either length-bounded UTF-8 strings (title ≤ 32, body ≤ 128,
  target_url ≤ 256 + https-only) or registered tokens from the
  store. No header/log injection surface, no third-party-token
  echo in error responses. Good.
