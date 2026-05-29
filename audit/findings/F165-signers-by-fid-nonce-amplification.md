---
id: F165
task: H202
attack_class: resource-amplification
severity: low
status: draft
---

# F165 — `get_signers_by_fid` unbounded `requester_fids` → per-request RocksDB nonce-read amplification

## Summary

The `GetSignersByFid` gRPC handler (and its HTTP proxy, see F166) reads one
RocksDB nonce counter for **every** element of the caller-supplied
`SignersByFidRequest.requester_fids` list. The list has no length cap in the
proto schema, in `to_proto()`, in `page_options()`, or in the handler itself.
A single unauthenticated request therefore fans out into N serial point-reads
against the gasless-key nonce store, where N is attacker-chosen. There is no
rate limiting on the read path. This is a request-amplification DoS / CPU-grief
surface.

The loop is byte-for-byte identical to snapchain v0.12.0 upstream (the hypersnap
copy merely drops upstream's explanatory comments), so this is an
upstream-inherited behavior that is newly reachable in hypersnap because the
PR #32 delta widens `GetSignersByFid` from `FidRequest` to the new
`SignersByFidRequest` and exposes it over HTTP.

## Affected files (file:line)

- `code/hypersnap/src/network/server.rs:2699-2731` — `get_signers_by_fid`; the
  unbounded loop is at:
  ```rust
  let mut requester_fid_nonces: HashMap<u64, u32> =
      HashMap::with_capacity(req.requester_fids.len());      // L2714-2715
  for requester_fid in &req.requester_fids {                 // L2716 — no cap
      let nonce = get_app_nonce(&stores.db, &nonce_txn, *requester_fid)
          .map_err(signer_store_error_to_status)?            // one RocksDB read per element
          .unwrap_or(0);
      requester_fid_nonces.insert(*requester_fid, nonce);
  }
  ```
- `code/hypersnap/src/network/rpc_extensions.rs:59-79` — `page_options()` passes
  `page_size` straight through (also no cap), so the page read is not a mitigating
  bound on the nonce fan-out.
- proto: `SignersByFidRequest.requester_fids` is `repeated uint64` (no size
  constraint; proto has no native length cap).

## Trigger / Reachability

- **Auth:** none. This is a read RPC on the public hub gRPC service.
- **Rate limit:** none on the read path (no `RateLimit`/governor anywhere in the
  gRPC read handler chain).
- **Per-element cost:** one `get_app_nonce` RocksDB point-read (a CF lookup in
  the key-nonce store) per `requester_fids` entry, executed serially, plus a
  `HashMap` insert. `HashMap::with_capacity(req.requester_fids.len())` also
  pre-allocates a map sized to the attacker-controlled length.
- **Amplification factor over gRPC:** bounded only by the gRPC max message size
  (default tonic decode limit, typically 4 MiB). Each `requester_fids` varint is
  ~1-10 bytes on the wire, so a single ~4 MiB request encodes on the order of
  10^5-10^6 FIDs → 10^5-10^6 serial RocksDB reads for one request.

Example (grpcurl-style):
```
GetSignersByFid({ "fid": 1, "requester_fids": [0,1,2, ... , 999999] })
```
One request → ~10^6 nonce-store reads, no auth, no rate limit. Repeating across
connections multiplies CPU/IO grief without per-FID storage cost to the attacker.

## Snapchain-parity note

**Inherited from snapchain upstream — also affects upstream.** The loop is
identical to `C:\Projects\snapchain\src\network\server.rs:2493-2531`
(`get_signers_by_fid`). The only textual difference is that upstream carries two
explanatory comments (lines 2504-2507, 2512-2513) that hypersnap dropped; the
logic, the missing cap, and the `with_capacity` pre-allocation are verbatim. This
is therefore not a hypersnap divergence — but the code lives inside the PR #32
delta (the request type was widened `FidRequest` → `SignersByFidRequest` in this
PR), so it is reported as a hypersnap finding with the parity caveat. If routed
upstream, it applies to snapchain v0.12.0 as well.

## Severity rationale

**Low.** Real unauthenticated, unrate-limited amplification, but: (a) the work is
bounded by the gRPC/HTTP request size ceiling (not unbounded memory like a body
bomb), (b) each operation is a cheap RocksDB point-read on a small-value CF
(block cache friendly; nonces are hot), and (c) the read is fully serial so it
self-throttles to a single core per connection. The blast radius is CPU/IO grief
proportional to request size, not a memory-exhaustion or state-corruption bug. It
becomes more interesting combined with the HTTP-GET exposure in F166 (trivially
scriptable, browser-reachable). Raise to medium if the deployment fronts this
service without an external rate limiter / WAF.

## Suggested remediation

- Cap `requester_fids.len()` at a small constant (e.g. ≤ 100 / one page) at
  handler entry and return `invalid_argument` when exceeded — mirrors how
  `page_size` *should* be capped.
- Avoid `HashMap::with_capacity(attacker_len)`; cap the capacity hint.
- Apply the same cap in the HTTP proxy `to_proto()` (F166) so the limit holds for
  both transports.
- Consider adding read-path rate limiting (per-IP / per-token) to the public hub
  endpoints generally.

## Dedupe links

- Link to the http/mempool finding cluster (recon §5: "http (`http_server.rs`,
  `server.rs`) → existing http findings").
- Paired with **F166** (same root cause, HTTP-GET transport + query-string path).
