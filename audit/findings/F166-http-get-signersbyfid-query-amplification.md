---
id: F166
task: H203
attack_class: dos
severity: low
status: draft
---

# F166 — `GET /v1/signersByFid` query-string path: no length cap on `requesterFids[]`, amplified nonce reads (no body cap on HTTP at all)

## Summary

The PR #32 delta adds `GET /v1/signer` and `GET /v1/signersByFid` HTTP endpoints
that proxy the gRPC signer service. GET requests are parsed from the URL query
string via `serde_qs::from_str` into `SignersByFidHttpRequest`, whose
`requester_fids` / `requesterFids` fields are unbounded `Vec<u64>`. `to_proto()`
forwards the list verbatim into `SignersByFidRequest`, which then drives the
unbounded per-FID RocksDB nonce loop in `get_signers_by_fid` (root cause shared
with F165). The endpoint is unauthenticated and unrate-limited.

The recon hypothesis framed this as "GET query bypasses the 4 MiB body cap that
protects POST." That framing is **inaccurate for hypersnap**: the HTTP server is
wired with a bare `http1::Builder::new().serve_connection(...)` and there is **no
body-size cap on any method** — POST handlers call
`req.collect().await.to_bytes()` with no limit either (a separate pre-existing
body-DoS surface, out of this delta's scope). So GET does not "bypass" a POST
protection that exists; rather, the new GET endpoint inherits the same lack of
input bounding, with the practical ceiling being the HTTP request-line/URI length
rather than a body limit.

## Affected files (file:line)

- `code/hypersnap/src/network/http_server.rs:1212-1256` — `SignersByFidHttpRequest`
  struct + `to_proto()`:
  ```rust
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub requester_fids: Vec<u64>,                 // L1227 — unbounded
  ...
  pub requesterFids: Vec<u64>,                  // L1238 — camelCase alias, also unbounded
  ...
  let requester_fids = if self.requester_fids.is_empty() {
      self.requesterFids                         // camel used only if snake empty
  } else {
      self.requester_fids                        // snake wins — deterministic precedence
  };
  ```
- `code/hypersnap/src/network/http_server.rs:3893-3899` — router wiring for
  `GET /v1/signersByFid` (and `:3886-3892` for `/v1/signer`).
- `code/hypersnap/src/network/http_server.rs:4166-4179` — `parse_request`: GET
  parses `serde_qs::from_str(query)`; no query-length / element-count check.
- `code/hypersnap/src/network/http_server.rs:4141-4200` — POST body parsers
  (`parse_protobuf_request`, `parse_bulk_protobuf_request`, JSON) all
  `req.collect().await` with no cap (pre-existing, out of scope, noted for context).
- `code/hypersnap/src/main.rs:309-331` — serve loop: `http1::Builder::new()` with
  no body/URI limit layer.
- Sink: `code/hypersnap/src/network/server.rs:2716` (the nonce loop — see F165).

## Trigger / Reachability

- **Auth:** none. Public read endpoint (same posture as the rest of the hub HTTP
  read surface).
- **Rate limit:** none (no rate-limit/governor anywhere in `http_server.rs`).
- **Amplification factor:** bounded by the maximum HTTP request-line length the
  server/intermediaries accept (hyper's default header buffer, typically tens of
  KiB up to a configured max). Each `&requesterFids=N` is ~16 bytes, so a single
  GET realistically encodes hundreds to a few thousand FIDs → that many serial
  RocksDB nonce reads per unauthenticated request. Lower per-request ceiling than
  the gRPC path (F165) but trivially scriptable and browser/`curl`-reachable.

Example:
```
GET /v1/signersByFid?fid=1&requesterFids=0&requesterFids=1&requesterFids=2& ... (xN)
```

## Dual snake/camel alias — request-shape confusion (sub-hypothesis): RULED OUT as a standalone issue

The hypothesis of "ambiguous precedence / request-smuggling-style param
confusion" does **not** hold. `to_proto()` has a single, deterministic rule:
snake_case `requester_fids` is used iff it is non-empty, otherwise camelCase
`requesterFids`; `page_size.or(pageSize)` always prefers snake. Both fields are
populated from the *same* parsed query struct in one pass, so there is no second
parser and no smuggling channel — at worst a client that sets both forms gets the
snake-case one silently. This is a minor API-ergonomics wart, not a security
boundary. It does not warrant its own finding. (Behavior is also identical to
upstream.)

## Snapchain-parity note

**Inherited from snapchain upstream — also affects upstream.** The
`SignersByFidHttpRequest` struct, its dual aliases, the `to_proto()` precedence,
the `serde_qs::from_str` GET parsing, and the absence of a body cap are all
byte-for-byte identical to `C:\Projects\snapchain\src\network\http_server.rs`
(struct L1087-1135; GET parse L3914; router L3634). Hypersnap only dropped
upstream's doc-comments. Snapchain's `main.rs` serve loop likewise applies no
body limit. Not a hypersnap divergence; reported here because the endpoints live
in the PR #32 delta (+405 in `http_server.rs`).

## Severity rationale

**Low.** Same reasoning as F165: unauthenticated and unrate-limited, but the work
is a serial sequence of cheap hot-CF RocksDB point-reads bounded by the HTTP
request-line length (smaller ceiling than the gRPC path). No memory-exhaustion,
no state corruption. The HTTP transport makes exploitation easier (no gRPC client
needed, fires from a browser), which is why it is worth a distinct draft from
F165. Note separately that the *absence of any HTTP body cap* (POST included) is
a real but pre-existing, out-of-delta concern worth its own ticket.

## Suggested remediation

- Enforce a small cap on `requester_fids` length inside `to_proto()` (or reject
  oversized requests in `parse_request` before dispatch); keep it consistent with
  the gRPC cap from F165 so both transports share one bound.
- Add a global HTTP body/URI size limit to the serve loop in `main.rs`
  (wrap the connection in a body-limit layer) — fixes the broader unbounded-body
  exposure too (track as a separate pre-existing issue).
- Add read-path rate limiting to public hub endpoints.

## Dedupe links

- Paired with **F165** (shared root cause: unbounded `requester_fids` nonce loop
  in `server.rs:2716`; this draft covers the HTTP-GET transport + query path).
- Link to the http finding cluster (recon §5).
- The unbounded-POST-body observation may overlap with mempool specialist drafts
  (F160-F164) touching `submitMessage`/`submitBulkMessages` body parsing — flag
  for dedupe.
