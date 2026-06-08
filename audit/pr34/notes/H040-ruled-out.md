---
id: H040
specialist: http-api-rocksdb
attack_class: body-size-no-cap
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - src/network/http_server.rs
---

# H040 — request body-size cap on submit/admin HTTP endpoints

## Question

Does any inbound HTTP body in `http_server.rs` — especially the
unauthenticated `POST /v1/submitMessage` / `submitBulkMessages` /
`validateMessage` submit endpoints — get read without a maximum-length
cap, allowing a trivial unauthenticated memory-exhaustion DoS (attacker
streams a multi-GB body that is buffered before any application check)?

## Conclusion: ruled out

Every body-reading path in `http_server.rs` is capped at 4 MiB using
`http_body_util::Limited`, which aborts the read as soon as the cap is
exceeded — before the full body is buffered. No `Incoming` body is read
via an uncapped `.collect()` / `.to_bytes()`. The in-file comments
attribute this to prior remediations F030/F031, and the code matches.

## Evidence walked end-to-end

### Central capped reader
`MAX_HTTP_BODY_BYTES = 4 * 1024 * 1024` (line 34) and the helper
`read_limited_body` (lines 39-46) wrap the body in
`Limited::new(body, MAX_HTTP_BODY_BYTES)` then `.collect()`, mapping the
overflow to an error. `Limited` stops reading at the cap, so an
oversized body never fully buffers.

### POST submit/admin routes all flow through the cap
Router dispatch is in `handle` (lines 3795-4037):
- `POST /v1/validateMessage` (3937) and `POST /v1/submitMessage` (3946)
  → `handle_protobuf_request` → `parse_protobuf_request` (4228-4250),
  which reads via `read_limited_body(req.into_body())` (4233). Oversize
  returns `413 PAYLOAD_TOO_LARGE`.
- `POST /v1/submitBulkMessages` (3952) → `handle_bulk_protobuf_request`
  → `parse_bulk_protobuf_request` (4207-4226), which reads via
  `read_limited_body` (4213) before `prost` decode. 413 on oversize.
- `/hyper/v1/*` handler branch (3773-3793) reads via `read_limited_body`
  (3777) before dispatch.
- GET routes → `handle_request` → `parse_request` (4252-4292). The GET
  branch parses only the query string (4257-4264); the POST/PUT branch
  (4267-4283) reads the body via a direct `Limited::new(req, 4 MiB)`
  with the same cap (lines 4272-4274), returning 413 on overflow.

### No uncapped body read remains
A scan for `Incoming` body consumption (`into_body`, `Limited::new`,
`.collect()`, `.to_bytes()`) shows only the four capped sites above. The
two `resp.into_body()` uses (4100, 4136) act on the response body, not
the request, and are irrelevant. There is no raw
`req.into_body().collect()` anywhere in the file.

### Defense is at the correct layer
`Limited` enforces the cap at the transport read, before any
application-level (signature / mempool / validate-before-broadcast)
logic runs, so the cap protects against the pre-validation buffering
OOM that this attack class targets. The submit endpoints are reachable
unauthenticated, but the body cap blunts the memory-DoS regardless of
auth.

## Residual / nits (not findings, partly out of scope)

- The v2 API handler is delegated out of this file:
  `self.api_handler.handle(req)` (line 3761) consumes the raw `req`
  inside a separate module. Whether that delegated handler applies its
  own body cap is outside H040's `src/network/http_server.rs` scope and
  is not assessed here. If a separate hunt covers the v2 API surface,
  its body-size handling should be confirmed there.
- The 4 MiB cap is duplicated as a local `const` inside `parse_request`
  (4272) rather than reusing the module-level `MAX_HTTP_BODY_BYTES`.
  Cosmetic only; both values are identical (4 MiB).
