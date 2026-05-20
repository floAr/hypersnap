---
finding_id: F030
hunt_task: H030
attack_class: body-size-no-cap
specialist: http-api-rocksdb
severity_initial: High
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
file_paths:
  - code/hypersnap/src/network/http_server.rs
  - code/hypersnap/src/api/webhooks/handler.rs
  - code/hypersnap/src/hyper/http_handler.rs
  - code/hypersnap/src/main.rs
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F030 — Unbounded HTTP request body buffered before size cap (memory DoS)

- Hunt task: H030
- Attack class: body-size-no-cap
- Specialist: http-api-rocksdb
- Severity (draft): High (anonymous, remote, memory-exhaustion DoS on the public node)
- Status: draft — to be validated

## Summary

The public-facing HTTP server buffers each request body into a single
contiguous `Bytes` allocation BEFORE any size cap is consulted. No
transport-level `http_body_util::Limited`, `tower-http::RequestBodyLimit`,
or `Content-Length` precheck is applied at the listener, and no
`max_body_size` is set on `http1::Builder`. As a result, an
unauthenticated remote attacker who issues a single POST with a 10 GB
(or chunked, indefinite) body causes the node to allocate that much
heap before the application layer can reject it — trivially OOM-killing
the node. The CORS origin defaults to `*` and these endpoints are
reachable over the open internet.

This affects three independent ingress paths:

## Affected sites

### A. Main snapchain REST router (no cap at all)

File: `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\network\http_server.rs`

1. `parse_bulk_protobuf_request` (line 3761-3780) — `POST /v1/submitBulkMessages`:

   ```rust
   let body_bytes = req.collect().await.map_err(|e| { ... })?;
   proto::SubmitBulkMessagesRequest::decode(body_bytes.to_bytes()).map_err(...)
   ```

   No size check before `collect().await`. A 10 GB body is fully
   buffered, then handed to `prost` for decode.

2. `parse_protobuf_request` (line 3782-3805) — `POST /v1/submitMessage`,
   `POST /v1/validateMessage`:

   ```rust
   let body_bytes = req.collect().await;
   ...
   message_decode(&body_bytes.unwrap().to_bytes().slice(..))
   ```

3. `parse_request<T>` (line 3807-3841) — every other POST/PUT JSON route
   that goes through the legacy router:

   ```rust
   let body_bytes = req.collect().await;
   ...
   serde_json::from_slice(&body_bytes.unwrap().to_bytes().slice(..))
   ```

4. Hyper-route dispatch (line 3344-3361):

   ```rust
   let body = req
       .into_body()
       .collect()
       .await
       .map(|c| c.to_bytes())
       .unwrap_or_else(|_| Bytes::new());
   let mut response = hyper_handler.handle(&method, &path, body).await;
   ```

   Routes `POST /hyper/v1/messages`, `POST /hyper/v1/validator/register`,
   `POST /hyper/v1/validator/deregister` (see
   `hyper/http_handler.rs:142-151`) all flow through this unbounded
   buffer.

In none of these paths is `Content-Length` checked, nor is the body
wrapped in `http_body_util::Limited`. `http1::Builder` is constructed
with defaults at `code\hypersnap\src\main.rs:332-340`:

```rust
http1::Builder::new()
    .serve_connection(io, service_fn(|r| router.handle(r, ...)))
```

No `.max_buf_size(...)` or equivalent. The whole body is collected into
RAM.

### B. Webhooks management handler — post-hoc cap (still buffers first)

File: `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\api\webhooks\handler.rs`

```rust
const MAX_BODY_BYTES: usize = 256 * 1024;
...
async fn read_body(body: hyper::body::Incoming) -> Result<Bytes, String> {
    let collected = body
        .collect()
        .await
        .map_err(|e| format!("failed to read body: {e}"))?
        .to_bytes();
    if collected.len() > MAX_BODY_BYTES {
        return Err(format!("body exceeds {} bytes", MAX_BODY_BYTES));
    }
    Ok(collected)
}
```

The length check (line 656-658) happens AFTER the body has been
fully buffered into `collected`. An attacker sending a 10 GB body
allocates 10 GB of heap before `read_body` returns the "body exceeds"
error. The constant `MAX_BODY_BYTES` is not load-bearing here — the
DoS occurs upstream of it. The webhook routes are reachable at
`/v2/farcaster/webhook*` over public CORS=`*`.

### C. Hyper handler (downstream of A.4, but worth noting)

File: `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\http_handler.rs`

`HyperHttpHandler::handle` takes a pre-buffered `body: Bytes` (line 58-63).
The caller in (A.4) is the unbounded collector; the handler itself
inherits the DoS via its caller.

## Impact

Memory-exhaustion DoS against the node process. The attacker needs only
TCP reachability to the public HTTP port. No authentication required —
the body is read BEFORE any auth header parsing, signature verification,
content-type check, or ownership check. A single connection with a
chunked-transfer body that streams indefinitely will hit OOM-kill
before any validation runs; multiple parallel connections multiply the
allocation. For the snapchain port specifically, this likely takes
down a validator (causing missed proposals/votes) and certainly takes
down read-only RPC nodes.

Aggravators:

- `http1::Builder` default has no per-connection memory cap.
- The router spawns a task per accepted connection
  (`code\hypersnap\src\main.rs:323`) with no connection limit, so a
  fleet of attackers can scale the allocation horizontally.
- CORS defaults to `*` per `docs\attack-surface.md:34`, confirming the
  endpoints are intended for arbitrary internet origins.

## Reproduction sketch

```
curl -X POST http://NODE:PORT/v1/submitBulkMessages \
  -H "Content-Type: application/octet-stream" \
  --data-binary @10GB-file-of-zeros
```

or, more cheaply, a chunked POST that streams `0xFF` bytes indefinitely
to `/v2/farcaster/webhook`, `/hyper/v1/messages`, or any legacy
`POST /v1/*` route. RSS grows in lockstep with bytes received until
OOM.

## Recommended fix

Apply a size cap at the transport boundary, BEFORE buffering:

1. Wrap incoming bodies with `http_body_util::Limited::new(body, MAX)`
   inside the router entry (around `serve_connection` or just inside
   `Router::handle`). `Limited` returns an error as soon as the
   accumulated byte count exceeds `MAX`, so the body is never fully
   buffered when oversized.

2. Choose distinct caps per route family: e.g. 256 KiB for webhooks
   (matches existing intent), a few MiB for `submitBulkMessages`, a
   few hundred KiB for `submitMessage`/`validateMessage`, 64 KiB
   for the hyper validator POST routes.

3. Reject early on declared `Content-Length` > cap with `413 Payload
   Too Large` before reading any body bytes.

4. Move the existing post-hoc `MAX_BODY_BYTES` check in
   `webhooks/handler.rs::read_body` to a pre-buffer `Limited` wrapper.

5. Consider adding `tower::limit::ConcurrencyLimit` and a per-IP
   connection cap on the listener to bound the aggregate memory budget.

## Notes / open questions for validator

- Confirm whether any upstream reverse proxy (nginx/envoy/cloudflare)
  is part of the deployment baseline and enforces a body cap. If so,
  the attack requires bypassing it; if not (typical for full-node
  operators), the DoS lands directly. The code-level vulnerability
  exists regardless — operators running without a proxy are exposed.
- Confirm whether `http1::Builder` defaults impose any implicit
  per-request memory limit. Reading the hyper 1.x source: it does
  not; `Body::collect`/`http_body_util::BodyExt::collect` accumulates
  without bound.
