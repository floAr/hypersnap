---
id: H076
specialist: http-api-rocksdb
attack_class: http-handler-ingress
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
file_paths:
  - code/hypersnap/src/hyper/http_handler.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/router.rs
  - code/hypersnap/src/network/http_server.rs
  - code/hypersnap/src/hyper/gossip_adapter.rs
---

# H076 — HTTP ingress validation parity vs gossip/mempool path

## Scope
`src/hyper/http_handler.rs` — hyper HTTP ingress. Question: do state-changing
HTTP routes enforce validation / auth / rate-limit / body-cap equivalent to
the gossip path, and does the F058 transparent-Lock seal hold at the handler?

## State-changing routes
- `POST /hyper/v1/messages` → `submit_message` (http_handler.rs:157)
- `POST /hyper/v1/validator/register` and `/deregister` →
  `submit_validator_event` (http_handler.rs:181)

All other `/hyper/v1/*` routes are GET (read-only).

## Validation parity — holds
Both ingress paths converge on the same gate:
- HTTP: `submit_message` / `submit_validator_event` send
  `HyperActorEvent::LocalSubmitMessage(msg)`.
- Gossip: `gossip_adapter.rs:79` maps the wire frame to
  `HyperActorEvent::InboundMessage(m)` with no extra auth.

In `actor.rs::dispatch`:
- `LocalSubmitMessage` (1225-1239): calls `runtime.submit_message(msg.clone())`,
  and only emits `BroadcastMessage` on `Ok` — i.e. validate-before-broadcast.
- `InboundMessage` (1215-1223): calls the same `runtime.submit_message(msg)`.

`HyperRuntime::submit_message` (runtime.rs:3664) delegates per-type to
`HyperRouter::route_inbound` (router.rs:131), which performs all per-message
validation (signature/custody checks, registry quota via
`validate_and_check_quota` / `validate_event`, uniqueness, etc.). There is no
HTTP-only path that skips a check the gossip path applies, nor the reverse.

## F058 seal — holds
`route_inbound` rejects `Body::Lock` for ALL callers
(router.rs:133-141, `RoutingError::Lock("transparent lock path removed; use
ConfidentialLockBody")`). An HTTP POST of a transparent `HyperLockEvent`
therefore cannot enter the mempool. Test
`post_messages_rejects_transparent_lock` (http_handler.rs:1706-1750) confirms
the mempool stays empty after such a POST.

## Body-size cap — present
The HTTP body is read by `read_limited_body` which wraps the incoming body in
`http_body_util::Limited::new(body, MAX_HTTP_BODY_BYTES)` (4 MiB) at
`http_server.rs:3777`, before `hyper_handler.handle` runs; oversize returns
413 PAYLOAD_TOO_LARGE. No unbounded `into_body().to_bytes()`. Proto/JSON
decode runs on already-capped bytes, bounding decoder-bomb allocation.

## Rate limit — present
Per-IP `limiter.allow(peer_ip)` (F031) at `http_server.rs:3709-3716` runs on
every request, including `/hyper/v1/*` POSTs, before dispatch; returns 429.

## Auth
Submit routes are intentionally unauthenticated but follow the documented good
pattern: validate-before-broadcast at the actor entry, with in-message
signature verification performed inside `route_inbound` and the registry. This
matches the gossip path's enforcement; the network layer is not relied upon as
the sole gate.

## Conclusion
No HTTP-vs-gossip validation divergence; F058 seal enforced at the shared
router layer covering both paths; body-cap, rate-limit, and validate-before-
broadcast all present. No issue.
