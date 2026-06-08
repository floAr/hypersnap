---
id: H041
specialist: http-api-rocksdb
attack_class: rate-limit-missing
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - src/network/rate_limit.rs
  - src/network/http_server.rs
  - src/main.rs
---

# H041 — routes lacking IpRateLimiter coverage; spoofable-key bypass

## Question

Which mutating/expensive HTTP/gRPC routes are NOT behind `IpRateLimiter`?
And is the limiter keyed on a client-controllable header
(`X-Forwarded-For`) so it can be trivially bypassed?

## Conclusion: ruled out

Both hypotheses are negative. The limiter gates **every** route at the
top of `Router::handle()` before any routing/dispatch, plus a second
time at TCP accept. It is keyed on the real TCP socket IP
(`peer_addr.ip()` / tonic `remote_addr()`), never on `X-Forwarded-For`
or any client-supplied header — so there is no header-spoof bypass.

## Evidence walked end-to-end

### Single chokepoint covers all HTTP routes
`Router::handle()` (`http_server.rs:3702`) performs the rate check as its
first statement (3709-3716): `if !limiter.allow(peer_ip) { return 429 }`.
This runs before the OPTIONS short-circuit, before the v2 `ApiHttpHandler`
branch (3759), before the `/hyper/v1/*` branch (3773), and before the
legacy `match (method, path)` table (3795-4037). Therefore the mutating /
expensive routes named in the original F031 finding are all covered:

- `POST /v1/validateMessage` (3937), `POST /v1/submitMessage` (3946),
  `POST /v1/submitBulkMessages` (3952) — full sig-verify + engine
  simulation paths.
- `/hyper/v1/*` (dispatched at 3773-3793 via `hyper_handler`).
- v2 API surface (`ApiHttpHandler`, dispatched at 3759-3768), which
  includes the webhook POSTs, mini-app notification webhook receiver, and
  the notification **send** fan-out endpoint (`api/http.rs:624-679`).
  These are reached only after the 3709 check passes.
- All `GET /v1/*` read routes.

The unreachable arm is the 404 fallback (4033). No route is dispatched
ahead of the limiter check.

### Second enforcement point at accept
`main.rs:356-369`: the HTTP accept loop calls
`rate_limiter.allow(peer_addr.ip())` and drops the stream on refusal, so
new connections are bounded even before a request is parsed. The same
`Arc<IpRateLimiter>` is cloned into the per-connection `Router`
(`with_rate_limiter(rl, peer_ip)`, 378-383) so keep-alive / pipelined
requests on an established connection are each re-checked at 3709 — a
single connection cannot amortize many requests under one accept.

### gRPC is covered by an equivalent interceptor
`main.rs:286-304`: an `InterceptedService` wraps `HubServiceServer` with
`rate_limit_interceptor`, which calls `grpc_rl.allow(addr.ip())` on every
RPC (120 req/min/IP). So gRPC submit/replication/admin RPCs are gated
per-call, not just per-connection.

### Key is the real socket IP, not a spoofable header
- HTTP: `peer_ip` originates from `listener.accept()` →
  `peer_addr.ip()` (`main.rs:358-379`). It is captured from the kernel
  TCP 4-tuple, not parsed from any header.
- gRPC: the interceptor uses `req.remote_addr()` (tonic `ConnectInfo`),
  also the real socket address (`main.rs:294`).
- A full-file scan finds **no** read of `X-Forwarded-For`,
  `Forwarded`, or any `forwarded`/`client-ip` header anywhere in
  `http_server.rs`, `rate_limit.rs`, or `main.rs`. The limiter cannot be
  bypassed by injecting a forged client IP.

### No alternate unprotected production listener
The only production ingress listeners are the rate-limited HTTP loop
(`main.rs:341`) and the rate-limited gRPC server (`main.rs:305`). The
other `serve_connection` / `listener.accept()` sites
(`api/webhooks/delivery.rs:808`, `api/notifications/sender.rs:516`,
`bootstrap/replication/client_test.rs`) are all inside `#[cfg(test)]` /
`_test.rs` harness code, not a production bind.

## Residual / nits (not findings)

- The limiter keys on the **immediate** peer IP. Behind a reverse proxy /
  load balancer (the doc comment in `rate_limit.rs:21` explicitly targets
  "edge-fronted deployments"), all clients collapse into the proxy's
  single IP bucket. This is a deployment/over-blocking concern, not a
  bypass: it makes the limiter strictly *more* aggressive, never weaker.
  Honoring `X-Forwarded-For` would be required to per-client limit behind
  a trusted proxy, but doing so naively is exactly the spoofable-key
  anti-pattern this hunt looked for — its absence is correct here.
- Limits are compile-time constants (HTTP 60/min, gRPC 120/min) with a
  TODO to plumb from config (`main.rs:349-355`). Tunability gap only.
- The fixed-window limiter allows a 2x burst across a window boundary
  (standard fixed-window artifact). Not a coverage gap.
