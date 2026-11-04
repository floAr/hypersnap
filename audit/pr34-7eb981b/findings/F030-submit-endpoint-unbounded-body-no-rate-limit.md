---
finding_id: F030
title: The Hypersnap submit endpoint (`submit_address`, `POST /v1/submitMessage`) reads the whole request body into memory with no size limit
severity: medium
status: pending-validation
related_findings:
- F018
- F032
---
# F030 — The Hypersnap submit endpoint (`submit_address`, `POST /v1/submitMessage`) reads the whole request body into memory with no size limit. It has no per-IP limiter and no header or body timeout. One unauthenticated client can OOM-kill the node with a single request. The endpoint also bypasses the 120/min per-IP gRPC limiter that guards the same `submit_message` handler.

- **Severity:** Medium. When enabled and reachable, the impact is a node crash (OOM). Likelihood is limited because the endpoint is opt-in: `submit_address` defaults to empty, and neither `docker-compose.mainnet.yml` nor `config/sample.toml` sets it. Raise it to High for any deployment that exposes it, for example a node that serves wallets.
- **Category:** body-size-no-cap / rate-limit-missing (missing ingress hardening, inconsistent with the rest of the node)
- **Specialist:** http-api-rocksdb · attack classes: body-size-no-cap, rate-limit-missing · tasks H037 (+H038)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). `src/node/hypersnap_main.rs` is new in this PR.
- **Trigger:** any TCP client that can reach `submit_address`. No authentication is needed: `rpc_auth` is checked only after the body is buffered and decoded.
- **PoC:** None. Reasoned from source; nothing was built. To reproduce, set `submit_address = "0.0.0.0:3591"`, then run `curl -X POST --data-binary @/dev/zero -H 'Transfer-Encoding: chunked' http://node:3591/v1/submitMessage` (or several in parallel) and watch the node's RSS.

## Code facts

1. **The body is unbounded.** `serve_submit` does `req.into_body().collect().await` and then `to_bytes()` (`src/node/hypersnap_main.rs:598-601`). `http_body_util::Collected` keeps every frame until end of stream. Nothing applies a `Limited` wrapper, and nothing checks `content-length`. The protobuf decode (`:602`) and the `rpc_auth` check inside `hub.submit_message` (`server.rs:1590`) run only after the full body is in memory.
2. **The rest of the node knows about this threat and caps it.** The main HTTP API wraps every body in `Limited::new(body, MAX_HTTP_BODY_BYTES)` with a 4 MiB cap. Its comment explains why: "Buffering caps prevent an anonymous public-internet POST of a multi-GB body from OOM-killing the node" (`src/network/http_server.rs:35-51`, also `:6179-6181`). gRPC is capped at tonic's default 4 MiB decode limit. The submit endpoint is the only ingress without a cap.
3. **There is no rate or connection limit.** The accept loop spawns one task per connection with no limit and no per-IP check (`hypersnap_main.rs:568-628`). The `IpRateLimiter` is wired into the gRPC server (interceptor, `src/node/servers.rs:426-441`) and the HTTP API (`:497-506`, `http_server.rs:5418`), but not here. `serve_submit` calls `MyHubService::submit_message` directly (`hypersnap_main.rs:617`), so it never goes through the tonic `InterceptedService`, and `rpc_exempt_ips` and the 120/min limit do not apply.
4. **There are no timeouts.** `http1::Builder::new().serve_connection(...)` (`:624-626`) has no `.timer(...)` set, so hyper's `header_read_timeout` is not enforced, and nothing times out a body read. A client can hold a connection, its task, its file descriptor and a partly buffered body for as long as it likes.
5. **Accept errors spin.** On an accept error, `let Ok(..) = listener.accept().await else { continue; }` (`:569-571`) loops with no back-off. If accept errors persist, this becomes a busy loop on a runtime worker.

## Attack

1. **Single-request OOM.** The attacker opens one connection to `submit_address` and streams a chunked body, or sends `Content-Length: 2^40` and keeps sending. `collect()` grows the `BytesMut` until the process is OOM-killed. Bandwidth bounds the speed: at 1 Gbit/s, 16 GiB takes about 2 minutes. N parallel connections divide the time by N. With `restart: always` the node restarts, and the attacker repeats.
2. **Slow-loris.** Many connections send partial headers or bodies and never finish. Each holds a task and an fd for as long as the client likes (no timeouts, no connection cap on this listener).
3. **CPU grief outside the limiter.** Valid-looking messages signed with fresh Ed25519 keys make `auth::open` do a full signature check (`src/chain/shard0/auth.rs:168-175`) under the shard-0 simulate mutex (`hypersnap_rpc.rs:78-97`). The gRPC limiter caps this at 120/min/IP. Through this endpoint there is no cap at all (see F032 for the runtime effect of that mutex).
4. **F018 ingress.** This is the one ingress with no size cap at all. A padded `Ed25519Falcon512` signature extension of any size passes `auth::open` (F018, validation note) and reaches the mempool. The gRPC and HTTP API routes cap it at about 4 MiB, which is already enough for F018, so this endpoint does not add a new F018 capability.

## Red-team (invalidation hypotheses walked)

1. *Is it on by default?* No. The default is `submit_address: String::new()` (`hypersnap_main.rs:139`), and it is spawned only if non-empty (`:1095-1101`). The wallet CLI's default `--node-url` is `http://127.0.0.1:3591` (`crates/hypersnap-wallet/src/main.rs:41`), so the expected setup is local. That is why the severity is Medium and not High. However, the wallet, the `hypersnap_pivot` vote submit (`src/bin/hypersnap_pivot.rs:158`) and the devnet setup (`setup_hypersnap_devnet.rs:133`) all target this endpoint. A public wallet service needs some node to expose it, and nothing in the config docs warns that it is unhardened.
2. *Does hyper cap bodies itself?* No. hyper 1.x `Incoming` has no size limit, and `BodyExt::collect` buffers without limit.
3. *Does `rpc_auth` protect it?* No. It is checked after buffering and decoding, and `allowed_users` is empty by default (`rpc_extensions.rs:157-163`).
4. *Does a reverse proxy in front fix it?* Only if the operator adds one with a body limit. Nothing in the repo says to.
5. *Duplicate of F018?* No. F018 is the proposer/validator size-rule mismatch. This finding is the missing ingress hardening, which exists independently of message validity.

## Recommendations

- Wrap the body: `http_body_util::Limited::new(req.into_body(), MAX_SUBMIT_BYTES)`, and also reject an over-cap `content-length` early. A cap of about 1 MiB + 4 KiB is enough for one message once F018's per-message encoded-size check exists. Reuse `read_limited_body` from `http_server.rs`.
- Apply the shared `IpRateLimiter` (and `rpc_exempt_ips`) per accept and per request, as `servers.rs` does for port 3381. Better still, drop the separate listener and route `/v1/submitMessage` and `/v1/shard0/*` through the existing `Router` on `http_address`, which already has both protections.
- Set `.timer(TokioTimer::new())` and `.header_read_timeout(..)` on the `http1::Builder`, wrap `serve_connection` in a total timeout, and cap concurrent connections with a semaphore.
- Back off on accept errors instead of `continue` in a tight loop.
- Document in `HypersnapMainConfig::submit_address` that the endpoint must not be exposed publicly until these protections exist.
