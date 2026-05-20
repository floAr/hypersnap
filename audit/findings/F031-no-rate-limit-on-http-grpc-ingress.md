---
id: F031
task: H031
specialist: http-api-rocksdb
attack_class: rate-limit-missing
severity: high
status: draft
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
file_paths:
  - src/network/server.rs
  - src/network/http_server.rs
  - src/network/admin_server.rs
  - src/network/rpc_extensions.rs
  - src/hyper/http_handler.rs
  - src/api/notifications/webhook_handler.rs
  - src/mempool/mempool.rs
  - src/main.rs
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F031 — No rate limiting on any HTTP / gRPC ingress endpoint (CPU-grief DoS)

- Hunt task: H031
- Attack class: rate-limit-missing
- Specialist: http-api-rocksdb
- Severity (draft): High (anonymous, remote, CPU-exhaustion DoS on the public node and consensus participant)
- Status: draft — to be validated

## Summary

`src/network/**` and `src/api/**` expose three internet-facing servers
(the snapchain v1 REST/gRPC HubService, the Farcaster v2 API, and the
hyper-protocol `/hyper/v1/*` handler) plus an `admin_server` gRPC
service. None of them install a per-IP, per-FID, per-API-key, or
per-shard request-rate limiter. The `governor = "0.10.0"` crate IS in
`Cargo.toml` but is only `use`d from one location:
`src/mempool/mempool.rs` (per-FID admission-rate ceiling computed from
the FID's storage allowance). That limiter fires only AFTER the request
has been fully validated (signature verified, full message simulated
through the engine, dest-shard routed). No `tower-governor` /
`tower::limit::ConcurrencyLimit` / `tower::limit::RateLimit` /
`tower-http` limiter is wired into the connection acceptor or the
service stack — confirmed by:

```
$ rg 'tower_governor|tower::limit|GovernorLayer' src/network src/api
(no matches)
$ rg 'use governor|governor::' src/
src/mempool/mempool.rs:1
src/mempool/mempool.rs:2
src/mempool/mempool.rs:38
```

Concretely, an unauthenticated remote attacker can saturate the node's
CPU by replaying any of the expensive, validation-heavy endpoints
listed below, with no per-source ceiling and with no operator-tunable
limit.

The connection accept-loop at
`code\hypersnap\src\main.rs:308-348` spawns a new tokio task per
accepted TCP connection with no aggregate connection cap, no semaphore,
no `tower::limit::ConcurrencyLimit`, so the attacker can also fan out
across many connections.

## Affected endpoints, ordered by per-request CPU cost

### A. `POST /v1/validateMessage` — anonymous signature verifier

File: `code\hypersnap\src\network\server.rs:2000-2022`

```rust
async fn validate_message(
    &self,
    request: Request<Message>,
) -> Result<Response<ValidationResponse>, Status> {
    let request = request.into_inner();
    let stores = self.get_stores_for(request.fid())?;
    let is_pro_user = stores
        .is_pro_user(request.fid(), &FarcasterTime::current()) ...;
    let result = validations::message::validate_message(
        &request, self.network, is_pro_user,
        &FarcasterTime::current(),
        EngineVersion::current(self.network),
    ).map_or_else(|_| false, |_| true);
    ...
}
```

No auth (`authenticate_request` is not called and the handler has no
header check), no rate limit. Every call performs:

1. A RocksDB read (`is_pro_user`).
2. A full Farcaster message validation including Ed25519 / ECDSA
   signature recovery (depending on signer scheme), hash recompute,
   timestamp window check, body-specific validity rules.

An attacker can issue this endpoint at line-rate; the signature verify
step costs ~30-100us per message of pure CPU, and the request
explicitly does not have to be well-formed for the heavy work to run.
Multiple connections multiply the cost. The mempool-side per-FID
limiter never triggers on this path because the message is never
admitted to the mempool.

### B. `POST /v1/submitMessage`, `POST /v1/submitBulkMessages` — engine simulation per request

File: `code\hypersnap\src\network\server.rs:1183-1250` (single),
`1252-1355` (bulk), `441-472` (`submit_message_internal`).

`submit_message` calls `authenticate_request` (line 1191), but
`authenticate_request` returns `Ok(())` immediately when
`allowed_users.is_empty()` (`src/network/rpc_extensions.rs:148-150`).
The standard non-validator hub configuration leaves `allowed_users`
empty so the gate is a no-op. Once past that no-op, every call runs:

1. Full `validate_message` (signature verify, hash, time-window,
   per-body validity rules) inside `simulate_message_for_shard_typed`.
2. A whole engine simulation against the destination shard's stores
   (`simulate_message_for_shard_typed`, line 452-468) — including
   RocksDB reads, signer-list look-ups, "missing fname" recovery path,
   etc.
3. Optional fname-registry lookup with a network timeout (line
   477-601) if the message references an unknown fname.

For bulk submit, the cost is N×. There is no per-IP or per-key cap on
how many bulk submits a single peer can issue.

### C. `POST /hyper/v1/messages`, `POST /hyper/v1/validator/register`, `POST /hyper/v1/validator/deregister`

File: `code\hypersnap\src\hyper\http_handler.rs:142-150, 157-258`.

These are validate-before-broadcast (as ruled in H029) so a forged-sig
flood cannot poison state, but each request consumes CPU to verify the
signature inside `runtime.submit_message` — BLS12-381 threshold-sig
verify for `RewardIssuance` / `TrustSnapshotUpdate`, Schnorr +
Pedersen-balance closure for transfers, Ed25519 + EIP-712 for
validator-register. Verify cost dwarfs decode cost. No per-IP limiter
exists on this path either. The body is also unbounded
(see F030) so the attacker can stream large bodies that all fail at
the verify step.

### D. `POST /v2/farcaster/notifications/{app_id}` — JFS verifier on anonymous input

File: `code\hypersnap\src\api\notifications\webhook_handler.rs:73-152`.

The handler runs `verify(&body, self.jfs_lookup.clone()).await`
(`webhook_handler.rs:101`) on every POST — a JSON Farcaster Signature
verification involving an Ed25519 check against an active-signer set
fetched via the `jfs_lookup`. The active-signer lookup itself may
issue an upstream HTTP call (depending on lookup impl). No rate limit;
no per-app, per-FID, or per-IP ceiling exists at the HTTP layer. The
post-hoc per-webhook `TokenBucket` in `api/webhooks/delivery.rs:373`
limits OUTBOUND delivery, not INBOUND request rate.

### E. `POST /v2/farcaster/webhook`, `POST /v2/farcaster/frame/app*` — EIP-712 verifier

File: `code\hypersnap\src\api\webhooks\handler.rs`,
`code\hypersnap\src\api\notifications\app_handler.rs`.

EIP-712 verification is `keccak256` + ECDSA recovery per request. No
rate limit on the unauthenticated pre-verify path; an attacker who
guesses a path component can grind verifier CPU.

### F. Expensive read endpoints (DoS, not just CPU)

- `GET /v1/events`, `GET /v1/eventById` — server-side event-log replay
  from RocksDB, no caller-supplied page-token validation against an
  attacker-controlled size.
- `GET /v1/onChainEventsByFid`, `GET /v1/userNameProofsByFid`,
  `GET /v1/castsByFid`, `GET /v1/reactionsByFid`,
  `GET /v1/linksByFid` — full-FID scans with paginated page-size up
  to whatever `PageOptions::page_size` the caller supplies (the
  http_server caps `limit` at 100 in `api/http.rs:783`, but the
  v1 routes pass the caller-controlled `page_size` straight through
  in many handlers).
- `GET /hyper/v1/mempool/pending`, `GET /hyper/v1/epoch/{n}/active`,
  `GET /hyper/v1/lock-tree/proof/{lock_id}`, `GET /hyper/v1/note-commitment/{hex}/proof`
  — return large serialised data structures (full validator-set
  hex-dump, full Merkle proof) read from RocksDB. Cheap per request
  but unbounded in fan-out; an attacker can chew bandwidth + CPU
  serialising responses they never read.
- gRPC `GetBlocks` (`src/network/server.rs:1357-1406`) is a streaming
  full-block response from `start_block_number` to
  `stop_block_number`, with channel capacity 100 and no rate limit.
  An attacker requesting `start=0, stop=u64::MAX` makes the node
  read every block from disk and serialise it to the wire.

### G. `admin_server.rs` debug endpoints lack auth AND rate-limit

File: `code\hypersnap\src\network\admin_server.rs`.

`submit_on_chain_event` (line 103-150), `submit_user_name_proof`
(152-203), `retry_onchain_events` (205-235), `retry_fname_events`
(237-261) DO NOT call `authenticate_request`. The first two are
gated by `allow_debug()` (devnet-only). The latter two are
unconditionally callable and trigger broadcasts on
`onchain_events_request_tx` / `fname_request_tx`. Anyone who can
reach the admin port can flood retry requests; combined with no
rate limit, this provides a side channel to amplify L1-RPC pressure
(each retry causes the on-chain-events watcher to re-poll the
external chain). The admin port is documented as operator-only but
mis-deployments where it is reachable from the public internet are
not impossible.

## Impact

For each endpoint family above:

- A and B (`/v1/validateMessage`, `/v1/submitMessage`,
  `/v1/submitBulkMessages`): anonymous remote CPU exhaustion. A single
  attacker host with a modest CPU can saturate signature verification
  on the target node, starving consensus-critical work (block import,
  proposal signing) of CPU and causing missed proposals / votes /
  attestations. The node will appear "online" (TCP accept still
  works) but lag chain progress.
- C (`/hyper/v1/messages`): same as A/B but on the hyper actor's
  signature verifier (BLS / Schnorr). Each request blocks an inbound
  `mpsc::Sender<HyperActorEvent>` slot — if the channel fills, the
  actor stalls and legitimate gossip-derived messages are dropped.
- D (`/v2/farcaster/notifications/{app_id}`): JFS lookup may issue
  upstream HTTP, providing an SSRF-adjacent amplification (each
  inbound POST = one outbound HTTP). Even without that, the verify
  step plus DB write is enough for grief.
- E (`/v2/farcaster/webhook*`): ECDSA-recover-per-request grief.
- F: bandwidth and disk-read amplification. An attacker can repeatedly
  request `GetBlocks` with a wide range and drop the TCP socket
  immediately after; the spawned task continues reading from RocksDB
  until the channel send fails.
- G: external-RPC amplification + operator confusion via log spam.

For a validator node, any of A, B, C is enough to drop it out of the
active set by missing the next epoch's participation threshold —
linking this DoS to economic damage (lost rewards, possible
slashing for missed sigs). For a read-replica RPC node, A or B is a
straight-up service outage.

The damage is amplified by:

1. CORS default `"*"` (per `docs\attack-surface.md:34`) — any web
   page can drive the attack from victims' browsers.
2. No `tower::limit::ConcurrencyLimit` on the connection acceptor
   (`main.rs:308-348`) — fan-out is unbounded.
3. F030: bodies are also unbounded so each request can be made large
   enough to consume time on the body-read step too, before the
   verify step even runs.

## Reproduction sketches

```
# A: 1k req/s of bogus-signature validateMessage. CPU pegged.
hey -z 60s -m POST -T application/octet-stream \
    -D /tmp/random-1kb-bytes \
    http://NODE:PORT/v1/validateMessage

# B: 100 concurrent submitBulkMessages each carrying 1k messages.
for i in $(seq 1 100); do
  curl -X POST -H 'Content-Type: application/octet-stream' \
       --data-binary @1k-message-bundle.bin \
       http://NODE:PORT/v1/submitBulkMessages &
done

# F (GetBlocks DoS): one request, exit immediately.
grpcurl -d '{"start_block_number":0,"stop_block_number":18446744073709551615}' \
        NODE:PORT hub.HubService/GetBlocks &
# repeat as needed; each spawns a tokio task that scans RocksDB.
```

## Recommended fix

1. Wrap the listener with `tower::limit::GlobalConcurrencyLimitLayer`
   and `tower::limit::RateLimitLayer` (or `tower_governor::GovernorLayer`
   keyed on remote IP) at the place in
   `code\hypersnap\src\main.rs:308-348` where `serve_connection` is
   called. The `governor` crate is already a direct dep — switch to
   `tower-governor` (a thin tower adapter) or use the same crate
   keyed manually per `SocketAddr` from `listener.accept()`.

2. Add a *per-route* rate limit for the expensive verify endpoints
   (`/v1/validateMessage`, `/v1/submitMessage`,
   `/v1/submitBulkMessages`, `/hyper/v1/messages`,
   `/v2/farcaster/notifications/*`, webhook/app POSTs). The mempool's
   existing per-FID `RateLimits` happens after signature-verify cost
   has already been paid; it is the wrong layer.

3. For the gRPC `GetBlocks` streaming endpoint, cap the requested
   `(stop_block_number - start_block_number)` range and reject early
   (or apply a token-bucket on bytes streamed).

4. Add a per-IP TCP accept cap (semaphore) on the listener in
   `main.rs:308-348` to bound fan-out.

5. Audit `admin_server.rs::submit_on_chain_event`,
   `submit_user_name_proof`, `retry_onchain_events`,
   `retry_fname_events` and add `authenticate_request(&request, &self.allowed_users)`
   to each (they currently skip auth and are only debug-gated).

## Notes / open questions for validator

- Confirm the deployment baseline. If every operator is documented
  as fronting the public port with an nginx/envoy/cloudflare instance
  that does per-IP rate limiting, severity is reduced from High to
  Medium (the bug is still real because that posture is not
  enforced by code). Per `docs\attack-surface.md:1.1-1.2`, no such
  baseline is documented.
- Confirm that `validate_message` does NOT short-circuit on cheap
  decode errors before reaching the signature step (a quick read of
  `validations/message.rs` suggests body decode + signature verify
  are both required). If decode failure short-circuits before
  signature, the cost per request is lower but still significant
  (decode + hash recompute).
- The mempool `RateLimits` (per-FID) docstring says capacity is
  derived from FID storage allowance. Verify this does not double
  as a rate-limit on un-mempooled traffic — it does not, but
  worth confirming the validator has read the right code path.
