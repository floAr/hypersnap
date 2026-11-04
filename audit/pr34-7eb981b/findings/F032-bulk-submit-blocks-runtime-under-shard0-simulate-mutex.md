---
finding_id: F032
title: '`SubmitBulkMessages` counts as one request for the per-IP limiter, yet carries about 25k messages in 4 MiB'
severity: medium
status: pending-validation
related_findings:
- F030
---
# F032 — `SubmitBulkMessages` counts as one request for the per-IP limiter, yet carries about 25k messages in 4 MiB. On a Hypersnap node, shard-0 batches are simulated synchronously on a tokio worker while a `std::sync::Mutex` over the one simulate engine is held, and every message gets a full Ed25519 check before any state lookup. A single IP within its 120/min quota keeps that mutex busy all the time, and each concurrent shard-0 submit then parks a runtime worker thread on the mutex. With as many in-flight calls as there are cores, the node's only multi-thread runtime, which also runs Malachite, gossip and the mempool, stops making progress.

- **Severity:** Medium. One IP can stall a validator's async runtime, or at least block every honest shard-0 submission to that node, for as long as the attack runs. Hitting several validators takes them offline at the same time without any crash. Exposure: the shipped mainnet compose publishes 3383/3381. Raise it to High if a load test confirms the runtime-wide stall (the per-message CPU figures below are estimates).
- **Category:** rate-limit-missing (limiter granularity) / blocking work on the async runtime
- **Specialist:** http-api-rocksdb · attack class: rate-limit-missing · task H038
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). `hypersnap_rpc.rs` and `rate_limit.rs` are new. The shard-0 bulk path in `server.rs:1196-1203, 1251-1270` is new; upstream rejects bulk for shard 0 (`:1204-1212`).
- **Trigger:** gRPC `SubmitBulkMessages` on `rpc_address`, or HTTP `POST /v1/submitBulkMessages` on `http_address` (`http_server.rs:5668-5675`, same handler). No authentication by default (`allowed_users` empty → `authenticate_request` returns `Ok`, `rpc_extensions.rs:157-163`).
- **PoC:** None (source-only). Sketch: generate one Ed25519 key, then build about 25k shard-0-routed messages (any `is_hypersnap()` type, `routing.rs:63-64`) with correct blake3 hash and signature and a minimal body. Send 16–32 such bulk calls concurrently over one HTTP/2 connection (≤ 64 streams, `servers.rs:440`). Measure tokio worker utilisation, the Malachite round timeouts and `rpc.submit_message.duration` for an honest client.

## Code facts

1. **The limiter is per RPC.** The interceptor calls `allow(ip)` once per call (`servers.rs:426-434`). `submit_bulk_messages` puts no limit on `messages.len()` (`server.rs:1652-1690`). The only bound is tonic's 4 MiB decode limit (HTTP: `MAX_HTTP_BODY_BYTES` = 4 MiB). A minimal Ed25519 message (hash 20 B, signature 64 B, signer 32 B, short `data_bytes`, framing) is about 160 B, so one call carries about 25k messages.
2. **Shard-0 batches go to one mutex-guarded engine.** On a Hypersnap node, `simulate_bulk_messages_for_shard` → `simulate_hypersnap` → `hypersnap.simulate_shard0(messages)` (`server.rs:1191-1203, 1264-1270`) → `engine.lock().unwrap().simulate_messages(..)` (`network/hypersnap_rpc.rs:78-97`). `NodeRpc.shard0` is `Option<std::sync::Mutex<Shard0Engine>>` (`hypersnap_rpc.rs:12, 37`; built at `hypersnap_main.rs:1009`). The lock is held for the whole batch.
3. **The work runs inline on a runtime worker.** None of these calls uses `spawn_blocking` or `block_in_place`. The file even defines `run_blocking` for this purpose (`server.rs:94-104`) but uses it only for the cast scan (`:4139`). The process runs one `new_multi_thread()` runtime with default worker count = cores (`src/main.rs:161-163`), shared with consensus.
4. **Every message costs an Ed25519 check before any cheap rejection.** `simulate_messages` calls `apply_message` per message (`shard0/engine.rs:264-302`) → `auth::open` (`engine.rs:437`). `auth::open` decodes, checks the hash, then runs `verify_ed25519` (`auth.rs:139, 168-175`), and only after that resolves the FID or signer. Fresh random keys are free, so every message pays a full verify (about 40–60 µs), or about 1–1.5 s of CPU per 25k-message call with the mutex held.
5. **Replays are quadratic.** If a message fails after touching state (`dirty`), all previously accepted messages in the batch are re-applied from a fresh `BlockState` (`engine.rs:287-296`). A batch alternating "accepted" and "dirty-failing" messages costs O(n²) `apply_message` calls. This needs messages that pass for a real FID, so it is a secondary lever (see leads).

## Attack

1. The attacker sends shard-0 bulk calls of about 25k self-signed messages at 2/s (120/min, within the limit). Each holds the simulate mutex for about 1–1.5 s, so the mutex is permanently busy. Every honest shard-0 submit to this node (transfers, stakes, bridge locks, DA responses submitted over RPC) queues behind it, and this one IP sets the rate.
2. Each queued call is a tokio task blocked in `std::sync::Mutex::lock`, which parks its worker thread. The attacker keeps ≥ `num_cpus` calls in flight. Arrivals (2/s) are faster than service (≤ 1/s), so the queue grows by itself. At that point all worker threads are either running Ed25519 under the lock or parked on it. Timers, Malachite actors, gossip and mempool tasks on the same runtime starve, the validator misses proposal and vote deadlines, and it is effectively offline while the attack lasts.
3. Shards 1/2 are similar without the mutex. `ShardEngine::simulate_bulk_messages` runs on the worker for the whole batch (`server.rs:1271-1290`), so the attacker needs a few IPs instead of one.

## Red-team (invalidation hypotheses walked)

1. *Does the per-FID mempool limiter stop it?* No. It runs at mempool insert, after simulation. All the CPU and lock time is spent first. Messages from unknown FIDs fail in simulation and never reach the mempool.
2. *Is the simulate engine shared with the proposer?* No. `NodeRpc.shard0` is a separate engine "used only to simulate" (`hypersnap_rpc.rs:36-37`), so consensus does not wait on this lock directly. The harm comes through the shared runtime threads, not lock sharing. That is why the severity is Medium pending a load test.
3. *Does the bulk version gate block it?* `DependentMessagesInBulkSubmit` is checked against the pivot record's engine version (`server.rs:793-806, 1657`). This is a long-enabled snapchain feature, so it is assumed on. If it were off, bulk would be refused entirely.
4. *Is the 4 MiB cap really the only bound?* Yes. `HubServiceServer::from_arc` has no `max_decoding_message_size` override (tonic default 4 MiB), and there is no `messages.len()` check.
5. *Spec?* The FIP says nothing about RPC ingress. This is not a spec-divergence.

## Recommendations

- Charge the limiter per message: cap `messages.len()` (e.g. ≤ 100) and debit the IP bucket by the batch size, or reject bulk on shard 0 as upstream does.
- Run simulation on the blocking pool (`spawn_blocking` / the existing `run_blocking`), and use `tokio::sync::Mutex`, or a small pool of simulate engines, so that waiters do not park runtime workers.
- Make `auth::open` reject cheaply before the signature check where possible (unknown FID / signer lookup first), or bound per-call verification work.
- Consider giving consensus its own runtime, separate from the RPC/HTTP servers.
