---
finding_id: F013
title: Each `/hyper/v1/lock-tree/proof` request reads every lock and rebuilds the whole tree on the async runtime (O(total locks) per
severity: info
status: pending-validation
related_findings:
- F012
- F017
---
# F013 — Each `/hyper/v1/lock-tree/proof` request reads every lock and rebuilds the whole tree on the async runtime (O(total locks) per unauthenticated request)

- **Severity:** Informational (availability of a public read endpoint. Latent at this commit.)
- **Category:** dos / resource-exhaustion
- **Specialist:** shard0-ledger-state · attack class: lock-tree-root-divergence · task H010
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Finding

`HyperV1::read` for `["lock-tree", "proof", lock_id]` (`src/node/hyper_v1.rs:212-242`) does
this on every request, including requests for a lock ID that does not exist:

1. It calls `txn.scan(&[HyperTokenLocked])`, which loads every `TokenLockState` key and value
   ever written into a `BTreeMap` (`state.rs:54-66` uses `for_each_iterator_by_prefix`, which
   forces `page_size: None`, `rocksdb.rs:639-643`). It then protobuf-decodes each value in a
   linear `find` by `lock_id`.
2. It calls `txn.scan(&[HyperBridgeLockTree])`, which loads all N leaves. A linear `position`
   finds the index.
3. It calls `Tree::build(leaves.clone())`, which computes N−1 Keccak-256 hashes and keeps all
   layers (about 2N × 32 B) to return a path of about log2 N hashes.

`handle` is `async`, but `read` is synchronous with no `spawn_blocking`
(`hyper_v1.rs:103-110`), so this work blocks a Tokio worker. Each IP is limited to 60
requests/min (`src/node/servers.rs:496-499`, applied per request at
`network/http_server.rs:5418`). There is no other limit.

**Sizing (estimate, not measured on the node).** With N = 10^6 locks, each request
materializes about 10^6 lock records (a key of about 41 B and a value of about 80 B, plus
`BTreeMap` and `Vec` overhead, roughly 150-200 MB transient). It also materializes 10^6
leaves (about 100 MB with overhead), decodes up to 10^6 protobufs, and computes 10^6 Keccaks
plus about 64 MB of layers. That is on the order of a second of CPU and a few hundred MB per
request. Each IP can send 60 of these a minute, and a few IPs can tie up the runtime's workers
and memory. N grows only through real locks. Each lock moves at least `min_bridge_amount`
(1 token, `shard0/mod.rs:143`) off Hypersnap, and the user can claim it back on L1, so the
cost is fees only. Locks are disabled at this commit (`bridge_outbound_activation_epoch =
u64::MAX`).

## Red-team

- A per-IP limiter exists, so one IP cannot flood the endpoint. The cost per request is still
  unbounded in N, and the endpoint is public by design.
- Not a consensus issue. It is the node-local read path.

## Recommendation

Store the leaf index in `TokenLockState` (or keep a `lock_id → index` key), so the lookup is
one point read. Build the proof in O(log N) reads from stored internal nodes or peaks. That
covers the in-peak path plus the other peaks, which `LockPeaks` already holds. Alternatively,
cache the tree per height. Run the handler in `spawn_blocking`. This fits with F012's
`?height=` change, which also needs the leaf prefix up to a given size.
