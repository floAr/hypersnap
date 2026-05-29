# F160 validation — LIVE_AT rate limiter unwrap panic on non-hosted shard

**Verdict:** WATERPROOF
**Confidence:** 0.97
**Validated at:** 2026-05-29
**PoC:** RUNNABLE & CONFIRMED — [`../poc/F160-live-at-shard-panic/f160_poc.rs`](../poc/F160-live-at-shard-panic/f160_poc.rs), log [`../poc/F160-live-at-shard-panic/f160-poc-4a6bca5.log`](../poc/F160-live-at-shard-panic/f160-poc-4a6bca5.log).

## PoC result (runnable, this workspace requires it)
Built and run on WSL nightly against the PR tip `4a6bca5` (tree compiles, 0 errors):
```
CARGO_TARGET_DIR=target-wsl-pr32 cargo +nightly test --lib \
  f160_poc_live_at_unwrap_panic_on_non_hosted_shard -- --nocapture
```
Output:
```
thread '...f160_poc_live_at_unwrap_panic_on_non_hosted_shard' panicked at
  src/mempool/mempool.rs:212:59:
called `Option::unwrap()` on a `None` value
test result: ok. 1 passed; 0 failed; ... finished in 0.20s
```
The PoC builds `Mempool` with `num_shards=2` but `shard_stores={1}` (subset-hosting, mirroring `snapchain_node.rs:83-123`), with `enable_rate_limits=false` (DEFAULT — proving the LIVE_AT limiter is always-on), then delivers a `UserDataType::LiveAt` for FID 2 (which `route_fid` maps to the non-hosted shard 2) via `MempoolRequest::AddMessage(.., MempoolSource::Gossip, ..)`. The mempool task panics at the exact claimed site `mempool.rs:212` (`shard_stores.get(&shard_id).unwrap()`). Confirms a remote, unauthenticated, default-config node crash.

## 8-hypothesis red-team (refutation attempts)
1. **shard_stores only hosted shards?** CONFIRMED — populated from `config.shard_ids` (`snapchain_node.rs:83-123`), the hosted subset; not all `1..=num_shards`. Refutation fails.
2. **route_fid uses network-wide num_shards?** CONFIRMED — `(sha256(fid)%num_shards)+1` over `consensus.num_shards`, independent of `shard_ids` (`routing.rs:12-19`, `consensus.rs:49-50`). Can return a non-hosted shard. Refutation fails.
3. **Earlier shard-ownership filter on gossip ingress?** NONE — gossip mempool messages enter as `MempoolSource::Gossip` and route to `route_fid`'s shard with no hosted-shard drop before `consume_for_fid` (`mempool.rs:899/947/813/712`). RPC path is shard-simulated, gossip is not. Refutation fails.
4. **LIVE_AT limiter gated by a flag?** NO — constructed unconditionally (`mempool.rs:674-678`), consulted for every LIVE_AT (`mempool.rs:712-719`); PoC sets `enable_rate_limits=false` and still panics. Refutation fails.
5. **Needs to be a LIVE_AT specifically?** YES — `is_live_at` gates the limiter; but LIVE_AT is a normal user-data type, trivially constructed (PoC uses `create_user_data_add(.., LiveAt, ..)`). Not a mitigating factor.
6. **Pre-auth / signature gate drops it first?** NO — the limiter runs at mempool admission inside `message_is_valid(.., at_admission=true)` before engine/signature validation; and a *legitimately-signed* message from any real FID on a non-hosted shard triggers it (no forgery needed). Refutation fails.
7. **Single-shard deployments?** CORRECT scoping — when `shard_ids == {1..=num_shards}` every routed shard is hosted, no panic. This bounds severity to subset-hosting topologies (the standard production multi-shard layout). → High, not Critical.
8. **Honest-traffic trigger (stability vs DoS)?** CONFIRMED — honest mainnet LIVE_AT traffic for FIDs on other shards crashes subset-hosting nodes with no attacker. Both a stability bug and a remote DoS amplifier.

## Severity
**High.** Remote, unauthenticated, low-effort, default-reachable node crash on the standard sharded topology; honest-traffic-triggerable; fleet-wide via gossip flooding across FIDs. Not fund-loss / no state corruption, and single-shard deployments are immune → High not Critical. Testnet live; mainnet arms at V17 activation (2026-06-04).

## Parity
Upstream-inherited (verbatim from snapchain v0.12.0). Newly reachable-by-default via the PR#32 LIVE_AT port. Route upstream as well.

## Caveat
The companion `stores.get_storage_limits(fid).unwrap()` (`mempool.rs:213`) is a lower-priority internal-fault panic (RocksDB read error), not attacker-chosen; shares the same fix.
