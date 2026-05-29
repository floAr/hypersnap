# PoC — F160 LIVE_AT rate limiter node crash (PR #32, `4a6bca5`)

Runnable behavioral witness for [F160](../../findings/F160-live-at-rate-limiter-unwrap-panic-on-non-hosted-shard-fid.md),
described in [`../../REVALIDATION-4a6bca5.md`](../../REVALIDATION-4a6bca5.md) and validated in
[`../../notes/F160-validation.md`](../../notes/F160-validation.md).

## What it proves

PR #32's new FIP-268 `LiveAtRateLimits::consume_for_fid` does
`self.shard_stores.get(&route_fid(fid, num_shards)).unwrap()` at `src/mempool/mempool.rs:212`.
`num_shards` is the network-wide shard count, but `shard_stores` only holds the shards this
node actually hosts (`config.shard_ids`, populated in `snapchain_node.rs:83-123`). On the
standard subset-hosting topology (`num_shards = 2`, `shard_ids = [1]`) roughly half of all FIDs
route to a shard absent from `shard_stores`, so `get()` returns `None` and `.unwrap()` panics —
crashing the mempool task (and the node). Unlike the pre-existing general `RateLimits` (gated
behind `enable_rate_limits`, default `false`), the LIVE_AT limiter is **always-on**, so this is
reachable **by default** and via unauthenticated gossip ingress (`MempoolSource::Gossip`). A
legitimately-signed LIVE_AT for any FID on a non-hosted shard triggers it — no forgery required,
so it is also an honest-traffic stability bug, not solely an adversarial DoS.

## Result

```
thread '...f160_poc_live_at_unwrap_panic_on_non_hosted_shard' panicked at
  src/mempool/mempool.rs:212:59:
called `Option::unwrap()` on a `None` value
test result: ok. 1 passed; 0 failed; ... finished in 0.20s
```

Full captured run: [`f160-poc-4a6bca5.log`](f160-poc-4a6bca5.log).

## How to run

The PoC (`f160_poc.rs`) is a `#[tokio::test]` designed to be inserted into the
`#[cfg(test)] mod tests` block at the bottom of `src/mempool/mempool_test.rs` (it reuses that
module's imports: `Mempool`, `mempool::Config`, `Stores`, `test_helper`, `create_user_data_add`,
`MempoolMessage`, etc.). The stock `setup(..)` helper always populates `shard_stores` with shards
`1..=num_shards`, so it cannot model the subset-hosting topology the bug requires; the PoC instead
builds the `Mempool` directly with `num_shards = 2` but `shard_stores = {1}` only (mirroring
`snapchain_node.rs:83-123`), with `enable_rate_limits = false` (DEFAULT — proving the LIVE_AT
limiter is always-on), then delivers a `UserDataType::LiveAt` for FID 2 (which `route_fid` maps to
the non-hosted shard 2) via `MempoolRequest::AddMessage(.., MempoolSource::Gossip, ..)`.

Built and run under WSL nightly against the PR tip `4a6bca5` (the tree compiles, 0 errors):

```bash
# insert f160_poc.rs into src/mempool/mempool_test.rs mod tests, then:
CARGO_TARGET_DIR=target-wsl-pr32 cargo +nightly test --lib \
  f160_poc_live_at_unwrap_panic_on_non_hosted_shard -- --nocapture
# restore afterwards:
git checkout -- src/mempool/mempool_test.rs
```

(Nightly is used only because stable rustc 1.95.0 ICEs on the unchanged `ed448-bulletproofs`
dependency — an environmental toolchain issue, not a property of the commit.)

- **Bug present (`4a6bca5`):** the mempool task panics at `mempool.rs:212` (`Option::unwrap()` on
  `None`); the reply channel sender is dropped, the task aborts — a remote, unauthenticated,
  default-config node crash.
- **After fix** (graceful non-hosted-shard handling): no panic; the LIVE_AT for a non-hosted-shard
  FID is rejected/skipped without crashing.

## Fix

Replace the `shard_stores.get(&shard_id).unwrap()` (and the companion
`get_storage_limits(fid).unwrap()`) with a non-panicking path — when the routed shard is not hosted
locally, fall through to a neutral decision or reject without crashing, mirroring how
`message_already_exists` already tolerates a missing store (`mempool.rs:444-448`). Same fix applies
to the pre-existing `RateLimits::get_rate_limiter_for_fid`. Inherited verbatim from snapchain
v0.12.0 — worth routing upstream as well.
