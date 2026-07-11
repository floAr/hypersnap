---
id: F075
source: felirami PR#34 inline review, 2026-07-11 (comment 3562734463)
specialist: http-api-rocksdb
attack_class: swallowed-error-then-commit (atomicity / defense-in-depth)
file_paths:
  - src/storage/store/block_engine.rs
  - src/storage/store/engine.rs
  - src/storage/store/block.rs
  - src/storage/store/shard.rs
commit: f4fc4afccbd0419e04000dca0c6677fd6191afec
severity_initial: low
title: On a stage_block failure the code logs and still commits the state batch (same in the engine.rs shard-chunk path); pattern is real but the reachable impact is a dropped secondary index, not state/header divergence
validation:
  validator: http-api-rocksdb (revalidation pass, reviewer-sourced)
  verdict: PARTIAL
  confidence: 0.9
  validated_at: 2026-07-11T00:00:00Z
---

## Summary

The log-then-commit anti-pattern the reviewer describes is **present** in both
files. But an adversarial trace of the reachable failure mode shows the
reviewer's stated consequence ("commits state mutations *without the
block/header*, recreating state/header divergence") **overstates** the impact
at this commit: in the only reachable failure, the block header+body are already
in the committed batch; what is dropped is a secondary timestamp index.
Verdict: real defect, but Low / defense-in-depth, **not** the claimed P1
divergence — and not a merge blocker.

## Evidence

`src/storage/store/block_engine.rs:959-969` (F033 single-batch atomicity):
```rust
if let Err(e) = self.stores.block_store.stage_block(&mut txn, block) {
    error!("Failed to stage block write: {}", e);   // logged, NOT propagated
}
self.db.commit(txn).unwrap();                        // commits regardless
self.stores.trie.reload(&self.db).unwrap();
```
`src/storage/store/engine.rs:1844-1851` has the identical pattern for
`stage_shard_chunk`.

`stage_block` (`src/storage/store/block.rs:172-194`) has three fallible points:
(a) `BlockMissingHeader`, (b) `BlockMissingHeight`, (c) a RocksDB read at the
timestamp-index existence check (`db.get(&timestamp_index_key)?`, line 190).
The callers **pre-unwrap** header+height before calling `stage_block`
(`block_engine.rs:922`, `engine.rs:1809-1810`), so (a)/(b) are dead arms in
these paths. The **only reachable** failure is (c) — a RocksDB read IO error.
Critically the block/chunk primary-key `txn.put` (`block.rs:186`) executes
**before** that fallible read.

## Consequence (corrected)

On the reachable failure, the committed batch contains the state mutations AND
the block/chunk header+body (primary key); only the **timestamp secondary
index** is dropped. Chain head/height stays consistent (`max_block_number()`
iterates the primary key, which is committed) — no height divergence, no fork.
The block is merely not discoverable via timestamp-range queries. The
reviewer's "state without block/header" would require `stage_block` to fail
before `block.rs:186`, only reachable via the header/height arms the callers
make unreachable today.

## Severity

**Low / robustness.** Reachable worst case is a dropped secondary index on a
rare RocksDB read IO error, with block+state still atomic. It is nonetheless a
legitimate defense-in-depth fix and a latent trap: swallowing the `Err`
contradicts the F033 atomicity intent, and a future refactor that removes the
caller-side header/height unwraps — or adds a fallible op before the primary
put — would silently produce the exact state-without-header divergence F033 set
out to prevent. **Not a merge blocker.**

## Fix

Propagate/abort before `commit`: early-return the `Err` from `stage_block` /
`stage_shard_chunk` instead of logging and falling through to `self.db.commit`.

## PoC (specified, not built)

Property: if `stage_block` returns `Err`, the state batch must not be committed.
A red test would need a `#[cfg(test)]` fault seam on `BlockStore::stage_block`
(the reachable RocksDB read fault is not deterministically injectable), then
assert `current_state_root() == root_before` after `commit_block`. Given the
Low severity and the invasive test-only seam required, the PoC is specified but
not built — consistent with how the audit treats Low defense-in-depth items.
