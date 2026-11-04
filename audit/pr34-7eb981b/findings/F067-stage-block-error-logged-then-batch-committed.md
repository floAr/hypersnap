---
finding_id: F067
title: '`BlockEngine::commit_block` and `ShardEngine::commit_and_emit_events` log a `stage_block` / `stage_shard_chunk` error and then commit the'
severity: info
status: pending-validation
related_findings:
- F033
---
# F067 — `BlockEngine::commit_block` and `ShardEngine::commit_and_emit_events` log a `stage_block` / `stage_shard_chunk` error and then commit the batch anyway. At 7eb981b the only reachable error drops a secondary timestamp-index entry. The block, header and state stay atomic. Regression of an issue raised in an earlier review round of this PR (unchanged in substance).

> **Status (2026-11-04):** Severity **Informational** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from regression pass 2026-11-04

- **Severity:** Informational, source-only. A latent trap: if `stage_*` ever gains a fallible step before the primary `put`, the state commits without its block or header, which is the divergence that the "F033" comments say this code prevents.
- **Confidence:** 0.9.
- **Category:** error handling / atomicity (defense in depth)
- **Specialist:** regression pass vs. old lineage, 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: the batch-aware `stage_block`/`stage_shard_chunk` and the "F033 fix" call sites come from the PR's audit-fix commits (`883c4a5`). Upstream used a separate `put_block`. **Regression of the earlier-round issue**: the same pattern, at new line numbers.

## Which state can be left inconsistent

- `stage_block` (`src/storage/store/block.rs:172-194`) and `stage_shard_chunk` (`src/storage/store/shard.rs:168-190`) can fail in three ways:
  1. **Missing header** (`BlockMissingHeader` / `ShardMissingHeader`). Not reachable. The callers unwrap the header first: `block_engine.rs:2227-2229` (`block.header.as_ref().unwrap()`) and `engine.rs:3352` (`shard_chunk.header.as_ref().unwrap()`). A missing header panics there, before the stage step.
  2. **Missing height** (`…MissingHeight`). Not reachable, for the same reason: `block_engine.rs:2227` (`.height.unwrap()`) and `engine.rs:3353` (`header.height.as_ref().unwrap()`).
  3. **DB read error** at `db.get(&timestamp_index_key)?` (`block.rs:190`, `shard.rs:186`). Reachable only on a RocksDB fault. It happens **after** `txn.put(primary_key, …)` (`block.rs:186`, `shard.rs:182`). So the batch still holds the block or chunk. On shard 0 of the read node, the batch also holds the state from `replay_proposal`. On a Hypersnap shard, it holds the Hypersnap block from `committing_block` (`engine.rs:3407-3421`).
- Result: the error is logged (`block_engine.rs:2271-2273`, `engine.rs:3423-3430`). Then `db.commit(txn).unwrap()` (`block_engine.rs:2274`, `engine.rs:3431`) persists everything except the `(shard, timestamp) → block` index entry. The index is read only by the timestamp lookups (`block.rs:305-307`, `shard.rs:381-383`), which would return the next block. Given an actual read fault, the following `commit(...).unwrap()` is likely to panic anyway.

## Fix

Propagate the error before committing: in both callers, `stage_*(...)` failure → do not commit, and panic or halt like the `replay_proposal` error branch next to it (`block_engine.rs:2261-2264`). Or move the fallible `db.get` ahead of the primary `put`.

## Files

- `src/storage/store/block_engine.rs:2226-2296`
- `src/storage/store/engine.rs:3343-3443`
- `src/storage/store/block.rs:162-194, 300-310`
- `src/storage/store/shard.rs:150-190, 378-385`
