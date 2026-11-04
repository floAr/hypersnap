---
finding_id: F068
title: On shards 1 and 2, `ShardBlockProducer::commit` compares the Keccak root with the certified header's `state_root` only **after**
severity: low
status: pending-validation
related_findings:
- F067
- F045
- F027
---
# F068 — On shards 1 and 2, `ShardBlockProducer::commit` compares the Keccak root with the certified header's `state_root` only **after** `hypersnap_commit` has written the state, the block and the chunk to RocksDB. A mismatch then panics ("stopping is safer than continuing"), but the divergent state is already durable under the certified block. On restart the node builds on that state and cannot recover by restarting or by a hotfix. Shard 0 does the check before its write. The same path also covers a failed Keccak-trie update: `stage_shadow_trie` logs it, disables the trie and commits the stores without the trie writes. Its comment says "the next start rebuilds it", but in Hypersnap mode a `Live` trie is not rebuilt.

- **Severity:** Low, source-only. No attacker path was found. This finding does not create a divergence. It turns any divergence on a data shard into persistent corruption that needs a full resync. Causes include a determinism bug, a node-local input, or a disk or read fault during the trie update. Fixing the cause and restarting does not repair the node. Today it affects only the node that diverges.
- **Confidence:** 0.8 for the code path and ordering. The consequences after restart are reasoned from source and were not run.
- **Category:** column-family-atomicity-around-fork / rocksdb-batch-write-partial (check-after-commit)
- **Specialist:** http-api-rocksdb · task H043
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard_blocks.rs`, `ShardEngine::hypersnap_commit` and `stage_shadow_trie` are absent at the merge base `bdef7b7` (grep for `fn hypersnap_commit` and `fn stage_shadow_trie` in `git show bdef7b7:src/storage/store/engine.rs` finds nothing).
- **PoC:** None (not built). Test sketch: in a two-shard engine test, commit a decided data-shard block whose header `state_root` is one byte off. Expect `ShardBlockError::StateRoot`. Then reopen the DB: `HypersnapBlockStore::last()` returns that block, and the store contents include its messages. Do the same with shard 0's `Shard0Engine::commit`: the DB is unchanged.

## Code facts

1. **The commit writes first.** `ShardBlockProducer::commit` calls `engine.hypersnap_commit(&block)` (`src/chain/shard_blocks.rs:538-542`). Only then does it compare `root` with `header.state_root` and return `StateRoot` (`:543-548`).
2. **`hypersnap_commit` makes the batch durable.** It sets `committing_block` and calls `commit_shard_chunk` (`src/storage/store/engine.rs:838-840`). This reaches `commit_and_emit_events`. That function puts the encoded block under `HypersnapBlock` in the same batch (`:3411-3417`), stages the chunk header and the shadow trie, and runs `self.db.commit(txn).unwrap()` (`:3424-3431`). The root is read afterwards with `self.state_root()` (`:841`).
3. **Nothing checks the root before the write.** On a cache miss, `replay_proposal` skips its root check in Hypersnap mode, because `shard_root` is empty. The comment says "the caller checks the Keccak root against the block header instead" (`engine.rs:1338-1341`, `blake3_root = vec![]` at `:827-830`). The cache-hit path checks only the blake3 root of the cached execution (`:3636-3646`).
4. **The caller panics after the write.** `HypersnapShardProposer::decide` does `panic!("Committing a decided Hypersnap block failed …")`, with the comment "State divergence: stopping is safer than continuing" (`src/chain/proposer.rs:329-332`). By then the block and state are committed. On restart, `tip_header()` reads the block from the store (`shard_blocks.rs:301-310`), so the next height is `H+1` and runs on top of the divergent state.
5. **Shard 0 does the opposite.** `Shard0Engine::commit` stages the trie, compares the root, reloads the trie and returns an error before `txn` is built and committed (`src/chain/shard0/engine.rs:1123-1136`).
6. **A trie-update failure is swallowed.** In `stage_shadow_trie`, an `Err` from `stage_chunk_with_ops` is logged and `self.shadow_trie = None` (`engine.rs:1009-1017`), with the comment "Diagnostic structure: never stop the shard for it. Drop it for this run; the next start rebuilds it." The batch is then committed without the trie nodes and without a new `Live{height}` status (`shadow_trie.rs:279-305`; the status is staged only in `commit_live`). The stores and the block do get committed. `state_root()` then returns `None`, so `hypersnap_commit` returns `HashMismatch` (`engine.rs:841`), and fact 4 applies.
7. **The trie is not rebuilt on restart in Hypersnap mode.** `enter_hypersnap_mode` accepts `ShadowStatus::Live{..}` as is (`engine.rs:447-448`). `enable_shadow_trie`, which rebuilds, is called only by the snapchain read node (`src/node/snapchain_read_node.rs:133`) and returns early for `Live` (`engine.rs:859-862`). After a restart the trie is `Live{H-1}`, while the stores and block are at `H`. Block `H+1` then applies its events to the `H-1` trie (`stage_chunk_with_ops` requires only `height > last`, `shadow_trie.rs:286-289`). Every later root on this node is wrong.

## Failure path

1. A data-shard node commits decided block `H` in one of two cases. (a) It did not validate the proposal: it is lagging, syncing, or saw only the decision, so the path replays the block with no root check. (b) The trie update fails because of a read error or a missing trie node.
2. In case (a) with any local divergence, or in case (b), the batch with the stores, the chunk header and block `H` is committed, possibly without the trie writes.
3. The root comparison fails, and `decide` panics.
4. After restart, the node's tip is the certified block `H`, and its state does not match `H.state_root`. Each later block fails the same way: it is committed, then the node panics. So each restart persists one more divergent block. The only recovery is to wipe the shard DB and resync or reinstall a snapshot. Even when the cause is a bug that a new release fixes, the hotfix does not help: block `H` stays committed wrongly.

## Red-team

1. *A decided block was validated by ≥ 2/3, so is a mismatch impossible?* A mismatch is possible on a node that diverges, which is exactly the case the check is for. The check only helps if it runs before the write.
2. *Is this F067?* F067 is about `stage_shard_chunk` / `stage_block` errors being logged before the commit; the reachable case is a lost timestamp-index entry. This finding is about ordering: the consensus root check runs after the commit, and a failed commitment-trie update is swallowed. The fixes differ. Link them.
3. *Can an attacker trigger it?* Not found. A block that fails `root_with_ops` during validation does not get decided, because validation uses the same trie apply (`engine.rs:695-707, 736, 778`; `shadow_trie.rs:332-342`). So input from peers cannot make a decided block fail to apply. That is why this is Low.
4. *Does the panic leave the stores and the trie consistent at least?* Case (a): yes, they agree with each other, but not with the network. Case (b): no. The stores are at `H` and the trie at `H-1`, which cannot be repaired without a rebuild.
5. *Does the shard self-heal by resync?* Sync goes through the same `decide` → `commit` path. The node never rolls back, because no code deletes a committed `HypersnapBlock` above a height except `prune_below`, which removes heights below.
6. *Is the "diagnostic structure" comment right for snapchain mode?* Yes. Before the pivot the shadow trie is diagnostic, and `enable_shadow_trie` rebuilds it. The flaw is that the same branch runs after the pivot, when the trie is the consensus commitment.
7. *Does a power loss produce the same state?* No. The batch is a single RocksDB transaction (`rocksdb.rs:407-…`), so a crash or power loss is atomic. This finding is about the logical ordering, not partial writes.
8. *Is the impact overstated?* It is limited to nodes that already diverge. The extra harm is that a transient fault becomes permanent and a fixable bug needs a resync. Low fits.

## Fix

- In `hypersnap_commit`, compute the Keccak root before `db.commit`. Either stage the trie, compare with `header.state_root`, and abort without committing (as `Shard0Engine::commit` does), or pass the expected root into `commit_and_emit_events` and check it after `stage_shadow_trie` and before `self.db.commit`. On a mismatch, roll back the trie (`trie.rollback()` / `reload`) and return an error. Nothing should be written.
- In Hypersnap mode, an `Err` from `stage_shadow_trie` must stop the commit and leave the batch uncommitted. Keep the "drop it for this run" behaviour only when `!self.hypersnap_mode`.
- Optionally, at start-up in Hypersnap mode, check that the trie's `Live{height}` equals the shard's last chunk height, and refuse to start if it does not.

## Files

- `src/chain/shard_blocks.rs:524-548`
- `src/storage/store/engine.rs:807-842, 965-1018, 1331-1352, 3404-3431`
- `src/storage/trie/shadow_trie.rs:279-305`
- `src/chain/proposer.rs:329-332`
- `src/chain/shard0/engine.rs:1123-1136` (correct ordering, for comparison)
