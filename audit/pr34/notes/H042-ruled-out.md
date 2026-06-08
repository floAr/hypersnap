---
id: H042
specialist: http-api-rocksdb
attack_class: column-family-atomicity-around-fork
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
scope:
  - src/storage/db/**
  - src/storage/store/**
---

# H042 — Multi-CF write atomicity around block import / fork — RULED OUT

## Hunt

Look for related writes during block/shard import or fork handling that are
committed as separate puts rather than one atomic `RocksDbTransactionBatch`,
which a crash/reorg could leave half-applied (e.g. block header at height H
but trie/state at H-1, or a primary record without its secondary index).

## Storage model

This codebase does **not** use RocksDB column families. Type separation is
done via single-byte key prefixes (`RootPrefix`, `src/storage/constants.rs`).
The atomicity unit is `RocksDbTransactionBatch` (`db/rocksdb.rs:31-61`),
committed in one shot by `RocksDB::commit` which opens a single
`TransactionDB` transaction, applies every staged put/delete, and calls
`txn.commit()` (`db/rocksdb.rs:377-395`). So "multi-CF atomicity" here means
"are all related prefix-keyed writes staged onto the same batch before the
single commit."

## Paths traced (all atomic)

1. **Block import — `BlockEngine::commit_block`** (`store/block_engine.rs:916-986`).
   `replay_proposal` stages state mutations onto `txn`, then
   `block_store.stage_block(&mut txn, block)` stages the block record + the
   `BlockIndex` timestamp index onto the **same** `txn`
   (`store/block.rs:172-194`), then one `self.db.commit(txn)`. This is the
   F033 fix (explicit comment at lines 955-963: previously separate commits
   could leave trie at H and header at H-1).

2. **Shard import — `ShardEngine::commit_shard_chunk` → `commit_and_emit_events`**
   (`store/engine.rs:2042-2112`, `1802-1862`). State mutations, the
   `BlockConfirmed` event, the shard-chunk record + `BlockIndex` timestamp
   index (`shard_store.stage_shard_chunk`, `store/shard.rs:168-190`), and all
   emitted hub events are staged onto one `txn`, committed once at line 1851,
   trie reloaded after. F033 comment at lines 1838-1843.

3. **On-chain event merge** (`store/account/onchain_event_store.rs:81-94`,
   `merge_onchain_event`): primary event record (`txn.put`, line 93) and
   **all** secondary indices (`build_secondary_indices`: id-register-by-fid,
   signer, etc., lines 125-268) are staged onto the same `txn`. The
   `OnchainEventStore::merge_onchain_event` wrapper (577-594) also stages the
   `MergeOnChainEvent` hub event onto the same `txn` via `commit_transaction`.

4. **Hub event id allocation** (`store/account/event.rs:122-139`,
   `put_event_transaction:173-183`): the event-id generator is in-memory and
   height-derived (no separately-persisted counter that could desync on a
   fork); the event record write goes to the supplied `txn`.

5. **Hyper dual-writes & fee fingerprint** (`store/engine.rs:1305-1369`):
   staged onto the same `txn_batch`; code explicitly notes the CastAdd
   fingerprint "MUST NOT be a direct db.put" and must share the batch.

## Standalone `db.put` / `db.del` (outside any batch) — all benign

Non-test direct writes that bypass batching are confined to **node-local
consensus bookkeeping**, none of which must be atomic with committed block
state:

- `store/node_local_state.rs`: `put_proposal` / `delete_proposals` (in-flight
  consensus proposals, deleted after decide), `set_latest_block_number`
  (L2 ingest cursor), `set_latest_fname_transfer_id` (fname ingest cursor),
  `set_onchain_events_migration_page_token` (migration resume token). These
  are idempotently re-derivable cursors / transient proposal records; a
  crash/reorg re-reads source-of-truth (the committed chain) and re-advances.
- `store/stores.rs:394` `set_schema_version` and `store/migrations/mod.rs:90`
  — migration-time only, not on the block-import hot path.

## Conclusion

Every multi-prefix write on the block-import / shard-commit / fork-replay
path is staged onto a single `RocksDbTransactionBatch` and committed
atomically. The atomicity gap this hunt targets was already closed by the
prior F033 fix (block/shard header now batched with state). Remaining loose
`db.put`/`db.del` are node-local, re-derivable bookkeeping that intentionally
sits outside block atomicity. No confirmed finding.
