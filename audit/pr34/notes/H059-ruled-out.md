# H059 — balance-escrow-atomicity — RULED OUT

- id: H059
- specialist: chain-economics
- attack_class: balance-escrow-atomicity
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- scope: `src/hyper/custody_escrow.rs` (+ wiring in `src/hyper/runtime.rs`, `src/hyper/actor.rs`)

## Question

Can an interrupted/reordered custody transfer double-credit or lose
balance? Is the escrow debit+credit a single atomic state transition?
Can a transfer be replayed or applied against a stale custody owner?

## Why no issue

`custody_escrow.rs` itself is only the escrow ledger store
(`balance_of` / `set_balance` / `credit`, with 20-byte address
validation and `checked_add` overflow guard). The atomic balance
movement it documents lives in `runtime.rs`. I followed it end to end.

1. Atomic debit+credit. `move_balance_to_escrow`
   (`src/hyper/runtime.rs:3548-3601`) reads the FID reward balance,
   computes `new_escrow = escrow.balance_of(from).checked_add(bal)`,
   then performs BOTH writes — zero the FID reward-balance key and set
   the escrow key — in one `self.db.txn()` batch committed via
   `self.db.commit(batch)` (lines 3581-3599). Debit and credit are a
   single RocksDB transaction; a partial application is not possible.
   No double-credit: the source is zeroed in the same batch that
   credits escrow.

2. Interrupted transfer (crash-safety). The watcher
   `process_pending_custody_transfers`
   (`src/hyper/runtime.rs:1511-1568`) calls `move_balance_to_escrow`
   (line 1557) and then writes the dedup marker in a SEPARATE put
   (lines 1560-1563). The ordering is move-then-mark and is
   crash-safe by construction: if the process dies after the atomic
   move but before the marker, the next epoch re-walks the event,
   the marker is absent, but `move_balance_to_escrow` now reads a
   zero FID balance (`bal == 0 → return Ok(0)`, lines 3563-3565) and
   is a clean no-op. The marker is then re-set. No double-move.

3. Replay protection. Dedup key `(fid, transaction_hash, log_index)`
   under `HyperEscrowTransferProcessed`
   (`escrow_transfer_processed_key`, lines 1570-1577) is checked
   before each move (lines 1540-1553); once set the event is never
   reprocessed. `log_index` is unique within a tx, so distinct
   transfers cannot collide. The claim/bridge debit paths
   (`apply_token_escrow_claim` 1624-, `apply_token_escrow_bridge`
   3447-3529) are each a single atomic batch (zero escrow + credit/
   lock + bump nonce) guarded by strict nonce monotonicity
   (`expected = current+1`, NonceMismatch otherwise), so re-applying
   the same claim/bridge fails. The bridge additionally nullifies on
   `lock_id` collision (lines 3481-3490).

4. Stale custody owner. Escrow is keyed by the specific event's
   `body.from` (the previous custodian at that transfer), not a
   mutable "current owner" lookup (line 1557, 3592). Transfer events
   are stored under primary key `[type][fid][block_number][log_index]`
   (`make_onchain_event_primary_key`,
   `src/storage/store/account/onchain_event_store.rs:72-79`) and
   iterated forward, so multiple historical transfers for one FID are
   processed in chronological order. Each move drains exactly the
   balance accrued under the prior custodian and attributes it to that
   custodian. No reordering or stale-owner misattribution.

5. No concurrency / no laundering. The runtime is single-threaded
   (`&mut self` on every apply path); the only production caller is the
   epoch-driven actor loop (`src/hyper/actor.rs:1301`, `:1313`), and
   `old_custody_address` is sourced from the on-chain event `body.from`,
   never from user-supplied message data. There is no path for a user
   to redirect their balance to an attacker-chosen escrow address.

Conclusion: the escrow debit+credit is a single atomic RocksDB
transaction; interruption, reordering, replay, and stale-owner
application are all prevented. No balance-escrow-atomicity defect.
