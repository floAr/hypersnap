---
hunt_id: H007
specialist: chain-economics
attack_class: retro-rewards-replay
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
scope:
  - code/hypersnap/src/hyper/retro_store.rs
  - code/hypersnap/src/hyper/runtime.rs (apply_retro_vesting_tranche)
date: 2026-06-08
---

# H007 — retro-rewards-replay — RULED OUT

## Hunt question
Can the same retro vesting tranche be applied twice (missing claimed-marker,
marker keyed on mutable data, epoch rollback / double-claim across epochs)?

## What was traced

### 1. Idempotency marker is keyed on immutable data
`apply_retro_vesting_tranche` (runtime.rs:4330) gates every credit on
`RewardStore::was_issued(epoch, fid, WorkMarket::Retroactive)`. The marker
key `issued_key(epoch, fid, market)` (rewards.rs:83-90) is
`[prefix][epoch BE][fid BE][market BE u32]` — all three components are
immutable. It is NOT keyed on the mutable `remaining_atoms`. The tranche
amount is stored as the marker value but plays no role in the existence
check used for replay prevention.

### 2. Marker is persisted and never deleted
No code path deletes `RootPrefix::HyperRewardIssued` keys (grep over
rewards.rs and the hyper module finds no `del`/`remove` on issued keys).
Once a `(epoch, fid, Retroactive)` credit lands, the marker is permanent,
so re-running the same epoch is a no-op forever.

### 3. Same-epoch re-run is idempotent (tested)
`retro_vesting_is_idempotent_per_epoch` (runtime.rs:5884) confirms the
second call for epoch 0 changes neither balance nor `remaining_atoms`.
The pre-plan filter (runtime.rs:4360-4384) and the per-FID
`stage_credit_if_unissued` guard (runtime.rs:4431-4440) both short-circuit
on an already-issued triple.

### 4. Crash atomicity (F015 fix) closes the marker/decrement skew window
Each per-FID tranche commits balance + issued-marker +
`retro_store.stage_put(remaining_atoms - tranche)` in a single
`self.db.txn()` batch (runtime.rs:4430-4448, rewards.rs:221-242). A crash
cannot leave the marker written but `remaining_atoms` un-decremented (which
would have inflated subsequent tranches), nor the inverse.

### 5. Epoch source is deterministic and monotone — no rollback replay
The only production caller is `actor.rs:1281`
(`HyperActorEvent::EvaluateEpochDkls`). The `epoch` value flows from
`epoch_for_with_offset(anchor_block, cutover_snapchain_block)`
(epoch.rs:24) = `(anchor_block - cutover) / EPOCH_LENGTH` — a pure const
function of the snapchain anchor block height. The same anchor block always
maps to the same epoch; there is no way for two different anchor blocks to
re-use one epoch number such that one tranche pays twice, and re-importing a
block re-derives the same epoch (caught by the persisted marker).

### 6. Cutover re-seed cannot re-inflate remaining_atoms
The replay-via-reseed vector (re-running `apply_cutover` overwrites
`remaining_atoms` back to the full CSV value while old markers persist,
over-paying future tranches) is blocked by the `self.genesis_applied`
guard (runtime.rs:4266). On restart `genesis_applied = chain.last_height
.is_some()` (runtime.rs:393). The only window where a restart could clear
the guard is a crash after `seed_records` but before the first hyper block
is committed — and tranches only run in `EvaluateEpochDkls` (post-import),
so no tranche has executed in that window. Re-seeding identical CSV values
into a store with zero applied tranches is harmless.

### 7. Retro vs live emission are segregated markets
Retro credits use `WorkMarket::Retroactive`; live emission uses distinct
markets (emission/schedule.rs:111 documents the separation). A live and a
retro credit for the same `(epoch, fid)` occupy different marker keys by
design and do not collide, so a single block cannot trigger both a live and
retro payout for the same retro activity.

## Conclusion
The classic retro-rewards-replay failure modes (missing claimed-marker,
marker keyed on mutable data, epoch rollback, separate retro/live code path
double-pay, crash-induced marker/decrement skew) are all closed. No
confirmed finding.
