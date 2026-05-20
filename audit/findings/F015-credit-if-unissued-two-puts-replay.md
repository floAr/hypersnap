---
id: F015
task: H015
specialist: chain-economics
attack_class: retro-rewards-replay
severity: medium
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# `credit_if_unissued`'s balance-then-issued-key writes are two unbatched RocksDB puts; a crash between them lets the next pass re-credit the same `(epoch, fid, market)` tranche, and the retro path adds a third unbatched `retro_store.put` that on crash leaves `remaining_atoms` un-decremented and over-pays the remainder of the §10.5 vesting schedule

## Summary

`RewardStore::credit_if_unissued`
(`src/hyper/rewards.rs:186-207`) is the single join point that both the
live `apply_reward_issuance` and the retro `apply_retro_vesting_tranche`
paths reach. The function takes the same `(epoch, fid, market)`
replay-prevention key documented in the module header as "re-importing
the same issuance is a no-op" (`src/hyper/rewards.rs:11`). It implements
the gate as **two separate, unbatched** `RocksDB::put` calls — one for
the recipient's balance and one for the issued-key — rather than the
`db.txn() / commit` pattern every other state-mutating method in the
same file uses (`apply_lock` 326-333, `apply_transfer` 398-418,
`apply_fee_deposit` 471-481, `drain_proposer_fee_pot` 632-641). The two
calls each generate an independent WAL record. A power/OS crash between
them leaves the balance bumped but the issued-key absent. On replay (or
on the next epoch pass after restart) `was_issued` returns false,
`credit_if_unissued` recomputes `balance_of + amount` against the
already-bumped value, and writes a second credit — double-payment of
the tranche.

The retro path layers a second, independent atomicity gap on top: after
the `credit_if_unissued` call,
`HyperRuntime::apply_retro_vesting_tranche`
(`src/hyper/runtime.rs:4101-4107`) does a *third* unbatched
`retro_store.put(&rec)` to persist the decremented `remaining_atoms`. A
crash between the rewards write and the retro_store write leaves the
issued-key set (so this epoch's tranche is replay-safe) but
`remaining_atoms` un-decremented. Every subsequent epoch in the §10.5
29-tranche schedule then computes
`tranche = remaining_atoms / (n - epoch)` against the *unchanged*
`remaining_atoms`, and every subsequent epoch over-pays. By the final
epoch (`remaining_tranches == 1`,
`src/hyper/runtime.rs:4093-4097`), the sweep
pays the original full `remaining_atoms` instead of the residual,
delivering up to `n / (n-1)` × the intended allocation to that FID over
the schedule.

This is the textbook `retro-rewards-replay` shape from the
chain-economics checklist: "Retro-rewards (paid for past activity at
chain launch) often go through a separate code path from live emission.
Without careful state-tracking, a single block can trigger both live and
retro rewards for the same activity." Here the live and retro paths
share the *same* join point and both inherit the same broken
state-tracking; the retro path additionally inherits a second broken
state-tracking step that the live path doesn't have.

## Description

### `credit_if_unissued` is the documented idempotency gate

The module header at `src/hyper/rewards.rs:1-11` is explicit: the
`(epoch, fid)` key "means re-importing the same issuance is a no-op,"
and the `apply_retro_vesting_tranche` doc-comment doubles down on this
contract — "Re-running the same epoch on a runtime where the issuance
store already has the credit is a no-op — neither the balance nor the
retro record changes. This is the property that makes block re-import
safe." (`src/hyper/runtime.rs:4054-4058`). Both contracts hold only if
the balance write and the issued-key write are either both visible or
both absent after a crash. The current implementation does not enforce
that.

### The implementation: two unbatched puts

```rust
// src/hyper/rewards.rs:186-207
pub fn credit_if_unissued(
    &self,
    epoch: u64,
    fid: u64,
    market: i32,
    amount: u64,
) -> Result<bool, RewardError> {
    if self.was_issued(epoch, fid, market)? {
        return Ok(false);
    }
    let new_balance = self
        .balance_of(fid)?
        .checked_add(amount)
        .ok_or(RewardError::BalanceOverflow { fid })?;
    self.db
        .put(&Self::balance_key(fid), &new_balance.to_be_bytes())   // (A)
        .map_err(HubError::from)?;
    self.db
        .put(&Self::issued_key(epoch, fid, market), &amount.to_be_bytes())  // (B)
        .map_err(HubError::from)?;
    Ok(true)
}
```

The two `db.put` calls each go through
`RocksDB::put` (`src/storage/db/rocksdb.rs:355-362`), which is a direct
`db.put(key, value)` against the underlying Transaction DB **outside**
any batch. By contrast, every other state-mutating method in the same
file uses the atomic `db.txn() → batch.put(...) → db.commit(batch)`
pattern (`src/storage/db/rocksdb.rs:373-395`), which wraps the writes in
a `txn.commit()` so either all of them land or none do. The asymmetry
is unique to `credit_if_unissued`.

If a crash occurs:
- **Between (A) and (B):** WAL record for (A) is flushed; WAL record for
  (B) is either not yet written or is in OS page cache when the kernel
  panics. On recovery, RocksDB replays only the durable WAL records, so
  the balance is at `prev + amount` but the issued-key is absent.
- **Next call to `apply_retro_vesting_tranche(epoch)` (block re-import,
  restart-driven retry, or whatever path triggers the second pass):**
  `was_issued` returns false, `balance_of` returns the **already-bumped**
  balance, the function computes `bumped + amount` and writes it. Net:
  `prev + 2·amount` after one crash + one retry.

A determined attacker can't induce the crash, but operators routinely
do crash/restart cycles (process kills, OOM, OS reboots, S3 snapshot
restore drift), and the property is documented as "block re-import
safe." A power-fail at the wrong moment during an epoch boundary
silently over-pays the affected FIDs by `amount` atoms each.

### Retro path's third unbatched write compounds the problem

`HyperRuntime::apply_retro_vesting_tranche` body
(`src/hyper/runtime.rs:4076-4108`):

```rust
for mut rec in records {
    if self.reward_store.was_issued(epoch, rec.fid, market)? { continue; }
    if rec.remaining_atoms == 0 { continue; }
    let tranche = if remaining_tranches == 1 {
        rec.remaining_atoms
    } else {
        rec.remaining_atoms / remaining_tranches
    };
    if tranche == 0 { continue; }
    self.reward_store
        .credit_if_unissued(epoch, rec.fid, market, tranche)   // step 1
        .map_err(...)?;
    rec.remaining_atoms = rec.remaining_atoms.saturating_sub(tranche);
    self.retro_store
        .put(&rec)                                              // step 2
        .map_err(...)?;
    credited += 1;
}
```

There are now **three** separate disk writes per credited FID:

1. `credit_if_unissued` → balance put (rewards.rs:200-202)
2. `credit_if_unissued` → issued-key put (rewards.rs:203-205)
3. `retro_store.put(&rec)` → updated record (runtime.rs:4105-4107)

with no batch wrapping any pair of them. Two crash windows now exist:

| Crash between | Issued-key | Balance bumped | `remaining_atoms` decremented | Net effect on retry |
|---|---|---|---|---|
| (A) and (B) | ✗ | ✓ | ✗ | Balance +amount **and** issued-key now write; next epoch's tranche divides the un-decremented `remaining_atoms`, so this epoch *plus* future epochs overpay |
| (B) and (3) | ✓ | ✓ | ✗ | This epoch is safe (replay no-ops), but next epoch divides the un-decremented `remaining_atoms` by `(n-e-1)` instead of `(R-tranche)/(n-e-1)` → systematic overpay for the remainder of the schedule, and the final-epoch sweep (`remaining_tranches == 1`) pays the original full balance |

Concretely: a FID with `remaining_atoms = 29` and a 29-tranche schedule
should pay 1 atom per epoch. A crash between (B) and (3) at epoch 0
leaves `remaining_atoms = 29` in `retro_store`. Epoch 1 computes
`29 / 28 ≈ 1`, epoch 2 computes `29 / 27 ≈ 1`, …, and epoch 28
(`remaining_tranches == 1`) pays the full `29`. Total credited:
`1 + 28·1 + 29 = 58` atoms, exactly 2× the intended payout. With
larger allocations and finer-grained division the overpay is smaller in
percentage but identical in shape; the final-epoch cliff guarantees the
overpay is at minimum 1× `remaining_atoms` (the residual sweep).

### Why this *replay* shape is distinct from F012's *budget cap* shape

`findings/drafts/F012-retro-vesting-bypasses-budget-cap.md` is a finding
on the same `apply_retro_vesting_tranche` function but a different
attack class — `emission-budget-cap-missing`. F012 says: "the retro
path never reads `max_reward_per_epoch[_per_market]` before minting, so
the budget cap is silently bypassed." That bug fires in the
*no-crash, normal operation* path and depends on operator-supplied
`remaining_atoms` exceeding a configured cap. It is bounded today
because production runs `max_reward_per_epoch = None` everywhere.

This finding (F015) fires in a *crash-then-restart* path independent of
any operator cap configuration. The two are layered: even if F012 is
fixed (cap added on the retro path), the F015 atomicity bug still
allows a single power-fail to inflate retro payouts beyond what the cap
would allow on retry, because the cap is consulted before the credit
and the recomputed `would_total` on the retry pass sees the new balance
and **not** the un-flushed issued-key. Conversely, fixing F015 (batch
all three writes atomically) does **not** fix F012; the cap is still
unconsulted on the retro path even when the writes are atomic.

The two findings share `apply_retro_vesting_tranche` as the function of
interest but exploit different invariants of the function: F012
exploits a missing precondition (no cap check); F015 exploits a
broken postcondition (the writes aren't atomic).

### Block re-import is an explicit production scenario

Block re-import is the documented justification for the
`(epoch, fid, market)` key (`src/hyper/rewards.rs:11`,
`src/hyper/runtime.rs:4054-4058`). The on-chain comment on
`apply_transfer` and `apply_lock` explicitly cites "block re-import
safe" as a design contract. Hypersnap's import path is
`HyperRuntime::import_block` (`src/hyper/runtime.rs:4120`), and
`EvaluateEpochDkls` is documented as "auto-fired from the block-import
dispatch when an anchor crosses an epoch boundary"
(`src/hyper/actor.rs:131-133`). So the second-pass scenario is:

1. Block at epoch boundary N imports successfully. `apply_retro_vesting_tranche(N)`
   runs. Crash mid-function (between any pair of the three writes).
2. Node restarts. Replays from snapshot or WAL. The same block at epoch
   N is re-imported (RocksDB doesn't know the previous import was
   incomplete because there's no batch boundary).
3. `apply_retro_vesting_tranche(N)` runs again on the partially-applied
   state. Re-credits or stale-divides as analyzed above.

The `make block re-import safe` contract isn't satisfied for the retro
path under this sequence.

### What does protect the live path partially

The live `apply_reward_issuance` (`src/hyper/runtime.rs:504-571`) does
not have step (3); it only goes through `credit_if_unissued`. So the
live path's atomicity gap is just (A)↔(B). A crash there
still double-pays on retry, but only the per-entry amount, not the
multi-epoch cascading retro overpay. The cap check (F012-protected for
live) catches the would-total only if the cap is set, and even then
only catches the case where the recomputed `already_global` already
reflects the bumped balance — which is only correct if `issued_total_for_epoch`
reads from issued-keys (it does, `src/hyper/rewards.rs:158-181`).
So in fact the live path's cap check is robust against the F015 gap as
long as the **issued-key** survived the crash; if the **balance** survived
but the **issued-key** didn't, the cap check on retry will read the
old `already_global` (issued-key absent) and admit the duplicate
credit anyway.

### The retro CSV / persistence story

The retro records are persisted via `RetroStore::seed_records`
(`src/hyper/retro_store.rs:154-164`), invoked from `apply_cutover`
(`src/hyper/runtime.rs:4034-4037`). `apply_cutover` is itself gated by
`genesis_applied` (line 3998-4000) and is currently not called from any
production code path (greps return only its definition and test
callers). When a production cutover wiring is added — the FIP §4.3
cutover is in scope per `src/lib.rs:37` and the module header at
`src/hyper/retro_store.rs:1-19` — the bug is triggered on the very
first epoch after cutover. The CSV's content-addressable identity
(`load_retro_csv` accepts whatever the operator passes,
`src/hyper/retro_store.rs:66-117`) does not provide replay protection;
the protection is supposed to come from the issued-key in
`RewardStore`. That protection is conditional on atomicity, which is
the broken invariant here.

### The three retro_rewards_* binaries do not touch this path

- `src/bin/retro_rewards.rs`, `retro_rewards_finalize.rs`,
  `retro_rewards_new.rs`: pure offline CSV producers. Greps for
  `RewardStore`, `RetroStore`, `credit_if_unissued`, `seed_records`,
  `HyperRetroactiveRecord`, `apply_retro_vesting_tranche` return zero
  matches across all three binaries plus the related
  `retro_rewards_analyze.rs`, `retro_rewards_combo.rs`,
  `retro_rewards_report.rs`. They emit CSVs (allocations, mode
  comparisons, eligibility reports) and never write to RocksDB. So the
  binaries themselves cannot trigger replay; they only feed the CSV
  that the operator later loads via `load_retro_csv` →
  `apply_cutover` (TBD-wired path) → `RetroStore::seed_records`.
- The replay surface is the in-protocol `apply_retro_vesting_tranche`
  on-chain side, not the offline tooling. The binaries are
  load-bearing for *input correctness* (which mutuality mode, which
  pool, which cutoff), not for replay safety.

## Impact

* **Double-credit on crash during live `apply_reward_issuance`.** A
  crash between the balance put and the issued-key put inside
  `credit_if_unissued` lets the next import pass re-credit the same
  `(epoch, fid, market)` entry. Each retried entry is over-paid by
  exactly `entry.amount` atoms. Across an issuance with `k` entries
  that crashed mid-loop, up to `k` FIDs can be double-paid. The cap
  check (F012-protected) sums issued-keys, so it does not see the
  duplicated balance and admits the second credit.
* **Cascading over-pay on the retro path.** A crash between the
  rewards-store writes and the `retro_store.put` leaves
  `remaining_atoms` un-decremented. *Every subsequent epoch in the
  29-tranche schedule for that FID* divides the un-shrunk balance by
  one-fewer remaining tranches, overpaying every time. The final
  epoch's sweep (`remaining_tranches == 1`) pays the original full
  pre-crash `remaining_atoms` as if no tranches had been paid before,
  delivering up to `2×` the intended allocation when the crash window
  was epoch 0 (or `n/(n-e)` × if the crash was epoch `e`).
* **No-op detection is impossible.** Because the discrepancy is between
  two RocksDB keys that are both consistent within themselves
  (`balance_key` holds a u64, `issued_key` holds a u64, both well-formed),
  no on-chain validation can detect that a credit was applied but its
  replay-prevention key was not persisted. The next correctness check
  (e.g., a periodic `Σ retro_store.remaining_atoms + Σ paid_so_far ==
  cutover_total` audit) is not present anywhere in the codebase.
* **Block re-import safety contract is violated.** Two distinct module
  doc-comments (`src/hyper/rewards.rs:11`,
  `src/hyper/runtime.rs:4054-4058`) promise that the
  `(epoch, fid, market)` key makes block re-import a no-op. Under a
  crash mid-`credit_if_unissued`, that contract does not hold.
  Operators relying on the documented invariant (e.g., trusting that a
  catastrophic crash is recoverable by simple WAL replay) get silent
  over-payment.
* **Bounded today by retro path not being wired in production.**
  `apply_cutover` is currently defined but uncalled (grep shows only
  the definition at `runtime.rs:3990`). When the cutover is wired (an
  open task per `src/lib.rs:37` and `src/hyper/retro_store.rs:10-13`),
  the retro side of this bug activates at the first
  `EvaluateEpochDkls` after cutover. The live side (`apply_reward_issuance`
  → `credit_if_unissued`) is wired today and the bug fires whenever a
  crash interrupts an issuance import.

Severity: **medium**. The bug is real, the trigger is a power/OS crash
or process kill at an exact moment, and the consequence is silent
overpayment by 1×–2× the affected tranche. The exploit requires
crash timing the attacker cannot induce directly, but operators
routinely encounter restart cycles, OOM kills, snapshot-restore drift,
and OS reboots. **High** is reasonable if you weight the violation of
the explicitly-documented "block re-import safe" contract heavily, or
if the project's threat model includes adversarial operator behavior
(an operator who notices the gap can deliberately power-cycle at the
right moment to mint over-payments to themselves or to colluders).

## Evidence

* `src/hyper/rewards.rs:186-207` — `credit_if_unissued` body. Two
  separate `self.db.put` calls (lines 200-202, 203-205), no
  `db.txn()` wrapping them. Compare to `apply_lock`
  (`src/hyper/rewards.rs:284-335`), `apply_transfer`
  (`src/hyper/rewards.rs:372-420`), `apply_fee_deposit`
  (`src/hyper/rewards.rs:442-483`), `drain_proposer_fee_pot`
  (`src/hyper/rewards.rs:623-643`) — every one of these uses the
  atomic `db.txn() / batch.put / commit` pattern. The asymmetry is the
  bug.
* `src/hyper/rewards.rs:1-11` — module-level comment guaranteeing
  "re-importing the same issuance is a no-op." This is the contract
  the implementation breaks under crash.
* `src/hyper/runtime.rs:4054-4058` — `apply_retro_vesting_tranche`
  doc-comment guaranteeing "Re-running the same epoch on a runtime
  where the issuance store already has the credit is a no-op — neither
  the balance nor the retro record changes. This is the property that
  makes block re-import safe."
* `src/hyper/runtime.rs:4076-4108` — `apply_retro_vesting_tranche` body
  showing the three-step write sequence: `credit_if_unissued` (line
  4101-4103), `rec.remaining_atoms -= tranche` (line 4104),
  `retro_store.put(&rec)` (line 4105-4107). No batch boundary; each
  step's writes are independently visible to a recovering RocksDB.
* `src/storage/db/rocksdb.rs:355-362` — `RocksDB::put` is a direct
  un-batched put. Compare with `commit` (lines 377-395), which uses
  `db.transaction()` for atomic multi-write commit.
* `src/hyper/runtime.rs:504-571` — `apply_reward_issuance` calls
  `credit_if_unissued` per entry (line 561-566). A mid-loop crash on
  entry `k` leaves entries 0..k-1 in the same atomicity-broken state.
* `src/hyper/retro_store.rs:1-19` — module header documenting the
  idempotency contract that depends on `credit_if_unissued` no-oping.
* `src/hyper/actor.rs:131-133` — `EvaluateEpochDkls` is "auto-fired
  from the block-import dispatch when an anchor crosses an epoch
  boundary." Block re-import is an in-design production scenario.
* `src/hyper/actor.rs:1192-1199` — `EvaluateEpochDkls` handler calls
  `apply_retro_vesting_tranche` unconditionally. There is no guard
  that the previous run completed cleanly; the gate is the issued-key
  inside `credit_if_unissued`, which the bug above can leave absent.
* `src/bin/retro_rewards*.rs` — none of the offline retro_rewards
  binaries touch `RewardStore`, `RetroStore`, or
  `credit_if_unissued`. They are pure CSV producers (grep results in
  the "Ruled-out" note H015). The replay surface lives entirely in
  the on-chain `apply_retro_vesting_tranche` path.
* `.claude/agents/specialists/chain-economics.md:79-83` — the attack
  class definition this finding maps to: "Retro-rewards (paid for past
  activity at chain launch) often go through a separate code path
  from live emission. Without careful state-tracking, a single block
  can trigger both live and retro rewards for the same activity."
  Here the "without careful state-tracking" is the two-then-three
  unbatched writes; "a single block can trigger" is the block
  re-import path; "both live and retro" is the shared
  `credit_if_unissued` join point that breaks for both.

## Suggested remediation

1. **Wrap the writes inside `credit_if_unissued` in a single batch.**
   Mirror the pattern from every other state-mutating method in the
   same file:

   ```rust
   pub fn credit_if_unissued(
       &self,
       epoch: u64,
       fid: u64,
       market: i32,
       amount: u64,
   ) -> Result<bool, RewardError> {
       if self.was_issued(epoch, fid, market)? {
           return Ok(false);
       }
       let new_balance = self
           .balance_of(fid)?
           .checked_add(amount)
           .ok_or(RewardError::BalanceOverflow { fid })?;
       let mut batch = self.db.txn();
       batch.put(Self::balance_key(fid).to_vec(),
                 new_balance.to_be_bytes().to_vec());
       batch.put(Self::issued_key(epoch, fid, market).to_vec(),
                 amount.to_be_bytes().to_vec());
       self.db.commit(batch).map_err(HubError::from)?;
       Ok(true)
   }
   ```

   This fixes the live path's atomicity gap completely. It also
   prevents the (A)↔(B) crash window on the retro path.

2. **Extend the batch to include the retro_store update, OR factor a
   `credit_and_decrement` method that takes both.** The cleanest fix
   is to give `RewardStore::credit_if_unissued` an optional companion
   parameter that also writes a retro record, so all three puts go in
   one batch:

   ```rust
   pub fn credit_if_unissued_with_retro_decrement(
       &self,
       epoch: u64, fid: u64, market: i32, amount: u64,
       retro_key: &[u8], retro_value: Vec<u8>,
   ) -> Result<bool, RewardError> { /* ... batch.put all three ... */ }
   ```

   Or pass a caller-owned `batch: &mut RocksDbTransactionBatch` so
   `apply_retro_vesting_tranche` can collect all three writes per FID
   into a per-FID batch:

   ```rust
   for rec in records {
       let mut batch = self.reward_store.db.txn();
       // 1. balance put
       // 2. issued-key put
       // 3. retro_store update put (encode rec with decremented atoms)
       self.reward_store.db.commit(batch)?;
   }
   ```

   This closes the (B)↔(3) crash window on the retro path.

3. **Add a regression test that simulates a power-fail mid-credit.**
   Use a mock RocksDB that drops the second write of a batch-less pair
   to reproduce the partial-flush scenario, then re-invoke the path
   and assert balance + issued-key + retro_store remain consistent.
   Today no test in `src/hyper/rewards.rs::tests` or
   `src/hyper/runtime.rs::tests` exercises a crash window — every test
   assumes the writes either all succeed or all fail, which the actual
   API does not guarantee.

4. **Audit every other call site that strings together `RewardStore`
   writes outside of a single `commit`.** Grep over the codebase for
   `reward_store.credit_if_unissued` and `reward_store.put`
   combinations within the same function — only `apply_retro_vesting_tranche`
   has the dual-store pattern today, but the long-tail risk is that a
   future feature adds another (epoch-keyed credit followed by
   per-FID state mutation) without realizing the atomicity expectation.
   A `#[must_use]` lint or a `clippy::custom` rule that flags
   `db.put` outside a `txn / commit` in the `RewardStore` impl would
   reduce the chance of regression.

5. **Document the contract explicitly in the function header.** Today
   the module header at `src/hyper/rewards.rs:1-11` promises
   atomicity-on-replay; the function header on `credit_if_unissued`
   itself only says "Returns true if applied; false if it was a no-op."
   Add a paragraph: "The balance write and the issued-key write are
   committed in a single RocksDB batch; either both land or neither
   does. Callers that compose `credit_if_unissued` with additional
   per-FID state writes (e.g., decrementing a retro vesting record)
   MUST extend the batch to cover those writes, or accept the partial-
   apply risk." This both fixes the precedent and surfaces the
   contract to future readers.
