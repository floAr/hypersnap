---
id: ONBD-3
specialist: chain-economics
attack_class: fund-inflation-non-atomic-state
title: Onboarding stake lock writes and commits the lock record before debiting the sponsor's balance in a separate transaction, so a crash between the two commits yields a valid, never-paid-for lock that mints net-new atoms when released after maturity
severity_initial: medium
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/runtime.rs
  - src/hyper/native_onboard.rs
validation:
  validator: cross-lane (economics + storage)
  verdict: CONFIRMED
  confidence: 0.78
  hypotheses_walked: 2
---

## Summary

`HyperRuntime::apply_onboarding_stake_lock` (`runtime.rs:819-885`) is the
mirror-image non-atomicity of ONBD-2, with the ordering reversed so the
**value-granting** write precedes the debit:

- **Commit #1:** `admit_onboarding_stake_lock` (`native_onboard.rs:972-1018`)
  writes `HyperOnboardingStakeLock[id]` and commits (`1010-1016`). The lock is
  now durable.
- **Commit #2:** the runtime debits `HyperRewardBalance[sponsor]` and bumps the
  nonce, then commits (`866-883`).

A crash — or a transient `db.commit` failure at `881-883` — between the two
leaves a **lock that was never paid for**: the sponsor's balance is untouched
and the nonce un-bumped. Because `admit_...` rejects a duplicate
(`LockAlreadyExists`, `native_onboard.rs:995-1003`), the debit can never be
retried. That free lock is fully valid; after maturity
`apply_onboarding_stake_release` credits back `lock.amount_atoms`
(`runtime.rs:933-936`) — atoms the sponsor never spent — i.e. **net minting**
of ≥ `MIN_STAKE_AMOUNT` = 1,000,000,000 atoms per crash-window occurrence.

## Impact / Severity

Ledger inflation contingent on a crash / commit I/O failure in a narrow window.
The window is narrow, but the payoff is unbounded atom inflation and
correctness of a ledger must not depend on process liveness between two writes.
**Medium** (would be **High** if the crash window is readily reachable in the
block-application checkpoint model, which was not fully traced).

## Fix

Fold the lock-record write, the balance debit, and the nonce bump into a
**single** `RocksDbTransactionBatch` committed once (have `admit_...` return
the encoded record + key instead of committing). Structurally identical to the
ONBD-2 fix — one root cause (runtime↔module two-commit where one atomic batch
is required).
