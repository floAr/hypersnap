---
id: ONBD-2
specialist: chain-economics
attack_class: fund-loss-non-atomic-state
title: Onboarding stake release deletes and commits the lock record before the fallible nonce check, across a non-atomic commit boundary, so a stale/wrong nonce (routine on the shared nonce stream) or a mid-flow crash permanently burns the sponsor's staked atoms with no refund
severity_initial: high
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/runtime.rs
  - src/hyper/native_onboard.rs
validation:
  validator: cross-lane (economics + storage + crypto)
  verdict: CONFIRMED
  confidence: 0.9
  hypotheses_walked: 3
---

## Summary

`HyperRuntime::apply_onboarding_stake_release` (`runtime.rs:891-957`) performs
two **independent** RocksDB commits with a fallible check between them, and the
**destructive** one runs first:

1. `admit_onboarding_stake_release` (`native_onboard.rs:1023-1069`) validates
   sponsor-match / not-bound / matured, then `batch.delete(lock_key)` +
   `db.commit(batch)` (`1064-1067`) — **the lock record is irrevocably
   destroyed** — and returns `(sponsor, amount)`. It never inspects
   `body.nonce`.
2. Back in the runtime: `if amount == 0 { return Ok }` (`916-920`); then the
   **nonce check** (`922-931`) which can `return Err(NonceMismatch)`; only past
   it does the balance credit-back get committed (`938-955`).

So a release whose `body.nonce` is stale deletes the lock and returns `Err`
before the atoms are ever credited. The refund is lost forever; the lock is
gone, so any retry hits the idempotent `(0,0)` no-op branch
(`native_onboard.rs:1033-1037`) and credits nothing.

## Why the trigger is routine, not exotic

`HyperTokenNonce` is a **shared** counter across TokenTransfer / FeeDeposit /
Shield / stake-lock / stake-release (all read `reward_store.nonce_of(fid)`).
A sponsor signs a release when `expected == n+1`; if any *other* token message
from the same FID lands first and advances the shared nonce, the release's
signed nonce is now stale and step 2 fails — after step 1 already burned the
lock. A mid-flow process crash (or a `db.commit` I/O failure) between the two
commits produces the identical loss on the happy path.

## Concrete loss trace

- Sponsor FID `S`: balance `B`, `HyperTokenNonce = n`. Locks 5,000,000,000
  atoms (lock `L`, matures at block `M`). → balance `B−5e9`, nonce `n+1`.
- After maturity, `S` signs a release for `L` with nonce `n+2`. Independently
  `S` submits any other HyperToken-stream message that lands first → nonce
  advances to `n+2`.
- Release executes: `admit_...` finds `L`, sponsor matches, unbound, matured →
  **deletes `L`, commits**, returns `(S, 5e9)`.
- Runtime: `amount≠0`; expected `= (n+2)+1 = n+3`, got `n+2` →
  `Err(NonceMismatch)`. Credit-back batch never runs.
- **Net: 5,000,000,000 atoms permanently burned.** `S` keeps neither the lock
  nor the refund; retry is a `(0,0)` no-op.

## Impact / Severity

Permanent, deterministic on-chain loss of a sponsor's staked funds, triggered
by an ordinary nonce race on a shared counter (or any crash) — no adversary
required, though an adversary who can induce the victim's own other-message
ordering can force it. **High.** Note the stake path is live now, not dormant
(see ONBD-6), so this is reachable at launch.

## Fix

Validate the nonce (and sponsor / maturity / unbound) **before** any
destructive write, and perform the lock deletion, balance credit, and nonce
bump in a **single** `RocksDbTransactionBatch` committed once. Concretely, have
`admit_onboarding_stake_release` *return* the lock (read-only) without
committing, and let the runtime assemble one batch containing `delete(lock)`,
`put(balance)`, `put(nonce)` and commit it atomically. Same single-batch
discipline the in-module `apply_onboarding` / `apply_custody_rotation` flows
already use. Shares its root cause with ONBD-3.

## PoC

Red property test: [`poc/onbd/ONBD-2-stake-release-burn/`](../../poc/onbd/ONBD-2-stake-release-burn/)
— asserts a sponsor is made whole after a stale-nonce release (no atoms
destroyed); FAILS on `573d671` (lock deleted, balance unchanged), passes once
the flow is made atomic.
