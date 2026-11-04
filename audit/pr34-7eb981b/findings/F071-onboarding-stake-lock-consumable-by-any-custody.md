---
finding_id: F071
title: An onboarding stake lock records only its sponsor, and `onboard` never asks the sponsor to approve the custody that uses it
severity: low
status: pending-validation
related_findings:
- F070
- F064
---
# F071 — An onboarding stake lock records only its sponsor, and `onboard` never asks the sponsor to approve the custody that uses it. Anyone can name any unbound `stake_lock_id` in a `NATIVE_ONBOARD` signed by their own custody address. That gives them a native FID, and the sponsor's stake becomes permanently non-refundable ("a consumed stake is not refundable"). This is dormant while `onboarding_stake_gate = false`.

- **Severity:** Low, source-only. **Dormant**: the stake gate ships disabled (`src/chain/shard0/mod.rs:155-156`, "ONBD-6"). Once enabled, the impact is theft of the sponsor's onboarding benefit and loss of at least `min_onboarding_stake` (1e9 atoms) per lock. The stake is never released (`onboarding.rs:507-508`) and nothing else reads the binding. Lock ids are public (`SHA-256(domain ‖ sponsor_fid ‖ nonce)`, and the lock records are in state), so no front-running is needed.
- **Confidence:** 0.8. Certain from source while the gate is on. The flag is in `params_hash`, so turning it on needs a release.
- **Category:** missing authorization (stake gate) / unbound gate proof
- **Specialist:** rust-crypto-primitives · task H053 (found while checking which onboarding fields the custody signature binds)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `onboarding.rs` is new since `bdef7b7`. `OnboardingStakeLockBody` has `reserved 1, 6, 7` (`proto/definitions/hypersnap_bodies.proto:253-259`). Earlier designs may have had a beneficiary field. Not checked against the old lineage.
- **PoC:** None. Engine-test sketch: with `test_support` params (`onboarding_stake_gate = true`, `test_support.rs:34`), sponsor S sends `ONBOARDING_STAKE_LOCK`. Attacker eth(77) sends `NATIVE_ONBOARD{custody eth(77), gate Stake{S's lock_id, amount, duration}}` signed by eth(77). Expected: FID issued, then S's `ONBOARDING_STAKE_RELEASE` after the duration fails with "a consumed stake is not refundable".

## Code facts

1. The lock stores `sponsor ‖ amount ‖ duration ‖ created_at` and nothing about who may use it (`onboarding.rs:457-487`).
2. `onboard_precheck` puts only `stake_gate_commitment(lock_id, amount, duration)` into the custody signature (`:268-279`, `:84-91`). The signer is the *new* custody, not the sponsor.
3. `onboard` checks only that the lock exists, `amount`/`duration` ≥ the claim, and that it is not yet bound (`:319-330`). Then it binds the lock to the new FID (`:346`).
4. `stake_release` refuses a bound lock forever (`:503-508`).

## Red-team

1. *Is the sponsor meant to be anyone's sponsor?* No. The sponsor locks the stake for a particular onboarding. Nothing lets the sponsor name it, so the first claimant takes it.
2. *Is the gate off, so it's moot?* It is off at `7eb981b`. The code, tests and params exist to switch it on, so file it for the record before it ships.
3. *Can the sponsor race it?* Only by putting the lock and the onboarding in the same block and hoping a proposer keeps them in order. A watcher can claim any lock as soon as it appears.

## Fix

- Bind the beneficiary custody address into `ONBOARDING_STAKE_LOCK`, and require `onboard` to match it. Or require a sponsor signature over `(lock_id, custody)` inside the `StakeProof`.
- Alternatively, refund the stake to the sponsor when the binding is made by a custody the sponsor didn't name.

## Files

- `src/chain/shard0/onboarding.rs:84-91, 268-279, 319-330, 346, 457-509`
- `src/chain/shard0/mod.rs:155-158`; `proto/definitions/hypersnap_bodies.proto:253-259`
