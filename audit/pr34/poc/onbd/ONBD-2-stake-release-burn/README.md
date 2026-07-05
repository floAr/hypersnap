# PoC — ONBD-2: rejected stake release burns the sponsor's staked atoms

**Finding:** [ONBD-2](../../../findings/native-onboard/ONBD-2-stake-release-burns-staked-atoms-non-atomic.md) (High) · commit `573d671`.

**Polarity:** red property test — it asserts the *secure* property (a rejected release conserves the sponsor's value) and therefore **FAILS on the buggy `573d671` code**, flipping green once the bug is fixed.

## What it proves

`apply_onboarding_stake_release` (`runtime.rs:891`) calls
`admit_onboarding_stake_release`, which **commits** `batch.delete(lock)`
(`native_onboard.rs:1064-1067`) *before* the runtime's nonce check
(`runtime.rs:922-931`). A release with a stale nonce — routine, since
`HyperTokenNonce` is shared across all of the sponsor's token messages — is
correctly rejected (`Err(NonceMismatch)`), but only *after* the lock has
already been destroyed, and the refund credit never runs. The staked atoms are
permanently lost.

## Result (build-verified, RED)

```
assertion `left == right` failed: ONBD-2: rejected stake release burned
5000000000 atoms (lock deleted before the nonce check, no refund)
  left: 5000000000      # sponsor value AFTER the rejected release (balance only; lock gone)
 right: 10000000000     # sponsor value BEFORE (balance + locked stake)
```

Full transcript: [test-output.txt](test-output.txt). Test source:
[onbd2_stake_release_burn_test.rs](onbd2_stake_release_burn_test.rs) (drop into
`mod tests` in `src/hyper/runtime.rs`).

## How to run

```bash
# On a WSL/Linux checkout of the tree at 573d671 with the test added:
cd ~/hs-573d671
RUSTFLAGS="--cap-lints allow" \
  cargo test -p hypersnap --lib -- \
  onbd2_rejected_stake_release_must_not_burn_staked_atoms --nocapture --test-threads=1
```
(`--cap-lints allow` dodges an unrelated `ed448-bulletproofs` lint-pass ICE in
rustc 1.95; the `malachite` path-dep sibling must be staged at `../../malachite`.)

## Expected after the fix

Validate the nonce (and sponsor/maturity/unbound) **before** any destructive
write, and fold `delete(lock)` + balance-credit + nonce-bump into one
`RocksDbTransactionBatch`. The rejected release then leaves the lock intact,
`value_after == value_before`, and the test passes.
