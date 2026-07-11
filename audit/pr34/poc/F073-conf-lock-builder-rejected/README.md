# F073 PoC — `build_confidential_lock` output is rejected by the runtime validator

**Finding:** [F073](../../findings/F073-confidential-lock-wallet-builder-emits-non-validatable-messages.md)
**Commit:** `f4fc4af` · **Polarity:** RED (asserts the property that should hold; FAILS on current code)

## What it proves

A message produced by the production wallet builder `build_confidential_lock`
is run through the live validator `confidential_lock::validate_against_store`.
The test asserts it should be accepted; it is rejected with
`BalanceClosureFailed` — because the builder sends
`blinding_diff = input_blinding − output_blinding` for an `output_commitment`
that is never attached (the runtime enforces `blinding_diff == input_blinding`).
The empty `range_proof` (`MissingRangeProof`) is the second, masked defect.

## Location

`src/hyper/confidential_lock.rs`, `#[cfg(test)] mod tests`,
`fn f073_confidential_lock_builder_output_must_validate` (see
[`f073_test.rs`](f073_test.rs)). Lives in the `hypersnap` crate, which
path-depends on `hypersnap-wallet`, so it calls the real builder.

## Reproduce (WSL)

```
cd ~/hs-f4fc4af
RUSTFLAGS='--cap-lints allow' cargo test -p hypersnap --lib \
  f073_confidential_lock_builder_output_must_validate -- --nocapture
```

## Verbatim RED output (f4fc4af)

```
thread 'hyper::confidential_lock::tests::f073_confidential_lock_builder_output_must_validate' panicked at src/hyper/confidential_lock.rs:296:9:
F073: build_confidential_lock output must pass validate_against_store, got Err(BalanceClosureFailed)
test hyper::confidential_lock::tests::f073_confidential_lock_builder_output_must_validate ... FAILED
```

## Green condition (after fix)

Builder sends `blinding_diff = input_blinding` and attaches a real
`prove_value_range(amount+fee, input_blinding, ...)` proof. Balance closure then
holds and the (now non-empty, valid) range proof verifies → `validate_against_store`
returns `Ok(..)` → assertion passes (green).

## Note — F036 linkage

The `MissingRangeProof` reject exists only because F036 was fixed at `f4fc4af`
(`verify_value_range` wired at `confidential_lock.rs:230`, empty-reject at
`:219`). F073 is the wallet-side mirror of F036.
