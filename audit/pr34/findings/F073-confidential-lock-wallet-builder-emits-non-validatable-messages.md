---
id: F073
source: felirami PR#34 inline review, 2026-07-11 (comment 3562734458)
specialist: rust-bulletproofs-pedersen
attack_class: producer-verifier-mismatch (broken primitive)
related: F036 (range-proof now wired at f4fc4af — this defect is its mirror on the wallet side)
file_paths:
  - crates/hypersnap-wallet/src/tx/confidential_lock.rs
  - src/hyper/confidential_lock.rs
  - proto/definitions/hyper.proto
  - crates/hypersnap-wallet/src/tx/confidential_transfer.rs
commit: f4fc4afccbd0419e04000dca0c6677fd6191afec
severity_initial: high
title: build_confidential_lock emits a blinding_diff for a phantom output_commitment and an always-empty range_proof; every message it produces is rejected by validate_against_store
validation:
  validator: rust-bulletproofs-pedersen (revalidation pass, reviewer-sourced)
  verdict: CONFIRMED
  confidence: 0.95
  validated_at: 2026-07-11T00:00:00Z
---

## Summary

The wallet builder `build_confidential_lock`
(`crates/hypersnap-wallet/src/tx/confidential_lock.rs`) produces
`ConfidentialLockBody` messages that the production validator
`confidential_lock::validate_against_store` (wired at `runtime.rs:1074/3957/4936`)
unconditionally rejects. Two independent defects; the balance-closure one fails
first.

## Defect 1 — blinding delta off by a phantom `output_blinding`

Builder (`confidential_lock.rs:30-32,44`):
```rust
let output_blinding = Scalar::random(&mut rng);
let output_commitment = PedersenCommitment::commit(amount + fee_atoms, &output_blinding); // never attached
let blinding_diff = input_blinding - output_blinding;
...
blinding_diff_scalar: blinding_diff  // = input_blinding - output_blinding
```
`output_commitment` is computed then never included — `ConfidentialLockBody`
has no output-commitment field (`hyper.proto:233-256`).

Runtime balance closure (`src/hyper/confidential_lock.rs:194-205`) enforces
`input_commitment - (amount+fee)·B == blinding_diff · B_blinding`, i.e. holds
**iff `blinding_diff == input_blinding`** (proto doc `hyper.proto:244-247`
agrees; there is no second output commitment in a lock — the lock burns the
note). Substituting the builder's value gives residual − expected =
`output_blinding · B_blinding ≠ 0` → `BalanceClosureFailed`. Correct value is
simply `blinding_diff = input_blinding`. (Contrast the sibling
`confidential_transfer.rs:61` `input_blindings_sum − output_blindings_sum`,
which is correct **because** real output commitments are attached.)

## Defect 2 — always-empty range_proof, hard-rejected

Builder sets `range_proof: Vec::new()` (`confidential_lock.rs:45`). Runtime
(`src/hyper/confidential_lock.rs:219-221`) rejects empty proofs:
```rust
if body.range_proof.is_empty() { return Err(ConfidentialLockError::MissingRangeProof); }
```
and then verifies it (`:230` `verify_value_range(...)`). The lock builder never
calls `prove_value_range` (contrast `confidential_transfer.rs:49-51`).

**Revalidation link to F036:** at the audited base `cab225f`, F036 recorded that
`validate_against_store` never read `body.range_proof`. At `f4fc4af` that is
**FIXED** — `verify_value_range` is now wired (`confidential_lock.rs:230`) with
the empty-proof reject at `:219`. So the F036 fix is exactly what makes the
wallet builder's empty-proof output now hard-fail. F036 → CLOSED at f4fc4af;
F073 is its wallet-side mirror.

## Which check fails first

`validate_structural` passes (all lengths correct) → owner/spent lookups →
Schnorr verify passes (builder signs the correct payload; DST
`b"hypersnap-conf-lock-v1"` matches) → **balance closure (`:203`) fails first →
`BalanceClosureFailed`**. `MissingRangeProof` (`:219`) is never reached but
would also fail.

## Severity / merge-blocker

**Broken feature (liveness), not a safety/consensus risk.** The runtime
correctly *rejects* — no invalid state admitted, no balance forgeable. Every
confidential lock this wallet produces is rejected, so the confidential
bridge-lock path is non-functional from this builder. P1-as-broken-primitive
merge blocker **for the confidential-lock feature**; no validator downgrade
involved (this is the correct live pipeline).

## Fix

Send `blinding_diff = input_blinding`; attach a real
`prove_value_range(amount+fee, input_blinding, ...)` proof over the input
commitment.

## PoC

Red-polarity test (see `poc/F073-conf-lock-builder-rejected/`): build a message
via `build_confidential_lock` against a mock `NoteStore`, run
`validate_against_store`, assert `res.is_ok()`. FAILS today with
`Err(BalanceClosureFailed)` (and would then fail `MissingRangeProof` until the
builder also attaches a real proof).
