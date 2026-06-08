---
id: F036
specialist: rust-bulletproofs-pedersen
attack_class: validator-defined-but-unwired
file_paths:
  - src/hyper/confidential_lock.rs
  - src/hyper/runtime.rs
  - crates/hypersnap-crypto/src/tokens.rs
  - proto/definitions/hyper.proto
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: low
title: ConfidentialLockBody.range_proof is carried on the wire but verify_value_range is never wired into the lock-admission path
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T12:30:00Z
---

## Summary

The confidential bridge-lock primitive defines a wire field
`ConfidentialLockBody.range_proof` (proto field 6) whose documented purpose
is "Bulletproofs range proof for `amount`. Proves `amount` fits in the
protocol's range." A range-proof verifier (`verify_value_range`) exists and
is correct. But the function that admits confidential locks on the live
gossip path — `confidential_lock::validate_against_store` — never calls
`verify_value_range` (or reads `body.range_proof` at all). The field is
accepted and silently discarded; locks are admitted with no range-proof
verification.

Note: the *primary* cryptographic verifier for this primitive
(`validate_against_store`: Schnorr spend-signature verify + Pedersen balance
closure + nullifier-not-spent) IS correctly wired (see "Live path" below),
so the broad "the verifier is dead code" framing does NOT hold. The
defined-but-unwired component is specifically the **range-proof** check.

## Affected code

Verifier defined (range proof):
- `crates/hypersnap-crypto/src/tokens.rs:158` — `pub fn verify_value_range(...)`.
  Its only non-test caller is `TransferTx::validate` at
  `crates/hypersnap-crypto/src/tokens.rs:332` (the confidential *transfer*
  path). Grep for `verify_value_range` across `src/**` returns zero hits in
  the confidential-lock path.

Wire field defined:
- `proto/definitions/hyper.proto:228-230` — `ConfidentialLockBody.range_proof`,
  documented as a Bulletproofs range proof for `amount`.

Admission verifier that omits it:
- `src/hyper/confidential_lock.rs:156` — `validate_against_store(...)`. Calls
  `validate_structural` (lengths/parse), Schnorr verify
  (`confidential_lock.rs:170-173`), and Pedersen balance closure
  (`confidential_lock.rs:177-184`). It never references `body.range_proof`.
- `src/hyper/confidential_lock.rs:100` — `validate_structural(...)` likewise
  never inspects `body.range_proof`.

## Live path (where admission happens)

- `src/hyper/runtime.rs:3699-3703` — `submit_message` (the inbound-gossip
  admission gate) intercepts `Body::ConfidentialLock` and calls
  `apply_confidential_lock`.
- `src/hyper/runtime.rs:860-913` — `apply_confidential_lock` calls
  `confidential_lock::validate_against_store` (runtime.rs:864), and on success
  immediately records a `TokenLockState` and marks the nullifier spent — a
  direct state change with no separate block-import re-validation for this
  body type (the importer at `src/hyper/importer.rs` has no confidential-lock
  handling). So `validate_against_store` is the sole gate, and it skips the
  range proof.

## Attack scenario

A peer crafts a `ConfidentialLockBody` with `range_proof` set to empty/garbage
bytes. `validate_against_store` ignores the field entirely, so the lock is
admitted as long as the Schnorr signature and Pedersen balance closure pass.
The "proves amount fits in range" guarantee advertised by the wire format is
never enforced.

## Impact

Low. The would-be value-overflow impact is already foreclosed by two facts
independent of the missing range proof:
1. `amount` is a public `uint64` (proto field 2), so it is structurally bounded
   to `< 2^64` and cannot be a near-group-order value.
2. The Pedersen balance closure
   (`commit_in - (amount + fee)*B == blinding_diff * B_blinding`,
   `confidential_lock.rs:177-184`) binds the committed input value to the public
   `amount + fee` exactly, so a prover cannot commit a large value while
   declaring a small public `amount`.

The codebase's own design treats this range proof as unnecessary when the
amount is public: the shield primitive reuses the same `range_proof` field as
a blinding scalar with the comment "the bulletproofs range proof is
unnecessary — `amount` is public" (`src/hyper/shield.rs:80-84`). The risk that
remains is a latent wire-format integrity gap: the field exists, looks
load-bearing, and could be relied upon by future code or off-chain tooling
that assumes lock admission enforces a range bound when it does not.

## Root cause

Defined-but-unwired verifier: `verify_value_range` is wired only for transfer
outputs, never for the confidential-lock body, even though the lock proto
carries a `range_proof` field. The omission is silent (no error, field simply
not read), which is exactly the dead-code-security pattern — a proof artifact
is transmitted but never checked.

## Fix

Either (a) verify the field on the live path — in
`confidential_lock::validate_against_store`, after balance closure, call
`hypersnap_crypto::tokens::verify_value_range(&body.range_proof,
&input.commitment[..].try_into()?, DEFAULT_RANGE_BITS)` and reject on failure;
or (b) if the range proof is genuinely redundant given the public `amount` +
balance closure (consistent with the shield rationale), remove the
`range_proof` field from `ConfidentialLockBody` in the proto and document that
lock amounts are bounded by the public `uint64` + closure, so no caller or
off-chain tool mistakes the discarded field for an enforced guarantee.
