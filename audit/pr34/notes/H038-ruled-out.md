---
id: H038
specialist: rust-bulletproofs-pedersen
attack_class: range-proof-bound-too-loose
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H038 — range-proof bit-length bound vs amount field width (RULED OUT)

## Scope
`crates/hypersnap-crypto/src/tokens.rs` + ed448-bulletproofs integration.
Hypothesis: the Bulletproofs range proof proves a value in `[0, 2^n)` with
`n` larger than the amount field width (or wire-controllable), so an attacker
proves a "valid" amount that wraps to a small committed value but mints large,
or `n` admits values that overflow downstream u64 arithmetic.

## What I checked

### 1. Range-proof bit width is hardcoded, equals the amount field width
- `DEFAULT_RANGE_BITS = 64` (`tokens.rs:36`). Amounts are atoms in `u64`
  everywhere: `proto::HyperTransferTx`/`ConfidentialLockBody`/`ShieldBody`
  use `uint64 amount`/`uint64 fee_atoms` (`proto/definitions/hyper.proto`).
  So `n = 64 = ` the field width exactly — not larger. This is the natural
  u64 width and matches the documented max supply (~2^64 atoms), per the
  doc-comment at `tokens.rs:33-36`.
- The attack class requires `n > amount field width`. Here `n == width`.

### 2. The verifier never reads `bit_size` from the wire
- `verify_value_range(proof, committed, bit_size)` (`tokens.rs:158`) takes
  `bit_size` as a parameter, but the only production call site is inside
  `TransferTx::validate()` (`tokens.rs:332`), which passes the constant
  `DEFAULT_RANGE_BITS` (64). The wire `range_proof` is opaque bytes; the
  bit length is fixed by the verifier, not chosen by the prover. An attacker
  cannot request a wider (e.g. 128/256-bit) proof to overflow.
- Confirmed: every non-test `verify_value_range`/`prove_value_range` call in
  `src/**` and `crates/**` uses `DEFAULT_RANGE_BITS` (the `8`-bit calls are
  test-only). The vendored `ed448-bulletproofs` additionally rejects a
  bitsize that is not a supported power of two (`ProofError::InvalidBitsize`,
  `range_proof/mod.rs:345`), so a malformed wider proof would fail to verify.

### 3. No overflow / wrap-to-small mint is reachable at 64 bits
- Production validation path (`runtime.rs:3720-3733` mempool admission,
  `runtime.rs:4482-4524` block import) runs
  `validate_against_store` → `validate()` (per-output 64-bit range proof) +
  `verify_balance_with_blinding_diff` (Pedersen closure
  `Σin − Σout − fee·B == r_diff·B_blinding`).
- Balance closure holds in the Decaf448 scalar field (group order ~2^446),
  not mod 2^64. Every output value is range-proven `≥ 0` and `< 2^64`; inputs
  are prior outputs that were themselves 64-bit range-proven on creation.
  Conservation over non-negative integers therefore prevents a large mint:
  a small input set cannot balance an output that is large-but-wrapped,
  because no output can be negative. Wrapping the group order would require
  ~2^382 outputs — infeasible and capped by block/wire size limits.
- `TransferInput` carries no range proof (only `TransferOutput` does), so
  there is no looser input-side bound to exploit; input bounds are inherited
  from the 64-bit proofs that created those notes.

### 4. Downstream u64 arithmetic on plaintext amounts is bounded + saturating
- The only plaintext u64 crossing into integer arithmetic is the confidential
  bridge `amount`/`fee_atoms`. `confidential_lock::validate_against_store`
  (`src/hyper/confidential_lock.rs:178`) computes
  `body.amount.saturating_add(body.fee_atoms)` and ties the result to the
  committed input value via Pedersen closure (`residual == blinding_diff·
  B_blinding`). `amount` is thus bounded by the note's committed value, which
  is itself ≤ 2^64−1 by the creating output's 64-bit range proof. `saturating_add`
  removes any add-overflow. (Whether the lock path range-proves `amount`
  separately is F036's concern — range-proof-defined-but-unwired — not a
  bit-width-too-loose issue.)

## Conclusion
The range-proof bit length (64) is correctly matched to the `u64` amount field:
it is neither larger than the field width nor wire-controllable, the verifier
pins it to a constant, the vendored library rejects unsupported bitsizes, and
non-negative 64-bit conservation plus saturating downstream arithmetic preclude
both wrap-to-small mints and u64 overflow. No range-proof-bound-too-loose
finding. (Related but distinct gaps in the lock/transfer range-proof wiring are
already captured by F035/F036.)
