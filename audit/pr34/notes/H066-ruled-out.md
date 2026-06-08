# H066 ruled out — pedersen-commitment-opening (transparent→confidential shield)

Specialist: rust-crypto-primitives
Attack class: pedersen-commitment-opening
Commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (HEAD == pinned)
Date: 2026-06-08
Scope: src/hyper/shield.rs, src/hyper/runtime.rs (apply_shield)

## Hunt question

Is the Pedersen commitment-opening check enforced before the transparent
balance is debited and the confidential note minted? Can a user shield for
more than they debit, or with a commitment that doesn't open to the debited
amount?

## Conclusion: no issue

The commitment-opening check is enforced, binds the committed note value to
the public signed `amount`, and runs before any state mutation.

### Binding (commitment opens to the debited amount)

`validate_shield` (`src/hyper/shield.rs:91-147`):
- Parses the wire commitment point (line 112) and the user-supplied blinding
  scalar, which is carried in the reused `range_proof` field as a canonical
  Decaf448 scalar (lines 120-126; rejects non-canonical).
- Recomputes `expected = amount·B + blinding·B_blinding` via
  `Point::multiscalar_mul` with `Scalar::from(body.amount)` (lines 139-142)
  and rejects with `CommitmentMismatch` unless `expected == commitment.0`
  (lines 143-145).
- `amount` is part of the Ed25519-signed payload (`shield_signing_payload`,
  lines 68-87: DST + chain_id + sender_fid + amount + nonce + signer_pubkey +
  commitment + one_time_pubkey + blinding), and the signature is verified
  (lines 128-135) before the opening check. So the committed value is bound to
  the exact public amount the user signed; a commitment to any other value
  fails the opening check.

`PedersenGens::default()` (vendored `crates/ed448-bulletproofs/src/generators.rs:42-49`):
B = basepoint, B_blinding = Shake256 hash-to-group of the basepoint encoding
(distinct, nothing-up-my-sleeve). `body.amount` is u64, far below the Decaf448
scalar field order, so `Scalar::from(u64)` is injective — no reduction/wrap.
Decaf448 encodings are canonical, so point equality is well-defined.

### Ordering (check before debit, before mint)

`apply_shield` (`src/hyper/runtime.rs:776-854`):
1. `validate_shield` (signature + commitment opening) — line 780-782.
2. Signer-authorization for `sender_fid` (lines 784-800).
3. Nonce check, then `InsufficientBalance` guard `sender_bal < body.amount`
   (lines 806-822).
4. Atomic debit + nonce-bump batch commit (lines 826-848).
5. Mint the note with the validated commitment (lines 850-852).

Validation strictly precedes the debit and the mint. The minted note commits to
exactly the debited `amount` (same value used in both the opening check and the
balance debit). No path mints more than is debited, and no commitment that fails
to open to the debited amount can be minted.

### Dispatch path

Single apply path: router rejects `Shield` as an unsupported message type
(`src/hyper/router.rs:311-314`); the runtime intercepts and routes it through
`apply_shield` (`src/hyper/runtime.rs:3704-3709`). No alternate path bypasses
`validate_shield`.

## Residual notes (out of scope for H066, not value-conservation defects)

- The blinding factor is recorded in the clear (signed body), so the note's
  value is publicly recoverable until re-randomized via a subsequent transfer.
  This is documented intent (shield.rs:10-14), not a minting/conservation bug.
- Whether the note's committed value is correctly conserved when later SPENT is
  the confidential-spend side (`apply_confidential_lock` / transfer), outside
  this hunt's mint-side scope.
