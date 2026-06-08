---
id: H065
specialist: rust-crypto-primitives
attack_class: canonical-encoding-validation
file_paths:
  - code/hypersnap/src/hyper/transfer_codec.rs
  - code/hypersnap/crates/hypersnap-crypto/src/tokens.rs
  - code/hypersnap/crates/ed448-bulletproofs/src/curve_adapter.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
title: Confidential transfer wire codec enforces canonical point/scalar decode
---

# H065 — canonical-encoding-validation in `transfer_codec.rs` — RULED OUT

## Scope
`src/hyper/transfer_codec.rs` — the proto <-> Rust wire codec for confidential
transfers (`HyperTransferTx`/`Input`/`Output`). Hunt: are curve points checked
for canonical encoding / subgroup membership on decode, and are scalars
reduced/range-checked, such that a non-canonical or malleable encoding could
(a) decode to the same logical value but distinct wire bytes (breaking
dedup/nullifier/signature-over-bytes assumptions), or (b) smuggle a
small-subgroup point.

## What decodes, and through which constructor

Every curve element crossing the decode boundary is parsed via a *validating*
constructor — there is no permissive/silent-reduction path in the codec:

- Commitment points (`input_from_proto`, `output_from_proto`):
  `PedersenCommitment::from_bytes` (tokens.rs:71) — strict 56-byte length check,
  then `point_from_compressed_bytes` -> `CompressedDecaf::decompress()`
  (tokens.rs:759-763, curve_adapter.rs:401-403). Returns `None` on failure.
- Schnorr signature (`SchnorrSignature::from_bytes`, tokens.rs:453-465):
  strict 112-byte length; `R` via `point_from_compressed_bytes`; scalar `s` via
  `Scalar::from_canonical_bytes` (curve_adapter.rs:460-466).
- `extract_blinding_diff` (transfer_codec.rs:148-157): strict 56-byte length,
  then `Scalar::from_canonical_bytes`.
- `extract_output_pubkeys` (transfer_codec.rs:163-181): per-output strict
  56-byte length, then `point_from_compressed_bytes`.
- `nullifier`: strict 32-byte length check (opaque hash output, not a group
  element — no canonicity notion applies).

### Points — canonical + subgroup-safe
The group is Decaf448 (`ed448-goldilocks-plus` 0.16). Decaf448 is a
prime-order group abstraction: `CompressedDecaf::decompress()` rejects
non-canonical `s`-coordinate encodings and rejects the would-be cofactor/
small-subgroup torsion components by construction. There is therefore no
small-subgroup point to smuggle, and each group element has exactly one valid
56-byte encoding. The codec uses `decompress()` (CtOption -> Option), NOT the
permissive `decompress_or(...)` fallback (curve_adapter.rs:405-410), so a bad
encoding is a hard `None` -> `BadCommitment`/`BadOneTimePubkey`/`BadSignature`.

### Scalars — range-checked, not silently reduced
The adapter exposes both a non-validating reducer/loader
(`from_bits` = `DecafScalar::from_bytes`, curve_adapter.rs:468-470;
`from_bytes_mod_order`) and the validating `from_canonical_bytes`
(curve_adapter.rs:460-466, rejects `s >= ell`). The codec uses **only**
`from_canonical_bytes` for both scalar fields (`s` and `blinding_diff_scalar`).
The non-validating loaders are not reachable from the transfer decode path.

## Why the malleability sub-case (distinct wire form, same value) does not bite
- Because points have a unique canonical encoding and scalars are reject-if-
  non-canonical, the decode boundary itself admits no "two byte-strings, one
  value" aliasing for the crypto fields.
- The remaining wire variability is protobuf-level non-determinism
  (field order / varint padding / `range_proof: Vec<u8>` copied verbatim).
  But nothing security-relevant hashes the *raw received proto bytes*:
  - Spend signatures are verified against `TransferTx::signing_payload()`
    (tokens.rs:243-262), which is recomputed from re-canonicalized field bytes
    (`commitment.to_bytes()`, `nullifier.0`, length-prefixed `range_proof`,
    `fee_atoms` BE) — invariant under any proto re-serialization that decodes
    to the same typed tx.
  - Mempool dedup (`mempool.rs:141-169`) is keyed on the decoded 32-byte
    first-input nullifier and rejects any pending nullifier overlap
    (`DuplicateNullifier`), so a re-encoded duplicate cannot create a second
    live entry under a different key.
  So malleating non-crypto bytes neither forges a signature nor defeats dedup.

## Out-of-scope adjacency (not this hunt)
The block-import strong-validation path (`runtime.rs:4511`) verifies spend
signatures via `validate_against_store` -> bare `signing_payload()`, i.e. it
does NOT bind `one_time_pubkey`/`blinding_diff_scalar` via
`signing_payload_with_envelope`. That is the already-tracked **F149** envelope-
binding concern (documented in transfer_codec.rs:109-119 and tokens.rs:264-308),
an authentication-coverage gap — not a canonical-encoding-validation defect.
Noted here only to disambiguate; H065 makes no claim on it.

## Conclusion
The confidential-transfer wire codec enforces canonical point encoding,
prime-order/subgroup safety (via Decaf448), strict per-field lengths, and
canonical scalar range checks on every decoded element, using validating
constructors exclusively. No canonical-encoding-validation finding.
