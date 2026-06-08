---
id: H029
specialist: rust-crypto-primitives
attack_class: ecdsa-recovery-id-handling
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H029 — ECDSA recovery-id (v) handling in EcdsaSignature is RULED OUT

Scope: `crates/hypersnap-crypto/src/ecdsa.rs`
(`EcdsaSignature::from_bytes`, `from_rsv`, `recover_address`,
`verify_against_address`) as consumed by `src/hyper/sig_verify.rs::dispatch`.
Library: `alloy-primitives` 0.8.14 (k256 feature); resolved source read at
`alloy-primitives-0.8.26` in the local cargo registry (`signature/primitive_sig.rs`,
`signature/utils.rs`). secp256k1 / k256 underneath.

## Threat hypotheses tested

1. The 65-byte `(r‖s‖v)` parser mishandles / fails to validate the v byte,
   letting a malformed or out-of-range v through.
2. A wrong or ambiguous v recovers a *different* pubkey/address than the one
   the signer intended, and that recovered address is trusted.
3. Recovery is used without checking the recovered address equals the
   claimed/expected signer (raw-recover-and-trust).
4. recovery_id ∈ {2,3} (R.x ≥ curve order) is silently coerced to a wrong v
   (e.g. 29/30) that the on-chain verifier would reject — or worse, accepted.

All four are ruled out for the scoped path.

## Why v handling is sound

- `from_bytes` (ecdsa.rs:79) length-gates to exactly 65 bytes, then delegates
  v parsing to `PrimitiveSignature::try_from(&[u8])` →
  `from_raw_array` → `normalize_v` (alloy `signature/utils.rs:13`).
  `normalize_v` accepts **only** v ∈ {0, 1, 27, 28, 35..} and reduces it to a
  single parity bit (`v % 2`); v ∈ {2..26, 29..34} returns `None` and surfaces
  as `EcdsaError::ParseFailed`. So a junk/out-of-range v is rejected at
  construction, and only the parity bit can ever influence recovery.
- The v byte therefore carries no exploitable degrees of freedom: it selects
  one of the two candidate public keys for a given (r, s). There is no path
  where attacker control over v recovers the *expected* address from a
  signature the expected signer did not produce — flipping v yields the other
  candidate key, i.e. a different address.

## Why "recover a different address" is not exploitable here

- Every in-scope `EcdsaSignature` consumer uses the **pinned** path
  `verify_against_address` (sig_verify.rs:76; plus runtime.rs:6303/6414/6506/
  6515/8266/8270 and the dkls test/round-trip helpers). That path recovers and
  then `recovered == expected` else `SignerMismatch` (ecdsa.rs:144-149) —
  fail-closed. A wrong/flipped v → wrong recovered address → hard rejection.
- The bare `recover_address` method on `EcdsaSignature` (the
  recover-and-trust-whatever-pops-out shape) is exercised only in unit tests;
  no production caller treats its output as authorization without an
  independent pin. (Other `recover_address_from_prehash` call sites —
  verification.rs, key.rs, token_escrow_*, validator_registry.rs,
  account_association.rs, webhooks/auth.rs — operate on raw alloy
  `PrimitiveSignature`, not `EcdsaSignature`, and are outside the H029 scope of
  `EcdsaSignature`/`sig_verify` dispatch.)
- `sig_verify::dispatch` additionally cross-checks any self-declared
  `group_address` against the expected address before recovery
  (GroupAddressMismatch, sig_verify.rs:59-73), so the comparison target is
  never attacker-supplied.

## Why high-S / parity ambiguity cannot diverge recovery

- alloy's `recover_from_prehash` (primitive_sig.rs:319-330) first calls
  `self.normalized_s()` and recovers with the *normalized* parity. Normalizing
  s>N/2 flips the parity bit, which could otherwise make the recovered key
  depend on whether the caller passed canonical-low or high-S.
- hypersnap's `from_bytes` (ecdsa.rs:90-96) **rejects** s > N/2 (and s == 0)
  before construction (the F044 low-S fix), so every accepted signature is
  already canonical-low-S. alloy's internal `normalized_s()` is consequently a
  no-op for these signatures — the parity used for recovery is exactly the
  parity decoded from byte 64, with no surprise flip. No malleability-driven
  recovery divergence remains.

## Why recovery_id ∈ {2,3} is handled, not silently mis-encoded

- The sign side already closes this (F045): `dkls_threshold.rs:442-453` rejects
  any DKLS23 `recovery_id > 1` with `RecoveryIdOutOfRange`/retry-ceremony rather
  than emitting a non-Ethereum v; `from_rsv` (ecdsa.rs:108-118) only accepts
  {0,1} (normalized to {27,28}) or {27,28} and errors on anything else, so a
  v=29/30 (the "v+27" mis-encoding the checklist warns about) can never be
  produced.
- On the verify side it is moot: `from_bytes` collapses v to a parity bit and
  rejects non-{0,1,27,28,35..} values, and the y_parity used by alloy recovery
  is always 0/1 — recid 2/3 is structurally unrepresentable through this type.

## Cross-side note (not a recovery-id finding)

- `to_bytes` re-serializes v as `27 + y_parity` (alloy `as_bytes`,
  primitive_sig.rs:158-164), matching the {27,28} convention the OZ
  `ECDSA.recover` Solidity verifier consumes — consistent with the wire-format
  doc in ecdsa.rs:23-35. No recovery-id encoding asymmetry across the
  Rust↔Solidity boundary.

Conclusion: the v byte is validated (out-of-range rejected) and reduced to a
parity bit; recovery is always pinned-compared against an out-of-band expected
address (fail-closed); low-S enforcement removes parity-flip ambiguity; and
recovery_id ∈ {2,3} is rejected on the sign side and unrepresentable on the
verify side. No recovery-id handling vulnerability in the scoped code.
