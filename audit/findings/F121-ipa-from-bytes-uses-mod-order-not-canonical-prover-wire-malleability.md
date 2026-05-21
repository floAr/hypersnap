---
id: F121
task: H121
attack_class: balance-closure-or-range-proof
severity: medium
status: draft
---

# F121 — `InnerProductProof::from_bytes` decodes the IPA witness scalars `a` and `b` via `Scalar::from_bytes_mod_order` instead of `Scalar::from_canonical_bytes`, giving the prover wire-byte malleability: distinct, signed, byte-encoded `RangeProof` payloads that all verify against the same `(value, blinding)`

- **Task:** H121
- **Attack class:** `balance-closure-or-range-proof` (range-proof port soundness — sub-class: scalar-canonical-bytes / wire-malleability in the ported IPA)
- **Severity (provisional):** Medium. Not a balance or range break — verification math is unchanged because the non-canonical input reduces to the same canonical scalar mod `L`. But this is a clear divergence from the well-audited upstream curve25519-dalek-bulletproofs (which explicitly uses `from_canonical_bytes` for exactly this reason) and from every other parser in the same hypersnap crate (`range_proof::from_bytes`, `linear_proof::from_bytes`, `r1cs::proof::from_bytes` — all canonical). The exploitable surface is **prover-side wire malleability**: for any honest `(value, blinding)` the prover can serialize ≥ 9 distinct byte sequences that all decode to the same proof and all carry valid Schnorr spend-signatures (because each signature is computed over its own chosen encoding). This breaks any property that assumes "one logical transfer ↔ one canonical byte string": censorship via byte-hash blocklist, mempool-fingerprint-keyed rate limiting, fork-on-bytes between validator implementations, and any future consensus rule that hashes the transfer wire bytes as an identifier. Nullifier-dedup and signed-over-payload bind value/balance, so this is not a direct theft; it is a soundness-of-port + wire-canonicality finding.
- **Status:** draft

## Scope files

- `code/hypersnap/crates/ed448-bulletproofs/src/inner_product_proof.rs:412` — `let a = Scalar::from_bytes_mod_order(a_bytes);` — IPA witness scalar `a` decoded mod-order from 56 raw bytes; non-canonical inputs (`a + k·L` for k ∈ {1, 2, …} with `a + k·L < 2^448`) are silently reduced and accepted.
- `code/hypersnap/crates/ed448-bulletproofs/src/inner_product_proof.rs:417` — `let b = Scalar::from_bytes_mod_order(b_bytes);` — same for `b`.
- `code/hypersnap/crates/ed448-bulletproofs/src/inner_product_proof.rs:374` — docstring promises *"any of 2 scalars are not canonical scalars modulo Ed448 group order"* → return error. The implementation contradicts the docstring.
- `code/hypersnap/crates/ed448-bulletproofs/src/curve_adapter.rs:446-466` — `from_bytes_mod_order` vs `from_canonical_bytes` semantics in this port.
- `code/hypersnap/crates/ed448-bulletproofs/src/range_proof/mod.rs:549,554,559` — RangeProof's own three scalars are decoded with `from_canonical_bytes` and rejected on FormatError, demonstrating the established pattern; the IPA's two scalars then break that pattern.
- `code/hypersnap/crates/ed448-bulletproofs/src/range_proof/mod.rs:561` — `RangeProof::from_bytes` delegates the IPA segment to `InnerProductProof::from_bytes`, so every range-proof wire-decode path is affected.
- `code/hypersnap/crates/ed448-bulletproofs/src/linear_proof.rs:389,391` — sibling parser uses `from_canonical_bytes`, confirming this was the intended convention.
- `code/hypersnap/crates/ed448-bulletproofs/src/r1cs/proof.rs:177-179` — sibling parser uses `from_canonical_bytes`.
- `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:158-176` — `verify_value_range(...)` is the production entry point that funnels every wire range-proof through `RangeProof::from_bytes` → `InnerProductProof::from_bytes` → the buggy `from_bytes_mod_order`.
- `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:237-256` — `TransferTx::signing_payload` includes `out.range_proof` bytes verbatim (length-prefixed). Per-input Schnorr spend signatures sign this payload (lines 334-337, 362-365), so the bytes are signature-bound BUT the signer is the prover, so the prover gets to pick which encoding to sign — multiple variants, each individually well-signed, all verify.
- `code/hypersnap/src/hyper/transfer_codec.rs:78-87` — `output_from_proto` clones `range_proof` bytes verbatim; no re-canonicalization on the verifier path.
- Compare upstream `dalek-cryptography/bulletproofs`, `src/inner_product_proof.rs:from_bytes`: uses `Scalar::from_canonical_bytes(...).ok_or(ProofError::FormatError)?` for both `a` and `b`.

## Root cause

`InnerProductProof::from_bytes` (lines 375-420):

```rust
let mut a_bytes = [0u8; 56];
a_bytes.copy_from_slice(&slice[pos..pos + 56]);
let a = Scalar::from_bytes_mod_order(a_bytes);     // <-- accepts non-canonical

let pos = pos + 56;
let mut b_bytes = [0u8; 56];
b_bytes.copy_from_slice(&slice[pos..pos + 56]);
let b = Scalar::from_bytes_mod_order(b_bytes);     // <-- accepts non-canonical

Ok(InnerProductProof { L_vec, R_vec, a, b })
```

For comparison, the same crate's `RangeProof::from_bytes` does the right thing three lines higher in the parsing stack:

```rust
let t_x = Scalar::from_canonical_bytes(t_x_bytes).ok_or(ProofError::FormatError)?;
// ... t_x_blinding, e_blinding same pattern
let ipp_proof = InnerProductProof::from_bytes(&slice[7 * 56..])?;   // <-- then falls into the non-canonical path
```

The docstring on `from_bytes` at line 374 explicitly states:

```
/// * any of 2 scalars are not canonical scalars modulo Ed448 group order.
```

so the intent matches upstream; the implementation diverged. Same divergence does NOT exist in `linear_proof.rs` (which uses `from_canonical_bytes` correctly) nor in `r1cs/proof.rs` (also correct). This is a single-site port mistake.

## Why every encoding decodes to the same proof

Ed448 prime-order group order: `L ≈ 2^446 - 0x335...` (446 bits). Scalars are wire-encoded as 56-byte = 448-bit little-endian. For any canonical `a ∈ [0, L)`:

- `a + L < 2L < 2^447 < 2^448` — fits in 56 bytes, reduces mod `L` to `a`.
- `a + 2L < 3L < 3 · 2^446 < 2^448` — fits in 56 bytes, reduces mod `L` to `a`.
- `a + 3L > 3 · 2^446 > 2^447` and may or may not fit; conservatively, **at minimum** `{a, a + L, a + 2L}` always fit and all reduce to `a` via `from_bytes_mod_order`.

So for any honest `(a, b)` proof, the prover can emit ≥ 3 × 3 = 9 byte-distinct serializations of the IPA segment (3 choices for `a`, 3 for `b`), each of which `RangeProof::from_bytes → InnerProductProof::from_bytes` accepts and each of which produces an `InnerProductProof { a, b, … }` whose internal scalars are identical to the canonical proof's. Hence the verification equation in `verification_scalars` + `verify_multiple` evaluates identically and accepts every variant.

## What signature-binding does and does not protect

The spend-signature path:

```rust
// tokens.rs:237-256
pub fn signing_payload(&self) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hypersnap-transfer-v1");
    // ... input commitments, nullifiers ...
    for out in &self.outputs {
        h.update(out.commitment.to_bytes());
        h.update((out.range_proof.len() as u32).to_be_bytes());
        h.update(&out.range_proof);              // <-- range-proof bytes ARE signature-bound
    }
    h.update(self.fee_atoms.to_be_bytes());
    // ... finalize
}

// tokens.rs:334-337, 362-365: each input verifies its Schnorr sig over this payload.
```

So **third-party** byte-mutation is blocked — flipping a non-canonical encoding to canonical (or vice-versa) changes the SHA-256 of the signing payload and breaks every input's Schnorr signature. A passive gossip relayer or block builder cannot weaponize the malleability against a victim signer.

What IS open: the **prover** (the signer of the inputs) gets to pick which encoding to sign. They can produce N byte-distinct, well-signed, validation-passing `TransferTx` payloads for the same logical transfer:

- same input commitments / nullifiers,
- same output commitments,
- same fee,
- same Pedersen balance closure (the residual is determined by the values + blindings, not by the IPA bytes),
- different range-proof bytes,
- different `signing_payload` hash,
- different per-input Schnorr signatures (each correctly produced under the same per-input spend secret over the chosen payload).

Nullifier dedup at `validate_against_store` / on-chain `note_store` blocks double-spend: only the first-applied variant gets its outputs recorded; subsequent variants fail at `InputCommitmentUnknown` or `NullifierAlreadySpent`. So this is **not a value bug**.

## Concrete exploitation paths

These are all secondary effects, but each is real:

1. **Censorship circumvention via byte-hash blocklist.** Any node that maintains a "drop this transfer's wire bytes" list (block-explorer abuse list, governance-driven blocklist, or per-tx-bytes mempool-quarantine cache) is bypassed by re-broadcasting a malleated variant. Operators have no canonical anchor to key the blocklist by (other than nullifier — and nullifier reveals identity of the input note to anyone who already knows that note).

2. **Mempool-fingerprint-keyed rate limiting / cache poisoning.** If a future ingress rate-limiter is keyed by `SHA256(transfer_bytes)` (a natural choice — many mempool implementations do this), the prover can multiply per-bytes-hash quota by ≥ 9× by submitting the variant set. With m output ranges, the multiplier is `(≥ 9)^m`; for a 4-output transfer that is ≥ 6561 variants per logical transfer.

3. **Per-block-builder fork pressure.** If two validator implementations canonicalize on byte-decode (one re-emits `to_bytes` after decode — which always produces canonical form — while the other forwards the wire bytes verbatim), the same logical tx propagated through the two paths produces different downstream bytes. Any downstream Merkle root keyed on transfer bytes (block transactions root, receipt Merkle, etc.) diverges. The current hypersnap codebase does NOT yet have such a root (the block roots are over `proto::HyperMessage` opaque bytes), so this is a future-fork risk, not a present-fork bug.

4. **Conformance / standard-of-care.** The upstream dalek-bulletproofs deliberately rejects non-canonical scalars, and Wycheproof's scalar-validation suite expects this behaviour. Any external auditor or cross-implementation test vector consumer will flag this divergence.

The first two are immediately exploitable; the third becomes exploitable as soon as a Merkle root or block-hash includes a transfer-bytes hash; the fourth is a standard-of-care issue.

## Why this was not caught upstream

- The crate's only round-trip test (`test_helper_create` at `inner_product_proof.rs:446-526`) calls `to_bytes()` to produce the input to `from_bytes`. `Scalar::to_bytes` always emits canonical bytes (canonical scalar → canonical encoding), so the test never exercises the `from_bytes_mod_order` reduction path. A targeted test that injects `a + L` would have failed.
- The docstring at line 374 says "any of 2 scalars are not canonical scalars modulo Ed448 group order" → returns FormatError. The dev who wrote the docstring almost certainly intended `from_canonical_bytes`; the body uses the wrong function. This is a textbook port-mistake pattern.
- All three sibling parsers in the same crate (`range_proof::from_bytes`, `linear_proof::from_bytes`, `r1cs::proof::from_bytes`) use `from_canonical_bytes` correctly, so the convention was established — only this single site diverged.

## Verification walk

1. `Scalar::from_bytes_mod_order(bytes)` (curve_adapter.rs:446-452): unconditionally calls `DecafScalar::from_bytes_mod_order` — always succeeds, always returns the canonical residue. Returns no `Option`/`Result`.
2. `Scalar::from_canonical_bytes(bytes)` (curve_adapter.rs:460-466): returns `Option<Self>`; `None` if `bytes` ≥ `L` in little-endian encoding.
3. Diff against upstream `bulletproofs/src/inner_product_proof.rs`: upstream `from_bytes` reads:
   ```rust
   let a = Option::from(Scalar::from_canonical_bytes(read32(&slice[pos..])))
       .ok_or(ProofError::FormatError)?;
   let b = Option::from(Scalar::from_canonical_bytes(read32(&slice[pos + 32..])))
       .ok_or(ProofError::FormatError)?;
   ```
4. Compare to the port at `inner_product_proof.rs:410-417` (this crate) — `from_bytes_mod_order`, no `Option`, no `FormatError`. Single-line bug.

## Cross-reference

- **F149** (transfer-codec one-time-pubkey and blinding-diff not signed): adjacent but distinct. F149 is about fields *outside* the signing payload (`one_time_pubkey`, `blinding_diff_scalar`); F121 is about a malleable encoding of a field *inside* the signing payload (`range_proof` bytes). Mitigating F149 by adding `one_time_pubkey` to the signing payload would NOT fix F121.
- **H120** (generator setup, port soundness): ruled out — the generators are NUMS. F121 is downstream of that ruling: the curve/generator construction is sound, but the wire codec for the IPA witness scalars is not.
- **H122** (linear-proof port soundness): ruled out — and `linear_proof.rs:389,391` confirms `from_canonical_bytes` was the established convention.
- **H055** (range-proof-bound-too-loose): ruled out — the bit-bound is fine; the IPA's wire codec is the new issue.
- **H056** (commitment-opening-leak): ruled out — unrelated to wire codec.

## Suggested remediation

Replace the two lines at `code/hypersnap/crates/ed448-bulletproofs/src/inner_product_proof.rs:412,417`:

```rust
let a = Scalar::from_canonical_bytes(a_bytes).ok_or(ProofError::FormatError)?;
// ...
let b = Scalar::from_canonical_bytes(b_bytes).ok_or(ProofError::FormatError)?;
```

This matches upstream dalek, matches the crate's own RangeProof / LinearProof / R1CS parsers, matches the docstring at line 374, and closes the prover-side wire malleability. The change has zero effect on honest-prover serialization (canonical scalars round-trip identically) and zero performance impact (canonical-byte check is constant-time on 56 bytes).

A confirming test would inject `a + L` into the serialized form and assert `RangeProof::from_bytes` returns `FormatError`:

```rust
#[test]
fn ipa_from_bytes_rejects_non_canonical_a() {
    // construct a valid proof, then add L to the encoded `a`
    // assert from_bytes returns FormatError
}
```

## What this finding does NOT claim

- Not a balance break. The IPA verification equation is unchanged because both encodings reduce to the same canonical scalar in the in-memory representation. The Pedersen balance closure (residual = r_diff · B_blinding) is computed over the in-memory point arithmetic, not the wire bytes.
- Not a range-bound break. The bit-width gates at `verify_multiple` (n ∈ {8, 16, 32, 64, 128, 256}) and the bp_gens capacity gate at `bp_gens.gens_capacity < n` still apply identically.
- Not a third-party theft. The signature path binds the chosen byte encoding; only the original prover can produce the variant set.

The finding is specifically about **prover-side wire malleability** and **divergence from the canonical bulletproofs wire-codec contract** in a single-site port mistake.
