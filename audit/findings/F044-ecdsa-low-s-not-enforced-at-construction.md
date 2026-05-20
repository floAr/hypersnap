---
id: F044
task: H044
attack_class: low-s-ecdsa-divergence
severity: low
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.80
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  note: "Core thesis stands: from_bytes/from_rsv don't enforce low-S; recover_address_from_prehash silently calls normalized_s (confirmed in alloy-primitives 0.8.26 primitive_sig.rs:319-330; from_raw_array at :132-138 only checks length+v); OZ ECDSA.recover strict-rejects high-S. Cross-side asymmetry is real. Caveats: (1) runtime.rs:9549 cite in body is a #[test] line, not production — the real bytes-as-identity consumers are chain.rs:38-39 (hyper_block_hash mix-in feeding slashing.rs:67-69 SameBlock check) and runtime.rs:2962 (da_boundary_seed_for SHA-256 over raw sig). (2) Bridge framing is forward-looking — DKLS is sole producer today and always normalizes. (3) Slashing-evidence malleability primitive is the most concrete in-protocol consumer and is real but the harm depends on downstream record_evidence/slashed_validators_for_epoch behavior not walked here. See findings/notes/F044-validation.md."
---

# F044 — `EcdsaSignature` wrapper does not enforce low-S at construction; wire-format invariant is unenforced, Rust verifier silently accepts malleated copies

- **Task:** H044
- **Attack class:** low-s-ecdsa-divergence
- **Severity (provisional):** Informational / Low (defense-in-depth gap; no current exploit on the bridge claim path because DKLS does normalize, but contract violations are silent in adjacent paths and create cross-side asymmetry).
- **Status:** draft

## Scope files

- `code/hypersnap/crates/hypersnap-crypto/src/ecdsa.rs`
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_threshold.rs`
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs`
- `code/hypersnap/crates/dkls23/src/protocols/signing.rs` (vendored)
- `code/hypersnap/contracts/src/HypersnapBridge.sol`
- `code/hypersnap/src/hyper/sig_verify.rs`

## Summary

The hyper-layer ECDSA wrapper type `EcdsaSignature` documents — and the
on-chain `HypersnapBridge.sol` (OZ `ECDSA.recover`) requires — that the
`s` component is **low-S** (i.e. `s <= (n-1)/2`). But the wrapper's
construction APIs (`from_bytes`, `from_rsv`) do not actually enforce
this invariant. Today the only production signer is DKLS, which calls
`Party::sign_phase4(..., normalize = true)` and so produces low-S
canonically; the bridge therefore accepts every DKLS-signed root
update / owner update / pause / etc. in practice. The defects are:

1. The documented contract of `from_bytes` ("Fails on wrong length or
   malformed sig (e.g., non-canonical `s`, junk bytes)" — `ecdsa.rs:60-61`)
   is **false**: the underlying `alloy::PrimitiveSignature::try_from` /
   `from_raw` does no low-S check (see
   `alloy-primitives/src/signature/primitive_sig.rs::from_raw_array` —
   only checks length and parses `v` via `normalize_v`).
2. `from_rsv` (`ecdsa.rs:75-85`) only validates `v` and never
   compares `s` against `n/2`.
3. The wire-format doc string `bytes 32..64 : s (big-endian uint256,
   low-S only)` (`ecdsa.rs:27`) is a comment-only promise; nothing in
   the type system or constructors holds the line.
4. The Rust-side verifier `EcdsaSignature::recover_address` calls
   `PrimitiveSignature::recover_address_from_prehash`, which performs
   `let this = self.normalized_s()` before recovery (see
   `primitive_sig.rs:319-330`). So the Rust verifier silently accepts
   **both** `(r, s, v)` and `(r, n-s, v^1)` against the same digest
   while the Solidity verifier accepts only the low-S form. This is a
   cross-side semantic asymmetry.

## Producer-side proof of normalization (so the bridge is currently OK)

The vendored `dkls23` `sign_phase4` (`code/hypersnap/crates/dkls23/src/protocols/signing.rs:651-669`):

```rust
let mut s = numerator * (denominator.invert().unwrap());
if normalize {
    let s_bytes = s.to_repr();
    let s_u256 = U256::from_be_slice(s_bytes.as_ref());
    let neg_one = -C::Scalar::ONE;
    let neg_one_bytes = neg_one.to_repr();
    let order_minus_one = U256::from_be_slice(neg_one_bytes.as_ref());
    let half_order = order_minus_one >> 1;
    if s_u256 > half_order {
        s = -s;
    }
}
```

Both production sign paths pass `normalize = true`:

- `dkls_threshold::run_honest_sign` — `dkls_threshold.rs:421`
- `dkls_sign::DklsSignCoordinator::try_advance_phase3_to_complete` —
  `dkls_sign.rs:373`

So today **all DKLS-produced signatures reaching `HypersnapBridge.sol`
are low-S**, and OZ `ECDSA.recover` accepts them. There is no current
"intermittent claim failure" symptom.

## Why this is still a finding

### (a) Misleading invariant — silent breakage on future signer swaps

`ecdsa.rs`'s top-of-file comment explicitly anticipates non-DKLS
producers: it references a "portal-api signer" that "already produces"
this wire format, and the bridge sigs landing in
`HyperBlockSignature.signature` are described as bit-identical to what
"the bridge has been verifying since launch." Any caller that
constructs an `EcdsaSignature` from an externally-produced `(r, s, v)`
(a Foundry script's `vm.sign`, a single-key `alloy_signer_local::PrivateKeySigner`
in dev tooling, a different library that doesn't normalize, a custom HSM
driver, etc.) can land a high-S signature that the wrapper happily
accepts but the bridge rejects. The symptom is signer-dependent
intermittent failure of `claim` / `rotateOwner` / `pause` /
`proposeUpgrade` / etc. — exactly the malleability-divergence pattern
this attack class warns about.

`alloy_signer_local::PrivateKeySigner::sign_hash_sync` uses
`k256::ecdsa::SigningKey::sign_prehash`, which since k256 0.13 returns
low-S by default — but this is a library-version implementation detail
not a contractual guarantee enforced at the wrapper boundary.

### (b) Cross-side verifier asymmetry — hyper-layer dedup malleability

`recover_address_from_prehash`'s silent `normalized_s()` means the
Rust verifier (`sig_verify::dispatch`) treats `(r, s, v)` and the
malleated counterpart `(r, n-s, v^1)` as both valid signatures over
the same digest by the same group address. Several runtime call sites
key on `ecdsa_signature` bytes for dedup / storage / replication:

- `runtime.rs:3012` stores `da_epoch_seed_signature` keyed on epoch but
  does not normalize the bytes before persisting / comparing them.
- `runtime.rs:9549` hashes `body.ecdsa_signature` for trust-snapshot
  identity.
- Hyperblock signatures are gossiped, stored, and (post-migration)
  used as canonical hyperblock identifiers in WAL replication.

If any consumer treats the raw `ecdsa_signature` bytes as a stable
identity (replay protection, dedup key, on-disk content-address),
malleability lets an attacker who observed one valid signature emit a
**distinct** byte-string that the same Rust verifier accepts. Whether
this is exploitable depends on dedup semantics elsewhere and is
out-of-scope here; the gap is created at this layer.

### (c) "Fails on non-canonical s" is documented-but-false

A future reader auditing the wrapper would reasonably treat the
`from_bytes` docstring as a load-bearing invariant and not re-check
low-S at call sites. This is the same hazard class as the
already-flagged `EcdsaError::ParseFailed` claim — promising stronger
parsing than the underlying library delivers.

## Recommended fix

Either:

**Option A (preferred):** enforce low-S in `EcdsaSignature::from_bytes`
and `from_rsv` by rejecting `s > (n-1)/2`. Add a dedicated error variant
(`EcdsaError::NonCanonicalS`). The check is one comparison against the
pinned secp256k1 half-order constant; cost is negligible. This makes
the type a true cross-side invariant carrier and matches the docstring.

```rust
// secp256k1 (n-1)/2
const SECP256K1_HALF_N: B256 = B256::from_be_slice(&hex!(
    "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
));

pub fn from_rsv(r: B256, s: B256, v: u8) -> Result<Self, EcdsaError> {
    if s.as_slice() > SECP256K1_HALF_N.as_slice() {
        return Err(EcdsaError::NonCanonicalS);
    }
    // ... rest unchanged
}
```

**Option B (acceptable if A is too disruptive):** normalize on
construction (flip `s -> n-s`, `v ^= 1`). Mirrors what
`recover_address_from_prehash` already does internally, but persists
the canonicalization into the stored bytes so wire-format-by-bytes
dedup / signature-bytes-as-identity logic elsewhere becomes safe by
construction.

Then drop the stale `recover_from_prehash` reliance on the silent
normalization — once construction guarantees low-S, the recovery path
need not be lenient.

### Adjacent hygiene

- Add an explicit test that fabricates a high-S signature (e.g. by
  flipping `s -> n-s, v ^= 1` on a known low-S DKLS output) and
  asserts `EcdsaSignature::from_bytes` rejects it.
- Add a pinned cross-side test vector that signs a known
  `DOMAIN_MERKLE_ROOT_UPDATE_V1`-shape payload in Rust and verifies
  in Foundry with the actual OZ `ECDSA.recover` to lock the
  low-S contract in CI.
- Update the wire-format docstring to either state truthfully ("low-S
  is enforced at construction") once fixed, or drop the misleading
  promise.

## Affected attack-class checklist items

- low-s-ecdsa-divergence: producer is OK today, but the wrapper
  type's invariant carrier is broken; cross-side asymmetry between
  Rust `normalized_s()`-on-recover and Solidity strict-reject creates
  bytes-identity ambiguity.
