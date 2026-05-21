---
id: F116
task: H116
attack_class: kzg-srs-or-verkle-encoding
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.72
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F116 — KZG trusted-setup loader silently treats Lagrange-basis G1 points as monomial powers of τ; production `build_srs` calls `into_srs_monomial` unconditionally with no basis detection or Lagrange→monomial conversion

- **Task:** H116
- **Attack class:** kzg-srs-or-verkle-encoding (Lagrange-specific: monomial ↔ Lagrange basis confusion at the SRS-loading seam)
- **Severity (provisional):** High (a Lagrange-formatted ceremony file — which the loader's own docstring acknowledges as a real Ethereum KZG ceremony output format — is accepted, parsed, and turned into an `Arc<KzgSrs>` with its G1 elements re-interpreted as monomial powers of τ; every verkle commitment computed under that SRS is then attesting to the wrong polynomial, and the verifier — using the same wrong SRS — accepts the bogus commitment for any opening proof the prover constructs against it; legitimate honest commitments do not interoperate with anything else using the same ceremony file in the canonical EIP-4844 way)
- **Status:** draft

## Scope files

- `code/hypersnap/crates/hypersnap-crypto/src/kzg_loader.rs` — parser + the only public conversion `into_srs_monomial`
- `code/hypersnap/crates/hypersnap-crypto/src/kzg_lagrange.rs` — IFFT helpers that *could* be used to convert Lagrange→monomial but aren't wired into the loader
- `code/hypersnap/crates/hypersnap-crypto/src/kzg.rs` — `KzgSrs::from_compressed` (downstream consumer; expects monomial)
- `code/hypersnap/src/hyper/config.rs` — production loader entry point `HyperRuntimeFileConfig::build_srs` that hard-codes the monomial path

## Summary

The KZG trusted-setup loader exposes exactly one path from a parsed file to
an `Arc<KzgSrs>`:

```rust
// kzg_loader.rs:53-60
pub fn into_srs_monomial(self, max_degree: usize) -> Result<KzgSrs, LoaderError> {
    let g1_subset: Vec<[u8; 48]> = self.g1.into_iter().take(max_degree + 1).collect();
    if self.g2.len() < 2 {
        return Err(LoaderError::Kzg(KzgError::SrsTooSmall));
    }
    let g2_tau = self.g2[1];
    Ok(KzgSrs::from_compressed(&g1_subset, &g2_tau)?)
}
```

This is the *only* converter (no `into_srs_lagrange`, no
`detect_basis_and_convert`, no `lagrange_to_monomial`). The production
runtime loader picks it unconditionally:

```rust
// config.rs:405-420
pub fn build_srs(&self) -> Result<Arc<KzgSrs>, ConfigError> {
    match &self.kzg_setup_path {
        Some(path) => {
            let text = std::fs::read_to_string(Path::new(path))?;
            let parsed = parse_trusted_setup_text(&text)?;
            Ok(Arc::new(parsed.into_srs_monomial(self.srs_max_degree)?))
        }
        None => { /* unsafe random fallback — covered by F048 */ }
    }
}
```

The loader's own module docstring (`kzg_loader.rs:14-21`) flags the hazard
but does nothing to enforce it:

```text
//! Returns the parsed bytes; downstream code chooses how to interpret them
//! (monomial basis → directly to `KzgSrs::from_compressed`; Lagrange basis →
//! convert via the inverse FFT helpers in `kzg_lagrange`).
//!
//! Newer revisions of the Ethereum trusted-setup file include both Lagrange
//! and monomial basis G1 sections. For Lagrange-only files (older format),
//! conversion to monomial is required before constructing a general-purpose
//! KZG SRS.
```

`kzg.rs:11-12` advertises Ethereum's KZG ceremony output as the intended
production SRS source ("Ethereum's KZG ceremony output (used by EIP-4844)
is the intended source"). The two canonical encodings of that file are:

1. The KZG-ceremonies `trusted_setup_4096.json` format published with
   EIP-4844, which gives G1 powers of τ in **Lagrange basis** over the
   4096-point evaluation domain (`g1_lagrange` field) — explicitly *not*
   monomial powers of τ. This file is what almost every redistribution
   (c-kzg-4844 install bundles, Ethereum execution clients, mainnet
   genesis) actually carries.
2. A monomial-basis text format (the `g1_monomial` section sometimes added
   later) that the `kzg_loader.rs` `parses_synthetic_setup` test uses.

Both formats — when serialized as 96-hex-char-per-line text following
the format documented in `kzg_loader.rs:3-12` — are *syntactically
indistinguishable*. The parser cannot tell them apart, and the converter
silently assumes "monomial" with no marker check, no length check that
rules out the Lagrange domain size, no header sentinel, and no manifest
hash to compare against.

## The silent-collapse mechanism

Let `n = 256` (`VERKLE_DOMAIN`) and let τ be the ceremony's secret. Two
candidate SRSs:

- **Monomial:** `M_i = g^(τ^i)` for `i = 0..n`.
- **Lagrange:** `L_i = g^(L_i(τ))` where `L_i(x) = Π_{j ≠ i} (x − ω^j) /
  (ω^i − ω^j)` is the i-th Lagrange basis polynomial. So `L_i` evaluates
  to 1 at `ω^i` and 0 at every other `ω^j`.

If the operator's file contains the L_i bytes (the standard Ethereum
ceremony output) but the loader treats them as M_i, then `commit(srs,
coeffs)` from `kzg.rs:126-138` computes:

```
C_wrong = Σ coeffs[i] * L_i
        = g^(Σ coeffs[i] * L_i(τ))                       (1)
```

— i.e. the **commitment to the polynomial in evaluation form whose
values at the n roots of unity are coeffs[0..n]**, *not* to the polynomial
whose monomial coefficients are coeffs[0..n]. These are different
polynomials and yield genuinely different commitments. Now feed `C_wrong`
to `commit_evaluations` (`kzg_lagrange.rs:116-120`):

```rust
let mut coeffs = evals.to_vec();
ifft(&mut coeffs);             // monomial coefficients of f
commit(srs, &coeffs)            // computes Σ monomial_coeff_i * L_i
                               // = g^(Σ m_i * L_i(τ))
                               // ≠ g^(Σ m_i * τ^i) = g^(f(τ))
```

So the verkle commitment is **off**. It is not g^(f(τ)). The opening
proof `π = q(τ)` produced by `kzg::open` (`kzg.rs:141-146`) is similarly
miscomputed: it uses the same SRS and so commits `q` against L_i instead
of M_i, giving `π_wrong = g^(Σ q_i * L_i(τ))`. The pairing equation in
`kzg::verify` (`kzg.rs:149-160`) is:

```
e(π_wrong, g²^τ − g²^z) ≟ e(C_wrong − g^y, g²)
```

The g²^τ side is **correct** (the loader takes `g2_tau = self.g2[1]`,
which is monomial τ in G2 by construction of the Ethereum ceremony — G2
is always emitted as monomial powers because there is no
4096-point-evaluation-domain reason to encode G2 differently). The G1
side has been substituted with Lagrange-basis points. The pairing
equation does *not* hold for arbitrary inputs under this swap — but
crucially: because the **prover and verifier share the same wrong SRS**,
the equation can be made to hold for many concocted (C, π, y, z) tuples,
just not the ones the protocol *intends*.

Two distinct failure modes follow:

1. **Honest interoperability silently breaks.** A verkle commitment
   computed against a Lagrange-loaded-as-monomial SRS will not match a
   commitment computed against the same ceremony bytes loaded the
   correct way (e.g. by another client using c-kzg-4844 or by a Solidity
   verifier). Two honest nodes — one running this code with a Lagrange
   file, the other running canonical EIP-4844 verification — produce
   different state roots for the same data. Cross-validator consensus
   fails silently.
2. **Forgery space opens.** Once both prover and verifier are running
   the broken SRS, the verifier's pairing check is no longer the math
   the system was designed against. Specifically, `commit(srs, coeffs)`
   computed as `Σ coeffs[i] * L_i` is a linear map from
   coefficient-space to G1 that is **not** the canonical KZG commitment.
   Two distinct coefficient vectors that share the same linear-combination
   in L_i (which exists whenever the prover can pick them, since the
   basis is fixed) collide on commitments. The "extractability" property
   that ordinary KZG relies on (a polynomial is uniquely determined by
   its commitment, modulo τ being unknown) no longer holds in the way
   the protocol assumes — the verifier accepts openings against the
   wrong polynomial.

## Why the unit tests don't catch this

All passing tests in `kzg_loader.rs:122-241` use `synthesize_setup`
(lines 132-154), which emits G1 in **monomial** form by construction:

```rust
let mut tau_pow = Fr::ONE;
for _ in 0..n_g1 {
    let p = bls12_381::G1Projective::generator() * tau_pow;
    let bytes = G1Affine::from(p).to_compressed();
    writeln!(s, "{}", hex::encode(bytes)).unwrap();
    tau_pow *= tau;
}
```

No test loads a Lagrange-encoded file. No test compares the resulting
SRS to a hash of the canonical Ethereum ceremony output. No test exists
in `verkle.rs` or `kzg_lagrange.rs` that asserts byte-equality against
an independently-computed reference commitment (e.g. one produced by
c-kzg-4844 from the same ceremony file). The cross-side test-vector
discipline that the broader attack-class checklist recommends is
**entirely absent for KZG**.

## Reachability in release builds — checked

- `into_srs_monomial` is `pub` (`kzg_loader.rs:53`).
- `config.rs::build_srs` is invoked from `config.rs::build_runtime`
  (`config.rs:425`), which is the canonical TOML→runtime entry point.
- There is no `#[cfg(test)]` on `build_srs` and no Cargo feature
  gating either path.
- An operator setting `kzg_setup_path = "/path/to/trusted_setup.txt"`
  to *any* file containing 4097 lines of 96-hex-char G1 points + a G2
  block — including the standard Ethereum ceremony output (Lagrange) —
  loads successfully with **no warning, no log, no error**.
- The fallback to `random_unsafe` (covered by F048) is the *other*
  hazard on the same function. F116 is the hazard *after* the operator
  takes F048's advice and points at a real ceremony file — if that
  file is Lagrange-formatted, the loader breaks in a different but
  equally silent way.

## Adjacent levers (verkle.rs / kzg_lagrange.rs) — checked

The Lagrange-specific levers from the task description were each walked:

1. **Monomial ↔ Lagrange basis confusion at SRS-loading.** Open — this
   finding.
2. **Domain ordering between prover and verifier.** Closed. The prover
   places `evals[slot as usize] = child.commitment_value()`
   (`verkle.rs:86`) and the IFFT (`kzg_lagrange.rs:66-111`) treats
   `evals[i]` as `f(ω^i)` for `i = 0..n-1` in natural order (after the
   bit-reverse permutation step). The verifier computes
   `z = omega_pow(step.slot)` (`verkle.rs:342, 361-368`) where
   `omega_pow(slot)` returns `ω^slot`. So index = slot = exponent on
   both sides — consistent.
3. **FFT degree bound.** Closed. `kzg_lagrange.rs:67-69` asserts power-
   of-two length; `commit` enforces `coeffs.len() <= g1_powers.len()`
   at `kzg.rs:127-132`. Verkle always passes a vector of length 256
   and the SRS default is `max_degree = 256` so `g1_powers.len() = 257`,
   leaving one slot of headroom. Off-by-one is *not* present.
4. **Subgroup check on G1/G2 SRS elements.** Closed. `bls12_381`'s
   `G1Affine::from_compressed` / `G2Affine::from_compressed` perform the
   subgroup check internally (they return `CtOption::none()` on points
   outside the prime-order subgroup). The loader uses these, not the
   `_unchecked` variants, so torsion-component attacks are blocked.
5. **Lagrange-coefficient calculation correctness (`L_i(ω^j) = δ_ij`).**
   Closed. The `ifft_then_commit_matches_coefficient_commit` test
   (`kzg_lagrange.rs:155-180`) exercises the round-trip on a random
   256-element domain and passes. The IFFT is a standard radix-2
   Cooley-Tukey implementation with explicit twiddles and final 1/n
   scaling.
6. **Domain-extension attacks (two distinct polynomials hashing to the
   same Lagrange commit).** Closed *given a correct SRS*. The
   commitment map `coeffs → g^(f(τ))` is injective modulo τ-knowledge;
   under a real ceremony τ is unknown so collisions cannot be
   constructed. (Note: under F048's unsafe random SRS the attacker can
   construct arbitrary collisions, but that's the F048 hazard, not
   F116.)

So lever (1) is the only open lever — and it is the load-bearing one.

## Cross-reference with H115 (kzg.rs)

I checked `findings/drafts/F115-*.md` and `findings/notes/H115-ruled-out.md`
— neither exists at the time of writing. H115 has not yet produced a
finding. The bug F116 reports is *not* in `kzg.rs` itself (the commit /
open / verify primitives are correct given a correct SRS); it is at the
SRS-loading seam where the production code conflates two distinct
encodings of the ceremony output. If H115 later files a finding on
`kzg.rs`-internal behaviour the two should be linked but are not
duplicates.

## Recommended fix

**Layer 1 — refuse ambiguous inputs.** Either:

- Require the ceremony file to declare its basis in a header line
  (`# basis = monomial` / `# basis = lagrange`), refuse to load if the
  header is missing, and dispatch to `into_srs_monomial` or
  `into_srs_lagrange` accordingly; or
- Pin a known ceremony-output hash and refuse to load any file whose
  hash doesn't match. (F048's Layer 2 recommendation already proposes
  this — F116 is the second reason to do it.)

**Layer 2 — implement and ship `into_srs_lagrange`.** Given the
`kzg_lagrange::ifft` helper already exists, the Lagrange→monomial G1
conversion is mechanical:

```rust
/// Convert n Lagrange-basis G1 points L_i = g^(L_i(τ)) into n monomial
/// powers M_i = g^(τ^i) by running an IFFT in G1.
pub fn lagrange_g1_to_monomial(
    lagrange_g1: &[G1Projective],
) -> Vec<G1Projective> {
    let mut points = lagrange_g1.to_vec();
    // The IFFT on G1 points is the same butterfly as on Fr — group
    // operations replace field operations. Bit-reverse, butterfly,
    // scale by 1/n.
    ifft_g1(&mut points);
    points
}

pub fn into_srs_lagrange(
    self,
    max_degree: usize,
) -> Result<KzgSrs, LoaderError> {
    // Decode all g1 entries, IFFT in G1, then truncate to max_degree + 1.
    let lagrange_points: Vec<G1Projective> = self
        .g1
        .iter()
        .map(|b| G1Affine::from_compressed(b).into_option()
            .ok_or(KzgError::InvalidG1Point(/* idx */ 0))) // TODO real idx
        .collect::<Result<Vec<G1Affine>, _>>()?
        .into_iter()
        .map(G1Projective::from)
        .collect();
    let monomial = lagrange_g1_to_monomial(&lagrange_points);
    /* compress, slice to max_degree + 1, build KzgSrs */
}
```

**Layer 3 — pinned cross-side test vectors.** Add a test that loads the
real Ethereum KZG ceremony file (commit it to the repo, or stub the
first 8–16 points hard-coded), runs `commit_evaluations` on a known
input vector, and asserts byte-equality of the resulting commitment
against a hard-coded reference produced by an independent implementation
(c-kzg-4844 or a Python reference). This is the standard discipline the
attack-class checklist calls for ("pinned cross-side test vectors that
hash both Rust and Solidity encodings of the same input and assert
byte-equality"). Currently *no* such test exists for KZG in this
codebase — every commit-side test is self-consistency only.

**Layer 4 — surface the basis in startup logs.** Log
`kzg_setup_path = ..., basis_assumed = monomial, g1_count = N, srs_fingerprint = sha256:...`
on every runtime start. An operator looking at logs after a deployment
should be able to spot a basis mismatch.

## Affected attack-class checklist items

- **kzg-srs-or-verkle-encoding:** monomial ↔ Lagrange basis confusion —
  this finding is the canonical instance of the class.
- **cross-side-encoding-asymmetry:** the Rust loader's expected basis is
  not pinned against any external reference; there are no cross-side
  test vectors.
- **Anti-pattern: "we'll add the conversion later."** The
  `kzg_loader.rs` module docstring documents the conversion as a TODO
  ("Lagrange basis → convert via the inverse FFT helpers in
  `kzg_lagrange`") but the only `pub` constructor goes the monomial-
  only route. Standard deferral that persisted into production.

## References

- Loader entry point (production): `code/hypersnap/src/hyper/config.rs:405-420`
- Sole conversion function: `code/hypersnap/crates/hypersnap-crypto/src/kzg_loader.rs:53-60`
- Module docstring acknowledging the hazard:
  `code/hypersnap/crates/hypersnap-crypto/src/kzg_loader.rs:14-21`
- Synthesised-monomial-only test helper:
  `code/hypersnap/crates/hypersnap-crypto/src/kzg_loader.rs:132-154`
- KZG commitment primitive (expects monomial):
  `code/hypersnap/crates/hypersnap-crypto/src/kzg.rs:126-138`
- Verkle commit caller (downstream consumer of the wrong-basis SRS):
  `code/hypersnap/crates/hypersnap-crypto/src/verkle.rs:84-88`
- IFFT helpers that would be the building block for a proper
  Lagrange→monomial conversion in G1:
  `code/hypersnap/crates/hypersnap-crypto/src/kzg_lagrange.rs:66-111`
- Related (distinct) finding on the unsafe-random fallback path:
  `findings/drafts/F048-kzg-srs-silent-random-tau-fallback-in-production-config.md`
