---
id: F048
task: H048
attack_class: kzg-srs-loader-fallback
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F048 — `HyperRuntimeFileConfig::build_srs` silently falls back to a `random_unsafe` KZG SRS when `kzg_setup_path` is unset; `random_unsafe` is `pub` (not `cfg(test)`) and reachable in release builds

- **Task:** H048
- **Attack class:** kzg-srs-loader-fallback
- **Severity (provisional):** High (catastrophic for any deployment that omits `kzg_setup_path` — every verkle commitment / KZG proof becomes forgeable by whoever ran the node, because the τ that constructs the SRS is generated in-process from `OsRng` and is therefore knowable; the function's own docstring labels the fallback "unsafe for production" but no compile-time, runtime, or config-validation gate enforces this).
- **Status:** draft

## Scope files

- `code/hypersnap/crates/hypersnap-crypto/src/kzg.rs` (the
  `random_unsafe` / `from_tau_unsafe` constructors)
- `code/hypersnap/crates/hypersnap-crypto/src/kzg_loader.rs` (the
  ceremony-file parser — itself fine)
- `code/hypersnap/crates/hypersnap-crypto/src/kzg_lagrange.rs` (downstream
  consumer; not the source of the bug)
- `code/hypersnap/src/hyper/config.rs` (the production loader entry
  point that contains the silent fallback)

## Summary

The KZG SRS loader entry point used by every `HyperRuntime` constructed
from a TOML config — `HyperRuntimeFileConfig::build_srs()` in
`code/hypersnap/src/hyper/config.rs:405-420` — silently falls back to
`KzgSrs::random_unsafe(OsRng, srs_max_degree)` when the optional
`kzg_setup_path` field is `None`:

```rust
// config.rs:405-420
pub fn build_srs(&self) -> Result<Arc<KzgSrs>, ConfigError> {
    match &self.kzg_setup_path {
        Some(path) => {
            let text = std::fs::read_to_string(Path::new(path))?;
            let parsed = parse_trusted_setup_text(&text)?;
            Ok(Arc::new(parsed.into_srs_monomial(self.srs_max_degree)?))
        }
        None => {
            let mut rng = rand::rngs::OsRng;
            Ok(Arc::new(KzgSrs::random_unsafe(
                &mut rng,
                self.srs_max_degree,
            )))
        }
    }
}
```

`kzg_setup_path` is `#[serde(default)]` (`config.rs:43`) and `Option<String>`
(`config.rs:44`), so omitting the field from the deployment TOML — or
deserializing a config file that pre-dates the addition of the field —
deserializes to `None` and silently picks the unsafe branch. The default
struct literal at `config.rs:697` (used by `HyperRuntimeFileConfig::default`-
style construction) also hard-codes `kzg_setup_path: None`. The function
docstring acknowledges the hazard ("either by loading the ceremony file or
(test-only) by sampling a random τ", `config.rs:404`) and the field doc
says "fine for testing but unsafe for production" (`config.rs:41-42`) —
both are comment-only.

Underneath, the primitive `KzgSrs::random_unsafe` (kzg.rs:49-53) is
declared `pub` and only `#[doc(hidden)]`; it is **not** `#[cfg(test)]`,
**not** behind a `cfg(debug_assertions)` gate, and **not** behind a Cargo
feature flag. It compiles into release artifacts, is callable from any
downstream crate, and the wrapper above unconditionally calls it on the
fallback path:

```rust
// kzg.rs:49-53
/// Sample an SRS using a fresh random τ. **Test-only** — no toxic-waste
/// destruction, the τ is in process memory and may leak.
#[doc(hidden)]
pub fn random_unsafe<R: RngCore + CryptoRng>(rng: &mut R, max_degree: usize) -> Self {
    let tau = Fr::random(rng);
    Self::from_tau_unsafe(tau, max_degree)
}
```

The hyper crate then takes `srs` as `Arc<KzgSrs>` in the production
runtime config (`runtime.rs:121: pub srs: Arc<KzgSrs>`) and passes it
to every verkle commit / open / verify call. There is no later
validation against a known ceremony-output checksum, no fingerprint
the verifier can compare against a hard-coded public reference, and
no panic if the SRS does not match a pinned hash.

## Why this is critical

The security of KZG depends on `τ` (the trusted-setup secret) being
**unknown to every party**. The published Ethereum KZG ceremony achieves
this via an MPC with hundreds of participants where any one honest
participant suffices. The `random_unsafe` path defeats this completely:

1. `Fr::random(&mut rand::rngs::OsRng)` samples `τ` inside the running
   process; the process holds `τ` in memory at the moment of generation.
   Even if `τ` is then overwritten, the same process can choose not to
   (or any debugger / memory dumper / cooperating operator can extract
   it before it goes out of scope).
2. Anyone who knows `τ` can forge a KZG opening for any polynomial at
   any point: pick desired `(C, z, y)`, choose any opening `π`, then
   solve for the "corresponding polynomial" using `τ`. With `τ` known,
   the pairing equation `e(π, g²^τ − g²^z) ≟ e(C − g^y, g²)` can be
   satisfied for arbitrary `(C, z, y, π)` because the prover can set
   `π = (C − g^y) / (g^τ − g^z)` directly — and computing that scalar
   division requires exactly the knowledge of `τ` that the ceremony is
   meant to deny.
3. Every verkle proof in the hyper state root is therefore forgeable
   by the operator (or by anyone who compromised the node at SRS-build
   time). State inclusion claims, balance proofs, nullifier-set
   membership proofs — all become attestable to arbitrary values.

In a multi-validator setting this is even worse: every validator
independently generates **its own** `τ`, so commitments produced by
validator A's SRS will not verify under validator B's SRS at all (and
forgeries by A only fool A's own proofs). The system either silently
diverges on state roots (different SRSs => different commitments for
the same data) or — if all validators happen to share an SRS via some
out-of-band mechanism — everyone trusts the SRS-builder unconditionally.
Neither outcome matches the trust assumptions the design documents
claim.

## Reachability in release builds — checked

- `KzgSrs::random_unsafe` is `pub` (no `#[cfg(test)]`, no feature
  flag): `kzg.rs:49-53`.
- `KzgSrs::from_tau_unsafe` (the underlying constructor) is also `pub`
  and `#[doc(hidden)]`-only: `kzg.rs:34-45`.
- The crate exposes `pub mod kzg;` from `lib.rs:29`, so any consumer
  can call it.
- `config.rs::build_srs` is called from `config.rs::build_runtime` at
  line 425, which is the canonical TOML→runtime entry point used by
  the snapchain main binary. There is no `#[cfg(test)]` on this
  module.
- The `random_unsafe` fallback predicate is `self.kzg_setup_path.is_none()`.
  A production deployment that simply forgets to add the `kzg_setup_path`
  key to its TOML — or copies a devnet TOML and edits other fields —
  gets the unsafe path with **no warning, no log, no error**.

In contrast, the parallel hazard for the transport secret on the
adjacent line (`config.rs:432-436`) at least documents the same pattern
("None → fall back to the zero secret. This is a hard-compromised
placeholder; production operators MUST set transport_secret_path."),
and is structurally weaker (compromised transport encryption is bad
but does not let attackers forge state).

## Recommended fix

**Layer 1 — hard-fail in release builds.** `build_srs` should be a hard
error when `kzg_setup_path` is `None`, and the `random_unsafe` path
should be reachable only behind a `#[cfg(test)]`, `#[cfg(feature = "test-utils")]`,
or explicit `--allow-unsafe-srs` startup flag.

```rust
pub fn build_srs(&self) -> Result<Arc<KzgSrs>, ConfigError> {
    let path = self.kzg_setup_path.as_ref()
        .ok_or(ConfigError::MissingKzgSetupPath)?;
    let text = std::fs::read_to_string(Path::new(path))?;
    let parsed = parse_trusted_setup_text(&text)?;
    Ok(Arc::new(parsed.into_srs_monomial(self.srs_max_degree)?))
}
```

For the test code that legitimately needs an in-process SRS, gate the
constructor behind a feature flag in `hypersnap-crypto/Cargo.toml`:

```toml
[features]
unsafe-test-srs = []
```

```rust
#[cfg(feature = "unsafe-test-srs")]
pub fn random_unsafe<R: RngCore + CryptoRng>(...) -> Self { ... }
```

then enable that feature in `[dev-dependencies]`-style test contexts
only, never in the production binary.

**Layer 2 — pin a ceremony fingerprint.** After loading, hash the
parsed `(g1_powers, g2_tau)` and compare to a hard-coded constant
matching the Ethereum KZG ceremony output for the chosen degree. If
the hash does not match, refuse to start. This catches both the
"forgot to set the path" and "set the path to a synthesized
setup file" failure modes.

```rust
const EXPECTED_SRS_HASH: [u8; 32] = hex!("..."); // pinned to ETH KZG ceremony output

let actual = blake3::hash(/* canonical encoding of g1_powers + g2_tau */);
if actual.as_bytes() != &EXPECTED_SRS_HASH {
    return Err(ConfigError::SrsHashMismatch);
}
```

**Layer 3 — startup log.** Independent of the above, emit a log line
on every runtime construction stating which SRS source is in use
(`kzg_setup_path = /path/to/file.txt, sha256 = ...`) so operators have
a concrete artifact to audit and so reviewers grepping logs can spot
the unsafe fallback in any environment.

**Layer 4 — name the constructor honestly at the wrapper layer.** Even
if `random_unsafe` stays available behind a feature, rename it
upstream of the wrapper to something like
`KzgSrs::insecure_random_for_tests_only` so any future call site
reads as a red flag in code review.

## Affected attack-class checklist items

- **kzg-srs-loader-fallback:** the canonical pattern — a `random_unsafe`
  fallback that fires whenever the real setup file is missing, with
  no compile-time gate and only a comment-level warning. Same hazard
  shape as the `library-fork-attribution` cautions on vendored
  fallback paths.

## References

- Loader entry point: `code/hypersnap/src/hyper/config.rs:405-420`
- Fallback predicate: `code/hypersnap/src/hyper/config.rs:406` (matches
  `&self.kzg_setup_path` — `None` arm at line 412-418 takes the unsafe path)
- Unsafe constructor: `code/hypersnap/crates/hypersnap-crypto/src/kzg.rs:49-53`
- Underlying primitive: `code/hypersnap/crates/hypersnap-crypto/src/kzg.rs:34-45`
- Field declaration with comment-only "unsafe for production" warning:
  `code/hypersnap/src/hyper/config.rs:40-44`
- Default literal that bakes in `kzg_setup_path: None`:
  `code/hypersnap/src/hyper/config.rs:697`
- `lib.rs:29` exposes `pub mod kzg;` — no feature gating on the module.
