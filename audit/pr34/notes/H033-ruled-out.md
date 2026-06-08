---
id: H033
specialist: rust-crypto-primitives
attack_class: kzg-srs-loader-fallback
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H033 — KZG SRS loader has NO silent unsafe fallback on the production path

Scope (named): `crates/hypersnap-crypto/src/{kzg,kzg_loader,kzg_lagrange}.rs`.
Followed the production loader into `src/hyper/config.rs::build_srs`, which is
where the file-vs-random decision actually lives.

Hypothesis: if the trusted-setup ceremony file is missing/unreadable, the
loader silently falls back to a randomly-generated (known-toxic-waste) SRS,
letting anyone who observed the τ in process memory forge verkle/KZG inclusion
proofs over committed state.

**Not exploitable.** The unsafe SRS constructors are test-gated, and the
production SRS builder hard-errors when the ceremony file is absent unless an
operator explicitly opts in via a flag that defaults to `false`. There is no
silent fallback.

## Load-bearing facts

Unsafe constructors are test-only, not a fallback.
`KzgSrs::random_unsafe` / `KzgSrs::from_tau_unsafe`
(`crates/hypersnap-crypto/src/kzg.rs:35-53`) are both annotated
`#[doc(hidden)]` with explicit "Test-only — exposing τ defeats the security"
doc comments. Every non-test caller of `random_unsafe` across the tree is
inside a `#[cfg(test)]` module or the by-name `src/bin/devnet.rs` devnet binary
(line 29) — never the production runtime path. The three scoped files
themselves contain *no* loader fallback: `kzg_loader.rs` only parses the
c-kzg-4844 text format and constructs via `from_compressed` (which validates
every point and rejects malformed input); `kzg_lagrange.rs` is pure
IFFT/commit math with no SRS sourcing.

Production SRS builder fails closed.
`HyperRuntimeFileConfig::build_srs` (`src/hyper/config.rs:465-500`):

    match &self.kzg_setup_path {
        Some(path) => { /* require declared monomial basis (F116),
                           read file, parse, into_srs_monomial */ }
        None => {
            // F048 fix: refuse the silent random-τ fallback in production.
            if !self.allow_random_kzg_srs {
                return Err(ConfigError::MissingKzgSetup);
            }
            // ... only here: KzgSrs::random_unsafe(...)
        }
    }

So a missing `kzg_setup_path` does NOT silently generate a random SRS — it
returns `ConfigError::MissingKzgSetup` and the node refuses to start. The
random path is reachable only when an operator has explicitly set
`allow_random_kzg_srs = true`.

The opt-in flag defaults to false.
`allow_random_kzg_srs: bool` (`config.rs:56-63`) carries `#[serde(default)]`,
which for `bool` is `false`. A production TOML that omits the flag deserializes
to `false`, so the gate at line 490 fires and the node fails closed. The only
place the flag is set `true` in the entire tree is the `#[cfg(test)]` helper
`make_file_config` (`config.rs:785`); the other two `= true` grep hits
(`config.rs:41`, `:316`) are doc-comment / error-message text, not code.

No struct-literal bypass.
The runtime's `HyperRuntimeConfig.srs` (`src/hyper/runtime.rs:131`) is populated
in production solely through `build_runtime → build_srs`
(`config.rs:504-505`). Direct `srs:` struct-literal assignments
(`runtime.rs:5090,5118,5643,5792`) are all in the test region of runtime.rs
(the surrounding SRS values there are `random_unsafe`, i.e. tests). No
production code path injects an SRS while bypassing the `build_srs` gate.

## Defense-in-depth already present (prior fixes referenced in code)

- **F048**: the random-τ fallback was converted from silent to opt-in
  (`config.rs:483-492`). This is exactly the kzg-srs-loader-fallback class and
  it is already closed.
- **F116**: a `kzg_setup_path` requires an explicit `kzg_basis` declaration
  (`config.rs:474-478`); a Lagrange-basis file is rejected
  (`LagrangeKzgSetupNotSupported`) rather than silently mis-interpreted as
  monomial. This prevents a different silent-misload failure but reinforces
  that the loader is fail-closed by design.

## Verdict

The production verkle SRS loader is fail-closed: missing ceremony file →
`MissingKzgSetup` hard error unless `allow_random_kzg_srs` (default `false`) is
explicitly enabled for devnet/test. The unsafe random-τ constructors are
`#[doc(hidden)]` test helpers reachable in production only via deliberate
operator opt-in. No silent toxic-waste fallback exists. H033 ruled out.
