---
id: F028
specialist: rust-threshold-signing
attack_class: threshold-vs-share-count-mismatch
title: DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set size), so any single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations
severity_initial: critical
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/main.rs
  - code/hypersnap/src/hyper/dkls_supervisor.rs
  - code/hypersnap/src/hyper/dkls_committee.rs
  - code/hypersnap/crates/hypersnap-crypto/src/dkls_threshold.rs
  - code/hypersnap/src/hyper/actor.rs
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The DKLS23 reconstruction threshold used to run the per-epoch DKG is taken
verbatim from a single static config field (`DklsSupervisorInputs.threshold`)
and is **never validated against the active-validator-set size** and **never
floored to a BFT-safe value**. In the production node-bootstrap path that
field is hard-coded:

`code/hypersnap/src/main.rs:1603`
```rust
let dkls_threshold = 1u8;
```

`build_driver` (`dkls_supervisor.rs:175`) then derives `share_count` from the
*real* active set (`share_count = active.len()`) but plugs the static
`inputs.threshold` straight into the DKG parameters with no relationship check:

`code/hypersnap/src/hyper/dkls_supervisor.rs:203`
```rust
let parameters = Parameters {
    threshold: inputs.threshold,   // = 1, regardless of share_count
    share_count,                   // = active.len(), e.g. 5, 10, 32
};
```

The result is a `1-of-N` group key for any validator set of size N. Because
DKLS23 signs with *exactly* `threshold` parties, the signing committee for
every ceremony is a **single** validator, and that one validator's share
alone produces a valid `(r, s, v)` group signature recovering to the group
address. One validator therefore unilaterally controls every threshold-signed
authority in the system.

## Where the mismatch lives

The lower layers are individually "correct" but enforce no floor, so the
config value flows through unchecked:

- `dkls_threshold.rs:115` (`run_honest_dkg`) rejects only `threshold == 0 ||
  threshold > share_count`. `threshold = 1, share_count = N` passes.
- `dkls_committee.rs:59` (`select_signing_committee`) rejects only the same
  two cases; `threshold = 1` is explicitly supported and even pinned by the
  `pinned_vector_one_of_three` test (`dkls_committee.rs:240`), which asserts a
  committee of size 1 for a 3-party group.
- At sign time the threshold is read back from the installed share
  (`actor.rs:2645` `share.party.parameters.threshold`) and fed to
  `select_signing_committee` (`actor.rs:2659`). With `threshold = 1`,
  `select_signing_committee` returns exactly one index — the lowest-rank
  party — and only that party (the `committee.contains(&local_party_index)`
  gate at `actor.rs:2666`) runs the single-party DKLS sign and broadcasts the
  finished signature.

There is no code path anywhere between config and DKG that requires
`threshold ≥ 2`, `threshold > share_count / 2`, or `threshold ≥ 2f+1`. The
`threshold == share_count == 1` checks scattered through `runtime.rs`
(e.g. lines 1079-1081, 1428) and `actor.rs:1289` are *local-sign shortcut*
detectors (for single-validator devnets that skip the gossip ceremony); they
do not constrain the multi-party threshold and in fact normalize the idea
that a `1`-threshold group is a legitimate operating mode.

## Impact

The DKLS23 group signature is the sole authority over (per `00-OVERVIEW.md`):
hyperblock production, reward/emission issuance, trust snapshots, **bridge
merkle-root (lock-leaf) updates, bridge owner rotations, and pause/upgrade
authorizations**. A `1-of-N` group means:

- Any single validator that wins the deterministic committee draw for a given
  `(epoch, digest)` signs alone, with no cosigners and no quorum. Equivocation
  detection (which assumes a fixed committee per `(epoch, digest)`) does not
  help, because the lone signer is the legitimately-selected committee.
- Compromise or malice of *one* validator forges bridge lock-root updates and
  owner rotations, i.e. mints arbitrary wrapped `SNAP` on the EVM side and/or
  seizes the bridge owner — a fund-loss / total-bridge-takeover primitive,
  with no t-of-n safety whatsoever.
- The system's entire threshold-security premise is void in production; the
  group key is effectively held by whichever single validator the committee
  selector elects each epoch.

Severity: critical. The threshold-signing scheme provides no security beyond a
single-key signer despite running an N-party DKG and presenting itself as a
threshold system.

## Reproduction / evidence

- Boot a multi-validator network through the production path in
  `main.rs` (operator identity configured). `dkls_threshold = 1u8` is fixed at
  `main.rs:1603` and passed to `dkls_supervisor::run`.
- For target epoch with active set of size N, `build_driver` constructs
  `Parameters { threshold: 1, share_count: N }` and runs the DKG; every
  validator receives a share of a 1-of-N key.
- At any ceremony, `select_signing_committee(epoch, seed, N, 1)` returns a
  single index; that party's `run_honest_sign`-equivalent single-party DKLS
  sign yields a full group signature. (The `dkls_committee` unit tests
  `selection_size_equals_threshold` and `pinned_vector_one_of_three` confirm
  committee size == threshold == 1.)

## Recommended fix

- Derive the threshold from the active-set size with a BFT-safe floor at
  `build_driver` time, e.g. `threshold = floor(2 * share_count / 3) + 1`
  (or the project's intended quorum), and reject construction when the
  resulting `threshold < 2` for non-devnet (`share_count > 1`) sets.
- Remove the static `dkls_threshold = 1u8` and treat `threshold == 1` with
  `share_count > 1` as a hard error in `run_honest_dkg` /
  `select_signing_committee` / the supervisor, distinct from the legitimate
  `threshold == share_count == 1` local-sign devnet mode.
- Add a regression test asserting that a ≥2-validator active set never yields
  a committee of size 1.

## Notes / scope

This is an integration-layer defect, not a flaw in the vendored `dkls23`
primitive (out of scope per `00-OVERVIEW.md`). The primitive faithfully
supports `t < n`; the bug is that Hypersnap selects `t = 1` for arbitrary `n`.
