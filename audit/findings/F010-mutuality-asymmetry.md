---
id: F010
task: H010
specialist: chain-economics
attack_class: mutuality-asymmetry
severity: low
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.90
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  note: "Two-pipeline divergence verified end-to-end: actor → evaluate_epoch → compute_growth_harmonic (consensus, harmonic-only) is wholly disjoint from compute_emissions.rs → compute_epoch_emissions → tally_growth_scores (offline CLI, default Sum). All cited line numbers resolve. Severity correctly bounded to low/informational; no direct on-chain exploit. Minor caveats on the Harmonic-mode footnote (Harmonic also zero-gates via mutuality.rs:56) and params.rs:30 'FIP-default' wording — both body-level, do not change verdict. See findings/notes/F010-validation.md."
---

# Mutuality formulas in `emission/mutuality.rs` and `proof-of-quality/scoring.rs` diverge on every axis

## Summary

The repo contains two independent implementations of "per-pair mutuality
growth scoring," one in `src/emission/mutuality.rs::tally_growth_scores`
and one in `crates/proof-of-quality/src/scoring.rs::compute_growth_harmonic`.
Both are described in their headers as "compute Hypersnap epoch emissions"
/ "per-epoch scoring pipeline", and both consume an `EigenTrust`-derived
trust vector plus a per-pair engagement count. **They disagree on the
numerator function, the crediter weight, the reciprocity filter, the
vouch-boost multiplier, and the post-composite eligibility gate.** For
identical inputs the two functions produce different per-FID growth
scores — by design in `scoring.rs`'s comment ("the in-protocol composite
formula with `harmonic` mutuality"), but not in any documented way to
downstream readers of the `compute_emissions` binary or to anyone whose
tooling links `hypersnap::emission`.

Today only the harmonic path (`scoring.rs`) is reached through
`evaluate_epoch`, which is what the validator actor runs and DKLS-signs
(`src/hyper/actor.rs:1759` "Run `evaluate_epoch` + DKLS23 1-of-1 inline
signing"). The configurable / `Sum`-default path
(`src/emission/mutuality.rs`) is reachable only through the offline
`src/bin/compute_emissions.rs` binary, which is **not** in the consensus
path. That bounds the direct exploitability — a validator cannot
swap formulas at signing time — but the discrepancy is the textbook
mutuality-asymmetry footgun: future refactors that connect these paths
(e.g. exposing `compute_epoch_emissions` to the actor, or aligning the
"emission" module with the "scoring" crate) will silently change
consensus, and any external tooling already integrating against
`hypersnap::emission::compute_epoch_emissions` is silently desynced from
the chain.

## Description

### Side-by-side divergence

| Axis | `src/emission/mutuality.rs` (offline path) | `crates/proof-of-quality/src/scoring.rs` (consensus path) |
| --- | --- | --- |
| Numerator (mutuality scalar) | `ln(1 + MutualityMode::apply(a, b))` with `MutualityMode` ∈ {Min, Geom, Harmonic, Avg, **Sum**}; default `Sum = a + b` (`params.rs:34-38`, `:42-56`) | Hardcoded `ln(1 + 2ab/(a+b))` (harmonic) — `scoring.rs:197-201, 215` |
| Crediter weight | Raw trust score: `trust_a * m` (`mutuality.rs:64`) | Credibility blend: `cred_u * vouch_boost` (`scoring.rs:215`), where `credibility_weight = compute_credibility_weight(age, trust, entropy, stake)` (`scoring.rs:133-138`) |
| Trust floor predicate | `trust_a >= params.crediter_trust_floor` (`mutuality.rs:63`; default 0.05 — `params.rs:85`) | `m_u.trust_score < crediter_trust_threshold` skip (`scoring.rs:188`) — parameterized separately via `ScoringParams::crediter_trust_threshold` |
| Reciprocity gate | None. `PairEngagement::new(100, 0)` (no return engagement) still contributes a positive `Sum`/`Avg`/`Geom`/`Harmonic`* score and credit (\*Harmonic returns 0 only on the `0,0` corner case but the function does not require reciprocity in the iteration itself). `mutuality.rs:54-69` iterates whatever pairs the caller supplies. | Hard gate: `if count_fu == 0 { continue; }` (`scoring.rs:182-183`). A pair where the would-be vouchee never engaged back is dropped entirely, even if the crediter engaged 100 times. |
| Edge-set source | Caller-supplied `Iterator<Item=(u64,u64,PairEngagement)>` (`mutuality.rs:51`) | `m_f.all_time_engagement` per vouchee, cross-referenced against `metrics[u].all_time_engagement[&f]` (`scoring.rs:175-180`) — **all-time** counts, no epoch window |
| Vouch boost (FIP §12) | Absent — no notion of `vouches_from` in `EmissionParams` or `tally_growth_scores` | `1 + stake_factor_from_atoms(vouch_atoms) ∈ [1, 2]`, gated on `m_f.trust_score >= vouch_boost_min_vouchee_trust` (`scoring.rs:209-214`) |
| §8.3 eligibility gate (F0–F6) | Absent — emission is allocated directly from `growth` via `allocate_emissions` (`mutuality.rs:76-106`); only floors below `min_per_recipient_atoms` | Composite is **zeroed** for any FID failing the §8.3 filter set **before** `allocate_budget` (`scoring.rs:354-369`) |
| Bidirectional symmetry | Each pair iteration credits **both** sides (`mutuality.rs:63-68`: `growth[b] += trust_a*m` and `growth[a] += trust_b*m`) | Each `(u,f)` iteration credits only `f`; the symmetric `(f,u)` pass is performed implicitly by the outer loop iterating over every `f` (`scoring.rs:167`). Different gating windows can therefore drop one direction but not the other. |
| Determinism | `HashMap` iteration (`mutuality.rs:13, 49`) — relies on caller-supplied ordering for determinism | `BTreeMap` iteration everywhere (`scoring.rs:15, 29, 165`) — deterministic by construction |
| Allocation rounding-remainder | Goes to the **largest recipient by atoms** (`mutuality.rs:99-103`) | Goes to the **highest-composite FID** with tie-break by **smaller fid** (`scoring.rs:291-301`) — different recipient under ties |

### What this means concretely

Pick any pair `(u, f)` with `count(u→f) = 100, count(f→u) = 0`,
`trust(u) = 0.9`, `trust(f) = 0.05`:

* `emission/mutuality.rs` under default `Sum`: `m = ln(1 + 100) ≈ 4.62`,
  `trust_u >= floor` → `growth[f] += 0.9 · 4.62 ≈ 4.15`. The "vouchee" `f`
  earns emission **without ever engaging back**.
* `scoring.rs` with the same engagement: the `count_fu == 0` branch
  (`scoring.rs:182-183`) fires and the entire pair is skipped.
  `growth[f] += 0` from this edge.

Inverting the situation — pick `count(u→f) = 1, count(f→u) = 1` with
`u` having a saturated vouch on `f` and `f.trust_score = 0.6`:

* `emission/mutuality.rs`: `m = ln(1 + 2) ≈ 1.10`,
  `growth[f] += 0.9 · 1.10 ≈ 0.99`. Vouch boost ignored.
* `scoring.rs`: `harmonic(1,1) = 1`, `ln(1+1)·cred_u·(1 + 1.0) ≈
  0.693 · cred_u · 2 ≈ 1.4 · cred_u`. Vouch doubles `f`'s growth from
  this edge.

So the two pipelines disagree both on the **shape** of the score
(numerator, weight) and on **whether the score exists at all**
(reciprocity gate, vouchee-trust gate on vouch boost, §8.3 eligibility).

### Why this is the `mutuality-asymmetry` attack class

The task description: "If the formula in one module disagrees with the
formula in another (e.g., live scoring vs retro rewards), validators can
game the discrepancy." Here, the live ↔ retro pairing the scoring.rs
header explicitly addresses
(`scoring.rs:4` "Mirrors the Phase 3–6 pipeline of
`retro_rewards_finalize.rs`") is internally consistent — both use
harmonic. The actual asymmetry sits between **live scoring** and
**`hypersnap::emission`**, which is presented to integrators as the
canonical emission library (`compute_emissions.rs:36` "Compute Hypersnap
epoch emissions per FIP-proof-of-work-tokenization §15").

Two attack/error surfaces follow:

1. **Tooling drift / silent disagreement with consensus.** A wallet,
   indexer, or community emission-projection tool that links
   `hypersnap::emission::compute_epoch_emissions` (the only public
   "compute emissions" entry point on the main crate) will produce
   numbers the chain does **not** ratify: different formula, different
   gating, different ordering, different rounding remainder. Operators
   who build dashboards or staking decisions on this binary are off-chain
   from consensus, and a sophisticated actor can construct engagement
   patterns whose offline-vs-onchain delta is large and predictable
   (e.g., one-sided high-volume engagement scores big under default
   `Sum` mode but zero on-chain).
2. **Refactor-grade gaming surface.** The `emission/mutuality.rs` API
   exposes `MutualityMode` and a configurable `crediter_trust_floor` on
   `EmissionParams`, and the public `compute_epoch_emissions` signature
   takes those params. A future change that wires this module into the
   actor (e.g., for a fast-path emission preview, or because someone
   thinks the two should be unified) would silently switch the chain's
   formula from harmonic to whatever `MutualityMode::default()` returns
   — currently `Sum` (`params.rs:34-38`). A validator who proposes such
   a refactor (or smuggles it through a `#[cfg]` flag) can flip the
   network to a formula under which their own engagement pattern pays
   out more.

### Bounded today, not bounded by construction

`evaluate_epoch` is the only function the validator actor signs, and its
call path leads exclusively to `compute_growth_harmonic`. So no validator
can currently produce a signed emission set computed under
`MutualityMode::Sum`. The bound is structural to the actor wiring, not
to the API surface. There is no compile-time or runtime assertion that
`hypersnap::emission` and `proof_of_quality::scoring` agree, and there is
no test that compares them on a non-trivial input.

## Impact

* **Tooling correctness — medium probability, low severity.** Any
  off-chain consumer of `hypersnap::emission::compute_epoch_emissions`
  (the only "emission" entry point on the crate) is silently desynced
  from consensus. The binary's CLI even exposes `--mutuality
  harmonic|sum|avg|geom|min` with `Sum` as default, advertising
  configurability that the chain does not honor.
* **Refactor / supply-chain risk — low probability, high severity if
  triggered.** The two modules look like sibling implementations; an
  unsuspecting refactor or "deduplication" PR that swaps `scoring.rs`'s
  call site for `tally_growth_scores` would change consensus emissions
  without any test catching it (no module-cross-check test exists). The
  `MutualityMode::Sum` default biases toward one-sided high-volume
  engagement — the exact pattern sybil rings produce.
* **No direct economic exploit today.** No validator can sign a non-
  harmonic emission set without first landing the refactor described
  above.

Severity: **low** (informational / hardening). The exploit requires
either (a) integrators trusting the wrong API or (b) a future code
change. There is no immediate path to extracting value on the live
chain.

## Evidence

* `src/emission/mutuality.rs:33-35` — `mutuality_score = MutualityMode::apply(a_to_b, b_to_a)`.
* `src/emission/params.rs:34-38, 42-56` — `MutualityMode::default() = Sum`, `apply` returns `(1 + raw).ln()` over `{Min,Geom,Harmonic,Avg,Sum}`.
* `src/emission/mutuality.rs:53-69` — bidirectional `tally_growth_scores`: `growth[b] += trust_a * m` and `growth[a] += trust_b * m`, with no reciprocity precondition and only a `trust >= floor` gate.
* `src/emission/mutuality.rs:99-103` — rounding remainder goes to **largest recipient by atoms**.
* `src/emission/compute.rs:66-72` — call chain `compute_epoch_emissions → tally_growth_scores → allocate_emissions`.
* `src/bin/compute_emissions.rs:23-27, 54-58` — public CLI exposes `--mutuality` with `Sum` default, presented as "Compute Hypersnap epoch emissions per FIP".
* `crates/proof-of-quality/src/scoring.rs:4-5` — "the in-protocol composite formula with `harmonic` mutuality."
* `crates/proof-of-quality/src/scoring.rs:160-222` — `compute_growth_harmonic`: hardcoded harmonic, reciprocity gate at line 183, credibility weighting at line 215, vouch boost at lines 209-214.
* `crates/proof-of-quality/src/scoring.rs:354-369` — §8.3 F0–F6 eligibility gate zeroes composite before allocation; no analogue in `emission/mutuality.rs`.
* `crates/proof-of-quality/src/scoring.rs:291-301` — allocation remainder goes to **highest-composite FID, tie-break smaller fid**.
* `src/hyper/actor.rs:1759` — "Run `evaluate_epoch` + DKLS23 1-of-1 inline signing" — confirms the harmonic path is the consensus path.
* `src/bin/compute_emissions.rs` is the **only** caller of `compute_epoch_emissions` outside tests; nothing in `src/hyper/` reaches `emission/mutuality.rs`.

## Suggested remediation

1. **Pick one implementation and delete the other.** Either:
   * Remove `MutualityMode` and `tally_growth_scores` and have
     `src/bin/compute_emissions.rs` call `proof_of_quality::scoring::
     compute_growth_harmonic` directly (preferred — single source of
     truth, matches the chain), or
   * Move `compute_growth_harmonic` into `hypersnap::emission` and have
     `proof_of_quality::scoring::evaluate_epoch` reach back into the
     emission crate.

2. **If keeping both for benchmarking/research purposes,** rename one
   so it cannot be mistaken for the canonical path. E.g.,
   `hypersnap::emission::experimental::tally_growth_scores`, and make
   `compute_emissions.rs` print a banner: "WARNING: this tool does not
   match consensus; for chain-equivalent numbers use `poq_dryrun`."

3. **Add a cross-check test** (`tests/mutuality_parity.rs` or similar)
   that builds a fixed scenario, runs **both** pipelines with the modes
   most likely to be confused (`MutualityMode::Harmonic`, no vouches, no
   §8.3 failures), and asserts the resulting per-FID growth scores agree
   within a documented tolerance. Today no such test exists.

4. **Remove the `MutualityMode` enum's `Sum` default** at a minimum —
   `Sum` is the mode most divergent from the chain's harmonic and
   maximally rewards one-sided sybil engagement. If the default were
   `Harmonic`, an accidental wire-up of `emission/mutuality.rs` to
   consensus would still gate on reciprocity weakly via `harmonic(a,0)
   = 0`, instead of silently switching to volume-favoring `Sum`.

5. **Add a CI lint or compile-time assertion** that
   `proof_of_quality::scoring::compute_growth_harmonic`'s call graph and
   `hypersnap::emission::compute_epoch_emissions`'s call graph remain
   disjoint until they are intentionally unified. (Or, equivalently:
   gate `compute_epoch_emissions` behind a `#[cfg(feature = "
   offline-emission")]` and forbid that feature in the validator binary
   target.)
