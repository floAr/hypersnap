# F003 validation — ring-vouch sybil amplification (no vouch caps)

Validator: validator (deliberate-disagreement). Commit `cab225f` (HEAD == pinned).

## Verdict: INVALIDATED (confidence 0.9)

The finding analyzes the **wrong pipeline**. It targets the offline/CLI
`src/emission/` module (`eigentrust.rs` + `mutuality.rs`), but the
**production consensus emission path** is
`crates/proof-of-quality/src/scoring.rs::evaluate_epoch`, which contains
every defense the finding claims is absent. Textbook
`two-pipeline-confusion`.

## Pipeline reachability (the decisive walk)

- `src/emission::compute_epoch_emissions` (the function whose
  `run_eigentrust` + `tally_growth_scores` the finding attacks) has
  exactly TWO call sites: `src/bin/compute_emissions.rs:209` (a standalone
  CLI that reads `follows.csv` + `engagement.csv` and writes
  `emissions.csv`) and its own `#[cfg(test)]` module. It is **never**
  reached from runtime/consensus.
- The production path: `actor.rs:2203 maybe_trigger_scoring` →
  `scoring_driver::run_epoch_dkls_local` (actor.rs:2236) →
  `proof_of_quality::scoring::evaluate_epoch` (scoring.rs:372), whose
  `EpochScoringOutput` is then DKLS23 threshold-signed (actor.rs:2012
  doc: "Run `evaluate_epoch` + DKLS23 1-of-1 inline signing"). The
  `compute_emissions` CLI output (a CSV) is never fed back into
  consensus.
- `params.rs:21-27` documents this split explicitly: "The other modes are
  retained for the `compute_emissions` CLI binary and offline
  experimentation only — the production consensus path never reads them."

## The four "absent" defenses all EXIST in the production path

The finding's root-cause list (no vouch cap / no mutual-vouch / no
min-vouchee-trust gate / closed-cycle mass) is refuted by
`crates/proof-of-quality/src/scoring.rs::compute_growth_harmonic` and its
default `ScoringParams` (lib.rs:318-368):

1. **`vouch_boost_min_vouchee_trust` gate** — claimed absent; present at
   scoring.rs:210-214, default **0.3** (lib.rs:334). When the vouchee's
   own trust < 0.3 the vouch boost is forced to 1.0 — exactly the
   "high-trust voucher amplifies a low-trust sybil" pump the finding
   describes. Closed by design (tests
   `vouch_boost_gated_by_vouchee_trust_floor`).
2. **`min_distinct_crediters` gate** — scoring.rs:247, default **3**
   (lib.rs:344). Growth is zero unless ≥3 distinct reciprocating
   crediters; small rings get nothing.
3. **Distribution-aware entropy damping (Layer 2)** — scoring.rs:251-269,
   default skew exponent **2.0** (lib.rs:358). A uniform sybil ring
   (H_norm ≈ 1) is damped toward zero; test
   `distribution_aware_damping_penalizes_uniform_rings` asserts a uniform
   ring lands >10× below a real user. This directly neutralizes the
   ring-recirculation amplification the PoC exhibits.
4. **Crediter trust floor (Layer 0)** — scoring.rs:192, default 0.05
   (lib.rs:320). Same floor the finding cites, but it is the FIRST of a
   layered defense, not the "only" one.

Additionally `evaluate_epoch` runs eligibility gating (scoring.rs:411)
and composite weighting by credibility/entropy (compute_composite) before
budget allocation — further blunting any residual amplification.

## 8-hypothesis walk

1. **Upstream auth/gate — INVALIDATED.** The production scoring path
   applies `crediter_trust_threshold` + `vouch_boost_min_vouchee_trust`
   (0.3) + `min_distinct_crediters` (3) upstream of allocation. The
   finding missed all three because it read the CLI module.
2. **Consumer-side impact — INVALIDATED.** The consumer of the finding's
   buggy `tally_growth_scores` is only `compute_emissions.rs` (CSV →
   CSV). No consensus, no signed issuance, no on-chain mint consumes it.
3. **Downstream enforcement — INVALIDATED.** Even within the production
   pipeline, the entropy damping (L2) + count gate (L1) downstream of
   EigenTrust catch precisely the uniform-ring mass the finding says is
   "never returned to the seed set."
4. **PR HEAD currency — STANDS (no help to finding).** HEAD ==
   `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pinned. No drift.
5. **Spec carve-out — INVALIDATED.** `params.rs:21-27` and `mod.rs:5-7`
   explicitly mark `src/emission` as the offline/retro-mirror path;
   `scoring.rs` is the in-protocol consensus path. The split is
   documented, not a latent bug.
6. **Reachability of harm — INVALIDATED.** No path from the analyzed code
   to emission/value. The PoC inflates a CSV that consensus ignores.
7. **Test wiring — INVALIDATED.** `compute_epoch_emissions` is invoked
   only by the CLI bin and unit tests. The runtime auto-trigger
   (actor.rs:2236) and `EvaluateEpoch` dispatch call
   `evaluate_epoch`, not the finding's functions.
8. **PoC mechanics — PARTIALLY STANDS, but moot.** The 6.59× ring-vs-
   dangling amplification is a faithful copy of `run_eigentrust` (the
   offline solver) and the math is plausible for *that* solver. But it
   proves a property of a non-consensus code path, so the prose impact
   ("siphons emission share") does not follow. The production solver
   `compute_eigentrust` (scoring.rs:24) is a *different* implementation
   (reverse-edge push, alpha restart) and its output is gated by L0/L1/L2
   before reaching any budget.

## Overall

INVALIDATED, confidence 0.9. The amplification math in the offline solver
may be real, but it has no production consumer; the actual consensus
emission path implements the exact anti-sybil controls the finding
asserts are missing. The residual 0.1 reflects that I did not execute the
production pipeline against a 6.6×-style ring to numerically confirm the
L2 damping drives it below the floor — but the code, defaults, and
existing tests (`end_to_end_real_vs_sybil`, `evaluate_epoch_ranks_real_
above_sybil`, `distribution_aware_damping_penalizes_uniform_rings`) all
point the same way.

## Open follow-ups (NOT new findings)

- If the audit scope ever wires the `compute_emissions` CLI output back
  into a consensus/airdrop path, F003's amplification would become live —
  worth a scope note, but currently out of the consensus path.
