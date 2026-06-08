# H004 — mutuality-asymmetry — RULED OUT

- specialist: chain-economics
- attack_class: mutuality-asymmetry
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- scope: `code/hypersnap/src/emission/mutuality.rs` vs `code/hypersnap/crates/proof-of-quality/src/scoring.rs`
- outcome: no confirmed exploitable finding (residual low/informational symbol-level inconsistency noted below)

## Hunt question

Is the live-emission mutuality transform consistent with the retro/offline
mutuality transform? An asymmetry would let an attacker score differently in
retro vs live to extract extra rewards, or a non-mutual vouch/engagement count
in one path but not the other.

## Architecture established

Two distinct emission pipelines exist; they are NOT two computations of one
metric smuggled past each other:

1. **Consensus / on-chain issuance** —
   `crates/proof-of-quality/src/scoring.rs::evaluate_epoch` →
   `compute_growth_harmonic` (harmonic mutuality HARDCODED).
   Reached by `src/hyper/actor.rs::run_scoring` →
   `scoring_driver::run_epoch_dkls_local`, threshold-signed into
   `proto::HyperRewardIssuance` (see `src/hyper/rewards.rs` header, actor.rs:2012+,
   2069). This is the only path that increments on-chain balances.

2. **Offline / operator tooling** — `src/emission/mutuality.rs` +
   `src/emission/compute.rs::compute_epoch_emissions`, driven solely by the
   `compute_emissions` CLI binary (`src/bin/compute_emissions.rs`). The retro
   reference is `src/bin/retro_rewards_finalize.rs` (also an offline binary).
   `src/emission/params.rs:21-27` documents explicitly: "the production
   consensus path never reads" the non-Harmonic modes; they are "for the
   `compute_emissions` CLI binary and offline experimentation only."

## Per-pair mutuality formula — CONSISTENT for the consensus mode

Harmonic mutuality is identical across all three implementations:

- consensus `scoring.rs:201-215`: `harmonic = 2ab/(a+b)`, then
  `(1.0 + harmonic).ln() * cred_u * vouch_boost`.
- retro `retro_rewards_finalize.rs:204-216`: gate `a<=0||b<=0 → 0`, else
  `(1.0 + 2ab/(a+b)).ln()`, contribution `* cred_u`.
- emission `params.rs:54-64`: `if a+b==0 {0} else {2ab/(a+b)}`, wrapped
  `(1.0+raw).ln()`.

For Harmonic the two zero-guards are equivalent (`2ab/(a+b)` is already 0 when
either side is 0, since the numerator `2ab=0`). Worked example a=100,b=0:
retro→0, emission→`ln(1+0)=0`. Mutuality requirement (`count_uf==0 → continue`)
is enforced in both consensus (`scoring.rs:185`) and retro
(`retro_rewards_finalize.rs:1849`); the emission path enforces it implicitly via
the harmonic formula. The consensus default and the FIP default are both
Harmonic (`params.rs:43-47`, `MutualityMode::Default`). Consensus issuance is
therefore unaffected — no retro-vs-live divergence an attacker can exploit for
extra on-chain rewards.

## Residual symbol-level inconsistency (low / informational, NOT a confirmed finding)

The two offline `MutualityMode::apply` implementations disagree on the
non-mutual gate for the **Sum** and **Avg** modes:

- retro `retro_rewards_finalize.rs:205-207` short-circuits `if a<=0||b<=0
  return 0.0` BEFORE the mode match, so a one-sided pair (a=100,b=0) yields 0.
- emission `params.rs:50-65` has NO such guard; `Sum→a+b` and `Avg→(a+b)/2`
  then credit a one-sided pair: `Sum.apply(100,0)=ln(101)≈4.615`,
  `Avg.apply(100,0)=ln(51)≈3.93`.

(Min and Geom remain consistent: `min(100,0)=0` and `sqrt(100·0)=0` both wrap to
`ln(1)=0`.)

### Why this is not escalated to a confirmed finding

- Both code paths that exhibit the divergence are **offline binaries**
  (`compute_emissions` and `retro_rewards_finalize`). Neither feeds the
  threshold-signed `HyperRewardIssuance` consensus path.
- The consensus and FIP default mode is **Harmonic**, which is fully
  consistent across all three implementations; the divergent Sum/Avg modes are
  documented non-consensus experimental knobs.
- No on-chain reward total changes as a function of this discrepancy, so there
  is no attacker-extractable value: an operator would have to deliberately run
  the offline CLI in a non-default, non-consensus mode AND treat its output as
  authoritative against retro output, both of which are out-of-protocol.

### Recommended hardening (non-security)

Hoist the `if a<=0||b<=0 { return 0.0 }` strict-mutuality guard into
`src/emission/params.rs::MutualityMode::apply` so the offline emission CLI's
Sum/Avg modes match the retro finalizer symbol-for-symbol, eliminating the
documented "offline vs offline disagree on the same named metric" anti-pattern.

## Files examined

- `code/hypersnap/src/emission/mutuality.rs`
- `code/hypersnap/src/emission/params.rs`
- `code/hypersnap/src/emission/compute.rs`
- `code/hypersnap/src/bin/compute_emissions.rs`
- `code/hypersnap/src/bin/retro_rewards_finalize.rs` (compute_growth_scores @1804, apply @204)
- `code/hypersnap/crates/proof-of-quality/src/scoring.rs` (compute_growth_harmonic @160)
- `code/hypersnap/src/hyper/rewards.rs`, `src/hyper/actor.rs` (run_scoring @2012)
