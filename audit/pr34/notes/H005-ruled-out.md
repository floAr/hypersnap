---
id: H005
specialist: chain-economics
attack_class: emission-budget-cap-missing
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
scope:
  - src/emission/schedule.rs
  - src/emission/compute.rs
  - src/emission/params.rs
---

# H005 — emission-budget-cap-missing / integer overflow — ruled out

## Question
Can total emitted in an epoch exceed the schedule cap via rounding,
missing clamp, overflow wrap, or sum-of-shares > budget, within the
scoped emission files?

## Analysis

### schedule.rs — `emission_per_epoch(epoch)`
`(INITIAL_EPOCH_EMISSION_ATOMS * frac_q32) >> shift`
- INITIAL ≈ 8.085e12, `frac_q32 = HALVING_DECAY_Q32[..] ≤ 2^32`.
- Product ≈ 3.5e22, far below `u128::MAX` (≈ 3.4e38). No multiply overflow.
- Shift guard `if halvings >= 96 { return 0 }` keeps `shift = 32 + halvings ≤ 127`.
  A u128 right-shift of 127 is well-defined; 128 would panic/wrap. The guard
  is exactly correct and is the only overflow/wrap path here.
- `TABLE[0] == 2^32` → `emission_per_epoch(0) == INITIAL` exactly; the curve
  is monotonically non-increasing (pinned by `emission_decreases_monotonically`),
  so no epoch's emission exceeds the calibrated per-epoch cap. Rounding is via
  truncating `>>` (rounds down), never up.

### schedule.rs — `market_budget(epoch, market)`
`pool * bps / BPS_DENOM`, pool ≤ ~8e12, bps ≤ 5000 → ≈ 4e16 ≪ u128::MAX. No
overflow. Today only Growth (2000 bps = 20%) is non-zero; DA / App / Retro /
Unknown return 0 early. Σ active shares = 20% of pool < pool. Even if all
markets ship (5000+2000+3000 = 10000 bps) the sum equals pool exactly — never
exceeds. No sum-of-shares > budget defect.

### compute.rs + allocate_emissions (mutuality.rs, consumed by compute.rs)
- First pass: `atoms = floor(proportion * tranche)`, so Σ ≤ tranche before
  reconciliation.
- Filtering entries below `min_per_recipient_atoms` only decreases the sum.
- Reconciliation adds `leftover = tranche - allocated ≥ 0` to the largest
  recipient, making the final Σ == tranche **exactly** (or less when empty).
  This is an under-distribution floor, never an over-cap; it cannot push the
  total above the tranche.
- `total_atoms` (u64) sums allocations that are ≤ tranche (u64); no u64 overflow.

### Cap-enforcement wiring (context, partly out of scope)
- Production path `actor.rs::run_scoring` inserts `market_budget(epoch, market)`
  into `params.market_budgets`; the actual Σrecipients ≤ market_budget check (if
  any) lives in `evaluate_epoch` inside the out-of-scope `proof-of-quality`
  crate — not in the H005 scope.
- The CLI `bin/compute_emissions.rs` takes `epoch_tranche_atoms` from user
  args and never derives it from the schedule, and is not a consensus path, so
  it cannot over-issue against a chain cap.

## Conclusion
Within the H005 scope (`schedule.rs`, `compute.rs`, `params.rs`), every
emission-producing function is internally cap-respecting: no round-up, no
missing clamp, no overflow/wrap (shift guard correct), and Σ shares ≤ pool /
Σ allocations ≤ tranche always hold. No issue.
