---
finding_id: F056
title: The consensus PoQ pipeline diverges from the in-repo FIP §6/§8 in several security-relevant places
severity: low
status: pending-validation
related_findings:
- F026
- F049
- F050
- F053
---
# F056 — The consensus PoQ pipeline diverges from the in-repo FIP §6/§8 in several security-relevant places. The crediter trust floor is a fixed 0.0001, not the data-derived percentile. F5 gets two extra pass conditions. Mutuality is harmonic, not sum. The composite is a five-factor product with exponents, not `credibility · growth`. EigenTrust seed mass and iteration rule differ. The code also cites FIP sections (§6.7 vouch boost, `REAL_NEW_USER_WINDOW`, `MIN_DISTINCT_CREDITERS`, `GROWTH_SKEW_EXPONENT`) that the in-repo FIP doesn't contain. Independent implementations, and reviewers checking the sybil defences against the spec, can't do so.

- **Severity:** Low, source-only (spec/code divergence). This is consensus code, so a second implementation written from the FIP would fork at the first `ScoringResult`. The floor change also weakens the documented sybil defence (see item 1).
- **Confidence:** 0.9 that the divergences exist. Their exploitability is not shown here, except for the floor estimate in item 1.
- **Category:** mutuality-asymmetry / spec divergence (PoQ)
- **Specialist:** chain-economics · task H026
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`crates/proof-of-quality/**` is new; the FIP is the PR's `docs/spec/FIP-proof-of-work-tokenization.md`).
- **PoC:** None, reasoned from source and not built.

## Divergences

1. **The crediter floor is fixed and very low.** FIP §6.1 and §15 say `CREDITER_TRUST_FLOOR` is "`THRESHOLD_PERCENTILE` of trust over the calibration cohort". Code: `CREDITER_TRUST_FLOOR_FP: u32 = 100` (trust ≥ 0.0001) (`crates/proof-of-quality/src/lib.rs:122-126`), used in `compute_growth_harmonic` (`scoring.rs:244`). *Effect (estimate):* a lone seed (no inbound follows) has a steady mass of about `0.15 / |S|`, and passes `0.85 / out_degree` of it to each followee. With `|S| ≈ 50k` and `trust_norm` = mean of the top-100 raw masses (likely 10^-3 or more of total mass), a seed that follows `k ≤ ~5` accounts lifts each of them over 0.0001 × `trust_norm`. A bought or compromised seed FID can make a handful of crediters for a ring, scaled down only by the crediters' own age factor. A percentile floor would adapt to the real distribution. Unmeasured.
2. **F5 has extra escapes.** FIP §8.3 F5 passes only below the upper-tail percentile. Code: it also passes when `share < NEW_USER_SHARE_ABSOLUTE_FLOOR (0.10)` or `trust_fp ≥ 100` (`eligibility.rs:99-107`). Any FID at the 0.0001 floor skips F5, which is the filter against onboarding-farm accounts.
3. **Mutuality is harmonic, not sum.** FIP §6.1 and §15 give `MUTUALITY_FUNCTION = sum` as the default. Code: `harmonic_fp = 2ab/(a+b)` only (`scoring.rs:163-171, 185-193`).
4. **The composite formula differs.** FIP §6.2: `composite = credibility · growth_score`. Code: `growth^½ · cred^4 · trust^½ · (entropy_e · entropy_i)^3 · (new_user + ε)^½` (`scoring.rs:335-372`, `lib.rs:340-346`). Growth itself adds `1/√n`, `MIN_DISTINCT_CREDITERS = 3`, skew damping and a vouch boost (`scoring.rs:201-280`). None of these are in the in-repo FIP.
5. **Skew damping rewards concentration.** `damping = max((1 − H(C(f)))^2, 0.05)` (`scoring.rs:266-274`). It is deliberate ("uniform rings are damped", test at `scoring.rs:1111-1170`). But it also damps real users with many evenly weighted crediters to about 0.05, while an account with one dominant colluding crediter plus two token ones keeps about 0.6. Illustrative contributions `[13.8, 0.35, 0.35]` give `H ≈ 0.2`. The attacker controls the shape, so the defence is gameable. Not in the FIP.
6. **EigenTrust seed and iterations.** FIP §8.2: `seed = 1/SEED_MAX_FID`, iterate until L1 < 1e-6 or 50 rounds. Code: `seed = 10^30 / |registered FIDs ≤ 50 000|`, exactly 30 rounds (`scoring.rs:38-111`, `lib.rs:109-111`, `src/chain/scoring.rs:309-314`). Normalization by the top-100 mean hides most of this, but the 30-round cap is not the spec rule.
7. **App weight and `client_diversity`.** See F053 (§7.1 `trust × age` vs. credibility; §8.4 `log2` vs. constant 1.0).
8. **DA.** See F049 "Related spec divergences" (no uptime factor, no 0.3/0.7 weights, 100 vs 10 challenges).

## Red-team

1. *Maybe the code follows a newer FIP draft?* Likely. The code cites §6.7 and constants that the in-repo FIP lacks. But the PR ships this FIP as the spec, and consensus needs one normative text.
2. *Do the golden and equivalence tests pin the behaviour?* They pin code to the code's f64 reference (`reference_f64.rs`, `golden_test.rs`), not to the FIP.
3. *Is item 1 exploitable today?* It needs a seed FID (buyable) and crediters with age. Real but costly, so it stays Low inside a roll-up.
4. *Already filed?* F026 covers validator-registry divergences and F050 emission. Nothing covers PoQ §6/§8.

## Fix

- Update the FIP with the actual composite, mutuality, floor, F5 rule, seed and iteration rules, or change the code to match. Then mark one normative.
- Make `CREDITER_TRUST_FLOOR` data-derived as specified, or justify 0.0001 with measured mainnet trust quantiles.
- Drop the trust escape from F5, or document it.

## Files

- `crates/proof-of-quality/src/lib.rs:103-126, 179-249, 333-359`
- `crates/proof-of-quality/src/scoring.rs:38-111, 163-280, 335-372`
- `crates/proof-of-quality/src/eligibility.rs:99-139`
- `src/chain/scoring.rs:309-314`
- `docs/spec/FIP-proof-of-work-tokenization.md` §6.1-6.2, §8.2-8.4, §15
