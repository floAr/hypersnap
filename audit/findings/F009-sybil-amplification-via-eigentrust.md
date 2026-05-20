---
id: F009
task: H009
specialist: chain-economics
attack_class: sybil-amplification-via-eigentrust
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.70
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Sybil cluster amplifies its own EigenTrust score to 1.0 via top-N normalization + structural seed gating

## Summary

The in-protocol EigenTrust pipeline (`crates/proof-of-quality/src/scoring.rs::compute_eigentrust` and `::apply_trust_and_credibility`) has **no anti-sybil predicate gating node admission to the trust matrix**. A sybil ring that (a) is bootstrapped by even a single seed-set endorsement and (b) maintains dense intra-cluster follows can saturate every cluster member's `trust_score` to ≈1.0 by virtue of the top-N average normalization defining the denominator out of the cluster itself. Once `trust_score ≈ 1.0`, every sybil becomes a valid crediter under the default `crediter_trust_threshold = 0.0` (`crates/proof-of-quality/src/lib.rs:260`) and contributes to the §6 growth scores of any account it engages with, breaking the design assumption documented at `crates/proof-of-quality/src/scoring.rs:155-159` ("the puppet-sybil pump where a high-trust voucher amplifies their engagement with a low-trust sybil").

## Where uniqueness should live but doesn't

The task scope names `crates/proof-of-quality/src/uniqueness.rs` as the candidate sybil defense. Inspection (`uniqueness.rs:1-82`) shows that file is **content-level deduping only** — a 128-bit SimHash over char n-grams that drives the message-fee discount path (`uniqueness.rs:5-8`, `fees.rs:58-66`). It is never invoked on the FID set before `compute_eigentrust` builds the follow graph. Search confirms:

- `scoring.rs:329-340` constructs the follow graph from `reader.all_active_fids()` and `reader.followees(f)` directly, with no uniqueness, proof-of-personhood, or stake-floor filter applied to nodes.
- `uniqueness.rs` is consumed only by `fees::compute_effective_fee_micro` (`fees.rs:58-66`) — the per-message discount lane.

There is therefore **no node-admission uniqueness predicate** at any point in the trust-matrix construction.

## Seed set is structural, not quality-gated

The seed set is defined as `fid ≤ seed_max_fid` (default 50,000 — `src/emission/params.rs:65,82`; see also `src/bin/poq_dryrun.rs:214-221`, `src/bin/compute_emissions.rs:175-189`, `src/bin/retro_rewards_finalize.rs:1025-1035`, `src/lib.rs:48`). Membership is purely a numeric FID range — no liveness, no stake, no human-verification gate. Any attacker who controls (purchases, compromises, or already owns) **one** FID in the bootstrap range is an endorser seed with `seed_weight = 1/|seeds|` mass per iteration (`scoring.rs:44`, `eigentrust.rs:58`).

## Amplification mechanism — step by step

Let the sybil ring be `S = {s_1, …, s_n}` for `n ≥ 100`, with one seed `k ∈ seed_set` such that `k → s_1` (a single follow edge from k). Inside `S`, every node follows every other node (`n(n-1)` edges, `out_degree(s_i) = n-1`).

1. **Each iteration of `compute_eigentrust` (`scoring.rs:76-99`) distributes the seed's mass uniformly across its followees by out-degree** (`acc += cur / od as f64`, line 87). The seed's `out_degree_k` includes `s_1`, so `s_1` receives `α · seed_weight / out_degree_k` per iteration.

2. **Inside the ring, mass recirculates with damping factor α = 0.85** (`scoring.rs:340`). After `s_1` receives mass, each subsequent iteration pushes `α · t(s_i) · 1/(n-1)` to each other ring member. Because the ring is strongly connected and every node retains `α · acc` of its inbound flow, the cluster acts as a near-rank sink — mass dissipates only through the `(1-α) = 0.15` teleport (which goes back to the seed set, of which one member belongs to the attacker).

3. **The top-N normalization is the kill step.** `apply_trust_and_credibility` (`scoring.rs:124-141`) divides every raw EigenTrust score by `top_n_avg(raw, 100)` (`scoring.rs:128`, then clamps to ≤1.0). If the sybil cluster has ≥100 members with concentrated mass and the rest of the active universe (genuine human users) is broadly distributed in EigenTrust mass, **the top-100 by raw score is dominated by the sybil cluster itself**. The normalizer therefore equals the cluster's own average raw score, and `(raw / norm).min(1.0)` returns `≈1.0` for every cluster member. Genuine users — whose raw scores are spread across the long tail — receive `trust_score < 1.0`. The "anti-saturation" comment at `eigentrust.rs:6-8` and `scoring.rs:103-105` ("prevents a single concentrated cluster from saturating the [0,1] range") is **inverted in effect**: top-N averaging is robust against one node dominating, but is *fragile against a numerous cluster* — the cluster IS the top-N.

4. **Trust score is then multiplied by `age_factor` and re-clamped** (`scoring.rs:132`). Sybils registered at any time accumulate `age_factor` over weeks; old (purchased) FIDs immediately have `age_factor = 1.0`.

5. **The growth pipeline gates on `crediter_trust_threshold`** (`scoring.rs:188`). Default is `0.0` (`lib.rs:260`) — every cluster member with positive trust qualifies as a crediter. Each sybil's contribution to a target's growth is `(1 + harmonic(count_fu, count_uf)).ln() · cred_u · vouch_boost` (`scoring.rs:215`). Because trust → 1.0 saturates `credibility_weight` via `compute_credibility_weight` (`scoring.rs:133-138`), each sybil contributes near the maximum per-pair credit.

6. **The §12 puppet-sybil mitigation does NOT plug this**. `vouch_boost_min_vouchee_trust` (`scoring.rs:210-214`) only gates the vouch multiplier (1× vs 2×). It does not gate the base `cred_u * harmonic` flow. Even with the gate fully on, a sybil ring of 100 members each cross-engaging a target contributes 100× the baseline credit — independent of vouching.

## Additional defenses missing in `compute_eigentrust` and `run_eigentrust`

Beyond the missing node-uniqueness predicate, both implementations lack:

- **Edge-weight bounds.** Every follow is weighted `1/out_degree` (`scoring.rs:87`, `eigentrust.rs:91`). A trusted seed that follows 5 sybils + 5 genuine users gives every follower 1/10 of its mass — there is no minimum follow-weight floor, no reputational discount on edges to brand-new accounts, and no stake-weighted edge.
- **Max-degree caps.** Out-degree is unbounded (`scoring.rs:71-74`); a single attacker FID can follow 100k sybils and dilute its seed mass intentionally, but this is not exploited here — the more dangerous path is *small out-degree* concentrating mass into the cluster, which is also uncapped.
- **In-degree caps.** A node receiving mass from N followers gets the full sum (`scoring.rs:79-89`); no per-target ceiling.
- **Self-loop handling.** Neither `compute_eigentrust` nor `run_eigentrust` filters `follower == followee`. A FID listing itself in `followees()` (depending on what the reader returns) would receive `α · t(self) / out_degree(self)` per iteration, an unbounded self-amplifier. The follow-graph builder at `scoring.rs:330-338` calls `followees(f)` without filtering out `f` itself; reader integrity is the only defense.
- **Convergence is fixed at 30 iterations** (`scoring.rs:340`) regardless of graph size — the offline driver in `src/emission/eigentrust.rs` checks an L1 epsilon (line 121), but the in-protocol path does not. With 30 iterations, mass distribution in a dense sybil ring has not fully stabilized, but this is a soundness concern, not an attack vector by itself.
- **Dampening source-of-truth.** `α = 0.85` is a hardcoded literal at `scoring.rs:340`, NOT pulled from `ScoringParams`. The same constant is hardcoded again in `EigenTrustParams::default()` (`eigentrust.rs:38`). Two source-of-truth copies risk drifting; the in-protocol path cannot be tuned without recompilation.

## Concrete attack scenario

Attacker controls one FID `k = 100` (within `seed_max_fid = 50,000`, easy to acquire on Farcaster's secondary market for a few thousand dollars). Attacker registers (or purchases) 100 sybil FIDs and constructs:
- A complete sub-graph: each sybil follows every other sybil (100 × 99 = 9,900 edges).
- One bridge edge: `k → s_1`.
- Light engagement padding: each sybil performs ≥10 reciprocal engagements with a target FID `T` over the epoch (≥1,000 engagements total).

Under default `crediter_trust_threshold = 0.0` and default `vouch_boost_min_vouchee_trust = 0.0` (`lib.rs:260`):

1. After 30 iterations of `compute_eigentrust`, raw scores `t(s_i)` are concentrated in the cluster.
2. `top_n_avg(raw, 100)` is dominated by `{s_1, …, s_100}` — their average becomes the divisor.
3. `trust_score(s_i) ≈ 1.0` × `age_factor(s_i)` for every sybil.
4. `compute_growth_harmonic` (`scoring.rs:160-222`): each sybil's contribution to `T`'s growth is `(1 + 2·10·10/(10+10)).ln() · ≈1.0 = ln(11) ≈ 2.4`.
5. Aggregate growth boost to `T`: 100 sybils × 2.4 ≈ 240 vs a genuine engager's single ~2.4. `T` outranks every honest account in `compute_composite` (`scoring.rs:225-265`).
6. `T` collects the Growth-market budget share in `allocate_budget` (`scoring.rs:271-314`).

The §8.3 eligibility filters (F0–F6, `scoring.rs:354-369`) operate on individual FID metrics — they do not inspect the structure of the trust graph that produced T's score, so they do not catch this.

## Affected file:line citations

- `crates/proof-of-quality/src/scoring.rs:24-101` — `compute_eigentrust` lacks node-uniqueness filter, edge bounds, self-loop guard.
- `crates/proof-of-quality/src/scoring.rs:106-141` — `top_n_avg` + `apply_trust_and_credibility` invert "anti-saturation" intent when the top-N is itself the sybil cluster.
- `crates/proof-of-quality/src/scoring.rs:160-222` — `compute_growth_harmonic` accepts every `trust ≥ crediter_trust_threshold` crediter, with no per-crediter aggregate cap on contributions to a single target.
- `crates/proof-of-quality/src/scoring.rs:340` — hardcoded `(iterations=30, alpha=0.85)`, not parameterized.
- `crates/proof-of-quality/src/lib.rs:260` — default `crediter_trust_threshold = 0.0` opens the floodgate.
- `crates/proof-of-quality/src/uniqueness.rs:1-82` — not a sybil predicate; content-level only.
- `src/emission/eigentrust.rs:17-127` — sibling implementation (offline driver) with same edge/degree/self-loop gaps.
- `src/emission/params.rs:65,82` — `seed_max_fid = 50_000` is the only seed gate.

## Severity rationale: high

- **Economic impact**: direct theft of Growth-market budget, scaling linearly with epoch budget.
- **Cost to attacker**: low — one in-range FID + 100 fresh sybils + 1k engagements per epoch.
- **Detection difficulty**: low for an auditor inspecting the graph, but the on-chain consensus has no provision to refuse a `EpochScoringOutput` produced from a well-formed graph — every validator computes the same biased result deterministically.
- **No active mitigation found** in the in-protocol path beyond F0–F6 eligibility filters, which operate on per-FID metrics rather than graph structure.

Not critical because (a) it requires acquiring a low-FID account (some cost / friction) and (b) the `crediter_trust_threshold` parameter exists in the schema — operators could in principle raise it. But with the default at 0.0 shipped in `lib.rs:260`, this is exploitable from genesis.

## Suggested remediations (for triage; not part of this draft's scope)

- Apply a per-account sybil predicate (vouching threshold, stake floor, on-chain attestation, or proof-of-personhood) **before** building `follow_graph` in `evaluate_epoch` (`scoring.rs:329-338`).
- Change `top_n_avg` to use percentile-based normalization with a fixed-percentile cutoff (e.g., raw / score at p99 across the *eligible* universe excluding rings detected by community detection), or normalize against the seed-set's own score rather than the top-N.
- Cap each crediter's total per-epoch contribution to any single target's growth (e.g., `min(cred_u, GLOBAL_PER_PAIR_CAP)`).
- Add a self-loop guard in `compute_eigentrust` and `run_eigentrust` (skip edges where `src == tgt`).
- Move `alpha`, `iterations` into `ScoringParams` to remove the dual source-of-truth.
- Set the shipped default `crediter_trust_threshold` to a positive value (e.g., 0.1–0.25) so that the bottom tail of the trust distribution cannot credit growth.
