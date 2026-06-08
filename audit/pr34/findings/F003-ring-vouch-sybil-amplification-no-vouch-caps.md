---
id: F003
specialist: chain-economics
attack_class: sybil-amplification-via-eigentrust
file_paths:
  - code/hypersnap/src/emission/eigentrust.rs
  - code/hypersnap/src/emission/mutuality.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: Ring-vouch sybil clusters cross the crediter trust floor — EigenTrust has no vouch cap, mutual-vouch requirement, or min-vouchee-trust gate
validation:
  validator: validator
  verdict: INVALIDATED
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The EigenTrust power iteration (`run_eigentrust`) propagates trust along the
post-transfer follow graph with **no out-degree cap, no mutual-vouch
requirement, and no minimum-vouchee-trust gate on edges**. A single legit /
seed account that follows ("vouches for") a small set of sybils, combined with
the sybils ring-following each other, recirculates the vouched mass inside the
sybil cluster instead of leaking it back to the seed set. This amplifies the
cluster's raw EigenTrust score by ~6.6× relative to the same vouch with no ring,
and lifts every sybil in the cluster over the `crediter_trust_floor` (0.05) — the
**only** sybil defense in the emission path. Once above the floor, each sybil
becomes a valid crediter in `tally_growth_scores`, so the cluster mints growth
score (and therefore emission share) far in excess of its actual stake/trust.

## Affected code

- `code/hypersnap/src/emission/eigentrust.rs:82-124` — power-iteration loop.
  Lines 86-94 propagate `damping · src_mass · weight` along **every** out-edge,
  regardless of whether the edge is reciprocated and regardless of the target's
  trust. Lines 104-110 redistribute *dangling* mass (nodes with no out-edges)
  back to the seeds, but mass circulating inside a closed follow-cycle is **not**
  dangling, so it is never returned to the seed set — it accumulates on the ring.
  There is no cap on a source node's out-degree and no per-edge weighting by the
  vouchee's own trust.
- `code/hypersnap/src/emission/mutuality.rs:60-68` — `tally_growth_scores` gates
  contributions solely on `trust_a >= params.crediter_trust_floor` /
  `trust_b >= ...`. This is the sole sybil gate, and the amplification above
  defeats it: amplified sybils satisfy `trust >= 0.05`.

## Attack scenario

1. Attacker controls (or buys a follow from) one moderately/high-trust account
   `H` (a seed FID ≤ 50_000, or any account with normalized trust near 1.0).
2. Attacker registers K sybils (FIDs > 50_000, so not seeds) and has `H` follow
   all K of them — a single cheap vouch action.
3. The K sybils follow each other in a closed ring (`s_i → s_{i+1 mod K}`).
4. EigenTrust now injects `damping · score(H) · (1/out_deg(H))` into the ring
   each iteration; the ring's closed cycle recirculates it (damped by `damping`
   per hop) instead of leaking it back to seeds. The cluster's steady-state mass
   is geometrically amplified.
5. After `top_n_avg_normalize`, each sybil's normalized trust exceeds the 0.05
   floor, so each sybil is an accepted crediter. The sybils mutually "engage"
   (also cheap) and `tally_growth_scores` credits each of them, converting the
   inflated reputation directly into emission share via `allocate_emissions`.

### Empirical reproduction (verbatim copy of `run_eigentrust` + `top_n_avg_normalize`)

200-node legit seed core; FID 1 additionally follows K ring-vouching sybils:

```
K=    1 | sybil_max_norm=0.515216 | sybils>=floor=   1/   1
K=   10 | sybil_max_norm=0.283694 | sybils>=floor=  10/  10
K=   50 | sybil_max_norm=0.094647 | sybils>=floor=  50/  50
--- no ring vouch (dangling sybils, same voucher edges) ---
K=   10 | sybil_max_norm=0.042555 | sybils>=floor=   0/  10
--- amplification ratio (K=10) ---
ring raw-mass=0.014163  dangling raw-mass=0.002150  amplification=6.59x
```

With ring vouching, one vouch edge lifts 10–50 sybils over the floor; without the
ring (dangling), the identical vouch leaves all sybils below the floor
(0.0426 < 0.05). The ring provides a 6.59× raw-mass amplification for K=10.

## Impact

A single legit/seed vouch is amplified into an arbitrarily large set of
floor-crossing crediter sybils, each of which then siphons growth-score and
emission. This is silent incentive distortion / Sybil inflation of emission
share well beyond stake — the precise failure mode this attack class targets.
Severity: High (direct, cheap inflation of the Growth emission budget by a
low-cost off-chain action; no fund-loss but quantifiable mis-issuance).

## Root cause

The mitigations standard for EigenTrust-based reputation are all absent:

- **No vouch (out-degree) cap** — `H` may vouch for unlimited sybils; each edge
  carries full `1/out_deg` weight (`eigentrust.rs:91-92`, `compute.rs:52`).
- **No mutual-vouch requirement** — trust flows along directed edges; reciprocity
  is never checked, so a ring of one-directional follows is treated as genuine.
- **No `vouch_boost_min_vouchee_trust` gate** — edges into near-zero-trust nodes
  still propagate full mass, so the ring can bootstrap from nothing.
- **Closed-cycle mass is not anchored to seeds** — the leak correction
  (`eigentrust.rs:104-110`) only recovers *dangling* (no-out-edge) mass; mass
  inside a follow-cycle is retained and amplified.

The `crediter_trust_floor` in `mutuality.rs` is the only backstop and is a fixed
absolute threshold on the normalized score, which the amplification crosses.

## Fix

Add edge-level anti-sybil gating in the EigenTrust input/propagation, in scope:

1. **Cap out-degree contribution / cap vouches**: bound the number of
   trust-bearing out-edges per source (or down-weight beyond a cap) so one
   account cannot vouch for unlimited nodes at full strength.
2. **Require mutual vouching**: when building `outgoing` (or inside
   propagation), keep an edge `a→b` only if `b→a` also exists, or weight the
   edge by the reciprocal-ness of the pair. This destroys one-directional rings.
3. **Gate edges by minimum vouchee trust** (`vouch_boost_min_vouchee_trust > 0`):
   refuse to propagate trust into nodes whose own (prior-iteration / seed-
   reachable) trust is below a floor, preventing ring bootstrap from zero.
4. Make `crediter_trust_floor` relative/percentile rather than a fixed absolute
   normalized value, and/or cap the number of crediters a single voucher can
   transitively create.
