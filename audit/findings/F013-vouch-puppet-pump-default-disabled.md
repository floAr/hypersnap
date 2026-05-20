---
id: F013
task: H013
specialist: chain-economics
attack_class: vouch-puppet-sybil
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Vouch graph has no admission gates and the documented anti-puppet-pump mitigation ships disabled by default

## Summary

The hyper-layer vouch graph — the `(voucher, vouchee, atoms)` set that
feeds the FIP §12 vouch boost in `compute_growth_harmonic` — has **no
input-side admission predicates** beyond a signed token-stake message
and a non-zero atoms balance. There is no per-voucher cap on distinct
vouchees, no k-distinct-sponsors requirement, no decay on stale vouch
edges, no minimum-trust-of-voucher gate beyond the universally-zero
`crediter_trust_threshold` (F009), and — critically — the one mitigation
the protocol *does* implement (`vouch_boost_min_vouchee_trust`) is
**defaulted to `0.0`** in `ScoringParams::default()` (`lib.rs:267`),
meaning the puppet-pump mitigation is structurally off-by-default at
genesis. A high-trust voucher can therefore stake a fully-saturating
vouch (100 HYPER = `STAKE_MATURITY_ATOMS`) on an otherwise low-trust
sybil and double the sybil's per-epoch growth contribution, even though
the sybil's own EigenTrust score is near zero. Repeating across N
distinct sybils gives N× amplification of the attacker's Growth-market
share for `100·N` HYPER of *locked* (not lost) capital.

This is distinct from F009: F009 inflates the EigenTrust output for a
sybil RING through the follow-graph + top-N normalization path. F013
sits on the orthogonal vouch axis — a *single*-voucher / *single*-vouchee
puppet pump that the FIP-§12 design explicitly anticipated and
implemented a gate for (`scoring.rs:155-159, 210-214`), but whose gate
is then shipped disabled (`lib.rs:267`).

## Write paths into the vouch graph

The vouch graph is materialized at runtime under the
`HyperTokenVouchStaked[voucher BE u64][vouchee BE u64]` key prefix
(`runtime.rs:6967`, `poq_reader.rs:818-849`,
`runtime.rs:1460-1474` for key-layout commentary). Every credit to
this map flows through exactly one entry point:

* `HyperRuntime::apply_token_stake` (`runtime.rs:1655-1691`) when the
  signed `TokenStakeBody.stake_type == Vouch`. The body is validated by
  `token_stake::validate_token_stake` (`token_stake.rs:141-156`) which:

  1. Requires a valid Ed25519 signature over the canonical
     `(DST | chain_id | fid | amount | stake_type | nonce | vouchee_fid |
     signer_pubkey)` payload (`token_stake.rs:64-76`);
  2. Requires `amount > 0`, `fid > 0`, `vouchee_fid != 0`, and
     `vouchee_fid != fid` (anti-self-vouch — `token_stake.rs:114-120`);
  3. Then in the runtime path, requires the signer pubkey to be an
     active key for the voucher FID via `get_active_key` (`runtime.rs:1635`
     and following — covered by the same gate as
     `apply_token_transfer`), and requires the voucher to hold ≥ `amount`
     in their reward balance (`runtime.rs:1643-1650`).

That is the **entire** admission gate. There is no:

* **Per-voucher cap on distinct vouchees.** Nothing in the stake path
  consults the number of existing rows under
  `HyperTokenVouchStaked[voucher][*]`. The prefix scan in
  `vouches_from` (`poq_reader.rs:818-849`) is unbounded, and the
  runtime never enforces an upper bound. A voucher with N HYPER can
  open N/STAKE_MATURITY_ATOMS independent fully-saturated vouches.
* **k-distinct-sponsors requirement.** A vouchee never has to be vouched
  for by ≥ k *different* high-trust accounts before the boost applies;
  one voucher is sufficient.
* **Voucher-trust gate.** The crediter trust check is the global
  `crediter_trust_threshold` in `compute_growth_harmonic`
  (`scoring.rs:188`). With the default `0.0` (`lib.rs:260`), any
  voucher with positive trust qualifies.
* **Vouchee-trust gate by default.** The intended puppet-pump defense
  `vouch_boost_min_vouchee_trust` (`scoring.rs:210-214`) reduces the
  boost back to `1.0` when the vouchee's trust is below the threshold —
  but the shipped `ScoringParams::default()` sets it to `0.0`
  (`lib.rs:267`), which makes the gate a no-op for every vouchee with
  any non-negative trust.
* **Decay or expiry on vouch edges.** Vouch atoms persist under
  `HyperTokenVouchStaked` until the voucher submits a matching
  `TokenUnstakeBody` (`runtime.rs:1733-1769`), then drain through the
  `HyperTokenUnstakeQueue` after `UNSTAKING_PERIOD_EPOCHS`. There is
  no per-epoch automatic decay, so a one-time vouch from a high-trust
  voucher continues amplifying the vouchee in every subsequent epoch
  for free.
* **Vouch cost in lost atoms.** The vouch atoms are *locked*, not
  *burned*. After the boost has run its course the voucher can
  unstake and reuse the same capital to vouch on a different sybil.
  The marginal economic cost of a vouch boost across epochs is the
  voucher's foregone yield on the staked capital — not the principal.

The validator-trust filter at registration time
(`min_validator_trust_score`, `runtime.rs:3600-3618`) and the
`crediter_trust_threshold` (`scoring.rs:188`) are the only two
trust-related admission gates in the entire pipeline, and neither
applies to *issuing* a vouch — only to *being a validator* and to
*contributing to growth*. There is no mechanism by which a low-trust
account is prevented from receiving a vouch, and no mechanism by
which a fresh (zero-trust) account is prevented from getting boost
mileage out of a vouch the first time its trust score nudges above zero.

## The puppet-pump exploit (single voucher, single sybil)

The vouch boost is gated only on the **vouchee's** `trust_score` —
the voucher's trust is checked but only against
`crediter_trust_threshold` (default `0.0`). The boost itself is

```text
vouch_boost = if m_f.trust_score >= vouch_boost_min_vouchee_trust {
                  1.0 + stake_factor_from_atoms(vouch_atoms)   // ∈ [1, 2]
              } else {
                  1.0
              }
```

(`scoring.rs:209-214`). With the shipped default
`vouch_boost_min_vouchee_trust = 0.0` (`lib.rs:267`), the gate
collapses to `m_f.trust_score >= 0.0`, which is true for every FID
that has not been explicitly assigned a negative trust score (i.e.,
every FID). The mitigation is structurally a no-op.

Concrete scenario (one voucher, one sybil — no ring needed):

1. Attacker controls **two** FIDs: `u` (any account with non-zero
   trust — even just 0.01 from a single seed-set follow) and `s` (a
   fresh sybil with no follow graph presence, trust near zero).
2. Attacker establishes minimal mutual engagement: `u → s` like, `s →
   u` like, plus `u` follows `s` and `s` follows `u`. That gives both
   sides `all_time_engagement = 1` and the harmonic gate
   (`scoring.rs:181-183, 195-201`) passes with `harmonic(1,1) = 1`.
3. Attacker submits a single `TokenStakeBody { stake_type: Vouch,
   fid: u, amount: STAKE_MATURITY_ATOMS, vouchee_fid: s, … }`
   (cost: 100 HYPER *locked*, recoverable after the
   `UNSTAKING_PERIOD_EPOCHS` cool-down).
4. At the next epoch scoring run:
   * `m_u.vouches_from.get(&s) = STAKE_MATURITY_ATOMS` →
     `stake_factor_from_atoms = 1.0`
     (`metrics.rs:149-153`).
   * `m_f.trust_score >= 0.0` is true (default gate) →
     `vouch_boost = 2.0` (`scoring.rs:210-211`).
   * `s`'s growth contribution from `u` becomes
     `ln(1 + 1) · cred_u · 2.0 = 0.693 · cred_u · 2.0 ≈ 1.39 · cred_u`,
     vs the unboosted baseline `0.693 · cred_u`.
5. With the §8.3 eligibility filters needing to pass for `s` to
   collect (`scoring.rs:354-369`), the attacker also needs `s` to pad
   `total_casts`, `active_days`, `replies_received`, etc., but these
   are cheap to fabricate compared to the boost gain.

Repeating with N independent sybils (`s_1`, …, `s_N`), the attacker
pays `N · STAKE_MATURITY_ATOMS` of *locked* (not lost) capital and
gets N independent 2× boosts on N growth recipients. As soon as
`s_i`'s composite carries it into the Growth budget allocation
(`scoring.rs:271-314`), the attacker collects boosted emission. They
can then unstake (`runtime.rs:1733-1769`, `UNSTAKING_PERIOD_EPOCHS`
wait), reuse the capital for the next epoch's puppets, and the cycle
repeats. The capital is fungible across vouchees and across epochs —
the only per-epoch friction is the unstaking cool-down.

## Why `vouch_boost_min_vouchee_trust = 0.0` defeats the design intent

The mitigation logic is correct when the floor is non-zero — the unit
tests `vouch_boost_gated_by_vouchee_trust_floor`
(`scoring.rs:1195-1227`) and
`vouch_boost_applies_when_vouchee_passes_trust_floor`
(`scoring.rs:1232-1255`) verify the suppress-when-below-floor /
apply-when-above-floor behavior with a floor of `0.5`. The doc
comment at `scoring.rs:155-159` correctly describes the intent: "this
closes the puppet-sybil pump where a high-trust voucher amplifies
their engagement with a low-trust sybil."

But `ScoringParams::default()` at `lib.rs:267` then sets the floor to
`0.0`, which is the lowest value the predicate `m_f.trust_score >=
threshold` can ever fail at — and `m.trust_score` is initialized to
`0.0` in `FidMetrics::new` and clamped non-negative
(`scoring.rs:131`, `metrics.rs:117-118`). The predicate is therefore
true for every FID present in the metrics map, which means the
boost-suppression branch (`scoring.rs:212-214`) is dead code under
the shipped default.

The §12 design intentionally chose to mitigate puppet-pump via the
vouchee floor rather than via voucher-side limits (caps, k-distinct,
decay). With the floor at 0.0 the entire defense is absent, and there
is **no second-layer mitigation** elsewhere in the path.

## Affected file:line citations

* `crates/proof-of-quality/src/lib.rs:267` —
  `vouch_boost_min_vouchee_trust: 0.0` shipped default disables the
  mitigation.
* `crates/proof-of-quality/src/scoring.rs:209-215` — the vouch_boost
  application; the gate at line 210 is the only puppet-pump defense
  and is bypassed when the threshold is `0.0`.
* `crates/proof-of-quality/src/scoring.rs:155-159` — doc comment
  describing the intended mitigation that the default disables.
* `crates/proof-of-quality/src/metrics.rs:149-153` —
  `stake_factor_from_atoms`: saturates to `1.0` at
  `STAKE_MATURITY_ATOMS = 100_000_000` (= 100 HYPER), giving boost
  factor `2.0`.
* `src/hyper/token_stake.rs:64-76, 94-156` — stake validation:
  Ed25519 sig + structural checks. No trust-based gate on voucher; no
  cap on distinct vouchees; no decay; no anti-collusion predicate.
* `src/hyper/runtime.rs:1655-1691` — `apply_token_stake` for the
  Vouch branch: writes `HyperTokenVouchStaked[voucher][vouchee]` with
  no per-voucher cap on the number of vouchees, no rate-limit, no
  voucher-trust gate.
* `src/hyper/poq_reader.rs:818-849` — `vouches_from` returns the full
  unbounded `[voucher][*]` slice; no filter on entry count or vouchee
  freshness.
* `crates/proof-of-quality/src/lib.rs:152-159` — docstring confirms
  `0.0` "disables the gate (any vouch boosts unconditionally)."
* `src/hyper/runtime.rs:1733-1781` — `apply_token_unstake` Vouch
  branch: capital recovers via `HyperTokenUnstakeQueue` after the
  configured `UNSTAKING_PERIOD_EPOCHS`; no penalty on retrieving the
  vouch atoms, so puppet-pump capital is **locked, not burned**.
* `src/hyper/trust_store.rs` (entire file) — the trust store is
  write-restricted: only the cutover snapshot (`runtime.rs:4024-4026`,
  operator-supplied at genesis) and the threshold-signed
  `HyperTrustSnapshotUpdate` from in-protocol scoring runs
  (`runtime.rs:581-616`) ever PUT into it. The trust store itself
  is **not** the admission surface — it is downstream of the vouch
  graph (vouches feed `compute_growth_harmonic`, which feeds
  composite, which feeds emission, which feeds neither the trust
  store directly nor the EigenTrust pass). The vulnerability is on
  the vouch-graph write path (`HyperTokenVouchStaked`), not the
  trust-store write path.
* `src/emission/eigentrust.rs` — runs on a *follow* trust matrix,
  not the vouch graph; vouches do not perturb EigenTrust output
  directly. They perturb the *post*-EigenTrust growth pipeline, which
  is why a sybil with EigenTrust trust ≈ 0 still gets a 2× boost
  through `vouch_boost`. The two attack paths (F009: ring →
  EigenTrust ≈ 1.0; F013: single vouch → 2× boost on sybil with
  trust ≈ 0) are independent and additive.

## Impact

* **Direct economic exploit:** a high-trust voucher can amplify any
  vouchee's per-epoch growth contribution by up to 2×, scaling
  linearly in the number of independent sybils. Cost is locked (not
  lost) capital plus the unstaking cool-down (one period of foregone
  yield per puppet-pump epoch).
* **Distinct from F009:** F009 inflates a sybil ring's EigenTrust
  trust scores; F013 boosts growth contributions for a sybil who is
  *not* in a high-trust EigenTrust position. The two stack: a sybil
  in F009's ring already has trust ≈ 1.0; a second pass of vouching
  among ring members further doubles each member's outbound
  contribution (`scoring.rs:209-215` is independent of
  `crediter_trust_threshold`'s effect on ring members).
* **Mitigation is shipped but disabled:** the protocol-level fix
  is a single config-value change (`lib.rs:267:
  vouch_boost_min_vouchee_trust: 0.0 → ~0.25`), so the cost of fixing
  is trivial; the cost of leaving it as-is is potentially a full
  Growth-market budget at every epoch.
* **No supplementary defenses on the vouch graph:** even after the
  default is fixed, the vouch graph still lacks per-voucher caps,
  k-distinct-sponsors requirements, decay, and vouchee-staleness
  filtering — meaning fix-by-default closes the *immediate* puppet
  pump but leaves the *structural* admission gap.

## Severity rationale: high

* **Economic impact:** direct theft of Growth-market emissions,
  bounded by the size of the per-epoch Growth budget. At equilibrium
  the attacker can capture a non-trivial fraction of the budget for
  capital cost = locked stake * opportunity cost per epoch.
* **Attacker cost:** low. Vouch capital is locked, not lost. A
  legitimately-acquired (or compromised) high-trust account is the
  only non-trivial prerequisite. The amount of locked HYPER scales
  linearly with the number of puppets, but the attacker recovers it
  all via unstake.
* **Detection difficulty:** medium. The vouch graph is on-chain and
  public, but distinguishing "puppet-pump" vouches from "legitimate
  endorsement" vouches without behavioral analytics is hard.
* **Mitigation difficulty:** low (one config-value change to
  `vouch_boost_min_vouchee_trust`), but the structural gap (no
  cap/decay/k-distinct on vouch graph) requires design-level work to
  fully close.

Not critical because: (a) requires control of one positive-trust FID
(some friction), (b) the mitigation IS implemented and a single
config change closes the immediate hole, and (c) the §8.3 eligibility
filters will still zero out composite for puppets that fail F0–F6.
But the §8.3 filters operate on per-FID engagement *quantity* metrics
that are cheap to fabricate, and the default config ships the pump
wide open.

## Suggested remediation

1. **Immediate (one-line):** Set
   `ScoringParams::default().vouch_boost_min_vouchee_trust` to a
   non-trivial floor — e.g. `0.25`, comparable to what the F009
   suggestion proposes for `crediter_trust_threshold`. This activates
   the documented mitigation at genesis and makes the boost
   suppress-by-default for sybils whose EigenTrust output stays low.

2. **Structural — per-voucher cap.** Limit the number of distinct
   active vouchees per voucher per epoch. In
   `apply_token_stake`, reject the Vouch branch if a prefix scan of
   `HyperTokenVouchStaked[voucher][*]` already returns ≥ N entries (e.g.,
   N = 10). Forces a high-trust voucher to choose which sybils to
   amplify, so the per-puppet cost rises with the number of puppets.

3. **Structural — k-distinct-sponsors.** Apply
   `vouch_boost > 1.0` only when ≥ k distinct vouchers each meet a
   per-voucher trust floor on the same vouchee. Stops a single
   compromised seed-set FID from puppet-pumping at all.

4. **Structural — decay.** Multiply `vouches_from` atoms by a
   per-epoch decay factor (e.g., 0.9 per epoch since last refresh) so
   a one-shot vouch from a high-trust voucher does not amplify a
   sybil forever. Voucher must actively re-stake to maintain the
   boost, which makes pump cost recurring rather than one-time.

5. **Belt-and-braces — cross-check test.** Add a test that
   instantiates a one-voucher / one-sybil scenario with the shipped
   `ScoringParams::default()` and asserts that vouch_boost
   is suppressed when the vouchee's trust is below an *operationally
   meaningful* floor (e.g., 0.05 — typical low-trust sybil). Such a
   test today fails (the shipped default is 0.0), surfacing the
   regression in CI.

6. **Documentation parity.** Update the
   `vouch_boost_min_vouchee_trust` rustdoc at `lib.rs:152-159` to add
   "**Default 0.0 disables this mitigation; production deployments
   MUST set this to a non-zero value to activate the §12 anti-
   puppet-pump defense.**" so an operator reading the spec does not
   assume the gate is on by virtue of being implemented.
