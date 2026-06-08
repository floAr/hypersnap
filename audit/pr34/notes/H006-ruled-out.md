---
id: H006
specialist: chain-economics
attack_class: eligibility-bypass
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
scope:
  - crates/proof-of-quality/src/eligibility.rs
  - src/hyper/validator_score.rs
---

# H006 — eligibility-bypass (TOCTOU admission-vs-payout) — RULED OUT

## Hunt

Is the reward-eligibility predicate checked consistently at admission
vs. at payout? TOCTOU: eligible at admission → ineligible at payout (or
vice versa) lets an ineligible party collect; or an eligibility flag set
once is never re-checked.

## What was examined

Two eligibility predicates live in the scoped files:

1. PoQ FID eligibility — `eligibility.rs::compute_eligibility` /
   `classify_one` / `Eligibility::passes_all` (the F0–F6 filters).
2. Validator eligibility — `validator_score.rs::should_auto_deregister`
   (FIP §5.3 auto-deregister, consecutive-misses based).

I walked each predicate from computation to consumption, plus the
adjacent reward-distribution paths.

## Why it is ruled out

### 1. PoQ FID eligibility is computed and consumed atomically

The only live consumer is `scoring.rs::evaluate_epoch`
(crates/proof-of-quality/src/scoring.rs:411-426). `compute_eligibility`
is called once, and `passes_all()` gates the composite into the `gated`
map in the *same synchronous pass*, immediately before
`allocate_budget(&gated, budget)` (line 475). There is no persisted
"eligible" flag that is set at one time and re-read later, and no
separate admission step that could drift from the payout step — the
predicate is both computed and enforced at the single point of budget
allocation. No TOCTOU window exists.

The App-PoW and DA-PoW markets deliberately do **not** consult the
F0–F6 predicate (scoring.rs:437-446, 458-476). App-PoW gates on
`credibility_weight > 0` instead (app_pow.rs:60-66, documented as
intentional: "sybils get filtered without needing eligibility gates on
the user side"); DA-PoW allocates by per-validator answered/commit
counts. These are per-spec (FIP §7.4 / §5) alternative reward functions,
not the §6 composite, so the absence of the F0–F6 gate there is by
design, not a bypass.

### 2. Validator auto-deregister is re-checked, not a once-set flag

`should_auto_deregister` (validator_score.rs:240-248) reads the live
cross-epoch counter (`HyperValidatorConsecutiveMisses`, prefix 90) every
time it is called. Its sole consumers are
`runtime.rs::get_active_validators_filtered` (4027) and
`get_active_validators_enforced` (4055), which recompute the active set
on demand via `compute_active_set_with_filter`. The predicate is
re-evaluated at every selection/DKG call — it is not latched. The F011
fix (cross-epoch counter, distinct from the epoch-keyed telemetry field)
makes `should_auto_deregister` survive epoch boundaries correctly; the
`_epoch` param is unused by design (counter is global).

The one asymmetry found is fail-safe: the cross-epoch counter is cleared
only by `record_successful_proposal` (validator_score.rs:176) and is NOT
cleared on deregister/re-register (runtime.rs:3848-3878 register path
touches only the trust gate). A re-registered validator therefore
inherits stale misses → **over**-exclusion, the safe direction. It
cannot let an ineligible validator slip through.

### 3. DA-PoW "pay for past work" is correct, not a bypass

`poq_reader.rs::validator_commit_signatures_for_epoch` (599-) reads
commit-signature counts persisted *for that epoch* and pays them,
without re-filtering against the enforced (auto-deregister / slash /
trust-floor) active set. A validator auto-deregistered going into
epoch N+1 still collects DA-PoW for signatures it actually produced in
epoch N. That is the intended semantics — eligibility for the reward is
"did the DA work that epoch", and enforcement gates *future* selection,
not retroactive pay for completed work. Skipping only keys absent from
the FID-lookup index (documented) is consistent at both ingest and
payout.

## Related-but-out-of-scope observation (not H006)

`eligibility.rs::classify_one` and the offline retro tool
(`src/bin/retro_rewards_finalize.rs:1160-1238`) compute the *same*
F0–F6 filters with non-trivial differences:
- F0: live uses `max(signer_authorizations,
  signer_authorizations_clustered, miniapp_author_count) < threshold`;
  retro uses only `signer_authorizations < threshold`.
- F3/F5: retro has escape hatches (`is_seed`, dual-entropy floor,
  absolute floor, trust escape) that the live classifier lacks.
- F5 comparison: live `<=` (eligibility.rs:134) vs retro `<`
  (retro_rewards_finalize.rs:1199).

This is an offline/online **mutuality-/spec-asymmetry** (retro-rewards
disagree with live emission), a different attack class. Within each
path the predicate is internally consistent admission==payout, so it
does not satisfy the H006 eligibility-bypass (TOCTOU) hunt. Flagging for
the asymmetry/spec-compliance specialist, not claiming it here.

## Conclusion

No admission-vs-payout inconsistency and no once-set-never-rechecked
eligibility flag within the H006 scope. Ruled out.
