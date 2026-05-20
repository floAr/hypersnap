---
id: F011
task: H011
specialist: chain-economics
attack_class: eligibility-bypass
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.93
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# `consecutive_misses` counter resets every epoch, so a chronically-failing validator never auto-deregisters

## Summary

FIP-hyper-validator-selection §5.3 requires that a validator who misses
`AUTO_DEREGISTER_CONSECUTIVE_MISSES = 100` proposals **consecutively** be
auto-evicted at the next epoch boundary. The implementation in
`code/hypersnap/src/hyper/validator_score.rs` stores the
`consecutive_misses` counter inside a per-epoch
`ValidatorScoreRecord` keyed by `[HyperValidatorScore][epoch][validator_key]`.
Because every call to `record_missed_proposal` does
`fetch(epoch, validator_key)` (which returns a freshly-zeroed record
when no row exists for that `(epoch, validator_key)` pair), the
counter **silently resets to 0 at every epoch boundary**. A validator
can miss up to 99 proposals per epoch indefinitely and never trip the
auto-deregister gate that the active-set filter consults at
`runtime.rs:3833-3848` and `runtime.rs:3785-3787`.

The eligibility-bypass is: an adversarial validator who refuses to
propose blocks but still participates enough to remain in the active set
(e.g., commit signatures only) collects per-epoch rewards while
contributing nothing to liveness — the auto-deregister policy that was
supposed to evict them never fires.

## Where the counter lives and how it's keyed

`ValidatorScoreTracker::make_key` (`validator_score.rs:71-77`)
constructs the storage key as
`[RootPrefix::HyperValidatorScore][epoch BE][validator_key]`. The
8-byte epoch is part of the key prefix, so each (`epoch`, `vk`) pair
gets its own physical row.

`fetch(epoch, vk)` at `validator_score.rs:79-98` returns a default
record with every counter set to 0 (including `consecutive_misses: 0`)
when no row exists for that key. `record_missed_proposal`
(`validator_score.rs:136-147`) reads that default-zero record at the
new epoch and increments to 1.

## How the active-set filter consults the counter

`HyperRuntime::get_active_validators_enforced` builds the filter at
`runtime.rs:3833-3848`. The predicate is:

```
if slashed.contains(vk) || tracker.should_auto_deregister(prev, vk).unwrap_or(false) {
    return true;  // exclude
}
```

`prev = epoch - 1` (`runtime.rs:3806`). So the filter looks at the
**single epoch immediately before** the one being computed. The
`prev`-epoch record's `consecutive_misses` is what determines
eviction.

`should_auto_deregister` itself (`validator_score.rs:186-194`) does
not aggregate across epochs — it simply reads
`fetch(epoch, vk).consecutive_misses >= AUTO_DEREGISTER_CONSECUTIVE_MISSES`.

## Why the FIP §5.3 intent is "consecutive across history"

The English-spec phrase the doc-comment at
`validator_score.rs:41-44` quotes is "Auto-deregistration threshold
per FIP §5.3. A validator that misses this many *consecutive*
proposals is automatically removed at the next epoch boundary." There
is no qualifier "within a single epoch" in the FIP, and the
reset-on-success behavior in `record_successful_proposal`
(`validator_score.rs:131`) confirms the author's mental model is
"reset only on a successful proposal", not "reset on epoch rollover".
The unit test at `validator_score.rs:307-319` exercises this only
inside one epoch, so the epoch-rollover regression is not covered.

The Hypersnap dataflow makes the bug exploitable in normal operation:
`HyperRuntime::import_block` at `runtime.rs:4210-4214` calls
`update_scores_for_missed_proposals` with `block.signature.epoch`,
which is the per-block epoch — so missed-proposal entries are credited
to the epoch in which the miss occurred, not aggregated to a single
ever-running counter.

## Concrete eligibility-bypass scenario

Assume an adversary's validator V is bootstrap-registered or
register-passed (per `validator_registry.rs:413-450`, which performs
no historical-misses check). Each epoch:

1. V is selected as proposer at 99 distinct rounds via the
   weighted-leader rotation (`scheduler.rs` / `chain.rs`). V deliberately
   times out at all 99. Each timeout's `MissedProposal` is included in
   the next produced block's `missed_proposals` metadata
   (`mod.rs:298-299`, `MissedProposal { validator_key, round }`).
2. Importing nodes credit those 99 entries to V's
   `[HyperValidatorScore][epoch=N][V]` row; `consecutive_misses`
   reaches 99 — strictly **less than** `AUTO_DEREGISTER_CONSECUTIVE_MISSES = 100`
   (`validator_score.rs:44`).
3. At the epoch boundary N → N+1, `get_active_validators_enforced(N+1)`
   reads `should_auto_deregister(N, V)` →
   `fetch(N, V).consecutive_misses = 99 < 100` → V stays in the
   active set.
4. In epoch N+1, V's `[HyperValidatorScore][epoch=N+1][V]` row is
   absent (or zeroed by default — `validator_score.rs:87-96`); the
   counter starts at 0 again. V misses another 99 proposals; the
   record at epoch N+1 ends with `consecutive_misses = 99`. Again
   below threshold → V stays active at epoch N+2.
5. Repeat indefinitely. V is never auto-deregistered, even though V
   has now missed 99·E proposals consecutively over E epochs.

The validator does not need to propose successfully at any point to
"reset" the counter — the per-epoch storage layout effectively
performs the reset for them at every epoch rollover.

## Secondary path: the `validators_below_trust_floor` enumeration

`HyperRuntime::validators_below_trust_floor` (`runtime.rs:3858-3891`)
is a sibling enforcement surface — it uses
`compute_active_set(epoch, bootstrap)` (the **unfiltered** form, line
3868) rather than the enforced filter, so it does not double-check
the auto-deregister threshold either. The trust-floor enumerator
returns FIDs whose `trust_store.get(fid)` is below the configured
floor, but it relies on the active-set filter to do the actual
eviction. Since the filter is broken, validators stay in the active
set even when both (a) their trust falls below the floor and (b)
their per-epoch miss counter would have qualified for auto-deregister
under the FIP's intent.

## Why this is NOT compensated elsewhere

- The **trust-gate** at `runtime.rs:3833-3848` (`min_trust > 0.0`
  branch) is independent of the miss counter; it consults
  `trust_store.get(fid)` which reflects the §6 growth scoring output,
  not validator-proposal liveness.
- The **register-time trust floor** at
  `validator_registry.rs:458-481` is admission-only and only fires on
  Register events; it does not re-evaluate sitting validators.
- The **slashing** path (`runtime.rs:3819-3821`,
  `slashed_validators_for_epoch`) only fires on
  conflicting-blocks-at-same-height evidence
  (`slashing.rs:73`), which a no-show validator never produces — they
  are silent, not equivocating.
- The **per-FID quota** check at
  `validator_registry.rs:486-520` only caps Register events; an
  already-active validator does not consume the quota.
- The **production trust-score pre-check** at `runtime.rs:3593-3623`
  is a Register-time gate on `submit_message`; it ignores already-active
  validators.

No production path applies an "across-epochs miss aggregation"
predicate. The only enforcement surface that mentions the FIP §5.3
auto-deregister policy is the broken
`should_auto_deregister(prev, vk)` call site.

## Affected file:line citations

- `code/hypersnap/src/hyper/validator_score.rs:44` — defines
  `AUTO_DEREGISTER_CONSECUTIVE_MISSES = 100` and docstring says
  "A validator that misses this many consecutive proposals is
  automatically removed".
- `code/hypersnap/src/hyper/validator_score.rs:71-77` — storage key
  layout `[HyperValidatorScore][epoch BE][vk]` makes the counter
  per-epoch.
- `code/hypersnap/src/hyper/validator_score.rs:79-98` — `fetch` for
  a new (epoch, vk) pair returns a zero-initialized record, including
  `consecutive_misses: 0`.
- `code/hypersnap/src/hyper/validator_score.rs:136-147` —
  `record_missed_proposal` increments the per-epoch counter only.
- `code/hypersnap/src/hyper/validator_score.rs:186-194` —
  `should_auto_deregister` reads a single-epoch counter, no
  cross-epoch aggregation.
- `code/hypersnap/src/hyper/runtime.rs:3785-3789` —
  `get_active_validators_filtered` consults
  `should_auto_deregister(prev, vk)` where `prev = epoch - 1`.
- `code/hypersnap/src/hyper/runtime.rs:3833-3848` —
  `get_active_validators_enforced` likewise consults only the
  previous-epoch record.
- `code/hypersnap/src/hyper/runtime.rs:4210-4214` —
  `update_scores_for_missed_proposals` credits to the block's epoch,
  so per-epoch counters are populated but never aggregated.
- `code/hypersnap/src/hyper/importer.rs:101-111` —
  `update_scores_for_missed_proposals` helper used at import time.
- `code/hypersnap/src/hyper/validator_score.rs:307-319` — existing
  test only verifies the threshold trip **inside a single epoch**;
  no regression coverage of the epoch-rollover reset.

## Severity rationale: high

- **Eligibility impact:** the policy that was supposed to evict
  chronically-non-proposing validators never fires. Such a validator
  continues to occupy a committee slot (and a DKG seat), continues to
  vote for blocks, and continues to be credited
  `record_commit_signature` participation rewards (which contribute
  to their per-epoch score and indirectly to retention).
- **Cost to attacker:** zero — an adversary just needs to stop
  proposing on the rounds where they are selected. They keep
  participating in commits to retain the rest of their score and
  rewards.
- **Liveness impact:** every epoch loses up to
  `(AUTO_DEREGISTER_CONSECUTIVE_MISSES - 1) = 99` proposal slots per
  bad validator. With multiple colluding validators this compounds —
  e.g., 5 bad validators × 99 proposal-rotations per epoch = 495
  empty rounds per epoch.
- **Detection difficulty:** invisible to monitoring that watches
  `should_auto_deregister(prev_epoch, vk)` — that predicate keeps
  returning `false` indefinitely. Only an auditor who aggregates
  `missed_proposals` across the full `[HyperValidatorScore][*]`
  prefix sees the pattern.
- **No active mitigation:** the slashing path only fires on
  conflicting evidence; the trust-floor path operates on §6 growth
  signals, not proposal liveness; the per-FID quota is admission-only.

Not critical because (a) the attacker cannot inflate their own
rewards beyond their normal share — they suffer the per-epoch
`miss_penalty = 50` weight (`validator_score.rs:30-39`) which keeps
their `score` low — and (b) the §6 growth pipeline (which
`min_trust > 0.0` would consult) may eventually catch them via
external signals. But the auto-deregister gate, as written, is
dormant against the intended threat model.

## Suggested remediation (for triage; not part of this draft's scope)

- Track `consecutive_misses` in a **second store** that is **not**
  epoch-keyed — e.g.,
  `[HyperValidatorConsecutiveMisses][validator_key] → u64`. Increment
  on every `record_missed_proposal`; reset to 0 only on
  `record_successful_proposal` (or on `Deregister` /
  re-`Register`). Read this counter directly in
  `should_auto_deregister`; deprecate the per-epoch field.
- Alternatively (less invasive): make `should_auto_deregister(epoch, vk)`
  walk the last K epochs' `ValidatorScoreRecord` entries and sum
  `missed_proposals` only when no `successful_proposals` appears in any
  of them, treating "no proposal at all" as a continuation of the
  consecutive streak.
- Add a regression test that exercises 50 misses in epoch N + 50 misses
  in epoch N+1 with no successes and asserts
  `should_auto_deregister(N+1, vk) == true`.
- Reconcile the docstring at `validator_score.rs:41-44` with the actual
  storage layout. If the FIP §5.3 intent is "per-epoch reset by design",
  document that explicitly and remove the word "consecutive"; otherwise
  fix the implementation to honor the cross-epoch semantics.
