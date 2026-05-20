---
id: F014
task: H014
specialist: chain-economics
attack_class: stale-trust-not-cleared
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.86
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# `TrustScoreStore` is append/overwrite only — stale trust scores persist indefinitely for FIDs absent from later snapshots

## Summary

`TrustScoreStore` (`src/hyper/trust_store.rs`) exposes only `set` and
`set_many` (PUT-only), and neither the cutover bootstrap path
(`runtime.rs:4024-4025`) nor the per-epoch `apply_trust_snapshot_update`
path (`runtime.rs:608-613`) ever issues a `del` for FIDs that were
present in a prior snapshot but are absent from the new one. The trust
gate consumed by `validator_registry::validate_register_with_trust`
(`validator_registry.rs:466-481`), by the enforced-active-set filter
(`runtime.rs:3839-3845`), by the validators-below-floor surface
(`runtime.rs:3877-3888`), and by `FeeCharger` uniqueness-discount logic
(`fee_charger.rs:95-99`) therefore reads **the most recent score that
was ever written for this FID**, not "the score in effect at the
last-applied snapshot." Any FID that earned a high score once and then
falls off the snapshot keeps that high score forever — across an
unbounded number of subsequent epochs in which they were never re-scored.

## The store has no eviction primitives

`src/hyper/trust_store.rs` exposes three operations: `set` (line 38),
`get` (line 44), and `set_many` (line 59). `set_many` is a plain
for-loop of `set` calls (lines 60-63):

```rust
pub fn set_many(&self, entries: &[(u64, f64)]) -> Result<(), HubError> {
    for &(fid, score) in entries {
        self.set(fid, score)?;
    }
    Ok(())
}
```

There is no `del`, no `clear`, no `delete_missing(new_universe)`, no
prefix scan, no iterator. `make_key` (lines 21-26) writes
`[HyperTrustScore][fid BE u64]` into RocksDB; nothing in the codebase
ever calls `db.del(...)` against that prefix. Confirmed by grepping
`HyperTrustScore` across the workspace and `trust_store.*del` (no
matches). The `set_many` doc comment promises that it is the "bulk
set used at cutover to install the bootstrap trust snapshot and at
epoch boundaries to rotate from a freshly-signed scoring output" —
but **rotate** is misleading: it can only *raise or change* scores for
FIDs in the new entry list, it cannot lower or clear a stale entry for
an FID the new list omits.

## The single point that should perform replace-set semantics doesn't

`HyperRuntime::apply_trust_snapshot_update` (`runtime.rs:581-616`) is
the only post-cutover path that writes the trust store, and it is
documented as "refreshes the per-FID trust snapshot used by the
validator-registration trust gate" (`runtime.rs:575-576`). The
implementation (lines 606-613) is:

```rust
// Persist entries to the trust store. Entries are sorted by
// fid in canonical encoding; we just iterate.
for entry in &update.entries {
    let score = f64::from_bits(entry.score_bits);
    self.trust_store
        .set(entry.fid, score)
        .map_err(|e| RuntimeRewardError::Reward(RewardError::Custom(e.to_string())))?;
}
self.last_trust_snapshot_epoch = Some(update.epoch);
```

There is no preceding pass to enumerate FIDs already in the store and
delete those not present in `update.entries`. The semantics are
strictly additive-with-overwrite, not replace-set. The doc-comment
declares it "Idempotent: re-applying the same snapshot is a no-op
(set_many is overwriting put)" (`runtime.rs:577-578`) — but
idempotency is a strictly weaker property than "snapshot reflects the
ground truth," and the line conflates the two.

The bootstrap path (`runtime.rs:4023-4026`) has the same shape:

```rust
// Idempotent under re-run (set_many is overwriting put).
self.trust_store
    .set_many(trust_snapshot)
```

— with no `clear` first. The bootstrap also installs only what the
operator supplies; any future epoch snapshot must overwrite *every
bootstrap entry whose FID disappears from production scoring* or the
bootstrap score persists.

## Where the snapshot can omit a previously-present FID

`evaluate_epoch` (`crates/proof-of-quality/src/scoring.rs:319-436`)
builds the per-epoch trust snapshot from `metrics` at line 427-428:

```rust
let trust_snapshot: BTreeMap<u64, f64> =
    metrics.iter().map(|(&f, m)| (f, m.trust_score)).collect();
```

`metrics` is in turn built by `build_metrics` (line 326), which
iterates **only** `reader.all_active_fids()` (`metrics.rs:217`).
`scoring_driver::run_epoch_dkls_local` and `run_epoch_unsigned`
serialize this exact map into `HyperTrustSnapshotUpdate.entries`
(`scoring_driver.rs:87-99` and `:163-170`). The wire-frame is therefore
**only as comprehensive as `all_active_fids()` at this epoch**.

The reader trait doc (`reader.rs:34-37`) explicitly defines this
universe as "FIDs that have any post-transfer activity within the
scoring window (the snapchain anchor block range)." Three concrete
ways a FID present at epoch N can drop out at epoch N+k:

1. **Bootstrap FIDs the live universe doesn't contain.** The cutover
   `set_many` is operator-supplied (`runtime.rs:4017-4026`,
   `RuntimeCutoverError::Reward` path). It can carry FIDs that the
   retro Phase-3 universe included but that `OnchainEventStore::get_fids()`
   on the snapchain anchor does not yet contain (registration latency,
   different snapshot boundary, recovery-flow exclusions). The
   production `fids_for_scoring` (`runtime.rs:454-483`) paginates
   `OnchainEventStore.get_fids` — the on-chain registered set, which
   need not equal the retro-snapshot FID set. Those discrepancy FIDs
   never appear in any post-cutover `HyperTrustSnapshotUpdate.entries`
   and keep their bootstrap score forever.

2. **`PoqReader.with_fids` overrides.** The reader caches a `BTreeSet<u64>`
   at construction (`poq_reader.rs:51, 82, 101-103`) and `with_fids` lets
   the caller substitute a narrower universe. Today the actor
   constructs `PoqReader::new(self.runtime.db_handle(), universe)` with
   `universe = self.runtime.fids_for_scoring()` (`actor.rs:1767-1780`,
   `actor.rs:1977-1981`, `actor.rs:2640-2644`), but the reader API
   itself accepts any narrower set. A future change that filters the
   universe (e.g., to "FIDs registered ≤ snapchain anchor block",
   which is the documented future optimization at `runtime.rs:450-453`
   — "A future optimization could filter to FIDs whose Register event
   happened ≤ the anchor block") would silently leave the previously-
   included FIDs with stale scores.

3. **Reader interface contract permits sparser implementations.** The
   `SnapchainStateReader` trait (`reader.rs:33-37`) defines
   `all_active_fids` as the "scoring window" universe. The
   `InMemoryReader` test impl uses an explicit set; a production reader
   could legitimately move to "FIDs with ≥1 cast / engagement in the
   window," which is the natural read of the doc comment, and at that
   point every dormant FID would drop out of every subsequent
   snapshot.

## Consumers that read the stale score

Every read site of `trust_store.get(fid)` will return the stale value
indefinitely:

1. `validator_registry::validate_register_with_trust`
   (`validator_registry.rs:466-481`). This is the validator-trust-gate
   on Register events. A FID that earned `trust_score = 0.9` two years
   ago, then dropped off the snapshot, will still pass any
   `min_validator_trust_score` floor when re-registering — even though
   the chain has no current evidence that the FID is still credible.

2. `HyperRuntime::compute_enforced_active_set_for_epoch`
   (`runtime.rs:3823-3849`). The "FIP threat-model fix (open backlog
   #6)" filter that excludes validators whose trust dropped below
   `min_validator_trust_score`. Its threat model is "a validator who
   was once trusted can be soft-deregistered if their score later
   collapses." But the filter reads `trust_store.get(fid)` which
   returns the old high score for any FID absent from the most-recent
   snapshot — defeating the purpose of the filter on dropout
   validators. The same `trust_store.get` lookup is in
   `validators_below_trust_floor` (`runtime.rs:3877-3888`); operator
   monitoring sees a clean list that does not reflect the true
   absence of fresh signal.

3. `FeeCharger::compute_effective_fee_micro` callsite
   (`fee_charger.rs:95-99`): `trust = self.trust_store.get(sender_fid)`
   passed into `compute_effective_fee_micro` for the uniqueness fee
   discount. A FID with a long-stale high score keeps paying the
   discounted fee tier even after they've stopped contributing.

4. `TrustScoreStore as TrustScoreResolver` (`trust_store.rs:71-75`):
   the trait impl is `fn trust_score_for_fid(&self, fid: u64) -> Result<Option<f64>, HubError> { self.get(fid) }` — there is no
   "as-of epoch" parameter. Every caller of the resolver gets the
   most-recent-ever-written score.

## Attack / drift scenarios

Scenario A — **bootstrap-trust permanent grant**. Operator ships the
cutover with a permissive retro snapshot that contains 10k FIDs the
on-chain registry doesn't yet include (registrations queued, retro
universe was a wider scrape). Those 10k entries stay at their
bootstrap score forever. When any of them later registers and the
live snapshot finally includes them, the live score overwrites the
bootstrap one — *if* they show post-transfer activity in some epoch
window. If they remain dormant, the bootstrap score is the source of
truth indefinitely, and they cross the validator trust gate without
ever proving on-chain credibility.

Scenario B — **trust-score laundering**. FID X earned `trust = 0.9`
at epoch N via legitimate engagement. At epoch N+1 the operator pays
X for an attack-of-opportunity; X stops engaging entirely; their
follow graph rots; an honest re-scoring would give them `trust ≈ 0`.
But because `evaluate_epoch` produces snapshots only for FIDs in
`all_active_fids()`, and an inactivity-pruning future reader (or
today's bootstrap path) can drop X, the trust gate continues to read
`0.9`. X can register a new validator slot at epoch N+M (any future
epoch) because the gate only consults the *latest written* score.

Scenario C — **silent drift through reader narrowing**. Today's
`PoqReader::new(db, universe)` is wired with the runtime's full
registered-FID set, so dropouts are bounded to scenarios A and B's
register-vs-active gap. But the codebase has TODOs to narrow the
universe (`runtime.rs:450-453`: "A future optimization could filter
to FIDs whose Register event happened ≤ the anchor block"). A future
PR that adopts that filter introduces a silent regression: every FID
older than the anchor block but registered before still has its old
score, and any FID registered after the anchor block does not (and
will not, until they show activity AND another snapshot is computed).

Scenario D — **bootstrap rollback resistance via stale entries**.
`apply_trust_snapshot_update` enforces a monotonic-epoch replay
guard at `runtime.rs:589-595`. That guard works correctly for the
*epoch* but does not invalidate trust entries that were written under
older snapshot epochs but are missing from the latest one. A
sophisticated attacker who can control which FIDs are in
`all_active_fids` (e.g., by getting the reader's universe filter to
exclude their target) can effectively *freeze* that target's trust at
whatever value it had the last time they were included.

## Affected file:line citations

- `src/hyper/trust_store.rs:38-65` — store API: only `set`,
  `set_many`, `get`. No `del`, no `clear`, no
  `prune_missing_from(set)`, no iterator. `set_many` (line 59) is a
  plain for-loop of PUT.
- `src/hyper/runtime.rs:573-616` —
  `HyperRuntime::apply_trust_snapshot_update`: iterates only
  `update.entries`. No precondition pass to enumerate currently-stored
  FIDs and delete those missing from `entries`. Doc-comment line
  577-578 calls it "Idempotent ... set_many is overwriting put"
  without acknowledging that overwriting-PUT is not replace-set.
- `src/hyper/runtime.rs:4019-4026` — cutover `set_many(trust_snapshot)`
  bootstrap path. No `clear` precondition; if a previous test/dev
  cutover had written different entries, those persist.
- `src/hyper/scoring_driver.rs:87-99` (`run_epoch_unsigned`) and
  `:163-170` (`run_epoch_dkls_local`) — serialize only
  `scoring.trust_snapshot.iter()` into the wire-frame `entries`. Any
  FID absent from `metrics` is silently absent from the
  snapshot-update message.
- `crates/proof-of-quality/src/scoring.rs:319-436` (especially
  427-428) — `evaluate_epoch`'s trust_snapshot is `metrics.iter()`,
  and `metrics` (`metrics.rs:213-293`) keys on
  `reader.all_active_fids()`.
- `crates/proof-of-quality/src/reader.rs:33-37` — trait contract
  permits sparse universes ("FIDs that have any post-transfer
  activity within the scoring window").
- `src/hyper/poq_reader.rs:81-104` — production reader caches a
  `BTreeSet<u64>` at construction; `with_fids` overrides it.
- `src/hyper/validator_registry.rs:466-481` —
  `validate_register_with_trust` consumes the (possibly stale) score
  via `trust_score_for_fid`.
- `src/hyper/runtime.rs:3823-3849` —
  `compute_enforced_active_set_for_epoch` reads
  `trust_store.get(fid)`; the auto-deregister soft-evict is
  predicated on the assumption that this returns "the score in effect
  at epoch `prev`" but in practice returns the latest-ever-written
  score, which can be older than `prev`.
- `src/hyper/runtime.rs:3858-3891` — `validators_below_trust_floor`
  surfaces the same stale read to operator dashboards.
- `src/hyper/fee_charger.rs:95-99` — fee charger trust-score lookup
  is also stale, biasing fee discounts toward FIDs whose old score is
  remembered.
- `src/hyper/trust_store.rs:71-75` — `TrustScoreResolver` trait impl
  has no as-of-epoch parameter.

## Severity rationale: medium

- **Detection difficulty**: low for an auditor (the store API is one
  file, 65 lines), but invisible in operation — the snapshot wire
  frame is well-formed, every validator computes the same biased
  result, and no test compares the store contents to the snapshot's
  entry set.
- **Exploitability today**: bounded. The production `fids_for_scoring`
  (`runtime.rs:454-483`) returns the full registered FID universe via
  paginating `OnchainEventStore::get_fids`, which is monotone. The
  realistic dropout vector today is the bootstrap-vs-live universe
  gap (Scenario A); how wide that gap is depends on how the operator
  builds the cutover snapshot. The remaining scenarios become live
  the moment any reader-side narrowing lands.
- **Latent impact severity**: high if Scenario A or C fires —
  validator trust-floor gate is the only thing standing between any
  FID and a registered validator slot, modulo per-FID quotas. A
  permanent stale high score is a permanent admission ticket.
- **Cost to fix**: low — add `delete_not_in(new_set)` to the store
  and call it at the head of `apply_trust_snapshot_update` (and the
  cutover path), or restructure the snapshot wire-frame to carry
  full replace-set semantics with a fids-with-zero-trust convention.

Not high because today's wiring is monotone in the FID universe, so
the direct loss is bounded to bootstrap-discrepancy entries. Not low
because the doc comments explicitly mis-describe `set_many` as
"overwriting put" — meaning the assumption that the trust store
mirrors the latest snapshot is already baked into the design, and
adjacent code (auto-deregister soft evict, fee charger) is built on
that false premise.

## Suggested remediation (for triage; not part of this draft's scope)

1. **Add a delete primitive** to `TrustScoreStore`. Either:
   - `pub fn delete_not_in(&self, keep: &BTreeSet<u64>) -> Result<usize, HubError>` that prefix-scans `[HyperTrustScore]` and deletes
     any key whose FID isn't in `keep`, **or**
   - `pub fn del(&self, fid: u64) -> Result<(), HubError>` plus a
     wrapper that the snapshot-update path uses to compute the diff
     between current keys and the new entry set.

2. **Make `apply_trust_snapshot_update` replace-set, not additive.**
   Before the PUT loop, call `trust_store.delete_not_in(&entry_fids)`
   so the store mirrors `update.entries` exactly. Cutover bootstrap
   should call `clear()` first.

3. **Bind snapshot entries to an epoch in storage.** Change the value
   layout from `[8B f64]` to `[8B BE epoch][8B f64]`, and make
   readers (`validator_registry`, `enforced_active_set`,
   `fee_charger`) require `epoch_in_store ≥ caller_epoch - K` for
   some staleness bound. A stale-but-not-yet-purged entry would be
   read as `None` past the staleness horizon, falling back to the
   gate's safe-default (the gate already handles `None` as `0.0`).

4. **Add a parity test** that runs `evaluate_epoch` twice with
   different FID universes (a larger one first, then a strict subset)
   and asserts that `apply_trust_snapshot_update` of the second
   leaves zero entries for FIDs in the first-but-not-second. Today
   the only `set_many_overwrites_existing` test
   (`trust_store.rs:104-110`) checks the trivial case that PUT
   overwrites a same-key value — it does not exercise the dropout
   case.

5. **Document the invariant.** `trust_store.rs:8-12` claims the
   snapshot is "refreshed" every successful issuance. Either make
   that true by implementing replace-set, or update the comment to
   "trust scores are *append-only*; a FID's score reflects the
   last epoch in which it appeared in `all_active_fids` and may be
   arbitrarily stale."
