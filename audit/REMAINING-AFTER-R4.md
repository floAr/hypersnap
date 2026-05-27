# Remaining after PR #28 round 4 (`f2b062c8`)

R4 compiles clean and closes the round-3 tail: **F031** and **F135** are resolved, and the
**F026 slashing read-path** is correctly fixed — `slashed_validators_for_epoch`
(`src/hyper/runtime.rs:4213`) now resolves `signer_indices` against
`get_active_validators_enforced(block_epoch, &self.bootstrap_validators)` rather than the raw
active set.

Three items remain for round 5, in priority order.

---

## 1. F026 — two unfixed twins of the slashing read-path (one-line fix each)

R4 fixed `slashed_validators_for_epoch` but missed two sibling helpers that resolve a DKLS
party index the *same* (now-wrong) way the slashing path used to. Both still index
`active.iter().nth(party_index - 1)` over the **raw** set
`self.validator_registry.compute_active_set(epoch, &self.bootstrap_validators)`:

- `transport_pubkey_for_party` — `src/hyper/runtime.rs:1200`
  (raw `compute_active_set` at `:1208`, `nth(target)` at `:1217`)
- `peer_id_for_party` — `src/hyper/runtime.rs:1244`
  (raw `compute_active_set` at `:1248`, `nth(target)` at `:1253`)

**Why this is wrong.** DKLS committee party indices are assigned over the **enforced** set:
`build_driver` calls `client.active_validators(target_epoch, true)`
(`src/hyper/dkls_supervisor.rs:199`) — i.e. the enforced active set — and fixes the 1-based
party index from its BTreeMap iteration order (`:211`–`:222`). The enforced set drops
validators removed by slashing / auto-deregister / trust-floor. The raw `compute_active_set`
does **not** drop them. So the moment any validator is enforced-excluded, the raw set carries
an extra entry and `nth(party_index - 1)` lands on the **wrong** validator — exactly the class
of bug R4 just fixed on the read-path, still live on these two lookups.

**Impact.**
- `transport_pubkey_for_party` seals outbound DKLS round messages to the wrong validator's
  X25519 transport key → the addressed receiver cannot decrypt → ceremony liveness failure.
- `peer_id_for_party` makes the F018 ingress sender cross-check resolve the wrong validator →
  honest frames false-rejected / misattributed.

The in-code comments on both helpers — "same ordering `compute_active_set` uses for committee
enumeration" (`:1212`–`:1215` and `:1236`–`:1243`) — are **stale**; committee enumeration uses
the enforced set, not `compute_active_set`.

**Fix.** Resolve both helpers against
`get_active_validators_enforced(epoch, &self.bootstrap_validators)`
(signature at `src/hyper/runtime.rs:4058`), preserving each helper's existing error handling
(both currently `.ok()?` → `None`, so map the `Result` error to `None` the same way). Update
or delete the two stale comments. This is the same substitution R4 already applied at `:4213`.

---

## 2. F004 — epoch-boundary race (R2 closed one race; deferred races remain, untouched R3/R4)

`findings/F004-epoch-boundary-race.md`. R2 (`b14378a2`) closed the
`refresh_proposer_context_loop` race — the scheduler now snapshots the anchor once and derives
`epoch = epoch_for(anchor.block)` from that same snapshot (`scheduler.rs:251-274`), instead of
three independent reads across `.await`. The deferred races below were **not** further addressed
in R3 or R4 (verbatim from the R2 revalidation's F004 deferred list):

- **Cutover/genesis-epoch arithmetic, no offset.** Epoch derivation is still bare
  `anchor_block / EPOCH_LENGTH` with no cutover offset (`epoch.rs:22-23`), so the genesis DKLS
  group (installed at epoch 0 by cutover) and the resolver's `epoch_for(snapchain_block)`
  (non-zero for any realistic mainnet cutover height) disagree. Fix: apply a cutover offset and
  add a regression test at a mainnet-shaped cutover height.
- **Two desynchronized anchor sources.** The supervisor keeps a *separate* anchor mutex (`u64`)
  from the scheduler's `LatestAnchor` struct; the two are written non-atomically and the
  supervisor derives its epoch from its private anchor, so the two epoch views can diverge by a
  full epoch. Fix: collapse to a single shared anchor source.
- **`build_driver` double-read across `.await`.** `build_driver` re-reads the supervisor anchor
  in a second lock acquisition (`dkls_supervisor.rs:90` vs `:233`) after the active-set query; an
  `InboundBlock` carrying a `HyperValidatorEvent` landing between the two reads changes
  `share_count` for some participants, so `canonical_session_id` diverges across the cohort and
  the ceremony cannot converge. Fix: take one `(anchor, active_set)` snapshot per tick and thread
  it through.

---

## 3. F024 — supervisor catch-up burst residuals (R1 + R2 fixed the primaries; two narrow gaps remain)

`findings/F024-scheduler-split-read-and-supervisor-anchor-jump.md`. Distinct from F004. Two of
this finding's mechanisms are already fixed: the **scheduler split-read** was closed in R1
(`should_propose_and_snapshot` — the gate decision and the anchor snapshot now share one critical
section), and the **supervisor anchor-jump epoch skip** was closed in R2 by the catch-up loop
`for target in first_undispatched..=next_epoch` that builds a driver and fires `StartDkls` for
every undispatched epoch in the gap (`dkls_supervisor.rs:131-133`). Two **narrow** liveness
residuals surfaced by that R2 fix remain, untouched in R3/R4:

- **Share watchdog tracks only the last epoch of a burst.** The dispatch tracker is a single
  `dispatched: Option<Dispatched>` (`dkls_supervisor.rs:85`); the share-install watchdog checks
  only `has_dkls_share_for_epoch(d.epoch)` for that one retained epoch (`:103`). When the
  catch-up loop dispatches several epochs in one tick, only the *last* is retained — if an
  earlier epoch in the burst never installs its share, it is never detected or retried. Fix:
  track dispatched epochs per-epoch (set / high-water-mark) so the watchdog covers every epoch in
  the gap, and refuse `StartDkls(N+2)` while `N+1` is unfinished.
- **Current epoch permanently skipped on mid-epoch cold start.** `first_undispatched =
  last_dispatched_epoch.max(current_epoch) + 1` (`dkls_supervisor.rs:132`) — a node that starts
  partway through an epoch with no share for it never dispatches `StartDkls` for the current
  epoch, so it holds no group key for the epoch it is already in. Fix: seed `first_undispatched`
  from the highest *installed* share + 1 rather than `current_epoch + 1`, so a cold-start node
  catches up the in-flight epoch.
