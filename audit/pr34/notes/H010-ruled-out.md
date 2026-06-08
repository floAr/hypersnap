---
id: H010
specialist: consensus-malachite-tendermint
attack_class: epoch-boundary-race
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H010 — epoch-boundary race (scoring / lock-root / unstake / DKLS ceremony): ruled out

## Hunt

Look for an epoch-boundary race where two of {validator scoring, signed
lock-root refresh, unstake-queue drain, DKLS signing-ceremony start}
observe inconsistent epoch state — one reading the pre-rotation committee/
validator set, another the post-rotation set — yielding a signed artifact
under the wrong committee/group key, or an unstake drain that races a
lock-root refresh.

## Scope walked

- `src/hyper/epoch.rs` — `EpochManager`, `epoch_for_with_offset`, `observe_anchor`.
- `src/hyper/epoch_resolver.rs` — `EpochResolver` (thin wrapper over `EpochManager`).
- `src/hyper/scheduler.rs` — `BlockProductionScheduler`, proposer-context /
  anchor refresh loops.
- `src/hyper/actor.rs` — `EvaluateEpochDkls` handler (dispatch ~L1276), the
  multi-party start paths (`start_dkls_scoring_multi_party`,
  `start_dkls_lock_root_multi_party`, `start_dkls_inbound_burns_multi_party`),
  `maybe_trigger_scoring`, `refresh_signed_lock_merkle_root`,
  `start_queued_sign`, the serial `run`/`dispatch` loop.
- `src/hyper/scoring_driver.rs` — `run_epoch_unsigned`, `run_epoch_dkls_local`.
- `src/hyper/dkls_committee.rs` — `select_signing_committee`,
  `committee_seed_for_epoch`.
- `src/hyper/runtime.rs` — `process_unstake_queue`, `active_validators*`,
  `dkls_share_for_epoch`, `dkls_group_address_for_epoch`,
  `produce_unsigned_block_dkls`, `import_block`/`apply_cutover` anchor
  observation, `apply_retro_vesting_tranche`.

## Why there is no race

1. **Single-threaded actor; no concurrency over runtime state.**
   `HyperActor::run` (actor.rs L1194-1206) consumes one inbound mpsc and
   awaits `dispatch(event)` serially. Every mutation of `epoch_resolver`,
   `last_scored_epoch`, `dkls_signers`, the unstake queue, and the lock-root
   store happens on this one task behind `&mut self`. There is no second
   task that reads or writes epoch-dependent runtime state, so the classic
   "thread A reads pre-rotation, thread B reads post-rotation" data race
   cannot occur.

2. **All four boundary operations share one `epoch` argument and run in
   sequence.** In the `EvaluateEpochDkls { epoch, .. }` handler
   (actor.rs L1276-1320) the same `epoch` value is threaded into retro-vesting
   (L1281), scoring (L1293 / `start_dkls_scoring_multi_party` L1309),
   lock-root refresh (L1295 / L1311), inbound-burns (L1298 / L1312),
   custody transfers (L1301 / L1313), and the unstake drain (L1304 / L1316).
   They execute one after another within a single `&mut self` call. No
   operation re-derives the epoch from a mutable resolver mid-handler, so two
   of them cannot disagree on the boundary.

3. **Committee / group key / active set are pure deterministic functions of
   `epoch`.** `active_validators(epoch)` (runtime.rs L3989) computes the set
   from the registry for that epoch; `dkls_share_for_epoch(epoch)` /
   `dkls_group_address_for_epoch(epoch)` are keyed by epoch;
   `select_signing_committee(epoch, digest, share_count, threshold)`
   (dkls_committee.rs) and `committee_seed_for_epoch(epoch, tag)` are pure.
   There is no mutable "current committee / current rotation" snapshot that a
   reader could observe mid-flip — the epoch argument fully determines the
   committee and key, so every signed artifact for content-epoch `e` is signed
   by epoch `e`'s committee and verifies under epoch `e`'s group address.

4. **Async sign-queue draining captures a per-task epoch snapshot.** The
   multi-party paths enqueue `DklsSignTask { epoch, digest, party, committee }`
   (actor.rs L1077, L3067/3090/...) with the committee already selected and
   the digest already computed. The queue drains over later `AdvanceDklsSign`
   ticks, but `start_queued_sign` builds the driver with the *task's* captured
   epoch (`DklsSignDriver::new(task.epoch, ...)` L2989), never a re-read of
   `epoch_resolver.current_epoch()`. So even if the resolver advances across a
   boundary while a ceremony is mid-flight, the in-flight artifact stays bound
   to its original committee/key.

5. **The production scoring trigger and the boundary handler do not coexist.**
   In production, per-epoch scoring + trust snapshot are driven by
   `maybe_trigger_scoring` (actor.rs L2203), called right after
   `import_block` (which advances `epoch_resolver`, runtime.rs L4581).
   `EvaluateEpochDkls` is only constructed in `src/bin/devnet.rs` (hardcoded
   `epoch: 0`) and in unit tests — there is no production supervisor that wires
   `EvaluateEpochDkls` to a live epoch derivation. So there is no second
   live path that could feed a stale/wrong `epoch` into the lock-root/unstake
   drain alongside scoring.

6. **Prior fixes already closed adjacent epoch-consistency gaps.** F004 makes
   the proposer-context refresh snapshot the anchor first, then derive epoch +
   active set from that single anchor (scheduler.rs L254-275). F024 folds the
   gating decision and anchor snapshot into one lock acquisition
   (scheduler.rs `should_propose_and_snapshot` L156-177). F028/F026 bind block
   production to `epoch_resolver.current_epoch()` and require the share to exist
   for exactly that epoch, instead of `dkls_signers.iter().next_back()`
   (runtime.rs L4824-4838) — preventing future-epoch material from leaking into
   current production. These eliminate the pre/post-rotation split surfaces in
   the scope.

## Residual notes (not exploitable, observed in passing)

- The unstake drain is monotone in `epoch` (`process_unstake_queue` stops at
  `current_epoch+1` prefix and is idempotent — draining the same epoch twice
  is a no-op, runtime.rs L2083-...). A re-org cannot roll the epoch back
  (`observe_anchor` only advances, epoch.rs L101-114), so a drained-then-rolled
  scenario is not reachable.
- `apply_retro_vesting_tranche(epoch)` runs before the share check inside the
  handler; on a node with no share it still advances vesting, but that is
  deterministic per-epoch state shared by all nodes, not a committee/key
  binding — out of scope for this attack class and not an inconsistency.

## Conclusion

No epoch-boundary race in the H010 scope. Epoch state is read once per
boundary handler, threaded as a single value through all four operations,
and committee/key/active-set are deterministic functions of that value.
The actor's serial execution model plus per-task epoch capture remove any
window for two operations to observe different rotation states.
