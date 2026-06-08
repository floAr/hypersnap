---
id: H017
specialist: node-lifecycle-actor
attack_class: scheduler-race
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
scope:
  - src/hyper/scheduler.rs
  - src/hyper/scoring_driver.rs
  - src/hyper/dkls_supervisor.rs
  - src/hyper/actor.rs (DKLS lifecycle handlers, read-supporting)
  - src/hyper/dkls_driver.rs
date: 2026-06-08
---

# H017 (scheduler-race) — ruled out on cab225f

Re-evaluated freshly on `cab225f` (PR #34, pow merge), not relying on the
prior OLD-commit ruling. Hunt target: a scheduler/supervisor race on the
DKLS ceremony lifecycle — two ceremonies running concurrently for the same
epoch, or a completion handler firing against a superseded ceremony and
corrupting share / group-address / block state.

## What was walked

- `dkls_supervisor.rs::run` — the per-epoch DKG dispatcher and its
  `dispatched: BTreeMap<u64,u32>` watchdog (F024/F040 retry logic),
  `build_driver`, `canonical_session_id`.
- `scheduler.rs` — `BlockProductionScheduler::run`, `should_propose_and_snapshot`
  (F024 single-lock gating+anchor snapshot), `refresh_proposer_context_loop`,
  `refresh_latest_anchor_loop`, `track_outbounds`. Shared `LatestAnchor`
  (F004) consumed by both scheduler and supervisor.
- `scoring_driver.rs` — `run_epoch_unsigned`, `run_epoch_dkls_local`.
- `actor.rs` DKLS lifecycle arms: `StartDkls`/`AdvanceDkls`,
  `StartDklsSign`/`AdvanceDklsSign`, `InboundDkls`/`InboundDklsSign`,
  `start_dkls_block_production`, `start_dkls_scoring_multi_party` and the
  lock-root/inbound-burn siblings, `finalize_dkls_signature`,
  `dispatch_dkls_signature`, `start_queued_sign`, `maybe_trigger_scoring`.
- `dkls_driver.rs::finalize_into_runtime` and
  `runtime.rs::install_local_dkls_share` / `active_validators`.

## Why no corruption-class race exists

1. **Single-consumer actor mailbox.** Supervisor (StartDkls/AdvanceDkls),
   scheduler (ProduceBlockDkls), and epoch-transition triggers all post to
   one `mpsc::Sender<HyperActorEvent>` and are processed serially by one
   actor task. There is no shared-mutable-state data race; only logical
   lifecycle ordering matters.

2. **Concurrent same-epoch DKG ceremony is blocked.** `StartDkls`
   (F023c) checks `active_dkls`: same target_epoch ⇒ "keep existing driver"
   and return; different epoch ⇒ replace with a warning. So a second
   StartDkls for an in-flight epoch never spins up a second ceremony, and
   the two-ceremonies-one-epoch corruption cannot occur.

3. **Watchdog never re-dispatches a stale lower epoch out of order.** When a
   dispatched epoch's share fails to install within `DKLS_RETRY_AFTER_TICKS`,
   the watchdog only removes it from `dispatched`. Re-dispatch is gated by
   `first_undispatched = highest_dispatched + 1` (or, on full-empty, a
   cold-start seed bounded by `current_epoch+1`). An epoch below
   `highest_dispatched` is never re-emitted, so a stale `StartDkls(E)` can
   never arrive after `StartDkls(E+1)` to nuke a legitimately-active newer
   ceremony via the different-epoch replacement branch. (Residual: such a
   stuck lower epoch is abandoned — a liveness gap, not state corruption.)

4. **Completion is digest-keyed, not ceremony-identity-keyed.**
   `dispatch_dkls_signature` matches a finalized signature to a pending item
   by `keccak(signing_payload)` digest in `pending_dkls_blocks` /
   `pending_dkls_messages`. The digest uniquely determines the canonical
   payload (block header incl. anchor/height/committee per F153, or
   issuance/snapshot body), so a signature finalized by any ceremony can only
   attach to the exact pending item whose bytes hash to that digest. A
   "superseded ceremony completes and corrupts a different item" requires a
   payload/digest collision, which is infeasible.

5. **Retry-install is idempotent.** `install_local_dkls_share` does an
   unconditional `insert` of share + group address keyed by epoch and
   write-through to the address store; a re-finalization of the same epoch's
   ceremony overwrites with an equal value (same deterministic active set →
   same group address). No partial/corrupt state.

6. **F004 single shared anchor.** Supervisor and scheduler read the same
   `Arc<Mutex<LatestAnchor>>`; the prior dual-anchor desync is gone.
   `should_propose_and_snapshot` (F024) takes the gating decision and the
   committed anchor under one lock, so a refresh tick cannot split them.

## Residual (non-finding) observations

- `start_dkls_block_production` overwrites an in-flight multi-party
  `active_dkls_sign` (scoring/lock-root/burn) without re-queuing it
  (documented F023b "block production outranks scoring"). The abandoned
  ceremony's pending message lingers in `pending_dkls_messages` and may
  never be signed that epoch → reward/lock-root liveness loss, not state
  corruption. Pre-existing accepted trade-off; out of H017 scope.
- A registry event mutating epoch E's active set between supervisor
  `build_driver` and finalization could in principle diverge party-index
  mappings, but the active set for E is forward-fixed before E and is a
  deterministic BTreeMap; this is validator-set-determinism territory, not
  a scheduler/supervisor timing race.

Conclusion: no scheduler/supervisor race on the ceremony lifecycle that
corrupts share, group-address, or block state. H017 ruled out on cab225f.
