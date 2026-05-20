---
id: F040
task: H040
specialist: rust-threshold-signing
attack_class: supervisor-non-recovery
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F040: DKLS supervisor latches `last_started_for_epoch` on dispatch, never retries within the epoch when the ceremony aborts

## Summary

`run` in `code/hypersnap/src/hyper/dkls_supervisor.rs` sets
`last_started_for_epoch = Some(next_epoch)` immediately after sending
`HyperActorEvent::StartDkls` to the actor — *before* the ceremony has
made any progress, let alone completed. The variable is the sole gate
the supervisor consults to decide whether to fire `StartDkls(next_epoch)`.
There is no retry budget, no backoff, no feedback path from the actor's
`HyperActorOutbound::DkgFinalized`, and no liveness check against the
runtime's installed-share registry. If the ceremony aborts for any
reason after dispatch (network partition during DKG, insufficient
participants reach quorum, peer panic, codec error in `try_advance`,
driver dropped on error in `AdvanceDkls` — see below), the supervisor
will *not* re-fire `StartDkls` until `next_epoch` ticks over to a new
value. The result is a permanent missing DKG group for that epoch
window, even though quorum might recover within seconds.

This is distinct from F024 issue 2 (anchor jump past the epoch lead
window): there the supervisor never enters the lead window and never
fires. Here the supervisor *does* fire, then mistakes "I sent the
event" for "the ceremony succeeded" and refuses to fire again.

## Description

### The latch is set on dispatch, not on completion

`dkls_supervisor.rs:68-104`:

```rust
let mut last_started_for_epoch: Option<u64> = None;

loop {
    ticker.tick().await;

    let anchor = *inputs.latest_anchor.lock().await;
    let current_epoch = epoch_for(anchor);
    let next_epoch = current_epoch + 1;
    let next_epoch_start = next_epoch * EPOCH_LENGTH;
    let blocks_until_next = next_epoch_start.saturating_sub(anchor);

    if blocks_until_next <= inputs.start_lead_blocks
        && last_started_for_epoch != Some(next_epoch)
    {
        match build_driver(&inputs, &client, next_epoch).await {
            Ok(driver) => {
                info!(...);
                if inbound
                    .send(HyperActorEvent::StartDkls { driver: Box::new(driver) })
                    .await
                    .is_err()
                {
                    break;
                }
                last_started_for_epoch = Some(next_epoch);   // <-- set on send
            }
            Err(e) => {
                warn!(target_epoch = next_epoch, "skip StartDkls: {}", e);
                // (latch NOT updated on build_driver error — see below)
            }
        }
    }

    if inbound.send(HyperActorEvent::AdvanceDkls).await.is_err() {
        break;
    }
}
```

The latch is updated only on the `Ok(driver)` branch, on the line
immediately after `inbound.send(StartDkls)` resolves. At that point:

- The actor has only *enqueued* the event (mpsc), not processed it.
- The ceremony has not started its phase-1 broadcast.
- No peer has acknowledged anything.

From this line onward the predicate
`last_started_for_epoch != Some(next_epoch)` is false until
`next_epoch` becomes a different value, i.e. until the chain has
already crossed into `next_epoch`. At that point firing `StartDkls`
for the *previous* epoch is useless anyway — the chain is already
trying to sign blocks under a key that was never derived.

### No completion feedback

The actor produces `HyperActorOutbound::DkgFinalized { target_epoch }`
on the successful path (`actor.rs:1282-1290`):

```rust
HyperActorEvent::AdvanceDkls => {
    let Some(mut active) = self.active_dkls.take() else {
        return Ok(());
    };
    active.driver.try_advance()?;       // <-- error path silently drops active
    self.flush_dkls_outbound(&mut active.driver).await;
    if active.driver.is_completed() {
        let target = active.driver.target_epoch();
        active.driver.finalize_into_runtime(&mut self.runtime)?;
        let _ = self
            .outbound
            .send(HyperActorOutbound::DkgFinalized { target_epoch: target })
            .await;
    } else {
        self.active_dkls = Some(active);
    }
    Ok(())
}
```

That `DkgFinalized` event is delivered into `gossip_adapter` /
`network_loop`. It is **never** read by the supervisor — the supervisor
holds only `inbound: mpsc::Sender<HyperActorEvent>` and
`client: HyperActorClient`. There is no channel from the actor back
to the supervisor for "ceremony N completed" or "ceremony N failed".

So the supervisor cannot self-correct by observing completion.

### Several failure modes drop the ceremony silently

Each of these failure modes leaves the supervisor's latch set but
the runtime with no installed share for `next_epoch`:

**Driver dropped on `try_advance` error.** Look at the AdvanceDkls
handler above carefully. `self.active_dkls.take()` removes the driver
from the actor; `active.driver.try_advance()?` propagates with `?`.
The `Ok(())` arm is the only place `self.active_dkls` is restored.
On the error arm (the `?` short-circuit), `active` goes out of scope
and is dropped — the actor's `active_dkls` is now `None`. Any
malformed peer message or coordinator-detected protocol fault during
DKG yields exactly this state: ceremony evaporates, supervisor's
latch stays set, no retry.

**Insufficient participants reaching the actor's StartDkls.** Each
peer's supervisor runs independently; they have no synchronized
clock and each polls its own `latest_anchor`. A peer whose snapchain
follower is lagging by a few blocks may not enter the lead window
until others have already started and timed out their phase-1
accumulators. If quorum-1 peers fire phase-1 messages and one is
missing, the ceremony stalls. (DKLS23 requires exactly `threshold`
parties — see the comment at `dkls_supervisor.rs:43-47`.) After
the stragglers catch up and become reachable, the early peers'
ceremonies are in an indeterminate state with stale phase-1
accumulators; the late peer's supervisor has latched on `next_epoch`
and will never fire its own StartDkls again. (This is also a
phase-accumulator-length-gating concern, separately auditable —
see attack_class catalog.)

**Network partition during DKG.** Standard distributed-systems
case: a partition isolates one side mid-ceremony. After the partition
heals, both sides need to retry. Neither retries.

**Driver internal error or panic in the actor task.** The actor
loop continues on `Ok(())`/`Err(e)` returns from the per-event
handlers, but the latched ceremony is gone from `active_dkls`. If
the actor task itself panicked and the operator restarted only it,
the supervisor's `run` task remains alive with `last_started_for_epoch`
still pointing at the lost epoch.

### `build_driver` error does NOT latch — exposes the inconsistency

A telling detail: in the `Err(e) => warn!(...)` branch at
`dkls_supervisor.rs:100-103`, the latch is *not* updated. That branch
covers `EmptyActiveSet`, `LocalNotActive(epoch)`, `ActiveSetTooLarge`,
and `Client(...)` (transient client RPC failure). For those, the
supervisor *does* retry on the next tick — the predicate
`last_started_for_epoch != Some(next_epoch)` stays true.

This means the supervisor implicitly understands "build-time failure
deserves a retry" but is blind to the much larger class of "post-dispatch
failure". The right invariant is the same in both cases: latch only
on confirmed install of the share into the runtime.

### In-memory only — restart is the only recovery

`last_started_for_epoch` is a local `let mut` in `run`. It is not
persisted. So the only way the supervisor unsticks is for the entire
supervisor task to die (and only the supervisor — not the actor,
because then the share state in memory dies too) and be restarted by
the operator, at which point the freshly-initialized `None` value
will let the gate reopen.

For operators running long-lived nodes this is effectively never.

## Impact

- **Single-epoch chain stall on the most common DKG abort modes.**
  Net + DKLS-protocol faults are routine: a slow peer, a temporarily
  partitioned subnet, a single malformed `DklsRoundMessage` that
  trips `try_advance`. Any one of these inside the
  `start_lead_blocks` window for epoch `N` permanently denies that
  epoch's group key on the affected supervisor's node.
- **Whole-cohort stall when the abort cause is shared.** If a
  network event affects multiple peers (the common case — the
  validators are nodes in the same gossip topology), every affected
  supervisor latches simultaneously. Recovery requires every
  affected operator to restart the supervisor process.
- **Validator slashing risk.** Per F004, with no installed share
  for epoch `N` the actor cannot produce signed blocks for `N`.
  Other peers see a non-responsive validator and may trigger
  auto-deregister (`F011` references the per-epoch counter).
- **Compounded with F024.** F024 issue 2 (anchor jump past the
  lead window) shares the "no retry" failure mode but enters it
  via a different door. The remediation for either should also
  cover the other.

## Evidence

- `code/hypersnap/src/hyper/dkls_supervisor.rs:68` — `last_started_for_epoch`
  declared as `let mut … : Option<u64> = None`, scoped to `run`,
  not persisted.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:80` — gate predicate is
  `last_started_for_epoch != Some(next_epoch)` only.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:89-98` — `inbound.send(StartDkls)`
  resolves to "event enqueued", then the latch is set unconditionally
  on the success branch.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:100-103` — `Err(e)` branch
  intentionally does NOT update the latch, demonstrating that the
  author understood retry semantics for build-time errors but not
  for post-dispatch.
- `code/hypersnap/src/hyper/actor.rs:1276-1295` — `AdvanceDkls`
  handler takes `active_dkls` and only restores it on `is_completed()`
  false. On `try_advance()?` error the driver is dropped. No event
  is sent back to the supervisor.
- `code/hypersnap/src/hyper/actor.rs:1287-1290` — `DkgFinalized` is the
  only outbound related to ceremony state; it goes to `outbound` (the
  gossip-adapter / network-loop), never to the supervisor.
- `code/hypersnap/src/hyper/network_loop.rs:52` and
  `gossip_adapter.rs:155` — confirm `DkgFinalized` is consumed only
  by transport.
- Comments at `dkls_supervisor.rs:43-47` confirm DKLS23 requires
  *exactly* `threshold` parties to sign — any abort of the DKG
  prevents next-epoch signing entirely.

## Suggested remediation

1. **Move the latch to install-confirmation, not dispatch.** Drop
   the local variable. On every tick, query the runtime via the
   `HyperActorClient` for "is a DKLS share installed for epoch
   `next_epoch`?" (parallel to `dkls_share_for_epoch` in the runtime).
   Fire `StartDkls(next_epoch)` if not. This is naturally retry-safe
   and self-healing.
2. **If a latch must remain, give it a TTL or a generation count.**
   E.g. `last_started_for_epoch: Option<(epoch, started_at_anchor)>`
   and re-fire when `current_anchor - started_at_anchor >
   max_ceremony_blocks` regardless of latch value. Tune `max_ceremony_blocks`
   to be larger than a healthy ceremony's wall-clock convergence and
   smaller than `start_lead_blocks` so a retry still completes in
   window.
3. **Add a feedback channel from actor to supervisor.** Either a
   second mpsc the supervisor reads (CompletedDkls / AbortedDkls)
   or extend the read-side `HyperActorClient` to expose
   `active_dkls_target_epoch()` so the supervisor can detect
   "I fired StartDkls(N) but the actor no longer has an active_dkls
   AND no share is installed ⇒ aborted, refire".
4. **Fix the silent drop in AdvanceDkls.** Restore `active_dkls` on
   the error path of `try_advance` *or* signal abort to the supervisor
   path:
   ```rust
   HyperActorEvent::AdvanceDkls => {
       let Some(mut active) = self.active_dkls.take() else {
           return Ok(());
       };
       match active.driver.try_advance() {
           Ok(()) => { /* existing flush + complete-check */ }
           Err(e) => {
               // Emit AbortedDkls outbound so supervisor can refire.
               let target = active.driver.target_epoch();
               let _ = self.outbound.send(
                   HyperActorOutbound::DkgAborted { target_epoch: target, reason: e.to_string() }
               ).await;
               return Ok(());   // active intentionally dropped
           }
       }
       ...
   }
   ```
5. **Persist the latch alongside completed-epoch state.** Per F024
   suggested remediation 5, key both off the installed-share registry
   so restart and steady-state share the same recovery semantics.
6. **Add an integration test** that drives the supervisor with a
   fake `inbound` and a fake `client`, fires StartDkls(N), simulates
   a `try_advance` error mid-DKG (no share installed), then advances
   the latest_anchor by one tick still within the lead window and
   asserts the supervisor re-fires `StartDkls(N)`.
7. **Cross-link with F024 in remediation tracking.** The "supervisor
   skips an epoch" failure mode and this "supervisor latches and
   doesn't retry" failure mode are best fixed by the same change
   (install-confirmation-based gating) — splitting them risks
   uncoordinated partial fixes.
