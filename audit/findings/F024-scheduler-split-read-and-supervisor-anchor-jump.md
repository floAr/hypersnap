---
id: F024
task: H024
specialist: node-lifecycle-actor
attack_class: scheduler-race
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.75
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F024: Scheduler tick splits proposer-context read into two critical sections; supervisor can skip a whole epoch's DKG on anchor jumps

## Summary

Two scheduler-races distinct from F004 (which covers the resolver/refresh-loop
write side):

1. **Scheduler `run` reads `ProposerContext` in two separate
   `proposer_ctx.lock().await` acquisitions per tick.** `should_propose`
   acquires the lock, reads `local_key`/`validators`/`anchor_block_hash`,
   then drops it. The body of `run` then re-acquires the lock to read
   `anchor_block`/`anchor_block_hash`/`anchor_block_timestamp` and
   embeds them in the produced block. Between those two acquisitions,
   `refresh_proposer_context_loop` can fully overwrite the context
   (its own write IS atomic). The block produced is therefore gated
   on the *old* `(anchor_block_hash, validators, local_key)` triple
   but committed with the *new* `(anchor_block, anchor_block_hash,
   anchor_block_timestamp)` metadata. The in-source comment "Snapshot
   the anchor info under the same lock so the produced block is
   consistent with the gating decision" is a lie: the lock was
   already released by `should_propose` before the snapshot block
   runs.

2. **Supervisor's `last_started_for_epoch` does not detect skipped
   epochs.** The DKLS supervisor's run-loop only fires `StartDkls`
   when the current anchor sits inside the `start_lead_blocks` zone
   immediately before `next_epoch`. If the anchor jumps from somewhere
   in epoch `N-1` past the end of epoch `N` in a single tick (operator
   was paused, snapchain catch-up, anchor poller backlog), the
   supervisor never sees the lead window for `N` and never fires
   `StartDkls(N)`. It will fire `StartDkls(N+1)` the next time the
   lead window is observed — there is no per-skipped-epoch catch-up.
   Epoch `N` then has no DKG group at all and any block that should
   be signed under epoch `N` cannot be produced.

## Description

### Issue 1 — `BlockProductionScheduler::run` split-read

`scheduler.rs:157-187`:

```rust
loop {
    ticker.tick().await;
    let snapshot = self.head.lock().await.clone();
    let next = snapshot.next_height();
    if !self.should_propose(next).await {         // (A) takes & drops proposer_ctx lock
        debug!("scheduler: not proposer for height {}, skipping", next);
        continue;
    }
    // Snapshot the anchor info under the same lock so the
    // produced block is consistent with the gating decision.
    let (anchor_block, anchor_hash, anchor_ts) = {
        let ctx = self.proposer_ctx.lock().await; // (B) re-acquires the lock
        (
            ctx.anchor_block,
            ctx.anchor_block_hash.clone(),
            ctx.anchor_block_timestamp,
        )
    };
    let event = HyperActorEvent::ProduceBlockDkls { ... snapchain_anchor_hash: anchor_hash, ... };
    ...
}
```

and `should_propose` at `scheduler.rs:135-148`:

```rust
async fn should_propose(&self, height: u64) -> bool {
    let ctx = self.proposer_ctx.lock().await;
    if ctx.anchor_block_hash.is_empty() || ctx.validators.is_empty() || ctx.local_key.is_empty() {
        return true;
    }
    is_proposer(
        &ctx.local_key,
        &ctx.validators,
        &ctx.anchor_block_hash,
        height,
        0,
    )
}
```

The lock is released when `ctx` (a `MutexGuard`) goes out of scope at
the end of `should_propose`. Between (A) and (B) the refresh loop
(`scheduler.rs:217-248`) can take the lock and replace every field at
once:

```rust
let mut g = ctx.lock().await;
g.anchor_block = anchor.block;
g.anchor_block_hash = anchor.hash;
g.anchor_block_timestamp = anchor.timestamp;
g.validators = validators;
g.local_key = local_key.clone();
```

This is unrelated to F004's complaint about non-atomic *reads* inside the
refresh writer — there the issue is that the writer collects
`current_epoch()` and `active_validators` across `.await` points before
the lock. Here the issue is on the *reader* side: even if the writer
were perfectly atomic, the scheduler reads it twice.

#### Concrete bad sequence

Two valid `ProposerContext` snapshots exist:

- `S_old`: epoch N anchor H1, validator set V1, `is_proposer(local, V1, H1, h) == true`.
- `S_new`: epoch N+1 anchor H2, validator set V2 (a peer churned in), `is_proposer(local, V2, H2, h) == false`.

Tick sequence:

1. `should_propose(h)` runs under `S_old`. Returns `true` — we will
   produce. Lock dropped.
2. Refresh tick fires concurrently; `ProposerContext` is replaced with
   `S_new`. Lock dropped.
3. Scheduler reacquires lock, reads `anchor_block = S_new.anchor_block`,
   `anchor_hash = H2`, `anchor_block_timestamp = S_new.anchor_block_timestamp`.
4. Scheduler emits `ProduceBlockDkls { height: h, snapchain_anchor_hash: H2, ... }`.
5. Actor produces the block, signs it, broadcasts it.

Peers verifying the block evaluate proposer selection using
`(H2, V2)` (the metadata in the block itself) and conclude that **a
different validator** is the proposer for height `h` — they reject the
block. Liveness is lost until the local node retries with a fresh
gating decision. Worst case (boundary tick across many validators
simultaneously) the network produces no block for that height because
the proposer per the new context is a node that wasn't selected by
its own scheduler tick (which was still under the old context).

The mirror case — `should_propose` says false on `S_new` but should
have produced under `S_old` — wastes a slot. Most concerning is the
race where `local_key` itself changes (operator-mediated key rotation
or registration), since then a block can be emitted under the wrong
identity.

### Issue 2 — supervisor skips an epoch's DKG on anchor jumps

`dkls_supervisor.rs:70-104`:

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
        match build_driver(&inputs, &client, next_epoch).await { ... }
        last_started_for_epoch = Some(next_epoch);
    }
    ...
}
```

The lead-window predicate `blocks_until_next <= start_lead_blocks`
fires only when the anchor sits inside
`[next_epoch_start - start_lead_blocks, next_epoch_start)`. The fired
`next_epoch` is whatever the current anchor implies.

Now consider what happens when the anchor advances by more than
`start_lead_blocks` between two ticks. Realistic causes:

- The operator's snapchain follower was paused (config reload, restart,
  GC pause). `refresh_latest_anchor_loop` `(scheduler.rs:260-287)`
  polls the local `BlockEventStore`, so the anchor catches up in a
  single `get_last_block_event()` read once the follower resumes.
- The node was offline / behind, and `BlockEventStore` accumulates
  many seqnums; the next `get_last_block_event` returns one far in
  the future.
- The supervisor task itself was suspended (Tokio runtime saturation,
  blocking work elsewhere) — `MissedTickBehavior::Delay` simply
  delays the next tick rather than firing one tick per missed
  interval.

Bad sequence with `EPOCH_LENGTH = 432_000`, `start_lead_blocks =
43_200` (~10%):

1. Tick T1: `anchor = 100`, `current_epoch = 0`, `next_epoch = 1`,
   `blocks_until_next = 431_900`. Not in lead window. No fire.
2. Tick T2: anchor jumps to `432_500` (mid-epoch-1). `current_epoch
   = 1`, `next_epoch = 2`, `blocks_until_next = 431_500`. Not in
   lead window. No fire. **`last_started_for_epoch` is still
   `None`. Epoch 1 has no DKG group.**
3. Subsequent ticks march toward epoch 2's lead window;
   `StartDkls(2)` fires there. Epoch 2 has a group. Epoch 1 still
   does not.

When the chain crosses into epoch 1, every produced block tries to
sign under the highest-installed share, which is the genesis share at
epoch 0 (cutover-installed, `runtime.rs:4014-4017` per F004). If the
chain's verifier is keyed on `signature.epoch`, it expects epoch 1's
DKLS group at epoch-1 boundary. There is none. Block production
stalls until enough operators manually intervene (re-issue
StartDkls(1) via some out-of-band mechanism, since there is no
catch-up path in the supervisor's main loop).

This is distinct from F004's `last_started_for_epoch` complaint,
which concerns supervisor *restart* re-issuing the same epoch's DKG.
Here we have the *opposite* problem: a supervisor that has been
running continuously can silently skip an epoch's DKG.

#### Per-epoch sequencing is also missing

A related sub-issue: after firing `StartDkls(N+1)`, the supervisor
sets `last_started_for_epoch = Some(N+1)` and will only fire again
when `next_epoch != N+1`. But the predicate is "current anchor +
1 != N+1". As soon as the chain enters epoch N+1, `next_epoch` becomes
N+2, and a tick can fire `StartDkls(N+2)` *even if the ceremony for
N+1 never completed* (e.g. peers couldn't agree on a session_id per
F004's build_driver race, or shares were lost). The supervisor has
no notion of "did the previous ceremony finalize?". Concurrency of
two open ceremonies is also possible if the actor's StartDkls
handler doesn't refuse one when another is active.

### Issue 1 + Issue 2 cross-pollinate

A node that experiences the supervisor's epoch-skip (Issue 2) will
not have a share for epoch N. The scheduler's `refresh_proposer_context_loop`
will, however, happily install the new active set for epoch N (via
`client.active_validators(epoch, true)`). The scheduler then thinks
the local node is a proposer and produces blocks under Issue 1's
race — but the signing step inside the actor finds no installed
DKLS share for epoch N and no-ops, dropping the block. From the
node's outside, this looks like an unresponsive validator and may
trigger auto-deregister.

## Impact

- **Liveness loss on every refresh tick that lands between scheduler's
  two reads** (Issue 1): the local node produces blocks with metadata
  that other peers reject as proposer-mismatched. Frequency scales
  with the ratio of `refresh_interval` to `block_time`. In typical
  configurations these are both seconds, so the collision window is
  not vanishingly small.
- **Identity confusion** (Issue 1, key-rotation variant): a block
  may be emitted under the wrong `local_key`/validator-identity if
  the operator rotates the key between the scheduler's two reads.
- **Permanent epoch-1 stall on anchor jumps** (Issue 2): once an
  epoch's DKG window is missed, there is no in-supervisor recovery.
  The chain transitions into that epoch with no signing group;
  block production halts. Manual operator action (or supervisor
  restart with a stale `latest_anchor` that backs into the lead
  window) is required to recover. In a coordinated post-network-partition
  rejoin, every supervisor that was partitioned can hit this together.
- **Compounded with F004's stale resolver**: the actor's
  `current_epoch()` is frozen post-cutover (F004 Issue 1), so any
  per-epoch DKG gate that uses `current_epoch` to decide which
  epoch's share to install is silently misaligned across the
  validator cohort even when the supervisor *does* fire.

## Evidence

- `code/hypersnap/src/hyper/scheduler.rs:135-148` — `should_propose`
  takes and drops the `proposer_ctx` lock.
- `code/hypersnap/src/hyper/scheduler.rs:157-187` — `run` invokes
  `should_propose` (lock acquisition 1), then re-locks (acquisition 2)
  to read the anchor metadata. The in-source comment claims the two
  reads happen under "the same lock" — they do not.
- `code/hypersnap/src/hyper/scheduler.rs:217-248` —
  `refresh_proposer_context_loop` writes all five fields under a
  single critical section, which is exactly what makes Issue 1 a
  silent bug: the refresh tick can rewrite the entire `ProposerContext`
  atomically between scheduler's two reads.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:68-104` — `last_started_for_epoch`
  is updated only when the lead-window fires; no catch-up for
  skipped epochs, no inspection of whether the previous ceremony
  completed.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:64-66` —
  `MissedTickBehavior::Delay` means the supervisor will not fire
  one tick per missed interval after being suspended; combined with
  the lead-window predicate it confirms Issue 2.
- `code/hypersnap/src/hyper/epoch.rs:14, 22-24` — `EPOCH_LENGTH =
  432_000`, `epoch_for(x) = x / EPOCH_LENGTH`. With production
  `start_lead_blocks` ≈ 10% of `EPOCH_LENGTH`, any anchor jump >
  43,200 blocks (~half a day at 1s blocks) skips the window.

## Suggested remediation

1. **Hold the `proposer_ctx` lock across the whole produce path.**
   Replace the current shape with a single critical section:
   ```rust
   let (should, anchor_block, anchor_hash, anchor_ts) = {
       let ctx = self.proposer_ctx.lock().await;
       let should = ctx.anchor_block_hash.is_empty()
           || ctx.validators.is_empty()
           || ctx.local_key.is_empty()
           || is_proposer(&ctx.local_key, &ctx.validators, &ctx.anchor_block_hash, next, 0);
       (
           should,
           ctx.anchor_block,
           ctx.anchor_block_hash.clone(),
           ctx.anchor_block_timestamp,
       )
   };
   if !should { continue; }
   ```
   so the gating decision and the anchor metadata embedded in the
   produced block come from the same snapshot. This also fixes the
   misleading in-source comment.
2. **Or pass the `ProposerContext` snapshot to a free function**
   that returns `Option<HyperActorEvent>`; this makes the
   single-snapshot invariant explicit at the type level.
3. **Catch up skipped epochs in the supervisor.** Change the
   predicate to fire StartDkls for every epoch from
   `last_started_for_epoch + 1` (or, on cold start, the
   highest-installed share's epoch + 1) up through `next_epoch`,
   not just the current `next_epoch`. Build a driver per missed
   epoch, queue them through the actor in order.
4. **Refuse to start StartDkls(N+2) while N+1 is unfinished.**
   Either query the actor for "did the ceremony for epoch K
   complete" before issuing `StartDkls(K+1)`, or persist the
   completed-epoch high-water mark next to `last_started_for_epoch`.
5. **Persist `last_started_for_epoch`** to KV (already noted in
   F004's remediation), which simultaneously lets the supervisor
   detect on restart that it has already fired StartDkls for some
   N but the ceremony never completed — and trigger a re-fire if
   the actor reports no installed share at N.
6. **Add an integration test** that simulates an anchor jump of
   `2 * EPOCH_LENGTH` and asserts the supervisor fires
   `StartDkls` for every intervening epoch, not just the latest.
7. **Add a property test** for the scheduler's `run` loop that
   races a `refresh_proposer_context_loop` task and asserts the
   anchor_hash embedded in produced blocks matches the anchor_hash
   that was used to gate proposer selection.
