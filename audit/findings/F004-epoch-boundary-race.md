---
id: F004
task: H004
specialist: consensus-malachite-tendermint
attack_class: epoch-boundary-race
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F004: Epoch resolver never advances post-cutover, with several downstream races

## Summary

The runtime's `EpochResolver` is only updated inside `apply_cutover()`. Once
the chain is past the cutover snapchain block, no code path inside the actor,
runtime, scheduler, or supervisor calls `epoch_resolver.observe_anchor()`
again. `HyperRuntime::current_epoch()` is therefore frozen for the lifetime
of the node, and every consumer that reads it — including the scheduler's
proposer-gating refresh loop and any state mutation that snapshots the
"current epoch" — operates with stale data after the first epoch boundary.

Compounding this, the DKLS supervisor derives `next_epoch` from a separate
`Arc<Mutex<u64>>` snapchain anchor that the operator polls into shared
state, while the scheduler derives the proposer-gating epoch from the
actor's `current_epoch()` API. The two sources can diverge by entire
epochs, producing classic boundary races: the supervisor builds DKG
ceremonies and downstream consumers (proposer gate, reward distribution,
unstake queue drain, slashed-validator eviction) all read inconsistent
"what epoch are we in" views at the cutover instant.

Also, the cutover itself sets the resolver to `epoch_for(cutover_block) =
cutover_block / EPOCH_LENGTH`, which is generally NOT zero, while it
installs the only DKLS group address at epoch `0`. The "epoch 0 begins at
cutover" comment is inconsistent with the arithmetic, breaking the
signature verification of the very first post-cutover block on any
mainnet-shaped cutover height.

## Description

### Stale runtime epoch

`epoch_resolver.observe_anchor(snapchain_block)` is called in exactly one
non-test location: `HyperRuntime::apply_cutover`
(`code/hypersnap/src/hyper/runtime.rs:4018`). Grep over the entire crate
confirms there are no other callers. In particular, the actor's
`InboundBlock` handler

```rust
HyperActorEvent::InboundBlock { block, locks, transfers } => {
    let anchor_block = block.envelope.metadata.snapchain_anchor_block;
    let anchor_ts    = block.envelope.metadata.snapchain_anchor_timestamp;
    self.runtime.import_block(&block, &locks, &transfers)?;
    self.metric_count("hyper.blocks.imported", 1);
    self.maybe_trigger_scoring(anchor_block, anchor_ts).await;
    ...
}
```
(`code/hypersnap/src/hyper/actor.rs:1157-1172`)

does NOT inform the resolver about the new anchor block. `import_block`
itself (`runtime.rs:4120`) also does not touch `epoch_resolver`. The net
effect is that `HyperRuntime::current_epoch()`
(`code/hypersnap/src/hyper/runtime.rs:3895`) returns the epoch of the
cutover snapchain block forever.

Downstream consumers that quietly inherit the stale epoch:

- `unstake` and `restake_unstaked` compute `maturation_epoch =
  current_epoch + UNSTAKING_PERIOD_EPOCHS` (`runtime.rs:1755-1758`). After
  the first natural epoch boundary, every new unstake matures
  `EPOCH_LENGTH` blocks too early.
- `RewardIssuance` and the scoring auto-trigger path read
  `self.epoch_resolver.current_epoch()` at several sites (`runtime.rs:2028,
  2210, 2742, 3067, 3630`). Rewards calculated during epoch N+1 attribute
  themselves to epoch N's active set.
- The scheduler's refresh loop calls `client.current_epoch()` followed by
  `client.active_validators(epoch, true)` (`scheduler.rs:231-238`). Because
  `current_epoch()` is frozen, the proposer-gating active set is also
  frozen, and new validators that registered/were-slashed at the boundary
  are not honored.

### Cutover/genesis-epoch arithmetic mismatch

```rust
// Install the genesis epoch's DKLS23 group address. Anchored
// at the cutover snapchain block so the epoch resolver knows
// where epoch 0 begins.
self.install_dkls_group_address(0, genesis_group_address);
self.epoch_resolver.observe_anchor(snapchain_block);
```
(`runtime.rs:4014-4018`)

`EpochManager::observe_anchor` computes `epoch_for(snapchain_block) =
snapchain_block / EPOCH_LENGTH`. There is no offset/zero-point handling.
For any cutover block above `EPOCH_LENGTH = 432_000` — the realistic
mainnet case — the resolver immediately reports a `current_epoch >= 1`,
yet the *only* installed DKLS group sits at epoch `0`. The first locally
produced block goes through `produce_unsigned_block_dkls`
(`runtime.rs:4459-4464`) which pulls the highest-installed epoch — still
0 because the supervisor hasn't fired StartDkls yet. The block is signed
under epoch 0; verification on import succeeds (because the verifier
also looks up by `signature.epoch`), but any policy that reads
`current_epoch()` — slashing eviction, reward attribution, scoring
trigger — disagrees about what the "current" epoch is.

### Two desynchronized anchors driving epoch-boundary decisions

`main.rs:1472-1480` creates *two* mutexes:

```rust
let scheduler_anchor:  Arc<Mutex<LatestAnchor>> = Arc::new(Mutex::new(LatestAnchor::default()));
let supervisor_anchor: Arc<Mutex<u64>>          = Arc::new(Mutex::new(0));
spawn_anchor_poller(client.clone(), scheduler_anchor.clone(),
                    supervisor_anchor.clone(), Duration::from_secs(1));
```

and `spawn_anchor_poller` writes them with two separate `lock().await`
acquires:

```rust
*scheduler_anchor.lock().await = snapshot;
*supervisor_anchor.lock().await = meta.snapchain_anchor_block;
```
(`main.rs:1566-1567`).

Between those two writes the DKLS supervisor (running on its own ticker,
default 1s) or the scheduler can re-read just one of them. Worse, the
DKLS supervisor — not the runtime, not the resolver — owns the
authoritative "next epoch" decision:

```rust
let anchor = *inputs.latest_anchor.lock().await;
let current_epoch = epoch_for(anchor);
let next_epoch    = current_epoch + 1;
...
match build_driver(&inputs, &client, next_epoch).await { ... }
```
(`dkls_supervisor.rs:73-82`).

The supervisor's `current_epoch` is computed from its private anchor,
NOT from `client.current_epoch()`. So in steady state the supervisor's
view of "what epoch are we in" can be N+1 while the runtime says N.
Reward calculations, proposer gating, and DKG share installation all
race on this disagreement.

### `build_driver` reads anchor twice

```rust
async fn build_driver(...) -> Result<DklsDriver, BuildError> {
    let active = client.active_validators(target_epoch, true).await... // (A)
    ...
    let session_id = canonical_session_id(target_epoch, &parameters);
    let coordinator = DklsCeremonyCoordinator::new(target_epoch, parameters,
                                                    own_idx, session_id)...;
    let anchor_at_install = *inputs.latest_anchor.lock().await;       // (B)
    Ok(DklsDriver::new(coordinator, anchor_at_install))
}
```
(`dkls_supervisor.rs:131-167`)

`active_validators(target_epoch, true)` resolves to
`active_validators_enforced(epoch)` which calls
`validator_registry.compute_active_set(epoch, bootstrap)` plus auto-deregister
+ slashing filters (`actor.rs:1464`, `runtime.rs:3759-3789`). The active
set at `target_epoch = current_epoch + 1` depends on the registry's
view of registration/deregistration events *up to* `target_epoch - 1`.
Between (A) and (B) the anchor poller can install a new
`InboundBlock` that contains a `HyperValidatorEvent`, mutating the registry
view. The set computed in (A) is then *stale* relative to the anchor
(B) the driver is bound to — and the ceremony coordinator's
`session_id`, derived solely from `(target_epoch, threshold,
share_count)`, captures a `share_count` (set size) that other
participants may not agree on if they observe the event before/after.
Different participants then derive different `session_id`s and the
ceremony cannot converge.

### Supervisor restart re-fires StartDkls

`last_started_for_epoch: Option<u64>` (`dkls_supervisor.rs:68`) lives in
the run-loop's local stack. On any supervisor restart (operator crash,
panic, deliberate redeploy) inside the `start_lead_blocks` window, the
supervisor will re-issue `StartDkls` for the same `next_epoch`. The
actor's `StartDkls` handler is expected to be idempotent against this,
but there is no fence in the supervisor itself, and no persistent
"last-started" record — if a future change makes `StartDkls` non-idempotent
(or rotates session_id derivation), this loses the safety property silently.

### Scheduler proposer-context update vs DKG completion

`refresh_proposer_context_loop` (`scheduler.rs:217-248`) overwrites the
proposer context's `validators` field whenever it ticks. The fetched
active set is for `client.current_epoch()` — which, per the first issue,
is frozen. Even if the runtime *did* observe new anchors, the gap between
`current_epoch()` returning N (line 231) and `active_validators(N, true)`
returning at line 235 spans an `.await` boundary on the actor's mailbox;
a `HyperActorEvent::InboundBlock` carrying an epoch-N+1 anchor can land in
between, and the writer that finally writes the proposer context (line
241-247) commits a `validators` list and `anchor_block_*` that mix epochs
N and N+1. The scheduler then gates proposer selection on that mix at
line 141 (`is_proposer(local_key, validators, anchor_block_hash, ...)`).

## Impact

- **Reward attribution drift**: every epoch after cutover, retroactive
  vesting, scoring, and unstake maturation use the wrong epoch. Unstakes
  mature `EPOCH_LENGTH` snapchain-blocks earlier than the FIP intends
  (in the worst case, immediately, if the cutover epoch never changes).
- **Slashing eviction never applied**: `active_validators_enforced(epoch)`
  for a frozen `epoch = cutover_epoch` evicts only validators slashed
  *before* the cutover. Any post-cutover slashing evidence (also
  `current_epoch()`-tagged) is filed against the wrong epoch and never
  actually evicts at the next boundary.
- **Proposer gate uses wrong set**: validators that joined or left after
  the cutover are mis-classified for the proposer-selection rotation —
  either included when they should not be, or excluded when they should
  produce. Liveness suffers in the worst case (no validator believes
  itself the proposer); safety suffers in the other (multiple
  validators believe themselves the proposer for the same height).
- **DKG ceremony desync at boundary**: a `HyperValidatorEvent` imported
  between the supervisor's `active_validators(target_epoch)` query and
  the ceremony's `DklsDriver` install changes `share_count` for some
  participants but not others. The resulting `canonical_session_id` no
  longer agrees across the cohort and the ceremony stalls — meaning the
  next epoch has no signing group.
- **First post-cutover block can't sign at high cutover heights**: if
  `cutover_snapchain_block >= EPOCH_LENGTH`, `current_epoch()` reports
  a non-zero epoch immediately, but the only DKLS group is installed
  at epoch 0. Any code that produces a block keyed on `current_epoch()`
  rather than the highest-installed share fails. The current
  `produce_unsigned_block_dkls` happens to use highest-installed
  (`next_back()`), so blocks still produce, but other consumers using
  `current_epoch()` to decide signature-verifier lookups (e.g. any
  future verifier that consults the resolver) would fail.

## Evidence

- `code/hypersnap/src/hyper/epoch_resolver.rs:24-26` — sole non-test
  caller of `EpochResolver::observe_anchor`; only the cutover path
  invokes it via `runtime.rs:4018`.
- `code/hypersnap/src/hyper/runtime.rs:4014-4018` — cutover installs DKLS
  group at epoch 0 but seeds the resolver with `snapchain_block` whose
  `epoch_for` value is generally non-zero.
- `code/hypersnap/src/hyper/runtime.rs:3895-3897` — `current_epoch()`
  returns the frozen resolver value; called from `runtime.rs:1755-1758,
  2028, 2210, 2742, 3067, 3630`.
- `code/hypersnap/src/hyper/actor.rs:1157-1172` — `InboundBlock` handler
  imports the block and triggers scoring on `anchor_block`, but never
  calls `epoch_resolver.observe_anchor`.
- `code/hypersnap/src/hyper/scheduler.rs:217-248` — proposer-context
  refresh reads `current_epoch()` (stale) then `active_validators`,
  with a re-acquire `await` in between, and writes the context
  non-atomically.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:70-110` — supervisor's
  run-loop computes `next_epoch` from its private anchor, ignoring the
  runtime's epoch view; `last_started_for_epoch` is stack-local with
  no persistent fence.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:131-167` —
  `active_validators(target_epoch, true)` read at L132 and
  `*latest_anchor.lock().await` read at L166 are separated by `.await`
  points; can observe inconsistent registry+anchor pairs.
- `code/hypersnap/src/main.rs:1472-1480, 1561-1567` — two anchor
  mutexes written non-atomically by the same poller; consumed by two
  different epoch-decision sites.

## Suggested remediation

1. **Drive `epoch_resolver.observe_anchor` from `InboundBlock`**. The actor
   already extracts `anchor_block` at `actor.rs:1162`; pass it through to
   `runtime.observe_anchor` (new method) immediately after
   `import_block` returns Ok. This is the single change that fixes the
   stale-epoch family of bugs at the source.
2. **Make the supervisor read `client.current_epoch()`, not its private
   anchor mutex**, for the `current_epoch / next_epoch` decision. Use the
   anchor only for the lead-blocks countdown. This removes one of the
   two desynchronized epoch sources.
3. **Take a single snapshot at the top of each supervisor tick**:
   ```
   let (anchor, current_epoch) = tokio::join!(
       async { *inputs.latest_anchor.lock().await },
       async { client.current_epoch().await }
   );
   ```
   and pass both into `build_driver` so the active-set query, the
   session-id derivation, and the driver-install anchor all agree.
4. **Persist `last_started_for_epoch`** to the operator's local KV (or
   look it up via the actor) so a supervisor restart inside the
   start-lead window cannot re-issue `StartDkls` for the same epoch.
5. **Fix the cutover/genesis-epoch arithmetic**: either install the
   genesis DKLS group at `epoch_for(cutover_snapchain_block)` instead of
   `0`, or offset the resolver so that `current_epoch()` returns `0` at
   the cutover. The comment "epoch 0 begins at cutover" should match
   reality. Add a unit test that constructs a runtime with
   `cutover_snapchain_block = 5 * EPOCH_LENGTH + 1` and asserts
   `current_epoch() == 0` immediately after `apply_cutover`.
6. **Fence the proposer-context write** under one lock, computing
   `(epoch, active_set, anchor)` in one critical section so they cannot
   span an epoch transition. Today three independent `.await`s in
   `refresh_proposer_context_loop` allow a transition to splice them.
7. **Eliminate the two-anchor design in `main.rs`**: collapse
   `scheduler_anchor` and `supervisor_anchor` into one
   `Arc<Mutex<LatestAnchor>>` and have the supervisor read the same
   struct. Atomically.
