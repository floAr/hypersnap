---
id: F023
task: H023
specialist: node-lifecycle-actor
attack_class: mailbox-ordering-assumption
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  sub_verdicts:
    a_drop_on_early_arrival: WATERPROOF
    b_sign_aad_no_digest: HAS_CAVEATS
    c_unconditional_overwrite: WATERPROOF
  notes: |
    Sub-claim (b)'s integrity-attack framing (Phase-4 produces a
    signature that fails verification) is rescued by the DKLS23
    protocol's sign_id-mixed mul_sid/zero_sid, which aborts on
    contaminated phase-2 advance. Liveness impact remains real.
    Remediation #2 (bind digest into sign AAD) is still required for
    liveness. Sub-claims (a) and (c) are clean. Detail in
    findings/notes/F023-validation.md.
---

# F023: DKLS round messages dropped on early arrival, and cross-routed across digests at the same epoch

## Summary

`HyperActor::dispatch` for `InboundDkls` and `InboundDklsSign` assumes that
the matching `StartDkls` / start-of-sign event is always processed by the
local actor **before** any peer's round message for that ceremony lands in
the actor mailbox. The handlers do not buffer pre-`StartDkls` messages —
they unconditionally return `HyperActorError::NoActiveDkg(epoch)` and
discard the frame.

In addition, `InboundDklsSign` routes purely by `epoch`, while the wire
codec's AAD only binds `(epoch, ROUND_TAG_SIGN, sender, receiver)` —
**not the digest**. The actor holds at most one
`active_dkls_sign: DklsSignDriver` at a time, and that driver is bound
to a single `(epoch, digest, committee)`. Different validators can have
different ceremonies active at the same epoch (block production vs.
reward issuance vs. lock-root vs. inbound-burn vs. DA-seed) because the
queue order in `pending_sign_queue` is driven by the per-peer order in
which `ProduceBlockDkls`, `EvaluateEpochDkls`, and `maybe_sign_da_epoch_seed`
fire — none of which are globally synchronised. When peer A broadcasts
a Phase-1 sign message for digest `D_A`, peer B with `D_B != D_A`
active for the same epoch will successfully decrypt the frame and
`submit` it into the **wrong** `DklsSignCoordinator`, corrupting its
accumulator with messages signed against an unrelated digest.

Finally, both `HyperActorEvent::StartDkls` and the
`start_dkls_block_production` path unconditionally overwrite
`self.active_dkls_sign` (line 2352) and `self.active_dkls` (line 1273),
which silently dropping any in-flight ceremony if the supervisor /
scheduler decides to start a new one — another order-assumption.

The transport (libp2p gossipsub) **does not preserve order between
publishers**: mesh propagation, IHAVE/IWANT pull, and the mempool can
re-order messages relative to actor-internal events (which arrive on the
local mpsc bound at `inbound_capacity`). The actor's "we'll have an
`active_dkls` by the time peer round messages land" invariant is
silently broken by anything that delays the local supervisor (anchor
poller lag, lock contention on `inputs.latest_anchor`, GC tick), or by
peers that fire their supervisor a few ticks earlier (clock skew,
faster polling cadence).

## Description

### 1. The drop-on-early-arrival pattern

`code/hypersnap/src/hyper/actor.rs:1237-1268` — `InboundDkls`:

```rust
HyperActorEvent::InboundDkls { target_epoch, encoded } => {
    let dkls = self
        .active_dkls
        .as_mut()
        .filter(|d| d.driver.target_epoch() == target_epoch)
        .ok_or(HyperActorError::NoActiveDkg(target_epoch))?;
    let local_party = dkls.driver.party_index();
    let opened = crate::hyper::dkls_wire_codec::open_dkls_round_message(
        &encoded,
        target_epoch,
        &self.runtime.local_transport_secret,
        local_party,
    )
    .map_err(|e| HyperActorError::DklsCodec(e.to_string()))?;
    ...
}
```

If `self.active_dkls` is `None`, or its `target_epoch()` doesn't match
the arriving frame, the message is discarded with `NoActiveDkg`. No
buffer, no replay, no later retry. The same shape appears at
`actor.rs:1296-1317` for `InboundDklsSign`.

### 2. There is no in-process synchronisation between `StartDkls` and gossiped peer messages

`dkls_supervisor.rs:70-110` (per-peer local clock) decides when to fire
`StartDkls` for the local actor:

```rust
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
                ... inbound.send(StartDkls { driver: Box::new(driver) }) ...
            }
            ...
        }
    }
    ...
}
```

Each validator independently reads its own `latest_anchor` mutex and
fires `StartDkls` when it crosses the lead-blocks threshold. Two
validators can fire `StartDkls` for the same `next_epoch` at different
wall-clock times — even seconds apart — depending on:

- `tick_interval` (default 1s per `main.rs` anchor poller).
- Lock-contention on `latest_anchor`.
- Block-import latency between when peer A imported a block reaching
  the lead threshold and when peer B did.
- `build_driver` itself waits for `client.active_validators(target_epoch,
  true)` (line 132) — an `.await` on the actor's mailbox.

Once peer A's supervisor fires `StartDkls`, the driver immediately
emits Phase-1 fragments via `flush_dkls_outbound` (actor.rs:1272) and
broadcasts them on `hyper/dkg/v1`. Peer B receives that gossip frame
and decodes it to `HyperActorEvent::InboundDkls`. If peer B's
supervisor hasn't yet ticked — entirely plausible at 1s tick interval
— peer B's `self.active_dkls` is still `None`. The Phase-1 fragments
are lost. Peer B's eventual `StartDkls` won't see them, and DKLS23's
phase-1-to-phase-2 transition needs **all** `share_count` poly
fragments (`dkls_ceremony.rs:417-420` — `if self.poly_fragments.len()
< needed { return Ok(false); }`).

Peer B can never advance unless peer A re-broadcasts. Gossipsub does
not automatically replay on join; once a message has been propagated
its retention is bounded by `history_length`. The ceremony stalls
silently for that epoch.

### 3. Same drop-pattern on `InboundDklsSign`, made worse by digest non-binding

`actor.rs:1296-1317`:

```rust
HyperActorEvent::InboundDklsSign { epoch, encoded } => {
    let driver = self
        .active_dkls_sign
        .as_mut()
        .filter(|d| d.epoch() == epoch)
        .ok_or(HyperActorError::NoActiveDkg(epoch))?;
    let local_party = driver.party_index();
    let opened = crate::hyper::dkls_wire_codec::open_dkls_sign_round_message(
        &encoded,
        epoch,
        &self.runtime.local_transport_secret,
        local_party,
    )
    .map_err(|e| HyperActorError::DklsCodec(e.to_string()))?;
    ...
    driver.submit(message)?;
    Ok(())
}
```

The filter checks `epoch()` only. Each validator can have up to **five**
concurrent in-flight signing ceremonies at the same epoch:

1. `ProduceBlockDkls` for a hyperblock — `start_dkls_block_production`,
   actor.rs:2270-2354. Digest = `keccak256(signing_payload(epoch))` of
   the block envelope.
2. `EvaluateEpochDkls` reward issuances — `start_dkls_scoring_multi_party`,
   actor.rs:2620-2710. Digest = `keccak256(issuance_signing_payload(iss))`.
3. `EvaluateEpochDkls` trust-snapshot — same path. Digest =
   `keccak256(trust_snapshot_signing_payload(snap))`.
4. `start_dkls_lock_root_multi_party` — actor.rs:2852-2910. Digest =
   `keccak256(merkle_root_update_signing_payload(block_number, root))`.
5. `start_dkls_inbound_burns_multi_party` — actor.rs:2775-2841.
   Digest per observed burn.
6. `maybe_sign_da_epoch_seed` — actor.rs:2045, enqueues a DA-seed task.

All five (or more) share `pending_sign_queue` and the single
`active_dkls_sign` slot.

The wire codec's AAD (`dkls_wire_codec.rs:177`) is
`build_aad(epoch, ROUND_TAG_SIGN, sender, receiver)` — no digest
component. So a peer's Phase-1 sign frame decrypts cleanly under
**any** active sign driver at the matching epoch, regardless of
which digest the driver is locally signing.

Concrete corruption scenario across two honest validators on the same
committee for both digests:

- Peer A's queue order: `[DA_seed_digest, block_prod_digest]`. A's
  `active_dkls_sign` = DA_seed ceremony.
- Peer B's queue order: `[block_prod_digest, DA_seed_digest]` (because
  B saw `ProduceBlockDkls` before the anchor-block-driven
  `maybe_sign_da_epoch_seed`). B's `active_dkls_sign` = block_prod
  ceremony.
- A broadcasts Phase-1 sign messages for digest `DA_seed_digest`.
- B's actor receives them on `hyper/dkg/v1` → decodes → routes via the
  filter-by-epoch — installs DA-seed Phase-1 frames into the
  block-prod coordinator.
- B's block-prod coordinator now has a Phase-1 message addressed to
  the wrong digest. Either DKLS23 detects the mismatch and aborts
  (best case — `submit` returns an error, but the actor only `?`s it
  back as `HyperActorError::DklsSign` and the driver remains in a
  corrupt state for the rest of the ceremony), or the protocol's
  zero-share / mul-share accumulators absorb the foreign material and
  Phase-4 produces a signature that fails on-chain verification.

### 4. The committee-selection invariant is queue-order-blind

`dkls_committee::select_signing_committee(epoch, digest, share_count,
threshold)` is deterministic per `(epoch, digest)`. So if peers A and
B are both on the committee for both digests, they agree on **set
membership** for each ceremony — but they don't agree on **which
ceremony is currently the active_dkls_sign**. That second piece is
purely local queue order. The protocol has no broadcast "I'm now
signing digest D" announcement that peers consult before submitting
round messages.

Three actor-level enqueue paths feed `pending_sign_queue`:

- `start_dkls_block_production` (actor.rs:2352) — synchronous to
  `ProduceBlockDkls` (driven by the local scheduler).
- `EvaluateEpochDkls` (actor.rs:2700-2708 scoring, 2832-2839 burns,
  2903-2907 lock-root) — driven by the local actor's epoch-transition
  detection.
- `maybe_sign_da_epoch_seed` (actor.rs:2045 → enqueues via
  `start_dkls_da_epoch_seed_multi_party`) — driven by the local
  actor's anchor-block observation.

None of these arrive in the same order at every validator — the
scheduler ticks, gossip mempool, and anchor poller fire independently
per peer. The queue-head digest (i.e. what's currently active) thus
diverges across the cohort.

### 5. `active_dkls` / `active_dkls_sign` overwrite paths

`actor.rs:1269-1275` (`StartDkls`):

```rust
HyperActorEvent::StartDkls { driver } => {
    let mut driver = *driver;
    driver.start()?;
    self.flush_dkls_outbound(&mut driver).await;
    self.active_dkls = Some(ActiveDkls { driver });
    Ok(())
}
```

No guard against `self.active_dkls.is_some()`. If the supervisor
re-fires `StartDkls` for the same epoch (legitimate, after a restart
with no persistent fence — see F004) or for a different epoch (the
supervisor's `last_started_for_epoch` is per-process-lifetime, so a
restart causes it), the prior in-flight ceremony is dropped on the
floor along with its accumulator state.

`actor.rs:2352` (`start_dkls_block_production`, end of fn):

```rust
self.active_dkls_sign = Some(driver);
```

Same — no guard. If `ProduceBlockDkls` fires while
`EvaluateEpochDkls`'s queue has just installed a multi-party scoring
driver, the scoring driver is silently overwritten and the
corresponding entry in `pending_dkls_messages` is orphaned — the
signature will never come back, the queue won't pop because
`active_dkls_sign.is_some()` after the overwrite, and any peer's
`Broadcast` finalized signature for that orphaned digest hits
`DklsSignFinalized` with no pending entry (actor.rs:2511-2520) — the
remediation message is sent on the outbound channel but the actor's
local state never `apply_*`s the reward / snapshot.

### 6. `InboundEvidence` has a parallel ordering assumption

`actor.rs:1344-1382`:

```rust
HyperActorEvent::InboundEvidence { block_a, block_b } => {
    let evidence = detect_conflicting_blocks(&block_a, &block_b)?;
    ...
    let group_address = self
        .runtime
        .dkls_group_address_for_epoch(evidence.epoch)
        .ok_or(EvidenceError::UnknownEpochGroupKey { epoch: evidence.epoch })?;
    verify_evidence_signatures(&evidence, &group_address)?;
    ...
}
```

Assumes the local node has finalized DKG for `evidence.epoch` before
ever seeing evidence for blocks signed at that epoch. If gossipsub
relays an evidence frame to a validator that joined the network
late, the local `dkls_group_address_for_epoch(epoch)` may be `None`
for that epoch (DKG ran before this node joined). The evidence is
discarded — the same evidence won't be re-broadcast unless another
peer happens to re-publish.

This isn't itself a buffering issue (slashing evidence is gossiped
on `hyper/evidence/v1` so other peers do hold copies), but combined
with the F004 stale-epoch issue and the per-process
`recent_evidence` LRU (actor.rs:971), it produces a class of "this
slashing evidence is silently lost in a quorum of partially-joined
validators" cases.

### 7. The `gossip_adapter` layer is order-blind too

`gossip_adapter::wire_to_event` (gossip_adapter.rs:56-90) does pure
translation — wire bytes in, `HyperActorEvent` out, FIFO into the
single mpsc. Multi-producer / multi-topic gossipsub does NOT preserve
cross-topic order. So the gossip layer can deliver
`hyper/dkg/v1::Phase1Fragment` for `target_epoch=N` to the actor
mpsc **before** the local supervisor's `StartDkls { target_epoch: N }`
even gets enqueued. The actor processes events strictly in mpsc
order — there's no priority queue or "system events first" lane.

## Impact

- **DKG ceremony non-completion**: Late-joining or slow-clock validators
  drop pre-`StartDkls` Phase-1 fragments and stall the entire epoch
  N+1 ceremony for the whole cohort (DKLS phase-1-to-2 needs all
  `share_count` fragments, per `dkls_ceremony.rs:417-420`). Liveness
  failure at every epoch boundary where the cohort isn't perfectly
  clock-aligned. Next epoch has no signing group → no block
  threshold-signatures → chain halt.
- **Sign-ceremony cross-routing produces invalid threshold signatures
  or aborts**: when peer A's sign Phase-1 lands in peer B's
  sign-coordinator for a different digest, B's coordinator either
  (a) detects the mismatch on a later phase and aborts, leaving B
  unable to participate in *either* ceremony for that epoch, or
  (b) absorbs the foreign material and produces a Phase-4 signature
  that fails verification on import / on-chain. Either way: signing
  liveness failure on every multi-output epoch boundary at multi-party
  parameters. (Single-party 1-of-1 path is immune — the local
  coordinator self-routes and never accepts a foreign frame.)
- **Silent ceremony loss via active-slot overwrite**: `StartDkls` and
  `start_dkls_block_production` blindly overwrite `active_dkls`/
  `active_dkls_sign`. A reward-issuance ceremony in flight when
  `ProduceBlockDkls` fires is orphaned; the unsigned message in
  `pending_dkls_messages` stays there until process restart, and the
  next epoch's reward-payout never gets the corresponding `apply_*`
  call. Operator can't tell — the orphan is in-memory only.
- **Slashing evidence silently dropped on join**: a validator that
  comes up after epoch N's DKG can't verify evidence frames for
  epoch N blocks (group address missing). Evidence isn't replayed
  by peers on-demand, so the validator never persists the evidence
  and never participates in the next-boundary eviction.

## Evidence

- `code/hypersnap/src/hyper/actor.rs:1237-1268` — `InboundDkls` drops
  on `NoActiveDkg(target_epoch)` if `self.active_dkls` is None or
  mismatched.
- `code/hypersnap/src/hyper/actor.rs:1296-1317` — `InboundDklsSign`
  drops on `NoActiveDkg(epoch)` and filters purely by epoch.
- `code/hypersnap/src/hyper/actor.rs:1269-1275` — `StartDkls`
  unconditionally writes `active_dkls`, clobbering any prior driver.
- `code/hypersnap/src/hyper/actor.rs:2352` —
  `start_dkls_block_production` unconditionally writes
  `active_dkls_sign`, clobbering any in-flight multi-party scoring
  / lock-root / inbound-burn / DA-seed ceremony.
- `code/hypersnap/src/hyper/actor.rs:2700-2708, 2832-2839, 2903-2907,
  2971-2976` — four independent enqueue sites for
  `pending_sign_queue` whose head order is locally determined.
- `code/hypersnap/src/hyper/dkls_wire_codec.rs:177` — sign AAD =
  `build_aad(epoch, ROUND_TAG_SIGN, sender, receiver)`. Digest is
  not bound.
- `code/hypersnap/src/hyper/dkls_wire_codec.rs:230` — DKG AAD =
  `build_aad(epoch, ROUND_TAG_DKG, sender, receiver)`. Same digest
  non-binding (DKG only has one ceremony per epoch so this is
  benign for DKG — but is fatal for sign).
- `code/hypersnap/src/hyper/dkls_ceremony.rs:417-420` — phase-1 to
  phase-23 transition needs **all** `share_count` poly fragments.
  Missing one stalls the whole cohort.
- `code/hypersnap/src/hyper/dkls_supervisor.rs:70-110` — per-peer
  supervisor loop with no cross-peer coordination on when
  `StartDkls` fires.
- `code/hypersnap/src/hyper/gossip_adapter.rs:56-90` —
  `wire_to_event` does pure translation; no priority lane for
  ceremony bootstrap.
- `code/hypersnap/src/hyper/actor.rs:1110-1117` — single FIFO
  `inbound.recv` loop; events are strictly serialized in arrival
  order with no per-class priority.
- `code/hypersnap/src/hyper/actor.rs:1344-1382` — `InboundEvidence`
  fails on `dkls_group_address_for_epoch` absent.

## Suggested remediation

1. **Buffer DKLS round messages that arrive before the local
   `StartDkls`/`start_dkls_block_production`.** Add a
   `BTreeMap<u64, Vec<RawDklsFrame>>` keyed by `target_epoch` that
   `InboundDkls`/`InboundDklsSign` push into when no matching driver
   is active. On `StartDkls` install, drain the buffer for that
   epoch through the new driver's `submit`. Cap the buffer per-epoch
   (e.g. `share_count * 16` frames) to avoid OOM from a malicious
   peer sending unbounded junk for a never-occurring epoch.

2. **Bind the digest into the sign AAD.** Change
   `dkls_wire_codec::seal_dkls_sign_round_message` and
   `open_dkls_sign_round_message` to include `digest` in the
   `build_aad` call. The wire envelope (`HyperWireDkg.encoded`)
   should carry the digest in the discriminator prefix so receivers
   can route to the correct in-flight ceremony **before** AEAD
   decryption. Migrate the round-tag enum to carry the digest as
   well (or add a third tag for "sign with digest D").

3. **Carry the digest into the actor event variant** so dispatch
   can route correctly. Today: `InboundDklsSign { epoch, encoded }`
   — change to `InboundDklsSign { epoch, digest, encoded }`. Filter
   `active_dkls_sign` on both `epoch()` and the active driver's
   `coordinator.digest()`. On mismatch, buffer into a per-`(epoch,
   digest)` queue and drain when the matching driver is installed.

4. **Guard the active-slot overwrite paths.** `StartDkls` and
   `start_dkls_block_production` must check whether
   `self.active_dkls_sign.is_some()` and, if so, push the new driver
   into `pending_sign_queue` (or queue the build-driver inputs)
   instead of clobbering. Symmetric guard on `StartDkls` for
   `self.active_dkls`.

5. **Replay evidence for missing-group-key epochs.** When
   `dkls_group_address_for_epoch(evidence.epoch)` is None, persist
   the evidence frame to a small pending-store keyed by epoch;
   re-process when the corresponding `install_local_dkls_share`
   call lands. Alternatively, request the group address via a
   bootstrap-sync RPC.

6. **Add a regression test** that simulates the gossipsub-reorder
   case: spawn two `HyperActor`s, fire `StartDkls` for actor A
   slightly before actor B, harvest A's outbound DKLS messages
   via the `outbound` channel and feed them into B's
   `HyperActorEvent::InboundDkls` BEFORE sending B its own
   `StartDkls`. Assert B's ceremony still completes.

7. **Add a regression test** for the cross-digest case: install
   two PendingDklsMessages with different digests in a single
   actor at the same epoch, start one as `active_dkls_sign`, then
   feed an opened Phase-1 sign frame for the *other* digest. Assert
   the actor either buffers it under that digest or rejects it
   with a typed error — NOT `coordinator.submit(...)` succeeds
   into the wrong driver.
