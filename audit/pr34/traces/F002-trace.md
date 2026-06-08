# F002 trace — cross-epoch evidence slashes innocent single-epoch signers

Finding: F002 / F026 cross-epoch equivocation false-slash
Commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (HEAD == pinned)
Scope: entry-point→sink reachability only; verdict unchanged (HAS_CAVEATS).

## Entry point(s)

- Gossip wire ingress: `src/hyper/gossip_adapter.rs:96-102`
  (`wire_to_inbound`, `Body::Evidence` arm) — decodes a
  `HyperWireEvidence { block_a, block_b }` libp2p frame into
  `HyperActorEvent::InboundEvidence`. No sender authentication; the
  frame is whatever a gossip peer published on the evidence topic.
- Actor handler: `src/hyper/actor.rs:1587` (`InboundEvidence` arm of the
  event loop) — first code that acts on the decoded blocks.

## Trust boundary crossed

Untrusted libp2p gossip → node-local slashing state. Any gossip peer can
publish an evidence frame; the only validity gate on the path is
per-block threshold-signature verification
(`verify_evidence_signatures`), which by design passes for two genuinely
committee-signed blocks. There is NO authentication of the *submitter*
and NO gate requiring the two blocks to share an epoch or a signer set.

## Call path (ordered hops)

1. `src/hyper/gossip_adapter.rs:96-101` — `wire_to_inbound` — decodes the
   two protobuf blocks (`decode_hyper_block`) and emits
   `HyperActorEvent::InboundEvidence { block_a, block_b }`. Delivered to
   the actor over the same mpsc the gossip layer feeds.
2. `src/hyper/actor.rs:1588` — `InboundEvidence` handler —
   `detect_conflicting_blocks(&block_a, &block_b)?`.
3. `src/hyper/slashing.rs:52-77` — `detect_conflicting_blocks` — accepts
   the pair iff same `canonical_block_id` (line 58) and different block
   hash (line 64). Records `epoch_a = a.signature.epoch`,
   `epoch_b = b.signature.epoch` (lines 69-70). NO same-epoch /
   signer-overlap / canonical guard — cross-epoch pairs pass.
4. `src/hyper/actor.rs:1597-1601` — dedupe on
   `(min(epoch_a,epoch_b), lo_hash, hi_hash)`; non-replay continues.
5. `src/hyper/actor.rs:1605-1607` — `verify_evidence_signatures(&evidence,
   |epoch| self.runtime.dkls_group_address_for_epoch(epoch))`.
6. `src/hyper/slashing.rs:89-110` — `verify_evidence_signatures` — for
   each block resolves the group address for the block's OWN epoch
   (line 94-96) and verifies the threshold signature (line 102-108).
   Passes when each block is genuinely signed by its epoch's committee —
   the intended F026 behavior. This is the sole substantive guard.
7. `src/hyper/actor.rs:1608` — `self.runtime.record_evidence(&evidence)`.
8. `src/hyper/runtime.rs:4156-4161` — `record_evidence` →
   `slashing_store.record(evidence)`.
9. `src/hyper/slashing_store.rs:50-70` — `record` — persists the wire
   evidence (both blocks) keyed under epoch `min(epoch_a, epoch_b)`
   (cap_epoch, line 56; `make_key` at slashing_store.rs:53). Idempotent.
   Evidence now durable. (Ingress path ends; sink is consumed later.)

   --- epoch boundary (separate invocation) ---

10. `src/hyper/runtime.rs:4055-4076` — `get_active_validators_enforced(E)`
    — to compute the enforced active set for epoch `E` it computes
    `prev = E-1` and calls
    `slashed_validators_for_epoch(prev, &prev_active)` (line 4074-4075).
    Wired into proposer selection / DKLS resolution
    (runtime.rs:1217, 1247) per validation note H2/H7.
11. `src/hyper/runtime.rs:4191-4228` — `slashed_validators_for_epoch(prev)`
    — loads persisted evidence for `prev` (line 4197), then for EACH
    block of EACH evidence row (line 4202) resolves that block's
    `signer_indices` against `get_active_validators_enforced(block.epoch)`
    (line 4209-4211) and inserts ALL resolved validator keys into one
    `slashed` BTreeSet (line 4223). This is the **union** of the two
    blocks' signer sets — no intersection / equivocator predicate. SINK:
    an epoch-A-only signer (V) of `block_a` is inserted even though they
    never signed `block_b`.
12. `src/hyper/runtime.rs:4088-4104` — back in
    `get_active_validators_enforced`, `compute_active_set_with_filter`
    excludes any `vk` in `slashed` (line 4090) — V is evicted from the
    active set for `E` (lost participation/rewards).

## Cross-epoch recursion path (validator's H6 observation)

In the genuine `epoch_a != epoch_b` case the sink at hop 11 re-enters
itself before returning:

- `get_active_validators_enforced(6)` → `slashed_validators_for_epoch(5)`
  (runtime.rs:4074-4075).
- Inside, processing `block_b` (epoch 6) calls
  `get_active_validators_enforced(6)` (runtime.rs:4210-4211), which again
  calls `slashed_validators_for_epoch(5)` (runtime.rs:4074-4075) →
  re-reads the same epoch-5 evidence → re-processes `block_b` (epoch 6)
  → unbounded self-recursion.
- `compute_active_set(6)` does not Err for a future epoch
  (`validator_registry.rs:686-689` returns Ok), so no Err→continue
  (runtime.rs:4214) breaks the loop. Net: stack overflow / node abort
  rather than a clean return with V removed. Same entry/sink wiring; the
  realized observable in the headline scenario is chain-halt DoS.

## Attacker capability / preconditions

- Network position: any peer able to publish on the evidence gossip
  topic (unauthenticated submitter).
- To pass hop 6, the attacker must supply two blocks each carrying a
  VALID threshold signature for its claimed epoch. `block_a` is the
  legitimate epoch-A canonical block (freely observable). `block_b` must
  be a validly group-signed epoch-B block at the same height — i.e.
  control of / collusion with enough of epoch-B's signing committee to
  produce a real group-key signature (NOT "one member," per validation
  caveat H1; the threshold-of-1 case is separate finding F028).
- No validator role, no owner key, no operator/local-config access
  required on the submitting node.

## Guards on the path

- `detect_conflicting_blocks` (slashing.rs:58,64): same-height +
  distinct-hash only. Does NOT block cross-epoch or canonical-block
  evidence.
- Dedupe set (actor.rs:1597-1601): replay suppression only; not a
  security gate.
- `verify_evidence_signatures` (slashing.rs:89-110): per-block,
  per-epoch threshold-signature check. This is the one real guard; it
  passes for genuinely committee-signed blocks and does NOT require the
  two blocks to share signers/epoch (necessary-but-not-sufficient, as the
  finding concedes).
- `record` height cap (slashing_store.rs:57-61): rate-limits rows per
  height; not an authorization gate.
- Sink (runtime.rs:4191-4228): NO intersection / "signed both blocks"
  predicate — the defect. Consumer filter (runtime.rs:4090) trusts the
  `slashed` set wholesale; no downstream rescue of innocent signers.

## Reachability verdict

REMOTE-AUTHED-PEER — reachable from unauthenticated gossip ingress, but
the only passable guard (hop 6) requires the attacker to present a valid
epoch-B committee threshold signature over `block_b`, i.e. effective
control/collusion of (a quorum of) one epoch's signing committee.
