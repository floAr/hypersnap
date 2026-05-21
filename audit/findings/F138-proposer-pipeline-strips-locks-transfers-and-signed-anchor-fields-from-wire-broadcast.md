---
id: F138
task: H138
attack_class: mempool-admission-or-deterministic-ordering
severity: critical
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.97
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F138 — Proposer pipeline broadcasts hyperblocks with all locks/transfers and signed anchor fields stripped, breaking importer signature verification + state-root replay for every non-trivial block

- **Task ID:** H138
- **Attack class:** mempool-admission-or-deterministic-ordering
- **Severity (draft):** Critical (no peer can ever import a non-empty / anchor-aware proposer block — chain halts at first real proposer block on a multi-node deployment)

## Summary

The proposer pipeline that runs on `HyperActorEvent::ProduceBlockDkls`
(scheduler → `start_dkls_block_production` →
`produce_unsigned_block_dkls` → `attach_dkls_signature` →
`HyperActorOutbound::BroadcastBlock`) signs the **full** block
metadata (snapchain anchor block / hash / timestamp, snapchain range
root, missed-proposal entries) AND drains the mempool to determine
the state root, but then loses **both** the message payload and most
of the signed metadata at the wire boundary:

1. `HyperActorOutbound::BroadcastBlock` carries only a `HyperBlock`,
   not the locks/transfers that the importer needs to re-apply.
   The gossip adapter (`gossip_adapter.rs:99-115`) hard-codes
   `locks: vec![], transfers: vec![]` on every block it publishes —
   so the receiver always gets a wire frame with **zero messages**
   even though `proto::HyperWireBlock` schema explicitly carries
   `repeated HyperLockEvent locks = 2` / `repeated HyperTransferTx
   transfers = 3` for this purpose (`gossip.proto:48-52`, comment:
   *"Importers need both to validate state transition"*).
2. Both `encode_hyper_block` and `decode_hyper_block`
   (`gossip_adapter.rs:173-228`) overwrite `missed_proposals`,
   `snapchain_anchor_block`, `snapchain_anchor_hash`,
   `snapchain_range_start_block`, `snapchain_range_root`,
   and `snapchain_anchor_timestamp` with their proto defaults
   (`vec![]` / `0`). These are exactly the fields the proposer
   committed to in `signing_payload(epoch)` (mod.rs:397–428).

The combination guarantees that on a multi-node deployment, every
post-cutover hyperblock the proposer broadcasts is rejected by every
peer's importer:

- `import_hyper_block` first computes `signing_payload(epoch)` against
  the **decoded** metadata (anchor fields zeroed) and verifies the
  threshold signature. The proposer signed the **original** metadata
  (anchor populated by `produce_unsigned_block_dkls`). The two
  payloads differ ⇒ `ImportError::SignatureVerificationFailed`
  for any block whose anchor block ≠ 0 / anchor hash ≠ `[]` /
  anchor timestamp ≠ 0 (in production every block past genesis).
- Even if anchor fields happen to be zero (devnet, test fixture),
  the importer still has `locks_in_block: &[]` and
  `transfers_in_block: &[]`, applies them (no-op), and the
  recomputed verkle root is the pre-block tree's root, which
  disagrees with the proposer-signed `hyper_state_root` whenever
  the mempool was non-empty. ⇒ `ImportError::StateRootMismatch`.

Net effect: the proposer-side pipeline is functionally a one-way
write-only path. Single-node devnets work because the proposer
imports its own block from the in-memory `HyperBlock` (not the
wire-decoded one) at `actor.rs:2386`. Multi-node networks halt
immediately on the first real proposer broadcast.

## Affected files

- `code/hypersnap/src/hyper/gossip_adapter.rs:99-115` —
  `outbound_to_wire(BroadcastBlock)` hard-codes `locks: vec![],
  transfers: vec![]` for every block. Inline comment acknowledges
  the gap: *"Currently we attach the messages on the producing
  side; the actor owns them at that point. This adapter doesn't
  have access to them since the actor doesn't publish them in the
  outbound today. Wire them in by changing the actor outbound."*
- `code/hypersnap/src/hyper/gossip_adapter.rs:173-200` —
  `decode_hyper_block` reconstructs metadata with
  `missed_proposals: vec![]`, `snapchain_anchor_block: 0`,
  `snapchain_anchor_hash: vec![]`, `snapchain_range_start_block: 0`,
  `snapchain_range_root: vec![]`, `snapchain_anchor_timestamp: 0`.
- `code/hypersnap/src/hyper/gossip_adapter.rs:203-228` —
  `encode_hyper_block` symmetrically drops those fields on the
  way out. (The signed proposer never sees this overwrite locally
  — only the wire frame is corrupted — so its own self-import
  during finalization still succeeds.)
- `code/hypersnap/src/hyper/actor.rs:557-559, 2384-2399` —
  `HyperActorOutbound::BroadcastBlock(HyperBlock)` variant
  carries no locks/transfers. The proposer pipeline at
  `dispatch_dkls_signature` sends this outbound after the
  ceremony finalizes — `pending.locks` and `pending.transfers`
  exist locally but are not forwarded to the network layer.
- `code/hypersnap/src/hyper/importer.rs:238-305` — `import_hyper_block`
  is the victim of the field-stripping. It reads
  `block.envelope.metadata.signing_payload(block.signature.epoch)`
  (line 249) against the decoded (zeroed) metadata, then reads
  `locks_in_block`/`transfers_in_block` to re-apply state. The
  failure is purely upstream — the importer's logic itself is
  correct given the inputs it's handed.
- `code/hypersnap/src/hyper/runtime.rs:4307-4324` —
  `produce_envelope_with_full_anchor` drains the mempool and
  computes the state root over the drained messages. The
  proposer's `hyper_state_root` therefore reflects messages
  the wire frame won't carry — so even ignoring the signature
  break (variant A below), the state-root recompute fails too
  (variant B).
- `code/hypersnap/proto/definitions/gossip.proto:48-52` —
  proto schema confirms `locks` and `transfers` ARE part of the
  wire frame; the implementation simply doesn't fill them.
- `code/hypersnap/proto/definitions/hyper.proto:14, 25-26, 44-45, 55` —
  proto schema confirms `missed_proposals`, `snapchain_anchor_block`,
  `snapchain_anchor_hash`, `snapchain_range_start_block`,
  `snapchain_range_root`, `snapchain_anchor_timestamp` are all
  first-class metadata fields. The proto encode/decode path drops
  them.

## Variant A — every non-zero anchor block fails signature verification

The proposer signs `signing_payload(epoch)` at `actor.rs:2288`:

```rust
let payload = block.envelope.metadata.signing_payload(epoch);
let digest = alloy_primitives::keccak256(&payload);
```

`signing_payload` (mod.rs:397–428) commits to **every** populated
metadata field including the snapchain anchor block (BE u64), anchor
hash (len32+bytes), range start (BE u64), range root (len32+bytes),
and anchor timestamp (BE u64). The DKLS sign ceremony produces an
ECDSA signature over `digest`.

After `attach_dkls_signature`, the proposer emits
`HyperActorOutbound::BroadcastBlock(send_block)` (actor.rs:2396). The
gossip adapter's `outbound_to_wire` calls `encode_hyper_block`
(gossip_adapter.rs:203-228), which constructs a `proto::HyperBlock`
with every anchor field set to `0` / `vec![]`. The wire frame is
published on `TOPIC_HYPER_BLOCKS`.

The peer's gossip layer hands the decoded `proto::HyperWireMessage`
to `wire_to_event` → `decode_hyper_block`
(gossip_adapter.rs:173-200), which constructs an in-memory
`HyperBlock` whose `envelope.metadata.snapchain_anchor_block == 0`,
`snapchain_anchor_hash == vec![]`, etc.

The peer's importer (importer.rs:246-258):

```rust
let payload = block
    .envelope
    .metadata
    .signing_payload(block.signature.epoch);
let expected =
    crate::hyper::sig_verify::ExpectedGroupKey::ecdsa_only(expected_dkls_group_address);
crate::hyper::sig_verify::verify_hyperblock_signature(
    &payload,
    &block.signature.ecdsa_signature,
    &block.signature.group_address,
    &expected,
)
.map_err(|_| ImportError::SignatureVerificationFailed)?;
```

`payload` here is `signing_payload(epoch)` over the **zeroed** anchor
fields. The proposer signed `signing_payload(epoch)` over the
**populated** anchor fields. The two byte strings differ ⇒
keccak256 differs ⇒ ECDSA verify returns `false` ⇒
`Err(ImportError::SignatureVerificationFailed)`.

In production every hyperblock has `snapchain_anchor_block ≥ 1`
(the cutover anchor block) and an anchor hash of length 32, so
**every** broadcast fails verification at every peer.

## Variant B — locks/transfers stripped on wire, state-root mismatch even on anchor-zero blocks

Even when the anchor fields happen to all be zero (e.g., the
single-node devnet test fixture at
`network_simulation_test.rs:118-120`), the wire payload still
carries empty `locks` and `transfers`:

```rust
HyperWireBlock {
    block: Some(encode_hyper_block(block)),
    locks: vec![],     // hard-coded
    transfers: vec![], // hard-coded
}
```

`wire_to_event` decodes this and emits
`HyperActorEvent::InboundBlock { block, locks: vec![], transfers: vec![] }`
(gossip_adapter.rs:61-65).

`import_hyper_block` (importer.rs:260-292), once it gets past the
signature gate (which it does at anchor-zero blocks), constructs an
empty `messages` vec, applies zero messages to the verkle tree,
reads the recomputed root, and compares against
`metadata.hyper_state_root`:

```rust
let mut builder = HyperBlockBuilder::new(tree);
for msg in &messages {                 // empty
    builder.apply_message(msg)...?;
}
let recomputed = tree.root_commitment()?;

let stated = HyperBlockMetadata::decode_state_root(&block.envelope.metadata)?;
if !commitments_eq(&recomputed, &stated) {
    return Err(ImportError::StateRootMismatch);
}
```

The proposer-side `produce_envelope_with_full_anchor` (runtime.rs:4307)
drained the mempool, applied each message to the **proposer's** tree,
and used the resulting root as `hyper_state_root`. Whenever the
mempool was non-empty at production time, the proposer's tree state
diverges from the empty post-apply tree at the importer ⇒ root
mismatch ⇒ `Err(ImportError::StateRootMismatch)`.

So even an anchor-zero broadcast fails to import on any block that
actually contained messages — and a hyperblock with no messages is
effectively a no-op anyway.

## Variant C — the same proto-decode drop pattern is mirrored in restart replay (test-only today, latent prod hazard)

`runtime.rs:4741-4769` defines `fn decode_proto_block(p: proto::HyperBlock)`
inside the `#[cfg(test)]` block, identical to `decode_hyper_block` in
the gossip adapter — it sets `missed_proposals: vec![]`,
`snapchain_anchor_block: 0`, `snapchain_anchor_hash: vec![]`,
`snapchain_range_start_block: 0`, `snapchain_range_root: vec![]`,
`snapchain_anchor_timestamp: 0`. While currently only the test path
calls it, the `block_index.rs` persistence stores `proto::HyperBlock`
(field-by-field) on disk; any production path that rehydrates from
that store using a similar decode helper would inherit the same
drop. The pattern is repeated four times in the codebase
(`gossip_adapter.rs:178-191`, `gossip_adapter.rs:206-218`,
`runtime.rs:4747-4759`, plus the symmetric tests in `block_index.rs`
seeded with zeroed anchors). One fix in three places.

## Why this isn't caught by tests

`hyper/network_simulation_test.rs` is the only end-to-end test that
exercises the wire round-trip. Two factors mask the bug:

1. The test uses `snapchain_anchor_block: 0, snapchain_anchor_hash:
   vec![], snapchain_anchor_timestamp: 0`
   (`network_simulation_test.rs:118-120, 272`). With all anchor
   fields at proto defaults, `signing_payload` produces the
   **same** bytes whether the metadata round-trips through the
   wire or not, so Variant A is silent on this fixture.
2. The same test acknowledges Variant B in a comment at
   `network_simulation_test.rs:144-148`:

   > "(The importer also needs the locks list in the InboundBlock
   > event, which the wire frame currently carries empty — this
   > test therefore manually attaches them via a synthesized event.
   > Once the producing path includes them in BroadcastBlock
   > outbounds, this step becomes pure wire decode.)"

   The test then **synthesizes** the importer event with the locks
   manually attached:

   ```rust
   let importer_event = match wire_to_event(decoded_block_wire).unwrap() {
       HyperActorEvent::InboundBlock { block, .. } =>
           HyperActorEvent::InboundBlock {
               block,
               locks: vec![lock.clone()],     // <-- bypassing the wire drop
               transfers: vec![],
           },
       ...
   };
   ```

   The comment explicitly anticipates the fix but the test
   compensates instead of failing.

So both variants are known-deferred in the test harness but never
landed in the production code.

## Cross-references against existing iter-1 findings

- **F002 (nil-block-proposal):** Malachite-side `add_proposed_value`
  panic on missing optional fields. Different layer (snapchain
  consensus); not the hyper-broadcast pipeline. No overlap.
- **F004 (epoch-boundary race):** epoch-resolver staleness and
  proposer-context refresh race. Doesn't touch the wire-payload
  drop. Orthogonal.
- **F028 (signing-payload-misses-hash-fields):** the inverse
  asymmetry — fields in `hyper_block_hash` but NOT in
  `signing_payload`. F138 is the orthogonal cousin: fields IN
  `signing_payload` but **dropped on the wire**. Different fields,
  different root cause (gossip adapter encode/decode vs.
  `signing_payload` definition), different fix.
- **F117 / F151 / F119 (verkle / codec / dlogproof panics):**
  panic surfaces. F138 is a silent rejection, not a panic.
- **F133 (fingerprint-store direct DB writes during simulate):**
  proposer-side DB-write-during-simulate. F138 is wire-payload
  drop; orthogonal.
- **F132 (charge-message-fee RAW pattern):** fee-charging path.
  Orthogonal.
- **F153 (signer_indices not in signed payload):** signature
  malleability of `signer_indices`. Same broader file
  (`signing_payload` coverage) but a different field gap. F138's
  failure mode is "wire decode zeros fields the proposer signed",
  not "field is absent from the signing payload entirely". Adjacent,
  not a duplicate.

## Impact

- **Liveness (chain halt) — Critical.** On any multi-node hyper
  deployment, every block the proposer pipeline broadcasts is
  rejected by every peer. The chain advances only on the
  proposer-local self-import path (which uses the in-memory
  `HyperBlock` with full metadata at actor.rs:2386, bypassing
  the wire codec). Peers never advance their `ChainTracker`,
  never update their verkle tree, and never see any of the locks
  / transfers that the proposer included. The proposer eventually
  runs ahead alone, by `parent_hash` divergence the chain
  irreparably forks.
- **Mempool integrity — High.** Locks and transfers that were
  included in a proposer block remain in every peer's mempool
  forever, because `mempool.forget_lock` / `forget_transfer`
  only runs on successful import (importer.rs:295-302), which
  never happens. The mempool LRU eventually evicts them, but
  in the meantime every peer carries N-1 wasted nullifiers in
  `pending_nullifiers` and rejects legitimate retransmits as
  `DuplicateNullifier`.
- **Slashing surface — Medium amplification.** Because peers
  receive the BroadcastBlock with anchor fields zeroed but the
  block has a valid threshold signature for some shape, any
  forwarded `HyperWireEvidence` (which embeds two full
  `HyperBlock` protos at `gossip.proto:69-71`) round-trips
  through the same `decode_hyper_block` and emerges with the
  same zeroed anchor. An evidence verifier that re-validates
  against the original signed payload would also fail. The
  slashing path is collateral damage but the same root cause.
- **No fund-loss path on its own**, but the chain-halt is the
  upper bound of any fund-loss bug — once the chain stops, all
  in-flight bridge mints/burns stall, custody-escrow drains
  stall, reward distribution stalls. So "Critical" by liveness
  rubric.

## Exploit walkthrough (no malicious actor required — fires on every honest broadcast)

Two-node honest topology, both nodes have the cutover-installed
epoch-0 DKLS share, scheduler-driven block production at 1s cadence.

1. Node A is the round-0 proposer for height 1 (per
   `is_proposer(local_key, validators, anchor_hash, 1, 0)` —
   proposer.rs:65-76).
2. A user submits a lock event to node A's HTTP handler. The
   actor admits it via `LocalSubmitMessage` →
   `mempool.submit_lock(event)` (mempool.rs:119), then emits
   `BroadcastMessage(msg)` (actor.rs:1153). The wire path for
   `BroadcastMessage` does NOT have this bug — `wrap_outbound_message`
   (gossip_adapter.rs:164-171) preserves the full message — so node
   B's mempool absorbs the lock.
3. At the next scheduler tick, A's `should_propose(1)` returns
   true (scheduler.rs:135-148). The scheduler fires
   `ProduceBlockDkls { height: 1, ..., snapchain_anchor_block: A,
   snapchain_anchor_hash: H, snapchain_anchor_timestamp: T }`
   with A, H, T populated from the latest snapchain anchor
   (scheduler.rs:165-182).
4. Node A's actor runs `start_dkls_block_production`. The runtime
   drains the mempool (`produce_envelope_with_full_anchor` at
   runtime.rs:4307), applies the lock to the verkle tree, computes
   the new root, and builds metadata `m` with the populated anchor
   fields. `payload = m.signing_payload(0)`. `digest = keccak256(payload)`.
5. The 1-of-1 (or full-quorum) DKLS sign ceremony produces an
   ECDSA signature over `digest`. The actor attaches it and
   emits `BroadcastBlock(block)` (actor.rs:2396).
6. The gossip adapter wraps: `encode_hyper_block(block)` strips
   anchor fields; `HyperWireBlock { locks: vec![], transfers: vec![] }`
   strips messages. The wire frame is published on
   `TOPIC_HYPER_BLOCKS`.
7. Node B receives. `wire_to_event` calls `decode_hyper_block`,
   producing an in-memory block with `snapchain_anchor_block = 0`,
   etc. `InboundBlock { block, locks: vec![], transfers: vec![] }`
   is dispatched to the actor.
8. Actor calls `runtime.import_block(&block, &[], &[])` →
   `import_hyper_block(...)`. It computes
   `payload' = block.envelope.metadata.signing_payload(0)` over
   the zeroed metadata. `payload' != payload`. ECDSA verify
   against the signature succeeds only if `keccak256(payload') ==
   keccak256(payload)`, which it doesn't (different bytes).
   `Err(ImportError::SignatureVerificationFailed)` returns.
9. Actor emits `HyperActorOutbound::EventError(Import(e))`
   (actor.rs:2390). Node B's `ChainTracker.last_height` does not
   advance. Mempool still contains the lock.
10. At the next height A is again the proposer; same thing
    happens. After enough ticks A's chain head is far ahead of B's
    (B is still at height 0). When B is randomly selected as a
    later-height proposer it tries to build on its own height 0,
    diverging from A's chain. Network is partitioned.

Failure mode is **honest-deterministic**: no malicious actor, no
specific input — just running the proposer pipeline as designed.

## Suggested remediation

1. **Plumb the messages through `BroadcastBlock`.** Change
   `HyperActorOutbound::BroadcastBlock(HyperBlock)` to
   `BroadcastBlock { block: HyperBlock, locks: Vec<HyperLockEvent>,
   transfers: Vec<HyperTransferTx> }`. The proposer pipeline
   already has `pending.locks` and `pending.transfers` in scope
   at `dispatch_dkls_signature` (actor.rs:2374) — forward them
   into the outbound. `outbound_to_wire` then populates
   `HyperWireBlock.locks` / `.transfers` from the outbound
   instead of `vec![]`. The inline TODO comment at
   `gossip_adapter.rs:104-108` already prescribes this fix.

2. **Stop stripping signed metadata in `encode_hyper_block` /
   `decode_hyper_block`.** Forward `missed_proposals`,
   `snapchain_anchor_block`, `snapchain_anchor_hash`,
   `snapchain_range_start_block`, `snapchain_range_root`, and
   `snapchain_anchor_timestamp` byte-for-byte. The proto schema
   already carries them (`hyper.proto:3-56`). Mirror the fix in
   `runtime.rs:4741-4769` `decode_proto_block` (test-only today
   but a latent prod hazard).

3. **Add a regression test that exercises a non-zero anchor.**
   Re-run `network_simulation_test.rs::full_network_round_trip_via_wire_frames`
   with `snapchain_anchor_block: 5, snapchain_anchor_hash:
   vec![0x42; 32], snapchain_anchor_timestamp: 1_700_000_000`
   and drop the manual `locks: vec![lock.clone()]` synthesis
   at line 152-156. The test should pass without any manual
   re-injection. Today it would fail at both
   `SignatureVerificationFailed` (variant A) and
   `StateRootMismatch` (variant B, if any messages are in the
   mempool).

4. **Add a `prop_test`-style fuzz** over a random
   `HyperBlockMetadata` + random `locks` / `transfers` that asserts
   `proto-decode(proto-encode(block)) == block` for every field,
   AND `import_hyper_block` accepts the round-tripped block.
   The current `block_round_trip_through_wire` test at
   `gossip_adapter.rs:296` only checks four fields, all of which
   happen to round-trip cleanly.

5. **Make the importer cross-check `retained_message_count ==
   locks_in_block.len() + transfers_in_block.len()`** as a
   belt-and-braces guard (also surfaces F028 variant 3). With (1)
   in place this would catch any future regression that drops
   messages mid-pipeline.
