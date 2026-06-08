---
id: F022
specialist: p2p-gossip
attack_class: gossip-message-size-no-cap
title: "FullProposal and DecidedValue gossip ingress paths lack F019 per-variant size caps; full-block payloads bounded only by the 10 MB transport ceiling (memory-amplification DoS)"
severity_initial: medium
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/network/gossip.rs
  - code/hypersnap/proto/definitions/gossip.proto
  - code/hypersnap/proto/definitions/blocks.proto
  - code/hypersnap/src/hyper/builder.rs
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.82
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The F019 hardening added per-variant application-level size caps in
`map_gossip_bytes_to_system_message` (`src/network/gossip.rs`) so that
each inbound gossip topic is bounded *below* the 10 MB transport ceiling
(`MAX_GOSSIP_MESSAGE_SIZE`). The stated goal (lines 46-51) is that
"anything larger is a Sybil-flood / amplification vector and is dropped
at ingress."

That coverage is incomplete. Two decode arms carrying full blocks have
**no per-variant cap at all** and are bounded only by the 10 MB transport
limit:

1. `GossipMessage::FullProposal` (consensus topic) — lines 1019-1039.
2. `GossipMessage::ReadNodeMessage` / `DecidedValue`
   (decided-values + read-node-peers topics) — lines 1007-1017.

Both are subscribed by honest nodes (consensus topic: lines 395-401;
decided-values via `SubscribeToDecidedValuesTopic`, read-node-peers:
lines 379-385) and both carry an entire `Block` / `HyperBlock`. Every
other application variant — ContactInfo, Consensus, Status, HyperWire,
Mempool — has an explicit `encoded_len()` cap.

## The evidence-topic question (hunt prompt focus)

The hunt asked specifically whether the **evidence** frame (two full
blocks, `hyper/evidence/v1`) lacks a cap. It does **not**: all four hyper
topics (`blocks`, `messages`, `dkg`, `evidence`) are carried by the outer
`GossipMessage::HyperWire` variant, which IS capped at
`MAX_HYPER_WIRE_BYTES = 512 KB` at line 1100 *before* the inner
`wire_to_event_with_source` decode. `wire.encoded_len()` measures the
full `HyperWireMessage`, including the nested `HyperWireEvidence` with
both `block_a` and `block_b`, so the evidence frame is bounded to 512 KB
total. The evidence path is therefore covered.

(Separately worth noting: a single full hyper block can hold up to
`MAX_MESSAGES_PER_BLOCK = 50_000` messages — see
`src/hyper/builder.rs:67` — so a legitimate two-block evidence frame can
plausibly exceed 512 KB, meaning the shared HyperWire cap may *under*-size
real evidence and silently drop it. That is a functional/availability
concern for the slashing path, not the DoS gap, but it shows the comment
on line 52 — "512 KB ... evidence frames" — does not reflect the true
natural max of an evidence frame.)

## Why the uncapped paths matter (memory amplification)

`proto::GossipMessage::decode(...)` (line 989) eagerly allocates the
entire decoded message tree before any arm-specific check runs. For the
two uncapped arms an attacker (or a Sybil swarm) can gossip frames up to
the full 10 MB transport ceiling, each forcing the recipient to:

- allocate the full decoded `FullProposal` / `DecidedValue` (incl. the
  whole `Block`/`HyperBlock`), then
- for `FullProposal`, immediately re-encode it
  (`full_proposal.encode_to_vec()`, line 1026) into a second `Bytes`
  buffer that is forwarded onward as a `SystemMessage`, and
- for `DecidedValue`, hand the full decoded value downstream as
  `SystemMessage::DecidedValueForReadNode`.

So each oversized frame costs >= 2x its wire size in transient heap on
every subscribed node, with no early-drop. The whole point of F019 was to
clamp this below 10 MB; these two arms were missed. The consensus topic
is the higher-value target because every validator subscribes to it and
the `FullProposal` arm both allocates and re-encodes.

`proto::GossipMessage` definition: `gossip.proto:12-24`.
`FullProposal { ... oneof { Block block; ShardChunk shard } }`:
`blocks.proto:73-81`. `DecidedValue` carries `Block` / `ShardChunk` /
`HyperBlock`: `gossip.proto` (DecidedValue is reached via
`ReadNodeMessage`).

## Affected code

`src/network/gossip.rs`:

- Lines 1007-1017 — `ReadNodeMessage` / `DecidedValue` arm: no
  `encoded_len()` cap before constructing
  `SystemMessage::DecidedValueForReadNode`.
- Lines 1019-1039 — `FullProposal` arm: no `encoded_len()` cap before
  `full_proposal.encode_to_vec()` and `SystemMessage` dispatch.

Contrast the capped arms: ContactInfo (994), Consensus (1041), Status
(1066), HyperWire (1100), Mempool (1146).

## Severity

Medium. Memory-amplification DoS on the consensus and decided-values
gossip topics. Bounded by the 10 MB transport ceiling (so not unbounded),
but the F019 intent — drop oversized frames at ingress before the heavy
decode/re-encode — is defeated for these two arms. Requires a peer with a
valid libp2p key in the mesh (transport is `Strict` + `Signed`), and
peer scoring (F017) provides eventual eviction, which caps sustained
abuse and is why this is medium rather than high.

## Suggested remediation

Add per-variant caps mirroring the other arms, e.g. a
`MAX_FULL_PROPOSAL_BYTES` / `MAX_DECIDED_VALUE_BYTES` (sized to the real
max block) checked via `full_proposal.encoded_len()` /
`decided_value.encoded_len()` at the top of each arm, returning `None`
with a warn! on overflow. Separately, re-evaluate `MAX_HYPER_WIRE_BYTES`
against the true worst-case two-block evidence frame so legitimate
evidence is not dropped.
