---
id: F013
specialist: consensus-malachite-tendermint
attack_class: shard-mismatch-panic
file_paths:
  - src/network/gossip.rs
  - proto/src/lib.rs
  - proto/definitions/blocks.proto
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: FullProposal gossip arm calls height().unwrap() before the shard-id guard, so a peer can crash any node with a height-less FullProposal frame
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

On the shard-routing decode path for inbound gossip
(`GossipReadActor`/`Gossip::map_gossip_bytes_to_system_message`), the
`GossipMessage::FullProposal` arm calls `full_proposal.height()` on a
prost-decoded, fully attacker-controlled message. `FullProposal::height()`
is `self.height.clone().unwrap()`. In proto3 the `Height height = 1` field
of `FullProposal` is an optional (message-typed) field that maps to
`Option<Height>` in Rust, so a peer can emit a `FullProposal` frame with
`height` omitted. The `.unwrap()` then panics, aborting the node — a
single unauthenticated gossip frame is a remote crash / DoS.

The shard-routing code immediately below (`full_proposal.shard_id()`, which
*does* return `Result` and is guarded with `is_err() -> return None`) was
clearly written to handle the missing-`height` case gracefully. That guard
is dead on arrival: `height()` at the top of the same arm already panicked
before control reaches it. This is the H013 shard-mismatch-panic surface:
the panic sits on the exact frame field used to route by shard.

## Location

`src/network/gossip.rs`, the `FullProposal` arm of
`map_gossip_bytes_to_system_message`:

```
Some(proto::gossip_message::GossipMessage::FullProposal(full_proposal)) => {
    let height = full_proposal.height();          // <-- panics: self.height.clone().unwrap()
    debug!("Received block with height {} from peer: {}", height, peer_id);
    ...
    let shard_result = full_proposal.shard_id();   // returns Result, guarded below — but unreachable on the None case
    if shard_result.is_err() {
        warn!("Failed to get shard id from consensus message");
        return None;
    }
    let shard = MalachiteEventShard::Shard(shard_result.unwrap());
    Some(SystemMessage::MalachiteNetwork(shard, event))
}
```

`FullProposal::height()` in `proto/src/lib.rs`:

```
pub fn height(&self) -> proto::Height {
    self.height.clone().unwrap()
}
```

Proto definition (`proto/definitions/blocks.proto`):

```
message FullProposal {
  Height height = 1;   // optional message field -> Option<Height> in Rust
  ...
}
```

## Reachability / attacker model

- `map_gossip_bytes_to_system_message` is invoked directly on raw
  gossipsub `message.data` for every received frame
  (`gossip.rs` swarm event handler, the `if let Some(system_message) =
  self.map_gossip_bytes_to_system_message(peer_id, data, originator)`
  call). The outer `proto::GossipMessage::decode` is the only gate; there
  is no signature/authentication check before the `FullProposal` arm.
- Unlike the `Consensus` / `Status` / `MempoolMessage` / `ContactInfo`
  arms, the `FullProposal` arm has no per-variant byte-size cap and, more
  importantly, no `height`-presence check — it dereferences `height`
  unconditionally.
- Any peer that can publish to the proposal-parts gossip topic (or any
  forwarding neighbor in a multi-hop mesh) can send a `FullProposal` with
  the `height` field absent and crash the receiving node. The proto itself
  carries the note `// TODO: This probably needs a signature?` confirming
  these frames are unauthenticated.

## Impact

Remote, unauthenticated, single-frame node crash (process abort via panic
on the actor/event thread). Repeatable against every node subscribed to the
topic → network-wide halt. Severity initial: high.

## Variant context

This is the same peer-controlled-`Option::unwrap` family already documented
for this codebase as F185 (F151 residual) — raw `GossipMessage::decode`
paths that bypass the fallible-codec arms and panic on missing
`height`/`value` or non-32-byte signer. The `FullProposal` arm is a fresh,
un-remediated instance of that pattern on the shard-routing decode path.
Worth re-scanning the other direct-decode arms and the `.height()` /
`Address::from_vec` / `round()` (`round.try_into().unwrap()`) helpers in
`proto/src/lib.rs` for the same missing-field unwrap shape.

## Suggested fix

Make the `FullProposal` arm height-fallible before any use: replace the
`full_proposal.height()` call with a check on `full_proposal.shard_id()`
(or a `match full_proposal.height { Some(h) => ..., None => return None }`)
*before* the `debug!`/`height` use, and drop the frame on `None`. The
existing `shard_id()` Result guard then becomes effective. Ideally also add
a fallible `try_height()` accessor and stop exposing the panicking
`height()` on peer-decoded values.
