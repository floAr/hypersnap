---
id: H023
specialist: p2p-gossip
attack_class: gossipsub-validation-mode-permissive
outcome: ruled-out
file_paths:
  - code/hypersnap/src/network/gossip.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H023 — gossipsub validation mode / message-id determinism — RULED OUT

## Scope
`src/network/gossip.rs` gossipsub configuration (`SnapchainGossip::create`,
behaviour builder at lines 285-326).

## Hunt
If the gossipsub `ValidationMode` were `Permissive`/`Anonymous` AND the
message-id function were non-content-addressed, a peer could forge the
`from`/source field or craft message-id collisions enabling
censorship/replay. Check the configured `ValidationMode` and `message_id_fn`.

## What the code actually does

### ValidationMode — SECURE
`gossip.rs:314`:
```rust
.validation_mode(gossipsub::ValidationMode::Strict)
```
This is the strict (signature-enforcing) mode — the recommended setting.
Not Permissive, not Anonymous, not None. libp2p rejects any frame whose
signature does not verify against `message.source`'s public key, and
rejects frames missing the signature / source / sequence-number fields.

### MessageAuthenticity — SECURE
`gossip.rs:324`:
```rust
gossipsub::MessageAuthenticity::Signed(key.clone())
```
Outbound frames are signed with the node's libp2p key. Combined with
`Strict` inbound validation this is exactly the good pattern
(`Strict` + `Signed`).

No override of either setting exists anywhere in the tree (grep over
`src/` for `validation_mode` / `MessageAuthenticity` / `Permissive` /
`Anonymous` returns only this single config site; the lone "Permissive"
hit in `hyper/actor.rs:2475` is an unrelated comment about peer-id
registration).

### message_id_fn — deterministic, and the non-content branch is not forgeable
`gossip.rs:286-309`. Two branches:
- `MEMPOOL_TOPIC | CONTACT_INFO`: content-addressed — hashes
  `message.data` (DefaultHasher). Deterministic and bound to payload
  content, so identical payloads dedupe regardless of source. Good for
  these high-volume / re-gossiped topics.
- All other topics (consensus, decided-values, read-node-peers, hyper,
  hyper-wire, …): the libp2p default — `source.to_base58() +
  sequence_number`.

The default (source+seqno) branch is the classic "forgeable id" concern
ONLY under Permissive/Anonymous signing, where `source` is attacker-set.
Here, under `Strict` + `Signed`, both `source` and `sequence_number` are
covered by the frame signature and verified against the source peer's
key before the message is ever delivered or its id computed for
dedupe/propagation. Consequences:
- A peer cannot set `source` to another peer's id (forged `from`) — the
  signature check fails first.
- A peer cannot manufacture a cross-source message-id collision to
  censor another peer's message, because it cannot produce a validly
  signed frame carrying the victim's `source`.
- Self-collision (same source reusing a seqno) only lets a peer suppress
  its OWN duplicate — not an attack on others.

## Conclusion
The configuration is the recommended secure pattern (`ValidationMode::Strict`
+ `MessageAuthenticity::Signed`). The non-content-addressed message-id on
consensus/sync/hyper topics is not exploitable for sender-spoofing,
censorship, or replay under Strict signing. The attack precondition
(Permissive/Anonymous mode) does not hold. No finding.

Related (separately tracked, out of H023 scope): app-level sender binding
for hyper-wire ingress is handled at `gossip.rs:1109-1135` via the
gossipsub originator (`message.source`), and contact-info inner peer-id is
bound to the libp2p sender at `gossip.rs:911-933` (F021). Neither bears on
the validation-mode question here.
