---
finding_id: F038
title: '`handle_contact_info` binds the inner `ContactInfoBody.peer_id` to `propagation_source`, the mesh neighbour that forwarded the gossip'
severity: low
status: pending-validation
---
# F038 — `handle_contact_info` binds the inner `ContactInfoBody.peer_id` to `propagation_source`, the mesh neighbour that forwarded the gossip message, instead of `message.source`, the gossipsub-signed author. Every contact-info message that has travelled more than one hop therefore fails the check and is dropped. A read node learns contact info only from its direct neighbours, which it is already connected to, so autodiscovery (`enable_autodiscovery`) never dials anyone new. Read nodes stay on their bootstrap peers, which makes eclipsing them easier.

- **Severity:** Low. Functional breakage of peer discovery, with a security side effect: eclipse resistance of read nodes depends entirely on the bootstrap list. No spoofing is possible, because the check is stricter than intended. Confidence 0.8.
- **Category:** logic error in sender binding (sender-spoofing-inside-payload; peer-discovery-eclipse)
- **Specialist:** p2p-gossip · task H040
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). The `contact_peer_id != peer_id` check is new (labelled "F021" in the code).
- **PoC:** None. Test sketch: three gossip nodes A–B–C in a line (A not connected to C). C publishes contact info. On A, the `"Dropping contact info: inner peer_id does not match libp2p sender"` warning fires with `sender = B`, `claimed = C`.

## Code facts

1. The swarm loop destructures `gossipsub::Event::Message { propagation_source: peer_id, message_id: _id, message }` and passes `peer_id` downstream (`src/network/gossip.rs:1320-1346`).
2. `handle_contact_info(contact_info, peer_id)` drops the message when `contact_peer_id != peer_id` (`gossip.rs:1606-1614`). The comment says the intent is to bind to "the libp2p sender".
3. With `ValidationMode::Strict` and `MessageAuthenticity::Signed` (`gossip.rs:636`, `658-660`), `message.source` is the authenticated author, so it is the right value to compare against.
4. Only read nodes dial from contact info (`gossip.rs:1619-1653`). Validators return after `self.peers.insert`. Validators' `peers` map is still populated only from direct neighbours.
5. FIP §4.10: "Peer discovery. The `contact-info` message contains the epoch registration of the validator, so a new peer can examine the membership." Discovery of non-neighbours is intended.

## Recommendations

- Compare against `message.source` (and drop when `source` is `None`). Pass both the author and the propagation source into the handlers, so that the forwarder is used only for metrics and scoring.
- Add a multi-hop discovery test.
