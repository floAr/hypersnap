# F013 trace — FullProposal missing-`height` `unwrap()` panic on gossip

Pinned commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`. Code is READ-ONLY.
This trace documents reachability only; it does not re-judge the WATERPROOF verdict.

## Entry point(s)

Untrusted ingress: the libp2p swarm event handler for an inbound gossipsub
message in `GossipReadActor`'s swarm loop:

- `src/network/gossip.rs:780` —
  `if let Some(system_message) = self.map_gossip_bytes_to_system_message(peer_id, data, originator)`
  where `data = message.data.clone()` (`gossip.rs:774`) is the raw, attacker-supplied
  gossipsub frame payload, dispatched on the matched `Message` swarm event.

## Trust boundary crossed

Network → process. The bytes arrive over the public gossipsub mesh. The
libp2p transport envelope is authenticated (`ValidationMode::Strict`,
`gossip.rs:314`; `MessageAuthenticity::Signed(key)`, `gossip.rs:324`), which
proves the frame was signed by *some* peer's libp2p keypair but does NOT
validate the application proto payload, its required fields, or the presence
of `height`. The only application-level gate is proto decoding; there is no
signature/authority check on the `FullProposal` payload (proto carries
`// TODO: This probably needs a signature?`). Crossing this boundary, a mesh
peer's bytes flow unchecked into a panicking accessor.

## Call path (ingress → panic sink)

1. `src/network/gossip.rs:774` — swarm handler — copies the raw attacker frame:
   `let data = message.data.clone();`.
2. `src/network/gossip.rs:780` — swarm handler — calls
   `self.map_gossip_bytes_to_system_message(peer_id, data, originator)` directly
   on the raw bytes. No auth/validation between here and the sink.
3. `src/network/gossip.rs:989` — `map_gossip_bytes_to_system_message` —
   `proto::GossipMessage::decode(gossip_message.as_slice())`. The only gate.
   A `FullProposal` with `height` omitted is well-formed proto3 and decodes
   successfully to `Some(FullProposal { height: None, .. })`.
4. `src/network/gossip.rs:1019` — same fn — matches the
   `GossipMessage::FullProposal(full_proposal)` arm with a fully
   attacker-controlled `full_proposal`.
5. `src/network/gossip.rs:1020` — same fn — **FIRST statement in the arm**:
   `let height = full_proposal.height();`.
6. `proto/src/lib.rs:185-187` — `FullProposal::height()` —
   `self.height.clone().unwrap()`. With `self.height == None` this `unwrap()`
   panics → **SINK**. The actor/event thread aborts; the node crashes.

(The `debug!` at `gossip.rs:1021-1024` and the `shard_id()` guard at
`gossip.rs:1032-1036` are never reached on the missing-`height` case — the
panic at step 6 precedes them.)

## Attacker capability / preconditions

- Be a peer in the gossipsub mesh with a valid libp2p identity (Strict+Signed
  admits arbitrary peers; gossipsub meshes accept arbitrary participants — no
  validator-only admission gate is shown). This is a remote, non-privileged
  attacker, not a privileged validator.
- Publish a single `GossipMessage::FullProposal` frame to the proposal-parts
  mesh (or have any forwarding neighbor relay it) with the message-typed
  `height` field omitted on the wire.
- No private key of the target, no committee/validator membership, no local
  config control required. One crafted frame per victim; repeatable against
  every subscribed node → network-wide halt.

## Guards on the path (and why they don't stop the panic)

- **`proto::GossipMessage::decode` (`gossip.rs:989`)** — only rejects malformed
  wire bytes. An omitted `Height height = 1` (a message-typed singular field →
  `Option<Height>` in prost, proto3 has no required fields) is valid wire and
  decodes to `height: None`. Does not stop it.
- **`shard_id()` Result guard (`gossip.rs:1032-1036`)** — `full_proposal.shard_id()`
  (`proto/src/lib.rs:139-145`) correctly returns `Err("No height in FullProposal")`
  when `self.height` is `None`, and the arm drops the frame on `is_err()`. This
  guard was clearly written to handle the missing-`height` case — but it is
  **dead on arrival**: it sits *after* the `height()` call at line 1020, so the
  `unwrap()` panics before control ever reaches it.
- **StatusMessage None-guard contrast** — the sibling `Status` arm
  (`gossip.rs:1076`) handles the identical `Height height` message field safely:
  `let Some(height) = status.height else { warn!(...); return None; };`. The
  codebase already knows this field is `None`-able and guards it there; the
  `FullProposal` arm instead routes through the panicking `height()` accessor.
- **Gossipsub Strict + Signed (`gossip.rs:314,324`)** — authenticates the
  transport envelope only, not the proto payload or `height` presence. Does not
  stop it.

## Reachability verdict

**REMOTE-AUTHED-PEER** — reachable by any peer holding a valid libp2p identity
in the proposal-parts mesh via one well-formed `FullProposal` frame with
`height` omitted; no committee/validator privilege or key required, and the
sole upstream gate (proto decode) accepts the frame.
