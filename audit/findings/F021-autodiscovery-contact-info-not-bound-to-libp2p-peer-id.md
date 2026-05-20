---
id: F021
task: H021
specialist: p2p-gossip
attack_class: peer-discovery-eclipse
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.88
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Read-node auto-discovery dials attacker-supplied multiaddrs because ContactInfo.peer_id / .gossip_address are never bound to the libp2p sender's peer-id

## Summary

When a read-node has `gossip.enable_autodiscovery = true`, every inbound
`ContactInfo` message gossiped on the `contact-info` topic causes the
node to **dial the `gossip_address` field carried in the message body**
(`src/network/gossip.rs:798-800`). The body is supplied by *the
publishing peer*, gossipsub only authenticates the *transport* sender,
and the dial uses `DialOpts::unknown_peer_id()` (`src/network/gossip.rs:506`)
so the address does not have to correspond to any particular libp2p
identity. There is **no check** that

1. the libp2p sender that propagated the gossip frame matches the
   `peer_id` field inside the body, or
2. the `gossip_address` inside the body has any relationship to the
   libp2p sender's connected multi-address.

A single connected peer can therefore unilaterally cause the read-node
to dial any number of attacker-controlled multiaddrs. Combined with the
absent peer-scoring / mesh-shape defences described in **F017**, an
attacker who delivers one well-timed `ContactInfo` burst to a freshly
booting node (window: between first bootstrap-peer dial and the
ten-or-twenty mesh slots filling with honest peers) can stuff its mesh
with Sybils, eclipsing it from the honest network.

The exact bug shape called out in the H021 task brief — "a malicious
peer responds to discovery probes with addresses of N attacker-controlled
nodes, filling the new node's mesh slots before any honest peer
connects" — is realised by this code path verbatim.

`src/network/gossip.rs:746-801`:

```rust
pub fn handle_contact_info(&mut self, contact_info: ContactInfo, peer_id: PeerId) {
    // TODO(aditi): We might want to persist peers and reconnect to them on restart
    if contact_info.body.is_none() {
        warn!("Received empty contact info from peer: {}", peer_id);
        return;
    }
    let contact_info_body = contact_info.body.unwrap();
    info!(
        peer_id = peer_id.to_string(),
        ip = contact_info_body.gossip_address,
        "Received contact info from peer"
    );

    let contact_peer_id = PeerId::from_bytes(&contact_info_body.peer_id).unwrap();   // (a)

    self.peers
        .insert(contact_peer_id, contact_info_body.clone());                          // (b)

    // Validators should just dial the bootstrap set since the validator set is fixed.
    if !self.read_node {
        return;
    }

    if let Some(peer_id) = self
        .swarm
        .connected_peers()
        .find(|peer_id| contact_peer_id == **peer_id)
    {
        info!(peer_id = peer_id.to_string(), "Already connected to peer, so not dialing");
        return;
    }

    if contact_info_body.network() != self.fc_network { return; }                     // (c)

    let current_version = EngineVersion::current(self.fc_network).protocol_version();
    if contact_info_body.snapchain_version != current_version.to_string() { return; } // (d)

    if self.enable_autodiscovery {
        let _ = Self::dial(&mut self.swarm, &contact_info_body.gossip_address);       // (e)
    }
}
```

The two filters at (c) and (d) only check fields *inside the same
attacker-controlled body* — the attacker simply puts the right network
ID and version string in. The dial at (e) takes
`contact_info_body.gossip_address` as a raw multiaddr string. The
transport-layer libp2p sender (`peer_id` in the function signature) is
*never compared* to `contact_peer_id` (the body's claim).

## Description

### 1. The transport-vs-payload binding gap

libp2p / gossipsub authenticates the *transport* sender: every gossip
frame is signed by the publisher's Ed25519 key (`MessageAuthenticity::Signed`
at `src/network/gossip.rs:295`, `ValidationMode::Strict` at `:285`).
That guarantees the function-signature `peer_id: PeerId` in
`handle_contact_info` faithfully identifies which libp2p peer pushed
the bytes onto the mesh.

It does **not** authenticate the *application-level body*. The
`ContactInfoBody` proto carries three operator-supplied fields:

- `peer_id: bytes` — the libp2p `PeerId` the publisher claims to be.
- `gossip_address: string` — the multiaddr the publisher claims to be
  reachable at.
- `announce_rpc_address: string` — the RPC URL the publisher claims
  to expose.

None of these are signed *as a body* with the libp2p key. They are
just whatever bytes the publisher chose to put in the protobuf. As a
result, peer **A** (libp2p peer-id `12D3...AAAA`) can publish a
`ContactInfo` claiming `peer_id = 12D3...BBBB`, `gossip_address =
/ip4/<attacker-controlled-ip>/udp/3382/quic-v1`, and the receiver has
no transport-level evidence that A and B are different entities. The
code only sees the libp2p sender (A) in the function argument; it
*believes* the body.

### 2. What the receiver does with the unauthenticated body

Three things happen to the unauthenticated body, all bad to varying
degrees:

**(a) `PeerId::from_bytes(&contact_info_body.peer_id).unwrap()` at
line 759** — this `unwrap()` panics the entire gossip task if the
publisher sets the `peer_id` field to anything that isn't a
well-formed libp2p PeerId (e.g. an empty bytestring, or 2 KB of zeros).
That's a **second, separate bug** (panic-on-malformed-gossip) on the
same ingress path, with severity equal to the gossip-task panic
surface (in a single-process node this stops *all* gossip until
restart).

**(b) `self.peers.insert(contact_peer_id, contact_info_body.clone())`
at line 762** — the receiver's per-peer cache is **always** poisoned
with the attacker-chosen body, regardless of `read_node` or
`enable_autodiscovery`. That means even a *validator* (which won't
auto-dial) records the attacker's lie in its `peers` map, and that
map is exposed via the `GossipEvent::GetConnectedPeers(...)`
RPC channel — so a validator may serve back attacker-fabricated
`announce_rpc_address` values to honest clients querying it, who will
then try to talk RPC to the attacker's chosen URL. (This is a
*reflected* SSRF / phishing surface on the RPC discovery path.)

**(c) `Self::dial(&mut self.swarm, &contact_info_body.gossip_address)`
at line 799** — when the receiver is a `read_node` and
`enable_autodiscovery == true`, the node fires a libp2p dial at the
attacker-chosen multiaddr. Because the dial uses
`DialOpts::unknown_peer_id()` (`src/network/gossip.rs:506-508`), the
dialer makes no identity claim, so the attacker can have the dial
land on:

- An attacker-controlled libp2p node, completing the eclipse
  (which is the primary vector here).
- Any arbitrary TCP/UDP service — the dial side of libp2p will
  try the QUIC handshake, fail, and emit
  `OutgoingConnectionError`. That's not as harmful directly, but it
  makes `gossip_address` a free *unauthenticated outbound-traffic
  generator* — i.e. a small **DDoS amplifier** against a chosen
  victim address.

### 3. The "fill mesh slots before honest peers" bug shape

The H021 brief asks about exactly this scenario. Realised by the code:

1. A fresh read-node starts. The operator has configured
   `bootstrap_peers = "/ip4/A/udp/3382/quic-v1, /ip4/B/udp/3382/quic-v1, ..."`
   (typically 4–7 entries; see `docker-compose.mainnet.yml:32`).
2. The node dials each bootstrap peer in turn at startup
   (`src/network/gossip.rs:326-328`).
3. **The attacker controls one of those bootstrap addresses** (or
   front-runs a single honest one with a faster QUIC handshake, since
   the dial uses `unknown_peer_id` and libp2p will happily accept
   whoever answers first on that address).
4. That single attacker-controlled bootstrap peer is now in the
   gossipsub mesh on the `contact-info` topic.
5. The attacker publishes (rapidly, via the same connection) `N`
   distinct `ContactInfo` messages, each with a different fabricated
   `peer_id` and a different attacker-controlled `gossip_address`.
   Each is gossiped via the now-shared `contact-info` topic to the
   victim.
6. The victim's `handle_contact_info` runs `N` times. For each, it
   passes the network / version filter (the attacker writes the
   correct strings), reaches line 798 with
   `enable_autodiscovery == true`, and dials the attacker's address.
7. Each dial completes the libp2p handshake against an attacker-run
   listener. Each new connection is a fresh gossipsub peer; gossipsub
   grafts new peers into meshes up to `mesh_n_high = 20`
   (`:289`). With **no peer scoring** (see F017) and **no IP-colocation
   guard** (also F017), the attacker's 20+ Sybils saturate the mesh
   before any honest read-node-fleet peers can dial in.
8. The victim is now eclipsed: its consensus/decided-values/mempool
   topic meshes are populated almost entirely by Sybils. From the
   victim's perspective the honest network "went quiet". A motivated
   attacker can keep the meshes pinned to its Sybils indefinitely
   because the only eviction mechanism (peer scoring) is disabled.

There is one mitigating factor: line 769-779 checks
`self.swarm.connected_peers().find(|p| contact_peer_id == **p)` and
short-circuits the dial if a peer with the same libp2p peer-id is
already connected. Defeated trivially by giving each fabricated
contact-info body a **fresh** `peer_id` field — the attacker can
spin up `N` libp2p keypairs at no cost, since the
field is body-only and not cryptographically tied to anything.

### 4. The 99% of the deployment surface this hits

`enable_autodiscovery` defaults to `false` (`:90`). That's a healthy
default for *validators*. However:

- Every shipped `docker-compose.*.yml` sets `read_node = true`
  (mainnet/testnet/nightly) — see `docker-compose.mainnet.yml:23`,
  `docker-compose.testnet.yml:24`, `docker-compose.nightly.yml:22`.
- The Hypersnap operator playbook (`docs/architecture.md`,
  `config/sample.toml`) does not include `enable_autodiscovery` —
  the field is undocumented at the user-facing level. An operator
  who *does* enable it (legitimately, to grow a read-node fleet
  without redistributing the bootstrap list every time it changes)
  immediately exposes the deployment to the attack above.
- The dispatch path in `handle_contact_info` does **not** gate on
  "is this peer in my bootstrap set" — every connected peer is an
  equal source of contact-info gossip. So compromising a *single*
  honest bootstrap peer cascades into eclipsing every read-node in
  the fleet that has `enable_autodiscovery = true`.

### 5. What's *not* a vulnerability (but should be confirmed)

- **mdns / Kademlia / DHT discovery.** The `libp2p` Cargo feature
  list at `Cargo.toml:50` includes `"mdns"`, but **`SnapchainBehavior`
  does not include `mdns::Behaviour`** (workspace-wide grep for
  `Mdns`, `mdns::`, `MDNS` in `src/**` returns zero hits outside the
  unused feature flag — the only matches are in `Cargo.lock`).
  Kademlia is not in the Cargo features at all; the workspace has
  zero hits on `Kademlia` / `kad::` / `kademlia`. So no LAN-scoped
  poisoning and no Kademlia routing-table-seed vector. The
  `mdns` feature should be removed from `Cargo.toml` to make this
  explicit; it currently produces ~30 KB of dead code on every
  build and could be accidentally wired up by a future contributor.
- **`direct_peers`.** Parsed as a comma-separated list of `PeerId`s
  (`:149-154`) and passed to `gossipsub.add_explicit_peer(&peer_id)`
  (`:299-302`). Explicit peers in gossipsub are "always-on" mesh
  peers; the peer-id is the identity criterion. Because libp2p will
  not actually be able to *reach* a peer that has no associated
  multiaddr (and the address must arrive separately via dialing /
  bootstrap), the `direct_peers` config field on its own does not
  open a dial-attacker surface. **However**, when an `add_explicit_peer`'d
  PeerId connects (via any path, including the autodiscovery dial
  above), gossipsub bypasses normal mesh-membership logic for that
  peer and grafts it permanently. If the attacker can guess or
  observe the operator's `direct_peers` value and present that
  PeerId, the attacker gets an unevictable mesh slot. Today that's
  unreachable because `direct_peers` is undocumented and unused in
  the shipped configs — but it's a sharp edge.
- **`bootstrap_peers` themselves.** The string is parsed as plain
  multiaddrs (`:142-147`), no peer-id required, dial uses
  `unknown_peer_id()`. So a man-in-the-middle on the bootstrap IP
  can answer the handshake as itself, and the dialer cannot tell.
  This is the standard "use `/ip4/.../p2p/<peer-id>` instead of
  `/ip4/...`" hardening, and the deployments do **not** apply it
  (see `docker-compose.mainnet.yml:32` — no `/p2p/...` suffix).
  This is a separate, smaller bug (MitM during bootstrap reconnect),
  not strictly an eclipse vector against a fresh node — but it
  compounds the F021 attack by letting the attacker passively
  become *the* honest-bootstrap-peer the new node dials into.

### 6. Why severity = medium

- The dangerous surface (dial-attacker-chosen-address) is gated by
  `enable_autodiscovery == true`. That gate is off by default in
  code, **but** the field is documented in `gossip.rs` as the
  read-node fleet-growth mechanism, so any operator running more
  than one read-node will eventually flip it on.
- The eclipse is only durable if peer scoring is also absent — and
  it is (see F017). Conversely, fixing F017 partially mitigates
  F021 (a Sybil-eclipsed mesh would now be evicted as the Sybils
  fail to deliver expected message classes). But F021's panic
  surface (point a above, the `unwrap()` on `peer_id` bytes) is
  unconditional — that one fires on validators too, with no
  `enable_autodiscovery` gate.
- Read-nodes are typically the public-facing RPC providers. An
  eclipsed read-node serves stale or selectively-censored data to
  end-user clients. That's a *centralised-API-poisoning* surface,
  not a consensus-safety surface.

## Impact

- **Eclipse of read-nodes — medium.** A single connected peer can
  cause `enable_autodiscovery = true` read-nodes to dial an arbitrary
  number of attacker-controlled multiaddrs. Combined with the absent
  peer scoring in F017, this is a durable eclipse: the read-node
  serves an attacker-chosen view of the chain to its RPC clients
  (stale heads, omitted messages, fabricated `announce_rpc_address`
  redirection on the `GetConnectedPeers` query).
- **Gossip-task panic — high (DoS).** The unconditional `.unwrap()` on
  `PeerId::from_bytes(&contact_info_body.peer_id)` at line 759 panics
  the gossip task when the publisher sets `peer_id` to any malformed
  bytestring. This is an unauthenticated reachable panic from any
  peer subscribed to `contact-info`. **Every node** (validator and
  read-node) is exposed — there is no `read_node` gate before the
  unwrap.
- **DDoS amplifier — low.** The autodiscovery dial path will fire a
  libp2p outbound dial to an attacker-chosen multiaddr. Each dial is
  small (a QUIC `Initial` packet), but a remote attacker who can
  spam `ContactInfo` messages through one connected peer can amplify
  one inbound gossip frame into one outbound dial. With ~100 read
  nodes on a network and the attacker holding a single connected
  peer slot on each, this becomes a low-but-nonzero reflected
  DDoS surface against any chosen IP / port the attacker writes
  into `gossip_address`.
- **Reflected RPC redirection — low.** Validators that record the
  attacker-supplied `announce_rpc_address` (because point (b) is
  unconditional) will return it to RPC clients who query
  `GetConnectedPeers`. End-user wallet apps or block explorers that
  rely on this field will be silently steered to an attacker
  endpoint.

## Evidence

- `src/network/gossip.rs:746-801` — the full `handle_contact_info`
  body. The libp2p `peer_id` argument is logged at line 754, then
  **never used again** for any authentication check.
- `src/network/gossip.rs:759` — `PeerId::from_bytes(...).unwrap()`
  panics on malformed `contact_info_body.peer_id` bytes from any
  peer.
- `src/network/gossip.rs:762` — `self.peers.insert(contact_peer_id, ...)`
  always runs, no `read_node` gate, no signer-binding check.
- `src/network/gossip.rs:798-800` — the dial fires on read-nodes
  with `enable_autodiscovery == true` against the body-supplied
  `gossip_address`.
- `src/network/gossip.rs:501-516` — `dial` uses
  `DialOpts::unknown_peer_id()`, so the dial is not bound to any
  expected identity. Any node answering the handshake at the
  attacker-chosen address is accepted.
- `src/network/gossip.rs:285-297` — gossipsub is `Strict` + `Signed`,
  which protects the *transport* identity but not the body fields.
- `src/network/gossip.rs:295` — `MessageAuthenticity::Signed(key.clone())`
  confirms transport-only authenticity; nowhere does the code
  re-sign or re-authenticate the inner protobuf body.
- `src/network/gossip.rs:142-147, 506-508` — `bootstrap_addrs` are
  parsed as bare multiaddrs without a `/p2p/...` suffix, so the
  bootstrap dial itself does not authenticate the responding peer
  to the configured identity.
- `src/network/gossip.rs:90` — `enable_autodiscovery: false` is the
  in-code default. The field is undocumented in
  `config/sample.toml`.
- `docker-compose.mainnet.yml:23, 32` / `docker-compose.testnet.yml:24, 33`
  — production deployments are `read_node = true` and ship bare
  `/ip4/.../udp/.../quic-v1` bootstrap entries (no `/p2p/<peer-id>`).
- `Cargo.toml:50` — `libp2p = { ... features = [..., "mdns", ...] }`.
  `mdns` is enabled at the Cargo level but no `mdns::Behaviour` is
  instantiated; workspace grep for `Mdns`, `mdns::`, `MDNS` in
  `src/**` returns no matches. So mdns is dead code, not an active
  LAN-scoped poisoning vector.
- Grep for `kad`, `kademlia`, `Kademlia` in `src/**` returns no
  matches in the gossip / network layer. Kademlia is not used; the
  routing-table-seeding sub-vector of the attack class does not
  apply.

## Suggested remediation

1. **Bind the inner `peer_id` field to the libp2p sender.** At the top
   of `handle_contact_info`, after extracting `contact_info_body`,
   verify:

   ```rust
   let contact_peer_id = match PeerId::from_bytes(&contact_info_body.peer_id) {
       Ok(p) => p,
       Err(e) => {
           warn!("Malformed peer_id in contact info from peer {}: {:?}",
                 peer_id, e);
           return;
       }
   };
   if contact_peer_id != peer_id {
       warn!("Contact info peer_id mismatch: transport={} claims={}",
             peer_id, contact_peer_id);
       return;
   }
   ```

   This single check (a) eliminates the unwrap panic, (b) shuts the
   spoofing surface entirely (an attacker can only publish
   contact-info claiming its *own* libp2p peer-id, and the receiver
   already has a direct connection to that peer so doesn't need to
   redial), and (c) makes `self.peers` faithful to the actual peer
   set.

2. **Verify `gossip_address` against the libp2p connection's observed
   address.** After the peer-id binding above, additionally check
   that the multiaddr in `gossip_address` is plausibly related to
   the connection libp2p already has to `peer_id`. The simplest
   form: when receiving a `ConnectionEstablished` event, capture the
   observed remote multiaddr per peer; in `handle_contact_info`,
   require that `contact_info_body.gossip_address` share the same IP
   prefix (or is verifiably a NAT/announce variant of the observed
   address). This stops the DDoS-amplifier sub-vector.

3. **Use peer-id-pinned bootstrap addresses.** Update all production
   `docker-compose.*.yml` to use
   `/ip4/<ip>/udp/<port>/quic-v1/p2p/<peer-id>` form, and parse
   accordingly in `bootstrap_addrs`. Then change `dial` to
   `DialOpts::peer_id(expected).addresses(vec![parsed_addr]).build()`
   so the libp2p dial fails if a different identity answers. This
   plugs the MitM-at-bootstrap sub-vector.

4. **Remove `enable_autodiscovery` as a config knob, or — at minimum —
   gate it on a TOFU registry of seen peer-ids.** The legitimate
   use-case (growing a read-node fleet) is better served by a static
   per-region bootstrap list; the attack surface from a string-typed
   "dial whatever the network tells me to" toggle is large enough
   that the field should not be a tri-state per-node operator
   choice.

5. **Remove the `mdns` Cargo feature** at `Cargo.toml:50` since no
   `mdns::Behaviour` is ever constructed. This eliminates dead code
   and prevents accidental future wiring of an LAN-scoped poisoning
   vector.

6. **Disallow `direct_peers` outside a stricter validator-set
   handshake.** Document the precondition (these peers will be
   grafted unevictably into your mesh if they ever connect, so they
   must be peer-ids you control). Today the field is silently
   accepted from operator config with no documentation in
   `config/sample.toml`.

7. **Add a regression test** that:
   - Spins up a `read_node = true, enable_autodiscovery = true`
     gossip instance.
   - Connects a single libp2p peer to it.
   - From that peer, publishes 25 `ContactInfo` messages each with
     a *different* fabricated `peer_id` field and `gossip_address =
     /ip4/127.0.0.1/udp/<dead-port>/quic-v1`.
   - Asserts that the read-node has issued **at most one** outbound
     dial (to its actual bootstrap peer), not 25.
   - Today the test should fail with 25 dials.

## Confidence

**High.** The code path is short, the unauthenticated body fields
are clearly separated from the transport-layer signer, and the
absence of a sender-binding check is unambiguous. The eclipse vector
itself depends on `enable_autodiscovery = true` (operator opt-in) plus
the F017 mesh-scoring gap to be *durable* — but the panic vector
(line-759 unwrap on `peer_id` bytes) and the `self.peers` poisoning
vector (line 762) require no opt-in and reach every validator.
