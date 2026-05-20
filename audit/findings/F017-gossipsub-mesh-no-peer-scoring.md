---
id: F017
task: H017
specialist: p2p-gossip
attack_class: topic-mesh-poisoning
severity: medium
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.78
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Gossipsub mesh has no peer-scoring, no outbound-min, and no app-level validation gate — Sybil mesh-poisoning eclipses hyper consensus topics

## Summary

The single libp2p gossipsub `Behaviour` that carries every snapchain *and*
hyper-layer topic is built without any of the libp2p-gossipsub defences
that exist specifically to resist topic-mesh-poisoning and eclipse
attacks. Concretely, in `src/network/gossip.rs:282-291`:

```rust
let gossipsub_config = gossipsub::ConfigBuilder::default()
    .heartbeat_interval(Duration::from_millis(500))
    .validation_mode(gossipsub::ValidationMode::Strict)
    .message_id_fn(message_id_fn)
    .max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE)
    .mesh_n(10)
    .mesh_n_high(20)
    .build()
    ...

let mut gossipsub = gossipsub::Behaviour::new(
    gossipsub::MessageAuthenticity::Signed(key.clone()),
    gossipsub_config,
)?;
```

What is *not* configured:

1. **No peer scoring.** `gossipsub.with_peer_score(...)` is never called
   anywhere in the workspace (grep over the crate finds zero hits for
   `with_peer_score`, `PeerScoreParams`, `PeerScoreThresholds`). Without
   peer scoring, libp2p-gossipsub has no mechanism to *evict* an
   ill-behaved peer from a topic mesh: every peer that opens a stream and
   sends a `GRAFT` is grafted in, every peer that sends a `PRUNE` survives
   the next round, and every peer that simply spams `IHAVE/IWANT` floods
   the receiver's bandwidth. This is the **single most important
   defensive mechanism in libp2p-gossipsub**, and it is absent.

2. **`mesh_n_low` and `mesh_outbound_min` use defaults.** The code
   overrides `mesh_n(10)` and `mesh_n_high(20)` but leaves `mesh_n_low`
   at its default of `5` and `mesh_outbound_min` at its default (1, in
   libp2p-gossipsub 0.55). That means an honest validator's mesh on
   `hyper/dkg/v1` (or any other hyper topic) is allowed to consist of
   **as few as 1 outbound-dialed peer**. An attacker that controls a
   single Sybil cluster the validator dials into, plus floods the
   validator with inbound GRAFTs, can dominate the *inbound* side of the
   mesh while leaving only one honest outbound link — which can be
   selectively dropped/disrupted at the transport layer (BGP, link
   flooding, …) to complete the eclipse.

3. **No application-level validation gate.** `validate_messages()` is
   never called on the `ConfigBuilder`. In libp2p-gossipsub, this means
   every decoded frame is *forwarded to subscribers* (re-emitted onto the
   mesh) **immediately upon successful decode**, before any application-
   level signature / structural validation runs. The application
   receives the message via the `gossipsub::Event::Message` event in
   parallel with — and *not before* — the propagation step. There is
   therefore no negative-feedback channel for an honest node to tell
   gossipsub "this peer just sent me a malformed/forged frame, lower
   its score" — and even if there were (see point 1), it would not
   matter, because the malicious frame has already been replicated to
   the whole mesh.

4. **Heartbeat interval is 1/6 of the typical recommendation.** The
   config sets `heartbeat_interval(500ms)` — the libp2p-gossipsub
   default is 1 second; the comment in this code admits "This might need
   to be lowered to 1/3 of the block time", so the 500 ms is a
   throughput tweak. Combined with mesh churn from inbound GRAFTs and
   no scoring, the heartbeat ticks fire `mesh_heartbeat` (mesh
   maintenance) roughly twice as often, accelerating any mesh-poisoning
   attack the attacker can wage with low-cost Sybils.

The four hyper-layer topics (`hyper/blocks/v1`, `hyper/messages/v1`,
`hyper/dkg/v1`, `hyper/evidence/v1` — `src/hyper/topics.rs:10-23`) ride
on this *same* gossipsub instance with no per-topic mesh parameters or
peer-scoring weights, so the eclipse story is uniform across all of
them. The DKG topic is the highest-value target: a validator eclipsed
from `hyper/dkg/v1` cannot participate in DKLS-DKG or threshold-sign
rounds and is treated as offline; an attacker who eclipses ≥ `1 + N - t`
validators from this topic stalls the entire ceremony (per
`crates/hypersnap-crypto/src/dkls_ceremony.rs` accumulator semantics).
Eclipse on `hyper/blocks/v1` starves a validator of new blocks and
forces it onto the sync (request/response) path, where it depends on
its *outbound* peer set for catch-up — and the outbound peer set is
exactly the surface point (2) compromises.

## Description

### 1. Peer scoring — the load-bearing defence that is absent

libp2p-gossipsub's resistance to mesh-poisoning, eclipse, and Sybil-based
liveness attacks rests almost entirely on the peer-scoring subsystem
introduced in the gossipsub v1.1 spec (the "GossipSub Hardening"
amendment). The scoring system tracks per-peer:

- mesh-time-in-topic
- first-message-deliveries-per-topic
- mesh-message-deliveries-per-topic (deficit metric: under-delivering
  peers are penalised)
- invalid-message-deliveries-per-topic
- IP-colocation factor
- application-specific score (set via
  `behaviour.set_application_score(peer, score)`)

…and uses thresholds (`gossip_threshold`, `publish_threshold`,
`graylist_threshold`, `accept_px_threshold`, `opportunistic_graft_threshold`)
to *evict* below-threshold peers from meshes and to refuse IHAVE/IWANT
from low-score peers.

When `with_peer_score` is never called, **all of this is disabled.**
`gossipsub::Behaviour::peer_score` is `None`. The `score_below_threshold`
function — checked at every GRAFT / IWANT / mesh-membership decision —
always returns `(0.0, false)` for every peer, so every threshold check
trivially passes. There is no eviction, no IP-colocation deduplication,
no application-feedback channel.

This means:

- An attacker that opens N TCP/QUIC streams from N Sybil IPs to a
  target validator will be GRAFTed into the validator's meshes on
  every topic it subscribes to (up to `mesh_n_high = 20` peers per
  topic — once the mesh exceeds 20, gossipsub randomly prunes back to
  `mesh_n = 10`, but the prune is *random* with no scoring weight, so
  honest peers are pruned at the same rate as Sybils).
- The IP-colocation factor that would normally deduplicate "all 20 mesh
  peers come from the same /24" is not applied.
- An attacker that publishes a malformed `HyperWireMessage` (e.g.
  `MissingBody`, `InvalidDkgRound(99)`) — both of which the adapter
  rejects at `src/hyper/gossip_adapter.rs:80, :432` — pays zero
  scoring cost because there is no scoring feedback path.

### 2. Where the mesh parameters fall short

`src/network/gossip.rs:288-289`:

```rust
.mesh_n(10)
.mesh_n_high(20)
```

That's the full mesh-shape configuration. Implicitly:

- `mesh_n_low` defaults to **5** (libp2p-gossipsub 0.55 `Config::default`).
- `mesh_outbound_min` defaults to **1** in libp2p-gossipsub 0.55
  (`max(mesh_n_low / 2, 1)` rounded down would give 2, but the
  documented default is `mesh_n / 2` = 3 for the default `mesh_n=6`;
  with a custom `mesh_n=10` and no explicit override, the actual
  constructor uses `min(mesh_n_low / 2, mesh_n)` which evaluates to 1
  with `mesh_n_low=5`). Either way the **outbound-dialed peer floor is
  far below the recommended `mesh_n / 4`**.
- `gossip_lazy` defaults to **6** — but with no peer scoring this
  control surface is moot, since lazy IHAVE peers cannot be selected by
  score and are picked randomly.
- `prune_peers` defaults to **0** — so when an honest validator's mesh
  is over-full, the prune message it sends does NOT include any peer
  exchange (PX) replacements. An attacker can therefore force a
  mesh-overflow → random-prune → empty-mesh oscillation by repeatedly
  GRAFTing.

The Filecoin lotus, Eth2 lighthouse / prysm, and Cosmos hub gossipsub
parameter sets all override these (Eth2 explicitly sets
`mesh_outbound_min = 2`, `D_lazy = 6`, plus a full peer-score table).
This codebase does not.

### 3. No `validate_messages()` → no application-feedback channel

`gossipsub::ConfigBuilder::validate_messages()` would set the gossipsub
behaviour to *not* re-emit a decoded message to mesh peers until the
application explicitly calls
`gossipsub.report_message_validation_result(MessageAcceptance::Accept/Reject/Ignore)`.

Without that call:

- libp2p-gossipsub forwards every successfully-decoded frame to mesh
  peers immediately, before any signature / structural / replay /
  field-coverage check runs at the application layer.
- There is no `Reject` path that would lower a sender's score (even if
  scoring were enabled).
- The application cannot rate-limit propagation. A peer that gossips a
  thousand structurally-valid-but-semantically-garbage `HyperMessage`
  body variants per second forces every mesh-neighbour to re-broadcast
  them all.

Combined with point (1), this means there is no feedback loop *at all*
between the application's verdict on a message and gossipsub's
treatment of the sender. Every peer is treated identically forever.

### 4. Heartbeat at 500ms — accelerates mesh churn under attack

`src/network/gossip.rs:284`:

```rust
.heartbeat_interval(Duration::from_millis(500))
```

`mesh_heartbeat` runs every 500ms instead of the default 1 second. Each
heartbeat tick prunes meshes above `mesh_n_high`, grafts to fill below
`mesh_n_low`, and emits `IHAVE` messages. Doubling that frequency:

- Doubles the rate at which an attacker who spams GRAFTs gets re-grafted
  after honest prunes.
- Doubles the rate at which random-prune (no scoring) removes honest
  peers from over-full meshes.
- Doubles the IWANT-flood bandwidth a low-score peer can extract from
  the validator.

The comment on this line (`This might need to be lowered to 1/3 of the
block time`) suggests the maintainer chose 500ms for sync-speed reasons.
That's a sensible *throughput* knob to turn — but combined with absent
scoring, it makes mesh attacks cheaper.

### 5. Why this matters for the hyper layer

Each of the four hyper topics is a single-point-of-failure for a
specific protocol surface:

- **`hyper/blocks/v1`** — eclipse means the validator stops seeing new
  hyperblock proposals and must fall back to sync-via-request-response.
  Sync only contacts a small set of peers (the sync-request path in
  `src/consensus/malachite/read_sync.rs`), so a Sybil-cluster in the
  sync peer set converts eclipse-from-gossip into eclipse-from-sync.
- **`hyper/messages/v1`** — eclipse means the validator's mempool
  receives no inbound locks, transfers, validator-events, reward
  issuances, or trust snapshots, so its next block proposal is
  artificially empty. Combined with the snapchain-side mempool being
  on a separate topic (`MEMPOOL_TOPIC`), this also lets an attacker
  censor a specific hyper-layer event-type from a specific validator.
- **`hyper/dkg/v1`** — eclipse from this topic prevents DKG / DKLS-sign
  round messages from reaching the validator. The ceremony coordinator
  accumulates `BTreeMap<u8, T>` indexed by `sender` index
  (`dkls_ceremony.rs:333-394`, `dkls_sign.rs:255-282`); a missing
  sender's contribution makes the ceremony stall (`try_advance` only
  fires when the accumulator covers `share_count` parties). An attacker
  needs only to keep `share_count - t + 1` honest parties offline-via-
  eclipse from this topic to stall a sign-round indefinitely.
- **`hyper/evidence/v1`** — eclipse on this topic silently suppresses
  slashing-evidence delivery to the validator. The validator continues
  participating but accepts (and signs) blocks from validators it
  *would* have slashed had the evidence reached it. Combined with the
  `ConflictingBlocksEvidence` flow (see `H001-ruled-out.md`), this is
  particularly nasty because it converts "honest network catches
  equivocator → evicts" into "honest network fails to catch equivocator
  → equivocation persists".

### 6. Subscribe pattern: is it fail-closed?

A separate piece of the topic-mesh-poisoning question is whether the
*subscribe* path admits attacker-chosen topics.

`src/network/gossip.rs:386-394, 423-440` shows the subscriber loops:

```rust
let topics: &[&str] = if validator {
    crate::hyper::topics::all_validator_topics()
} else {
    crate::hyper::topics::all_observer_topics()
};
for t in topics {
    let topic = gossipsub::IdentTopic::new(*t);
    if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
        warn!("Failed to subscribe to hyper topic {}: {:?}", t, e);
    }
}
```

This is fine: topics are *hard-coded constants* from `src/hyper/topics.rs`,
not derived from peer input. There is no wildcard, no regex, no
peer-influenced topic-name. The `gossipsub::IdentTopic::new(...)` call
takes a static `&str`. The consumer side (`map_gossip_bytes_to_system_message`,
`src/network/gossip.rs:803-942`) also fail-closes on unknown
`proto::GossipMessage` variants (`None` arm at `:932-935` warns + drops,
`HyperEnvelope` arm at `:882-887` warns + drops). The wire-to-event
adapter (`src/hyper/gossip_adapter.rs:56-90`) fail-closes on unknown
DKG-round numbers (`InvalidDkgRound(n)`).

So the **subscribe / topic-name** side of the question is healthy.
The **mesh-membership / scoring** side is not.

### 7. Reachability of the attack

The bridging requirement for this attack class is "an attacker who
controls enough peers". Concretely:

- libp2p connection limits are set to **100 incoming, 100 outgoing**
  (`src/network/gossip.rs:312-315`). A Sybil cluster of 80+ IPs (cheap
  on residential proxy networks or a small DigitalOcean fleet) saturates
  the inbound capacity of a target validator.
- The bootstrap-peers list is operator-configured (`bootstrap_peers`
  in `Config`, `src/network/gossip.rs:64-66`). If the operator
  configures only a handful of bootstrap peers, an attacker who
  compromises any one of them has an enormous advantage in being the
  first peer in the new node's mesh. (This is the
  `peer-discovery-eclipse` corner of the attack class, which
  `H016-ruled-out.md` does not address.)
- `enable_autodiscovery` is **off by default** for validators
  (`src/network/gossip.rs:90`) — so validators only ever talk to
  the operator-configured bootstrap set. Good. But read-nodes have
  it on by default in some deployments, so a read-node fleet can be
  dialed into and used as an amplification surface for IHAVE-flooding
  the validator set.

## Impact

- **Liveness — medium.** A Sybil-rich attacker (cost: low-thousands of
  USD/month for ~100 distinct IPs across multiple ASes) can eclipse a
  *single* validator from any one of the four hyper topics, with the
  worst case being `hyper/dkg/v1`: the eclipsed validator becomes
  unable to participate in DKG or threshold-sign rounds, which forces
  the active set to operate without it. If the same attacker eclipses
  > `n - t` validators from `hyper/dkg/v1` (with current `n=committee
  size`, `t=committee threshold`), the entire signing pipeline stalls
  until manual operator intervention.
- **Censorship — medium.** Eclipse from `hyper/messages/v1` lets the
  attacker selectively starve a validator of *inbound* messages of a
  given variant, e.g. specifically suppressing `RewardIssuance` while
  letting `Lock` events through. The eclipsed validator then proposes
  blocks that omit those messages, and unless quorum catches the
  omission (via the importer's content-coverage checks), the omission
  is consensus-laundered.
- **Slashing-evidence suppression — medium.** Eclipse from
  `hyper/evidence/v1` silently de-fangs the slashing pipeline against
  the eclipsed validator's view. The validator continues signing blocks
  from a peer it would otherwise have slashed.
- **Not safety.** Threshold-sigs are still verified end-to-end on
  import (`importer.rs:246-258`), so an eclipsed validator cannot be
  tricked into accepting forged blocks. The attack class here is
  liveness + censorship, not state corruption.
- **No remote code execution / panic** path observed from mesh poisoning
  directly. Some of the unwraps in upstream consensus (see F002, F005)
  *can* be triggered via gossip ingress, but those are independent
  attack classes.

## Evidence

- `src/network/gossip.rs:282-291` — the gossipsub `ConfigBuilder` chain,
  showing `validation_mode(Strict)`, `mesh_n(10)`, `mesh_n_high(20)`,
  `max_transmit_size(10 MB)`, and **no** `with_peer_score` /
  `mesh_n_low` / `mesh_outbound_min` / `validate_messages` /
  `flood_publish` calls.
- `src/network/gossip.rs:294-297` — the `Behaviour::new` constructor.
  No `with_peer_score(...)` follow-up call anywhere in the module.
- Workspace-wide grep confirms zero hits for `with_peer_score`,
  `PeerScoreParams`, `PeerScoreThresholds`, `validate_messages`,
  `report_message_validation_result`, `flood_publish`, `gossip_lazy`,
  `mesh_outbound_min`, `mesh_n_low`. (See methodology grep in
  `findings/notes/H017-ruled-out.md`.)
- `src/network/gossip.rs:312-315` — connection limits set to 100/100,
  which is what makes an 80+ Sybil cluster sufficient to dominate the
  inbound surface.
- `src/network/gossip.rs:308` — comment "Connection limits are set high
  so that we don't keep kicking off read nodes for now" — acknowledges
  the trade-off without addressing the mesh-poisoning surface that the
  trade-off opens.
- `src/network/gossip.rs:423-440` — `attach_hyper_actor` subscribes to
  the static list returned by `topics::all_validator_topics()`. The
  same gossipsub instance carries every topic.
- `src/hyper/topics.rs:10-23` — hard-coded topic constants; subscriber
  side is fail-closed on unknown topic names (good — not part of the
  bug).
- `src/hyper/gossip_adapter.rs:56-90` — `wire_to_event` fail-closes on
  unknown DKG rounds (good — not part of the bug). However, it has
  no path to *report* a malformed frame back to gossipsub for scoring,
  so the failed-decode penalty does not exist.
- `Cargo.toml:50` — `libp2p = { version = "0.55.0", features = [..."gossipsub"...] }`.
  Version pins the surface to the libp2p-gossipsub 0.55 defaults
  (`mesh_n_low=5`, no scoring, `mesh_outbound_min` derived from
  `mesh_n_low`).

## Suggested remediation

1. **Enable peer scoring.** After `gossipsub::Behaviour::new`, call:

   ```rust
   let peer_score_params = gossipsub::PeerScoreParams {
       topics: HashMap::from([
           (TOPIC_HYPER_BLOCKS.into(), topic_params_blocks()),
           (TOPIC_HYPER_DKG.into(),    topic_params_dkg()),
           (TOPIC_HYPER_MESSAGES.into(), topic_params_messages()),
           (TOPIC_HYPER_EVIDENCE.into(), topic_params_evidence()),
           // and snapchain topics
       ]),
       behaviour_penalty_weight:   -16.0,
       behaviour_penalty_threshold: 6.0,
       behaviour_penalty_decay:     0.999,
       app_specific_weight:         1.0,
       ip_colocation_factor_weight: -5.0,
       ip_colocation_factor_threshold: 10.0,
       decay_interval: Duration::from_secs(1),
       decay_to_zero:  0.01,
       retain_score:   Duration::from_secs(3600),
       ..Default::default()
   };
   let peer_score_thresholds = gossipsub::PeerScoreThresholds {
       gossip_threshold:               -4000.0,
       publish_threshold:              -8000.0,
       graylist_threshold:           -16_000.0,
       accept_px_threshold:           1000.0,
       opportunistic_graft_threshold:   100.0,
   };
   gossipsub.with_peer_score(peer_score_params, peer_score_thresholds)?;
   ```

   The exact constants are protocol-specific tuning; the Eth2 lighthouse
   and Filecoin lotus parameter sets are reasonable starting points.
   For `hyper/dkg/v1` and `hyper/evidence/v1` (low-volume, high-trust
   topics), set `mesh_message_deliveries_threshold` low and
   `invalid_message_deliveries_weight` aggressive.

2. **Set `validate_messages()` in the `ConfigBuilder`,** and add a
   gossipsub-feedback callback at the end of the application's per-
   message validation. Example shape in `map_gossip_bytes_to_system_message`
   and `gossip_adapter::wire_to_event`:

   ```rust
   match wire_to_event(wire) {
       Ok(event) => {
           tx.try_send(event)?;
           gossipsub.report_message_validation_result(
               &msg_id, &peer_id, MessageAcceptance::Accept);
       }
       Err(AdapterError::InvalidDkgRound(_)) | Err(AdapterError::MissingBody) => {
           gossipsub.report_message_validation_result(
               &msg_id, &peer_id, MessageAcceptance::Reject);
       }
       Err(_) => {
           gossipsub.report_message_validation_result(
               &msg_id, &peer_id, MessageAcceptance::Ignore);
       }
   }
   ```

   Without `validate_messages()`, gossipsub forwards before the app
   can react. With it, the forward only happens on `Accept`, and
   `Reject` lowers the sender's score.

3. **Explicitly set `mesh_n_low`, `mesh_outbound_min`, and `gossip_lazy`.**
   For a validator population of (typical Snapchain/Hypersnap target)
   ~25–100 validators, recommended values (matching Eth2):

   ```rust
   .mesh_n_low(6)
   .mesh_n(8)
   .mesh_n_high(12)
   .mesh_outbound_min(2)
   .gossip_lazy(6)
   ```

   Current `mesh_n(10), mesh_n_high(20)` is *high* for a small
   validator set — it forces the mesh to be most of the validator
   population, which is bandwidth-heavy and doesn't materially improve
   delivery once `mesh_n` ≥ 8. Lowering `mesh_n_high` to 12 and
   explicitly setting `mesh_outbound_min(2)` improves the Sybil
   surface: an attacker now needs to dominate *both* the outbound side
   (which they cannot, because the validator dials its own outbounds)
   *and* the inbound side to fully eclipse a topic.

4. **Bind application score to validator-identity.** When a peer's
   libp2p peer-id maps (via contact-info / validator-registry) to a
   known validator's Ed25519 identity key, set
   `gossipsub.set_application_score(peer_id, +5000.0)` to deprioritise
   evicting known validators in favour of evicting unknown Sybils.
   Currently no application-score is set for any peer.

5. **Reduce libp2p connection limits to a sensible per-peer cap.**
   The 100/100 in `src/network/gossip.rs:313-314` is documented as a
   "Connection limits are set high so that we don't keep kicking off
   read nodes for now" workaround. Combined with absent scoring, this
   gives an attacker plenty of inbound capacity to dominate. Either
   set up a separate `read-node` topic with relaxed limits, or set the
   gossip-instance inbound limit to ≤ 32 with a `mesh_outbound_min`
   floor of 2.

6. **Add an IP-colocation guard at the libp2p dial layer.** Even with
   peer scoring, an attacker that bridges a Sybil cluster through a
   single front-end IP defeats `ip_colocation_factor`. Track
   per-`/24` connection counts at dial time and refuse to dial into a
   `/24` already represented in the connected-peer set.

7. **Set `prune_peers` ≥ 8.** When pruning a mesh, gossipsub will
   then include 8 PX (peer-exchange) hints in the prune message, so
   the pruned peer can find replacement peers; this slows the
   mesh-overflow → empty-mesh oscillation an attacker can force.

8. **Add a regression test** that constructs a 21-Sybil cluster, has
   each Sybil GRAFT into the validator's `hyper/dkg/v1` mesh, and
   asserts that at least 4 honest peers remain in the mesh after one
   heartbeat (this requires peer scoring + outbound-min to pass; with
   the current configuration the test should fail today).

## Confidence

**Medium.** The configuration deficiencies are objectively present and
documented above. The exploit cost (Sybil-cluster + bandwidth) is
non-trivial but well within the reach of any nation-state-class or
even any motivated DeFi-bridge-attacker adversary. The impact ceiling
is bounded by the threshold-sig safety verification on the importer
side — so this is firmly a liveness / censorship class, not state
corruption.
