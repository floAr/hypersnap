---
id: F019
task: H019
specialist: p2p-gossip
attack_class: gossip-message-size-no-cap
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.87
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Hyper gossip topics have no per-topic / per-message size bound; the only cap is the 10 MB libp2p `max_transmit_size` shared across every topic — an attacker on any topic can amplify 10x or more over its protocol-defined message size and grief the mesh

## Summary

`src/network/gossip.rs:43` defines a single transport-level cap:

```rust
const MAX_GOSSIP_MESSAGE_SIZE: usize = 1024 * 1024 * 10; // 10 mb
```

and passes it to the gossipsub `ConfigBuilder` at line 287:

```rust
.max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE)
```

That is the **only** size enforcement in the gossip ingress path. There
is no per-topic ceiling and no per-`HyperWireMessage::Body` variant
ceiling. Concretely:

1. `wire_to_event` (`src/hyper/gossip_adapter.rs:56-90`) is the
   application-level decoder for the four hyper topics. It receives
   `proto::HyperWireMessage` (already prost-decoded by
   `proto::GossipMessage::decode` in `src/network/gossip.rs:808`) and
   immediately dispatches by `body` variant. **It never inspects the
   serialized length** of the frame, nor of any sub-field. There is no
   `if encoded.len() > MAX_DKLS_ROUND` guard, no
   `if locks.len() > MAX_LOCKS_PER_BLOCK` guard, no
   `if block.envelope.payload.len() > MAX_BLOCK_PAYLOAD` guard.
2. The DKLS handlers consume `encoded: Vec<u8>` as opaque bytes
   (`actor.rs:1237-1267` for DKG, `1296-1316` for sign) and pass them
   straight into `open_dkls_round_message`. The AEAD will reject
   garbage, but **the wire frame can carry up to ~10 MB of bytes that
   pass prost-decode** (a single `bytes encoded = 3` field can be that
   large) before AEAD attempts to open it. Honest mesh peers
   *forward* the frame to all mesh-neighbours *before* AEAD-decode runs
   (since `validate_messages()` is not set on the gossipsub config —
   see F017), so an attacker spending CPU on one publish can force
   `mesh_n_high = 20` peers to each replicate ~10 MB.
3. The block topic accepts `HyperWireBlock { block, locks, transfers }`
   with `repeated HyperLockEvent locks = 2` and
   `repeated HyperTransferTx transfers = 3` (`gossip.proto:48-52`).
   Neither vector is length-bounded at decode time. The honest
   producer's `produce_envelope` path caps in-block messages at
   `MAX_MESSAGES_PER_BLOCK = 50_000` (`src/hyper/builder.rs:67, :238,
   :275`), but **`wire_to_event` does not check that bound on inbound
   frames** — an attacker can gossip a `HyperWireBlock` with 500_000
   locks (or one lock with a giant `dest_address` byte string) and the
   adapter will happily decode and forward.
4. The evidence topic accepts `HyperWireEvidence { block_a, block_b }`
   with two full nested `HyperBlock`s, each carrying an unbounded
   `bytes payload = 2` inside `HyperEnvelope`. There is no upper bound
   on the combined size; the only cap is the 10 MB transport cap, which
   permits two ~5 MB blocks. A real evidence pair, by construction, is
   the size of two block headers + their signatures (a few hundred
   bytes) — anything larger than that should be rejected, but is not.
5. The hyper-messages topic accepts a single `HyperMessage`
   (`gossip.proto:39`, `hyper.proto:1049`) whose `oneof body` variants
   each have a *protocol-defined* expected size — e.g. a
   `HyperLockEvent` is exactly 29+8+4+32+8+8+8+32 = 137 bytes of
   payload (`inbound_burn.rs:138` documents `payload_size_is_fixed`
   for the closely-related burn body), and a `HyperTransferTx` is a
   few hundred bytes plus a bullet-proof. Yet the adapter does not
   bound the inbound size against any of these per-variant expected
   sizes.

The 10 MB transport cap is **three to five orders of magnitude larger**
than the legitimate maximum for every hyper-topic frame type. An
attacker that controls a single peer subscribed to any hyper topic can
publish 10 MB-sized frames at the gossipsub publish rate (one per
heartbeat = two per second) and force every honest mesh-neighbour to
re-broadcast them onto the mesh. Combined with the absence of peer
scoring (see F017), the attacker pays zero scoring cost and continues
indefinitely. This is a textbook `gossip-message-size-no-cap` bug.

## Description

### 1. What the code does today

`src/network/gossip.rs:282-291`:

```rust
let gossipsub_config = gossipsub::ConfigBuilder::default()
    .heartbeat_interval(Duration::from_millis(500))
    .validation_mode(gossipsub::ValidationMode::Strict)
    .message_id_fn(message_id_fn)
    .max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE) // 10 MB, applies to every topic
    .mesh_n(10)
    .mesh_n_high(20)
    .build()
```

`max_transmit_size` is a global gossipsub setting — it caps the size of
any single `RPC` message gossipsub will accept on any topic. There is no
analogous per-topic configuration in libp2p-gossipsub 0.55, so to get
per-topic bounds the application must enforce them itself in the
inbound decode path.

The inbound decode path is:

1. `src/network/gossip.rs:625-639` — receives `gossipsub::Event::Message`,
   passes `message.data` (`Vec<u8>`) to
   `map_gossip_bytes_to_system_message`.
2. `src/network/gossip.rs:803-942` — `map_gossip_bytes_to_system_message`
   calls `proto::GossipMessage::decode(gossip_message.as_slice())` at
   `:808`. Prost decode runs on the full ≤ 10 MB buffer; prost's default
   recursion / length limits apply (no custom limits set anywhere in
   the workspace). On `Some(HyperWire(wire))` (`:889`) the wire is
   handed to `wire_to_event`.
3. `src/hyper/gossip_adapter.rs:56-90` — `wire_to_event`. Matches on
   `wire.body` and constructs a `HyperActorEvent`:

   ```rust
   pub fn wire_to_event(wire: proto::HyperWireMessage) -> Result<HyperActorEvent, AdapterError> {
       match wire.body.ok_or(AdapterError::MissingBody)? {
           proto::hyper_wire_message::Body::Block(b) => {
               let block_proto = b.block.ok_or(AdapterError::MissingBlock)?;
               let block = decode_hyper_block(block_proto)?;
               Ok(HyperActorEvent::InboundBlock {
                   block, locks: b.locks, transfers: b.transfers,
               })
           }
           proto::hyper_wire_message::Body::Message(m) => Ok(HyperActorEvent::InboundMessage(m)),
           proto::hyper_wire_message::Body::Dkg(d) => match d.round {
               WIRE_ROUND_DKLS => Ok(HyperActorEvent::InboundDkls { ..., encoded: d.encoded }),
               WIRE_ROUND_DKLS_SIGN => Ok(HyperActorEvent::InboundDklsSign { ..., encoded: d.encoded }),
               n => Err(AdapterError::InvalidDkgRound(n)),
           },
           proto::hyper_wire_message::Body::Evidence(e) => { ... }
       }
   }
   ```

   No `if encoded.len() > N`, no `if locks.len() > N`, no
   `if payload.len() > N` — every length field is whatever prost
   produced from the wire bytes.

The legacy snapchain topics (`consensus`, `mempool`, `decided-values`,
`read-node-peers`, `contact-info`) are the same story — every
`Some(...)` arm of the `proto::GossipMessage::decode` match
(`src/network/gossip.rs:809-936`) accepts the decoded body without a
size cross-check.

### 2. Why per-topic / per-variant size bounds matter

Each hyper-topic frame has a *deterministic* protocol-bounded size,
nowhere close to 10 MB:

| Topic                 | Frame variant         | Legitimate maximum size (approximate)                                                                                                                                                                                |
|-----------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `hyper/blocks/v1`     | `HyperWireBlock`      | A `HyperBlock` header (`HyperBlockMetadata` is ~200 bytes of fixed-shape fields plus three byte-vectors bounded by hash sizes: `parent_hash` 32 B, `hyper_state_root` 48 B, etc.) + `HyperBlockSignature` (~150 B incl. `signer_indices` ≤ committee size). Plus `locks` and `transfers` vectors with the proposer-enforced cap of `MAX_MESSAGES_PER_BLOCK = 50_000` items each. With a generous 256 B per lock and 1 KB per transfer (bulletproof-sized), a *full* block tops out near 50 KB to a few MB. The 10 MB transport cap is roughly 10x looser than the worst legitimate block. |
| `hyper/messages/v1`   | `HyperMessage`        | Each `oneof body` arm has a tight protocol-defined size: `HyperLockEvent` ~137 B (`inbound_burn.rs:138`), `HyperTransferTx` ~1 KB (note + bulletproof), `ValidatorEvent` ~200 B, `RewardIssuance` ~80 B, `TrustSnapshotUpdate` ~400 B. The largest legitimate body is bounded by a few KB. **10 MB is 10000x oversized.** |
| `hyper/dkg/v1`        | `HyperWireDkg.encoded`| A DKLS round message: Phase 1 fragment ~1 KB, Phase 2 broadcast ~16 KB, Phase 3 broadcast similar, plus a 96-byte AEAD wrapper (`dkls_wire_codec.rs:38-46`). The largest legitimate round message is a few tens of KB. **10 MB is 100x oversized.** |
| `hyper/evidence/v1`   | `HyperWireEvidence`   | Two `HyperBlock` headers + sigs. By construction evidence carries the *block headers*, not full block payloads — but the proto type is `HyperBlock` which includes `bytes payload = 2`, and the adapter accepts whatever payload bytes prost decodes. Legitimate evidence: a few KB. **10 MB is 1000x oversized.** |

The disparity matters because gossipsub *re-broadcasts every accepted
frame* to all `mesh_n` ≈ 10 mesh-neighbours. A peer that publishes one
10 MB frame on `hyper/dkg/v1` consumes:

- 10 MB egress for itself,
- ~10 × 10 MB = 100 MB egress for each first-hop honest validator,
- 10 × 10 MB at each subsequent hop until the dedupe TTL (`MessageId`
  derived from peer-id + sequence number, `gossip.rs:259-269`) prevents
  further fan-out.

At 2 publishes per second per peer (paced by the heartbeat), one
malicious peer forces every honest validator into the equivalent of a
200 MB/s bandwidth sink. With 100 connected peers (per the connection
limits in `gossip.rs:312-315`) and 20 of them malicious, the honest
validator's gossip subsystem is bandwidth-DoSed.

### 3. Where the per-variant decode path silently inflates

A second amplification surface: the *prost decoder* on the
`HyperWireDkg.encoded` field accepts ≤ ~10 MB of raw bytes (whatever
fits inside the outer `GossipMessage` envelope). The DKLS AEAD codec
(`dkls_wire_codec.rs`) then runs `DklsRoundMessage::from_bytes`
(`dkls_wire_codec.rs:216`, `:232`, `:270`, `:286`) on either the
plaintext bytes (broadcast) or the AEAD-decrypted bytes (P2P). The
bincode decoder used by `from_bytes` *does not* impose a per-field
length cap by default — a malicious `encoded` consisting of a few-byte
bincode header that claims a huge `Vec<u8>` inner length **will
allocate that vector** at decode time. (See bincode's
`DefaultOptions::default()`; it does honour limits if
`with_limit()` is called, but the workspace does not call it.)
This converts the 10 MB byte budget into an unbounded `Vec<u8>` allocation
inside the actor process, racing the OOM killer rather than the network
budget.

The grep evidence:

```
$ grep -rn "with_limit\|max_size\|bound_size\|max_alloc" \
       code/hypersnap/src/hyper/dkls_wire_codec.rs \
       code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs \
       code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs
# no hits
```

Same for the prost side: the workspace nowhere calls
`prost::DecodeOptions` or any equivalent length-bounding helper on the
inbound decode of `proto::GossipMessage`.

### 4. Why this isn't the same as F017

F017 (`F017-gossipsub-mesh-no-peer-scoring.md`) covers the mesh-shape
and scoring deficiencies that *amplify* a size-flood into an eclipse.
F019 is the upstream bug: even with peer scoring enabled, every honest
mesh-neighbour of the attacker still pays the bandwidth cost of one
10 MB publish *before* the score lookup decides to drop the next
publish. Per-topic / per-variant size bounds are the cheap defensive
constant that closes the per-publish amplification window. The two
findings are complementary.

### 5. Why this isn't the same as F018

F018 covers `sender-spoofing-inside-payload` — the inner `sender` byte
of DKLS round messages is not bound to the libp2p peer-id. F019 covers
the orthogonal "even if the sender is honest, the payload size is
unbounded" leg. The two compose: a Sybil that *also* spoofs sender
identity (F018) and *also* sends 10 MB payloads (F019) can grief the
ceremony at peak amplification.

### 6. Reachability

Every hyper topic is publicly reachable to any libp2p peer that
connects to a validator. There is no per-topic publish ACL: the
gossipsub `add_explicit_peer` calls (`gossip.rs:299-302`) only affect
the *direct-peers* set for active-fanout, not a publish allowlist.
A read-node attacker, a connected observer, or any newly-dialed peer
can publish on `hyper/dkg/v1`, `hyper/evidence/v1`,
`hyper/messages/v1`, or `hyper/blocks/v1` with arbitrary content up
to the 10 MB transport cap. (Topic-level ACL via `flood_publish` or a
gossipsub `publish_filter` is not used.)

## Impact

- **Liveness / bandwidth DoS — medium.** A single attacker peer (cost:
  one $5/month VPS) connected to a validator can flood the validator's
  mesh-neighbours with 10 MB frames at gossipsub-heartbeat rate. The
  validator's outbound bandwidth and the inbound bandwidth of every
  mesh-neighbour saturate. Sustained over hours, this is enough to
  knock a validator off-pace for block production and DKLS rounds.
  Combined with F017's missing peer scoring, the attacker is never
  evicted.
- **CPU DoS via prost / bincode decode — medium.** The 10 MB → decode
  → allocate path is uncapped; `DklsRoundMessage::from_bytes` and
  `prost::GossipMessage::decode` can be forced to allocate large
  intermediate buffers per-frame, multiplied by the mesh fan-out factor.
- **Targeted eclipse via mesh-saturation — low.** With F017 already
  documenting the missing peer scoring, F019 is the *force-multiplier*
  for that eclipse: when the validator's mesh slots are saturated
  forwarding attacker frames, honest publishers' frames get queued or
  dropped at the libp2p send-queue layer.
- **No state corruption.** The 10 MB cap still bounds memory per-frame
  to a finite (if generous) value, and downstream verifiers (AEAD,
  threshold-sig, `import_hyper_block`) reject malformed content. So
  this is a liveness / bandwidth class, not a safety class.

## Evidence

- `src/network/gossip.rs:43` — `MAX_GOSSIP_MESSAGE_SIZE = 1024 * 1024 * 10`
  (10 MB). The only application-side size constant in the gossip
  module.
- `src/network/gossip.rs:287` — sole consumer:
  `.max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE)` on the global
  gossipsub `ConfigBuilder`. Applies uniformly to every topic; no
  per-topic override exists in libp2p-gossipsub 0.55.
- `src/network/gossip.rs:803-942` — `map_gossip_bytes_to_system_message`.
  Decodes `proto::GossipMessage` via prost; every `Some(...)` arm
  builds a downstream `SystemMessage` or invokes
  `gossip_adapter::wire_to_event` *without first checking either the
  outer `gossip_message.len()` or any nested field's size against a
  per-variant expected max*.
- `src/hyper/gossip_adapter.rs:56-90` — `wire_to_event`. No size check
  on any of the four `Body::*` arms. The DKLS arms pass `d.encoded`
  through opaque; the block arm passes `b.locks`, `b.transfers`,
  `b.block.payload` through unbounded; the evidence arm passes two
  full `HyperBlock`s through unbounded.
- `proto/definitions/gossip.proto:48-72` — wire types for the four
  hyper-topic frames. Note `bytes encoded = 3` on `HyperWireDkg` and
  `repeated HyperLockEvent locks = 2`, `repeated HyperTransferTx
  transfers = 3` on `HyperWireBlock`: each is unbounded at the proto
  level.
- `proto/definitions/hyper.proto:99-102` — `HyperBlock` contains
  `HyperEnvelope` which contains `bytes payload = 2` — also
  unbounded.
- `src/hyper/builder.rs:62-67, 238, 275` — `MAX_MESSAGES_PER_BLOCK =
  50_000` is enforced **only on the proposer side** in
  `validate_block_size(...)`. The *importer* path
  (`HyperActorEvent::InboundBlock` → `runtime.import_block`,
  `actor.rs:1157-1172`) calls `import_block(&block, &locks, &transfers)`
  with whatever the gossip frame contained. `import_block`
  (`importer.rs`) verifies cryptographic integrity but does not
  pre-bound `locks.len()` / `transfers.len()` against
  `MAX_MESSAGES_PER_BLOCK`. (A separate vector-length bug — but it
  surfaces here.)
- `src/hyper/dkls_wire_codec.rs:216, 232, 270, 286` — bincode
  `DklsRoundMessage::from_bytes` / `DklsSignRoundMessage::from_bytes`
  invocations. Neither call site nor the bincode `DefaultOptions`
  default imposes a max-allocation cap. Grep for `with_limit`,
  `bound_size`, `max_alloc` over `src/hyper/` and
  `crates/hypersnap-crypto/` returns zero hits.
- `src/hyper/actor.rs:1237-1267, 1296-1316` — DKLS dispatch arms
  consume `encoded: Vec<u8>` opaque; no upfront length check before
  passing to `open_dkls_round_message`.
- `Cargo.toml:50` — `libp2p = "0.55.0"`. The 0.55 gossipsub crate has
  no per-topic `max_transmit_size`; per-topic bounds must be enforced
  by the application.

## Suggested remediation

1. **Per-topic / per-variant size constants.** Define expected-maximum
   constants in `src/hyper/topics.rs` (or alongside in a new
   `src/hyper/topic_limits.rs`) — one per (topic, body-variant)
   combination:

   ```rust
   pub const MAX_DKLS_ROUND_BYTES:        usize = 64 * 1024;   // 64 KB
   pub const MAX_HYPER_MESSAGE_BYTES:     usize = 16 * 1024;   // 16 KB
   pub const MAX_HYPER_BLOCK_FRAME_BYTES: usize = 4  * 1024 * 1024; // 4 MB (50k locks @ ~80 B each)
   pub const MAX_HYPER_EVIDENCE_BYTES:    usize = 16 * 1024;   // 16 KB (two headers + sigs)
   ```

   The constants should be ceiling estimates that comfortably exceed
   the largest legitimate frame for each variant, but tens-to-hundreds
   of times tighter than the 10 MB transport cap.

2. **Enforce in `wire_to_event`.** Before constructing each
   `HyperActorEvent`, check the relevant length:

   ```rust
   match wire.body.ok_or(AdapterError::MissingBody)? {
       Body::Dkg(d) => {
           if d.encoded.len() > MAX_DKLS_ROUND_BYTES {
               return Err(AdapterError::DklsCodec(format!(
                   "encoded too large: {}", d.encoded.len()
               )));
           }
           // ...existing match on d.round
       }
       Body::Block(b) => {
           if b.locks.len() > MAX_MESSAGES_PER_BLOCK
               || b.transfers.len() > MAX_MESSAGES_PER_BLOCK {
               return Err(AdapterError::BlockTooManyEntries);
           }
           if let Some(block) = &b.block {
               if let Some(env) = &block.envelope {
                   if env.payload.len() > MAX_HYPER_BLOCK_PAYLOAD_BYTES {
                       return Err(AdapterError::BlockPayloadTooLarge);
                   }
               }
           }
           // ...existing decode
       }
       Body::Message(m) => {
           // Encoded length check after re-serialization, or per-variant cap.
           let enc_len = m.encoded_len();
           if enc_len > MAX_HYPER_MESSAGE_BYTES {
               return Err(AdapterError::MessageTooLarge { len: enc_len });
           }
           Ok(HyperActorEvent::InboundMessage(m))
       }
       Body::Evidence(e) => {
           let enc_len = e.encoded_len();
           if enc_len > MAX_HYPER_EVIDENCE_BYTES {
               return Err(AdapterError::EvidenceTooLarge { len: enc_len });
           }
           // ...existing decode
       }
   }
   ```

   The new `AdapterError` variants are reported back to gossipsub as
   `MessageAcceptance::Reject` once F017 enables peer scoring —
   converting size-flood into a scoring penalty.

3. **Cap inbound bincode allocations.** Configure the bincode used by
   `DklsRoundMessage::from_bytes` with
   `bincode::DefaultOptions::new().with_limit(MAX_DKLS_ROUND_BYTES as
   u64)` so that a 4-byte header claiming a 4 GB inner `Vec<u8>`
   fails fast rather than allocating.

4. **Cap prost recursion / length on the outer decode.** prost honours
   `prost::Message::decode` with an explicit budget if used via a
   `bytes::Buf` reader with a `Buf::take(n)`. Wrap the inbound
   `gossip_message: Vec<u8>` with
   `let mut buf = &gossip_message[..MAX_GOSSIP_MESSAGE_SIZE];` or
   reject up-front if `gossip_message.len() > MAX_GOSSIP_MESSAGE_SIZE`
   (it already cannot exceed the transport cap, but a defence-in-depth
   pre-check makes the relationship explicit).

5. **Lower `MAX_GOSSIP_MESSAGE_SIZE`.** Once per-topic bounds are
   enforced, the global cap can drop from 10 MB to ~4 MB (the worst
   legitimate hyperblock frame) — reducing the bandwidth per-publish
   ceiling everywhere.

6. **Regression test.** A `tests::wire_to_event_rejects_oversized_dkg`
   test that constructs a `HyperWireMessage::Dkg(d)` with
   `d.encoded = vec![0u8; 1024 * 1024]` and asserts
   `wire_to_event(wire)` returns an `AdapterError::DklsCodec(_)`
   (or new `DklsRoundTooLarge` variant). Mirror tests for the other
   three variants.

## Confidence

**Medium.** The absence of size enforcement is objectively present in
`wire_to_event` and `map_gossip_bytes_to_system_message`, and the 10 MB
transport cap is many orders of magnitude looser than any legitimate
per-topic frame. Exploit cost is low (one peer, one connection, one
publish per heartbeat). Impact is liveness / bandwidth amplification,
not safety — bounded above by the 10 MB transport cap but unbounded
in time. Worth fixing; not a critical-severity bug because the
threshold-sig and importer verifiers still close the safety surface.
