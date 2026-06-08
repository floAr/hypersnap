# F016 — Reachability trace

Finding: F023a pre-StartDkls buffer keyed by attacker-controlled `target_epoch`
with no global epoch-key cap / eviction → unbounded memory growth.
Audited commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`.
Stage: trace only (verdict unchanged: WATERPROOF, High).

## Entry point(s)

Untrusted ingress is the public gossipsub topic `hyper/dkg/v1`.

- Topic constant: `code/hypersnap/src/hyper/topics.rs:18` — `TOPIC_HYPER_DKG = "hyper/dkg/v1"`.
- Wire decode of a received gossipsub frame on that topic:
  `code/hypersnap/src/network/gossip.rs:1099` —
  `Some(GossipMessage::HyperWire(wire)) => { ... }`.

Any libp2p peer that connects and subscribes to the mesh can publish here;
`hyper/dkg/v1` is a normal public gossipsub topic. The "validators-only /
peer-restricted" notes in `topics.rs:16,36` describe only which topics *this*
node subscribes to — there is no publish-side allow-list or committee gate.

## Trust boundary crossed

Network (remote, mutually-untrusted gossipsub peer) → in-process actor state.
Gossipsub `ValidationMode::Strict` + signed messages authenticate the
*publishing peer-id* only; they do not restrict *who* may publish, and the
buffering branch in the actor runs **before** any DKLS codec decrypt /
F018 sender↔peer-id cross-check. So the boundary is crossed with the payload
still unauthenticated at the application layer.

## Call path

1. `code/hypersnap/src/network/gossip.rs:1099` — gossipsub event handler,
   `HyperWire` arm. A frame received on `hyper/dkg/v1` enters here.
2. `code/hypersnap/src/network/gossip.rs:1100-1108` — size guard:
   `wire.encoded_len() > MAX_HYPER_WIRE_BYTES (512 KB)` → drop. Per-frame cap
   only; does not bound key count.
3. `code/hypersnap/src/network/gossip.rs:1120-1123` — calls
   `gossip_adapter::wire_to_event_with_source(wire, Some(sender_bytes))`.
4. `code/hypersnap/src/hyper/gossip_adapter.rs:80,84-88` —
   `Body::Dkg(d)` + `WIRE_ROUND_DKLS` ⇒ builds
   `HyperActorEvent::InboundDkls { target_epoch: d.target_epoch, encoded: d.encoded, propagation_source }`.
   `target_epoch` is copied verbatim from the wire `proto::HyperWireDkg`; no
   range / committee / current-epoch validation. Full `u64` reachable.
5. `code/hypersnap/src/network/gossip.rs:1125` —
   `tx.try_send(event)` onto the bounded `hyper_actor_tx` channel (rate-limits
   ingestion only; does not bound actor-resident state).
6. `code/hypersnap/src/hyper/actor.rs:1321-1325` — actor `dispatch` arm
   `HyperActorEvent::InboundDkls { target_epoch, encoded, propagation_source }`.
7. `code/hypersnap/src/hyper/actor.rs:1329-1334` — computes `is_active`
   (true only if a live ceremony's `driver.target_epoch() == target_epoch`).
   For any attacker-chosen epoch with no active ceremony, `is_active == false`.
8. **Sink** — `code/hypersnap/src/hyper/actor.rs:1335-1337` —
   `let buf = self.pending_dkls_inbound.entry(target_epoch).or_default(); buf.push(encoded);`
   then `return Ok(())` at `:1345`, **before** `open_dkls_round_message`
   (decrypt/auth, `:1358`) and the F018 sender check (`:1373`). A fresh `Vec`
   (up to 256 × ≤512 KB) is allocated per distinct attacker `target_epoch`.

Field: `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>` —
`code/hypersnap/src/hyper/actor.rs:1004`.

Sole removal path: `code/hypersnap/src/hyper/actor.rs:1430` —
`self.pending_dkls_inbound.remove(&target)` inside the `StartDkls` arm. Only
the honest supervisor emits `StartDkls`, and only for the bounded window
`first_undispatched..=next_epoch` (`dkls_supervisor.rs:119-150`), so
far-future / non-member epochs are never drained.

## Attacker capability / preconditions

- Be a connected libp2p peer subscribed to `hyper/dkg/v1` (open public mesh
  topic). No committee membership, no transport secret, no valid DKLS frame.
- Emit `HyperWireDkg` frames with `round = WIRE_ROUND_DKLS` and a distinct,
  arbitrary `target_epoch` per frame (e.g. far-future or non-member epochs).
- `encoded` may be arbitrary bytes ≤512 KB; it is buffered verbatim pre-auth.
- By varying `target_epoch`, allocate unboundedly many never-drained per-epoch
  buffers → allocator pressure / OOM on every subscribed node (DKG /
  threshold-signing liveness DoS).

## Guards on the path

- `MAX_HYPER_WIRE_BYTES = 512 KB` per frame (`gossip.rs:52,1100`) — bounds
  per-entry size, not key count.
- `PENDING_DKLS_INBOUND_CAP_PER_EPOCH = 256` per epoch
  (`actor.rs:1045,1336`) — bounds entries *within one epoch*, not the number
  of distinct epoch keys.
- Gossipsub Strict signing + F017 peer scoring (`gossip.rs:314,324,328-343`) —
  authenticate peer-id and give generic rate protection, but the buffer path
  returns `Ok(())` with no `report_message_validation_result(...Reject)`
  (grep: zero matches in `gossip.rs`), so junk DKG frames are not scored as
  invalid and the map is not bounded.
- Missing: any global cap on `pending_dkls_inbound.len()`, any TTL / stale-
  epoch eviction, any prune on epoch advance / `DkgFinalized`, and any
  `target_epoch` plausible-window check at the adapter or arm head. Whole-file
  grep confirms the map is mutated in exactly two places: insert (`:1335`) and
  `remove(&target)` (`:1430`).

## Reachability verdict

REMOTE-UNAUTH — reachable from any peer on the public `hyper/dkg/v1`
gossipsub topic; the sink insert at `actor.rs:1335` executes before any DKLS
decrypt or F018 sender authentication, with `target_epoch` attacker-chosen and
unvalidated.
