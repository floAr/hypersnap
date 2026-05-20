---
id: F018
task: H018
specialist: p2p-gossip
attack_class: sender-spoofing-inside-payload
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# DKLS round messages carry an application-level `sender` byte that is bound to neither the libp2p source peer-id nor any validator identity key; any peer subscribed to `hyper/dkg/v1` can inject DKG/sign-round messages claiming to be from an honest party, overwriting that party's slot in every honest accumulator and (depending on phase) aborting the ceremony or steering the resulting threshold key

## Summary

`DklsRoundMessage` (`crates/hypersnap-crypto/src/dkls_ceremony.rs:74-95`)
and `DklsSignRoundMessage`
(`crates/hypersnap-crypto/src/dkls_sign.rs:53-69`) both carry an
application-level `sender: u8` field that identifies the claimed
ceremony party (1-based party_index). On the receive side the
coordinator routes every inbound message into a
`BTreeMap<u8, T>::insert(sender, payload)` slot
(`dkls_ceremony.rs:333-394`, `dkls_sign.rs:255-282`), so the inner
`sender` byte is **load-bearing** — it picks which party's data slot
the payload occupies.

That inner `sender` is bound to nothing that authenticates the actual
publisher:

1. The gossip ingress path (`src/network/gossip.rs:889-912`) hands
   `wire_to_event` only the decoded `proto::HyperWireMessage` and
   discards the libp2p `propagation_source: peer_id` it has on hand
   from the `Gossipsub::Event::Message` event (`gossip.rs:625-639`).
   `wire_to_event` (`src/hyper/gossip_adapter.rs:56-90`) and the
   resulting `HyperActorEvent::InboundDkls { target_epoch, encoded }`
   / `InboundDklsSign { epoch, encoded }` (`actor.rs:94, :105`) carry
   no peer-id field. Grepping the entire `src/hyper/` tree for
   `propagation_source`, `libp2p::PeerId`, `peer_id.*party`, or
   `party.*peer_id` returns **zero** matches — the hyper actor has no
   way to know who published any frame.
2. The actor's DKLS handlers (`actor.rs:1237-1294, 1296-...`) call
   `open_dkls_round_message` / `open_dkls_sign_round_message` and then
   `dkls.driver.submit(decoded)` (`actor.rs:1247-1290`). They never
   compare the decoded `sender` byte to any peer-identity claim. The
   only sender-related check is the `inner_receiver != Some(receiver)`
   self-consistency check inside `open_dkls_round_message`
   (`dkls_wire_codec.rs:236-243, 289-296`), which only proves the
   inner header matches the outer header — both filled in by the
   *same* publisher.
3. The AEAD AAD on encrypted P2P frames does include
   `sender || receiver` (`dkls_wire_codec.rs:100-108`), and the
   receiver re-derives the AAD from the outer wire header bytes 1-2
   and feeds it to `local_secret.open` (`dkls_wire_codec.rs:230-231,
   :284-285`). But the AEAD's confidentiality + integrity is sealed
   to the **recipient's X25519 transport pubkey**
   (`dkls_wire_codec.rs:138-148`); the AAD is supplied by whoever
   constructed the ciphertext. The receiver only verifies "the AAD I
   reconstructed matches what the sealer included" — a self-consistency
   check, not authentication of the sealer's identity. Any peer who
   knows the recipient's transport pubkey (`runtime.rs:1019-1043`
   exposes it from the validator registry; the registry is by
   construction public to all subscribers of the topic) can encrypt a
   round message to that recipient and **choose any `sender` byte
   they want** in the AAD.
4. For the **plaintext broadcast** variants — `Phase2ProofCommitment`,
   `Phase2BipBroadcast`, `Phase3BipBroadcast`
   (`dkls_ceremony.rs:74-95`) and sign-phase `Phase3Broadcast`
   (`dkls_sign.rs:53-69`) — there is no AEAD at all. The wire
   format's plaintext discriminator branch just bincode-decodes the
   payload (`dkls_wire_codec.rs:215-219, 268-272`) and `Ok(Broadcast(message))`'s
   straight into the coordinator's `submit`. The inner `sender` byte
   is fully attacker-chosen.

The libp2p layer authenticates the gossipsub *publisher* via
`MessageAuthenticity::Signed` (`gossip.rs:295`), but the publisher's
libp2p ed25519 keypair has no documented or enforced relationship to
the DKLS `party_index`. There is no `(peer_id → party_index)` registry
anywhere in the codebase; the validator registry maps
`validator_key (ed25519)` to (FID, transport_pubkey) but **not** to
libp2p peer-ids, and the gossip layer never consults the registry on
ingress.

Net: any peer subscribed to `hyper/dkg/v1` (a public topic on the
hyper gossipsub mesh, no admission control) can publish a DKG or sign
round message claiming any `sender` byte they like. On every honest
receiver the coordinator's `BTreeMap::insert(sender, payload)` will
overwrite — or pre-empt — that slot.

H016's ruled-out note explicitly defers this attack to a separate
class: "Sender-spoofing for broadcasts is a separate attack class;
not the H016 question."
(`findings/notes/H016-ruled-out.md:91-95`). That separate class is
this finding.

## Description

### Wire-format trust chain (or absence thereof)

The DKLS gossip ingress path is a four-step funnel, and at every step
the publisher's identity attestation gets *less* specific:

```
libp2p Gossipsub::Event::Message {
    propagation_source: peer_id,   ← gossipsub-signed; bound to publisher's
    message: { data, ... },           libp2p keypair via MessageAuthenticity::Signed
}
     │
     │ src/network/gossip.rs:625-639
     ▼
map_gossip_bytes_to_system_message(peer_id, data)
     │
     │ src/network/gossip.rs:889-912  — HyperWire arm
     ▼
crate::hyper::gossip_adapter::wire_to_event(wire)
     │
     │ peer_id is DROPPED here. The HyperActorEvent enum has no peer-id field.
     ▼
HyperActorEvent::InboundDkls { target_epoch, encoded }    ← no source attribution
     │
     │ src/hyper/actor.rs:1237-1294
     ▼
open_dkls_round_message(&encoded, target_epoch,
                        &runtime.local_transport_secret,
                        local_party)
     │
     │ Only checks: outer header matches inner payload's sender/receiver bytes.
     │ Both are publisher-chosen.
     ▼
driver.submit(decoded)
     │
     │ crates/hypersnap-crypto/src/dkls_ceremony.rs:333-394
     ▼
self.poly_fragments.insert(sender, fragment);     ← attacker chooses 'sender'
```

The libp2p layer's `MessageAuthenticity::Signed` (`gossip.rs:295`)
guarantees the gossipsub frame was signed by *some* libp2p keypair.
This proves who published the frame at the libp2p layer. It does
**not** prove the publisher is the validator they claim to be in the
inner `sender` byte, because:

- The publisher's libp2p ed25519 keypair is initialized from a
  `Keypair` passed to `SnapchainGossip::create` (`gossip.rs:240`).
  This keypair has no on-protocol registration step that binds it to
  a `validator_key` or `party_index`. The validator registry
  (`src/hyper/validator_registry.rs`) registers (validator_key,
  FID, transport_pubkey) tuples; it does not register a libp2p
  peer-id.
- Even if it did register one, the gossip layer never looks it up
  on ingress before forwarding to the actor.

So even though the *gossipsub frame* has provenance, the *application
sender byte* inside that frame has none.

### The sealed-to-recipient AEAD does not authenticate the sender

The encrypted-P2P codec (`dkls_wire_codec.rs:118-150`) seals to the
recipient's `TransportPublicKey`. The `seal` function on
`TransportPublicKey` is by name an X25519-sealed-box / ephemeral
DH construction — the encryptor's identity is **anonymous** to the
recipient at the cryptographic layer. The AAD that the recipient
verifies (`dkls_wire_codec.rs:100-108`) is:

```
"hypersnap-dkls-wire-v1" || epoch (8B BE) || round_tag (1B)
                         || sender (1B) || receiver (1B)
```

Receiver reconstructs that AAD using outer wire bytes 1 (sender) and
2 (receiver) — both **bytes the encryptor supplied**. AEAD decrypt
succeeds iff the ciphertext was produced with those same AAD bytes;
that is a tautology — the encryptor set the AAD, the AEAD verifies
nothing more. The only thing the recipient learns from the AEAD is:

> Someone who knows my transport public key encrypted this. They
> wrote `(epoch, round_tag, sender, receiver)` into the AAD.

The X25519 sealed box does not prove the encryptor knows party
`sender`'s private material; only that they know **the recipient's
public** transport key. The recipient's transport pubkey is
**registered in the validator registry**
(`runtime.rs:1019-1043`) and exposed via `transport_pubkey_for_party`,
which iterates over the validator registry's active set. Every
subscriber of the hyper gossip mesh has, by construction, access to
the broadcast `HyperValidatorEvent`s that register transport pubkeys,
so this material is **public**. Any peer can therefore craft an
encrypted P2P frame addressed to honest receiver R with any `sender`
byte X they choose, and the AEAD will verify.

### The plaintext broadcast variants have no protection at all

For broadcast variants the wire codec puts the bincoded message
straight after the `DISCRIMINATOR_PLAINTEXT` byte
(`dkls_wire_codec.rs:131-135, 167-171`). The receiver
`open_dkls_round_message` decodes via `DklsRoundMessage::from_bytes`
(`dkls_wire_codec.rs:216-218, 270-272`) and returns
`Broadcast(message)`. No sender authentication of any kind.

The receiving coordinator's `submit` then performs:

```rust
DklsRoundMessage::Phase2ProofCommitment { sender, proof_commitment } => {
    self.proof_commitments.insert(sender, proof_commitment);
}
DklsRoundMessage::Phase2BipBroadcast { sender, bip_broadcast } => {
    self.bip_broadcasts_2to4.insert(sender, bip_broadcast);
}
DklsRoundMessage::Phase3BipBroadcast { sender, bip_broadcast } => {
    self.bip_broadcasts_3to4.insert(sender, bip_broadcast);
}
```
(`dkls_ceremony.rs:345-372`)

A spoofed broadcast inserts at `sender = X` (the attacker's chosen
party). The same shape exists in `dkls_sign.rs:277-279` for
`Phase3Broadcast`.

### `BTreeMap::insert` is a last-writer-wins overwrite

The accumulator pattern is `BTreeMap::insert(sender, payload)`. The
standard library's `BTreeMap::insert` semantics: the latest call wins.
Two consequences:

- **Spoof-first attack:** If the attacker can publish before honest
  party Q (e.g., the attacker is geographically closer to a victim,
  or honest Q's network is slow), the attacker's bogus payload sits
  in `accumulator[Q]`. When Q's honest message arrives, it
  overwrites the spoof — but the ceremony state machine has already
  consumed the accumulator via `.values().cloned().collect()`
  (`dkls_ceremony.rs:423, 528`) and progressed to the next phase
  using the spoofed value.
- **Spoof-last attack:** If the attacker publishes after Q's honest
  message but before the receiver's `try_advance` consumes the
  accumulator, the attacker's bogus payload overwrites the honest
  one and that bogus value goes into phase 2.

Either way, every honest receiver ends up with an attacker-chosen
`poly_fragments[Q]`, `proof_commitments[Q]`, `bip_broadcasts_2to4[Q]`,
etc., for any `Q` the attacker chose to spoof.

### Cryptographic impact per phase

The accumulator slot the attacker controls feeds directly into
DKLS23 phase-2 / phase-3 cryptographic computations:

- **`poly_fragments`** is fed to `phase2::<Secp256k1>` (`dkls_ceremony.rs:423-431`)
  as a `Vec<Scalar>` aggregated via summation. The phase-2
  computation includes the resulting share's polynomial point.
  Steering one party's fragment changes the resulting threshold
  share that this receiver computes for itself — and **disagrees**
  with what other (un-attacked) receivers computed for themselves
  if the attacker spoofed differently per recipient. The ceremony
  may complete locally but produce divergent shares across the
  committee, yielding either:
  (a) silent DKG output where threshold signing later fails when
      shares can't reconstruct the group key (denial of service +
      stuck epoch until the supervisor times out); or
  (b) the DKLS23 proof-commitment phase aborts via
      `DklsError::Abort` (`dkls_ceremony.rs:344-345 ish`) on the
      next phase boundary — also DoS, but the ceremony explicitly
      halts.
- **`proof_commitments`** is verified internally by phase-2
  consistency checks — a bogus commitment from the attacker fails
  the phase, aborts with `Abort{ party: Q, ... }` blaming the
  *honest* party (`dkls_ceremony.rs:344-345`). This is the
  **misattribution** sub-bug: the attacker can frame an honest
  validator as the source of DKG abort, which is a slashable
  offense in some protocols and at minimum will trigger the
  supervisor's blame logic in `dkls_supervisor.rs` (which then
  excludes honest Q from the next ceremony, possibly recursively
  if the attacker keeps doing it).
- **`bip_broadcasts_2to4` / `bip_broadcasts_3to4`** drive the
  BIP-32 chain-code aggregation. A spoofed BIP broadcast alters the
  derived chain code at this receiver, which is consumed by the
  hierarchical key derivation step.
- **Sign-phase `Phase1Send` / `Phase2Send` / `Phase3Broadcast`**
  (`dkls_sign.rs:255-279`) drive the threshold-ECDSA signing
  flow. A spoofed `Phase1Send { sender=Q, transmit }` corrupts
  Q's share of the signing nonce contribution. Phase 2 cross-
  consistency checks will detect this and abort
  (`dkls_sign.rs:312-317`), again blaming honest Q. Repeated
  attacks on the sign path block threshold-signing of:
  - Per-epoch `RewardIssuance` (no rewards paid out for that
    epoch).
  - Per-epoch `TrustSnapshotUpdate` (trust scores frozen).
  - Bridge `LockMerkleRootUpdate` (bridge claim flow halted).
  - `InboundBurn` signatures (bridge burn flow halted).

The bridge claim flow halt is the most operationally severe: if
attacker P repeatedly spoofs honest Q during sign rounds, the
threshold-ECDSA signature over the merkle-root update never
completes, the L1 bridge contract's `latestBlock` watermark stops
advancing, and all `claim()` calls on L1 fail with `StaleBlock`
until the supervisor finds a sign-committee that excludes both P
and the framed Q. With ≥ 1 attacker among the active set the
attacker can keep rotating which honest Q they frame each round.

### No layer further down catches this

I looked for downstream sender-rebinding in the obvious places:

- The actor's DKLS dispatch (`actor.rs:1237-1294, 1296-1330`)
  passes the decoded `DklsRoundMessage` straight to
  `driver.submit(msg)` — no peer-id consultation.
- The driver (`src/hyper/dkls_driver.rs:59-62`) just delegates to
  `coordinator.submit`.
- The coordinator does the `BTreeMap.insert(sender, payload)` —
  no signature check, no peer-id binding.
- `DklsRoundMessage`'s bincode codec has no signature field. The
  type definition (`dkls_ceremony.rs:54-95`) shows only `sender`,
  `receiver`, and the cryptographic payload variants. There is no
  `signature: Ed25519Signature` field anywhere in the variant.
- The validator registry, which would be the natural place to
  enforce a `(party_index → validator ed25519 key)` binding, is
  *not consulted* on the DKLS ingress path. The only place it
  is consulted is `transport_pubkey_for_party` on the **sealing**
  outbound side (`runtime.rs:1019-1043`) — the receiver does not
  perform the symmetric "is this sender's validator_key the
  expected one?" check because there is no signature to check.

### Why H016's ruled-out note is consistent with this finding

H016 was the *replay* hunt task. Its conclusion was correct: replay
is bounded because `BTreeMap::insert` is idempotent under same-payload
re-emission and the AEAD-AAD pins each frame to `(epoch, round, sender,
receiver)`. But H016 explicitly carves out sender-spoofing as a
separate concern (`findings/notes/H016-ruled-out.md:91-95`):

> "Sender-spoofing for broadcasts is a separate attack class; not
> the H016 question."

This finding is that separate attack class. The AEAD-AAD that locks
replay (because Q can't relabel Q's own message as P's, since the
sealed ciphertext is bound to P's transport pubkey) does **not** lock
spoofing (because an attacker who is *not* Q can encrypt to honest R's
pubkey claiming `sender=Q`).

### What a correct binding would look like

The fix is to bind the inner `sender` to either:

1. **(Preferred) An Ed25519 signature over the entire encoded round
   message, by the validator's registered `validator_key` for the
   party_index claim**, with the verifier consulting the validator
   registry for the active set at `epoch` and party slot
   `sender`. This is the standard pattern for BFT round messages
   (e.g., Tendermint / Malachite votes are signed by the
   proposer's consensus key).
2. **(Acceptable) The gossipsub `propagation_source: peer_id`,
   provided there is a registered `(peer_id → validator_key →
   party_index)` table** the actor consults on ingress. The peer-id
   must be the *original publisher's*, not the propagator's — for
   gossipsub the `message.source.as_ref()` field
   (`gossip.rs:259-265`) gives the originator (since
   `MessageAuthenticity::Signed` is on), but the current code never
   plumbs `message.source` through the adapter; the actor only
   sees the encoded bytes.

The current codebase has neither.

## Impact

- **Spoofing DKG round messages.** A peer subscribed to `hyper/dkg/v1`
  (no admission control beyond gossipsub subscription) can publish a
  round message claiming `sender = Q` for any honest party Q. On every
  honest receiver R, the coordinator's
  `BTreeMap::insert(sender = Q, payload = attacker_chosen)` writes the
  attacker's payload into Q's accumulator slot. The DKG aborts in
  phase 2 (consistency-check failure) blaming **honest Q**. This both:
  - **Denies service** (the DKG fails; epoch's threshold key is not
    produced; downstream signing is blocked until supervisor retries
    without Q).
  - **Misattributes blame.** The actor / supervisor's failure
    diagnosis sees `Abort{ party: Q, reason: ... }`. If `dkls_supervisor.rs`
    has a "exclude failing party on retry" policy, repeated attacks
    can permanently push honest Q out of every DKG ceremony, leaving
    only attackers and their collusion targets.
- **Spoofing sign-ceremony round messages.** Same shape. The
  threshold-ECDSA signing flow is used for:
  - `RewardIssuance` finalization (no payouts).
  - `TrustSnapshotUpdate` (frozen scores).
  - `LockMerkleRootUpdate` (bridge `claim()` halts on L1 because
    `latestBlock` doesn't advance).
  - `InboundBurn` (bridge burns can't be confirmed on hypersnap).
  - `DaEpochSeed` (data-availability seed not signed, DA challenge
    cycle stalls).
  An attacker controlling one peer on the gossip mesh can stall any
  / all of these by spoofing one round message per sign attempt; the
  victim epoch's signing committee gets blamed and rotated out, and
  the protocol takes an epoch's worth of latency before any progress.
- **Possible threshold key takeover under maximally favorable
  conditions.** If the attacker can race honest Q to publish first
  AND publish a `Phase1Fragment { sender = Q, fragment = chosen }`
  that mass-deceives one or more honest receivers (the attacker can
  publish a different spoof to each receiver since the
  receiver-bound AEAD lets the attacker tailor per-recipient), the
  resulting shared secret on the deceived receivers diverges from
  the non-deceived ones. If the threshold is configured to be tight
  (e.g., threshold = share_count), even one deceived receiver causes
  total ceremony failure; with a larger gap, the deceived receivers
  hold a share that doesn't reconstruct the group key. Either way
  this is silent corruption of the threshold key state — operators
  see "DKG completed" but signatures don't verify and require manual
  recovery from `recovery_watcher`.
- **Compatible with the single-party DKLS path (`RuntimeProduceError::
  DklsLocalSignRequiresSingleParty`, called out in
  `docs/00-OVERVIEW.md`).** A single-party bootstrap is immune to
  spoofing only because there are no peers; the moment the active set
  expands to ≥ 2, the spoofing surface activates instantly because
  the gossip ingress decoding is identical regardless of cardinality.
- **No detectability.** The receiver records the spoofed value with
  no indication it didn't come from honest Q. Forensics would need
  to capture the original gossipsub message and inspect
  `message.source` to compare to the validator registry — neither
  the codebase nor the standard libp2p log captures this. The
  hypothetical "audit log of `(propagation_source, inner_sender,
  matched_validator_key)`" is not implemented.

Severity: **high**. The attack:
- Requires only "be subscribed to a public gossip topic" — no
  validator status, no operator credentials, no on-chain registration.
- Is reliable (no probabilistic component — `BTreeMap::insert` always
  succeeds; the only question is ordering, which the attacker can
  bias by publishing aggressively or by being geographically closer
  to victims).
- Has a continuous-DoS surface: one bad peer can stall a
  threshold-signing event per round-trip.
- Has a misattribution side-effect that, if `dkls_supervisor.rs`
  blames the spoofed-as party, lets the attacker durably exclude
  honest validators from future ceremonies.
- Has a (smaller but real) chance of silent threshold-key
  corruption under unlucky timing.

Promoted to **critical** if `dkls_supervisor.rs` does in fact exclude
the blamed party on the next epoch (this finding does not analyze the
supervisor's retry policy in depth; the chain-actor specialist should
follow up — see "Related" below).

## Evidence

* `src/network/gossip.rs:889-912` — the `HyperWire` ingress arm.
  `propagation_source: peer_id` is in scope at line 626 but never
  passed to `wire_to_event` at line 891.
* `src/network/gossip.rs:295` — `MessageAuthenticity::Signed(key.clone())`
  proves that the libp2p layer is configured correctly; gossipsub
  frames are signed by their publisher's libp2p keypair. But the
  validator registry has no mapping from libp2p peer-id to
  validator_key, so this signature provides only "some peer signed
  it," not "the validator claiming party_index=X signed it."
* `src/hyper/gossip_adapter.rs:56-90` — `wire_to_event` signature
  takes only `wire: proto::HyperWireMessage`; no peer-id parameter.
  Line 80 emits `HyperActorEvent::InboundDkls { target_epoch,
  encoded }` — no source attribution.
* `src/hyper/actor.rs:94, :105` — `HyperActorEvent::InboundDkls /
  InboundDklsSign` carry only `target_epoch / epoch` and `encoded:
  Vec<u8>`. No peer-id or source-validator field.
* `src/hyper/actor.rs:1237-1294` (DKG) and `:1296-...` (sign) —
  the actor handlers call `open_dkls_round_message` then
  `driver.submit(decoded)`. There is no check between the
  decoded `sender` byte and any validator identity claim.
* `src/hyper/dkls_wire_codec.rs:100-108` — `build_aad` content:
  `"hypersnap-dkls-wire-v1" || epoch || round_tag || sender ||
  receiver`. The `sender` is supplied by the encryptor.
* `src/hyper/dkls_wire_codec.rs:118-150` — `seal_dkls_round_message`:
  encryptor calls `recipient_pk.seal(&raw, &aad, rng)`. The seal is
  to the recipient's pubkey; sender identity is not authenticated.
* `src/hyper/dkls_wire_codec.rs:215-244, :268-297` —
  `open_dkls_round_message` / `open_dkls_sign_round_message`. The
  `HeaderMismatch` check at lines 236-243 / 289-296 only compares
  inner payload's sender/receiver against outer wire header bytes
  — both publisher-chosen, so this is a self-consistency check
  only.
* `crates/hypersnap-crypto/src/dkls_ceremony.rs:333-394` — the
  coordinator's `submit`: every variant does
  `self.<accumulator>.insert(sender, payload)`. The `sender` byte
  is the BTreeMap key, last-writer-wins.
* `crates/hypersnap-crypto/src/dkls_sign.rs:255-282` — mirror in
  the sign-ceremony coordinator: `received_1to2.insert(sender, ...)`,
  `received_2to3.insert(sender, ...)`, `broadcasts_3to4.insert(sender, ...)`.
* `crates/hypersnap-crypto/src/dkls_ceremony.rs:74-95` — the
  `DklsRoundMessage` enum variants. Each variant has `sender: u8`;
  none has a `signature: ...` field. There is no Ed25519 or
  validator-key signature attached to the round message at the
  type level.
* `crates/hypersnap-crypto/src/dkls_sign.rs:53-69` — same for the
  sign variants.
* `src/hyper/runtime.rs:1019-1043` — `transport_pubkey_for_party`
  looks up validator registry. Public on the active-set ordering;
  any subscriber to validator events knows every party's transport
  pubkey, so the seal-to-recipient pattern provides no sender
  authentication.
* `findings/notes/H016-ruled-out.md:91-95` — the H016 specialist
  already noted that sender-spoofing is a separate attack class
  not addressed by the replay analysis. This finding is that
  class.
* `src/hyper/dkls_wire_codec.rs:99` — comment claims the AAD
  "binds the ciphertext to its protocol context so a sealed payload
  from epoch N round R can't be replayed into epoch M or a
  different round." This is true for **replay** (the H016 concern)
  but is **insufficient for sender authentication** (this finding):
  the AAD is encryptor-supplied, not derived from any external
  identity claim.

## Suggested remediation

1. **Sign each `DklsRoundMessage` / `DklsSignRoundMessage` under the
   sender's registered `validator_key`.** Add a `signature: Vec<u8>`
   field to the wire format (or a per-frame envelope wrapping the
   bincoded message + Ed25519 signature). On `open`/`submit`, the
   actor must:
   ```rust
   let claimed_party = decoded.sender();
   let expected_pk = self.runtime
       .validator_key_for_party(epoch, claimed_party)
       .ok_or(DklsActorError::UnknownParty(claimed_party))?;
   let signing_bytes = decoded.signing_payload(); // bincode of
                                                   // the message
                                                   // sans signature
   expected_pk.verify(&signing_bytes, &decoded.signature)
       .map_err(|_| DklsActorError::BadSenderSignature {
           claimed: claimed_party,
       })?;
   ```
   This is the same shape as `signing_payload` /
   `verify_event_signature` already used for `HyperValidatorEvent`
   (`validator_registry.rs:131-180`). Reuse that machinery.
2. **Bind the AAD to a sender-side identity rather than a self-
   supplied byte.** If you keep the sealed-box transport, switch
   to a noise-XX-style authenticated handshake or a libsodium-style
   `crypto_box_curve25519xchacha20poly1305_easy` keyed by the
   sender's static X25519 pubkey from the validator registry —
   not just an ephemeral pubkey. The recipient must be able to
   verify that the encryptor knew the sender's *secret*, not just
   the recipient's public pubkey.
3. **(Defense in depth.) Plumb `propagation_source` through the
   adapter and have the actor consult a
   `(peer_id → validator_key → party_index)` table on ingress.**
   Even with #1 or #2 in place, recording the gossipsub source
   peer-id alongside the inner sender is cheap (one extra field on
   `HyperActorEvent::InboundDkls`) and provides forensic value
   ("which peer is publishing spoofed frames?") that would let
   the supervisor blacklist the *actual* attacker rather than the
   spoofed-as honest party.
4. **Add an explicit regression test that spoofs `sender = X`
   from a peer who is not X.** Today
   `dkls_wire_codec.rs::sealed_p2p_message_round_trips` (line
   348) only exercises the honest path. Add:
   ```rust
   #[test]
   fn spoofed_sender_must_be_rejected() {
       // Party A (alice_pk) is the genuine sender of a P2P message
       // to party B. An attacker with no DKLS share encrypts a
       // forged message to party B with sender=A. The recipient's
       // open_dkls_round_message currently returns Ok(ForUs(...)).
       // After remediation it must return DklsWireError::BadSenderSignature.
   }
   ```
   This test should currently *fail* (which is the bug); after
   remediation it should pass.
5. **Audit `dkls_supervisor.rs`'s retry/blame policy.** Determine
   whether a party that "fails" a DKG (via the spoofed-sender
   path) is excluded from the next epoch's ceremony. If yes,
   this finding's misattribution sub-impact is a slow-burn
   validator-eviction attack that compounds across epochs — a
   second referral for the node-lifecycle-actor specialist.

## Related

- `findings/notes/H016-ruled-out.md` — the replay analysis that
  explicitly defers spoofing to this hunt task.
- `findings/notes/H001-ruled-out.md` (per H016 reference) — evidence
  ingest path. The "must verify signatures at the gossip ingest gate"
  pattern from C1 of the original audit is the *correct* shape; the
  DKLS path here is exactly the *wrong* shape (no signature check at
  the ingest gate).
- `src/hyper/dkls_supervisor.rs` — referred for follow-up by
  node-lifecycle-actor on the blame / eviction policy.
- `docs/attack-surface.md:158-187` (4.2 Threshold ECDSA (DKLS23)
  integration) — "the libp2p peer-id must be bound to the inner
  sender." This finding is the realization of that hotspot.
