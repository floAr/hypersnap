---
id: F024
specialist: rust-threshold-signing
attack_class: broadcast-sender-spoofing
severity_initial: high
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
title: Pre-StartDkls buffered DKG drain feeds round messages to the ceremony state machine without the F018 sender/peer-id check, enabling broadcast-sender spoofing
file_paths:
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/dkls_wire_codec.rs
  - code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.84
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

DKLS23 DKG broadcast round messages carry a claimed `sender: u8` party
index that the protocol state machine uses as a map key
(`proof_commitments[sender]`, `bip_broadcasts_2to4[sender]`,
`bip_broadcasts_3to4[sender]`). The codec itself does NOT authenticate this
field (it is documented as an "untrusted hint" in
`dkls_wire_codec.rs:256-283`). Authentication lives one layer up, in the
actor: `HyperActor::check_dkls_sender_against_propagation_source`
(`actor.rs:2462`) binds the claimed inner `sender` to the libp2p gossipsub
originator (`message.source`, cryptographically authenticated because
gossipsub runs `ValidationMode::Strict` + `MessageAuthenticity::Signed`,
`network/gossip.rs:314,324`).

That guard is applied on the **live** DKG ingress path (`actor.rs:1373`)
and on the sign path (`actor.rs:1521`). It is **NOT** applied on the
**buffered pre-StartDkls drain path**. The F023(a) buffer
(`pending_dkls_inbound`) exists specifically because peers' round-1
messages routinely arrive before this node's supervisor dispatches
`StartDkls` — i.e. the buffered path is on the normal happy path, not an
edge case. When the buffer is drained (`actor.rs:1430-1462`), each frame is
re-opened and handed straight to `driver.submit(m)` with no sender check.
The originator is not even available to check against, because the buffer
stores only `encoded` (`actor.rs:1337`) and discards the
`propagation_source` captured on the `InboundDkls` event.

Net effect: any gossip peer can inject plaintext broadcast variants
(`Phase2ProofCommitment`, `Phase2BipBroadcast`, `Phase3BipBroadcast`)
claiming `sender = <victim committee party>` into a target node's DKG
accumulator, as long as the frame arrives before that node starts its
ceremony (attacker-influenceable ordering).

## Mechanism

1. Gossip ingress for `InboundDkls { target_epoch, encoded, propagation_source }`.
   If no ceremony for `target_epoch` is active yet, the frame is buffered:
   only `encoded` is pushed (`actor.rs:1334-1345`); `propagation_source`
   is dropped.
2. On `StartDkls`, the buffer is drained (`actor.rs:1430-1462`):
   `open_dkls_round_message` decodes the plaintext broadcast and the actor
   calls `driver.submit(m)` directly. There is no
   `check_dkls_sender_against_propagation_source` call here, unlike the
   live path at `actor.rs:1373` and the sign path at `actor.rs:1521`.
3. `DklsCeremonyCoordinator::submit` (`dkls_ceremony.rs:333`) inserts
   broadcast payloads keyed by the attacker-chosen `sender`:
   `proof_commitments.insert(sender, ...)` (line 349),
   `bip_broadcasts_2to4.insert(sender, ...)` (line 355),
   `bip_broadcasts_3to4.insert(sender, ...)` (line 384). Broadcast variants
   have NO inner-vs-outer cross-check (the F114 guard at lines 365-412
   only covers the P2P `Phase*ZeroShareSend` / `Phase3MulSend` variants
   that carry an inner `parties.{sender,receiver}`; broadcasts have no such
   inner field to cross-check).
4. `try_advance_phase23_to_complete` (`dkls_ceremony.rs:526`) collects
   `proof_commitments.values()` and the bip-broadcast maps and feeds them
   to `phase4::<Secp256k1>(...)` (line 558). A forged/garbage commitment in
   the victim's slot makes phase4 return
   `DklsError::Abort { party: abort.index, reason }` (lines 570-573),
   where the blame index is the party whose commitment failed verification
   — i.e. the spoofed `sender` (an innocent committee member).

## Impact

- **DKG abort (liveness):** one forged broadcast in the victim's slot,
  delivered before the victim's genuine commitment, corrupts the
  accumulator and forces a phase4 abort. DKG cannot resume in-place
  (`try_advance` short-circuits once `error`/`output` is set,
  `dkls_ceremony.rs:421`), stalling per-epoch threshold-key generation.
- **Blame mis-assignment:** the abort names the spoofed `sender`, not the
  attacker. If abort blame drives any exclusion / scoring / slashing
  downstream, an honest validator is penalised for an attacker's frame.
- **Last-write-wins races:** `insert` means whoever lands last in a given
  slot wins. The attacker can race the victim's genuine commitment;
  ordering through the buffer/drain is attacker-influenceable.

This is integrity/liveness, not silent key corruption — phase4's
verification catches the garbage and aborts rather than producing a
poisoned group key. Rated **high**: it is a remotely-triggerable,
race-only DKG denial-of-service against per-epoch threshold key generation
plus false-blame against honest committee members, on a code path that is
hit during normal operation (the buffer is the F023(a) happy path).

## Why the live path is not affected

On the live path the originator is the gossipsub `message.source`
(`network/gossip.rs:1110-1122`), authenticated by Strict-mode signed
gossipsub, and `check_dkls_sender_against_propagation_source` compares the
claimed `sender` to `runtime.peer_id_for_party(epoch, sender)`
(`runtime.rs:1242`). A spoofing peer is dropped at `actor.rs:1378`. The
buffered path bypasses exactly this guard.

## Secondary observation (permissive fallthrough)

Even on the live path, `check_dkls_sender_against_propagation_source`
returns `true` (accept) when `peer_id_for_party` returns `None` — i.e. when
the committee member has not yet published a ContactInfo / has no entry in
`compute_active_peer_ids(epoch)` (`actor.rs:2472-2479`). During registry
warm-up this re-opens the same spoofing window on the live path. The
codec's own doc-comment (`dkls_wire_codec.rs:276-283`) still describes the
registry as "not yet wired" and the residual risk as "liveness-only" — the
narrative is stale (the registry IS wired now) but the buffered-path gap
and the permissive fallthrough mean the residual risk it describes is real
and broader than liveness-only (blame mis-assignment).

## Suggested remediation

- Buffer the authenticated originator alongside `encoded` in
  `pending_dkls_inbound` (store `(encoded, propagation_source)`), and run
  `check_dkls_sender_against_propagation_source` in the drain loop before
  `driver.submit(m)` — mirroring `actor.rs:1373`.
- Consider making the registry-unknown fallthrough fail-closed for
  committee members of an active/forming ceremony (drop rather than
  accept), at least once the epoch's committee peer-id set is expected to
  be populated.
- Defence-in-depth: have `DklsCeremonyCoordinator::submit` reject a second
  broadcast that would overwrite an already-populated `sender` slot, so
  late spoof frames cannot clobber a genuine commitment.
