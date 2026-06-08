---
id: F021
specialist: p2p-gossip
attack_class: sender-spoofing-inside-payload
title: DKLS inner-sender binding fails open per-party when a committee member registered no libp2p_peer_id, letting any peer spoof that party in a DKLS round
severity_initial: medium
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/dkls_wire_codec.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/validator_registry.rs
  - code/hypersnap/src/hyper/http_handler.rs
  - code/hypersnap/src/network/gossip.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.82
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The F018 mitigation that binds a DKLS round message's application-level
inner `sender` byte to the authenticated libp2p originator
(`check_dkls_sender_against_propagation_source`,
`code/hypersnap/src/hyper/actor.rs:2462`) is **fail-open on a per-party
basis**. When the runtime has no registered libp2p peer-id for the
claimed sending party in the target epoch, the check returns `true`
(accept) instead of rejecting.

A committee member can be in the enforced active set / DKLS committee
yet absent from the peer-id registry, because `libp2p_peer_id` is an
**optional, never-validated-non-empty** field of the validator Register
event. For any such party, an attacker controlling a single gossip mesh
peer can broadcast a plaintext DKLS round message claiming
`sender = <that party>`, and honest nodes submit it into their active
DKLS driver as if it came from that committee member. That is exactly
the sender-spoofing-inside-payload class the F018 registry was built to
close, and it is open for the empty-peer-id case.

## Where the binding fails open

`check_dkls_sender_against_propagation_source`
(`code/hypersnap/src/hyper/actor.rs:2462`):

```rust
let registered = match self.runtime.peer_id_for_party(epoch, claimed_sender) {
    Some(p) => p,
    None => {
        // Permissive: no registered peer-id for this party
        // in this epoch. Validator registry rollout is
        // gradual; treat as unverified rather than reject.
        return true;
    }
};
```

The `None` branch unconditionally accepts. The author's doc comment
(`actor.rs:2450-2453`) frames this as a transitional "pre-rollout
permissive mode … until every active validator has registered a
`libp2p_peer_id`." The problem is that this is not a global rollout
flag — it is evaluated **per claimed sender, every frame**, so the
fail-open path persists indefinitely for any party that simply never
supplied a peer-id.

## Why a committee party can have no registered peer-id

`peer_id_for_party` (`code/hypersnap/src/hyper/runtime.rs:1242`) resolves
the party's `validator_key` from the enforced active set, then looks it
up in `validator_registry.compute_active_peer_ids(epoch)`.

`compute_active_peer_ids`
(`code/hypersnap/src/hyper/validator_registry.rs:757`) only inserts a
peer-id when it is **non-empty**:

```rust
if !e.libp2p_peer_id.is_empty() {
    peer_ids.insert(e.validator_key.clone(), e.libp2p_peer_id.clone());
}
```

But the active-set / DKLS-committee computation
(`get_active_validators_enforced`, `runtime.rs:4055`;
`compute_active_set`) does **not** require a peer-id at all — membership
is keyed on the Register event and trust/slashing filters, never on
peer-id presence. So a validator who registers with an empty
`libp2p_peer_id` is a full committee member (gets a party index, gets
DKLS round messages addressed to/from it) yet is missing from the
peer-id map → `peer_id_for_party` returns `None` →
`check_dkls_sender_against_propagation_source` returns `true` for any
frame claiming that party as `sender`.

`libp2p_peer_id` is optional and unvalidated at registration:
`code/hypersnap/src/hyper/http_handler.rs:234-239` parses it with
`.unwrap_or_default()` (empty vec when omitted), and the registry never
rejects an empty peer-id (it is folded into the canonical signed
payload at `validator_registry.rs:167-168` but no non-empty check
exists anywhere). The runtime's own test fixtures register validators
with `libp2p_peer_id: vec![]` (`runtime.rs:6813, 6863, 6899, 6972`),
confirming an empty peer-id is a fully supported registration shape.

## Attack path

1. Victim nodes run a DKLS DKG (or sign) ceremony for epoch E. Committee
   party `Q` registered with an empty `libp2p_peer_id` (permitted).
2. Attacker controls any one peer `A` in the gossip mesh (does not need
   to be a committee member — it just needs to publish on
   `TOPIC_HYPER_DKG`). Gossipsub is `ValidationMode::Strict` +
   `MessageAuthenticity::Signed` (`gossip.rs:314,324`), so `A`'s frames
   carry `A`'s authenticated peer-id as `originator`.
3. `A` publishes a DKLS DKG frame with discriminator
   `DISCRIMINATOR_PLAINTEXT` (a broadcast variant) wrapping a
   `DklsRoundMessage` whose `sender() == Q`. Plaintext broadcasts are
   accepted without any AEAD/transport-pubkey check
   (`dkls_wire_codec.rs:294-298`), and the inner/outer header
   cross-check only runs for the *encrypted* branch — broadcasts skip
   it entirely.
4. Ingress threads `originator = A` as `propagation_source`
   (`gossip.rs:1119-1122`, `wire_to_event_with_source`).
5. In `HyperActorEvent::InboundDkls`
   (`actor.rs:1367-1385`), the opened broadcast message reaches
   `check_dkls_sender_against_propagation_source(E, Q, Some(A))`.
   Because `peer_id_for_party(E, Q)` is `None`, the check returns
   `true`, and `dkls.driver.submit(message)` ingests the spoofed frame
   as if `Q` sent it. The same hole exists on the sign path
   (`actor.rs:1521-1533`).

The libp2p transport authenticated `A`, but the application-level
`sender = Q` was never bound to `A` — the anti-pattern "we trust the
transport for sender-auth" applied selectively to the empty-peer-id
subset of the committee.

## Impact / severity

The codec doc (`dkls_wire_codec.rs:276-283`) argues residual risk is
"liveness-only" because forged round messages cause peer-side aborts per
DKLS23's `sign_id` binding rather than state corruption. Even taking
that at face value, the consequence is a **liveness / griefing**
vector: a single non-committee mesh peer can inject forged round-1/round
messages attributed to `Q`, driving honest drivers into aborts or
inconsistent transcripts and stalling the threshold ceremony that gates
epoch reward issuance, trust-snapshot updates, lock-root and burn
signatures. The defense the whole F018 registry exists to provide is
silently disabled for any committee member who omitted a peer-id, and
nothing forces a committee member to provide one.

Rated **medium**: confirmed authentication bypass of the F018
sender-binding control with a concrete remote, low-privilege trigger
(one mesh peer, no committee membership required), bounded by the
upstream DKLS `sign_id`/abort behavior to liveness/griefing rather than
threshold-secret compromise in the cases reviewed. If a downstream
driver path treats a `submit`-accepted spoofed broadcast as
state-affecting (not re-reviewed exhaustively here), impact rises.

## Suggested direction (non-binding)

Make the binding fail-closed for active committee members: if
`claimed_sender` is a party in the enforced active set for `epoch` but
has no registered peer-id, **drop** rather than accept; and/or require a
non-empty, well-formed `libp2p_peer_id` at validator registration so a
committee party can never be peer-id-absent. The `propagation_source ==
None` (locally-synthesized) accept branch is acceptable; the
registry-miss accept branch for an active party is the hole.
