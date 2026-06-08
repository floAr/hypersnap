# F024 validation — buffered pre-StartDkls DKG drain skips the F018 sender/peer-id check

Validator: validator (deliberate-disagreement). Commit pinned `cab225f`.
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` (no drift, clean tree).

Finding under test: the F023(a) buffer drain on `StartDkls` (`actor.rs:1430-1462`) hands each
buffered round message straight to `driver.submit(m)` WITHOUT
`check_dkls_sender_against_propagation_source`, unlike the live DKG path (`actor.rs:1373`) and
the sign path (`actor.rs:1521`). Net: broadcast-sender spoofing into a target node's DKG
accumulator if the frame arrives before the node starts its ceremony.

## Code claims re-verified (file:line)

- Buffer fill stores ONLY `encoded`, discards `propagation_source`: `actor.rs:1334-1345` (push at 1337).
  CONFIRMED verbatim. The captured `propagation_source` on the `InboundDkls` event is dropped.
- Live DKG path DOES call the F018 check before submit: `actor.rs:1373-1379`. CONFIRMED.
- Drain loop calls `driver.submit(m)` with NO sender check: `actor.rs:1430-1462` (submit at 1444).
  CONFIRMED — no `check_dkls_sender_against_propagation_source` anywhere in the drain block;
  the originator is not even in scope (only `encoded` was buffered).
- `check_dkls_sender_against_propagation_source` body: `actor.rs:2462-2493`. CONFIRMED. It is the
  ONLY application-level sender-binding control.
- `driver.submit` is a thin pass-through to `coordinator.submit` with no auth: `dkls_driver.rs:59-61`.
  CONFIRMED — no second sender check downstream of the actor.
- Coordinator `submit`: broadcast variants insert by attacker-chosen `sender` with NO inner-vs-outer
  cross-check: `dkls_ceremony.rs:345-356` (`proof_commitments.insert(sender,...)` 349,
  `bip_broadcasts_2to4.insert` 355), `383-384` (`bip_broadcasts_3to4.insert` 384). The F114 guard
  (`zero_init.parties.sender != sender` etc.) covers ONLY `Phase*ZeroShareSend`/`Phase3MulSend`
  (lines 375, 395, 409) — broadcasts have no inner `parties` field to cross-check. CONFIRMED.
- `Phase2ProofCommitment` insert has no state guard — always inserted regardless of `state`,
  persists last-write-wins until phase4 reads it: `dkls_ceremony.rs:345-350`. CONFIRMED.
- phase4 abort names `abort.index` (the party whose data failed) as blame: `dkls_ceremony.rs:558-573`.
  CONFIRMED — a forged commitment in the victim's slot makes phase4 blame the spoofed `sender`.
- `try_advance` short-circuits once `error`/`output` set (no in-place resume): `dkls_ceremony.rs:421`.
  CONFIRMED.
- Gossip ingress: only a size cap, no committee-membership filter; produces `InboundDkls` with
  `propagation_source = Some(originator)`: `gossip.rs:1099-1135` (originator at 1119,
  `wire_to_event_with_source` at 1120). `gossip_adapter.rs:65-92` threads it into `InboundDkls`.
  CONFIRMED.
- Plaintext broadcast decode, no AEAD/transport key: `dkls_wire_codec.rs:294-298`. CONFIRMED.
- Gossipsub Strict + Signed: `gossip.rs:314,324` (per F021 note, re-confirmed by reference). The
  originator is cryptographically authenticated, but the buffered path never compares against it.

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a committee-membership / sender gate UPSTREAM of the drain that the specialist missed?
NO. Gossip ingress (`gossip.rs:1099-1135`) applies only a size cap and forwards any Strict-signed
frame. Buffer fill (`actor.rs:1334-1345`) applies no auth at all — it just pushes `encoded`. The
ONLY application sender-binding control is `check_dkls_sender_against_propagation_source`, and the
drain path provably never calls it (it can't — it threw away the source at 1337). The bug is the
absence of the gate, not a gate hidden upstream. Stands.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (impact bounded to liveness/blame, not key compromise)
What consumes the spoofed `submit`? `coordinator.submit` → broadcast map insert → `phase4` at
`try_advance_phase23_to_complete` (`dkls_ceremony.rs:558`). phase4 verifies the proof/bip broadcasts;
a forged/garbage commitment in the victim's slot returns `DklsError::Abort { party: abort.index }`
(570-573), NOT a poisoned group key. So this is liveness (ceremony abort/stall) + blame
mis-assignment (the abort names the spoofed honest party), exactly as the finding states. It is NOT
silent threshold-key corruption. The finding already rates this "integrity/liveness, not silent key
corruption" and severity high on the DoS+false-blame basis — consistent with the same `sign_id`/abort
ceiling F021's validator found. So this PARTIALLY bounds impact but does NOT overstate it: the
finding's own impact section is already correctly ceiling'd. The "if blame drives slashing" escalation
is conditional (NEEDS_MORE_DATA below). Partial only against any reader who infers key compromise.

### H3 Downstream enforcement — STANDS (bounds severity, does not catch the spoof)
Does a layer below the actor re-verify the sender? `driver.submit` (`dkls_driver.rs:59-61`) is a pure
pass-through; `coordinator.submit` only cross-checks inner-vs-outer for P2P variants (F114), and
broadcasts have no such field. So no layer re-authenticates the broadcast sender. phase4's
verification is downstream enforcement of *cryptographic consistency* — it converts the forgery into
an abort rather than rejecting it at auth time. The authentication-bypass claim genuinely stands;
phase4 only bounds blast radius to liveness/blame (see H2). Stands.

### H4 PR HEAD currency — STANDS
HEAD == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pin. Clean tree. No drift. Stands.

### H5 Spec carve-out — PARTIALLY INVALIDATED (a doc carve-out exists but is stale/narrower than the bug)
`dkls_wire_codec.rs:276-283` says the peer-id registry "is not yet wired" and frames residual risk as
"liveness-only." Two problems: (a) the doc is STALE — the registry IS wired now at `actor.rs:2462`
and consulted on the live path, so "not yet wired" no longer holds; (b) the carve-out covers the
*plaintext broadcast on the live path* class, but the F024 gap is specifically that the DRAIN path
omits the now-wired check entirely, and the consequence includes blame mis-assignment (an innocent
party named in the abort), which is broader than the "liveness-only" the doc claims. So there is a
documented-as-transitional flavor, but the doc neither anticipates the drain-path omission nor the
blame vector. Reframes public narrative slightly ("the wired check is bypassed on one path + the
sibling doc is stale") rather than "silent undocumented hole." Core gap unchanged. Partial.

### H6 Reachability of harm — STANDS
Can the spoof land via untrusted gossip? Requires: (i) a frame for `target_epoch` arriving while
`active_dkls` is not yet that epoch → buffered (`actor.rs:1334`) — this is the F023(a) happy path
(round-1 messages routinely precede local `StartDkls`, per the fix's own comment 1424-1429); (ii)
attacker controls one Strict-signed mesh peer publishing a `DISCRIMINATOR_PLAINTEXT` broadcast with
`sender()==Q` (`dkls_wire_codec.rs:294-298`) — no AEAD, no committee membership, no peer-id needed;
(iii) `StartDkls` later drains the buffer and submits unchecked (1444). All preconditions are normal
operating conditions / attacker-attainable. Ordering through the buffer is attacker-influenceable
(attacker can send early). Reachable. Stands.

### H7 Test wiring — STANDS
Is the drain path live in production? `StartDkls` is the production ceremony-start handler; the drain
block (1430-1467) runs on every `StartDkls` that finds a non-empty `pending_dkls_inbound` for the
epoch, and that map is filled from real gossip ingress (`gossip.rs:1099-1135` →
`wire_to_event_with_source` → `InboundDkls` → buffer fill 1334-1345). Not test-only. Stands.

### H8 PoC mechanics — NEEDS_MORE_DATA
No executable PoC attached; the claim rests on static reasoning. Each link is line-confirmed above.
A live PoC would need to show that a buffered+drained broadcast attributed to Q (a) reaches `submit`
(it does: `OpenedDklsMessage::Broadcast(m) => driver.submit(m)` at 1442-1444) and (b) actually lands
in `proof_commitments[Q]` and survives to phase4 to produce the blamed abort. The static path is
sound: broadcast insert has no state/dedup guard (349) and `try_advance` reads the map at 549. The
last-write-wins race (attacker frame vs Q's genuine commitment) is plausible but the precise ordering
window is not executed. This does not undercut the authentication-bypass core (the bypass is the
missing check at the actor, upstream of any driver behavior) but leaves the abort-vs-other downstream
outcome unproven by PoC. Impact ceiling stays as written (high, liveness+blame). NEEDS_MORE_DATA.

## Distinctness from F016 / F021 (root-cause separation — requested)

- F016 (mailbox-ordering-assumption, WATERPROOF): unbounded growth of `pending_dkls_inbound` keyed by
  attacker `target_epoch` with no global cap / no stale-epoch eviction → memory-exhaustion DoS. Root
  cause = buffer *sizing/keying*. DISTINCT.
- F021 (sender-spoofing-inside-payload, HAS_CAVEATS): on the LIVE path the F018 check fails OPEN when
  `peer_id_for_party` returns `None` (committee party with empty registered peer-id). Root cause =
  *fail-open inside the check*. DISTINCT.
- F024 (this): on the DRAIN path the F018 check is NEVER CALLED, because the buffer discarded
  `propagation_source` (1337). Root cause = *check omitted on one path*. This works even for parties
  WITH a registered peer-id (F021 needs the empty-peer-id case; F024 does not). DISTINCT root cause.
  All three are facets of the same F023(a) buffer but with non-overlapping fixes — F024's fix (buffer
  the source + run the check on drain) does not fix F016 or F021 and vice versa.

## Overall verdict

WATERPROOF on the core claim: the buffered pre-StartDkls drain (`actor.rs:1430-1462`) submits round
messages to the ceremony state machine without `check_dkls_sender_against_propagation_source`, while
the live path (1373) and sign path (1521) apply it; the buffer (1337) discards the authenticated
`propagation_source`, so the check is structurally impossible on this path. Broadcast variants
(`Phase2ProofCommitment`/`Phase2BipBroadcast`/`Phase3BipBroadcast`) then insert by attacker-chosen
`sender` with no inner cross-check (`dkls_ceremony.rs:349,355,384`), and phase4 blames the spoofed
party on abort (570-573). Every link line-confirmed.

HAS_CAVEATS on framing/impact: (a) impact is liveness (DKG abort/stall) + blame mis-assignment,
bounded by phase4's verification — NOT silent key compromise (H2/H3); (b) the "blame drives slashing"
escalation is conditional and not traced to a slashing consumer here (NEEDS_MORE_DATA); (c) the
"liveness-only" codec doc is stale and narrower than the actual gap, so public framing should note
the blame vector explicitly; (d) no executable PoC for the last-write-wins ordering window (H8).

Verdict: HAS_CAVEATS. Confidence: 0.84.

## Open follow-ups (NOT new findings — for specialist/lead triage)
- Whether abort blame (`DklsError::Abort { party }`) is consumed by any
  exclusion/scoring/slashing path is the key escalation question and was not exhaustively traced
  here; if it is, F024's blame-mis-assignment rises above pure liveness. Worth a downstream trace.
- The "defence-in-depth: reject overwriting an already-populated `sender` slot" suggestion in the
  finding would also mitigate the F021 live-path spoof — shared mitigation surface across F021/F024.
