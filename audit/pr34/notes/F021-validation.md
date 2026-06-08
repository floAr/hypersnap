# F021 validation — DKLS sender-binding fail-open for peer-id-absent committee party

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f`. HEAD verified == `cab225f` (no drift).

Finding under test: `check_dkls_sender_against_propagation_source` (actor.rs:2462) returns `true` (accept) when
`peer_id_for_party(epoch, claimed_sender)` is `None`, i.e. the claimed sender is an active committee party that
registered an empty `libp2p_peer_id`. This re-opens the F018 sender-spoofing-inside-payload class for that party.

## Code claims re-verified (file:line)

- Fail-open `None` branch: `actor.rs:2474-2479` — `return true` with "permissive" comment. CONFIRMED verbatim.
- Both ingest paths call it: DKG `actor.rs:1373-1379` (ForUs | Broadcast), Sign `actor.rs:1521-1527`. CONFIRMED.
- `peer_id_for_party` resolves active set then registry peer-ids, returns `None` on miss: `runtime.rs:1242-1256`. CONFIRMED.
- Registry inserts peer-id only when non-empty: `validator_registry.rs:805-806`. CONFIRMED.
- Register validation enforces validator_key/validator_address/transport_pubkey lengths but has NO non-empty
  check on `libp2p_peer_id`: `validator_registry.rs:372-411`. CONFIRMED — registration invariant does NOT
  require a peer-id, while it DOES require a 32-byte transport_pubkey (asymmetry is the root cause).
- HTTP parse uses `.unwrap_or_default()` (empty vec when omitted): `http_handler.rs:234-239`. CONFIRMED.
- Test fixtures register with `libp2p_peer_id: vec![]`: `runtime.rs:6813,6863,6899,6972`. CONFIRMED — empty peer-id
  is a fully supported shape.
- Gossipsub Strict + Signed: `gossip.rs:314,324`. Originator passed as source: `gossip.rs:1119-1122`. CONFIRMED.
- Plaintext broadcast decode (no AEAD): `dkls_wire_codec.rs:294-298`. CONFIRMED.

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a committee-membership gate on the gossip ingress that drops a non-committee publisher before the actor?
NO. `GossipMessage::HyperWire` ingress (`gossip.rs:1099-1135`) checks only size cap, then forwards any Strict-signed
frame to the actor with `originator` as source. There is no "is this peer a committee member" filter at ingress.
The ONLY application-level sender-binding control is `check_dkls_sender_against_propagation_source` itself — the
function that fails open. So the bug is not masked by an upstream gate; it IS the gate. Stands.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (impact bounded, not zero)
What consumes a spoofed `submit`? `dkls.driver.submit(message)` → `coordinator.submit` (dkls_driver.rs:59-61).
The codec doc-comment (`dkls_wire_codec.rs:276-283`) and the finding both assert residual risk is liveness-only:
DKLS23 `sign_id` binding makes a forged round message cause a peer-side Abort, not threshold-secret extraction or
state corruption. I did not find evidence contradicting that bound (no path where a `submit`-accepted spoofed
broadcast writes finalized state without the ceremony's own internal consistency/`sign_id` checks). The finding
already rates this medium and explicitly flags the unbounded case as "not re-reviewed exhaustively." So impact is
real but correctly bounded to liveness/griefing (ceremony abort / stall of reward / lock-root / burn signing).
This does not invalidate the finding; it confirms the finding's own impact ceiling. Partial only re: the
"if downstream treats spoof as state-affecting, impact rises" speculation, which remains NEEDS_MORE_DATA.

### H3 Downstream enforcement — STANDS (with caveat that it bounds severity, see H2)
Does a lower layer re-verify the sender? The DKLS coordinator's `sign_id` binding is exactly that downstream
enforcement — but it enforces *consistency/abort*, not *authentication of who sent the frame*. It converts a forgery
into an abort rather than rejecting the forgery at authentication time. So the F018 control (authenticate sender)
genuinely IS bypassed; the downstream layer only limits the blast radius to liveness. The authentication-bypass
claim stands; the catastrophic-impact claim is correctly downgraded by this layer.

### H4 PR HEAD currency — STANDS
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pinned commit. No drift. Stands.

### H5 Spec carve-out — PARTIALLY INVALIDATED (documented-as-transitional, but stale & not fail-closed)
The author's doc comment (`actor.rs:2447-2455`) explicitly frames the `None` branch as intentional "pre-rollout
permissive mode … until every active validator has registered a `libp2p_peer_id`." So there IS a doc carve-out:
the behavior is documented as deliberate. HOWEVER (a) it is evaluated per-sender per-frame, so it never converges —
any party that simply never supplies a peer-id stays permissive forever, which the comment does not acknowledge;
(b) the codec doc (`dkls_wire_codec.rs:276-283`) is now STALE — it says the registry "is not yet wired" even though
actor.rs:2462 wires it, which weakens any "this is a known, tracked gap" defense. Net: this reframes the finding
slightly toward "documented-as-transitional but the doc is wrong about convergence and a sibling doc is stale,"
rather than "silent undocumented hole." The security gap itself is unchanged. The author intent reduces the
"hidden footgun" framing but the medium rating survives.

### H6 Reachability of harm — STANDS
Can the spoof actually land? Requires: (i) a committee party Q with empty peer-id — confirmed permissible and a
supported registration shape (H-fixtures, no validation); (ii) an in-flight ceremony so `active_dkls` /
`active_dkls_sign` matches `target_epoch` (actor.rs:1380-1384 / 1528-1532) — a normal operating condition during
DKG/sign rounds; (iii) attacker controls one Strict-signed mesh peer publishing a DISCRIMINATOR_PLAINTEXT frame
with `sender()==Q`. No AEAD/transport key needed for the plaintext branch (codec:294-298), no committee membership
needed (H1). All preconditions are attainable. Reachable. Stands.

### H7 Test wiring — STANDS
Is the buggy function actually called in production? `check_dkls_sender_against_propagation_source` is invoked on
the live inbound DKLS DKG (actor.rs:1373) and sign (actor.rs:1521) paths, which are driven by real gossip ingress
(gossip.rs:1099-1135 → wire_to_event_with_source → HyperActorEvent::InboundDkls). Not test-only. Stands.

### H8 PoC mechanics — NEEDS_MORE_DATA
No executable PoC is attached to the finding; the claim rests on static reasoning. The static chain is sound and
each link is line-confirmed above. A live PoC would need to demonstrate that a spoofed broadcast attributed to Q is
actually fed to `submit` (vs silently dropped as NotForUs or rejected by the driver). The DKG broadcast path opens
to `OpenedDklsMessage::Broadcast` (codec:294-298) which the actor matches and submits (actor.rs:1367,1385), so the
ingest is plausible, but the precise driver acceptance of an out-of-context round-1 message was not executed. This
does not undercut the authentication-bypass claim (the bypass is at the binding check, upstream of the driver) but
leaves the downstream abort-vs-other behavior unproven by PoC. Hence the impact ceiling stays as written (medium).

## Overall verdict

WATERPROOF on the core claim (the F018 sender-binding control is bypassed for any active committee party with an
empty registered `libp2p_peer_id`, and nothing forces a committee member to register one). Confirmed by line.
HAS_CAVEATS on impact framing: (a) impact is liveness/griefing-bounded by the DKLS `sign_id`/abort behavior — the
finding already says this; (b) the `None` branch is documented as intentional transitional behavior (actor.rs:2447),
so the public framing should be "documented-as-transitional but non-converging + stale sibling doc," not "silent
hole"; (c) no executable PoC for the downstream driver acceptance.

Verdict: HAS_CAVEATS. Confidence: 0.82.

## Open follow-ups (NOT new findings — for specialist/lead triage)
- The codec doc-comment `dkls_wire_codec.rs:276-283` claims the peer-id registry "is not yet wired" but it IS wired
  at `actor.rs:2462`. Stale doc; worth a doc-correction note, not a security finding on its own.
- `transport_pubkey` is enforced 32-byte at registration but `libp2p_peer_id` has no non-empty check
  (`validator_registry.rs:386-392`) — the asymmetry is the registration-invariant root cause and matches the
  finding's suggested direction.
