# F024 trace — buffered pre-StartDkls DKG drain skips the F018 sender/peer-id check

Finding: `findings/F024-buffered-dkls-dkg-drain-skips-sender-authentication.md`
Validation: `findings/notes/F024-validation.md` (verdict HAS_CAVEATS, conf 0.84)
Code (READ-ONLY): `code/hypersnap` @ `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`

This trace does not re-judge the verdict. It documents the entry-point→sink
reachability of a spoofed-sender DKG broadcast frame from the `hyper/dkg/v1`
gossip topic to the ceremony state-machine insert, via the drain path that
omits `check_dkls_sender_against_propagation_source`.

## Entry point(s)

- Gossip ingress for a `HyperWire` frame on the DKG topic:
  `code/hypersnap/src/network/gossip.rs:1099` (match arm), size cap at
  `:1100`, hand-off to actor channel at `:1119-1124`.
  - The libp2p gossipsub originator is captured here
    (`originator.unwrap_or(peer_id).to_bytes()`, `:1119`) and threaded as
    `propagation_source` into the event via
    `code/hypersnap/src/hyper/gossip_adapter.rs:65` →
    `InboundDkls { target_epoch, encoded, propagation_source }` at
    `gossip_adapter.rs:84-88`.
- Gossipsub is `ValidationMode::Strict` (`gossip.rs:314`) +
  `MessageAuthenticity::Signed` (`gossip.rs:324`): the originator peer-id is
  cryptographically authenticated. The frame *payload* (`encoded`,
  containing the inner DKLS `sender: u8`) is NOT — the codec documents
  `sender` as an untrusted hint.

## Trust boundary crossed

Untrusted network → ceremony state machine.

A remote gossip peer (any Strict-signed mesh peer; no committee membership,
no DKLS transport-key, no registered peer-id required) crosses into this
node's DKG accumulator. The boundary that *should* gate this crossing is
`HyperActor::check_dkls_sender_against_propagation_source`
(`actor.rs:2462`), which binds the inner claimed `sender` to the
authenticated originator via `runtime.peer_id_for_party(epoch, sender)`.
On the drain path that boundary check is never invoked — and cannot be,
because the buffer threw away `propagation_source` (see hop 2).

## Call path (ordered file:line hops)

1. `network/gossip.rs:1099` — DKG `HyperWire` frame accepted (size cap only),
   authenticated originator captured at `:1119`, forwarded at `:1120-1124`.
2. `hyper/gossip_adapter.rs:84` — `InboundDkls { target_epoch, encoded,
   propagation_source }` constructed (`:87` carries the source).
3. `hyper/actor.rs:1321` — `InboundDkls` handler. Liveness check `is_active`
   at `:1329-1333`. When the ceremony for `target_epoch` is NOT yet active
   (`!is_active`, `:1334`): buffer the frame.
   - `hyper/actor.rs:1337` — **`buf.push(encoded)`**: only `encoded` is
     stored; `propagation_source` is dropped. Early `return Ok(())` at
     `:1345`. THIS is where the authenticated originator is discarded.
     (Contrast: the live, already-active branch at `:1367-1385` DOES call
     the F018 check at `:1373` before `submit` at `:1385`.)
4. `hyper/actor.rs:1397` — `StartDkls` handler fires later (supervisor
   dispatch). `driver.start()` at `:1422`.
5. `hyper/actor.rs:1430` — drain `pending_dkls_inbound.remove(&target)`;
   loop over each buffered `encoded` (`:1431`).
   - `:1433` — `open_dkls_round_message(...)` decodes the plaintext
     broadcast (no AEAD for `DISCRIMINATOR_PLAINTEXT` broadcasts).
   - `:1442-1444` — `OpenedDklsMessage::ForUs(m) | Broadcast(m) =>
     driver.submit(m)`. **No `check_dkls_sender_against_propagation_source`
     here** (it is absent and impossible — the source is not in scope).
     This is the missing-guard sink-entry, ~`actor.rs:1444`.
6. `hyper/dkls_driver.rs:59-61` — `DklsDriver::submit` is a thin pass-through
   to `coordinator.submit` (no auth added).
7. `crates/hypersnap-crypto/src/dkls_ceremony.rs:333` —
   `DklsCeremonyCoordinator::submit`. Broadcast variants insert by the
   attacker-chosen `sender` with no inner/outer cross-check:
   - `Phase2ProofCommitment` → `proof_commitments.insert(sender, ...)`
     `:349` (no state/dedup guard).
   - `Phase2BipBroadcast` → `bip_broadcasts_2to4.insert(sender, ...)` `:355`.
   - `Phase3BipBroadcast` → `bip_broadcasts_3to4.insert(sender, ...)` `:384`.
   - (The F114 inner-vs-outer guard at `:375`/`:391`/`:409` covers only the
     P2P `Phase*ZeroShareSend`/`Phase3MulSend` variants, which carry an
     inner `parties.{sender,receiver}`. Broadcasts have no such field.)
8. `crates/hypersnap-crypto/src/dkls_ceremony.rs:548-558` —
   `try_advance_phase23_to_complete` collects `proof_commitments.values()`
   and the bip-broadcast maps and feeds `phase4::<Secp256k1>(...)`.
   A forged/garbage commitment in the victim's slot makes phase4 return
   `DklsError::Abort { party: abort.index, reason }` (`:570-573`), where the
   blame `party` is the spoofed `sender` (an innocent committee member).

## Attacker capability / preconditions

- Membership: control of one libp2p mesh peer that can publish a
  Strict-signed gossipsub frame on the DKG topic. No committee membership,
  no DKLS transport secret, no registered validator peer-id required.
- Payload: a `DISCRIMINATOR_PLAINTEXT` DKLS broadcast variant
  (`Phase2ProofCommitment` / `Phase2BipBroadcast` / `Phase3BipBroadcast`)
  with inner `sender = Q` (a target committee party index), targeted at the
  victim node's `target_epoch`.
- Ordering: the frame must arrive at the victim while `active_dkls` is not
  yet that epoch, so it is buffered (`actor.rs:1334`). This is the F023(a)
  happy path — round-1 messages routinely precede the local `StartDkls`
  (per the fix's own comment, `actor.rs:1424-1429`) — and an attacker can
  simply send early, so the ordering window is attacker-influenceable.

## Guards on the path

- `gossip.rs:1100` size cap (`MAX_HYPER_WIRE_BYTES`) — does not authenticate
  sender.
- `gossip.rs:314/324` Strict+Signed gossipsub — authenticates the
  *originator peer-id*, but the inner DKLS `sender` is never compared to it
  on this path.
- `actor.rs:1334` `is_active` gate — routes to the buffer; not a security
  guard, it is the condition that *selects* the unauthenticated path.
- `check_dkls_sender_against_propagation_source` (`actor.rs:2462`) — the
  intended guard. Present on the live path (`actor.rs:1373`) and sign path
  (`actor.rs:1521`); ABSENT on the drain path (`actor.rs:1444`). Even where
  present, it is fail-open when the originator is `None` (`:2470`) or when no
  peer-id is registered for the party (`:2478`) — that fail-open is F021's
  root cause, not F024's.
- F114 inner/outer cross-check in `coordinator.submit`
  (`dkls_ceremony.rs:375/391/409`) — covers only P2P variants; does NOT
  cover broadcasts, so it provides no protection on this path.
- phase4 cryptographic verification (`dkls_ceremony.rs:558`) — the only
  downstream backstop. It does NOT reject the spoof at auth time; it
  converts a forged broadcast into a `DklsError::Abort` blaming the spoofed
  party. This is what bounds impact (see verdict).

## Reachability verdict

REACHABLE — exploitable to liveness/blame impact only (bounded).

Justification: every hop is line-confirmed at the pinned commit. An
unauthenticated, Strict-signed gossip peer can land a broadcast frame in the
pre-StartDkls buffer (`actor.rs:1337`, which discards the authenticated
`propagation_source`); the `StartDkls` drain
(`actor.rs:1430-1462`, submit at `:1444`) then hands it to
`coordinator.submit` with no sender/peer-id check, and broadcast variants
insert by attacker-chosen `sender`
(`dkls_ceremony.rs:349/355/384`) with no inner cross-check. The crossing of
the untrusted-network → state-machine boundary is real and the F018 guard is
structurally bypassed on this path (the source was thrown away before it
could be checked).

Impact ceiling (per validator H2/H3, restated, not re-judged): DKLS
`sign_id`/phase4 verification converts the forgery into a ceremony **abort**
(`DklsError::Abort { party: <spoofed sender> }`, `dkls_ceremony.rs:570-573`),
not a silently-poisoned group key. So the harm is **liveness** (per-epoch DKG
abort/stall; no in-place resume, `dkls_ceremony.rs:421`) plus **blame
mis-assignment** (an innocent committee member is named in the abort). The
"blame drives slashing" escalation remains conditional and was not traced to
a slashing consumer (validator NEEDS_MORE_DATA, H8 — no executable PoC for
the last-write-wins ordering window).

## Contrast with sibling findings (shared buffer, distinct root causes)

- F021 (`findings/F021-...md`): LIVE path fail-open. The F018 check IS
  called but returns `true` when `peer_id_for_party` is `None`
  (`actor.rs:2474-2478`). Root cause = fail-open *inside* the check; needs
  the empty-peer-id case. F024 does not — it works for parties WITH a
  registered peer-id because the check is never reached.
- F024 (this): DRAIN path the check is NEVER CALLED, because the buffer
  discarded `propagation_source` at `actor.rs:1337`. Root cause = check
  omitted on one path.
- F016 (`findings/F016-...md`): unbounded growth of `pending_dkls_inbound`
  keyed by attacker `target_epoch` (cap is per-epoch only,
  `actor.rs:1336`, with no global cap / stale-epoch eviction) →
  memory-exhaustion DoS. Root cause = buffer sizing/keying.

All three touch the same F023(a) buffer but have non-overlapping fixes.
