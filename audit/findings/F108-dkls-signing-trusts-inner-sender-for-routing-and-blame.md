---
id: F108
task: H108
attack_class: dkls23-protocol-correctness
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.95
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# DKLS signing dispatches `kept[..]`, `mul_senders[..]`, `mul_receivers[..]` and abort-blame strings on `message.parties.sender` — the inner byte attacker-controls independent of the wire `sender`, the upper-layer `dkls_sign.rs::submit` never cross-checks `parties.sender == wire sender`, and the protocol's `.unwrap()`s panic on out-of-range inner-sender. A single inbound `Phase1Send` or `Phase2Send` lets any reachable peer either (a) crash a victim's signing actor permanently via `kept.get(&attacker_byte).unwrap()`, or (b) frame an innocent committee member by injecting `parties.sender = victim_to_frame` plus garbage `mul_transmit` that triggers an `Abort::new(self.party_index, "...failed because of Party {framed_index}...")`. The literal F107 self-skip pattern is NOT present in signing.rs, but the same root cause — inner-index field trusted without cross-binding to wire sender or to a sealed set — produces a different, sign-time-specific halt/misattribution primitive.

## Scope files

- `code/hypersnap/crates/dkls23/src/protocols/signing.rs:347-425` —
  `sign_phase2` loop: `counterparty = message.parties.sender`, then
  `kept.get(&counterparty).unwrap()` (line 350) and
  `mul_senders.get(&counterparty).unwrap().run(...)` (line 366). Both
  panic on out-of-range. The blame string at lines 377-383 cites
  `counterparty` (the spoofed inner sender), not a verified identity.
- `code/hypersnap/crates/dkls23/src/protocols/signing.rs:483-562` —
  `sign_phase3` loop: same `counterparty = message.parties.sender`
  (line 485), `kept.get(&counterparty).unwrap()` (line 486), then
  `verify_commitment_point(...)` against `current_kept.commitment`
  whose value depends on the **last** Phase-1 `received` slot whose
  `parties.sender` mapped to `counterparty`. If overwritten in
  `sign_phase2` by an attacker spoof, `sign_phase3` aborts with blame
  on the legitimate party whose inner-index was spoofed
  (`Abort::new(self.party_index, "Failed to verify commitment from
  Party {counterparty}!")`, line 497). The OT-extension session-id is
  derived from `counterparty` too (lines 506-513), so two iterations
  with `counterparty = V_B` invoke `MulReceiver.run_phase2(&same_sid, ...)`
  on the same OTE state.
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs:255-282` —
  upper-layer `submit`: keys `received_1to2`, `received_2to3`,
  `broadcasts_3to4` on the WIRE `sender` byte from the round-envelope
  variant, then later `.values().cloned().collect()`'s on lines 308,
  337, 365 — the BTreeMap key is **discarded**, the inner
  `transmit.parties.sender` is what `signing.rs` dispatches on. No
  cross-check that `transmit.parties.sender == wire sender`. No check
  that `wire sender` is in `signing_committee`. (Phase-3 broadcast
  additionally permits inserting under `wire sender = any byte`,
  including a value not in the committee, contributing to a separate
  but related sign-aggregation primitive — noted under
  "Out-of-scope-here-but-related".)
- `code/hypersnap/crates/dkls23/src/protocols.rs:76-91` — definition
  of `PartiesMessage { sender, receiver }`. Both fields are bare
  `u8` payload bytes with no cryptographic or transport-layer binding.

## Summary

`sign_phase2` and `sign_phase3` in
`crates/dkls23/src/protocols/signing.rs` are the per-counterparty
inner loops of DKLS23 signing. Both extract a routing index `let
counterparty = message.parties.sender;` from the **inner**
`TransmitPhaseXtoY.parties.sender` byte (a free-form field
serialised inside the bincode payload) and use that index to:

1. Look up the victim's local per-counterparty state:
   `kept.get(&counterparty).unwrap()` (sign_phase2 L350, sign_phase3 L486).
2. Look up the victim's OT-extension state for that counterparty:
   `mul_senders.get(&counterparty).unwrap()` (sign_phase2 L366),
   `mul_receivers.get(&counterparty).unwrap()` (sign_phase3 L515).
3. Compose the OT-extension session id with `&counterparty.to_be_bytes()`
   embedded (sign_phase2 L357-364, sign_phase3 L506-513).
4. Write the per-counterparty Phase-2-to-3 state:
   `keep.insert(counterparty, KeepPhase2to3 { ..., commitment:
   message.commitment, ... })` (sign_phase2 L399-408). Last-writer-wins.
5. Compose the **abort blame string**:
   `Abort::new(self.party_index, "Two-party multiplication protocol
   failed because of Party {counterparty}: ...")` (sign_phase2 L377-383),
   and `"Failed to verify commitment from Party {counterparty}!"`
   (sign_phase3 L497).

The upper-layer codec in `dkls_sign.rs::submit` accumulates inbound
messages into `BTreeMap<u8, Transmit>`s keyed on the **wire**
`sender` byte (the envelope field outside the bincode payload), and
in the phase-advance step flattens via `.values().cloned().collect()`
— discarding the key — before passing the slice into
`sign_phase2`/`sign_phase3`. The inner `parties.sender` byte is the
sole index dkls23 uses for routing.

There is **no check anywhere** that the inner `parties.sender`
matches the wire `sender`. There is no check that `parties.sender`
is in `signing_committee`. There is no check that `parties.sender`
is in `data.counterparties`. There is no `if X != party_index`
self-skip pattern (F107's literal lever does not transfer here —
the loops iterate only over inbound messages, which exclude self by
construction).

The exploit primitives the missing cross-check unlocks are:

### Primitive A — panic DoS (one packet)

The `unwrap()`s at sign_phase2 L350 and L366, sign_phase3 L486 and
L515, panic when `counterparty = message.parties.sender` is not a
key in `kept`, `mul_senders`, or `mul_receivers`. Those maps are
populated from `data.counterparties` (the legitimate signing-committee
minus self). An attacker who can deliver one valid wire-codec envelope
to the victim sends:

```rust
DklsSignRoundMessage::Phase1Send {
    sender: 99,                                  // wire — any byte
    receiver: V,                                 // wire — the victim
    transmit: TransmitPhase1to2 {
        parties: PartiesMessage {
            sender: 200,                         // INNER — not in
                                                 // V's signing committee
            receiver: V,
        },
        commitment: junk,
        mul_transmit: junk,                      // never read; panic
                                                 // fires before .run()
    },
}
```

V's `submit` (`dkls_sign.rs:262-265`) checks `receiver == V` —
passes. Inserts `received_1to2[99] = transmit_junk`. Eventually
`try_advance_phase1_to_phase2` flattens, calls `sign_phase2`. Loop
iteration with the spoofed entry: `counterparty = 200`,
`kept.get(&200) = None`, `.unwrap()` PANICS.

The actor task is `tokio::spawn(actor.run())` (`actor.rs:1063`)
with NO `catch_unwind`. The panic unwinds the actor task; the actor
silently dies; `active_dkls_sign` is in an indeterminate state;
subsequent `InboundDklsSign` / `AdvanceDklsSign` / `StartDklsSign`
events queued on `inbound` are received by a dead receiver-half
(`inbound.recv()` returns `None` after the task drops; the `while
let Some(event)` loop in `actor.rs:1111` has already exited via
unwind). **The victim's hyperblock signing pipeline is permanently
disabled until process restart.**

The panic primitive is robust to F018 fixes (the inner `parties.sender`
byte is independent of the wire `sender`) and to any committee-side
authentication (the attacker only needs ONE valid wire envelope; no
correct DLog proof, no correct multiplication payload — junk is
fine, the panic fires before any verification).

### Primitive B — misattribution-blame (one packet, frame an innocent)

The blame string at sign_phase2 L377-383 cites `counterparty` (the
spoofed inner sender). If the attacker spoofs an inner sender that
**is** in V's `data.counterparties` (so no panic) but supplies
malformed `mul_transmit` that fails the multiplication protocol's
internal verification, V returns
`Err(Abort::new(self.party_index, "Two-party multiplication
protocol failed because of Party {V_B}: ..."))` — naming the
innocent V_B as the misbehaving party.

The malformed `mul_transmit` can be any one of:
- a copy of V_B's legitimate `mul_transmit` with one byte flipped
  in `data.u[i][j]` — fails the KOS consistency check
  (`extension.rs:338-342`),
- an `OTEDataToSender { u: vec![], verify_x: zero, verify_t: vec![]
  }` — wrong dimensions, fails inside the OT extension.

V's `sign_phase2` aborts immediately on first bad mul_result. The
upper layer maps this to `DklsError::Abort { party: V, reason:
"...failed because of Party V_B..." }` (`dkls_sign.rs:314-317`).
The supervisor (or operator inspecting the log) sees blame on V_B,
not V_A.

The supervisor's retry-and-exclude policy — if any — excludes V_B
on the next attempt, removing an honest party from the signing
committee. With each retry, V_A can shift blame to a new innocent
party, eventually leaving an unsignable committee.

### Primitive C — phase-2-to-3 commitment-check misattribution

Even if the attacker can't supply a `mul_transmit` that fails
cleanly (some checks require Fiat-Shamir-valid framing), they can
spoof a Phase1Send with `parties.sender = V_B` and a
**different `commitment` byte** alongside the legitimate Phase1Send
from V_B.

Both entries survive `submit` (BTreeMap keyed by wire sender; the
attacker's wire sender is different from V_B's). Both go into the
`received` slice. The loop iterates over both. For BOTH iterations,
`counterparty = V_B`. The line 399-408 `keep.insert(V_B,
KeepPhase2to3 { ..., commitment: message.commitment, ... })` writes
TWICE for the same key V_B. Last-writer-wins on BTreeMap insert.

BTreeMap iteration order during `.values()` is by KEY (wire sender),
ascending. So:
- If the attacker's wire sender > V_B's wire sender → the attacker's
  spoof writes LAST → `keep[V_B].commitment` becomes the attacker's
  bogus commitment.
- If the attacker's wire sender < V_B's wire sender → V_B's
  legitimate commitment wins.

The attacker controls their own wire sender (by signing the
envelope with their own peer-id). They simply pick a wire sender
greater than V_B's index. Even after a hypothetical F018 fix that
binds wire-sender to peer-id, the attacker can ensure their
authenticated party index is greater than V_B's by selecting V_B
as the **lowest-indexed** target (always possible — at least one
innocent party is lower-indexed than the attacker if the attacker
is not the lowest-indexed).

Result: V's `keep[V_B].commitment = bogus`. In phase 3, V receives
V_B's legitimate Phase2Send (containing V_B's true `salt`,
`instance_point`). V's phase 3 loop dispatches with `counterparty =
V_B`, fetches `kept[V_B].commitment = bogus`, calls
`verify_commitment_point(legit_instance_point, bogus_commitment,
legit_salt)` → returns `false` → V aborts:
```
Abort::new(self.party_index, "Failed to verify commitment from
Party V_B!")
```

Blame is again pinned on innocent V_B. The supervisor excludes V_B.

### Primitive D — OT-extension session-id reuse against same OTESender

The OT-extension session id in `sign_phase2` is
```rust
let mul_sid = [
    "Multiplication protocol".as_bytes(),
    &counterparty.to_be_bytes(),
    &self.party_index.to_be_bytes(),
    &self.session_id,
    &data.sign_id,
].concat();
```
When the attacker plants a second `received` entry with
`parties.sender = V_B` (alongside V_B's legitimate one), the loop
calls `mul_senders.get(&V_B).unwrap().run(&mul_sid_same, ...)`
TWICE with the SAME `mul_sid`. Each call invokes
`OTESender.run(&ote_sid_same, ...)` on the same `seeds[i]`,
`correlation[i]` state.

KOS OT extension security assumes each batch session-id is used
**exactly once**. Two runs with the same `ote_sid` and the same
underlying `extended_seeds` (deterministically derived from
`seeds[i]` and `ote_sid`), but two different `data.u` matrices,
exposes the equation
```
q1[i][j] XOR q2[i][j] = correlation[i] · (data.u1[i][j] XOR data.u2[i][j])
```
to an adversary who knows both `data.u` matrices (the attacker
chose at least the second one). If the adversary can recover any
of the `q[i][j]` outputs (via the downstream `v0`, `v1`, `tau` they
observe in V's outbound `TransmitPhase2to3` and `mul_transmit`
contents, or via timing or via comparing against their own honestly
running counterparty role), the equation leaks `correlation[i]` —
i.e., the SENDER's secret bit in the OT extension setup.

The Fiat-Shamir consistency check at `extension.rs:338-342` makes
it hard to construct a SECOND valid `(data.u, data.verify_x,
data.verify_t)` tuple without breaking the random oracle. So the
direct exploit of this primitive requires the attacker either (a)
to replay V_B's legitimate tuple verbatim (which produces the same
`q` and same outputs — useless for the bit-recovery equation), or
(b) to find a colliding Fiat-Shamir transcript (cryptographically
hard).

This primitive is therefore a **defense-in-depth concern, not a
direct break**: the OT extension is being used in a way that
relies on the consistency check to fail-closed. If the consistency
check has any softness — e.g., a future change relaxes the strict
equality check, or a side-channel reveals partial data — this becomes
a key-extraction primitive against the long-lived OTE setup that
persists across signings within the same DKG epoch.

## Round-by-round walk (Primitive B and C — the load-bearing variants)

### Setup

- DKG epoch E has produced parties V_1, V_2, V_3, V_A (party_index
  1, 2, 3, 4, with V_A in 4th slot). `share_count = 4, threshold =
  3` (typical 3-of-4).
- A new signing is started for digest `d` with `signing_committee =
  [2, 3, 4]` (V_2, V_3, V_4=V_A). Each of V_2, V_3, V_4 constructs a
  `DklsSignCoordinator` (via `dkls_sign.rs::HyperblockDklsSigner::signing_coordinator`)
  and calls `start()`, emitting their Phase1Send messages.
- V_A is malicious. The audit goal: V_A wants to frame V_2 for the
  abort and force the supervisor to exclude V_2 from the next sign
  attempt.

### Phase 1 — V_A's spoof

V_A's legitimate phase 1 produces two Phase1Send messages addressed
to V_2 and V_3, with inner `parties.sender = 4`. These V_A emits.

Additionally, V_A crafts the spoof:

```rust
DklsSignRoundMessage::Phase1Send {
    sender: 4,                                   // wire — V_A
    receiver: 3,                                 // V_3 the victim
    transmit: TransmitPhase1to2 {
        parties: PartiesMessage {
            sender: 2,                           // INNER spoofed —
                                                 // claims to be V_2
            receiver: 3,
        },
        commitment: [0xff; 32],                  // bogus, but
                                                 // self-consistent
                                                 // (any 32-byte hash)
        mul_transmit: OTEDataToSender {          // junk → triggers
                                                 // ErrorOT
            u: vec![],
            verify_x: [0u8; 26],
            verify_t: vec![],
        },
    },
}
```

V_A publishes this. The wire codec (`dkls_wire_codec.rs`, scoped
to a per-recipient sealed envelope) seals the payload to V_3's
transport secret. V_3's actor opens it, sees `receiver = 3`,
passes it to `DklsSignCoordinator::submit`.

### V_3's `submit` accepts

`submit` matches `Phase1Send`, checks `receiver == V_3.party_index ==
3` (true), inserts `received_1to2[wire_sender = 4] = transmit_junk`.
Total state of `received_1to2` on V_3 after all phase-1 messages
arrive:

```
{ 2: legit_from_V_2,
  4: spoof_from_V_A_with_inner_sender = 2,
  4: <V_A's own legit phase-1 entry addressed to V_3 — overwritten
        by V_A's spoof: BTreeMap key is wire sender 4 for BOTH the
        legit and the spoof; the LATER arrival wins> }
```

Hmm — there's an in-attacker conflict: V_A's own legit phase-1
message to V_3 and V_A's spoof to V_3 share wire sender = 4. V_A
can split: emit the spoof BEFORE the legit, then emit the legit.
The legit overwrites the spoof on V_3's side — the spoof is lost.

V_A's counter: emit ONLY the spoof and not the legit. V_3 then
sees only `{ 2: legit, 4: spoof }`; the spoof carries inner sender
= 2. V_4=V_A's contribution to V_3 is the spoof (which V_3 cannot
distinguish from a legit V_A entry without verifying the inner
sender against the wire sender).

`try_advance_phase1_to_phase2` checks `received_1to2.len() == 2 ==
signing_committee.len() - 1 == 2`. Passes. Flattens:
```
received = [ legit_V_2, spoof_with_inner_sender = 2 ]
```

(BTreeMap key order is 2, 4. So legit_V_2 iterates first, spoof
iterates second.)

### V_3's `sign_phase2` runs

Iteration 1: `message = legit_V_2`. `counterparty = 2`.
- `kept[2]` exists (V_3's own kept entry for counterparty 2). OK.
- `mul_senders[2]` exists. OK.
- `mul_senders[2].run(&mul_sid_for_2, &input, &legit_mul_transmit)`
  succeeds (legit_V_2 is honest). Returns `(c_u, c_v,
  mul_transmit_2to3)`.
- `keep.insert(2, KeepPhase2to3 { ..., commitment: legit_commitment_2,
  ... })`.
- `transmit.push(TransmitPhase2to3 { parties: { sender: 3, receiver:
  2 }, ... })`. Outbound message scheduled for V_2.

Iteration 2: `message = spoof_inner_sender_2`. `counterparty = 2`.
- `kept[2]` exists. OK.
- `mul_senders[2]` exists. OK.
- `mul_senders[2].run(&mul_sid_for_2, &input, &junk_mul_transmit)`
  — `OTESender::run` returns `Err(ErrorOT)` from the consistency
  check at `extension.rs:338-342` (or earlier from a malformed
  `data.u`).
- Match arm at L376-384 fires:
  ```
  return Err(Abort::new(
      self.party_index = 3,
      "Two-party multiplication protocol failed because of Party 2: ..."
  ));
  ```

V_3 aborts. The blame string says **V_2**.

### Supervisor sees blame on V_2

The upper layer maps this abort to
`DklsError::Abort { party: 3, reason: "...failed because of Party 2: ..." }`
(`dkls_sign.rs:314-317`).

If the supervisor logs and excludes by parsing `reason` for "Party
N", it now excludes V_2. The next sign attempt uses committee
`[3, 4, V_5]` (or similar). V_2 — honest — is wrongly out.

V_A repeats: spoofs `parties.sender = 3` in the next round to
frame V_3. Eventually the committee runs out of acceptable members.
Threshold signing for this epoch halts.

If the supervisor does NOT exclude by parsed blame but simply
retries with the same committee, V_A repeats the spoof and the
ceremony halts again. Each attempt re-attaches blame to a chosen
innocent. Without inner-sender authentication, no retry policy
can identify the actual culprit (V_A).

## Why existing checks don't close the gap

1. **`signing_committee` membership check** at construction
   (`dkls_sign.rs:159-180`) — gates which parties V is willing to
   sign WITH, but does NOT gate which inner `parties.sender` byte
   may appear in inbound messages. V's actor accepts an inbound
   `Phase1Send` with `parties.sender = 200` so long as the wire
   `receiver == V.party_index`.

2. **`submit`'s `receiver != self.party.party_index` filter**
   (L262-265, L272-275) — drops messages not addressed to V on
   the wire, but doesn't drop messages whose inner sender is
   invalid.

3. **OT-extension consistency check**
   (`extension.rs:338-342`) — catches malformed `data.u` /
   `verify_x` / `verify_t` tuples. Causes the misattribution-blame
   primitive (Primitive B) to FIRE, not to be silently absorbed.
   So in the Primitive B exploit, this check is doing exactly the
   wrong thing — it produces the blame string the attacker wants.

4. **Commitment check in `sign_phase3`**
   (L489-499) — verifies that `message.instance_point` matches
   `current_kept.commitment` via `salt`. But `current_kept` was
   populated in `sign_phase2` from one of the inbound messages
   dispatched by `counterparty = parties.sender`. If the attacker
   overwrote it, the check fails — and the abort blames the
   legit V_B whose name the attacker injected (Primitive C).

5. **F018 fix is orthogonal**. F018 binds wire `sender` to the
   libp2p peer-id, preventing wire-sender forgery. After F018 is
   fully fixed, the attacker still publishes from their OWN
   authentic peer-id (wire `sender = V_A`) carrying inner
   `parties.sender = V_B`. The cross-binding between wire and
   inner is NOT in scope of F018's fix.

6. **F023 fix (DKLS round messages dropped and cross-routed)** is
   also orthogonal. F023 addresses gossip-layer routing for DKG
   round messages; it doesn't validate inner protocol fields for
   signing messages.

7. **F107's fix recommendations** (verify every proof in `step5`,
   pre-filter `proofs_commitments` by expected indices, enforce
   `proof_commitment.index == wire sender`) all target DKG. None
   of them apply to signing, because signing has no "proof_commitment"
   field — the analogous field is `parties.sender` inside Transmit
   messages, and signing's `submit` would need the parallel fix.

8. **The phase4 `recovery_id > 1` guard at `dkls_sign.rs:379-385`**
   (F045) is a different sign-phase issue and doesn't intersect
   here.

## Recommended fix

In descending order of robustness — layer at least one, ideally all:

1. **In `dkls_sign.rs::submit`, enforce `transmit.parties.sender ==
   wire sender` for `Phase1Send` and `Phase2Send`**, and reject
   the message otherwise:

   ```rust
   DklsSignRoundMessage::Phase1Send {
       sender, receiver, transmit,
   } => {
       if receiver != self.party.party_index { return Ok(()); }
       if transmit.parties.sender != sender {
           return Err(DklsError::InnerSenderMismatch {
               wire_sender: sender,
               inner_sender: transmit.parties.sender,
           });
       }
       if transmit.parties.receiver != self.party.party_index {
           return Err(DklsError::InnerReceiverMismatch {
               wire_receiver: self.party.party_index,
               inner_receiver: transmit.parties.receiver,
           });
       }
       self.received_1to2.insert(sender, transmit);
   }
   ```

   (Same for Phase2Send.)

2. **Also enforce `wire sender ∈ signing_committee` and `wire
   sender != self.party.party_index` in `submit`**, so an
   attacker not in the committee can't even insert garbage into
   the BTreeMap:

   ```rust
   if !self.signing_committee.contains(&sender) {
       return Err(DklsError::UnknownPartyIndex(
           sender, self.party.parameters.share_count));
   }
   if sender == self.party.party_index {
       // Don't accept others claiming to be us.
       return Err(DklsError::InnerSenderMismatch {
           wire_sender: sender, inner_sender: sender });
   }
   ```

3. **In `signing.rs::sign_phase2` and `sign_phase3`, validate
   `counterparty ∈ data.counterparties` and convert the `.unwrap()`s
   into `Err(Abort)`s**:

   ```rust
   for message in received {
       let counterparty = message.parties.sender;
       if !data.counterparties.contains(&counterparty) {
           return Err(Abort::new(
               self.party_index,
               &format!("Inbound message with inner sender {} not in counterparties",
                        counterparty),
           ));
       }
       let current_kept = kept.get(&counterparty).ok_or_else(|| Abort::new(
           self.party_index,
           &format!("Internal: no kept state for counterparty {}", counterparty),
       ))?;
       // ... similarly for mul_senders / mul_receivers ...
   }
   ```

4. **Reject duplicate inner senders**: even after fix #1, if a single
   wire sender V_A sends two distinct Phase1Send messages with
   different bincode payloads (BTreeMap insert overwrites; only the
   second survives), this doesn't create the duplicate-dispatch
   issue. But fix #4 belt-and-braces: in `sign_phase2`, build a
   `BTreeSet<u8>` of seen `counterparty` values and abort on
   duplicate.

5. **Eliminate the panic surface generically** by wrapping the
   actor's signing call in `std::panic::catch_unwind` (with
   appropriate `AssertUnwindSafe`), or by converting all `.unwrap()`s
   in the dkls23 crate to `?`-propagated errors. The panic surface
   in `signing.rs` is at L196-197 (`assert_eq!`), L350, L366, L486,
   L515, and several invert/`.unwrap()`s (e.g., L333, L651, L692).

## Tests to add

1. **Inner-sender out-of-range panic regression.** In
   `dkls_sign.rs::tests`, construct a 3-of-3 setup, build coordinator
   for V_1. Submit:
   ```rust
   DklsSignRoundMessage::Phase1Send {
       sender: 2, receiver: 1,
       transmit: TransmitPhase1to2 {
           parties: PartiesMessage { sender: 99, receiver: 1 },
           commitment: [0u8; 32], mul_transmit: junk_OTEDataToSender,
       },
   }
   ```
   plus a legit Phase1Send from V_3. Call `try_advance`. Today this
   PANICS (`kept.get(&99).unwrap()`). After fix #3 it must return
   `Err(DklsError::Abort)` with a description mentioning "99" and
   "not in counterparties".

2. **Inner-sender ≠ wire-sender rejection.** Submit a Phase1Send
   with `sender: 2 (wire), transmit: { parties: { sender: 3
   (inner), receiver: 1 } }`. After fix #1, `submit` must return
   `Err(DklsError::InnerSenderMismatch { wire_sender: 2,
   inner_sender: 3 })`. Today, accepted silently.

3. **Misattribution-blame attack reproduction.** Construct a 3-of-3
   {V_1, V_2, V_3}, with V_3 acting as attacker. V_3 emits to V_1
   one Phase1Send with `parties.sender = 2` (claiming to be V_2) and
   junk `mul_transmit`. V_1 also receives a legit Phase1Send from
   V_2. V_1's `try_advance` today produces `DklsError::Abort {
   party: 1, reason: "...failed because of Party 2: ..." }`.
   After fix #1, V_1 must produce `Err(DklsError::InnerSenderMismatch
   { wire_sender: 3, inner_sender: 2 })` BEFORE entering
   `sign_phase2`, never reaching the misattribution.

4. **Commitment-mismatch misattribution (Primitive C).** Construct
   3-of-3 with V_3 attacker. V_3 emits to V_1 a Phase1Send with
   `parties.sender = 2` and a self-consistent (any 32 bytes)
   `commitment`, plus a `mul_transmit` cloned from V_3's OWN legit
   phase-1 broadcast to V_1 (so the multiplication step succeeds,
   no abort fires in phase 2). V_2 also sends legit. After
   phase-2-to-3 advance, V_1's `kept_2to3[2].commitment` is the
   attacker's value (because BTreeMap iter order: wire 2 first,
   wire 3 second; the second iteration overwrites). V_1 receives
   V_2's legit Phase2Send, runs `sign_phase3`, hits the commitment
   check, aborts with `"Failed to verify commitment from Party 2!"`.
   Today this aborts blaming V_2. After fix #1 (`submit`
   rejects the inner-sender mismatch at the gate), this never
   reaches `sign_phase3`.

5. **Panic ≠ permanent actor death (fix #5).** End-to-end test:
   start an `HyperActor`, install epoch keys, submit a
   `Phase1Send` with `parties.sender = 200`, then a legitimate
   `InboundDklsSign` envelope. Without the catch_unwind / `?`
   conversion, the second submit fails because the actor task is
   dead. After fix #5, the actor returns `EventError` for the
   bad packet and continues processing the legit one.

## Out-of-scope-here-but-related

- **Phase-3 broadcast wire-sender unfiltered**:
  `dkls_sign.rs:277-279` inserts `broadcasts_3to4.insert(sender,
  broadcast)` with NO check that `sender ∈ signing_committee` and
  NO check on `sender != self.party.party_index`. Combined with
  `try_advance_phase3_to_complete`'s `len() >= needed` gate
  (`dkls_sign.rs:359-362`), an attacker can fill the BTreeMap with
  arbitrary-keyed bogus broadcasts that pass the count gate and
  feed garbage `(u, w)` into `sign_phase4`'s numerator/denominator
  sums, producing an invalid signature that fails
  `verify_ecdsa_signature` at L674 — abort with
  `"Invalid ECDSA signature at the end of the protocol!"`. No
  party blame. Same fix family: cross-check the wire-sender field
  against `signing_committee` and `!= self`.
- **`pending_sign_queue` retry on abort**: `actor.rs` does not
  appear to dequeue and retry on a `DklsError::Abort` (only on
  `Completed`). An abort halts the current ceremony's progress;
  next-queued ceremony fires only on `finalize_dkls_signature`.
  Combined with F040's "no retry after abort" — F108's
  misattribution gives the supervisor the WRONG party to exclude,
  amplifying F040.

## Related

- **F018** (`findings/drafts/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md`):
  wire-sender unbound to peer-id (DKG side). F108 is the
  signing-side variant of the same root cause family, with the
  added twist that **even with F018's fix in place**, the inner
  `parties.sender` byte is independent of the wire sender and
  remains attacker-controlled. Both findings must be fixed; a
  fix to F018 alone leaves F108 fully exploitable.
- **F023** (`findings/drafts/F023-dkls-round-messages-dropped-and-cross-routed.md`):
  DKG cross-routing. Signing's analog (sealed-to-recipient codec
  per per-recipient transport keys) appears stronger; not directly
  exploited here.
- **F040** (`findings/drafts/F040-dkls-supervisor-no-retry-after-ceremony-abort.md`):
  amplifies F108's misattribution: a single spoofed packet aborts
  the sign with misdirected blame, and the supervisor can't retry
  within the same operator-coordinated retry window. Per-epoch
  hyperblock signing halts.
- **F045** (`findings/drafts/F045-dkls-recovery-id-2-or-3-bricks-signing-no-retry.md`):
  separate sign-phase issue; doesn't intersect.
- **F107** (`findings/drafts/F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md`):
  DKG-side cousin of F108. F107's literal self-skip pattern does
  NOT exist in signing.rs (the signing loops iterate only over
  inbound counterparties, never self). What transfers is the
  meta-pattern: dkls23 trusts an inner protocol field
  (`proof_commitment.index` for DKG, `parties.sender` for signing)
  as a routing/blame index, without binding to any authenticated
  identity. F107's fix recommendations 1, 2, 3 (verify every
  proof, pre-filter by expected indices, enforce inner-index ==
  wire-sender at the upper layer) all have direct analogs for
  signing.rs that this finding lists.
- **In-tree tests at `signing.rs:792-1471`**: simulate honest
  parties in a single-process loop. None of the three test
  functions (`test_signing`, `test_signing_against_ecdsa`,
  `test_dkg_and_signing`) exercise an inbound message with
  spoofed inner `parties.sender`. The defect is invisible to the
  existing test suite.
