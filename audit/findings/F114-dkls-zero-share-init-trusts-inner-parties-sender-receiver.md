---
id: F114
task: H114
attack_class: dkls23-protocol-correctness
severity: high
status: draft
related_findings:
  - id: F107
    relationship: related-but-distinct
  - id: F108
    relationship: related-but-distinct
  - id: F110
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# DKLS DKG zero-share initialization in `phase4` (`dkg.rs:731-773`) dispatches on the inner `TransmitInitZeroSharePhase2to4.parties.sender / .receiver` byte and on `TransmitInitZeroSharePhase3to4.parties.sender / .receiver` byte — the ceremony layer (`dkls_ceremony.rs:357-381`) keys the accumulator BTreeMaps on the **wire** `sender` byte but never cross-checks the inner `zero_init.parties.sender == wire sender` or `zero_init.parties.receiver == self.party_index`; the inner-index field is an independent attacker-controlled `u8` (analogous to F107's `proof_commitment.index` and F108's `transmit.parties.sender`). Three exploit primitives reachable from any peer that can publish into the ceremony: (A) one-packet DoS via inner `parties.receiver != V.party_index` triggers `dkg.rs:741` blame-the-victim abort; (B) misattribution-blame for the zero-share commitment-verify failure at `dkg.rs:760-762` ("Party {their_index} cheated when sending the seed!") — frames an innocent counterparty; (C) silent ZeroShare-vec corruption when a committee-member attacker emits a single Phase2/Phase3 ZeroShareSend with `parties.sender = T (T != attacker)` from their own wire identity, the BTreeMap-keyed-by-wire-sender OVERWRITES the attacker's own honest entry, V's phase4 loop finds NO Phase2 entry with `parties.sender == attacker`, the seeds vec is silently missing the (V, attacker) pair, and subsequent threshold signing aborts at the final `verify_ecdsa_signature` with `"Invalid ECDSA signature at the end of the protocol!"` (no party blame). Same root-cause family as F107/F108/F110 (inner-index trust pattern), distinct caller (zero-share init) with distinct downstream consequences (DKG-time blame-the-victim DoS, DKG-time framing-blame, OR sign-time silent corruption with blame-less abort).

## Scope files

- `code/hypersnap/crates/dkls23/src/utilities/zero_shares.rs:62-83` —
  `ZeroShare::generate_seed_pair`: takes `index_party, index_counterparty,
  seed_party, seed_counterparty` and produces a `SeedPair { lowest_index,
  index_counterparty, seed }`. The `seed` is `seed_party XOR
  seed_counterparty` (good — commutative, no chair-bias possible). The
  `lowest_index` flag is `index_party <= index_counterparty` (this is
  the sign-flip lever that makes the per-pair fragments cancel between
  the two parties in the pair). `index_counterparty` is stored verbatim
  and is later used by `compute()` as the routing index for inclusion
  in a signing session. **The function does not — and cannot, by API
  shape — verify that `index_counterparty` corresponds to the actual
  party who contributed `seed_counterparty`**; that binding must be
  enforced by the caller. The caller in question (`dkg.rs::phase4`)
  fails to enforce it.
- `code/hypersnap/crates/dkls23/src/utilities/zero_shares.rs:101-126` —
  `compute<C>(counterparties, session_id)`: walks `self.seeds` and
  for each `SeedPair { lowest_index, index_counterparty, seed }`:
  - skips if `!counterparties.contains(&index_counterparty)`,
  - computes `fragment = hash_as_scalar::<C>(&seed, session_id)`,
  - adds (`lowest_index = false`) or subtracts (`lowest_index = true`)
    the fragment.
  Two correctness premises: (1) for every counterparty `T` in the
  signing committee, V's seeds vec contains EXACTLY ONE SeedPair with
  `index_counterparty = T`, and (2) that SeedPair's `seed` equals
  `seed_V XOR seed_T` where the two parties agree on the same XOR. F114
  attacks premise (1): the attack can cause V's seeds vec to either
  duplicate an entry for `T` (raising the local fragment-sum count) or
  silently omit an entry for `T` (lowering it). Either way the
  zero-sum invariant `Σ_party zeta_party == 0` is broken.
- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:731-773` — the
  vulnerable callsite. The triple-nested loop processes `zero_kept` (V's
  own keeps for each target party `T`), `zero_received_phase2` (the
  Vec collected from `zero_received_2to4.values()` — the BTreeMap key
  is DISCARDED on `.collect()`), and `zero_received_phase3` (similarly
  flattened). The loop:
  - Line 737-738: extracts `my_index = message_received_2.parties.receiver`
    and `their_index = message_received_2.parties.sender` — the **inner**
    fields, attacker-controlled.
  - Line 741-746: if `my_index != data.party_index`, abort with
    `"Received a message not meant for me!"` and blame `data.party_index`
    (the local victim, NOT the spoofer). This is the one-packet DoS
    primitive — a single spoofed Phase2ZeroShareSend with `parties.receiver
    = X (X != V)` halts the whole DKG ceremony for V with self-blame.
  - Line 749-752: `if *target_party != their_index || msg3.parties.sender
    != their_index { continue; }` — `their_index` is the spoofed inner
    value, NOT the wire sender. The continue path is reached for all
    iterations where the inner `parties.sender` doesn't match the current
    `target_party`. Critical bug: this means a spoof with inner
    `parties.sender = T` is treated as a candidate "from party T",
    even when the WIRE sender is the attacker A.
  - Line 755-762: `ZeroShare::verify_seed(msg3.seed, msg2.commitment,
    msg3.salt)` — this DOES verify the (seed, commitment, salt) triple
    are consistent, but it verifies them as a **standalone hash check**
    with NO party-index binding. Failure aborts with
    `"...Party {their_index} cheated when sending the seed!"`, where
    `their_index` is the SPOOFED inner sender. Misattribution-blame
    primitive — frames the spoofed inner sender.
  - Line 765-770: pushes `SeedPair { my_index, their_index, kept_seed,
    msg3.seed }` into V's seeds vec. The pushed `index_counterparty`
    is the spoofed inner `their_index`, the `seed_counterparty` is
    `msg3.seed` — V's local zero-share state diverges from the actual
    seed-pair agreement with the real party `their_index` (because the
    real party never sent this `msg3.seed`).
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:357-365`
  — `Phase2ZeroShareSend` submit branch:
  ```rust
  DklsRoundMessage::Phase2ZeroShareSend {
      sender, receiver, zero_init,
  } => {
      if receiver != self.party_index { return Ok(()); }     // L362
      self.zero_received_2to4.insert(sender, zero_init);     // L365
  }
  ```
  Checks the TOP-LEVEL `receiver` against `self.party_index` (a wire
  field that the wire codec already binds at `dkls_wire_codec.rs:236`
  via the `message.sender() == sender && message.receiver() == Some(receiver)`
  identity-check, which verifies wire vs top-level only — see below).
  **Does not cross-check `zero_init.parties.sender == sender` or
  `zero_init.parties.receiver == self.party_index`**. The inserted
  key is the top-level wire `sender`, and the value is the entire
  bincode-deserialised `zero_init` whose inner `parties.{sender,receiver}`
  are independent attacker-chosen bytes.
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:373-381`
  — `Phase3ZeroShareSend` submit branch — same shape, same missing
  inner-vs-wire check.
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:529-532`
  — phase4 advance step flattens BTreeMaps:
  ```rust
  let zero2: Vec<TransmitInitZeroSharePhase2to4> =
      self.zero_received_2to4.values().cloned().collect();
  let zero3: Vec<TransmitInitZeroSharePhase3to4> =
      self.zero_received_3to4.values().cloned().collect();
  ```
  The BTreeMap KEY (wire sender) is discarded; `phase4` sees a Vec of
  payloads and dispatches purely on inner `parties.sender / .receiver`.
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:127-150`
  — `sender()` and `receiver()` accessors return the TOP-LEVEL variant
  fields (the wire `sender`/`receiver` bytes), NOT the inner
  `zero_init.parties.sender / .receiver`. So the wire codec's
  inner/outer consistency check at `dkls_wire_codec.rs:236-241` only
  binds the wire byte to the top-level variant field — it does not
  reach into `zero_init.parties`.
- `code/hypersnap/crates/dkls23/src/protocols/signing.rs:262-280` —
  the downstream consumer: `Party.zero_share.compute::<C>(&data.counterparties,
  &zero_sid)` produces `zeta`, which is added into `key_share =
  poly_point * l + zeta` at L336. If V's `zero_share.seeds` is
  corrupted (missing or duplicate entries), `zeta_V` is biased; the
  final signature fails the `verify_ecdsa_signature` check at
  `signing.rs:674-680`; V aborts with `"Invalid ECDSA signature at
  the end of the protocol!"` and blames itself (`self.party_index`).
  No party blame for the attacker.

## Summary

This is the **zero-share-initialization-side variant of F107/F108**,
applying the inner-index trust pattern to the DKLS23 zero-share
initialization protocol (Functionality 3.4, page 7 of the DKLS23
paper, implemented in `utilities/zero_shares.rs` and integrated into
the DKG via `dkg.rs::phase2`/`phase3`/`phase4`).

The `utilities/zero_shares.rs` file itself is **a faithful and
correctness-clean implementation** of the seed-pair-commitment-XOR
zero-share scheme:

- `generate_seed_with_commitment` produces `(seed, commit(seed), salt)`
  honestly.
- `verify_seed` is a thin wrapper around `commits::verify_commitment`.
- `generate_seed_pair` XORs the two parties' seeds (the suggested
  variant from DKLS23, which is more robust than addition because
  XOR is its own inverse and the per-bit independence prevents
  chair-bias attacks).
- `lowest_index` derivation is straightforward and the sign-flip in
  `compute` is correct: the pair `(V, T)` contributes `-hash(seed_pair)`
  at the lower-indexed party and `+hash(seed_pair)` at the higher-indexed
  party — summing to zero across the pair, hence Σ_party zeta_party = 0
  across the whole committee.
- The session-id binding (`hash_as_scalar(seed, session_id)` in
  `compute`) prevents cross-session replay of zero-share fragments.
  The session_id passed into `compute` in production is
  `["Zero shares protocol".as_bytes(), &self.session_id, &data.sign_id]`
  (signing.rs:262-268), so it binds both the DKG session_id and the
  per-sign-attempt sign_id. **No `compute`-side finding.**

**The finding is therefore NOT in `zero_shares.rs` itself**, but in
its caller `dkg.rs::phase4` (lines 731-773) and in the upper-layer
ceremony codec `dkls_ceremony.rs::submit` (lines 357-381). Both fail
to bind the *inner* `parties.sender / .receiver` fields of
`TransmitInitZeroSharePhaseXto4` to any authenticated identity. The
same omission exists at exactly the same code-pattern site for
proofs_commitments (F107), for signing transmits (F108), and for
the refresh-side step5 (F110). F114 is the zero-share-init variant.

The three exploit primitives this enables:

### Primitive A — one-packet DKG DoS via inner `parties.receiver != V.party_index`

The cleanest exploit. Attacker A publishes:

```rust
DklsRoundMessage::Phase2ZeroShareSend {
    sender: A,                                        // wire — A's
                                                      // identity (F018
                                                      // fix doesn't help)
    receiver: V,                                      // wire — the victim
    zero_init: TransmitInitZeroSharePhase2to4 {
        parties: PartiesMessage {
            sender: T,                                // INNER — any byte;
                                                      // doesn't need to
                                                      // match A
            receiver: 99,                             // INNER receiver:
                                                      // ANY byte
                                                      // != V.party_index
        },
        commitment: junk,                             // never reached
    },
}
```

V's wire codec opens the frame (top-level sender=A, receiver=V — both
match the wire bytes). V's `submit` checks top-level `receiver == V`
— passes. Inserts `zero_received_2to4[wire_sender = A] = zero_init`.

When V's `try_advance_phase23_to_complete` runs, it flattens to a Vec
and calls `phase4`. The triple-nested loop hits the spoofed message;
on the FIRST iteration touching this entry (regardless of which
target_party V is currently processing in the outer loop), the check
at `dkg.rs:741-746`:

```rust
let my_index = message_received_2.parties.receiver;       // = 99
if my_index != data.party_index {                         // 99 != V ⟹ TRUE
    return Err(Abort::new(data.party_index,
        "Received a message not meant for me!"));
}
```

fires immediately. The ENTIRE phase4 aborts. The DKG ceremony for V
fails with self-blame; the supervisor (per F040) cannot retry in the
epoch; chain halts on DKG.

**Critically**: the check is INSIDE the triple-nested loop and runs
**before** the `target_party != their_index || msg3.parties.sender !=
their_index { continue; }` filter at L749-752. So even messages that
don't match the current target_party trigger the abort. ANY single
spoofed Phase2ZeroShareSend whose inner `parties.receiver != V.party_index`
halts V's phase4.

Cost to attacker: ONE packet. Damage: full DKG halt for the epoch (or
forever, given F040 no-retry).

### Primitive B — misattribution-blame for the seed/commitment mismatch

Attacker A is a committee member (party_index=A, in the DKG). After
honestly running phase 1, A crafts an additional Phase2ZeroShareSend
addressed to V that frames innocent T:

```rust
DklsRoundMessage::Phase2ZeroShareSend {
    sender: A,                                        // wire — A's
                                                      // authentic identity
    receiver: V,                                      // wire — V is victim
    zero_init: TransmitInitZeroSharePhase2to4 {
        parties: PartiesMessage {
            sender: T,                                // INNER spoof —
                                                      // claims to be T
            receiver: V,                              // INNER ok
        },
        commitment: junk_32_bytes,                    // arbitrary,
                                                      // NOT consistent
                                                      // with T's actual
                                                      // (seed, salt)
    },
}
```

V's `submit` inserts under wire-sender key `A` (different from T's
wire-sender, so no overwrite). V's `zero_received_2to4`:
`{ T: legit_phase2_from_T, A: spoof_phase2_with_inner_sender_T, ... }`.

In V's `phase4` triple-loop, when `target_party = T`:
- Iteration (msg2 = legit_phase2_from_T, msg3 = legit_phase3_from_T):
  - `target_party = T, their_index = T` → enters body.
  - `verify_seed(legit_seed_T, legit_commit_T, legit_salt_T) = TRUE`.
  - Pushes `SeedPair(V, T, kept, legit_seed_T)`.
- Iteration (msg2 = spoof_with_inner_T, msg3 = legit_phase3_from_T):
  - `target_party = T, their_index = T` (the SPOOFED value) →
    enters body.
  - `verify_seed(legit_seed_T, JUNK_commit, legit_salt_T) = FALSE`.
  - **Aborts with `"...Party T cheated when sending the seed!"`**.

Innocent T is blamed. The supervisor (if it parses blame from abort
descriptions, common pattern) excludes T on retry. The attacker repeats
with a different victim/target combination to frame every honest
party in turn. Eventually the committee has no honest members and
DKG cannot complete; chain halt with progressive misattribution.

Note: BTreeMap iteration order for `zero_received_2to4.values()` is
ascending by wire-sender key. If T's wire-sender < A's wire-sender,
the legit entry comes first; the legit iteration succeeds and pushes
the SeedPair, then the spoof iteration triggers the abort. The
attacker controls their own wire-sender (= their authenticated party
index). To guarantee their spoof iterates AFTER T's legit entry,
they target T such that T's index < A's index. Always possible if
A is not the lowest-indexed party (and even if A is lowest-indexed,
they can still frame: the abort fires in the spoof iteration regardless
of order).

### Primitive C — silent seed-pair-vec corruption causing sign-time abort

This is the most consequential variant: the attack does NOT abort
the DKG. The DKG completes silently with V holding a CORRUPTED
ZeroShare. The corruption surfaces only at signing time, with
blame-less abort.

Attacker A is a committee member. Instead of running phase 2
honestly, A emits ONLY a spoofed Phase2ZeroShareSend addressed to V
(NOT A's own legit phase-2 message to V):

```rust
DklsRoundMessage::Phase2ZeroShareSend {
    sender: A,                                        // wire — A
    receiver: V,                                      // wire — V
    zero_init: TransmitInitZeroSharePhase2to4 {
        parties: PartiesMessage {
            sender: T,                                // INNER — A claims
                                                      // this is from T
                                                      // (T != A)
            receiver: V,                              // INNER ok
        },
        commitment: any_consistent_commit(seed_X, salt_X),
                                                      // attacker-chosen
                                                      // seed_X
                                                      // ↳ NOT what real
                                                      //    T sent
    },
}
```

A also emits a matching Phase3ZeroShareSend:

```rust
DklsRoundMessage::Phase3ZeroShareSend {
    sender: A,                                        // wire — A
    receiver: V,                                      // wire — V
    zero_init: TransmitInitZeroSharePhase3to4 {
        parties: PartiesMessage {
            sender: T,                                // INNER — same
                                                      // spoofed identity
            receiver: V,
        },
        seed: seed_X,                                 // attacker's seed
        salt: salt_X,                                 // consistent with
                                                      // the commit above
    },
}
```

V's `submit` keys both inserts on wire-sender = A:
- `zero_received_2to4[A] = spoof_phase2` (replacing A's honest legit
  phase-2 message because A never emitted that legit message — only
  the spoof).
- `zero_received_3to4[A] = spoof_phase3` (similarly).

V's `zero_received_2to4` state:
```
{
    1: legit_phase2_from_party_1,
    2: legit_phase2_from_party_2,
    ...
    A: spoof_phase2_with_inner_sender_T,         // <— A's ONLY entry
                                                 // is the spoof
    ...
}
```

When `try_advance_phase23_to_complete` runs the count gates at
`dkls_ceremony.rs:517-520`:

```rust
if self.zero_received_2to4.len() < needed_p2p { return Ok(false); }
if self.zero_received_3to4.len() < needed_p2p { return Ok(false); }
```

`needed_p2p = share_count - 1`, so the legit phase-2/3 messages from
each non-V party (including the slot at wire-sender = A) satisfy the
count. The gate passes.

Phase4's triple-loop runs. For `target_party = T`:
- Iteration (msg2 = legit_phase2_from_T, msg3 = legit_phase3_from_T):
  - `*target_party (T) == their_index (T) && msg3.parties.sender (T)
    == their_index (T)` → enters body.
  - `verify_seed` passes (T's legit commit/seed/salt are consistent).
  - Pushes `SeedPair(V, T, kept_seed_V, legit_seed_T)`.
- Iteration (msg2 = spoof_with_inner_T, msg3 = legit_phase3_from_T):
  - Both their_index = T → enters body.
  - `verify_seed(legit_seed_T, spoof_commit, legit_salt_T)`. Both
    `legit_seed_T` and `legit_salt_T` are NOT what the attacker
    committed to (the attacker committed to `seed_X, salt_X`). So
    verification FAILS.
  - Wait — but `verify_seed(seed, commit, salt) = hash(seed, salt) ==
    commit`. The attacker's spoof_commit = `hash(seed_X, salt_X)`.
    `hash(legit_seed_T, legit_salt_T) != hash(seed_X, salt_X)` (with
    overwhelming probability). So this iteration ABORTS with "Party
    T cheated".

So Primitive C as described above runs into Primitive B's abort path
at this combination. The attack needs an additional twist: the
attacker must ALSO suppress (or delay) one of the legit Phase2 or
Phase3 messages from T to V so that the verify failure doesn't happen.

**Better Primitive C variant — committee-member overwrites own slot**:

The attacker A is still a committee member, but uses the BTreeMap
KEY=WIRE_SENDER overwrite property to ERASE A's own honest contribution
to V's accumulator. A emits a spoofed Phase2ZeroShareSend with **inner
`parties.sender = T (T != A)` and consistent (commit_A', seed_A', salt_A')**:

```rust
DklsRoundMessage::Phase2ZeroShareSend {
    sender: A,                                        // wire — A
    receiver: V,                                      // wire — V
    zero_init: { parties: { sender: T, receiver: V },
                 commitment: commit_A' },
}
```

Plus matching:
```rust
DklsRoundMessage::Phase3ZeroShareSend {
    sender: A,                                        // wire — A
    receiver: V,                                      // wire — V
    zero_init: { parties: { sender: T, receiver: V },
                 seed: seed_A', salt: salt_A' },
}
```

with `hash(seed_A', salt_A') == commit_A'`.

If the attacker emits ONLY these (and NOT A's own legit phase-2/3
to V), V's `zero_received_2to4[A]` and `zero_received_3to4[A]`
contain the spoof — NOT A's honest contribution. The BTreeMap entries
for wire-sender < A contain T's legit entry (with `parties.sender = T`),
and wire-sender = A contains the spoof (also with `parties.sender = T`).

Phase4's triple-loop for `target_party = A`:
- Iterates all (msg2, msg3) combinations. NONE of the msg2/msg3
  entries has `parties.sender == A` — both T's legit and A's spoof
  have `parties.sender = T`. So at `*target_party (A) != their_index
  (T)`, the `continue` at L749-752 fires for every iteration.
- The seeds vec ends with NO entry for `index_counterparty = A`.

For `target_party = T`:
- Legit msg2 from T paired with legit msg3 from T → verify passes,
  pushes `SeedPair(V, T, kept, legit_seed_T)`.
- Spoof msg2 (inner T) paired with spoof msg3 (inner T) → verify
  `(seed_A', commit_A', salt_A')` PASSES (attacker chose
  consistent values).
  Pushes `SeedPair(V, T, kept, seed_A')`. **DUPLICATE entry for
  counterparty T, with different seed.**
- Cross-combination: legit msg2 from T + spoof msg3 (inner T) →
  verify `(seed_A', legit_commit_T, salt_A')` FAILS → **ABORT
  blaming T**.

So this path also runs into the abort. To make the silent-corruption
work, the attacker must arrange the BTreeMap values iteration order
such that the cross-combination is iterated AFTER the two consistent
pairs. But the triple-loop is fully cartesian — it iterates ALL
combinations and aborts on the FIRST failing one. So unless the
attacker can suppress one of T's legit messages (Phase2 or Phase3),
the failing cross-combination always fires.

**Strongest Primitive C — combined with F023 (network-layer drop)**:

F023 documents that ordinary peer-message drops are reachable
(gossipsub mesh dropouts, peer-scoring evictions). If T's
Phase3ZeroShareSend to V is dropped (independent of attacker action,
just garden-variety mesh churn — F023 demonstrates this is reachable),
then V's `zero_received_3to4` is missing T's entry entirely. The
count gate at L520 would normally block phase23-to-complete advance
because `zero_received_3to4.len() < needed_p2p`. But if A separately
emits a spoof Phase3ZeroShareSend addressed to V (wire-sender = A,
inner `parties.sender = T`), the count is restored, the gate
passes. In phase4 triple-loop for `target_party = T`: msg3 entries
include only the spoof (with seed_A', salt_A') — T's legit one
is missing. msg2 entries include T's legit commit_T. Pair: msg2 =
legit_commit_T, msg3 = spoof_seed_A',salt_A' → verify FAILS →
abort blaming T.

Or, if A spoofs BOTH phase2 AND phase3 with consistent values AND
T's legit messages are dropped:
- msg2 entries: legit-from-others, **spoof_commit_A' under wire-sender = A
  with inner_sender = T**. No legit_from_T.
- msg3 entries: legit-from-others, **spoof_seed_A',salt_A' under wire-sender
  = A with inner_sender = T**. No legit_from_T.
- Triple-loop for target_party = T: only iteration is (spoof_msg2, spoof_msg3)
  with their_index = T → verify(seed_A', commit_A', salt_A') = TRUE →
  pushes `SeedPair(V, T, kept_V, seed_A')`.
- V's local SeedPair for (V, T): uses `seed_A'` instead of the true
  `seed_T`. Critically, V's kept_seed_V is V's own honest seed for T,
  but T's actual `seed_T` (which T XORed with V's kept) is NOT
  `seed_A'`. So the per-pair fragment at V is
  `hash(kept_V XOR seed_A', session_id)` whereas the corresponding
  fragment at T (using T's own kept_seed_T_for_V and V's true seed
  contribution to T, which IS the legit one) is
  `hash(kept_T_for_V XOR legit_seed_V_to_T, session_id)`. These do NOT
  cancel.

So V's zeta has a stray uncancelled term, T's zeta has a different
stray uncancelled term, and Σ_party zeta_party ≠ 0.

Subsequent signing: `key_share = poly_point * l + zeta` is biased.
The aggregated signature does not correspond to `pk`. The final
`verify_ecdsa_signature` check at `signing.rs:674-680` returns
FALSE. V (and every other corrupted party) aborts with `"Invalid
ECDSA signature at the end of the protocol!"` — blame is on
`self.party_index` (the local victim), NOT on the attacker A.

The supervisor sees a sign abort with the LOCAL party blamed. There
is no way to trace this back to A's phase-2/3 spoof — by the time
the abort fires, the DKG has long completed and the ZeroShare state
is opaque.

**Severity for Primitive C**: high — silent corruption of the long-lived
`Party.zero_share` state, surfacing as sign-time blame-less abort.
Combined with F040 (no retry within epoch), threshold signing is
permanently halted for the epoch.

## Round-by-round walk (Primitive A — the cleanest one-packet DoS)

### Setup

- Hypersnap is running a 3-of-3 DKLS DKG for epoch `E`. Active validators:
  V1, V2, V3.
- Phase 1 (fragment exchange) completes honestly.
- Phase 2 starts. Each of V1, V2, V3 produces and broadcasts their
  legitimate `Phase2ProofCommitment`, `Phase2BipBroadcast`, and three
  `Phase2ZeroShareSend` messages (one per counterparty).

### Adversary publishes

A is either (a) any node that subscribes to the DKG gossip topic
(pre-F018-fix) or (b) any authenticated validator who is in scope
to publish, including a malicious member of the V1, V2, V3 set
itself. Adversary publishes ONE additional sealed-to-V1 Phase2ZeroShareSend:

```rust
DklsRoundMessage::Phase2ZeroShareSend {
    sender: 4,                                        // wire — A
                                                      // (any byte)
    receiver: 1,                                      // wire — V1
    zero_init: TransmitInitZeroSharePhase2to4 {
        parties: PartiesMessage {
            sender: 2,                                // INNER —
                                                      // arbitrary
            receiver: 99,                             // INNER — NOT
                                                      // V1's
                                                      // party_index
        },
        commitment: [0u8; 32],                        // any junk
    },
}
```

The wire codec opens this for V1: outer sender=4, outer receiver=1,
matches the top-level enum-variant fields (outer-decoded == enum-encoded
for both fields by the wire codec's self-check at
`dkls_wire_codec.rs:236-241`). V1's `submit` checks top-level
`receiver == 1 == V1.party_index` — passes. Inserts
`zero_received_2to4[4] = spoof_zero_init`.

### V1 advances to phase 4

V1 receives the rest of the legitimate messages from V2 and V3:
- `proof_commitments`: {V1, V2, V3} populated.
- `bip_broadcasts_2to4`, `bip_broadcasts_3to4`: same.
- `zero_received_2to4`: {V2, V3, **A**=spoof} — len = 3 ≥ needed_p2p=2.
- `zero_received_3to4`: {V2, V3} — len = 2.
- `mul_received_3to4`: {V2, V3} — len = 2.

All count gates pass. V1's `try_advance_phase23_to_complete` calls
`phase4`. Inside phase4, before any zero-share work runs, `step5`
(DKG public-key reconstruction) runs first — this succeeds because
A didn't spoof a `Phase2ProofCommitment`. The check `pk == identity()
|| pk == generator()` passes. The polynomial-point triviality check
passes.

Then the zero-share triple-loop at `dkg.rs:731-773` starts. The outer
loop iterates `(target_party, message_kept)` over V1's `zero_kept`
(entries for V2 and V3). For each, the middle loop iterates
`message_received_2 ∈ zero_received_phase2 = [legit_V2, legit_V3,
spoof_A]` (BTreeMap-flatten in wire-sender key order, so 2, 3, 4).

When the inner loop reaches `message_received_2 = spoof_A` (inner
`parties.receiver = 99, parties.sender = 2`):
- `my_index = message_received_2.parties.receiver = 99`.
- `99 != data.party_index (=1)` → return `Err(Abort::new(1, "Received
  a message not meant for me!"))`.

V1 aborts. The supervisor receives the abort. Per F040, the supervisor
cannot retry within the epoch. DKG halts. Hypersnap epoch E has no
group key. Chain halts on any epoch-E threshold-signed payload.

V2 and V3 may complete phase4 independently if A's spoof was targeted
only at V1 (sealed-to-V1). They register the DKG as successful with
their own `pk` (consistent between them because step5 was unaffected).
But V1 has no group key and cannot sign. Threshold signing requires
all signers' shares — V1 can't participate. With 3-of-3, no signing
is possible.

For deployments where `threshold < share_count`, the attacker repeats
the targeted spoof for each share holder until enough share holders
abort, denying the threshold. Always feasible because the attack
needs only one packet per victim.

## Round-by-round walk (Primitive C — silent corruption with sign-time fallout)

Setup: A is a committee member (party_index = 4). 4-of-4 deployment
(threshold = 4, share_count = 4), validators V1–V4. A is V4.

### Phase 1: honest

All four parties exchange polynomial fragments honestly. No
attacker action.

### Phase 2/3 (A's spoof + drop)

A executes their honest phase2 work locally (producing
their own ProofCommitment, BipBroadcast, three Phase2ZeroShareSends
to V1, V2, V3). A emits the ProofCommitment and BipBroadcast — these
land in V1, V2, V3's accumulators (so step5 succeeds and DKG group
public key matches).

But for the Phase2ZeroShareSends, A emits — addressed to V1 (only;
similar attacks on other recipients are independent) — ONLY a single
spoofed frame:

```rust
Phase2ZeroShareSend {
    sender: 4 (wire),
    receiver: 1 (wire),
    zero_init: {
        parties: { sender: 2 (INNER — claims to be V2),
                   receiver: 1 (INNER — ok) },
        commitment: hash(seed_A_prime || salt_A_prime),
                                                      // consistent
                                                      // commit, but
                                                      // seed not V2's
    },
}
```

A does NOT emit any phase-2 ZeroShareSend with `parties.sender = 4`
(A's own legit one). Or, if A emits it, A also publishes a
gossip-layer NACK / waits until V2's legit Phase2ZeroShareSend has
flooded to V1 first AND THEN publishes the spoof so the BTreeMap
overwrite-by-key-wire-sender (= 4) keeps only the spoof.

Either way, V1's `zero_received_2to4[wire_sender = 4]` ends up
holding the spoof (inner `parties.sender = 2`).

A also emits a matching spoofed Phase3ZeroShareSend:

```rust
Phase3ZeroShareSend {
    sender: 4 (wire), receiver: 1 (wire),
    zero_init: {
        parties: { sender: 2, receiver: 1 },
        seed: seed_A_prime, salt: salt_A_prime,
    },
}
```

V1's `zero_received_3to4[4]` holds this spoof.

A relies on the legitimate V2 → V1 Phase2ZeroShareSend AND V2 → V1
Phase3ZeroShareSend being **dropped** (F023's network-layer drop
primitive). Alternatively, A is the gateway node for V1 and selectively
drops V2's outbound. Either way, V1's `zero_received_2to4` and
`zero_received_3to4` are missing V2's legit entries (wire-sender = 2);
they ARE present for V3 (wire-sender = 3) and the spoof (wire-sender
= 4 with inner = 2).

count gates: `zero_received_2to4 = {3: V3_legit, 4: spoof_inner_2}`,
len = 2. `needed_p2p = share_count - 1 = 3`. Gate FAILS (`2 < 3`),
phase23-to-complete doesn't advance.

Hmm — the count gate requires `share_count - 1 = 3` entries. With
V2's legit dropped, count is 2. Attack can't progress on count.

A's adaptive move: emit a SECOND spoofed Phase2ZeroShareSend, this
one from a DIFFERENT wire-sender, to fill the count. But the wire
codec encrypts to V1's transport pubkey using the wire-sender field
as part of the AAD (`dkls_wire_codec.rs:140`); the wire-sender must
match the actual signer. A can use only their own party-index for
the wire-sender (post-F018 fix).

Pre-F018-fix, A can spoof any wire-sender — including V2. Post-F018-fix
(if applied), A can't.

For the post-F018 case, A would need to compromise V2's transport key
or convince a different validator V_B to collude. Both are out-of-scope
for a single-attacker model.

**Therefore Primitive C, in the strict single-attacker model, is
gated on F018's wire-sender-spoofing primitive remaining unfixed,
OR on a multi-attacker (V2 + V4) collusion model.**

Re-tightening Primitive C to assume F018 IS fixed: A can only emit
under wire-sender = 4. V1's `zero_received_2to4[4] = spoof_with_inner_2`
ALONE doesn't reach count = 3 (it's only ONE entry, replacing A's
own legit). The phase23-to-complete gate blocks.

So Primitive C strictly requires F018-style wire-sender spoofing OR
multi-party collusion. Severity downgrade for Primitive C alone: from
high to medium pending F018 fix.

**Primitives A and B remain HIGH severity** (do not require wire-sender
spoofing): they exploit only the INNER `parties.{sender, receiver}`
field, which is independent of the wire-sender and remains
attacker-controlled even after F018 fix.

## Primitives B and A composability

Note: Primitives A and B can be combined with F107/F108. An attacker
exploiting F107 (step5 self-claimed index) gets DKG-time blame-less
abort or pk-divergence. Adding F114 Primitive A on top: another
one-packet DoS lever at a different code site. The supervisor's
retry logic (if any) is overwhelmed by multiple independent abort
sources, each blaming a different innocent party or no party.

## Why existing checks don't close the gap

1. **Wire codec inner/outer check** (`dkls_wire_codec.rs:236-241`):
   verifies `message.sender() == outer_sender && message.receiver() ==
   Some(outer_receiver)`. But `message.sender() / .receiver()` return
   the TOP-LEVEL variant fields (`dkls_ceremony.rs:127-150`), not the
   inner `zero_init.parties.{sender, receiver}`. This check is a
   tautology — it confirms wire-bytes equal enum-variant-bytes (which
   they always do, having been serialised together). It does NOT
   reach into the bincoded `zero_init.parties`.

2. **`submit`'s top-level `receiver != self.party_index` filter**
   (`dkls_ceremony.rs:362, 378`): drops messages whose TOP-LEVEL
   `receiver` isn't V. Does nothing for inner `parties.receiver`.

3. **`phase4`'s `my_index != data.party_index` check**
   (`dkg.rs:741`): catches the inner-receiver-mismatch, BUT it does
   so by **aborting with self-blame** rather than by **filtering the
   message out**. This converts the spoof into an active DoS instead
   of harmlessly ignoring it. Recommended fix: replace `return
   Err(Abort)` with `continue` (treat as not-for-us, skip).

4. **`phase4`'s `target_party != their_index || msg3.parties.sender
   != their_index { continue; }`** (`dkg.rs:749-752`): partial defense
   — filters out messages whose inner `parties.sender` doesn't match
   the current target_party. But the attacker simply sets inner
   `parties.sender = T` (the target party they want to frame),
   defeating this filter.

5. **`verify_seed` (`zero_shares.rs:54-58`)**: catches malformed
   (commitment, seed, salt) triples — but doesn't bind to any party
   index. A consistent (commit', seed', salt') triple from an
   attacker passes verification, only to push a SeedPair that doesn't
   correspond to any real cross-party agreement.

6. **F018 fix is orthogonal**. F018 binds wire `sender` to libp2p
   peer-id. After F018 fix, the attacker still publishes from their
   OWN authentic peer-id (wire `sender = A`) carrying inner
   `parties.sender = T (T != A)`. The cross-binding between wire
   sender and inner sender is NOT in scope of F018's fix. Primitives
   A and B remain fully exploitable post-F018-fix; Primitive C is
   downgraded as noted above.

7. **F023 fix** (DKLS round messages dropped and cross-routed) is
   also orthogonal — F023 addresses network-layer drop/cross-route;
   it doesn't validate inner protocol fields for zero-share messages.
   F023's drop primitive AMPLIFIES F114 Primitive C (silently
   removing legit messages, letting spoofs replace them), but
   neither finding's fix subsumes the other.

8. **F107 / F108 / F110 fix recommendations**: F107's recommended
   fix #3 ("In `dkls_ceremony.rs::submit`, enforce
   `proof_commitment.index == sender`") is the closest analog. The
   parallel fix for F114 is to enforce `zero_init.parties.sender ==
   sender && zero_init.parties.receiver == self.party_index` in the
   `Phase2ZeroShareSend` and `Phase3ZeroShareSend` submit branches.
   Neither F107's nor F108's specific fix touches the zero-share
   path — F114 needs its own fix.

## Recommended fix

In descending order of robustness — layer at least one, ideally all:

1. **In `dkls_ceremony.rs::submit`, enforce inner-vs-wire equality
   on both `parties.sender` and `parties.receiver` for
   `Phase2ZeroShareSend` and `Phase3ZeroShareSend`**:

   ```rust
   DklsRoundMessage::Phase2ZeroShareSend {
       sender, receiver, zero_init,
   } => {
       if receiver != self.party_index { return Ok(()); }
       if zero_init.parties.sender != sender {
           return Err(DklsError::InnerSenderMismatch {
               wire_sender: sender,
               inner_sender: zero_init.parties.sender,
           });
       }
       if zero_init.parties.receiver != self.party_index {
           return Err(DklsError::InnerReceiverMismatch {
               wire_receiver: self.party_index,
               inner_receiver: zero_init.parties.receiver,
           });
       }
       self.zero_received_2to4.insert(sender, zero_init);
   }
   ```

   Same for `Phase3ZeroShareSend`.

2. **Also enforce `wire sender ∈ 1..=share_count` and `wire sender !=
   self.party_index`**:

   ```rust
   if sender == 0 || sender > self.parameters.share_count {
       return Err(DklsError::UnknownPartyIndex(
           sender, self.parameters.share_count));
   }
   if sender == self.party_index {
       return Err(DklsError::InnerSenderMismatch {
           wire_sender: sender, inner_sender: sender });
   }
   ```

3. **In `dkg.rs::phase4`'s zero-share loop, replace the abort at
   line 741 with `continue`** (treat invalid inner_receiver as
   not-for-us-skip rather than fatal-abort-with-self-blame):

   ```rust
   for (target_party, message_kept) in zero_kept {
       for message_received_2 in zero_received_phase2 {
           for message_received_3 in zero_received_phase3 {
               let my_index = message_received_2.parties.receiver;
               let their_index = message_received_2.parties.sender;

               if my_index != data.party_index {
                   continue;            // CHANGED from Err(Abort)
               }
               if *target_party != their_index
                   || message_received_3.parties.sender != their_index
               {
                   continue;
               }
               // ... rest unchanged
           }
       }
   }
   ```

   This eliminates Primitive A (one-packet DoS) outright. Note: if
   fix #1 is applied at the upper layer, the spoof never reaches
   phase4 anyway, but the defense-in-depth here costs nothing.

4. **In `dkg.rs::phase4`'s zero-share loop, after the loop completes,
   validate that the seeds vec has exactly `share_count - 1` entries
   with EXACTLY ONE entry per counterparty in `1..=share_count` (excl.
   self)**:

   ```rust
   let mut seen: BTreeSet<u8> = BTreeSet::new();
   for pair in &seeds {
       if pair.index_counterparty == 0
           || pair.index_counterparty > data.parameters.share_count
           || pair.index_counterparty == data.party_index
       {
           return Err(Abort::new(data.party_index, &format!(
               "Invalid zero-share counterparty index {}",
               pair.index_counterparty)));
       }
       if !seen.insert(pair.index_counterparty) {
           return Err(Abort::new(data.party_index, &format!(
               "Duplicate zero-share entry for counterparty {}",
               pair.index_counterparty)));
       }
   }
   if seen.len() != (data.parameters.share_count - 1) as usize {
       let missing: Vec<u8> = (1..=data.parameters.share_count)
           .filter(|i| *i != data.party_index && !seen.contains(i))
           .collect();
       return Err(Abort::new(data.party_index, &format!(
           "Missing zero-share entries for counterparties {:?}", missing)));
   }
   ```

   This catches Primitive C's "silent missing entry" path — phase4
   aborts at DKG time with a specific party blame ("missing
   zero-share for counterparty A"), rather than silently completing
   DKG and surfacing a blame-less sign-time abort later.

5. **In `zero_shares::ZeroShare::compute`, abort if a counterparty
   listed in `counterparties` is not represented in `self.seeds`**:

   ```rust
   let mut covered: BTreeSet<u8> = BTreeSet::new();
   for seed_pair in &self.seeds {
       if counterparties.contains(&seed_pair.index_counterparty) {
           if !covered.insert(seed_pair.index_counterparty) {
               panic!("duplicate seed pair for counterparty {}",
                      seed_pair.index_counterparty);
               // OR: return early Result; current API returns Scalar
               // and can't propagate error — refactor to return Result.
           }
       }
   }
   for c in counterparties {
       if !covered.contains(c) {
           panic!("missing seed pair for counterparty {}", c);
       }
   }
   // proceed with sum
   ```

   This is the deepest defense — catches even DKG-time defects that
   slip through fixes #3 and #4 (e.g., a future caller bug that
   doesn't validate seeds vec well-formedness).

6. **Refactor `ZeroShare::compute` to return `Result<C::Scalar, Abort>`**
   so it can fail-close instead of panicking on inconsistent state.
   Current `#[must_use]` signature returns `C::Scalar` and offers no
   error path.

## Tests to add

1. **Phase 4 zero-share inner-receiver-mismatch is filtered (not
   aborted)**. Modify `test_dkg_initialization` (or add a new test):
   construct V1's `zero_received_phase2` with one entry having
   `parties.receiver = 99` (and `parties.sender = 2`); other entries
   are honest. Today, phase4 aborts at L741 with "Received a message
   not meant for me!" After fix #3, the offending entry is skipped
   and DKG completes successfully.

2. **Upper-layer inner-sender-mismatch rejected at submit**. In
   `dkls_ceremony.rs::tests`, submit a `Phase2ZeroShareSend { sender:
   2 (wire), receiver: 1, zero_init: { parties: { sender: 3, receiver:
   1 }, commitment: ... } }` to a coordinator with `party_index = 1`.
   Today this is accepted silently. After fix #1, this MUST return
   `Err(DklsError::InnerSenderMismatch { wire_sender: 2, inner_sender:
   3 })`.

3. **Misattribution-blame attack reproduction (Primitive B)**.
   Construct a 3-of-3 DKG. Attacker = V3 emits a spoofed
   Phase2ZeroShareSend addressed to V1 with `parties.sender = 2`
   (claiming to be V2) and arbitrary junk commitment. V2 also sends
   legit. Today, V1's phase4 aborts with "...Party 2 cheated when
   sending the seed!" — wrongly blaming V2. After fix #1, V1's
   submit rejects the spoof at the gate, never reaching phase4.

4. **Missing-zero-share-entry sign-time abort (Primitive C)**.
   Manually corrupt a `Party.zero_share.seeds` after DKG completion
   by removing the entry for one counterparty. Run a signing protocol.
   Today, signing aborts at `verify_ecdsa_signature` with "Invalid
   ECDSA signature at the end of the protocol!" — blame on
   self.party_index, no party blame for the missing slot. After fix
   #4 + #5, DKG aborts BEFORE completion with "Missing zero-share
   entries for counterparties [4]", giving the supervisor actionable
   blame.

5. **Duplicate-counterparty zero-share entry detection**. Manually
   inject a duplicate `SeedPair` (same `index_counterparty`, different
   `seed`) into the seeds vec returned by phase4. After fix #4, DKG
   aborts at the post-loop validation with "Duplicate zero-share
   entry for counterparty {N}".

## Composition with other findings

- **F018** (wire-sender unbound to libp2p peer-id): F114 is the
  cryptographic-layer companion. After F018 is fully fixed, F114's
  Primitives A and B remain exploitable (inner `parties.{sender,
  receiver}` is independent). Primitive C's full silent-corruption
  variant requires F018 wire-sender spoofing OR multi-party collusion;
  in single-attacker post-F018-fix model, Primitive C reduces to a
  DKG abort (still bad, but at DKG time with blame, rather than at
  sign time with no blame).
- **F023** (DKLS round messages dropped and cross-routed): amplifies
  F114 Primitive C — dropping legit messages lets spoofs fill the
  count gates with attacker-controlled inner-index payloads.
- **F040** (supervisor no-retry after ceremony abort): converts all
  F114 primitives into permanent epoch halts.
- **F107** (step5 self-claimed-index verification skip): same root
  cause family (inner-index trust), different code site (step5
  proofs_commitments). F114 is the zero-share variant. Both findings
  must be fixed; F107's fix does NOT touch the zero-share path.
- **F108** (signing trusts inner sender for routing and blame): same
  root cause family (inner-index trust), different code site (signing
  `transmit.parties.sender`). F108's recommended fix #1 (enforce
  `transmit.parties.sender == wire sender` at submit) is the direct
  analog of F114's recommended fix #1, but F108's fix doesn't touch
  the zero-share path.
- **F110** (refresh-side step5 variant of F107): identical relationship
  — same root cause family, different caller. F114 is the
  zero-share-init variant; F110 is the refresh variant; F107 is the
  DKG step5 variant; F108 is the signing variant. Same fix family:
  bind inner index to wire sender at the upper layer; layer additional
  validations at the protocol layer.
- **F045** (recovery_id 2/3 bricks signing): separate sign-phase
  issue; not directly related.

## Reachability

DKG is the active ceremony pipeline. Zero-share initialization is run
inside `phase4` at every DKG round (production code path):

- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:537-552`
  calls `phase4` from `try_advance_phase23_to_complete`.
- `code/hypersnap/src/hyper/actor.rs` drives the ceremony via
  `HyperActorEvent::StartDkls` and `HyperActorEvent::InboundDkls`
  (per F018, F023 analyses).
- `code/hypersnap/src/hyper/dkls_supervisor.rs` schedules DKG per
  epoch.

So F114 is reachable from any peer that can publish into the DKG
gossip topic. Pre-F018-fix, that's any subscriber. Post-F018-fix
that's any authenticated validator. Either way, the inner-index
field is attacker-controlled.

## Specific affected callsite map (for the supervisor's blame parser, if any)

| Variant | Abort site | Blamed party | Attacker action |
|---------|-----------|-------------|-----------------|
| Primitive A | `dkg.rs:741-746` | `data.party_index` (self) | One Phase2ZeroShareSend with inner `parties.receiver != V` |
| Primitive B | `dkg.rs:760-762` | `their_index` (innocent T) | One Phase2ZeroShareSend with inner `parties.sender = T` and mismatched commitment |
| Primitive C (DKG-time abort variant, post-F018-fix) | Count gate at `dkls_ceremony.rs:517` | none — never advances | One Phase2ZeroShareSend overwriting attacker's own slot |
| Primitive C (sign-time abort variant, pre-F018-fix or multi-attacker) | `signing.rs:677-680` | `self.party_index` (self) | Phase2/3 ZeroShareSend overwriting attacker's own slot via wire-sender spoof + drop of legit |

## In-tree tests

The in-tree DKG end-to-end test at `crates/dkls23/src/protocols/dkg.rs`'s
`test_dkg_initialization` (around line 1306) produces all
`TransmitInitZeroSharePhase2to4` / `TransmitInitZeroSharePhase3to4`
messages honestly with `parties.sender = i, parties.receiver = j`
matching the actual sender/receiver. The inner-index spoofing path
is invisible to the existing test suite — adding the regression
tests above is feasible without significant scaffolding (use the
in-tree helpers to construct phases and substitute one message's
inner fields).

The ceremony-layer test in `dkls_ceremony.rs::tests` is similar:
all messages are honestly produced. F114's primitives are not
exercised.
