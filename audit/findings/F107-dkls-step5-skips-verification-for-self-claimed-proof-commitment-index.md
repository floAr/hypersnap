---
id: F107
task: H107
attack_class: dkls23-protocol-correctness
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# DKLS `step5` skips proof+commitment verification for any `ProofCommitment` whose inner `index` field matches the verifier's own `party_index` — an attacker who can plant an inbound message carrying `proof_commitment.index = victim_party_index` (independent of the wire `sender` byte) gets an attacker-controlled "public-key fragment" inserted into the victim's `committed_points[victim_party_index]` slot without any DLog proof check, silently corrupting DKG output (group-address divergence across the committee → ceremony completes locally with diverging pks → all subsequent threshold signatures unverifiable) and, when `threshold == share_count`, allowing arbitrary-pk injection without any Lagrange cross-window detection

## Scope files

- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:321-333` — the verification-skip site in `step5`
- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:341-376` — the Lagrange consistency-check loop; degenerates to a single non-cross-checked window when `threshold == share_count`
- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:686-708` — `phase4` call into `step5` (no pre-filter on `proofs_commitments[i].index` vs. expected party slot)
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_ceremony.rs:345-350, 528-538` — upper-layer accumulator: keys the BTreeMap by wire `sender` byte but never cross-checks the inner `proof_commitment.index` against `sender`, and finally feeds `proof_commitments.values().cloned().collect()` into `phase4` — the BTreeMap key is discarded; `step5` dispatches purely on `proof_commitment.index`

## Summary

`step5` (the DKG public-key reconstruction in
`crates/dkls23/src/protocols/dkg.rs`) decides whether to run
`DLogProof::decommit_verify` on each incoming `ProofCommitment` based on
a comparison of the **inner `index` field** to the verifier's own
`party_index`:

```rust
for party_j in proofs_commitments {
    if party_j.index != party_index {                          // L322
        let verification =
            DLogProof::<C>::decommit_verify(...);
        if !verification {
            return Err(Abort::new(...));
        }
    }
    committed_points.insert(party_j.index, party_j.proof.point); // L332
}
```

The intent: "I don't need to re-verify the proof I just generated for
myself." The implementation defect: any inbound `ProofCommitment`
whose `index` byte equals `party_index` is **trusted unverified**.

The inner `index: u8` field on `ProofCommitment` (`dkg.rs:84-88`) is a
free-form byte chosen by the producer. Nothing in `dkg.rs::step5` ties
it to the wire layer's `sender` byte. Nothing in the upper-layer
`dkls_ceremony.rs::submit` (which keys the BTreeMap on wire `sender`)
cross-checks `proof_commitment.index == sender`. And the upper layer
finally flattens via `.values().cloned().collect()` before calling
`phase4 → step5` — the BTreeMap key is **discarded**; `step5` sees a
slice of `ProofCommitment`s and dispatches on each one's `index` byte.

Combined consequence: a peer who can publish ONE inbound
`Phase2ProofCommitment` message into the victim's ingress queue —
spoofing the wire sender OR being a legitimate-but-malicious validator
who chooses an `index` value different from their own — can overwrite
the victim's `proof_commitments[victim_party_index]` slot with a
`ProofCommitment { index: victim_party_index, proof: bogus,
commitment: bogus }`. The victim's `step5` accepts the bogus
`proof.point` without verification, and:

- **If `threshold < share_count` (typical 2-of-3, 3-of-5 deployments)**:
  the multi-window Lagrange cross-check at `dkg.rs:341-376` detects
  divergence between the `pk` reconstructed from window 1 and window 2,
  and aborts with the generic message `"Verification for public key
  reconstruction failed in iteration {i}"`. The abort assigns blame to
  **no party** (no party index in the error). The DKG epoch halts.
  Downstream supervisor cannot identify and exclude the culprit on
  retry (F040-style chain halt amplification).
- **If `threshold == share_count` (full-share / "M-of-M" deployments)**:
  the consistency-check loop iterates `i ∈ 1..=(share_count - threshold + 1) = 1..=1`,
  so only one window is computed. There is no cross-window agreement
  check; `pk = current_pk` from window 1 is the only assignment and is
  returned directly. The attacker-chosen `proof.point` propagates
  unmodified through Lagrange combination into the victim's notion of
  the group public key.

In the second case, since each honest receiver independently runs the
same `step5` against its own per-receiver-targetable inbound queue (the
codec at `crates/hypersnap-crypto/src/dkls_ceremony.rs` is sealed-to-recipient
per F018; the attacker tailors per-recipient spoofs), the attacker can
drive **different** honest receivers to compute **different** group
pks. Each receiver registers its own pk as the epoch's group address
(`finalize_into_runtime`), and signatures verified under one receiver's
group address fail under another's. Threshold signing — which requires
all signers to share the same group address — silently stops working
for the epoch.

This is **NOT a duplicate of F018**. F018 documents that the wire-layer
`sender` byte is unauthenticated. This finding documents that even
assuming F018 is fully fixed — i.e., the wire `sender` byte is bound
to the libp2p peer-id and the validator's registered key — the **inner
`proof_commitment.index` field is an independent, attacker-chosen
byte** that the upper-layer `submit` never cross-checks against
`sender`. A *legitimately authenticated* validator can submit a
`Phase2ProofCommitment { sender: own_party_index, proof_commitment:
ProofCommitment { index: VICTIM, proof: bogus, commitment: bogus } }`,
and the wire layer happily forwards it (sender matches their
authenticated identity), the coordinator inserts under
`proof_commitments[own_party_index]` (so the attacker's slot is
clobbered with their own crafted payload — fine from their
perspective), the BTreeMap key is discarded on flatten, and `step5`
on the receiving end sees a `ProofCommitment` with
`index == VICTIM` and skips verification.

## Round-by-round walk

### Phase 2 — honest production (dkg.rs:428-497, ceremony self-record at dkls_ceremony.rs:435-446)

1. Each party `P` runs `step3(P, session_id, poly_fragments)` →
   `(poly_point, ProofCommitment { index: P, proof, commitment })`.
2. `proof` is a Fischlin-randomized DLog proof of knowledge of the
   polynomial point underlying `proof.point = poly_point · G`.
3. `commitment = hash(serialize(proof), session_id)` — a hash of the
   whole DLog proof (`proofs.rs:399-437`).
4. Honest `P` broadcasts `Phase2ProofCommitment { sender: P,
   proof_commitment }` and **self-records** the same payload into
   their local `proof_commitments[P]` (line 435-436 of
   `dkls_ceremony.rs`).

### Phase 2 — adversary spoof injection (dkls_ceremony.rs:345-350)

Adversary `A` publishes (one of many equivalent forms):

```rust
DklsRoundMessage::Phase2ProofCommitment {
    sender: A,                                            // matches A's
                                                          // wire identity
                                                          // (so F018 fix
                                                          // doesn't help)
    proof_commitment: ProofCommitment {
        index: V,                                         // V = victim party
        proof: arbitrary_DLogProof_for_any_point_Q,
        commitment: hash(serialize(arbitrary_proof),
                         session_id),                     // valid
                                                          // self-commitment
                                                          // — passes the
                                                          // hash check that
                                                          // IS done
    },
}
```

The arbitrary proof+commitment must self-verify (`decommit_verify =
true`) because *attacker controls both*; the attacker picks any scalar
`q`, computes `Q = q·G`, runs `DLogProof::prove_commit(q,
session_id)` to get a consistent `(proof, commitment)` pair, and
plugs in `index: V`.

But — and here is the gap — **the attacker doesn't even have to bother
producing a valid DLog proof.** Because `step5` skips verification when
`party_j.index == party_index`, the attacker can put a completely
malformed `proof` (e.g., `proof.rand_commitments = vec![]`,
`proof.proofs = vec![]`) and a meaningless `commitment` — the
verifier never looks. The only field that matters is
`proof.point = Q` (any AffinePoint of the attacker's choosing).

### Phase 2 receive at honest victim V (dkls_ceremony.rs:345-350)

V's `submit` does:
```rust
self.proof_commitments.insert(sender = A, proof_commitment);  // L349
```

V's `proof_commitments` map state: `{V: honest_PC_V, A: spoofed_PC_for_V, ...}`.

### Phase 23-to-complete advance (dkls_ceremony.rs:505-540)

V's `try_advance_phase23_to_complete` collects:
```rust
let proof_commitments: Vec<ProofCommitment<Secp256k1>> =
    self.proof_commitments.values().cloned().collect();    // L528 — KEY DISCARDED
```

The slice now contains:
- `ProofCommitment { index: V, proof: honest_proof_V, commitment: honest_commitment_V }` (V's own)
- `ProofCommitment { index: V, proof: bogus, commitment: bogus }` (A's spoof carrying `index: V`)
- ... legitimate other-party PCs ...

### `phase4 → step5` (dkg.rs:308-378)

V runs `step5(parameters, V, session_id, &proof_commitments)`. The
loop at `dkg.rs:321-333`:

- Iter for V's own honest PC: `party_j.index == V == party_index` →
  **skip verification** → `committed_points.insert(V, honest_proof.point)`.
- Iter for A's spoofed PC: `party_j.index == V == party_index` →
  **skip verification** → `committed_points.insert(V, BOGUS_POINT)` —
  overwrites V's honest entry (`BTreeMap::insert` last-writer-wins).
- Iter for other-party PCs: `party_j.index != V` → verify normally
  (these are unchanged).

Result: `committed_points[V] = BOGUS_POINT`.

### Lagrange reconstruction (dkg.rs:341-376)

```rust
for i in 1..=(parameters.share_count - parameters.threshold + 1) {
    // Compute current_pk = Σ_{j=i..i+t} l_j · committed_points[j]
    ...
    if i == 1 {
        pk = current_pk;
    } else if pk != current_pk {
        return Err(Abort::new(party_index,
            "Verification for public key reconstruction failed in iteration {i}"));
    }
}
```

- **Case `t < n`**: multiple windows. Some windows include slot V's
  bogus point, others don't. Reconstructed `pk` differs between
  windows → `Err(Abort)` returned. Note the abort message **carries
  no party blame** (no `party_j.index`), so the supervisor's
  retry-and-exclude policy cannot identify A as the culprit on
  retry. Repeated attempts indefinitely halt the DKG ceremony for the
  epoch.
- **Case `t == n`**: `share_count - threshold + 1 == 1`, the loop runs
  once. `pk = current_pk` is assigned and returned. The bogus point at
  slot V propagates through Lagrange combination into the returned
  `pk`. No cross-check.

### Per-recipient tailoring (F018 + this finding compose)

Because the wire codec is sealed-to-recipient (`dkls_wire_codec.rs:118-150`
per F018's analysis), the attacker can craft different bogus PCs for
different recipients. Each honest recipient ends up with a different
`committed_points[V]`, hence (with `t == n`) a different `pk`. Each
recipient computes and registers a different group address for the
epoch (via `finalize_into_runtime`), and threshold signing — which
requires consensus on the group address for verification — silently
breaks: a signature produced by one share-set verifies against one
group address; the same payload signed by a different share-set
yields a different signature/address. The protocol's threshold-signed
artifacts (`RewardIssuance`, `TrustSnapshotUpdate`,
`LockMerkleRootUpdate`, `InboundBurn` ack, `DaEpochSeed`) become
non-finalizable for the affected epoch.

## Concrete attack scenario

**Adversary capability**: any peer that can publish to the gossip
topic `hyper/dkg/v1`. After F018 fix, this is restricted to
authenticated validators; before F018 fix (current state), any
subscriber. Either way, this attack is exploitable today and would
remain exploitable after a targeted F018 fix.

**Setup**: hypersnap is running a 3-of-3 DKLS DKG for epoch `E`.
Validators V1, V2, V3 are active; V1 = honest, V2 = honest, V3 = honest.
A new attacker validator V_A (party index 4 — joins the active set at
epoch E because of a planned committee rotation, OR a malicious node
operator who fully validates and signs round messages with their own
key) is in scope. Parameters: `threshold = 3, share_count = 3`.

(For deployments where `threshold < share_count`, the same attack
yields a guaranteed DoS rather than silent corruption — see "Severity"
below.)

**Attack steps**:

1. V_A waits for phase 1 (fragment exchange) to complete honestly.
   The attack does not corrupt fragments — it corrupts the *commitment*
   to the resulting `poly_point`.
2. V_A captures the phase-2 `Phase2ProofCommitment` broadcasts from
   V1, V2, V3 and learns the session_id (already public).
3. V_A computes its OWN honest phase-2 broadcast and emits it normally
   so it doesn't get phase-2-aborted by the other parties' validators.
4. V_A then crafts THREE additional malicious broadcasts, one per
   victim, each tailored differently:
   - To V1: `Phase2ProofCommitment { sender: V_A, proof_commitment:
     ProofCommitment { index: V1, proof: anything, commitment:
     anything, point: random_Q1 } }`
   - To V2: same with `index: V2, point: random_Q2`
   - To V3: same with `index: V3, point: random_Q3`
5. Each victim Vi receives all four phase-2 broadcasts (V1's, V2's,
   V3's, V_A's), plus V_A's tailored spoof targeting Vi.
   Note: this requires the attacker to also be able to drop or
   re-route the legitimate broadcasts so Vi's `proof_commitments[Vi]`
   ends with V_A's bogus payload after Vi's own self-record. With
   gossipsub's flood-fill propagation order, this is straightforward:
   V_A's spoof, if published last from V_A's vantage, arrives at Vi
   AFTER Vi's own self-record (line 435-436) — last-writer-wins on
   the BTreeMap.
6. Each Vi's `try_advance_phase23_to_complete` flattens the BTreeMap
   to a slice and runs `phase4 → step5`. With `t == n == 3`, the
   Lagrange loop runs once. V_A's bogus `random_Qi` propagates into
   each Vi's reconstructed `pk_i`. **`pk_1 != pk_2 != pk_3`**.
7. Each Vi registers `pk_i` as the epoch's group address via
   `finalize_into_runtime`. The on-protocol "DKG completed for epoch
   E" event fires three times with three different addresses. The
   group-address registry (a per-validator local store, see
   `src/hyper/runtime.rs::dkls_group_address_for_epoch`) holds
   different values on different validators.
8. Subsequent threshold-ECDSA signing of epoch-E artifacts
   (rewards, snapshots, merkle-root updates, …) silently produces
   signatures that no validator can mutually verify against the same
   group address. Operationally: the chain halts on every
   threshold-signed message because each verifier sees a sig under a
   different group address than its own registered one.

**Damage**:
- All epoch-E threshold-signed artifacts become unfinalizable. Per
  the F040-class halt: there is no per-epoch retry, so the chain
  halts until manual operator intervention or until the next
  scheduled DKG ceremony rotates the parameters.
- Misattribution: the abort, when `t < n` and the cross-window check
  fires, blames *no party* (the error message at `dkg.rs:371-374`
  cites only the iteration index, not a party). The supervisor's
  blame-and-exclude policy (if any) cannot exclude V_A on retry,
  inviting indefinite recursion.

**Alternative scenario — `t < n` DoS** (more realistic given current
production hints at `t=2, n=3` setups): the cross-window check
catches the divergence on V_A's spoof in the first window beyond
window 1, abort fires, blame is generic. With every retry across the
epoch the same attack repeats because V_A is never identified, so
the DKG ceremony for this epoch never completes. Combined with
F040's "no retry after abort," this is a permanent epoch halt and a
real chain stall.

## Why existing checks don't close the gap

1. **The DLog proof itself**: `DLogProof::decommit_verify` IS robust
   — it verifies the proof against the commitment and the
   `session_id` (`proofs.rs:441-480`). The defense fails because the
   call is *skipped* under `party_j.index == party_index`.

2. **Public-key cross-window consistency** (dkg.rs:341-376): catches
   *some* divergence when `t < n`, but with three caveats: (a) blames
   no specific party, (b) doesn't catch the `t == n` case at all,
   (c) the message attribution is to "iteration {i}" not to the
   adversarial party slot. So the check produces noise rather than
   actionable blame for the supervisor.

3. **`dkls_ceremony.rs::submit` (line 345-350)**: keys the BTreeMap on
   wire `sender` but does *not* check `proof_commitment.index ==
   sender`. The inner index is an independent attacker-chosen byte.

4. **`dkls_ceremony.rs::try_advance_phase23_to_complete` (line 528)**:
   uses `.values().cloned().collect()` — **the BTreeMap key is
   discarded**. Even if a future fix added a "key == inner_index"
   check at `submit` time, the flatten step removes the key, and
   step5 still dispatches on inner `index` only.

5. **The phase4 wrapper** (dkg.rs:686-708): does no pre-filtering of
   `proofs_commitments` by index. It passes the slice straight into
   `step5`.

6. **F018 fix would NOT close this**: F018 binds the wire `sender`
   byte to the libp2p peer-id. The inner `proof_commitment.index`
   field is an independent payload byte that F018's fix doesn't
   touch. A legitimately authenticated validator (wire `sender`
   binds to its peer-id correctly) can still set `index: victim`
   inside the payload. This finding's primitive is orthogonal to
   F018.

7. **F023 (DKLS round messages dropped and cross-routed) and F026
   (DKLS share-selection leak)**: neither addresses the inner-index
   field semantics.

## Recommended fix

In **descending order of robustness** (any one of these closes the
attack; layered defense is best):

1. **Make `step5` verify EVERY proof, including the own party's
   one** (`dkg.rs:321-333`). The optimization of skipping
   self-verification saves negligible CPU (one DLog verify of ~64 R
   iterations of Schnorr) and breaks soundness when the slice can
   contain attacker-substituted entries. Replace:

   ```rust
   for party_j in proofs_commitments {
       if party_j.index != party_index {
           // verify
       }
       committed_points.insert(party_j.index, party_j.proof.point);
   }
   ```

   with:

   ```rust
   for party_j in proofs_commitments {
       let verification =
           DLogProof::<C>::decommit_verify(&party_j.proof,
                                           &party_j.commitment,
                                           session_id);
       if !verification {
           return Err(Abort::new(
               party_index,
               &format!("Proof from Party {} failed!", party_j.index),
           ));
       }
       committed_points.insert(party_j.index, party_j.proof.point);
   }
   ```

   With this change, the attacker's bogus PC fails
   `decommit_verify` (because they don't know the DLog of the bogus
   point under the *correct* session_id binding) and the ceremony
   aborts with the correct party blame.

2. **Pre-filter `proofs_commitments` to exactly the expected indices
   1..=share_count, rejecting duplicates and missing indices**, in
   either `step5` or the `phase4` wrapper:

   ```rust
   let mut seen = std::collections::BTreeSet::new();
   for pc in proofs_commitments {
       if pc.index == 0 || pc.index > parameters.share_count {
           return Err(Abort::new(party_index,
               &format!("Invalid index {} in proof_commitments", pc.index)));
       }
       if !seen.insert(pc.index) {
           return Err(Abort::new(party_index,
               &format!("Duplicate index {} in proof_commitments", pc.index)));
       }
   }
   if seen.len() != parameters.share_count as usize {
       return Err(Abort::new(party_index,
           "Missing proof_commitments for some parties"));
   }
   ```

3. **In the upper layer (`dkls_ceremony.rs::submit`), enforce
   `proof_commitment.index == sender` before inserting**, and reject
   the message otherwise:

   ```rust
   DklsRoundMessage::Phase2ProofCommitment {
       sender, proof_commitment,
   } => {
       if proof_commitment.index != sender {
           return Err(DklsError::InnerIndexMismatch {
               wire_sender: sender,
               inner_index: proof_commitment.index,
           });
       }
       self.proof_commitments.insert(sender, proof_commitment);
   }
   ```

4. **Augment the Lagrange consistency abort to name the divergent
   slot**: in `dkg.rs:341-376`, when `pk != current_pk` is detected,
   compute the slot whose `committed_points[k]` differs from the
   honest reconstruction (by recomputing the per-slot contribution
   for each `k` in the window and identifying which one yields the
   mismatch). Surface that slot in the `Abort::new(...)` description.
   This gives the supervisor blame attribution even in the `t < n`
   DoS case.

5. **Bind `committed_points[i] = i · G + something` consistency**:
   the cleanest cryptographic fix is to require, after
   `committed_points` is built, that the polynomial committed by
   each pair of `(committed_points[j])`'s Lagrange interpolant
   agrees in **all** `share_count` slots against the published
   `pk` — not just `share_count - threshold + 1` windows. This
   provides cross-check even when `t == n`. Concretely: after
   computing `pk` from window 1, recompute `committed_points[k]'`
   from `pk` and `committed_points[i]` for `i != k` for each `k`
   not in window 1, and assert equality. (This requires
   `share_count > threshold` to have anything to check, which is
   the root issue with `t == n` — without redundancy there's
   nothing to check, period; recommending operators avoid `t == n`
   deployments for this reason is a parallel fix.)

## Tests to add

1. **Self-spoofed `ProofCommitment` is rejected.** Modify
   `test1_dkg_t2_n2_fixed_polynomials` (or add a new test): after
   honest production, append to `proofs_commitments` a synthesized
   `ProofCommitment { index: 1, proof: junk_DLogProof, commitment:
   junk_HashOutput }`. Then call
   `step5::<C>(&parameters, 1, &session_id, &proofs_commitments)`.
   Today this returns `Ok(some_attacker_steered_pk)` (or aborts on
   cross-window mismatch with no party blame). After the recommended
   fix #1, this MUST return `Err(Abort)` with `description` containing
   `"Proof from Party 1 failed!"`.

2. **Inner-index mismatch detected at the upper-layer codec.** In
   `dkls_ceremony.rs`'s test module, submit a
   `Phase2ProofCommitment { sender: 2, proof_commitment: { index: 1,
   ... } }` to a coordinator with `party_index: 1`. Today this is
   accepted silently. After recommended fix #3, this MUST return
   `Err(DklsError::InnerIndexMismatch { wire_sender: 2,
   inner_index: 1 })`.

3. **`t == n` step5 doesn't accept arbitrary `pk`.** With `threshold
   == share_count == 2`, manually substitute `committed_points[1]`
   with `random_point`. After recommended fix #5, the
   `step5` consistency check must abort. Today (without fix #5), the
   single-window loop returns the attacker-steered `pk`.

4. **Multi-attacker tailored spoofs cause `pk` divergence detection.**
   Simulate three honest receivers, each receiving a different
   spoofed `ProofCommitment` for the same victim slot. Assert that
   after the recommended fixes, each receiver returns the same
   `Abort` with the same `description` (so the supervisor sees a
   consistent blame story).

5. **Misattribution-blame test** for fix #4: when the cross-window
   check fires due to inner-index spoofing, the abort description
   must contain a specific party index (not just "iteration {i}").

## Related

- **F018** (`findings/drafts/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md`):
  documents wire `sender` byte spoofing. This finding is the
  cryptographic-layer companion: the inner `proof_commitment.index`
  byte is a SEPARATE attacker-chosen field that an F018 fix does not
  bind. Both findings should be fixed; neither alone is sufficient.
- **F023** (`findings/drafts/F023-dkls-round-messages-dropped-and-cross-routed.md`):
  documents network-layer drop/cross-route. Doesn't cover the inner
  index field semantics.
- **F040** (`findings/drafts/F040-dkls-supervisor-no-retry-after-ceremony-abort.md`):
  amplifies this finding's `t < n` DoS variant — a single spoofed
  inbound aborts the ceremony, and the supervisor cannot retry within
  the epoch.
- **F045** (`findings/drafts/F045-dkls-recovery-id-2-or-3-bricks-signing-no-retry.md`):
  separate DKLS path; not directly related.
- **dkg.rs:1306-1486** (`test_dkg_initialization`): the in-tree DKG
  e2e test does NOT exercise the inner-index spoofing path because
  all `ProofCommitment` entries are produced honestly with
  `index == party_index`. A regression test for this finding is
  feasible without significant new scaffolding.
