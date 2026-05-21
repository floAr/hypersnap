---
id: F119
task: H119
attack_class: kzg-srs-or-verkle-encoding
severity: high
status: draft
---

# `DLogProof::verify` panics on adversarially-shaped `proof.proofs[i].challenge` whose `Vec<u8>` length differs from `T/8 == 4`, giving any peer who can deliver a `DLogProof` to a verifier a 1-message remote-panic primitive against the DKG `step5` decommit path (`dkg.rs::step5` → `DLogProof::decommit_verify` → `InteractiveDLogProof::verify` → `U256::from_be_slice` assert!) and the OT base `run_phase2_step1` path (`ot/base.rs:286`) — a malicious party in the DKLS ceremony, or any peer that can spoof an inbound DKG / OT base round message under F018 conditions, can crash the verifying validator's thread by replacing every `challenge` field with a non-4-byte payload and grinding ~256 attempts for an 8-bit Fischlin hash collision on iteration `i=0`

## Scope files

- `code/hypersnap/crates/dkls23/src/utilities/proofs.rs:104-107` — `prove_step2` builds `extended = vec![0u8; 28]; extended.extend_from_slice(challenge); U256::from_be_slice(&extended)`. The `from_be_slice` (`crypto-bigint-0.4.9::uint::encoding::from_be_slice`) hard-asserts `bytes.len() == Limb::BYTE_SIZE * LIMBS` (= 32 for `U256`). Any `challenge.len() != 4` ⇒ assertion panic, both in debug and release.
- `code/hypersnap/crates/dkls23/src/utilities/proofs.rs:128-145` — `InteractiveDLogProof::verify` reproduces the same padding+`from_be_slice` flow against `self.challenge`. This is the network-facing reachable variant.
- `code/hypersnap/crates/dkls23/src/utilities/proofs.rs:319-392` — `DLogProof::verify`: the Fischlin transform verifier. Computes 1-byte Fiat-Shamir hash slices (`L/4 = 4/4 = 1`) per iteration and short-circuits with `return false` only when `first_hash != second_hash`. When the 8-bit hashes coincide, control flow falls through to `proof.proofs[i].verify(&proof.point, ...)` which panics on the malformed challenge.
- `code/hypersnap/crates/dkls23/src/utilities/proofs.rs:439-481` — `DLogProof::decommit_verify`: calls `Self::verify(proof, session_id)`. The commitment `hash(serialize(proof), session_id) == commitment` check passes trivially because the attacker chooses BOTH the proof bytes AND the commitment bytes.
- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:321-333` — `step5` invokes `DLogProof::decommit_verify(&party_j.proof, &party_j.commitment, session_id)` on every inbound `ProofCommitment` (except the verifier's own; F107). The malformed `proof.proofs[i].challenge.len() != 4` panic fires from a single inbound `Phase2ProofCommitment` message.
- `code/hypersnap/crates/dkls23/src/utilities/ot/base.rs:275-297` — `OTReceiver::run_phase2_step1` invokes `DLogProof::verify(dlog_proof, ...)` on `dlog_proof` supplied by the OT sender (other party). Same panic vector applies at the OT base layer (DKLS init / refresh / signing init).
- `code/hypersnap/crates/dkls23/src/utilities/multiplication.rs:142-146` — `MulSender::init_phase2` plumbs `dlog_proof` from the wire into `OTESender::init_phase2` → `OTReceiver::run_phase2_step1`. Same panic vector applies during signing-init / multiplication init.
- `code/hypersnap/crates/dkls23/src/utilities/hashes.rs:64-70` — `scalar_to_bytes` returns 32 bytes; not the panic source.
- `C:/Users/floar/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/crypto-bigint-0.4.9/src/uint/encoding.rs:14-18` — confirms the panic-on-wrong-length behavior of `UInt::from_be_slice`:
  ```rust
  pub const fn from_be_slice(bytes: &[u8]) -> Self {
      assert!(
          bytes.len() == Limb::BYTE_SIZE * LIMBS,
          "bytes are not the expected size"
      );
      ...
  }
  ```
  Note: this is `assert!`, **not** `debug_assert!` — fires in release builds.

## Summary

`DLogProof` is the Fischlin-randomized Schnorr non-interactive proof of knowledge used to prove possession of `proof.point`'s discrete log under the protocol's curve generator. It is serialized as a struct containing 64 random commitments, 64 `InteractiveDLogProof` instances, and one `point`. Each `InteractiveDLogProof` carries a `challenge: Vec<u8>` and a `challenge_response: C::Scalar`.

Both `InteractiveDLogProof::prove_step2` (used internally by `DLogProof::prove`) and `InteractiveDLogProof::verify` (called from `DLogProof::verify`) reconstruct the challenge scalar by left-padding `challenge` to 32 bytes with zeros and then calling `U256::from_be_slice(&extended)`:

```rust
let mut extended = vec![0u8; (32 - T / 8) as usize];   // = 28 bytes of zero
extended.extend_from_slice(&self.challenge);            // attacker controls .len() over network
let challenge_scalar = C::Scalar::reduce(U256::from_be_slice(&extended));  // panic if extended.len() != 32
```

`T == 32`, so `T/8 == 4`. The honest prover always produces `challenge` of exactly 4 bytes (from `rng.gen::<[u8; (T/8) as usize]>()` at `proofs.rs:221, 259`). But the `InteractiveDLogProof::challenge` field is typed `Vec<u8>` (line 63) with `Deserialize` derived — the deserializer accepts **any** length on the wire. There is **no length validation anywhere on the receive path**:

- `DLogProof::verify` (line 319-392): only checks `rand_commitments.len() == R` and `proofs.len() == R` (line 325). No per-element `proofs[i].challenge.len() == T/8` check.
- `DLogProof::decommit_verify` (line 441-481): only checks `commitment == hash(serialize(proof), session_id)`. Since the attacker chooses both proof and commitment, this is trivially satisfiable for any challenge length.
- The downstream callers (`dkg.rs::step5`, `ot/base.rs::run_phase2_step1`, `multiplication.rs::init_phase2`) pass the proof straight through to `DLogProof::verify` without any per-field validation.

When `DLogProof::verify` runs on an attacker-supplied proof, the loop at `proofs.rs:351-388` computes 1-byte Fiat-Shamir hash slices (`L/4 == 1`) for each of 32 paired indices `i ∈ 0..R/2 = 0..32`. If `first_hash != second_hash`, the verifier short-circuits with `return false` — safe. If `first_hash == second_hash`, control flow falls through to `proof.proofs[i].verify(&proof.point, &proof.rand_commitments[i])` (line 379), which inside calls `U256::from_be_slice(&extended)`. If `proof.proofs[i].challenge.len() != 4`, the assert panics.

### The attacker's grind cost is trivial — 8 bits of hash collision per iteration

The Fischlin parameter pair is `R = 64, L = 4`, so `L/4 == 1` byte and the 1-byte hash-collision target is 8 bits = 256 expected trials. The attacker only needs ONE of the 32 paired iterations to collide; under default execution order the loop processes `i = 0` first, panicking on the first collision-and-malformed-challenge that fires. Grinding the rand_commitments and challenge_responses to make hashes match at `i=0` is ~256 trials of SHA-256, milliseconds on a laptop.

(Even cheaper: the attacker can grind ALL 32 iteration-pairs to collide. Cost scales linearly. ~8 KB of trial work to find a fully-passing-FS-but-malformed-challenge proof.)

### Construction of the panic payload

The attacker, given any session_id `S` (which is broadcast on the public DKLS wire in the clear before phase 2 begins):

1. Sets `proof.point = ANY_AFFINE_POINT` (the identity, the generator, anything — irrelevant to the panic).
2. Generates 64 distinct random points for `proof.rand_commitments`.
3. For each `i ∈ 0..64`, sets `proof.proofs[i].challenge = [0u8; 5]` (or any non-4-byte sequence, including `vec![]`).
4. Grinds `proof.proofs[i].challenge_response` (and/or `proof.rand_commitments[*]`) until `hash(first_msg, S)[0] == hash(second_msg, S)[0]` for at least `i = 0`. ~256 SHA-256 trials.
5. Computes `commitment = hash(serialize(proof), S)`. (Trivially passes the `decommit_verify` outer check.)
6. Wraps in `ProofCommitment { index: ANY, proof, commitment }` and broadcasts on `hyper/dkg/v1`.

Honest receiver V's `step5` runs `DLogProof::decommit_verify(&proof, &commitment, S)`:
- Commitment check passes.
- Inside `Self::verify`:
  - Length checks pass (64 of each).
  - HashSet dedup of rand_commitments passes (distinct).
  - Iteration `i = 0`: 1-byte hash slices match → fall through to `proof.proofs[0].verify(...)`.
  - `verify` builds `extended = 28-byte zeros + 5-byte challenge = 33 bytes`. `U256::from_be_slice(&extended)` **panics**: `"bytes are not the expected size"`.
  - Thread (and process, in default panic mode) aborts.

### No `catch_unwind` on the verify call site

I checked all `crates/` for `catch_unwind` / `panic::catch`: **no results**. The DKLS verify chain runs in the consensus / DKG worker thread without panic isolation. A panic in `step5` propagates up and either:
- Aborts the worker thread, leaving the DKG ceremony deadlocked (no progress message ever produced for the victim).
- Aborts the process if the project's panic strategy is `abort` (Cargo.toml not pinned, default `unwind`, but the panic still escapes to the top-level `tokio::spawn` or thread join handle, which most production stacks log-and-restart at best).

Either way, the consequence is a remote-triggerable validator outage for one DKG message.

### Reach — three independent panic paths

1. **DKG `step5`** (`dkg.rs:321-333`). Verifier processes inbound `ProofCommitment` from peers. Triggers on any `Phase2ProofCommitment` whose inner `proof_commitment.proof.proofs[i].challenge.len() != 4`. Fires once per honest DKG ceremony per victim per attacker-spoofed message.

2. **OT base `run_phase2_step1`** (`ot/base.rs:275-297`). Receiver verifies a `DLogProof` from the OT sender. Reachable in DKLS init (`multiplication.rs:144-146`), refresh, and signing init (the OT base layer is invoked at every multiplication setup). One malformed `DLogProof` from a peer panics the receiving thread.

3. **DKLS signing init via multiplication**. The init phase of signing wraps `OTReceiver::run_phase2_step1` (transitively via `OTESender::init_phase2`). A malicious co-signer can panic the other signer at signing-init time, never completing the signing ceremony.

### Pre-existing related findings — F107 family does not subsume this

- **F107** describes `step5` skipping `decommit_verify` for `party_j.index == party_index`. That avoids the panic for self-spoofed messages but DOES NOT avoid it for any **other** index: when `party_j.index != party_index`, `decommit_verify` IS called and the panic fires. So this finding is exploitable both before and after F107 is fixed; F107's fix (verify-every-proof) actually **opens** the self-spoofed path to this panic too.
- **F018** (wire-sender unbound). Without F018, ANY peer subscribed to `hyper/dkg/v1` can publish a malformed `DLogProof`. With F018 fixed, only authenticated validators can — but a malicious validator suffices.
- **F108 / F110 / F114** — inner-index trust pattern, orthogonal.
- **F045** — DKLS recovery-id signing path, unrelated.

This is a **cryptographic-primitive-layer** finding inside `proofs.rs` (the only file in the scope of H119). It is not a duplicate of any inner-index finding; the root cause is the missing length validation of `InteractiveDLogProof::challenge` against the protocol-required `T/8` bytes.

## Round-by-round walk

### Honest behavior (proofs.rs:217-300)

`DLogProof::prove` runs:

```rust
let first_challenge = rng::get_rng().gen::<[u8; (T / 8) as usize]>();  // exactly 4 bytes, hardcoded by the type
```

Honest `challenge` is always exactly 4 bytes. The honest verifier always sees `extended = 28 + 4 = 32 bytes` and no panic occurs. Tests pass.

### Adversary path

The attacker constructs `proof.proofs[i] = InteractiveDLogProof { challenge: vec![0u8; 5], challenge_response: <grinded scalar> }` (or any non-4-byte challenge). Serializes the `DLogProof`. The wire codec accepts the message; serde does not enforce `Vec<u8>` length on `challenge`.

On the victim side, the panic fires in `U256::from_be_slice` as described above.

### Reachability under the threat model

The DKLS DKG flow (per `dkls_ceremony.rs::submit`) accepts inbound `Phase2ProofCommitment` messages from any peer the wire layer has not rejected. Under F018-uninitiated state, any subscriber can publish. After F018, any authenticated validator can. The DKG message body is `Vec<u8>`-typed at the wire layer; no inner shape validation precedes the `DLogProof::decommit_verify` call in `step5`.

The OT base flow (`ot/base.rs::run_phase2_step1`) accepts inbound `DLogProof` from the paired OT sender (the other DKLS party). Same observation: no inner shape validation.

## Concrete attack scenario

**Adversary capability**: any authenticated validator (or any subscriber to `hyper/dkg/v1` pre-F018) in a hypersnap deployment running DKLS DKG.

**Setup**: deployment with `share_count = n` validators V_1, ..., V_n. Attacker is V_A (authenticated as one of them, or unauthenticated pre-F018).

**Attack steps**:

1. V_A waits for phase 1 (fragment exchange) to complete normally.
2. V_A constructs the panic payload as described:
   - `DLogProof { point: any_point, rand_commitments: <64 distinct random points>, proofs: <64 entries each with .challenge = [0u8; 5] and .challenge_response = <grinded> > }`.
   - Grind `challenge_response[0]` and `rand_commitments` (~256 trials) until `hash(first_msg_for_i=0, session_id)[0] == hash(second_msg_for_i=0, session_id)[0]`.
   - `commitment = hash(serialize(proof), session_id)`.
3. V_A broadcasts `Phase2ProofCommitment { sender: V_A (or any index for inner-trust spoof), proof_commitment: ProofCommitment { index: V_target, proof, commitment } }`.
4. Victim V_j (j ≠ V_A) ingresses the message. `dkls_ceremony.rs::submit` inserts into `proof_commitments[V_A]` keyed by wire sender. Eventually `try_advance_phase23_to_complete` flattens and calls `step5(parameters, j, session_id, &flat_slice)`.
5. `step5` iterates: for V_A's PC, `index == V_target ≠ V_j (party_index)` → calls `DLogProof::decommit_verify`.
6. Commitment check passes. `Self::verify` runs. Iteration `i = 0`: hashes match. `proof.proofs[0].verify` is called. `U256::from_be_slice(&extended)` panics: `"bytes are not the expected size"`.
7. V_j's DKG worker thread panics.

**Damage**:
- Per-validator DoS at DKG time. Repeat the attack each epoch → permanent DKG halt.
- Combined with F040 (no supervisor retry after abort) → chain stalls indefinitely.
- Combined with the OT base panic path → also blocks signing-init for ongoing signing operations after DKG.
- The panic gives no protocol-level "blame" — the supervisor cannot identify and exclude V_A; it just sees a crashed worker / a missing phase-3 advance.

**Variation — signing-init panic**: at signing time, V_A is one of the `t` signers. The OT base flow runs `run_phase2_step1` on V_A's `DLogProof`. V_A submits the panic payload. The other signer's thread panics. Signing never completes. With high enough `t` and no per-attempt retry, the threshold-signed message (`RewardIssuance`, etc.) never finalizes.

## Why existing checks don't close the gap

1. **`from_be_slice`'s assert is hard, not soft**: even in release builds. Cannot be "compiled away."

2. **The Fischlin transform binding is at the byte level**: the FS hash includes `&self.challenge` as bytes (`proofs.rs:357, 367`). The wire-bytes-to-scalar conversion (right-pad-and-reduce) is done after the hash check. So the bytes can be malformed-length while still hashing into the expected 1-byte slot.

3. **The 1-byte hash hardness (L=4) is too low to provide grinding resistance against panic-search**: 8 bits is 256 trials per iteration. The Fischlin parameter `L` is sized for soundness of the proof of knowledge, not for grinding resistance of arbitrary downstream byte-shape checks. Increasing `L` would slow honest provers and not actually fix the root cause.

4. **Serde does not validate `Vec<u8>` length**: the `InteractiveDLogProof::challenge: Vec<u8>` field accepts any length on deserialization. There is no `#[serde(deserialize_with = "...")]` to enforce 4 bytes.

5. **`decommit_verify` commitment check is self-consistent**: the attacker controls both proof and commitment; passes trivially regardless of internal field shape.

6. **F107's "verify-every-proof" fix opens the self-spoof panic path**: if F107 is fixed by removing the `party_j.index != party_index` skip, then self-spoofed panic payloads ALSO trigger this finding's panic. The fixes for F107 and F119 are independent and complementary.

7. **No `catch_unwind` anywhere in the codebase**: confirmed `grep -rn 'catch_unwind' code/hypersnap/crates` returns no matches. Panics propagate.

## Recommended fix

In descending order of robustness:

### Fix 1 (minimal): add length guards in `InteractiveDLogProof::verify` and `DLogProof::verify`

At the top of `InteractiveDLogProof::verify` (`proofs.rs:127`):

```rust
pub fn verify(&self, point: &C::AffinePoint, point_rand_commitment: &C::AffinePoint) -> bool {
    // Validate challenge length to prevent panic in U256::from_be_slice.
    if self.challenge.len() != (T / 8) as usize {
        return false;
    }
    // ... rest unchanged
}
```

And at the top of `DLogProof::verify` (`proofs.rs:319`), after the existing length checks:

```rust
if proof.rand_commitments.len() != (R as usize) || proof.proofs.len() != (R as usize) {
    return false;
}
// NEW:
if proof.proofs.iter().any(|p| p.challenge.len() != (T / 8) as usize) {
    return false;
}
```

This converts the panic into a clean `verify == false` and an `Abort` at the caller's level, preserving normal protocol error handling.

### Fix 2 (defense-in-depth): switch `InteractiveDLogProof::challenge` to a fixed-size array

```rust
pub struct InteractiveDLogProof<C: CurveArithmetic> {
    pub challenge: [u8; (T / 8) as usize],  // = [u8; 4]
    pub challenge_response: C::Scalar,
}
```

This forces serde to enforce the length at deserialization time. Requires propagating the array type through `prove_step2` (`challenge: &[u8]` → `challenge: &[u8; 4]`) and `verify` reads.

### Fix 3 (defense-in-depth): wrap the FS hash check in a length-guarded path

Inside `DLogProof::verify`'s loop, **before** computing the hashes (`proofs.rs:353`), assert:

```rust
if proof.proofs[i as usize].challenge.len() != (T / 8) as usize
    || proof.proofs[(i + R / 2) as usize].challenge.len() != (T / 8) as usize {
    return false;
}
```

### Fix 4 (defense-in-depth): wrap consensus-thread proof-verification call sites in `catch_unwind` as a process-level safety net

In `dkg.rs::step5` and `ot/base.rs::run_phase2_step1`, wrap the verify call:

```rust
let result = std::panic::catch_unwind(|| {
    DLogProof::<C>::decommit_verify(&party_j.proof, &party_j.commitment, session_id)
});
let verification = match result {
    Ok(b) => b,
    Err(_) => return Err(Abort::new(party_index, &format!("Panic verifying proof from Party {}", party_j.index))),
};
```

This is **belt-and-suspenders** — Fix 1 is the cleanest at the cryptographic layer; Fix 4 is the operational safety net.

### Out of scope but observed

`DLogProof::verify` does NOT include `proof.point` (the statement) in the Fischlin Fiat-Shamir transcript (`proofs.rs:353-360, 363-370`). Soundness is preserved because the per-iteration Schnorr `verify` (line 379) algebraically binds `proof.point` via `R = response*G + challenge*point`. This is intentional per the Fischlin construction; not a defect. Mentioned here only because the H119 brief asks about Fiat-Shamir input completeness.

The challenge is also not included via the canonical-encoding-prefix convention some texts require for transcripts; an attacker cannot exploit this either because byte equality is hashed verbatim.

## Tests to add

1. **`test_dlog_proof_malformed_challenge_length_does_not_panic`**:
   ```rust
   #[test]
   fn test_dlog_proof_malformed_challenge_length_does_not_panic() {
       let scalar = Scalar::random(rng::get_rng());
       let session_id = rng::get_rng().gen::<[u8; 32]>();
       let mut proof = DLogProof::<C>::prove(&scalar, &session_id);
       // Mutate first challenge to wrong length.
       proof.proofs[0].challenge = vec![0u8; 5];
       // Should return false, NOT panic.
       assert!(!DLogProof::<C>::verify(&proof, &session_id));
   }
   ```
   Today this **panics**. After Fix 1, returns false cleanly.

2. **`test_dlog_proof_empty_challenge_does_not_panic`**: same as above with `proof.proofs[0].challenge = vec![]`.

3. **`test_dlog_proof_grinded_panic_payload`**: build a fully crafted attacker payload (64 distinct rand_commitments, 5-byte challenges, response grinded for ≤1024 trials such that `first_hash == second_hash` at `i = 0`). Confirm `DLogProof::verify(&proof, &session_id)` returns false (Fix 1). On unfixed code, this test panics.

4. **`test_dlog_proof_oversized_challenge_does_not_panic`**: `proof.proofs[0].challenge = vec![0u8; 1024]`.

5. **`test_dkls_step5_robust_to_malformed_challenge`** (in `dkg.rs`): submit a `ProofCommitment` with a malformed-challenge inner proof to `step5`. Confirm it returns `Err(Abort)` rather than panicking.

## Related

- **F107** (`F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md`):
  describes the verification-skip in `step5`. Complementary to this finding: F107's "verify everything" fix opens the self-spoof variant of the F119 panic.
- **F018** (`F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md`):
  wire-sender unbinding. Without F018, the panic payload can come from ANY subscriber; with F018, only from authenticated validators. The panic vector exists in both cases.
- **F040** (`F040-dkls-supervisor-no-retry-after-ceremony-abort.md`):
  amplifies the DoS by preventing per-epoch retry after a worker panic.
- **F045** (`F045-dkls-recovery-id-2-or-3-bricks-signing-no-retry.md`):
  unrelated DKLS-specific recovery-id issue.
