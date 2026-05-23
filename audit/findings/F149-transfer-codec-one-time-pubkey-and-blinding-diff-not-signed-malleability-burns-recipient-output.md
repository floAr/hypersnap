---
id: F149
task: H149
attack_class: serialization-boundary
severity: medium
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-23T09:11:34Z
---

# F149 — `HyperTransferTx` wire codec carries two security-critical fields (`output.one_time_pubkey`, `blinding_diff_scalar`) that the per-input Schnorr signature does NOT cover; any gossip-relay attacker can rewrite a recipient's `one_time_pubkey` to a key they control and permanently lock the recipient out of their stealth output

- **Task:** H149
- **Attack class:** `serialization-boundary` (signing-coverage subclass — the wire codec emits fields outside the `signing_payload` set that the network blindly applies to durable per-recipient state)
- **Severity (provisional):** Medium. Targeted output-burn / griefing on confidential transfers. The attacker cannot extract value from the captured note (they don't know `(value, blinding)`; the encrypted note payload is sent out-of-band to the original recipient's view-pubkey and the strong-validation gate requires Pedersen balance closure for any onward spend), so this is **not direct theft**. But the attacker can permanently and selectively **destroy** specific stealth outputs to a recipient by winning a gossip race, with no slashing or detection: the on-chain `note_store.record_note(commitment, ATTACKER_PK)` write is what every future `validate_against_store` consults to recover the spend-verification key, and the legitimate recipient has no path to produce a Schnorr signature under a key they don't know. Block proposers + well-connected relayers are naturally positioned to win the race against the originator's first hop.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/transfer_codec.rs:107-130` — `tx_to_proto_full`: populates `one_time_pubkey` per output and `blinding_diff_scalar`; these are the two security-critical fields the wire ships outside the signing payload.
- `code/hypersnap/src/hyper/transfer_codec.rs:150-168` — `extract_output_pubkeys`: decodes the per-output pubkey and only validates length=56 + canonical-Decaf448 form; no cross-check against any signed structure.
- `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:233-256` — `TransferTx::signing_payload`: the canonical bytes each input's Schnorr signature covers. Covers `(input commitments, input nullifiers, output commitments, output range proofs (length-prefixed), fee_atoms)`. Does **not** cover `one_time_pubkey`, `blinding_diff_scalar`, or `chain_id`.
- `code/hypersnap/src/hyper/runtime.rs:4178-4205` — `import_block` post-apply: blindly calls `note_store.record_note(commitment, output_pubkeys[i])` with the wire-supplied pubkey for every output in a block.
- `code/hypersnap/src/hyper/builder.rs:143-174` — `apply_message_with_notes`: same blind record at proposer-side apply.
- `code/hypersnap/proto/definitions/hyper.proto:186-208` — `HyperTransferOutput.one_time_pubkey` field is documented "REQUIRED — empty rejects" but is **not** part of any signed payload.
- `code/hypersnap/src/hyper/router.rs:312-317` — `outbound_transfer`: wraps the transfer in `HyperMessage` for gossip with NO outer envelope signature.

## Summary

The transfer wire format and its strong-validation gate are bolted together such that two protobuf fields are required to be present and well-formed for admission, **applied as durable state**, and **completely unauthenticated by the existing Schnorr signature**:

1. `HyperTransferOutput.one_time_pubkey` — recorded by the runtime in the persistent note store as the verification key that future spenders of this output must sign under. (`runtime.rs:4187-4197`, `builder.rs:153-165`, `note_store.rs:87-92`)
2. `HyperTransferTx.blinding_diff_scalar` — the prover-supplied `r_in − r_out − r_fee` used by `verify_balance_with_blinding_diff` for Pedersen balance closure. (`transfer_codec.rs:135-144`, `runtime.rs:3463-3471` and `:4146-4164`)

Compare against what each input's `spend_signature` actually signs (`tokens.rs:237-256`):

```rust
pub fn signing_payload(&self) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hypersnap-transfer-v1");
    h.update((self.inputs.len() as u32).to_be_bytes());
    for inp in &self.inputs {
        h.update(inp.commitment.to_bytes());
        h.update(inp.nullifier.0);
    }
    h.update((self.outputs.len() as u32).to_be_bytes());
    for out in &self.outputs {
        h.update(out.commitment.to_bytes());
        h.update((out.range_proof.len() as u32).to_be_bytes());
        h.update(&out.range_proof);
    }
    h.update(self.fee_atoms.to_be_bytes());
    // ... finalize
}
```

The signing payload covers input commitments, input nullifiers, output commitments + range proofs (length-prefixed), and the fee. It does **not** cover `output.one_time_pubkey`, `blinding_diff_scalar`, or `chain_id`. This is by construction: the signer is the input note's owner (who holds `spend_secret` for the input), not the output's creator, so the signer never sees the output one-time keys at signing time. But because the wire-level fields are then *blindly recorded* by every full node, anyone with the ability to alter the wire bytes between sender and the first-accepting validator can swap them.

`blinding_diff_scalar` is uniquely determined by the (inputs, outputs, fee) Pedersen residual — there is exactly one scalar that closes the balance — so an attacker rewriting it just causes `verify_balance_with_blinding_diff` to fail and the transfer to be dropped at the mempool gate (DoS only). `one_time_pubkey` has **no such constraint**: any canonical Decaf448 point passes `extract_output_pubkeys`, including a pubkey the attacker controls the secret for.

## Concrete attack — recipient output-burn via gossip-race

Setup:
- Alice operates a hypersnap full node + has a valid stealth-input she wants to spend to Bob.
- Bob is identified by his stealth public address `(view_pubkey_B, spend_pubkey_B)`.
- Alice's runtime produces, via `tx_to_proto_full` (`runtime.rs:4967` is the canonical test/example path):
  - `inputs`: `(C_in, nf_in, sig_in)` — Schnorr signature over `signing_payload` (above).
  - `outputs`: `[(C_out, range_proof, one_time_pubkey = P_B)]` where `P_B = h·G + spend_pubkey_B` is the stealth one-time key derived in `create_stealth_output` (`tokens.rs:737-752`).
  - `blinding_diff_scalar = r_in − r_out` (no fee for simplicity).
- Alice gossips `HyperMessage::Transfer(tx_proto)` (`router.rs:312-317`). There is no outer envelope signature on the gossip message — only the per-input Schnorr signature, which only covers `signing_payload`.

Attack (Eve, a relayer / peer that receives the gossip frame before Alice's neighbors propagate to validator nodes):
1. Eve decodes `HyperTransferTx` from the gossip frame.
2. Eve generates fresh `x_atk ← Scalar::random; P_atk = x_atk · G`.
3. Eve replaces `outputs[0].one_time_pubkey` with `point_to_compressed_bytes(P_atk)` (56 bytes, canonical Decaf448 form — `extract_output_pubkeys` accepts).
4. Eve re-encodes (or, simpler: edits the bytes in-place — protobuf `bytes` field is a fixed-size span here) and re-broadcasts.
5. The mutated transfer reaches validator V before Alice's copy. V's `submit_message` runs (`runtime.rs:3459-3482`):
   - `tx_from_proto` succeeds — the typed `TransferTx` is identical to Alice's (signature, commitments, nullifier all unchanged).
   - `extract_blinding_diff` succeeds — Eve didn't touch this field.
   - `validate_against_store(&note_store)` succeeds — looks up the *input* owner pubkey, recomputes `signing_payload`, verifies the Schnorr signature. `one_time_pubkey` is **not part of `signing_payload`** so verification still passes.
   - `verify_balance_with_blinding_diff` succeeds — depends only on commitments, fee, and the unchanged scalar.
   - `extract_output_pubkeys` succeeds — `P_atk` is a canonical Decaf448 point.
   - The transfer is admitted to V's mempool.
6. Alice's copy arrives later; mempool dedupe (`mempool.rs:158-161`, keyed by first input nullifier) rejects it as a `DuplicateNullifier`. The legitimate `one_time_pubkey = P_B` is now permanently displaced at V.
7. The proposer drains the mempool and includes Eve's mutated transfer in a block. On `import_block` (`runtime.rs:4185-4205`), every importing node executes:

   ```rust
   self.note_store.record_note(commitment, output_pubkeys[i]);
   //                                       ^^^^^^^^^^^^^^^^^^^^
   //                                       This is P_atk, NOT P_B.
   ```

   Persisted in the durable note store (`note_store.rs:87-92`): `(C_out → P_atk)`.
8. Future state: Bob scans the chain. The encrypted note payload (which Alice presumably delivered to Bob out-of-band, encrypted under `view_pubkey_B` per `encrypt_note_payload` at `tokens.rs:487-520`) tells Bob `(value, blinding)`. Bob recomputes `C_out = commit(value, blinding)` — matches the on-chain commitment. Bob is convinced he received the funds.

   But when Bob tries to spend: `validate_against_store` calls `note_store.lookup_owner(&C_out)` and gets `P_atk` (`tokens.rs:347-360`). Bob's `spend_secret = h + spend_secret_B` (from `scan_stealth_note`) satisfies `spend_secret · G == P_B ≠ P_atk`. `schnorr_verify(P_atk, payload, sig_under_Bob)` rejects. Bob cannot spend.

   The output is permanently burned from Bob's POV. The `value` atoms are durably committed to in the Pedersen commitment but unreachable. Eve cannot redeem them either (she has `x_atk` matching `P_atk` so she could produce a valid Schnorr signature, but she does not know `(value, blinding)` — without those, she cannot construct an onward `TransferTx` that closes the Pedersen balance: `verify_balance_with_blinding_diff` would require her to reveal the precise `r_diff = r_out_old − r_out_new − r_fee` and she does not know `r_out_old`).

   Net: targeted destruction of Bob's confidential payment, undetectable to the spender (Alice's input nullifier is correctly consumed — Alice has spent her money), invisible to outside observers (everything looks like a normal anonymous transfer), un-attestable to Bob (the on-chain commitment matches what he expects; only the unspendability surfaces when he eventually tries to spend).

The race condition is winnable in practice:
- Validators / block proposers receive gossip from many peers and are positioned to see any transfer before it widely propagates.
- A relay-class node colocated near a target sender's network neighborhood (or running as the sender's first gossip peer) can intercept-and-mutate before the legitimate copy reaches downstream nodes.
- The attacker can also wholesale spam-mutate every observed `HyperTransferTx` on the network. They lose value parity (they cannot capture the burned atoms) but inflict per-transfer damage; this is a feasible economic griefing attack against the entire confidential-transfer rail, not just a targeted victim.

## Why mempool / chain rails do not catch this

1. **Per-input Schnorr signature**: covers `signing_payload`, which (correctly) commits to the input authority + the output structure that affects Pedersen balance (commitments + range proofs + fee). It does not cover output `one_time_pubkey` because the signer (input owner) cannot in general be expected to know which output keys will go on the wire — but the production-path encoder `tx_to_proto_full` is called by code that DOES know both. Nothing prevents a one-line fix that hashes `one_time_pubkey` bytes into `signing_payload`. See *Recommended fix*.
2. **Pedersen balance closure** (`verify_balance_with_blinding_diff`): depends only on commitments + fee + `blinding_diff_scalar`. Output `one_time_pubkey` is independent of the balance equation.
3. **Range proofs**: per-output, prove `0 ≤ value < 2^64` for the output commitment. Independent of the one-time pubkey.
4. **Mempool dedupe**: keyed by first input's nullifier (`mempool.rs:158`). The mutated transfer has the same first nullifier, so it competes for the same key slot — exactly the race condition that lets the first-arriving (mutated) copy displace the honest one.
5. **Block hash** (`chain.rs:25-44`): covers `hyper_state_root` (which reflects new nullifiers + commitments in the verkle tree) and signature/epoch/etc. — does NOT cover the raw transfer wire bytes. So even nodes that observed Alice's original encoding will accept the mutated one in the block; the verkle root commits to `(commitment, nullifier)` not `(commitment, one_time_pubkey)` (see `builder.rs:122-130` — the tree gets `nullifier` keys with value `[1u8]` and `commitment` keys with value `commitment_bytes`; `one_time_pubkey` is recorded in the **off-tree** note store).
6. **Off-tree note store** (`note_store.rs:80-95`): the only place `(commitment → one_time_pubkey)` is persisted, and it accepts whatever the wire says. This is the trust boundary that is breached.

## Variant — `blinding_diff_scalar`

Same coverage gap, but uniquely-determined value (the residual `r_in − r_out − r_fee` is a single scalar). Mutating it just fails `verify_balance_with_blinding_diff` and drops the transfer at the gate. Realised effect: targeted DoS — an attacker can drop any specific honest transfer they observe by mutating this field, since the mempool will then reject the legitimate copy as a duplicate-nullifier (Eve's mutated copy may have been admitted first, accepted into the gossip pipeline, then dropped at the mempool gate for failing the balance check; OR Eve's mutated copy is rejected at all mempool gates as a balance failure but only after consuming the dedup-by-nullifier slot in the gossip-relayer caches that don't perform strong validation). The DoS variant is lower severity than the `one_time_pubkey` variant but a strict superset of the canonicality concern.

## Variant — protobuf field-tag mutability of `tx_to_proto` (non-full encoder)

`transfer_codec.rs:89-96`:

```rust
pub fn tx_to_proto(t: &TransferTx) -> proto::HyperTransferTx {
    proto::HyperTransferTx {
        inputs: t.inputs.iter().map(input_to_proto).collect(),
        outputs: t.outputs.iter().map(output_to_proto).collect(),
        fee_atoms: t.fee_atoms,
        blinding_diff_scalar: Vec::new(),
    }
}
```

`output_to_proto` (`transfer_codec.rs:70-76`) similarly produces `one_time_pubkey: Vec::new()`. So calling `tx_to_proto` produces a wire message that the strong-validation gate **always rejects** (empty `blinding_diff_scalar`, empty `one_time_pubkey`). This is a footgun encoder that is `pub` in the codec module and used by router/proofs tests (`router.rs:390`, `proofs.rs:93`, `builder.rs:501`, `mempool.rs:273`). A future production caller picking the wrong encoder yields silently-undeliverable transfers; not directly exploitable, but the existence of two parallel encoders where one always fails downstream is anti-pattern.

## Non-finding — chain-id binding on the transfer payload

`signing_payload` also omits `chain_id`, which is the same F104/F105-family invariant gap. For the confidential transfer rail this is **practically inert** in a way that the F104 fee-deposit / F101 account-association cases are not: the input commitment must be present in the target chain's note store for `validate_against_store` to even resolve an owner pubkey, and note sets are per-chain by construction (notes are created by per-chain `record_note` calls keyed by commitment bytes that are unique per random blinding). For a cross-chain replay to work, an attacker would need to first cause the same input commitment to be recorded with the same owner pubkey on the destination chain — which the chain would need to be tricked into via some independent flaw. Noting here so the chain-id-binding family is not re-opened as a duplicate; this is the codec's mitigating circumstance, not an absolute protection.

## Recommended fix

Extend `TransferTx::signing_payload` to cover the wire-level output one-time pubkeys + the blinding-diff scalar. Concretely, the producer must:

1. Have `tx_to_proto_full` (and any future producer that fills these fields) feed the **full wire-level payload** into `signing_payload` *before* the signer is asked to sign. The signer must receive a `signing_payload_v2` that hashes:

   ```
   "hypersnap-transfer-v2"
   chain_id          (u64 BE)               # F104/F105 family fix
   inputs.len()      (u32 BE)
   for inp in inputs:
       inp.commitment.to_bytes()
       inp.nullifier.0
   outputs.len()     (u32 BE)
   for out in outputs:
       out.commitment.to_bytes()
       out.range_proof.len()  (u32 BE)
       out.range_proof
       out.one_time_pubkey    (56-byte compressed Decaf448, REQUIRED)  # F149 fix
   fee_atoms         (u64 BE)
   blinding_diff_scalar       (56-byte canonical Decaf448 scalar)      # F149 variant fix
   ```

   The signer (input owner) DOES know `one_time_pubkey` and `blinding_diff_scalar` at signing time in the production path — `tx_to_proto_full` is given both as arguments and the production runtime example at `runtime.rs:4960-4967` constructs the signature **before** calling `tx_to_proto_full`, but it could equally well construct the signature **after**, with the two extra fields injected into the signing payload.

2. Eliminate the non-full encoder `tx_to_proto` (or rename it to `tx_to_proto_unfilled_FOR_TESTS_ONLY` and feature-gate it under `#[cfg(test)]`). Production callers should not have access to an encoder that produces always-rejected wire bytes.

3. Reject empty/missing `one_time_pubkey` in `output_from_proto` rather than only in the separate `extract_output_pubkeys` pass — the structural decoder should not produce a typed `TransferOutput` that has been stripped of its wire authority.

Adopting v2 requires a domain-separator bump (`hypersnap-transfer-v2`) and synchronized roll-out; the v1 chain-id-binding remediation pattern in the F104/F105 finding family is precedent. Treat this as the v2 DST migration's defining payload-coverage upgrade.

## Severity discussion

- Not direct theft: attacker cannot extract the burned atoms (Pedersen balance closure blocks them).
- Is permanent value destruction targetable at any specific recipient that the attacker can identify by transfer flow.
- Is undetectable to the spender (their input nullifier is consumed normally — they spent their money) and undetectable to the recipient until they try to spend (the on-chain commitment matches; only the missing/wrong `one_time_pubkey` surfaces when `validate_against_store` runs and finds no signature can match).
- Easy to execute for any peer that wins the gossip race; trivially scriptable at relayer scale; cost = re-encoding the protobuf bytes per observed transfer.
- No slashing path — the mutator is anonymous on the gossip plane (no per-message sender authentication; `router.rs:312-317` wraps the transfer with no outer envelope signature).

Sets the floor at **Medium**. Considered "high" if the design intent is for confidential transfers to provide payment integrity against active network adversaries — which is the standard model for stealth-address rails of this class.

## Suggested cross-references

- F101 / F104 / F105 / F153: chain-id and payload-coverage binding family. F149 is the codec-side variant — same class of "signing payload missing fields the runtime trusts" but in a context where the un-bound fields are wire-format outputs of a codec rather than envelope metadata.
- The mempool key choice (`mempool.rs:158`) — first-input-nullifier — is what makes the race winnable; mempool design alternatives (e.g., keying by full canonical wire hash) would change the variant landscape but introduce a new spam vector (multiple gossip copies of the same logical transfer would coexist).
