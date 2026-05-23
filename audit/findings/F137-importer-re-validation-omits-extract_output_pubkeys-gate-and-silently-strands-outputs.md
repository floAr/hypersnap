---
id: F137
task: H137
attack_class: mempool-admission-or-deterministic-ordering
severity: low
status: draft
related_findings:
  - id: F138
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.90
  hypotheses_walked: 8
  validated_at: 2026-05-23T00:00:00Z
---

# F137 — Importer's per-transfer re-validation omits the `extract_output_pubkeys` gate that mempool admission enforces; a malformed `one_time_pubkey` on an output included by the threshold committee passes import but is silently dropped during the note-store sync, leaving the verkle-tree commitment with no corresponding owner pubkey and permanently stranding the output

- **Task:** H137
- **Attack class:** `mempool-admission-or-deterministic-ordering` (specifically: importer-side re-validation that does NOT match proposer-side admission byte-for-byte — the H137 brief explicitly asks whether the re-validation gate matches the proposer's)
- **Severity (provisional):** Low. Requires a malicious threshold signer (or a 1-of-1 devnet/recovery share) to actually include a transfer with a malformed `one_time_pubkey` — that is already a powerful attacker who has many more direct attacks. The novel observation is the defense-in-depth gap: the importer accepts a class of transfer that the proposer rejects at admission, and the resulting state divergence (verkle commitment present, note-store entry absent) is permanent. Severity escalates if the field ever gains non-pubkey semantics or if `apply_message_with_notes` is wired in without removing the silent-skip inline duplicate.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/importer.rs:238-305` — `import_hyper_block`; the production importer entry point. Does NOT call `extract_output_pubkeys` and does NOT call `apply_message_with_notes`.
- `code/hypersnap/src/hyper/runtime.rs:4120-4217` — `HyperRuntime::import_block`; the runtime wrapper. Calls `import_hyper_block_with_index` and then does an inline silent-skip note-store sync (lines 4184-4205).
- `code/hypersnap/src/hyper/runtime.rs:3459-3482` — `HyperRuntime::submit_message` (transfer arm); the proposer-side mempool admission gate. Calls `extract_output_pubkeys(tx_proto)?` (line 3476-3477) and hard-rejects on Err.
- `code/hypersnap/src/hyper/builder.rs:143-175` — `HyperBlockBuilder::apply_message_with_notes`; documented as the production import path ("Production callers (block import + restart replay) use this variant"). Calls `extract_output_pubkeys(tx_proto)?` and hard-rejects on Err. **Defined but never called from production** — see `grep` evidence below.
- `code/hypersnap/src/hyper/transfer_codec.rs:150-168` — `extract_output_pubkeys`; the gating function. Validates `one_time_pubkey.len() == 56` and `point_from_compressed_bytes` canonical Decaf448.

## The four sites

```text
SITE 1 — proposer-side mempool admission (runtime.rs:3459-3482)
  tx_from_proto                ✓ called as gate
  extract_blinding_diff        ✓ called as gate
  validate_against_store       ✓ called as gate
  verify_balance_with_blinding_diff  ✓ called as gate
  extract_output_pubkeys       ✓ called as gate  ← gate

SITE 2 — importer-side re-validation (runtime.rs:4138-4165)
  tx_from_proto                ✓ called as gate
  extract_blinding_diff        ✓ called as gate
  validate_against_store       ✓ called as gate
  verify_balance_with_blinding_diff  ✓ called as gate
  extract_output_pubkeys       ✗ NOT called           ← gap

SITE 3 — importer apply (importer.rs:269-284 via builder.rs:113-135)
  Uses apply_message — does not touch one_time_pubkey at all.
  apply_message_with_notes (builder.rs:143-175), which would surface a
  malformed pubkey as BuilderError::TransferCodec(BadOneTimePubkeyLength/BadOneTimePubkey),
  is documented as "Production callers (block import + restart replay) use this variant"
  but is never called from production.

SITE 4 — post-import note-store sync (runtime.rs:4185-4205)
  if let Ok(output_pubkeys) =
      crate::hyper::transfer_codec::extract_output_pubkeys(tx_proto)
  {
      for (i, out) in tx_proto.outputs.iter().enumerate() {
          if let (Some(commitment), Some(&pk)) = (
              PedersenCommitment::from_bytes(&out.commitment),
              output_pubkeys.get(i),
          ) {
              self.note_store.record_note(commitment, pk);
          }
      }
  }
  // SILENTLY SKIPS on Err — no error returned, import succeeds.
```

Sites 1 and 2 should be identical re-validations of the same transfer. They are not.

## Grep evidence that `apply_message_with_notes` is dead

```
$ rg 'apply_message_with_notes' code/hypersnap
code/hypersnap/src/hyper/builder.rs:143:    pub fn apply_message_with_notes<S: NoteStoreMut>(
code/hypersnap/src/hyper/runtime.rs:3474:            // `apply_message_with_notes` can populate the note
```

Two hits: one is the definition (`builder.rs:143`), the other is a comment in
`runtime.rs:3474` that references it. No call sites. The documented
production-import variant is unused; the actual import path uses
`apply_message` (which only touches the verkle tree) and then runs the
inline silent-skip duplicate at runtime.rs:4185-4205.

## Concrete exploit walk-through

### Threat model

A malicious threshold-signing committee (or, in devnet, a single dev with the
1-of-1 group share) constructs a hyperblock containing a transfer whose
`outputs[i].one_time_pubkey` field is non-canonical — either the wrong
length, or a 56-byte string that does not decode to a canonical Decaf448
compressed point. The transfer is otherwise valid: its `spend_signature`
verifies, its Pedersen balance closes, the input nullifier is unspent.

### Why mempool admission would reject

`HyperRuntime::submit_message` (`runtime.rs:3459-3482`):

```rust
// Output one-time pubkeys must be present + canonical so
// `apply_message_with_notes` can populate the note
// store deterministically when the block lands.
crate::hyper::transfer_codec::extract_output_pubkeys(tx_proto)
    .map_err(|e| RoutingError::Transfer(format!("codec: {}", e)))?;
self.mempool
    .submit_transfer(tx_proto.clone())
    .map_err(|e| RoutingError::Transfer(format!("{}", e)))?;
```

Any honest validator running its own `submit_message` would refuse to
admit such a transfer to its local mempool. A malicious proposer skips
this gate by inserting the transfer directly into the block they
threshold-sign.

### Why importer accepts

`HyperRuntime::import_block` (`runtime.rs:4138-4165`) — note the absence
of `extract_output_pubkeys`:

```rust
for (i, tx_proto) in transfers_in_block.iter().enumerate() {
    let typed = tx_from_proto(tx_proto).map_err(/* ... */)?;
    let blinding_diff = extract_blinding_diff(tx_proto).map_err(/* ... */)?;
    typed.validate_against_store(&self.note_store).map_err(/* ... */)?;
    if !typed.verify_balance_with_blinding_diff(&blinding_diff) {
        return Err(/* Pedersen balance closure failed */);
    }
    // No extract_output_pubkeys here.
}

crate::hyper::importer::import_hyper_block_with_index(/* ... */)?;
```

`tx_from_proto` (`transfer_codec.rs:170-184`) and the downstream
`output_from_proto` (`:78-87`) do NOT touch `one_time_pubkey`. So a
malformed pubkey field flows through the importer's re-validation
unchecked, then through `apply_message` (which only inserts the
commitment into the verkle tree), then through the verkle-root match
(which only compares the root commitment — also independent of
`one_time_pubkey`).

### Why the post-apply note-store sync silently swallows the failure

`runtime.rs:4184-4205`:

```rust
use hypersnap_crypto::tokens::{NoteStoreMut, Nullifier, PedersenCommitment};
for tx_proto in transfers_in_block {
    if let Ok(output_pubkeys) =
        crate::hyper::transfer_codec::extract_output_pubkeys(tx_proto)
    {
        for (i, out) in tx_proto.outputs.iter().enumerate() {
            if let (Some(commitment), Some(&pk)) = (
                PedersenCommitment::from_bytes(&out.commitment),
                output_pubkeys.get(i),
            ) {
                self.note_store.record_note(commitment, pk);
            }
        }
    }
    // No else / log — silent skip.
    for input in &tx_proto.inputs { /* mark_spent — OK */ }
}
```

`if let Ok(_) = extract_output_pubkeys(...)` — the Err branch silently
skips ALL outputs of this transfer. The transfer's nullifier still gets
marked spent (line 4198-4204), but its OUTPUTS are NOT recorded in the
note store.

### Resulting state divergence

After import:
- **Verkle tree:** Output commitment present at
  `note_commitment_verkle_key(commitment_bytes)` (builder.rs:127-130).
  The verkle root reflects this insertion and matches the proposer's
  signed root.
- **Note store:** Output commitment NOT in the
  `[RootPrefix::HyperNoteCommitment][commitment 56B]` keyspace
  (`note_store.rs:33-38`).

When a later transfer attempts to spend this output, `validate_against_store`
(`tokens.rs::TransferTx::validate_against_store`) looks up the owner
pubkey by calling `note_store.lookup_owner(&input.commitment)`
(`note_store.rs:66-78`). That returns `None`. The spend is rejected.

**The output is permanently unspendable from the moment it lands.** The
commitment stays in the verkle tree forever — it counts toward the
canonical state root that every validator agrees on — but no validator
can prove ownership of it, because the field that would identify the
owner was malformed and silently dropped.

This is consensus-side coherent (every validator drops the pubkey in
the same way for the same input bytes), so it is NOT a fork primitive.
But it is a permanent loss of the output, which makes it a strict
asymmetry from the proposer-side gate that would have rejected the
transfer outright.

### Variant — the dead `apply_message_with_notes` has the OPPOSITE behavior

`builder.rs:148-175`:

```rust
self.apply_message(msg)?;
if let PendingMessage::Transfer(tx_proto) = msg {
    let output_pubkeys = extract_output_pubkeys(tx_proto)?;  // ← hard reject
    for (i, out) in tx_proto.outputs.iter().enumerate() {
        let commitment = PedersenCommitment::from_bytes(&out.commitment).ok_or(
            BuilderError::TransferCodec(TransferCodecError::BadCommitment),
        )?;
        let pk = output_pubkeys
            .get(i)
            .copied()
            .ok_or(BuilderError::TransferCodec(
                TransferCodecError::BadOneTimePubkeyLength(i, 0),
            ))?;
        note_store.record_note(commitment, pk);
    }
    ...
}
```

`extract_output_pubkeys(tx_proto)?` — propagates Err. So if anyone ever
refactors the production importer to use `apply_message_with_notes`
(thinking they are "wiring in" the documented production variant), the
silent-skip behavior in the inline duplicate (runtime.rs:4186-4205)
turns into a hard reject. Historical blocks that happen to contain
malformed `one_time_pubkey` (planted by an earlier malicious proposer,
or produced by a since-fixed bug) would suddenly fail to replay at
restart, bricking the node's verkle replay loop.

The inline duplicate and the dead canonical function thus encode TWO
incompatible decisions about malformed `one_time_pubkey`:

| Path | Decision on malformed `one_time_pubkey` |
|---|---|
| Mempool admission (`runtime.rs:3476-3477`) | Hard reject (RoutingError::Transfer) |
| Inline post-import sync (`runtime.rs:4186-4197`) | Silent skip; output stranded |
| Dead `apply_message_with_notes` (`builder.rs:153-165`) | Hard reject (BuilderError::TransferCodec) |
| Restart replay (`runtime.rs:362`, uses `apply_message`) | No interaction; note store survives from RocksDB |

Three of the four sites should produce the same answer for the same
bytes. They do not.

## Cross-references

- **F058** (INVALIDATED) — addressed an analogous "validator-defined-but-unwired" pattern: `verify_lock_signature` exists but is not called from production. Same anti-pattern as `apply_message_with_notes`, different module. F058 was invalidated for its bridge-mint impact but the validator's residual note acknowledges the unused-function pattern. F137 is the equivalent observation for the transfer-side import.
- **F117** — verkle key-derivation panic. F117's "Layer 1" recommendation requires that every verkle-tree insert go through a discriminator-prefixing constructor. F137 is a separate "Layer 1 equivalent" for the note-store: every block import should ensure every output's pubkey lands in the note store, with the SAME decision rule as mempool admission.
- **F149** — `one_time_pubkey` is unsigned (not in `signing_payload`). F149 documents the gossip-relay malleability attack on a canonical attacker-controlled key (the attacker steals the output by substituting their own pubkey). F137 documents the orthogonal attack: a malicious proposer (post-signature) supplies a malformed/non-canonical pubkey and the importer silently strands the output. Different threat models, different impacts, same root cause class (unsigned field consumed asymmetrically).
- **F033 + H035** — non-atomic per-store writes (block_index, note_store, etc.) during import. H035's note explicitly tables `note_store.rs:86-96` as a cross-witness of F033 (silent Result swallow + bare puts). F137 is distinct: it does not concern the atomicity / crash-window issue (F033) but the **decision-rule asymmetry** between mempool admission and importer apply for the same field. Even with perfect atomicity, the gap exists.
- **F028 + F153** — signing-payload coverage gap. `one_time_pubkey` is not in `signing_payload`, which is a separate signing-coverage class. F137 takes the unsigned-field state as a given and asks: given that the field flows into apply-time state, does the importer enforce the same decision rule as the admission gate? Answer: no.

## Why this is `mempool-admission-or-deterministic-ordering`, not `signing-payload-coverage`

H137's brief asks whether the importer's re-validation matches the
proposer-side validation byte-for-byte. The relevant gate is the
admission-time re-validation, not the signature. The signature covers
exactly what `signing_payload` covers; F028 and F153 own that. F137
specifically owns: "given the signed bytes, when the apply-side
re-runs the mempool's strong validation, does it run the same set?"

## Recommended fix

### Fix A (minimal, no migration cost) — make the importer's re-validation enforce the same gate

In `runtime.rs:4138-4165`, add an `extract_output_pubkeys` call:

```rust
for (i, tx_proto) in transfers_in_block.iter().enumerate() {
    let typed = tx_from_proto(tx_proto).map_err(/* ... */)?;
    let blinding_diff = extract_blinding_diff(tx_proto).map_err(/* ... */)?;
    typed.validate_against_store(&self.note_store).map_err(/* ... */)?;
    if !typed.verify_balance_with_blinding_diff(&blinding_diff) {
        return Err(/* ... */);
    }
    // NEW — match the proposer-side gate.
    crate::hyper::transfer_codec::extract_output_pubkeys(tx_proto)
        .map_err(|e| crate::hyper::importer::ImportError::TransferValidation(format!(
            "transfer[{}] one_time_pubkey: {}", i, e
        )))?;
}
```

This makes Site 2 match Site 1 byte-for-byte. A malicious proposer that
includes a transfer with a malformed `one_time_pubkey` is now rejected
at import — every validator returns Err, the threshold sig is treated
as having signed an invalid block, and the chain stays out of the
malicious state. This is a hard fork (changes which blocks are
accepted) and must be scheduled accordingly.

### Fix B (structural) — wire `apply_message_with_notes` into production and remove the inline duplicate

In `importer.rs:269-284`, replace `builder.apply_message(msg)` with
`builder.apply_message_with_notes(msg, &mut note_store)`. This requires
threading a `&mut RocksDbNoteStore` into the importer. With this in
place, drop the inline post-apply loop in `runtime.rs:4185-4205`. Now
the two paths (Site 3 and Site 4) collapse into one, with a single
documented decision rule (hard reject on malformed pubkey).

Caveat: this change must be done at the same time as Fix A, because
otherwise the dead function's hard-reject becomes live for old blocks
that may have been admitted under the silent-skip rule. If any
historical block contains a malformed `one_time_pubkey` (planted by an
earlier bug or attack), the restart replay would suddenly start
failing.

### Fix C (defense-in-depth) — delete `apply_message_with_notes` if Fix B is rejected

If Fix B is too invasive, at minimum delete the unused function so it
cannot create a false impression of safety. The inline duplicate in
runtime.rs becomes the single canonical decision rule. Add a comment
explaining the silent-skip choice.

### Fix D (sub-fix) — surface the silent skip via a metric

`runtime.rs:4186-4205` should at least log + increment a metric when
`extract_output_pubkeys` fails or when individual output decoding
fails. Today the failure is completely silent — operators have no
signal that an output was stranded.

## Open questions

- Have any historical blocks in any deployment ever contained a malformed
  `one_time_pubkey`? If yes, Fix A is a hard fork that needs careful
  migration. If no, Fix A can land as a simple consensus-rule tightening.
- Is there a path by which an HONEST proposer could produce a block with
  malformed `one_time_pubkey`? The grep shows `tx_to_proto_full` (the
  encoder used by the runtime's transfer-construction path) populates
  the field via `point_to_compressed_bytes(pk)` on a canonical `Point`
  — so under all honest code paths the field is canonical. The malformed
  case requires either (a) a malicious proposer constructing the proto
  directly, or (b) a wire-level mutation that survives gossip (per F149,
  this requires winning a gossip race). For (a) the threshold sig itself
  is the gate; for (b) the malleability is gossip-side and admission
  rejects, so block-level inclusion still requires (a).
- The reverse asymmetry — does the importer enforce ANY check that
  mempool admission does NOT? Skimming both sides: no, the importer is
  a strict subset of the mempool gate. So the only divergence is the
  `extract_output_pubkeys` gap surfaced here.

## Reproduction sketch

```rust
use crate::hyper::{HyperBlock, HyperEnvelope, HyperBlockMetadata, HyperBlockSignature};
use crate::hyper::runtime::HyperRuntime;
use crate::proto::HyperTransferTx;
// ... assume threshold-signing helpers ...

#[test]
fn importer_accepts_malformed_one_time_pubkey_that_mempool_rejects() {
    let mut rt = make_runtime();

    // Construct a transfer with a malformed one_time_pubkey on output[0]
    // (e.g., length=55, or length=56 but non-canonical).
    let tx_proto: HyperTransferTx = make_balanced_transfer_with_bad_pubkey();

    // Mempool admission MUST reject.
    let msg = wrap_in_hyper_message(tx_proto.clone());
    assert!(rt.submit_message(msg).is_err(), "mempool should reject malformed pubkey");

    // Importer accepts the same transfer when included in a threshold-signed block.
    let block = build_and_threshold_sign_block(&[/* lock */], &[tx_proto.clone()]);
    let imported = rt.import_block(&block, &[], &[tx_proto.clone()]);
    assert!(imported.is_ok(), "importer accepts what mempool rejects — gap demonstrated");

    // The note store does NOT contain the output's owner pubkey.
    let commitment = PedersenCommitment::from_bytes(&tx_proto.outputs[0].commitment).unwrap();
    assert!(rt.note_store.lookup_owner(&commitment).is_none(),
        "output silently stranded");

    // The verkle tree DOES contain the commitment (the recomputed root matched).
    let comm_key = note_commitment_verkle_key_public(&tx_proto.outputs[0].commitment);
    assert!(rt.tree.get(&comm_key).is_some(), "verkle commitment is present");

    // Any future spend of this output fails validation.
    let onward = build_transfer_spending(&tx_proto.outputs[0]);
    let validation = wrap_in_hyper_message(onward).validate_against_store(&rt.note_store);
    assert!(validation.is_err(), "downstream spend rejected — output permanently stranded");
}
```

## Affected attack-class checklist items

- `mempool-admission-or-deterministic-ordering` — primary. H137's
  brief asks specifically whether the importer's re-validation matches
  the proposer-side byte-for-byte. Answer: no, the
  `extract_output_pubkeys` gate is missing.
- `validator-defined-but-unwired` — `apply_message_with_notes` is the
  textbook unused-pub-fn anti-pattern (sibling of F058's
  `verify_lock_signature`, F117's `lock_verkle_key`, F116's KZG
  loader's Lagrange detection).
- `inline-duplicate-vs-canonical-function` — the inline silent-skip
  duplicate at runtime.rs:4185-4205 and the canonical hard-reject
  function at builder.rs:143-175 encode different policies for the
  same input. Whichever is wrong, the SAME bytes should be processed
  the SAME way by both, or one should be deleted. Currently both
  exist and disagree.
