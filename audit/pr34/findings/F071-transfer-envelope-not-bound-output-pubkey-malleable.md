---
id: F071
source: felirami PR#34 inline review, 2026-07-11 (comment 3562734450)
specialist: rust-crypto-primitives
attack_class: signature-covered-payload-omits-wire-field (malleability)
file_paths:
  - src/hyper/runtime.rs
  - crates/hypersnap-crypto/src/tokens.rs
  - src/hyper/transfer_codec.rs
  - src/hyper/router.rs
commit: f4fc4afccbd0419e04000dca0c6677fd6191afec
severity_initial: high
title: Transfer admission and import verify the bare signing_payload(), not signing_payload_with_envelope(); a relay can rewrite an output's one_time_pubkey without invalidating the spend signature
validation:
  validator: rust-crypto-primitives (revalidation pass, reviewer-sourced)
  verdict: CONFIRMED
  confidence: 0.95
  validated_at: 2026-07-11T00:00:00Z
---

## Summary

The transfer primitive ships two signing digests. `signing_payload()`
(`crates/hypersnap-crypto/src/tokens.rs:243-262`) covers per-input
commitment+nullifier, per-output commitment+range_proof, and fee — but **not**
the output `one_time_pubkey` (the recipient stealth address) nor the
`blinding_diff_scalar`. `signing_payload_with_envelope(output_pubkeys,
blinding_diff_scalar)` (`tokens.rs:276-308`) additionally hashes each output
pubkey (`:298-299`) and the blinding diff (`:303`) — i.e. it binds the
recipient. **`signing_payload_with_envelope` has zero call sites** (grep across
the tree returns only its definition and two doc-comment mentions in
`router.rs:357` and `transfer_codec.rs:110`).

Both admission and block-import verify the *bare* digest, so the wire-supplied
`one_time_pubkey` is unauthenticated and yet is durably persisted. A gossip
relay can rewrite it, keeping the spend signature valid.

## Affected code (all at f4fc4af)

Admission — `submit_message`, `Body::Transfer`, `src/hyper/runtime.rs:3956-3958`:
```rust
typed
    .validate_against_store(&self.note_store)
    .map_err(|e| RoutingError::Transfer(format!("{:?}", e)))?;
```
`validate_against_store` verifies the bare payload —
`crates/hypersnap-crypto/src/tokens.rs:414`:
```rust
let payload = self.signing_payload();
...
if !schnorr_verify(pubkey, &payload, &input.spend_signature) { ... }
```

`one_time_pubkey` is not a field of the signed `TransferTx`/`TransferOutput`
(only `commitment` + `range_proof` are). It travels in a *separate* wire field
`proto.outputs[i].one_time_pubkey`, read only by `extract_output_pubkeys`
(`src/hyper/transfer_codec.rs:163-181`). So `tx_from_proto` yields a
byte-identical `TransferTx` regardless of the wire pubkey.

Import — `import_block`, `src/hyper/runtime.rs:4935-4942` runs the identical
bare `validate_against_store`, then persists the wire pubkey unconditionally at
`runtime.rs:5006-5017`:
```rust
if let (Some(commitment), Some(&pk)) = (PedersenCommitment::from_bytes(&out.commitment), output_pubkeys.get(i)) {
    self.note_store.record_note(commitment, pk);   // attacker-chosen pk persisted
}
```

Producer — no production producer exists (`router.rs:362`); the reference test
producer (`runtime.rs:5951-5957`) also signs `tx.signing_payload()` (bare) and
attaches the pubkey out-of-band via `tx_to_proto_full`. So even the reference
path does not bind the envelope.

## Attack

Mempool dedup key is the first input nullifier
(`src/hyper/mempool.rs:188`). Sequence:

1. Honest sender broadcasts transfer T with `outputs[0].one_time_pubkey =
   OPK_recipient`, spend-sig over the bare digest.
2. A relay captures T, overwrites `outputs[0].one_time_pubkey` with any
   canonical Decaf448 point `OPK_attacker`; nothing else changes.
3. Bare digest unchanged → `schnorr_verify` passes; Pedersen closure passes
   (commitments + blinding_diff untouched); `extract_output_pubkeys` accepts
   the well-formed point. Admission (3957) and import (4936) both accept.
4. Relay front-runs the honest copy; whichever lands first wins the
   nullifier-keyed mempool slot, the other is rejected `DuplicateNullifier`.
5. Import persists `record_note(out_commitment, OPK_attacker)`. The legitimate
   recipient's scan no longer resolves ownership → the output is stranded.

## Impact

**High.** Targeted output-burn / denial-of-funds against arbitrary recipients.
Theft is **not** possible: to spend the stranded output the attacker needs the
output blinding `r_out` to build a balancing `blinding_diff`, which they don't
have (`tokens.rs:266-273` documents this as "forced loss-of-funds, not theft").
The malleability is live on the **verifier** side today — admission + import
accept gossiped transfers unconditionally — so it is not gated by the missing
honest producer; the moment any transfer traffic flows, the defect is
exploitable. The code self-documents the gap as unfixed (`router.rs:355-364`,
`tokens.rs:238-242`, `transfer_codec.rs:108-119` all say production callers MUST
use the envelope while none do and neither verifier enforces it).

## Merge-blocker assessment

Blocker **for the transfer feature**. Conditional on confidential/stealth
transfers being an in-scope shipped capability of this PR (parallels the
bridge B2–B4 "conditional-on-guarantee" framing). If transfers ship, this is a
P1: wire `signing_payload_with_envelope` into `validate_against_store` on both
admission and import, and make the producer sign that same digest.

## Fix

- `validate_against_store` takes the envelope (`output_pubkeys`,
  `blinding_diff_scalar`) and verifies `signing_payload_with_envelope(...)`
  instead of `signing_payload()`.
- Import re-verifies the same envelope-bound digest before `record_note`.
- Producer/wallet signs `signing_payload_with_envelope(...)`.

## PoC

Red-polarity test `poc/F071-transfer-envelope-malleable/` — asserts the
security property (admission rejects a transfer whose `one_time_pubkey` was
rewritten post-signing), which FAILS on current code because `submit_message`
returns `Ok(())`. See that directory for verbatim red output.
