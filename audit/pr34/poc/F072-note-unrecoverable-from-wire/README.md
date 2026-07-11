# F072 PoC — recipient cannot recover a confidential note from wire data

**Finding:** [F072](../../findings/F072-confidential-note-recovery-data-absent-from-wire.md)
**Commit:** `f4fc4af` · **Polarity:** RED (asserts the property that should hold; FAILS on current code)

## What it proves

A confidential transfer is built to a known recipient, serialized, then decoded
like a peer receiving it off gossip. The recipient reconstructs a `ChainOutput`
from **only** the on-chain `HyperTransferOutput` fields (`commitment`,
`range_proof`, `one_time_pubkey`) and calls `scan_notes`. Because the wire
carries no `tx_pubkey`, `ChainOutput.tx_pubkey` cannot be populated and
`scan_notes` returns empty — the recipient can neither discover nor spend the
output. The test asserts recovery should succeed, so it fails today (red).

## Location

`crates/hypersnap-wallet/src/scan.rs`, appended `#[cfg(test)] mod f072_poc_tests`,
`fn f072_recipient_cannot_recover_note_from_wire_data` (see
[`f072_test.rs`](f072_test.rs)).

## Reproduce (WSL)

```
cd ~/hs-f4fc4af
RUSTFLAGS='--cap-lints allow' cargo test -p hypersnap-wallet --lib \
  f072_recipient_cannot_recover_note_from_wire_data -- --nocapture
```

## Verbatim RED output (f4fc4af)

```
thread 'scan::f072_poc_tests::f072_recipient_cannot_recover_note_from_wire_data' panicked at crates/hypersnap-wallet/src/scan.rs:110:9:
F072: recipient could not discover its confidential output from wire data -- HyperTransferOutput carries no tx_pubkey, so scan_notes returned 0 notes
test scan::f072_poc_tests::f072_recipient_cannot_recover_note_from_wire_data ... FAILED
```

## Green condition (after fix)

Add `bytes tx_pubkey = 4;` (and `bytes encrypted_note = 5;`) to
`HyperTransferOutput`; populate from the existing `StealthOutput.tx_pubkey` and
`encrypt_note_payload` in the builders/codec; persist `tx_pubkey`. `scan_notes`
then resolves the note (and `decrypt_note_payload` yields value+blinding for a
subsequent spend) → assertion passes (green).
