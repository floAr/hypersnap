---
id: F072
source: felirami PR#34 inline review, 2026-07-11 (comment 3562734455)
specialist: general-purpose (crypto/protocol)
attack_class: feature-incomplete (funds undiscoverable + unspendable)
file_paths:
  - proto/definitions/hyper.proto
  - crates/hypersnap-crypto/src/tokens.rs
  - crates/hypersnap-wallet/src/tx/shield.rs
  - crates/hypersnap-wallet/src/tx/confidential_transfer.rs
  - crates/hypersnap-wallet/src/scan.rs
  - src/hyper/transfer_codec.rs
  - src/hyper/note_store.rs
commit: f4fc4afccbd0419e04000dca0c6677fd6191afec
severity_initial: high
title: HyperTransferOutput carries neither the sender's ephemeral tx_pubkey nor an encrypted note payload; recipients cannot discover or spend confidential outputs from on-chain data
validation:
  validator: general-purpose (revalidation pass, reviewer-sourced)
  verdict: CONFIRMED
  confidence: 0.95
  validated_at: 2026-07-11T00:00:00Z
---

## Summary

A confidential output is recorded on-chain as `HyperTransferOutput`
(`proto/definitions/hyper.proto:215-226`) with exactly three fields:
`commitment`, `range_proof`, `one_time_pubkey`. It carries **no ephemeral
`tx_pubkey`** and **no encrypted note payload**. Both are required for a
recipient to independently (a) detect the output is theirs and (b) construct a
subsequent spend. The crypto layer fully implements both mechanisms; they are
simply never wired to the wire message or persisted.

## Evidence

**Wire message omits both fields** — `hyper.proto:215-226`:
```proto
message HyperTransferOutput {
  bytes commitment = 1;
  bytes range_proof = 2;
  bytes one_time_pubkey = 3;   // REQUIRED — empty rejects.
}
```
Grep for `tx_pubkey|ephemeral|encrypted_payload|encrypted_note` across `proto/`
→ no matches.

**`scan_stealth_note` cannot run without `tx_pubkey`** —
`crates/hypersnap-crypto/src/tokens.rs:842-857`: it computes the ECDH shared
secret `a·R` from the sender ephemeral `tx_pubkey = R` and the recipient view
secret, then checks the candidate one-time pubkey and derives the one-time
spend secret. `R` is fresh per-note sender randomness (`create_stealth_output`,
`tokens.rs:823-838`) and is not derivable from `commitment` or
`one_time_pubkey`.

**The crypto layer DOES provide the payload, unused** —
`tokens.rs:504-599`/`:563` `encrypt_note_payload(...) -> EncryptedNotePayload`
(plaintext = 8-byte value ‖ 56-byte blinding); `decrypt_note_payload`
(`:666-701`). The `Note` struct has an `encrypted_payload` field
(`tokens.rs:107-114`). The decrypt doc-comment (`tokens.rs:664`) states the
intended contract: the recipient gets `tx_pubkey` + commitment "from the
on-chain note row alongside the encrypted payload." Grep for
`encrypt_note_payload|decrypt_note_payload|EncryptedNotePayload` across `src/`
→ no matches. The on-chain note row that doc presumes does not exist
(`src/hyper/note_store.rs:4` maps `[commitment] -> one_time_pubkey` only).

**Wallet builders generate `tx_pubkey` and drop it** —
`crates/hypersnap-wallet/src/tx/shield.rs:23-32` reads only
`stealth.one_time_pubkey`; `tx_pubkey` is discarded (shield reuses `range_proof`
to carry raw blinding, no AEAD).
`crates/hypersnap-wallet/src/tx/confidential_transfer.rs:53-54` pushes only
`one_time_pubkey`; `tx_pubkey` dropped, and `value`/`blinding` are carried
nowhere. Runtime encoder `src/hyper/transfer_codec.rs:70-77` emits the same
three fields.

**The wallet's own scanner expects data the wire never delivers** —
`crates/hypersnap-wallet/src/scan.rs:12-31` defines
`ChainOutput { tx_pubkey, one_time_pubkey, commitment }` and calls
`scan_stealth_note(keypair, &tx_pk, &otp)`, but no path can populate
`ChainOutput.tx_pubkey` from a decoded `HyperTransferOutput`; the guard at
`scan.rs:22` (`out.tx_pubkey.len() != 56`) short-circuits to `None`.

## Consequence

Given only on-chain/gossiped data (`commitment`, `range_proof`,
`one_time_pubkey`), a recipient **cannot discover** which outputs are theirs
(needs `tx_pubkey`) and **cannot construct a spend** (needs `tx_pubkey` for the
one-time secret and `(value, blinding)` to open the commitment). For **shield**,
`amount` is public and blinding leaks via the reused `range_proof` field, so
value/blinding are technically recoverable, but the note is still
undiscoverable/unspendable because `tx_pubkey` is dropped. There is no other
channel — recovery requires an undocumented out-of-band transfer of
`(tx_pubkey, value, blinding)` from sender to recipient.

## Severity / merge-blocker

**Feature-incomplete → received confidential funds are undiscoverable and
unspendable.** Not an exploitable security hole — no theft, forgery, or
double-spend; value is stranded. P1 correctness/liveness blocker **for the
confidential-transfer / shield feature**: it does not function end-to-end as
shipped. Not a consensus- or theft-class vulnerability.

## Fix

Add `bytes tx_pubkey = 4;` and `bytes encrypted_note = 5;` to
`HyperTransferOutput`; populate them in `shield.rs` /
`confidential_transfer.rs` / `transfer_codec.rs` from the existing
`StealthOutput.tx_pubkey` and `encrypt_note_payload`; persist `tx_pubkey` in the
runtime note store.

## PoC

Red-polarity roundtrip test (see `poc/F072-note-unrecoverable-from-wire/`):
sender builds a confidential transfer to a known keypair, message is
serialized then decoded, a `ChainOutput` is reconstructed from the decoded
`HyperTransferOutput` fields only, and the test asserts
`scan_notes(recipient, &[chain_output])` returns a spendable note. It FAILS
today because `tx_pubkey` cannot be populated from the wire, so `scan_notes`
returns empty.
