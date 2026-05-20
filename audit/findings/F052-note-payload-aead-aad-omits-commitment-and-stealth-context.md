---
id: F052
task: H052
specialist: rust-crypto-primitives
attack_class: aead-aad-discipline
severity: medium
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.78
  hypotheses_walked: 8
  validated_at: 2026-05-20T17:10:00Z
  note: "AAD shape claim verified; today impact is forward-looking (no production caller, no wire field). Reframe as primitive hardening, not active vuln."
---

# F052: privacy-note AEAD payload AAD is a static label only — does not bind the Pedersen commitment, the stealth `tx_pubkey`, the recipient's view pubkey, or any per-note context

## Summary

`encrypt_note_payload` / `decrypt_note_payload`
(`code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:487-520, 583-616`)
are the privacy-note AEAD primitives. They encrypt
`value (8B BE) || blinding (56B Decaf448 scalar)` to the recipient's
stealth view pubkey under `key = HKDF-SHA256(salt = b"hypersnap-note-salt-v1",
ikm = compressed(r·A), info = b"hypersnap-note-payload-v1")` with
ChaCha20-Poly1305 and a random 12-byte nonce.

The AAD passed to ChaCha20-Poly1305 at both encrypt time
(`tokens.rs:511`) and decrypt time (`tokens.rs:598`) is the literal
constant `NOTE_PAYLOAD_HKDF_INFO = b"hypersnap-note-payload-v1"` — a
static byte string with no per-note variation. This AAD content binds
nothing about the context the note lives in:

- **NOT** the Pedersen `commitment` C = v·B + r·B_blinding that the
  encrypted `(value, blinding)` is supposed to open. The receiver only
  finds out about the commitment mismatch by separately calling
  `PedersenCommitment::opens_to(value, blinding)` (`tokens.rs:53-56`),
  which is a post-decrypt check the caller has to remember.
- **NOT** the stealth ephemeral `tx_pubkey = R = r·G` that anchors the
  Diffie-Hellman shared secret. R is published alongside the note
  (`tokens.rs:108-114 Note`) and is the receiver's only fix on which
  sender produced this note.
- **NOT** the one-time pubkey P = h·G + B that identifies the spend
  authority of the note (`tokens.rs:746`).
- **NOT** any transfer identifier, nullifier, or transaction signing
  payload that the note is part of.

The result: the AEAD ciphertext is portable across notes that share
the same recipient view pubkey and sender ephemeral secret. There is
nothing in the authenticated envelope that says *this payload belongs
to this commitment and this R*. Cross-binding is delegated to caller
discipline (the "rebuild commitment from decrypted plaintext, compare
to on-chain commitment" pattern at `PedersenCommitment::opens_to`), and
the only spot in the codebase that documents this delegation is
**absent** — neither the module-level doc-comment, nor the
`Note`/`EncryptedNotePayload` struct docs, nor the `encrypt_note_payload`
signature comment, tells callers that they must perform that
post-decrypt commitment check before trusting the value/blinding
they received.

This is the parallel AAD-discipline gap to F018 (sender-binding
missing from DKLS wire AAD) and F023 (digest binding missing from
DKLS sign-ceremony wire AAD) — but in the privacy-token AEAD layer
rather than the DKLS transport layer.

## Description

### Where the AAD is supplied

`tokens.rs:506-514` (encrypt):

```rust
let ciphertext = cipher
    .encrypt(
        nonce,
        Payload {
            msg: &plaintext,
            aad: NOTE_PAYLOAD_HKDF_INFO,
        },
    )
    .expect("ChaCha20-Poly1305 encrypt cannot fail on 64 bytes");
```

`tokens.rs:593-601` (decrypt):

```rust
let plaintext = cipher
    .decrypt(
        nonce,
        Payload {
            msg: &encrypted.ciphertext,
            aad: NOTE_PAYLOAD_HKDF_INFO,
        },
    )
    .map_err(|_| NotePayloadError::Decryption)?;
```

`NOTE_PAYLOAD_HKDF_INFO` is defined at `tokens.rs:458`:

```rust
const NOTE_PAYLOAD_HKDF_INFO: &[u8] = b"hypersnap-note-payload-v1";
```

— a domain-separator label and nothing else. There is no per-note,
per-recipient, per-sender, or per-commitment data fed into the AEAD
authentication tag beyond what's in the plaintext itself.

### What an attacker (or a buggy caller) can do

The intended threat model for this AEAD is: "anyone who is not the
recipient sees an opaque ciphertext that they cannot decrypt, cannot
modify without invalidating the tag, and cannot cross-bind to a
different note."

The first two properties hold (AEAD confidentiality + integrity under
a key only the recipient can derive). The third property — cross-
binding — is the one this finding is about, and it does not hold at
the primitive level. Specifically:

1. **Mix-and-match between two notes from the same `(sender_secret,
   recipient_view_pubkey)` pair.** If a sender ever produces two
   notes to the same recipient view-pubkey under the same
   `sender_secret` scalar `r` (i.e. they reuse `r` across two notes;
   the stealth scheme picks a fresh `r` per `create_stealth_output`
   call at `tokens.rs:742`, but nothing on `encrypt_note_payload`'s
   signature forbids a caller from reusing one `r` across multiple
   commitments), the two notes share the same AEAD key (because the
   key is derived from `r·A`). Random nonces under a repeated key are
   safe-ish (~2^48 birthday safety for 96-bit nonces), but worse:
   **a single ciphertext is decryptable under any note that shares
   the key**. There is no AAD that pins the ciphertext to commitment
   C₁ vs commitment C₂. The receiver scans, gets two notes, decrypts
   each, and recovers `(value₁, blinding₁)` and `(value₂, blinding₂)`
   from the respective ciphertexts. An attacker (or a wire-layer bug)
   who swaps the two `encrypted_payload` fields between the two notes
   produces a state where:
   - Note(C₁, encrypted_payload₂): receiver decrypts → gets
     (value₂, blinding₂). `C₁.opens_to(value₂, blinding₂)` is false.
   - Note(C₂, encrypted_payload₁): symmetric.

   The receiver can detect this by calling `opens_to` *if they
   remember to do it*. The AEAD tag itself raises no alarm — both
   decrypts succeed. The wire-format check in `transfer_codec.rs`
   has no `encrypted_payload` field today (the type is plumbed but
   not in proto, see `proto/definitions/hyper.proto` — there is no
   `bytes encrypted_payload` in `HyperTransferOutput`), so a future
   wire integration would have to remember to add the cross-check
   *outside* the AEAD.

2. **Cross-recipient-view-key replay across notes that share an `r·A`
   collision.** This is the cryptanalytic generalization of (1). The
   shared point `r·A` determines the AEAD key entirely. Two distinct
   `(r, A)` pairs that produce the same compressed-Decaf448 point
   produce the same AEAD key. The chance of a random collision on
   Decaf448's 446-bit group is negligible, but the same kind of
   "wrong-context decryption succeeds" pattern from (1) recurs for
   any shared-key path.

3. **No binding to the on-chain commitment when the ciphertext
   becomes wire-resident.** Today the `encrypted_payload` is not on
   the wire (see proto grep below). But the type is plumbed and
   advertised in the module doc — the privacy-token feature is
   "currently unused in production flow per the README, but plumbing
   is present" (per `docs/00-OVERVIEW.md` section 2 bullet 6). The
   first wire-integrator will encode `EncryptedNotePayload` into
   `proto::HyperTransferOutput` (the natural place — it already has
   `bytes one_time_pubkey` per `transfer_codec.rs:74-76`). At that
   point an on-chain or relay-layer adversary who controls payload
   bytes (the field is per the proto's bytes-payload convention not
   signed by anyone in `validate_against_store`, which only verifies
   commitment + nullifier + range_proof + spend signature) can swap
   `encrypted_payload` fields across outputs of distinct transfers.

   The current `TransferTx::signing_payload`
   (`tokens.rs:237-256`) hashes:
   ```
   inputs (each commitment + nullifier)
   outputs (each commitment + range_proof_len + range_proof)
   fee_atoms
   ```
   — i.e., `encrypted_payload` is NOT covered by the spend signature
   either. So the AEAD is the only barrier against
   `encrypted_payload` substitution, and the AEAD's AAD is a static
   label that doesn't bind anything that would let the receiver tell
   the substitution happened at the AEAD layer.

4. **Documentation gap.** `encrypt_note_payload`'s doc comment
   (`tokens.rs:484-485`) says:
   > Encrypt `(value, blinding)` to the recipient's view pubkey
   > using the sender's ephemeral secret `r`.

   No mention of "callers must verify after decrypt that the
   plaintext re-commits to the note's published commitment." No
   mention of "the AAD is empty of contextual data; if you want
   commitment-binding you must add it yourself by extending the
   AAD." Future callers in this codebase or downstream forks will
   have no in-source signal that the primitive is unsafe-by-default
   for swap attacks.

### Why this is a real AAD-discipline gap (not just "implementation detail")

The brain library's `aead-aad-discipline` attack class checklist (see
the rust-crypto-primitives persona at
`.claude/agents/specialists/rust-crypto-primitives.md`):

> A protocol that puts session-id / role / direction in AAD prevents
> cross-context replay. A protocol that delegates AAD entirely to the
> caller and the caller forgets, leaves cross-session replay possible.

This is exactly the pattern: AAD-as-static-label = caller delegated
the cross-context binding (to the post-decrypt commitment check); a
caller who forgets the check has zero detection of substitution.

Contrast with `dkls_wire_codec::build_aad` (`dkls_wire_codec.rs:100-108`)
which puts `(epoch, round_tag, sender, receiver)` into the AAD as
intentional cross-context binding. That model is the right shape for
the privacy-note primitive too — the contextual binding should at
minimum include the note's commitment (so a swap is detected at the
AEAD tag, not via a remember-to-call-`opens_to` rule) and ideally
include the `tx_pubkey` R (so the encryptor cannot create one
ciphertext usable under two distinct stealth ephemera).

### Where this lives on the spectrum

- **F018**: sender authentication is missing from DKLS wire AAD →
  active gossip-spoof attack on running DKG/sign ceremonies.
- **F023**: digest binding is missing from DKLS sign wire AAD →
  cross-routing across in-flight ceremonies at the same epoch.
- **F052 (this finding)**: commitment binding is missing from
  privacy-note AEAD AAD → future-tense substitution attack on
  privacy-token notes once they go on the wire; today, this is a
  primitive-level discipline gap whose impact is moderated because:
  (a) the primitive isn't yet wired into the on-chain proto, and
  (b) the recipient *can* detect substitution via `opens_to` if
  they remember.

F018 / F023 are higher severity because they bite *now*. F052 is
medium severity because it's a *primitive-level shape* that locks
in a foot-gun for future integrators. The mitigation cost is small
(add commitment + R bytes to the AAD), and doing it before any wire
integration is much cheaper than retrofitting after.

## Impact

- **Future wire-integration risk.** When the privacy-token flow is
  wired into the proto (the README explicitly says this is planned;
  the type is already in `hypersnap_crypto::tokens` and
  `transfer_codec.rs` already round-trips `TransferTx` minus the
  payload), the first wire format will carry `bytes encrypted_payload`
  on each output. Per `validate_against_store` /
  `validate_with_input_pubkeys` (`tokens.rs:347-369, 326-341`) the
  spend signature covers commitment + nullifier + range proof + fee
  but NOT the encrypted payload. Without per-note AAD binding, an
  on-the-wire byte-level swap of `encrypted_payload` between two
  outputs of the same or different transfers (or in P2P delivery /
  read-API serving) produces a state where:
  - Outputs are well-formed structurally (range proofs are valid,
    nullifiers don't double, spend signatures verify).
  - Receiver decrypts successfully (the AEAD tag passes — the AAD
    is a static label, common to all notes).
  - Plaintext `(value', blinding')` does not match `C`, so
    `opens_to` fails.
  - **If the receiver doesn't run `opens_to` after decrypt, they
    treat the wrong `(value', blinding')` as authentic and may
    spend a note that doesn't exist (or fail to spend one that
    does).**

  The receiver's spendability is bounded by the on-chain
  commitment and nullifier-set semantics, so the worst outcome is
  "I can't spend this note" or "I think I have N atoms but
  actually I have M ≠ N." This is loss of property (lost ability
  to spend) and bookkeeping error (perceived balance ≠ real
  balance). Not silent value loss in the system, but silent value
  loss to the recipient.

- **Caller-discipline pitfall in primitives crate.** A downstream
  consumer of `hypersnap-crypto` (e.g., the planned hypersnap-app
  SDK, an offline wallet tool, the bridge-ceremony binary that
  already imports `hypersnap_crypto::tokens`) may use
  `encrypt_note_payload`/`decrypt_note_payload` for related but
  not-on-wire purposes — e.g., storing notes encrypted at rest with
  the user's view secret. In those code paths the
  "remember-to-call-`opens_to`" mitigation is the consumer's
  responsibility and there's no compile-time hook to remind them.

- **Cryptographic shape, not active exploit today.** Because the
  note-payload AEAD is not yet on the wire, this finding does NOT
  describe an in-production attack. It describes the wrong shape at
  the primitive level — the kind of thing that, once shipped, gets
  papered over by "the receiver remembers to check" rules that
  invariably get forgotten by some downstream caller. Treat this as
  a hardening recommendation against future production wire-up.

Severity: **medium**. Active-attack severity today is low (the
primitive is not on the wire); architectural-defect severity is
medium because the shape will be re-used as-is in the first
wire-integration if not fixed first.

## Evidence

* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:458` —
  `const NOTE_PAYLOAD_HKDF_INFO: &[u8] = b"hypersnap-note-payload-v1";`.
  This single constant is the AAD value used at both encrypt and
  decrypt.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:506-514` —
  `encrypt_note_payload` passes `aad: NOTE_PAYLOAD_HKDF_INFO`
  unconditionally with no per-call context.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:593-601` —
  `decrypt_note_payload` mirror with the same static AAD. The two
  sites are byte-equal, which is the only correctness requirement
  for AEAD verification to succeed — but they encode no per-note
  context.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:487-495` —
  `encrypt_note_payload` signature: `sender_secret`,
  `recipient_view_pubkey`, `value`, `blinding`, `rng`. None of these
  are AAD-bound; they only contribute to the key derivation (via the
  shared point) or end up in the plaintext.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:108-114` —
  `Note { commitment, encrypted_payload, one_time_pubkey }`. The
  commitment and one_time_pubkey are public alongside the
  ciphertext but are not bound to it via the AEAD.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:53-56` —
  `PedersenCommitment::opens_to(value, blinding) -> bool`. The
  receiver's only mechanism to detect commitment ↔ payload mismatch
  is to call this function after `decrypt_note_payload`. There is
  no automatic invocation; it's a manual cross-check.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:483-486` —
  doc comment on `encrypt_note_payload`. No mention of the
  caller's responsibility to verify the commitment opens to the
  decrypted plaintext.
* `code/hypersnap/crates/hypersnap-crypto/src/tokens.rs:237-256` —
  `TransferTx::signing_payload`. Hashes inputs (commitment +
  nullifier), outputs (commitment + range_proof), and fee. Does NOT
  include any `encrypted_payload` bytes. If `encrypted_payload`
  later joins the wire, the spend signature on inputs does not
  cover it.
* `code/hypersnap/src/hyper/transfer_codec.rs:36-87` — proto
  encode/decode for inputs and outputs. No `encrypted_payload`
  field on `HyperTransferInput` or `HyperTransferOutput`. Future
  wire integration will need to add one; absent F052's mitigation,
  the AAD shape stays unchanged when the wire bytes appear.
* `code/hypersnap/proto/definitions/hyper.proto` (grep result above)
  — no `bytes encrypted_payload` field anywhere in transfer-type
  messages. Confirms the "not yet on the wire" state.
* `findings/notes/H051-ruled-out.md:88-102` — H051 explicitly
  carved out caller-side AAD-discipline concerns as belonging to
  this hunt class:
  > "If a caller reused one `sender_secret` across multiple
  > encryptions to the same recipient, the AEAD key would repeat
  > and a random 96-bit nonce would only have ~2^48 birthday
  > safety. The expected usage … makes this a misuse rather than a
  > default behavior; if a Hunt of caller-side discipline finds
  > such reuse, it would be tracked under `aead-aad-discipline` …"

  This finding is that follow-up: the AAD shape does not protect
  against the very misuse that H051 declined to call out.
* `findings/drafts/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md` —
  prior DKLS-side AAD finding. Cited here as the precedent that AAD
  binding is load-bearing in this codebase; the same shape gap
  exists in the privacy-note AEAD.
* `findings/drafts/F023-dkls-round-messages-dropped-and-cross-routed.md` —
  the DKLS sign-AAD digest-binding finding. Same shape: AAD that
  omits a needed identifier produces cross-context substitution.
  The note-payload AAD omits the commitment in exactly the
  analogous way.
* `code/hypersnap/src/hyper/dkls_wire_codec.rs:100-108` —
  the "good shape" comparison point: `build_aad` includes
  `(epoch, round_tag, sender, receiver)`. The privacy-note AEAD
  should follow the same pattern with the note's `(commitment,
  tx_pubkey)` instead of `(sender, receiver)`.

## Suggested remediation

1. **Bind the Pedersen commitment and the tx_pubkey into the
   note AEAD AAD.** Change `encrypt_note_payload` and
   `decrypt_note_payload` to accept the commitment and tx_pubkey
   as explicit arguments and construct the AAD as:
   ```
   AAD = b"hypersnap-note-payload-v2"
       || compressed(C)            (56 bytes)
       || compressed(tx_pubkey)    (56 bytes)
   ```
   This makes the AEAD tag fail at decrypt time on any swap, no
   `opens_to` post-check needed. Bump the version label to v2 so
   forward-compat is unambiguous; v1 ciphertexts (if any exist by
   the time the migration lands) decrypt under the old AAD and the
   migration is a hard cutover.

2. **Reflect the AAD requirement in the type signature.** The
   `encrypt_note_payload` function should not let callers forget;
   the cleanest shape is to pass a `&Note` reference (or at least
   a `&NoteContext { commitment, tx_pubkey }` newtype) that
   embeds the binding fields, so the call site reads:
   ```rust
   let payload = encrypt_note_payload(
       &note_ctx,    // binds C and R
       &sender_secret,
       &recipient_view_pubkey,
       value,
       &blinding,
       &mut rng,
   );
   ```

3. **Add a regression test that exercises the cross-binding.**
   Today the test suite covers `note_payload_round_trip` (line
   1135), `note_payload_rejects_wrong_view_secret` (line 1158),
   `note_payload_rejects_tampered_ciphertext` (line 1178). Add:
   ```rust
   #[test]
   fn note_payload_rejects_swap_with_different_commitment() {
       // Encrypt payload₁ for commitment C₁; attempt to decrypt
       // it claiming commitment C₂. AEAD tag must reject because
       // C₂'s compressed bytes are in the AAD and don't match C₁'s.
   }
   ```
   This test should pass after remediation and fail before.

4. **Document the cross-check obligation.** Until #1 lands,
   document on `encrypt_note_payload`, `decrypt_note_payload`,
   `Note`, and `EncryptedNotePayload` that callers MUST call
   `PedersenCommitment::opens_to(value, blinding)` after
   decryption and treat a false result as note-corruption. This
   buys time but doesn't fix the underlying primitive shape.

5. **When the privacy-token flow is wired into the proto, ensure
   `encrypted_payload` is covered by `TransferTx::signing_payload`.**
   This is orthogonal to the AAD fix and provides defense in
   depth: even if the AAD is bound, having the spend signature
   also cover the encrypted-payload bytes prevents on-wire
   substitution by anyone other than the spender.

## Related

- `findings/drafts/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md`
  — DKLS-wire AAD does not bind sender to libp2p peer-id; same
  primitive-level AAD-discipline shape.
- `findings/drafts/F023-dkls-round-messages-dropped-and-cross-routed.md`
  — DKLS sign AAD does not bind the signing digest; cross-routing
  consequence directly analogous to the swap consequence here.
- `findings/notes/H051-ruled-out.md:88-102` — H051 explicitly
  flagged caller-side AAD discipline as out-of-scope for the
  nonce-reuse class and referred it here.
- `docs/00-OVERVIEW.md` §2 bullet 6 — "Privacy-preserving token
  primitives … Currently unused in production flow per the README,
  but plumbing is present." This finding's severity is medium
  rather than high precisely because the wire is not yet hot;
  fixing before integration is the cheap path.
