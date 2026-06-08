---
id: H026
specialist: rust-threshold-signing
attack_class: cross-ceremony-cross-digest-replay
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - crates/hypersnap-crypto/src/dkls_sign.rs
  - src/hyper/dkls_sign_driver.rs
  - src/hyper/dkls_wire_codec.rs
  - src/hyper/actor.rs
  - crates/dkls23/src/protocols/signing.rs
---

# H026 — cross-ceremony / cross-digest replay of DKLS signing-round messages

## Question

Can a round-2 (or any round) message from one DKLS sign ceremony (e.g.
block-signing, digest D_A) be replayed into a different concurrent or
subsequent ceremony (e.g. lock-root signing, digest D_B) to corrupt or
hijack the second ceremony's `(r, s, v)` output?

## Conclusion: ruled out

Cross-ceremony and cross-digest replay is defended in depth at five
independent layers. The worst residual outcome is a liveness abort, never a
corrupted-but-valid signature on an attacker-chosen digest.

## Evidence walked end-to-end

### 1. At most one ceremony is active per node, gated by epoch
`HyperActor` holds a single `active_dkls_sign: Option<DklsSignDriver>`
(`actor.rs:1008`) plus a FIFO `pending_sign_queue` (`actor.rs:1025`).
Tasks run strictly sequentially — the next pops only when the active one
finalizes. There is no map of concurrent same-epoch drivers that an
attacker could mis-route between. `StartDklsSign` (`actor.rs:1536-1563`)
explicitly **refuses** to replace an already-active same-epoch ceremony
(F023b fix), so two ceremonies for the same epoch never co-exist in memory.

### 2. Inbound routing decodes against the active driver's own digest
The `InboundDklsSign` handler (`actor.rs:1491-1534`) reads the active
driver's digest (`active_sign.coordinator.digest()`, line 1504) and passes
it to `open_dkls_sign_round_message(..., active_digest.as_slice(), ...)`.
The decode is therefore always performed in the context of the one ceremony
currently running.

### 3. P2P sign frames bind the digest cryptographically in the AAD
`build_sign_aad` (`dkls_wire_codec.rs:138-147`) constructs:
`"hypersnap-dkls-wire-v1" || epoch(8B BE) || ROUND_TAG_SIGN(0x51) ||
sender(1B) || receiver(1B) || digest(32B)`.
A Phase1/Phase2 frame sealed for digest D_A presents D_A in its AAD; when a
driver signing D_B calls `open_dkls_sign_round_message` with D_B, the AAD
reconstructed at decrypt time differs and the ChaCha20-Poly1305 tag check
fails (`TransportError::AeadFailed`). The codec's `aad_binds_to_epoch` test
demonstrates the same mechanism for the epoch field. Distinct
`ROUND_TAG_DKG`/`ROUND_TAG_SIGN` also prevents a DKG-sealed ciphertext from
re-presenting as a sign frame at the same epoch.

### 4. Broadcast sign frames carry a structural digest prefix
Phase3 broadcasts (no receiver) cannot use the AEAD AAD, so they use
`DISCRIMINATOR_SIGN_BROADCAST` = `[disc][digest_32B][raw]`
(`dkls_wire_codec.rs:194-222`). `open_dkls_sign_round_message` rejects any
frame whose prefix digest disagrees with the active driver's digest
(`dkls_wire_codec.rs:353-373`, `SignBroadcastDigestMismatch`), tested by
`sign_broadcast_cross_digest_rejected`. The digest is public so this is
structural rather than cryptographic, but it is sufficient: it drops the
cross-digest frame before it ever reaches `coordinator.submit`.

### 5. Ceremony digests are domain-separated by type
Every signing-payload builder prepends a distinct DST before `keccak256`,
so block / scoring / lock-root / burn / owner ceremonies can never share a
digest:
- block: `b"hypersnap-hyperblock-v2:"` (`mod.rs:404`)
- issuance: `b"hypersnap-reward-issuance-v2:"` (`rewards.rs:711`)
- trust snapshot: `b"hypersnap-trust-snapshot-v1:"` (`rewards.rs:745`)
- DA epoch seed: `b"hypersnap-da-epoch-seed-v1:"` (`rewards.rs:734`)
- inbound burn: `b"hypersnap-inbound-burn-v1"` (`inbound_burn.rs:42`)
- bridge merkle-root / owner / upgrade / pause / lock-leaf:
  `HYPERSNAP_*_V1` domains in `bridge_payload.rs:54-70`
  (`domain_tags_distinct` test asserts pairwise distinctness).
Cross-*type* digest collision is therefore cryptographically infeasible,
which is the precise scenario the hunt named ("block vs scoring vs
lock-root vs burn").

### 6. Protocol backstop: replay aborts, it does not corrupt
`DklsSignCoordinator::new` sets `SignData.sign_id = digest`
(`dkls_sign.rs:187`) and `message_hash = digest`, so the digest is woven
into every round transcript hash inside the vendored library
(`signing.rs:226,266,376,540`). Each ceremony instance draws a fresh random
`instance_key` (`signing.rs:200`). Phase 3 verifies every counterparty
commitment (`signing.rs:518`) and phase 4 runs `verify_ecdsa_signature`
against the group pubkey before returning `(s, recovery_id)`
(`signing.rs:710-712`). A message replayed from a different instance carries
inconsistent nonce commitments and yields an `Abort`, never a valid
signature on a digest the attacker did not legitimately get the committee to
sign. This matches the wire codec's own characterization of residual risk as
"liveness-only".

## Note on the doc-comment claim

`dkls_sign.rs:20-23` claims DKLS binds the ceremony to its
`(digest, signing committee)` pair via `sign_id`. In this integration
`sign_id` is set to the digest alone (line 187); the committee lives in
`SignData.counterparties`, not in `sign_id`. This is a comment/precision
nit, not a vulnerability: same-digest/different-committee instances would
still abort (point 6), and in practice digest type-separation (point 5)
plus the single-active-ceremony invariant (point 1) leave no exploitable
path. Flagging for accuracy only.

## Adjacent findings (not this hunt's class)
- F021 / F024 cover DKLS sender-binding fail-open in
  `check_dkls_sender_against_propagation_source` — a sender-spoofing
  (broadcast-sender-spoofing) issue, orthogonal to cross-digest replay and
  already filed.
