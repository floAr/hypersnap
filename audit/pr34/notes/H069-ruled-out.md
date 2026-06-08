---
id: H069
specialist: rust-crypto-primitives
attack_class: dual-sig-dst-separation
outcome: ruled-out
file_paths:
  - code/hypersnap/src/hyper/node_attestation.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H069 — dual-sig node<->FID binding DST separation (ruled out)

## Scope
`src/hyper/node_attestation.rs` — the attest flow binds an Ed25519
`node_public_key` to an `fid` using two signatures:

1. **Outer FID-signer sig** (`body.signature`) over
   `node_attest_signing_payload` =
   `ATTEST_DST(32) || chain_id || fid || node_public_key || nonce || signer_pubkey`.
2. **Node possession sig** (`body.node_signature`) over
   `node_possession_payload` =
   `NODE_POSSESSION_DST(24) || chain_id || fid`, verified under
   `node_public_key`.

Revoke uses the same body shape but a distinct `REVOKE_DST` and does
not require a node possession sig (FID owns the binding; documented).

## Hunt questions and findings

### Are the two sigs over domain-separated payloads (no cross-context reuse)?
Yes. Every signing payload in the crate carries a unique constant DST:
- `ATTEST_DST = "hypersnap-node-attest-v2"` (padded to 32B)
- `REVOKE_DST = "hypersnap-node-revoke-v2"` (padded to 32B)
- `NODE_POSSESSION_DST = "FIP-PoW-node-attest-v2"` (24B)

These differ from each other and from every other DST in the codebase
(token-transfer/stake/unstake, miniapp add/remove/update, app-receipt,
da-response, validator-event, fee-deposit, inbound-burn, etc.). The
hunt's named concern — a validator-registration signature replayed as
an attestation — does not hold: validator events sign
`validator_event_signing_payload` under
`DST = "hypersnap-validator-event-v4"` with a completely different
field layout (event_type, validator_key, length-prefixed
transport_pubkey/operator_address/validator_address/libp2p_peer_id),
so a validator-key Ed25519 signature can never coincide with the
40-byte possession payload, and vice versa. The in-file test
`attest_signature_does_not_replay_as_revoke` pins the attest-vs-revoke
separation.

### Is the binding mutual (both directions proven)?
Yes. The outer FID-signer sig commits to `node_public_key` (and to
`signer_pubkey`, `nonce`, `fid`); the node possession sig is verified
under that exact `node_public_key` (`validate_node_attest` parses
`body.node_public_key` and calls `node_pk.verify(...)`) and commits to
`fid`. To bind node key N to FID F an attacker needs BOTH N's
consent-to-F (possession sig over `...||F`) AND F's active hyper signer
(outer sig). Neither side can be impersonated with the other's key
alone. `apply_node_attestation` additionally enforces the FID-signer
authorization (`get_active_key`), the shared per-FID nonce watermark,
and global node-key uniqueness, all atomically.

The possession payload deliberately omits `nonce` and `signer_pubkey`
and `node_public_key` (the last is supplied implicitly by the
verification key). This makes a node's consent-to-FID reusable across
re-attestations after a revoke, but that is not a privilege escalation:
the node has irrevocably consented to that FID, and replay/uniqueness
are gated by the FID-signer + nonce + global-uniqueness checks in the
apply layer. The possession sig binds `fid` and `chain_id`, so it
cannot be replayed across FIDs or chains. The in-file test
`possession_proof_must_bind_fid` confirms FID binding.

## Non-security observations (not findings)
- Doc drift only: the module/proto comments and the payload-layout
  doc-comment still reference `-v1` strings ("hypersnap-node-attest-v1",
  `FIP-PoW-node-attest-v1`) while the live constants are `-v2`. The
  executed code, tests, and length assertions all use the v2 constants
  consistently; this is stale documentation, not a behavioral bug.

## Conclusion
DST domain separation is complete and the node<->FID binding is mutual
and bidirectionally proven. No cross-protocol or cross-operation
signature-reuse path. Ruled out.
