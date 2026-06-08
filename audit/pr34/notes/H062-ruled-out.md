---
id: H062
specialist: solidity-bridge
attack_class: inbound-burn-signing-payload-replay
outcome: ruled-out
file_paths:
  - code/hypersnap/src/hyper/inbound_burn.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H062 — inbound-burn signing-payload replay: ruled out

## Scope

`src/hyper/inbound_burn.rs::inbound_burn_signing_payload(burn, hypersnap_chain_id)`
— the threshold-signing payload encoder for `HyperInboundBurn`. Hunt: does the
signed burn payload bind chainId + deployment + a unique nonce/event-id so a
burn credit can't be replayed across chains/deployments or double-claimed, and
are amount/recipient bound exactly?

## What the encoder produces

Fixed-width, no length prefixes (every field is a known size):

```
DST  "hypersnap-inbound-burn-v1"   (25 bytes, verified)
hypersnap_chain_id  BE u64          (8)
epoch               BE u64          (8)
source_chain_id     BE u32          (4)
burn_id                             (32 — contract uint256 burnId)
recipient_fid       BE u64          (8)
amount              BE u64          (8)
source_block_number BE u64          (8)
source_tx_hash                      (32)
= 133 bytes
```

Field widths match the proto integer types in `proto/definitions/hyper.proto`
(`HyperInboundBurn`: epoch/recipient_fid/amount/source_block_number u64,
source_chain_id u32). `burn_id` and `source_tx_hash` are validated to be exactly
32 bytes at the apply path (`runtime.rs::apply_inbound_burn`, lines 1296-1307),
so the absence of length prefixes is safe.

## Replay / binding analysis — all defenses present

- **Deployment binding:** `hypersnap_chain_id` (= `Runtime::protocol_chain_id`,
  a deployment-fixed config value) is bound into the signed bytes (line 45). A
  burn captured on one deployment cannot land on a sibling deployment because
  the payload differs and the signature recovers to that deployment's epoch
  group address.
- **Source-chain binding:** `source_chain_id` (the L1 origin) is bound (line 47).
- **Unique event-id / nullifier:** `burn_id` (the contract's strictly-monotonic
  `burnNonce`-derived uint256) is bound (line 48). The apply path keys the
  replay marker on `(source_chain_id, burn_id)`
  (`runtime.rs::inbound_burn_key`, line 3603) and checks + atomically persists
  it in `apply_inbound_burn`.
- **Sig-before-nullifier ordering (F096):** `apply_inbound_burn` verifies the
  threshold signature against the epoch group address BEFORE the nullifier
  short-circuit (lines 1324-1357), so a forged/unsigned message carrying an
  already-processed key is dropped at sig-verify rather than returning the
  router-relay-triggering `Ok(false)`.
- **Exact amount/recipient binding:** `recipient_fid` and `amount` are bound as
  BE u64 (lines 49-50). The `inbound_burn_rejects_tampered_amount` test confirms
  a post-sign amount tamper fails verification with zero state change.
- **Domain separation:** the 25-byte DST prevents cross-message-type signature
  confusion (distinct from reward-issuance / trust-snapshot / owner-rotation
  payloads).
- **Epoch re-sign cannot double-credit:** the nullifier `(source_chain_id,
  burn_id)` deliberately excludes `epoch`. A new validator set at epoch E+1
  could validly re-sign the same burn under `epoch=E+1`, but the second
  `apply_inbound_burn` hits the existing nullifier and returns `Ok(false)` —
  no second credit.

## Signature verification

`sig_verify::verify_hyperblock_signature` enforces 65-byte length, recovers the
secp256k1 ECDSA sig against the expected per-epoch DKLS group address, and fails
closed on mismatch (`sig_verify.rs`). Producer side keccak256-prehashes the same
payload before DKLS signing (`runtime.rs::produce_signed_inbound_burn_local`,
lines 1442-1446), so producer and verifier encode identically.

## Conclusion

The encoder binds deployment chainId, source chainId, a unique monotonic
burn-id nullifier, epoch, exact recipient and amount, plus a domain separator;
the apply path enforces signature-before-nullifier and an atomic
`(source_chain_id, burn_id)` replay marker. No cross-chain, cross-deployment, or
double-claim replay path identified. No issue.
