---
id: H061
specialist: solidity-bridge
attack_class: claim-vs-bridge-domain-separation
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/token_escrow_bridge.rs
  - code/hypersnap/src/hyper/token_escrow_claim.rs
  - code/hypersnap/src/hyper/runtime.rs
---

# H061 — claim-vs-bridge domain separation & exact-amount binding (ruled out)

## Scope
`src/hyper/token_escrow_bridge.rs` (escrow bridge-out). Hunt: can a
signature/payload meant for the escrow-claim path be reused on the
bridge-out path (or vice versa), and is the bridged amount bound exactly?

## Domain separation — SOUND

Both paths share the same EIP-712 domain
(`domain = {name:"HypersnapEscrow", version:"1", chainId:10}`) but use
distinct `primaryType` values:

- claim: `primaryType = "TokenEscrowClaim"`, struct
  `TokenEscrowClaim(address custody_address, uint256 destination_fid, uint256 nonce)`
  (`token_escrow_claim.rs:90`)
- bridge: `primaryType = "TokenEscrowBridge"`, struct
  `TokenEscrowBridge(address custody_address, uint256 amount, uint256 destination_chain_id, bytes destination_address, bytes32 lock_id, uint256 nonce)`
  (`token_escrow_bridge.rs:108`)

Under EIP-712, the signed digest is
`keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))` where
`hashStruct = keccak256(typeHash ‖ encodeData)` and `typeHash`
encodes the full type string. The two type strings differ, so the
typeHashes differ, so the message hashes differ even with an
identical domain separator and identical `custody_address`/`nonce`.
A signature produced for one path recovers to a different ECDSA
address on the other path and fails the `recovered != custody_address`
check in `validate_token_escrow_*` (bridge: `token_escrow_bridge.rs:171`).

The field-count asymmetry also forecloses collision: the bridge struct
hashes four additional fields (`amount`, `destination_chain_id`,
`destination_address`, `lock_id`) that the claim struct never includes,
so `encodeData` can never coincide in either direction. Both reuse
directions (claim→bridge and bridge→claim) are blocked.

This is exercised by `claim_and_bridge_have_distinct_signature_domains`
(`token_escrow_bridge.rs:273`), which signs a real `TokenEscrowClaim`
and asserts the same 65-byte signature on a bridge body yields
`SignatureMismatch`.

A repo-wide scan for `"primaryType"` / `"HypersnapEscrow"` confirms only
these two paths share the `HypersnapEscrow` domain; no third EIP-712
operation reuses it without its own distinct primaryType.

## Exact-amount binding — SOUND

`amount` is part of the bridge typeHash (`uint256`), so it is
cryptographically bound; tampering it post-signature is rejected
(`tampering_amount_after_sign_rejected`, `token_escrow_bridge.rs:246`).

The apply path enforces an exact escrow-balance equality:
`runtime.rs:3473` `if escrow_balance != body.amount { reject }`.
No partial bridge, no rounding, no truncation.

Width agreement is exact, ruling out a truncation/mismatch bug:
- proto `TokenEscrowBridgeBody.amount` is `uint64` (`hyper.proto:904`)
- `custody_escrow::balance_of` returns `u64` (`custody_escrow.rs:76`)
- typed-data serializes `amount` as `body.amount.to_string()` — full
  u64 decimal value rendered into a `uint256` field (lossless widening).
- `destination_chain_id` is proto `uint32`, serialized as
  `(body.destination_chain_id as u64).to_string()` into a `uint256`
  field — also a lossless widening, no truncation.

Both sides of the `!=` are `u64`, so the equality is exact and there is
no implicit narrowing.

## Conclusion
No domain-separation reuse path and no amount truncation/rounding/mismatch.
The PR-authored module implements distinct typeHashes and an exact
`u64` balance==amount gate. Ruled out.
