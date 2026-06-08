---
id: H031
specialist: rust-crypto-primitives
attack_class: cross-side-encoding-asymmetry
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
scope:
  - crates/hypersnap-crypto/src/bridge_payload.rs
  - src/hyper/lock_event.rs
  - contracts/src/HypersnapBridge.sol
---

# H031 — cross-side-encoding-asymmetry (lock leaf / bridge payload) — RULED OUT

## Hunt

Look for a byte-for-byte asymmetry between the Rust encoding and the Solidity
decoding of the lock leaf / bridge payload that would let the two sides
interpret the same bytes differently (forge a claim — amount/recipient parsed
differently on L1 than committed on hyper).

## What the scope contains — two *separate* leaf representations

There are two structurally different "lock leaf" encoders in the codebase, and
they are NOT two halves of one cross-side contract. They belong to two
disjoint pipelines:

1. **L1-facing bridge merkle leaf — `bridge_payload.rs::lock_leaf_evm`.**
   `keccak256(DOMAIN_LOCK_LEAF || lockId(32) || u8(FAMILY_EVM) || u32_be(chainId) || recipient(20) || u256_be(amount))`.
   This is the leaf that `HypersnapBridge.claim` recomputes on-chain
   (`HypersnapBridge.sol:204-211`) from its typed calldata arguments
   (`bytes32 lockId, bytes1(FAMILY_EVM), bytes4(destinationChainId),
   bytes20(recipient), bytes32(amount)`).

2. **Hyper-side verkle leaf value — `lock_event.rs::encode_lock_leaf` /
   `decode_lock_leaf`.**
   `amount(8 BE) || dest_chain_id(8 BE) || dest_address_len(2 BE) ||
   dest_address || spend_pubkey_len(2 BE) || spend_pubkey`.
   This is the *value blob* stored at the verkle path `lock_id`
   (`lock_event.rs::insert_lock_into_tree` → `VerkleTree::insert`).

These two formats differ in every field width (chain id 8B vs 4B, amount 8B vs
32B), in field set (verkle leaf has no `lockId`, no family byte; carries a
`spend_pubkey` and two `u16` length prefixes the contract leaf has none of),
and in framing (length-prefixed vs fixed `abi.encodePacked`).

## Why this is NOT an exploitable asymmetry

The decisive question is *which commitment L1 actually verifies against*, and
*whether the scoped `encode_lock_leaf` bytes ever reach a Solidity decoder.*

- **L1 `claim` verifies the bridge merkle root, built exclusively from
  `lock_leaf_evm`.** The threshold-signed `latestRoot` is produced by
  `runtime.rs::produce_signed_lock_merkle_root_local` →
  `build_lock_merkle_tree` → `lock_tree.rs::build_lock_tree` →
  `encode_token_lock_leaf` → `bridge_payload::lock_leaf_evm`
  (`lock_tree.rs:36-46`, `runtime.rs:940-987`). The verkle/`encode_lock_leaf`
  bytes are never hashed into this root and are never decoded by the contract.
  `decode_lock_leaf`'s doc ("Mirrors the L1 bridge contract's parsing")
  and the `HyperLockLeaf` proto doc ("The L1 bridge contract decodes this
  exact byte layout") are **stale/false**, but no live L1 path consumes those
  bytes, so the false claim has no security consequence.

- **The L1-facing `lock_leaf_evm` path is byte-exact and pinned on BOTH
  sides.** `bridge_payload.rs::tests::cross_side_pinned_vectors` pins
  `lock_leaf_evm(lockId, 1, recipient, 1_000_000) ==
  0x946e398b9ac10b77850cfc5877dab9207e37c8622db8bbacecbbc1c997818996`, and
  `contracts/test/CrossSideDigests.t.sol:164-182` independently recomputes the
  same leaf with `bytes4(destinationChainId)` / `bytes32(amount)` /
  `bytes20(recipient)` and asserts the identical hex. Domain tags, the
  `FAMILY_EVM` byte (0), and all field widths match. `lock_tree.rs` has its own
  pin tying the single-lock tree root to the same vector
  (`lock_tree.rs:178-210`). All seven other signed payloads
  (root-update, owner-update/acceptance, upgrade, upgrade-cancel, pause,
  recover-erc20) are likewise pinned cross-side and use matching widths
  (`u64`→`bytes8`, `Address`→`bytes20`, `U256`→`bytes32`, `chain_id`→`bytes32`).

- **Width flow on the live path is consistent and lossless.**
  `ConfidentialLockBody.destination_chain_id` is `uint32` →
  `TokenLockState.destination_chain_id` `uint32` → `lock_leaf_evm`'s `u32` →
  Solidity `uint32`/`bytes4`, with `claim` enforcing
  `destinationChainId == uint32(block.chainid)`. `amount` is `u64` widened to
  `U256` (`lock_tree.rs:39`) → `bytes32`; the relayer-supplied `claim` amount
  must reproduce the signed leaf, so the widening is exact. No truncation, no
  endianness flip, no packed/non-packed mismatch on this path.

- **The scoped `encode_lock_leaf` / transparent `HyperLockEvent` path is
  retired (F058) and L1-isolated even where still live.** Gossip ingress
  (`router.rs:133-142`) and HTTP ingress
  (`http_handler.rs:1706-1744` test pins the rejection) both reject transparent
  `Lock` messages. The remaining live `encode_lock_leaf` callers
  (`importer.rs:263-271`, `runtime.rs:368-388` replay, `builder.rs:115-118`)
  only insert the blob into the **verkle** state tree inside an already
  threshold-signed `HyperBlock`; that blob is committed to the hyper state root
  and is never posted to, or decoded by, the bridge contract.

## Self-consistency of the scoped functions

`encode_lock_leaf`/`decode_lock_leaf` round-trip correctly on the Rust side
(length-prefixed, matching widths, truncation-checked — see the module's own
tests). The only latent encode-side foot-gun is the `len() as u16` cast on
`dest_address`/`spend_pubkey`, which would silently truncate a length prefix
for a > 65535-byte field; `validate_lock_event` caps EVM addresses at 20/33
bytes but non-EVM lengths are unbounded. Because nothing decodes these bytes
cross-side (the consumer is the verkle tree, which stores and returns the blob
verbatim), this is not a cross-side asymmetry and not in scope for H031. Noted
only for completeness.

## Conclusion

No confirmed cross-side encoding asymmetry. The single encoder that the
Solidity contract actually decodes/recomputes (`lock_leaf_evm` and the other
`bridge_payload` digests) agrees with `HypersnapBridge.sol` byte-for-byte and
is pinned by dual Rust + Foundry test vectors. The differently-shaped
`encode_lock_leaf`/`decode_lock_leaf` verkle-leaf format never crosses the
Rust↔Solidity boundary on any live path, so its divergent layout and stale
"L1 decodes this" documentation cannot forge a claim.

Outcome: ruled-out.
