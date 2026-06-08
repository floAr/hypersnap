---
id: H044
specialist: solidity-bridge
attack_class: cross-side-encoding-asymmetry
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H044 — cross-side-encoding-asymmetry in L1↔hyper claim path — RULED OUT

## Scope walked

- `contracts/src/HypersnapBridge.sol` — `claim`, leaf reconstruction, root-update
  digest, watermark (`latestBlock`), nullifier (`claimed[lockId]`).
- `crates/hypersnap-crypto/src/bridge_payload.rs` — `lock_leaf_evm`, all digest encoders.
- `crates/hypersnap-crypto/src/bridge_state.rs` — `OutstandingLock::leaf_hash`,
  `BridgeRoot::build` (production root constructor).
- `crates/hypersnap-crypto/src/merkle.rs` — sorted-pair binary tree.
- `crates/hypersnap-bridge-ceremony/src/{main.rs,calldata.rs,types.rs}` — the
  CLI that actually produces the signed root + per-leaf proofs the contract verifies.
- `src/hyper/lock_event.rs` — verkle `encode_lock_leaf` (see "two-pipeline" note below).
- Cross-side pinned tests: `bridge_payload.rs::cross_side_pinned_vectors`,
  `bridge_state.rs::cross_check_against_ceremony_tool_5leaf`,
  `contracts/test/CrossSideDigests.t.sol`, `contracts/test/MerkleHelper.t.sol`.

## Why ruled out

The claim-path encoding boundary is byte-for-byte symmetric and exhaustively
pinned on both sides, including the areas the leaf vector alone does not cover:

1. **Leaf reconstruction.** Solidity `claim` rebuilds the leaf as
   `keccak256(DOMAIN_LOCK_LEAF || lockId || bytes1(0) || bytes4(chainId) ||
   bytes20(recipient) || bytes32(amount))`. Rust `lock_leaf_evm` produces the
   identical preimage (`u8(0) || u32_be(chainId) || recipient(20) ||
   u256_be(amount)`). Field order, widths, and the family/domain tag all match.
   The attacker cannot supply an arbitrary `leaf`: it is **derived** from the
   claim params, so a second-preimage / internal-node-as-leaf attack would
   require a keccak preimage on a fixed-shape 137-byte input — infeasible.
   Leaf preimages (137 B) and internal-node preimages (64 B) have distinct
   lengths, so no leaf can collide an internal node.

2. **Merkle tree.** `merkle.rs` (`commutative_keccak256`, lone-leaf promotion)
   matches OZ `MerkleProof.verifyCalldata` and the Solidity `MerkleHelper`.
   The 5-leaf root is pinned identically in Rust (`bridge_state`, ceremony CLI)
   and Solidity. Single-leaf tree (root == leaf, empty proof) is consistent on
   both sides and exercised in `Claim.t.sol`.

3. **Double-claim / replay within a deployment.** Gated by the `claimed[lockId]`
   nullifier (checked before any mint) plus the monotonic `latestBlock`
   watermark shared across all universal payloads. The root-advance branch
   verifies the owner sig; the ride-free branch enforces
   `blockNumber == latestBlock && merkleRoot == latestRoot`, so the leaf is
   always verified against the same root that was signed.

4. **recipient / amount extraction.** `bytes20(recipient)` / `bytes32(amount)`
   match `recipient.as_slice()` / `amount.to_be_bytes::<32>()`. `OutstandingLock.amount`
   is `U256`; `HyperLockEvent.amount` is `u64` which widens losslessly.

No asymmetry exists in field width, order, type, `abi.encodePacked` ambiguity
(every field is fixed-width — no two adjacent variable-length fields), the
family byte, or the domain tag.

## Observations noted but NOT a finding for this class

- **chainId truncation is symmetric, not an asymmetry.** Both the leaf
  (`bytes4(destinationChainId)`) and the on-chain guard
  (`destinationChainId != uint32(block.chainid)`) use only the low 32 bits of
  the chainId, and the off-chain side accepts only a `u32` chainId end-to-end
  (ceremony `LockEntry`, `NetworkTarget::Evm.chain_id`, `lock_leaf_evm`). The
  two sides agree, so there is no encoding *asymmetry*. The residual risk is a
  cross-deployment **duplicate claim** only if two canonical EVM deployments
  ever sit on chains whose chainIds are congruent mod 2^32 (the universal,
  non-chain-bound root signature replays across deployments, and `claimed` is
  per-deployment). None of the documented canonical chains (1, 8453, 10, 42161,
  137, 11155111) collide mod 2^32, so this is latent/conditional and is a
  cross-chain-replay design concern rather than a cross-side-encoding-asymmetry
  bug. Recorded here for the cross-chain-replay specialist's awareness.

- **Two-pipeline separation is correct.** `src/hyper/lock_event.rs`
  `encode_lock_leaf` produces a length-prefixed *verkle* leaf
  (`amount(8) || dest_chain_id(8) || len-prefixed dest_address || len-prefixed
  spend_pubkey`) that is NOT consumed by `HypersnapBridge.sol`. Its doc comment
  ("the L1 bridge contract proves inclusion of before minting wrapped tokens")
  is stale/aspirational: the deployed L1 path verifies a binary-merkle proof of
  a `lock_leaf_evm` leaf produced via `bridge_state` / the ceremony CLI, not a
  verkle proof. The verkle pipeline's separate balance-closure gap is already
  covered by F035; it is not an L1 claim-path encoding asymmetry.
