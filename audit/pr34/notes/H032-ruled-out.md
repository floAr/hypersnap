---
id: H032
specialist: rust-crypto-primitives
attack_class: merkle-leaf-domain-separation
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H032 — merkle leaf vs internal-node domain separation is SOUND

Scope: `crates/hypersnap-crypto/src/merkle.rs` (sorted-pair tree) +
`src/hyper/lock_tree.rs` (lock-leaf root constructor) +
`contracts/src/HypersnapBridge.sol` `claim` / `MerkleProof.verifyCalldata`.

Hypothesis: leaves and internal nodes are hashed with no distinguishing
domain tag, letting an attacker present an internal node as a leaf (or
vice versa) to forge a Merkle inclusion proof for a fake lock and mint
wrapped SNAP on the bridge.

**Not exploitable.** Leaves are domain-separated from internal nodes by an
explicit leaf-domain tag AND by a structurally distinct, fixed preimage
length. The classic OZ second-preimage condition (raw, un-prehashed
variable-length leaves passed straight into `verifyCalldata`) does not hold
here.

## Preimage analysis (the load-bearing facts)

Leaf hash — `bridge_payload::lock_leaf_evm`
(`crates/hypersnap-crypto/src/bridge_payload.rs:191-206`) and the byte-exact
Solidity twin (`HypersnapBridge.sol:204-211`):

    keccak256( DOMAIN_LOCK_LEAF(32) || lockId(32) || FAMILY_EVM(1)
               || chainId(4) || recipient(20) || amount(32) )   = 121-byte preimage

where `DOMAIN_LOCK_LEAF = keccak256("HYPERSNAP_LOCK_LEAF_V1")`
(`bridge_payload.rs:70`, `HypersnapBridge.sol:60`).

Internal node hash — `commutative_keccak256`
(`merkle.rs:15-21`), matching OZ `Hashes.commutativeKeccak256` used by
`MerkleProof.verifyCalldata` and the test `MerkleHelper.commutativeKeccak`
(`contracts/test/utils/MerkleHelper.sol:17-21`):

    keccak256( min(a,b)(32) || max(a,b)(32) )                   = 64-byte preimage

Two independent separations therefore hold:

1. **Domain tag.** Every leaf preimage begins with the 32-byte
   `DOMAIN_LOCK_LEAF` tag; no internal-node preimage contains it. (Distinct
   from all seven other domain tags too — `bridge_payload.rs:447-463`
   `domain_tags_distinct`.)
2. **Preimage length.** Leaf preimage is 121 bytes; internal-node preimage
   is exactly 64 bytes. A 64-byte node can never equal a 121-byte leaf
   except via a keccak collision.

## Why the substitution attack fails

- Leaf value is the *output* of keccak over an attacker-non-controllable,
  domain-tagged structured preimage. The bridge recomputes it from
  `(lockId, recipient, amount, destinationChainId)` at
  `HypersnapBridge.sol:204-211`; the attacker supplies only those structured
  fields, never the leaf bytes directly. To make that recomputed leaf equal
  some internal node value in the committed tree, the attacker needs a keccak
  second-preimage — infeasible.
- Reverse direction (pass an internal node hash as a claimed leaf) fails for
  the same reason: the contract will re-derive the leaf from the structured
  fields and the domain tag, so a bare 32-byte node value is never accepted
  as a leaf.
- Leaves are fixed-format and fixed-size (all fields fixed width; `lock_id`
  enforced to 32 bytes upstream). This is exactly the "safe if leaves are
  fixed-size" case in the attack-class checklist.

## Single-leaf / lone-leaf promotion edge cases

- Single-leaf tree: `root == leaf` (`merkle.rs:58`, `lock_tree.rs:121`). The
  root is still a domain-tagged leaf hash, so no untagged value is ever the
  root. Empty set → `B256::ZERO` (`merkle.rs:38-42`); the contract's
  `latestRoot` would be zero and no leaf hash can be zero (keccak output),
  so nothing is claimable.
- Lone-leaf-on-odd-layer promotion (`merkle.rs:51-53`, mirrored in
  `MerkleHelper.sol:34-38` and `HypersnapBridge` via OZ) promotes a node
  without re-hashing. This does not create a leaf/node ambiguity: a promoted
  value is always itself a prior leaf hash or a prior 64-byte-preimage node
  hash; neither can be substituted for a structured leaf the contract
  re-derives.

## Cross-side agreement is pinned

Both sides compute the identical leaf preimage and the identical sorted-pair
tree, and a single shared algorithm is used:

- All Rust leaf construction routes through `lock_leaf_evm`
  (`lock_tree.rs:40`, `bridge-ceremony/src/main.rs:297,412`); the ceremony
  reuses `hypersnap_crypto::merkle::Tree` (`bridge-ceremony/src/main.rs:30,326`)
  — no divergent vendored fork. (`MerkleHelper.sol`'s header comment cites a
  `ceremony/src/merkle.rs` that does not exist; the code actually imports the
  shared crate. Stale comment, not a code path.)
- Pinned cross-side vector: `lock_leaf_evm(deadbeef…, 1, 0102…1314, 1_000_000)`
  == `946e398b9ac10b77850cfc5877dab9207e37c8622db8bbacecbbc1c997818996`,
  asserted in Rust (`bridge_payload.rs:439-443`, `lock_tree.rs:203-209`) and
  in Solidity (`contracts/test/CrossSideDigests.t.sol:172`,
  `MerkleHelper.t.sol:24`).

## Verdict

Leaf-vs-internal-node domain separation is present and correct (explicit
domain tag + fixed-length distinct preimages), so no leaf/node second-preimage
substitution forges an inclusion proof. H032 ruled out.

Note (out of scope for H032, flagged for awareness only): a *separate* leaf
encoder `lock_event::encode_lock_leaf` (`src/hyper/lock_event.rs:27-37`)
builds variable-length verkle-tree leaves with no domain prefix, but that
feeds the KZG *verkle* tree path, not the sorted-pair merkle root / bridge
`claim` path under audit here. Distinct primitive; not part of this hunt.
