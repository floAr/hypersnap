---
id: F062
attack_class: merkle-root-monotonicity
file_paths:
  - contracts/src/HypersnapBridge.sol
  - src/hyper/lock_tree.rs
  - src/hyper/runtime.rs
  - src/hyper/actor.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: low
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.90
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  note: "Zero-root sign-and-relay is the canonical empty-epoch behavior — `refresh_signed_lock_merkle_root` runs every epoch boundary with no non-empty-set check and `build_lock_tree(vec![]) == B256::ZERO` is pinned by an in-source test. The finding may understate severity (Low → Medium) since no validator bug is required to trigger the freeze."
---

# F062 — `HypersnapBridge.claim` accepts a zero merkle root as a valid `latestRoot` update

- **Attack class:** `merkle-root-monotonicity`
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\contracts\src\HypersnapBridge.sol`
- **Severity (provisional):** Low (defense-in-depth gap; requires validator-side bug or signing-key compromise for direct impact, but the Rust side confirms a zero root is **producible by the canonical path**, so the contract is one buggy signature away from an indefinite claim freeze)
- **Direct fund-loss?** No. Cannot mint to attacker.
- **Direct grief / freeze?** Yes — any **legitimately threshold-signed** "empty epoch" advance instantly invalidates every then-unclaimed leaf until a fresh non-zero root is signed.

## What the code does

`HypersnapBridge.claim` (lines 173-220) advances `latestBlock` / `latestRoot`
in one branch and re-verifies an existing root in the other:

```solidity
if (blockNumber > latestBlock) {
    bytes32 digest = keccak256(abi.encodePacked(
        DOMAIN_MERKLE_ROOT_UPDATE,
        bytes8(blockNumber),
        merkleRoot
    ));
    if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();
    latestBlock = blockNumber;
    latestRoot  = merkleRoot;          // <-- no `merkleRoot != bytes32(0)` guard
    emit RootAdvanced(blockNumber, merkleRoot);
} else {
    if (blockNumber != latestBlock || merkleRoot != latestRoot) {
        revert RootMismatch();
    }
}
```

There is no check that `merkleRoot != bytes32(0)`.

## Why the Rust side makes this exploitable in practice

`code\hypersnap\src\hyper\lock_tree.rs::build_lock_tree` explicitly returns
`B256::ZERO` for an empty input set, and there is a pinned test
(`empty_set_produces_zero_root`, line 97-101) that asserts this behaviour
is **canonical**, not a bug:

```rust
#[test]
fn empty_set_produces_zero_root() {
    let (tree, indexed) = build_lock_tree(vec![]);
    assert_eq!(tree.root, B256::ZERO);
    assert!(indexed.is_empty());
}
```

So the validator set is free to threshold-sign
`HYPERSNAP_MERKLE_ROOT_UPDATE_V1 || bytes8(N) || 0x00..0` for an "empty"
hyper-epoch with zero unclaimed locks. The contract will accept the relay
and overwrite `latestRoot` with zero.

## Impact

Once `latestRoot = 0x00..0` and `latestBlock = N` are committed:

1. Any leaf `L` that was unclaimed under the **previous** root `R_{N-1}`
   becomes immediately unclaimable: a claimant trying to use the proof
   that verified against `R_{N-1}` now lands in the `else` branch
   (`blockNumber <= latestBlock`) and is rejected with `RootMismatch`
   (their `merkleRoot` is `R_{N-1}`, not 0).
2. Any leaf `L` that the validator set *should have* re-included in the
   new tree but didn't (because they treated this as an "empty epoch")
   is unrecoverable until the validators sign a fresh non-zero root that
   re-includes `L`. The contract has no on-chain enforcement that the
   validator merkle-builder is monotone in "set of unclaimed leaves".

The fastest realistic failure mode is a **validator merkle-builder bug**
that produces an empty tree from a non-empty `RewardStore` snapshot
(e.g. column-family iteration regression, off-by-one on a hyper-block
boundary, or a hyper-fork resolution that drops the canonical snapshot).
The signing path itself is correct; the on-chain contract has no
defense-in-depth against the off-chain builder producing the wrong tree.

Note that `claim()` itself does NOT permit an attacker-controlled fake
"mint": after `latestRoot = 0`, the per-claim `MerkleProof.verifyCalldata`
check still requires `keccak256(...) == 0` for the proof to pass, which
is computationally infeasible. So this is **a freeze / grief vector**,
not a steal-funds vector.

## Suggested fix

Add a single line in the `if (blockNumber > latestBlock)` branch:

```solidity
require(merkleRoot != bytes32(0), "ZeroRoot");
// or: if (merkleRoot == bytes32(0)) revert ZeroRoot();
```

and on the Rust side, either:
- short-circuit the threshold-signing pipeline when the input set is
  empty (don't even attempt to advance the bridge for empty epochs), or
- have `Tree::build(vec![])` return a sentinel non-zero value
  (`keccak256("HYPERSNAP_EMPTY_TREE_V1")`) that the contract whitelists
  as the canonical empty-root.

Either side alone is a sufficient guard; both together is defense-in-depth.

## What this finding does NOT claim

- The block-number monotonicity itself is fine: line 188 (`blockNumber
  > latestBlock`) is strict; lines 199-201 reject any historic-block claim
  whose `(blockNumber, merkleRoot)` disagrees with the latest pair. There
  is no rewind path.
- The other `latestBlock`-gated entry points (`rotateOwner`, `proposeUpgrade`,
  `cancelUpgrade`, `pause`, `recoverERC20`) all gate on `blockNumber <=
  latestBlock revert`, which is strictly monotone. They are out of scope
  for this finding.
- The "universal" (no chain binding) shape of the merkle-root-update digest
  is intentional per the contract docstring (lines 22-26) and out of scope
  for this finding.
