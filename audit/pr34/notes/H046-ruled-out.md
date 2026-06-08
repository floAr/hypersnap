---
id: H046
specialist: solidity-bridge
attack_class: merkle-root-monotonicity
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
  - code/hypersnap/src/hyper/lock_tree.rs
  - code/hypersnap/contracts/test/Invariants.t.sol
---

# H046 — Merkle-root monotonicity / stale-root rollback (ruled out)

## Scope

The hunt names `updateMerkleRoot`. There is no standalone `updateMerkleRoot`
function in `HypersnapBridge.sol`; root advancement is folded into the
permissionless `claim` entry point (lines 173-220). The question: can an old
(lower-watermark) root be re-submitted to roll the bridge back so an
already-claimed lock becomes claimable again, or a since-removed lock
reappears?

## Why the rollback is not possible

### 1. Watermark advance is strictly monotonic and atomic with the root

`claim` only advances state when `blockNumber > latestBlock` (line 188).
Inside that branch the contract verifies the owner signature over
`(DOMAIN_MERKLE_ROOT_UPDATE, bytes8(blockNumber), merkleRoot)` and then sets
`latestBlock = blockNumber; latestRoot = merkleRoot` together (lines 195-196).
There is no path that writes `latestRoot` with a block number that is not
strictly greater than the current watermark.

A stale (lower) blockNumber takes the `else` branch (lines 198-202), which
requires `blockNumber == latestBlock && merkleRoot == latestRoot` exactly, else
reverts `RootMismatch`. So a lower-watermark root can neither advance nor
overwrite state — it can only match the current state. No rewind primitive
exists.

The watermark is shared across every universal payload (`rotateOwner`,
`proposeUpgrade`, `cancelUpgrade`, `pause` all gate on
`blockNumber <= latestBlock` / `> latestBlock`), so each block number is
consumed at most once globally. This is pinned by
`Invariants.t.sol::test_watermarkMonotonicAcrossOperations` and
`test_oneBlockNumber_oneOperation`.

### 2. Old root is fully superseded

`latestRoot` is a single storage word that is overwritten on each advance
(line 196). No prior-root history is retained, so there is no stale root left
addressable for proof verification. Per-claim proofs verify against the live
`latestRoot` (line 213).

### 3. Already-claimed locks cannot be re-claimed even under a new root

`claimed[lockId]` (line 100) is a permanent nullifier set, checked first at
line 186 (`AlreadyClaimed`) and set true at line 217. It is never cleared by
any function (no reset, no rollback). Even if validators sign a *higher*-block
root that re-includes a previously-claimed lock, the claim still reverts
`AlreadyClaimed`. Replacing the root cannot resurrect a spent claim.

### 4. "Since-removed lock reappears" is an off-chain policy matter, not a
contract monotonicity defect

The Rust side (`src/hyper/lock_tree.rs`) rebuilds the full tree from the
current full lock set each epoch and threshold-signs the resulting root. If a
lock were re-included in a future root it would require a fresh
strictly-higher block number and a valid threshold signature — i.e. a
deliberate, authorized, forward-moving state transition, not a stale-root
replay. That is governed by validator policy / signing, outside the contract's
monotonicity guarantee, and outside this attack class. (The empty-set → ZERO
root behavior at `lock_tree.rs:110-114` is a separate concern; it cannot be
used to rewind on-chain state because it still needs a higher block number and
cannot un-set `claimed[]`.)

## Conclusion

The watermark is strictly increasing; the root advance is atomic with the
watermark bump; the old root is fully overwritten with no retained history; and
`claimed[]` is a permanent nullifier. There is no in-deployment path to
re-submit a lower-watermark root, nor to make an already-claimed lock claimable
again. No monotonicity / stale-root-acceptance vulnerability.

Note: the root-update digest is universal (binds no chainId / contract
address). That is a cross-deployment replay consideration belonging to the
`claim-signature-replay` class, not to in-deployment rollback monotonicity, and
is out of scope for H046.
