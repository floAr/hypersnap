---
finding_id: F012
title: '`/hyper/v1/lock-tree/proof` returns a proof against the node''s tip lock root, not the anchored `latestLockRoot`, and V2 accepts only the'
severity: low
status: pending-validation
related_findings:
- F013
---
# F012 — `/hyper/v1/lock-tree/proof` returns a proof against the node's tip lock root, not the anchored `latestLockRoot`, and V2 accepts only the latest root. Once a newer lock exists, the proof no longer verifies

- **Severity:** Low (claim liveness and spec divergence. No funds are lost or forged.)
- **Category:** spec-divergence / liveness
- **Specialist:** shard0-ledger-state · attack class: lock-tree-root-divergence · task H010
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Summary

The tree itself is correct. The incremental MMR root (`ledger.rs:691-712`) equals the
`merkle::Tree` root at every leaf count, and every proof that tree produces passes OZ
`MerkleProof` against the root of the same size (see the internal validation notes).
The problem is which root a proof is built for:

1. **The node serves proofs for its tip state only.** `lock-tree/proof/{lock_id}`
   (`src/node/hyper_v1.rs:212-242`) scans every leaf in the live shard-0 DB (`[130][index]`)
   and builds `Tree::build(all_leaves).proof_for(i)`. It has no height or size parameter. The
   response does not say which root or height the proof is for (`lock_id_hex`, `leaf_hex`,
   `proof_hex`, `included` only). No endpoint exposes the lock count at a past height, and no
   endpoint lists the leaves. A client therefore cannot rebuild a proof for an older prefix.
2. **V2 verifies against one root only.** `claim` checks the proof against `latestLockRoot`
   (`contracts/src/HypersnapBridgeV2.sol:300-306`). `_anchor` overwrites that root
   (`:471-475`) on every `advanceRoot` (`:276-282`) and on each `advanceEpoch` above
   `latestHeight` (`:271`). Earlier anchored roots are not kept.
3. **Proofs do not carry over between tree sizes.** The tree root covers every leaf, so a
   proof built at size N verifies only against the root of size N. The PoC below shows that no
   (N, M < N, i < M) case verifies, including M = N−1.

This means a proof from the endpoint verifies on chain only while the node's tip lock count
equals the lock count at the anchored height. Both of these break that:

- **Endpoint ahead of anchor.** A lock in any block after the anchored header makes every
  proof the endpoint serves fail with `BadMerkleProof` until someone anchors the new tip, which
  costs a CERT-STARK verification of a few million gas (spec §13.4). With steady lock traffic,
  the tip lock count rarely matches the anchored count. The spec's model (*"Later claimants
  against the same root pay only for their claim"*, §13.4, spec line 1186) then does not hold:
  each claimant has to post their own anchor at the exact height their proof was built for.
- **Anchor moves past a pending claim.** Any `advanceRoot` or `advanceEpoch` to a header with
  more locks, mined before a pending `claim`, makes that claim revert. The spec expects this to
  happen during normal use (*"Usually, the first claimant after a new lock posts the
  anchor"*). Two claimants of different locks invalidate each other's proofs. A griefer who
  can get certified headers can also do it on purpose: create a lock of `min_bridge_amount`
  (1 token, recoverable on L1, `shard0/mod.rs:143`), then front-run claims with
  `advanceRoot`. Each attempt costs the griefer an anchor (a few million gas), so this is
  expensive. It is not free.

## Spec divergence

§13.5 step 4 (spec line 1205): *"The user (or any relayer) gets the Merkle proof of the leaf
against latestLockRoot."* The only proof source in the tree produces a proof against the
node's tip root, which is a different root. §13.7 "Stale root" (line 1257) answers the
staleness concern with *"A later root contains all earlier locks."* That holds for inclusion,
but a proof built for one root does not verify against a later root, so a stale proof still
fails. The code is the side that needs to change: the endpoint should serve the root the spec
names. The spec should also say that a proof is tied to one tree size.

## Why funds are not stranded (trust assumptions)

- The leaves are append-only. Nothing deletes `[130][index]`, `LockCount` or `LockPeaks`
  (grep across `src`). Their positions never change. For any anchored root R_M, the proof can
  be rebuilt from the first M leaves (PoC check D: 0 failures). The data is in every full
  node's DB. Only the API does not expose it.
- A claimant can always anchor a header whose lock count matches their proof and then claim.
  This needs a CERT-STARK for that header and a few million gas, and it is open to the race
  above.
- The engine test checks the endpoint only at the tip, right after the lock block
  (`engine_test.rs:1922-1930`). Nothing tests a proof against an anchor that lags the tip.
- No locks are possible at this commit (`bridge_outbound_activation_epoch = u64::MAX`,
  `shard0/mod.rs:144`), so this is latent.

## Red-team walk

| Hypothesis | Verdict |
|---|---|
| The relayer/claimer is expected to run its own tree off-node | No such tool is in the tree. The module doc says the endpoint serves "OpenZeppelin proofs against the `bridge_lock_root` of the state" (`hyper_v1.rs:10-12`). That is the tip, not the anchor. |
| A tip proof still verifies against an older root | Ruled out by the PoC (0/366,145). |
| A truncated tip proof can hit R_M | Only when R_M is an internal node on the leaf's path, i.e. M is a power of two and i < M. That is not a general fix, and clients would not know to try it. |
| V2 keeps old roots | No. One `latestLockRoot` slot is overwritten by `_anchor`. |
| Permanent loss | No (see trust assumptions). This is liveness, UX and gas cost. |
| Self-anchoring always works | It races any other anchor poster, and `/head` and `/lock-tree/proof` are separate reads with no shared snapshot. |

## Recommendation

Do either of these, or both:

- **Endpoint:** take `?height=` (or `?size=`) and build the proof over the leaf prefix of the
  lock count at that height. Store `LockCount` per height, or put it in the header or the
  `RootAdvanced` event. Return `root_hex`, `size` and `height` with the proof. Default to the
  height that the destination contract has anchored.
- **Contract:** keep `mapping(bytes32 => bool) anchoredLockRoot` and let `claim` take any
  anchored root. Old roots stay safe because the tree is append-only and certified, and
  `claimed[lockId]` prevents double claims. This makes proofs independent of anchor races.
  (It does not widen F004: a forged root is accepted either way.)

## Evidence

`poc/H010/lock_tree_port.py` ports `append_lock_leaf`/`lock_root_of_peaks`, `Tree::build`/
`proof_for` and OZ `processProof`. Output (`poc/H010/lock_tree_port-output.txt`):

```
A/B: n=0..300: root mismatches=0, proof failures=0
C: tip-size proof vs older anchored root: 0/366145 verify (0.00%)
C': anchor one lock behind tip: 0/8385 verify
D: prefix-rebuilt proofs vs anchored root failures=0
```
