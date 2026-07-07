# ONBD-9 — Custody rotation identity is off-root and applied at gossip ingestion → per-node divergence

- **Severity:** High
- **Status:** OPEN (new at `ab73681`; merge blocker **B8**, shared root cause with [ONBD-10](ONBD-10-onboard-replay-resurrects-rotated-custody.md))
- **Component:** `src/hyper/native_onboard.rs`, `src/hyper/runtime.rs`
- **Introduced by:** the ONBD-1 fix in `ab73681` — it moved *onboarding* identity on-root but left *rotation* identity off-root.
- **Corroboration:** storage-boundary lane (S1) + deliberate-disagreement validator (independent).

## Summary

The ONBD-1 fix folds native-onboarding FID assignment into the threshold-signed verkle `hyper_state_root`, so onboarding divergence between honest nodes now halts via `StateRootMismatch` instead of forking silently. **Custody rotation received no equivalent treatment.** `apply_custody_rotation` mutates only the off-root RocksDB custody→FID mirror (+ rotation nonce) and is applied inline at gossip-ingestion time — the exact per-node, arrival-order-dependent path ONBD-1 was filed against, now reintroduced for rotation.

## Mechanism (code-traced)

- `apply_custody_rotation` (`native_onboard.rs:784-878`) takes `(db, body, chain_id)` — **no `VerkleTree`**. Its only writes (`:867-877`) are `batch.delete(custody_to_fid_key(current))`, `batch.put(custody_to_fid_key(new), fid)`, `batch.put(rotation_nonce_key(fid), nonce)`. It never touches the tree and never recomputes/checks a root. (Grep-confirmed: zero tree access in the function.)
- It is invoked **inline from `submit_message`** (`runtime.rs:4109-4116`) — reached from `HyperActorEvent::InboundMessage → submit_message` (the gossip-ingestion path, `actor.rs`), which commits to the mirror immediately.
- Rotations are **never included in a block** (`import_block`'s message tuple is `locks/transfers/onboards` only, `runtime.rs:4819-4825`) and are **not persisted for replay** (`importer.rs:173-178` records only locks/transfers/onboards). There is no block fold, no root coverage, no anti-entropy reconciliation.

## Impact / failure scenario

1. Node A receives rotation gossip `R` (C1→C2, fid F) and applies it → mirror `{C2=F}`, `C1` deleted, `nonce[F]=1`.
2. Node B drops that gossip frame (or is briefly offline) → mirror stays `{C1=F}`, `nonce[F]=0`.
3. There is no block, no root fold, and no reconciliation path. The divergence is **permanent**, and because rotation is off-root it can **never** surface as a `StateRootMismatch` — no fail-closed halt. This is precisely the ONBD-1 failure mode, relocated.

**Severity walk (consumer-side).** Fund-authorization for hyper-native FIDs runs through account-store signer keys (`require_active_signer`, `runtime.rs:520-537`), **not** custody→FID; on-root import uniqueness uses the tree `ever` marker. No on-root/consensus computation reads the mirror, so this is **not** a chain fork or direct fund-loss. The residual is an **off-root identity-registry divergence** (rotation-chain state + HTTP identity queries) — rated High because it (a) silently forks the identity registry across honest nodes and (b) is the root enabler of the ONBD-10 revocation bypass.

## Fix direction

Fold custody rotation into the on-root verkle tree as a block-ordered state transition: update (and, for the old custody, delete) `onboard_custody_verkle_key` in-tree under the signed root, and move the rotation nonce into a tree domain. Then rotation is deterministic, root-covered (divergence halts instead of forking), included/persisted in blocks like onboards, and the mirror-sync reflects rotations rather than resurrecting them (closes [ONBD-10](ONBD-10-onboard-replay-resurrects-rotated-custody.md)).

## Key locations

`native_onboard.rs:784-878` (rotation, RocksDB-only) · `runtime.rs:4109-4116` (gossip-time apply) · `runtime.rs:4819-4825` (block message tuple excludes rotation) · `importer.rs:173-178` (rotation not persisted).
