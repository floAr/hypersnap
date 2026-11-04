---
finding_id: F048
title: '`CUSTODY_MIGRATION` checks the EIP-712 signature against the classical custody that shard 0 has applied so far, not the custody on Optimism'
severity: medium
status: pending-validation
related_findings:
- F043
---
# F048 — `CUSTODY_MIGRATION` checks the EIP-712 signature against the classical custody that shard 0 has applied so far, not the custody on Optimism. An Optimism `Transfer` reaches shard 0 only after `ONCHAIN_CONFIRMATIONS` (64 blocks) plus the proposal margin. During that window the previous owner can migrate the FID. Once migrated, the earlier transfer is filed under `onchain_ignored` and never applied. A seller can sell an unmigrated FID on Optimism and keep it on Hypersnap: custody, Falcon keys, token balance, stakes and age.

- **Severity:** Medium, source-only. The victim must transact an unmigrated FID (a sale, OTC transfer, or `transferFor` marketplace trade) after the pivot. The attacker is the previous custodian acting in a window of about 2-3 minutes, or longer while shard 0 lags. Losses: the FID's identity on Hypersnap, and its token balance, which the transfer would have moved to the seller's escrow anyway. The buyer gets no Hypersnap assets and loses the FID's age and trust. Confidence 0.7.
- **Category:** custody-change-takeover (an Optimism transfer loses to a later migration by the old custody)
- **Specialist:** shard0-ledger-state · task H035
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (§16.9 migration).
- **PoC:** None. Engine-test sketch: register FID f to A, then apply block N with a `CUSTODY_MIGRATION` signed by A (EIP-712) whose `deadline` is later. In block N+1, apply the `IdRegistry Transfer A→B` with `block_timestamp` earlier than block N's time. The transfer goes to `onchain_ignored`, and `custody(f)` keeps A's Falcon key.

## Code facts

1. `custody_migration` gets `address = classical_custody_of(txn, onchain, fid)`, which is the `to` of the latest IdRegister event *applied on shard 0* (`src/chain/shard0/registry.rs:62-74, 262-271`). It then accepts the EIP-712 by that address (`registry.rs:262-276`). It never compares Optimism time with the message, and never checks for a pending transfer.
2. `apply_onchain_event`: for a migrated FID, `Transfer` and `ChangeRecovery` are written to `onchain_ignored` and not applied. That skips `custody_change` (the escrow of the balance to the old custodian), the clock reset, and the outbox to shards 1 and 2 (`registry.rs:151-176`). The decision is made by shard-0 application order, not by `event.block_timestamp` compared with `migrated_at_timestamp`.
3. On-chain events are proposed only when final in the watcher view, `ONCHAIN_CONFIRMATIONS = 64` Optimism blocks plus `PROPOSAL_MARGIN = 2` (`src/chain/watchers.rs:39-44, 316-318`). That is about 132 s at 2 s blocks, plus shard-0 inclusion latency.

## Attack path

1. After the pivot, A owns unmigrated FID f. A sells f to B on an Optimism marketplace. The Transfer A→B lands in Optimism block t.
2. Within the window, A submits `CUSTODY_MIGRATION` for f with A's EIP-712 signature (A can prepare it in advance with a long deadline) and A's own Falcon keys. Shard 0 still sees A as custody and accepts.
3. At around t+66, the Transfer reaches shard 0, finds f migrated, and is ignored for good. On Hypersnap and on shards 1 and 2 (which receive Optimism events only through the shard-0 outbox), f stays with A. On legacy snapchain, f belongs to B.

The same race lets a key thief beat a victim's Optimism recovery (`Recover` → Transfer), but a thief can migrate pre-emptively anyway. The new harm is to third-party buyers, who cannot see Hypersnap state on Optimism.

## Red-team

1. *By design, migrated FIDs ignore Optimism (§16.9).* Yes, for transfers *after* migration. Here the transfer happened first on Optimism, and the code orders by inclusion. The FIP's intent (classical custody signs the migration) is violated: at signing-acceptance time the signer was no longer the custodian.
2. *Buyers should check migration status.* They can't, because the migration happens after the sale and inside the confirmation window.
3. *Can B fix it?* No. B has no Falcon key, and Optimism events for f are ignored from then on.
4. *Window size.* At least ~66 Optimism blocks. It grows with any shard-0 or watcher lag (F015 pattern).

## Recommendations

- When applying an Optimism `Transfer` for a migrated FID with `event.block_timestamp < migrated_at_timestamp` (or `block_number` ≤ the on-chain cursor at migration), undo the migration (or put the FID in a disputed state) instead of ignoring the transfer.
- Or give migration a delay: record a pending migration, and activate it only after the Optimism head that the shard-0 cursor has passed covers the migration time plus `ONCHAIN_CONFIRMATIONS`. Cancel it if a Transfer with an earlier timestamp arrives meanwhile.
