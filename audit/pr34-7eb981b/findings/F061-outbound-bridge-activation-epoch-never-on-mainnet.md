---
finding_id: F061
title: '`Shard0Params::new` sets `bridge_outbound_activation_epoch = u64::MAX` on every network, and nothing on the production path changes it'
severity: medium
status: pending-validation
related_findings:
- F050
- F007
- F012
---
# F061 — `Shard0Params::new` sets `bridge_outbound_activation_epoch = u64::MAX` on every network, and nothing on the production path changes it. On mainnet, every `TOKEN_LOCK` and every `TOKEN_ESCROW_BRIDGE` is invalid forever ("the outbound bridge is not active"). The value is in `params_hash`. The FIP defines no such gate, and the only code that sets it to an activating value is the test harness. Turning the bridge on after the pivot needs a coordinated consensus release.

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from time/defaults cross-cut 2026-11-04

- **Severity:** Medium, source-only. No funds are lost or stolen. But a core FIP feature is missing on mainnet from day one. FIP §10 says "a holder can bridge tokens from Hypersnap to Ethereum with the outbound bridge (Section 13.5)", and FIP §13.9 makes `TOKEN_ESCROW_BRIDGE` one of the two ways a previous custodian gets back escrowed tokens. A previous custodian who has no FID of their own (the usual case after selling an FID) can then reach their escrow only by bridging out, so the escrow stays frozen until a hard fork. All test coverage runs with the gate open (`test_support.rs:29`), so the suite cannot catch this. Severity drops to Low/Informational if the team confirms a deliberate staged launch with a planned activation release.
- **Confidence:** 0.65. The code path is certain: `u64::MAX`, no override, the check at the top of `check_bridge`. Whether it is unintended is not certain. It may be a deliberate "ship disabled" gate like `onboarding_stake_gate`. That gate carries a comment ("ONBD-6: the stake gate ships disabled"); this one has none, and it is not in the FIP.
- **Category:** parameter left at default / feature gate never opens on mainnet / spec divergence
- **Specialist:** cross-cut (time-and-defaults) · 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard0/{mod.rs,ledger.rs}` and `src/chain/pivot.rs` are new in the PR (absent at merge-base `bdef7b7`).
- **PoC:** None, reasoned from source and not built. Test sketch: `Shard0Params::new(FarcasterNetwork::Mainnet, 1_000_000)`, a funded migrated FID and a `TOKEN_LOCK` to chain 1 at epoch 1. Expected (bug): `Shard0Error::Invalid("the outbound bridge is not active")`. The same holds at epoch 10⁶.

## Code facts

1. **The default.** `Shard0Params::new` → `bridge_outbound_activation_epoch: u64::MAX` for every network (`src/chain/shard0/mod.rs:144`). The field has no doc comment (`mod.rs:88`).
2. **No override.** `shard0_params` copies only `epoch_length`, `scoring_delay`, `min_difficulty_bits`, `retro_minted`, `auto_deregister_threshold`, `rebalance_window` and `seed_reveal_margin` from `[hypersnap]` (`src/node/hypersnap_main.rs:296-327`). `HypersnapConfig` has no activation-epoch field (`:40-124`). Grep for `bridge_outbound_activation_epoch`: the only assignment outside `Shard0Params::new` is `p.bridge_outbound_activation_epoch = 1` in `src/chain/shard0/test_support.rs:29`.
3. **The gate.** `check_bridge` begins `if ctx.epoch < ctx.params.bridge_outbound_activation_epoch { return Err(invalid("the outbound bridge is not active")); }` (`src/chain/shard0/ledger.rs:546-554`). Both outbound paths call it: `lock` (`ledger.rs:~610-630`, TOKEN_LOCK) and `escrow_bridge` (`ledger.rs:~637-670`, TOKEN_ESCROW_BRIDGE). `ctx.epoch` is a `u64` epoch number, so `epoch < u64::MAX` always holds.
4. **Hashed.** `params_hash` includes the value (`src/chain/pivot.rs:170`), and the test `params_hash_covers_every_consensus_parameter` checks that coverage (`pivot_test.rs:345-388`). The genesis `PivotRecord` therefore commits to "never".
5. **Spec.** The in-repo FIP (lastEditedAt 2026-10-12) has no `BRIDGE_OUTBOUND_ACTIVATION*` parameter in §13.5, §13.8 or §15. The only activation epoch it defines is `QCT_ACTIVATION_EPOCH`, which is open under §18 item 5. §10 (spec line 873) and §13.9 (lines 1290-1297) describe the outbound bridge and escrow bridge-out as working features.

## Impact

- No Hypersnap-earned token (DA/Growth/App rewards, fees) can reach Ethereum. The V2 `lock_tree` only ever holds what the genesis put there. The L1 token supply stays at the retro claims (F050/F007), so the inbound bridge has nothing new to carry back.
- Escrows from custody changes (§13.9) can be released only by `TOKEN_ESCROW_CLAIM` to an FID that the previous custodian controls. A custodian without one has no way out.
- Turning it on needs every node to switch rules at the same epoch: a coordinated release with a future activation epoch. That is possible, but it is a hard fork that the FIP doesn't plan for.

## Red-team

1. *Deliberate staged launch?* Possible. Nothing in the code, the FIP, the CHANGELOG or the compose files says so, and a staged gate would normally have a config knob or a release-set epoch, not `u64::MAX` with no doc comment. The confidence stays at 0.65 for this reason.
2. *Is there another lock path that bypasses `check_bridge`?* No. `add_lock` is called only from `lock` and `escrow_bridge`, and both call `check_bridge` first (grep `add_lock(`: `ledger.rs:567, 627, 665`). QCT locks are behind their own open item.
3. *Could a devnet or testnet config enable it?* No. There is no config field. Only the test harness sets it.
4. *Is `epoch` ever `u64::MAX`?* No. The epoch is `1 + (h − P)/36_000`.
5. *Does it break consensus or liveness?* No. It is deterministic on all nodes, so Medium rather than High.
6. *Already filed?* No. F007 is about V1 retro claims stranded by the upgrade. F012 is about lock-proof roots. F050 is about the retro supply constant. None covers the outbound gate.

## Fix

- Choose the intended mainnet value: `1` (active at the pivot, as the tests assume), or a release-set epoch. Document it in FIP §13.8/§15 as `BRIDGE_OUTBOUND_ACTIVATION_EPOCH`.
- If a staged launch is intended, add a comment like the ONBD-6 one, and a release-checklist item that names the activation release.
- Add a test that builds `Shard0Params::new(Mainnet, P)` (not the `test_support` params) and asserts that a lock in some reachable epoch passes `check_bridge`.

## Files

- `src/chain/shard0/mod.rs:88, 144`
- `src/chain/shard0/ledger.rs:546-560, 567, 627, 647, 665`
- `src/chain/shard0/test_support.rs:29`
- `src/chain/pivot.rs:170`
- `src/node/hypersnap_main.rs:296-327`
- FIP §10 (line 873), §13.5, §13.9 (lines 1281-1297), §15
