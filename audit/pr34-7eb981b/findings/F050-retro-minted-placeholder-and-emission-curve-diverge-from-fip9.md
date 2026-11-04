---
finding_id: F050
title: The emission schedule implements a different monetary policy from FIP §9
severity: medium
status: pending-validation
related_findings:
- F007
- F049
---
# F050 — The emission schedule implements a different monetary policy from FIP §9. It schedules forward emission against `TOTAL_SUPPLY` with a `RETRO_MINTED` offset that the FIP never defines, instead of against `TOTAL_SUPPLY − RETROACTIVE_POOL`. The mainnet `RETRO_MINTED` is a hard-coded provisional 50M placeholder. Nothing in the code, the ceremony or the tests binds it to the real sum of `Claimed` amounts. Any mismatch is a permanent, consensus-fixed deviation from the 2B supply cap.

- **Severity:** Medium, source-only. This is a spec divergence on total supply and on the year-1 issuance. The cap is exact only if an off-chain constant is filled in correctly before release, and nothing checks that. Once the pivot runs, `RETRO_MINTED` is in `params_hash` and drives every `ScoringResult`, so a correction needs a hard fork. No attacker is involved.
- **Confidence:** 0.7. The divergence from FIP text is certain. Whether the shipped value will differ from Σ `Claimed` depends on the release process, which is not in the repo.
- **Category:** emission-budget-cap-missing (supply cap depends on an unverified constant) / spec divergence
- **Specialist:** chain-economics · tasks H024, H052
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`src/chain/shard0/emission.rs` is new).
- **PoC:** Arithmetic only (below), from the constants in `emission.rs`.

## Code facts

1. **Schedule.** `E0 = TOTAL_SUPPLY / (2·EPOCHS_PER_HALVING)` with `TOTAL_SUPPLY = 2e9` tokens, so year 1 of the *schedule* is 25% of TOTAL_SUPPLY. `q, r` are where `C(q) + r = RETRO_MINTED`. Then `emission(1) = E(q) − r` and `emission(e) = E(q+e−1)` (`src/chain/shard0/emission.rs:1-17, 66-89`). Forward emission therefore sums to `≈ TOTAL_SUPPLY − RETRO_MINTED`, and the first halving moves earlier by `q` epochs.
2. **The mainnet constant is a placeholder.**
   ```rust
   /// `RETRO_MINTED` of mainnet (FIP §10.1), in micro-units. Provisional:
   /// 50,000,000 tokens until the claim close fixes the sum of the `Claimed`
   /// amounts.
   pub const MAINNET_RETRO_MINTED: u64 = 50_000_000 * 1_000_000;
   ```
   (`emission.rs:20-23`). `Shard0Params::new` uses it for mainnet (`src/chain/shard0/mod.rs:106-109, 159-163`). It is hashed into `params_hash` (`src/chain/pivot.rs:183`). The only test checks `MAINNET_RETRO_MINTED ≤ RETROACTIVE_POOL` (`emission.rs:147-157`).
3. **V1 mints retro tokens on claim.** `HypersnapBridge.claim` calls `_mint(recipient, amount)` (`contracts/src/HypersnapBridge.sol:173-219`). So Ethereum supply from the retro is Σ `Claimed`, not `RETROACTIVE_POOL`. F007 shows the V1 claim path closes at the V2 upgrade, so Σ `Claimed` is final only once `executeUpgrade` runs.
4. **No link to the real sum.** Nothing reads the `Claimed` events or a final claim total. The ceremony `build-tree` does not total the amounts (`crates/hypersnap-bridge-ceremony/src/main.rs:281-358`). The retro tools allocate a float `RETROACTIVE_POOL = 200_000_000.0` (`src/bin/retro_rewards_finalize.rs:148, 1284`) and never produce `RETRO_MINTED`.

## Spec

FIP §9 (spec lines 825-841): "`RETROACTIVE_POOL`. The retroactive distribution **minted it on Ethereum**." Also: "Forward emission: `TOTAL_SUPPLY − RETROACTIVE_POOL`". `INITIAL_EPOCH_EMISSION` "makes year 1 mint 25% of `TOTAL_SUPPLY − RETROACTIVE_POOL`", with emission from epoch 1 at `0.5^((epoch−1)/EPOCHS_PER_HALVING)`. The FIP defines neither `RETRO_MINTED` nor any `q`/`r` offset (grep `RETRO_MINTED` in the spec: 0 hits). The code comment cites "FIP §10.1", but §10.1 only says the retroactive distribution is complete.

## Numbers (from the constants)

| | FIP §9 | Code (RETRO_MINTED = 50M) |
|---|---|---|
| Epoch-1 emission | 6.164M | 4.795M (`E0 − 0.3·E0`) |
| Epochs 2.. | 6.164M | 6.849M |
| Year 1 (epochs 1-73) | 450.0M | 497.9M |
| First halving | epoch 147 | epoch 140 |
| Total forward | 1,800M | 1,950M |
| Total supply | 200M + 1,800M = 2,000M | Σ Claimed + 1,950M |

## Failure paths

- **Placeholder ships.** The release keeps 50M (the comment says it is provisional) while Σ `Claimed` = X. Total supply is then `2,000M + (X − 50M)` forever. For example, X = 120M gives 70M tokens over the hard cap. X < 50M under-issues.
- **Ordering.** `RETRO_MINTED` is compiled into the release and into `params_hash` at the pivot. Σ `Claimed` is final only after the V2 upgrade (F007). If the pivot release is cut before the upgrade executes, the constant cannot be exact.
- **Spec reader.** Anyone who audits supply from the FIP expects 1.8B forward and 450M in year 1. The chain issues about 48M more in year 1 and 150M more overall, against a different (claims-based) accounting model that the FIP does not describe.

## Red-team

1. *Is the code design actually better (it keeps the cap exact if unclaimed retro is never minted)?* Yes, as a design. But that only holds if the constant equals Σ `Claimed`. Neither the FIP nor the code makes that a checked step. The finding is about the unbound constant and the undocumented policy, not the idea.
2. *Maybe the release process fixes the constant.* Possibly. It is not in the repo, the FIP or the ceremony README. The comment says it is provisional.
3. *Could the devnet override leak to mainnet?* `[hypersnap] retro_minted` applies to any network when > 0 (`src/node/hypersnap_main.rs:311-313`). At the pivot block, a mis-set node builds a different `PivotRecord` (`params_hash`, `pivot.rs:469`), and the record must equal this node's (`engine.rs` "PivotRecord differs from this node's"). I did not verify whether a node joining after the pivot re-checks `params_hash`. If it does not, the node would diverge at the first `ScoringResult` and stall there. That is an operator error, so it is not filed.
4. *Rounding.* `emission(1)` uses `saturating_sub` and `r < E(q)` by construction. `pools()` floors three shares (`emission.rs:92-100`), so dust ≤ 2 micro-units per epoch stays unminted. That is fine and documented.
5. *Overlap with F007?* F007 is about unclaimed allocations becoming unclaimable. This finding is about the forward schedule's dependency on the claimed total. They are related: F007's upgrade timing decides when Σ `Claimed` is final.

## Fix

- Amend FIP §9/§10 to define `RETRO_MINTED = Σ Claimed` (final at the V2 upgrade) and the `q`/`r` schedule. Or implement §9 as written (`INITIAL_EPOCH_EMISSION` from `TOTAL_SUPPLY − RETROACTIVE_POOL`, from epoch 1).
- Make the value a checked release input. For example, the V2 upgrade emits or stores the final claimed total, the ceremony prints it, and the pivot tooling refuses a `MAINNET_RETRO_MINTED` that differs from it. Add a test that pins the final value with its provenance (block number, tx).
- Require the pivot release to be cut after `executeUpgrade`.

## Files

- `src/chain/shard0/emission.rs:1-23, 66-100, 147-157`
- `src/chain/shard0/mod.rs:106-109, 159-163`
- `src/chain/pivot.rs:183`
- `contracts/src/HypersnapBridge.sol:173-219`
- `docs/spec/FIP-proof-of-work-tokenization.md` lines 825-841, 862-876, 911-919
