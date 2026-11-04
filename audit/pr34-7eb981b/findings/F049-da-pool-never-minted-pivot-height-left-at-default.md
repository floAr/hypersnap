---
finding_id: F049
title: The node scores DA-PoW against a boundary height computed with `PIVOT_HEIGHT_0 = 0`, because `params_for` keeps the PoQ default
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.9
poc:
  path: poc/F049
  kind: build-backed
  result: 4/4
related_findings:
- F045
- F026
---
# F049 — The node scores DA-PoW against a boundary height computed with `PIVOT_HEIGHT_0 = 0`, because `params_for` keeps the PoQ default. On mainnet the pivot height is the snapchain shard-0 height (far above 25), so every validator's latency factor is 0, every DA score is 0, and the DA pool (50% of each epoch's emission, about 3.42M tokens per epoch at launch) is never minted or paid. Devnets with a shortened epoch hide the bug: there every response scores perfect latency.

> **Status (2026-11-04):** Severity **High** (validated 0.9, HAS_CAVEATS). PoC: poc/F049 (build-backed, 4/4). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity High (validated 0.9). PoC: poc/F049 (4/4; the DA pool mints 0 of 3,424,657 tokens at pivot 5,000,000).


- **Severity:** High, source-only. No theft and no consensus split: every node computes the same zero. But one of the three work markets, the one FIP §9 calls "the foundation" and the validators' main protocol income, pays nothing from epoch 1, for good. Half of forward emission is never minted (FIP: an empty market "is not minted and does not roll over"). Fixing it after launch needs a coordinated release, because the `ScoringResult` is consensus.
- **Confidence:** 0.9. The source path is short and complete. Only the exact mainnet `PIVOT_HEIGHT_0` is unmeasured, and any value ≥ 25 is enough.
- **Category:** emission-budget-cap-missing / parameter left at default (pool under-minted)
- **Specialist:** chain-economics · task H024
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/scoring.rs`, `crates/proof-of-quality/**` and `src/chain/shard0/work.rs` are new in the PR (absent at merge-base `bdef7b7`).

## Code facts

1. **The response height is stored as an absolute shard-0 height.** `da_response` accepts a response only in `[boundary_height(e), boundary_height(e) + challenge_response_window]` (`src/chain/shard0/work.rs:94-96`). It stores `txn.put_u64(answered, ctx.height)` (`work.rs:138`). `boundary_height(e) = pivot_height_0 + (e − 1)·epoch_length` (`src/chain/epoch.rs:37-40`).
2. **The scoring reader sums those absolute heights.** `da_response_block_sum_for_epoch` adds `decode_u64(v)` per answer (`src/chain/scoring.rs:263-274`).
3. **The node's scoring parameters are the PoQ defaults plus the pools, and nothing else.**
   ```rust
   pub fn params_for(epoch: u64, schedule: &Schedule) -> ScoringParams {
       let pools = schedule.pools(epoch);
       let mut params = ScoringParams::default();
       params.market_budgets = [ ... ].into_iter().collect();
       params
   }
   ```
   (`src/chain/scoring.rs:279-290`, the only `ScoringParams` built for a live result: `try_run` → `compute(&reader, epoch, now_unix, &params_for(epoch, &self.schedule))`, `scoring.rs:424`). `ScoringParams::default()` sets `pivot_height_0: 0` and `epoch_length_blocks: EPOCH_LENGTH` (`crates/proof-of-quality/src/lib.rs:356-357`). The field's own doc says the 0 "is a placeholder for tests and devnets" (`lib.rs:241-244`). A grep for `pivot_height_0 =` / `pivot_height_0:` outside tests finds no other assignment. `poq_dryrun` has no pivot flag either.
4. **The DA boundary comes from those defaults.** `evaluate_epoch` computes `boundary_height = epoch_boundary_height(params.pivot_height_0, epoch, params.epoch_length_blocks)` = `0 + (e − 1)·36_000` (`crates/proof-of-quality/src/scoring.rs:563-564`, `lib.rs:407-408`).
5. **Latency collapses to 0.** `da_score_fp`: `offset_sum = block_sum − n·boundary_height`, `avg_offset = offset_sum / n`, `latency = 1 − min(1, avg_offset / 25)` (`crates/proof-of-quality/src/da_pow.rs:37-53`). With the real boundary `B = P + (e−1)·36_000` and responses at `B + d` (`0 ≤ d ≤ 25`), `avg_offset = P + d`. For `P ≥ 25` that gives latency 0 and `da_score = answered_ratio × 0 = 0`.
6. **A zero score set mints nothing.** `compute_da_pow_rewards` inserts only `score > 0` (`da_pow.rs:80`). `allocate_proportional` returns an empty list when `Σ w = 0` (`crates/proof-of-quality/src/scoring.rs:417`). `compute` builds `rewards` from the entries and `minted = Σ rewards` (`src/chain/scoring.rs:327-342`). `apply_scoring_result` credits only those rows (`src/chain/shard0/boundary.rs:160-170`). The budget doc confirms there is no rollover: "its budget for the epoch is not minted and does not roll over" (`lib.rs:203-208`).
7. **`P` is large on mainnet.** The node takes `pivot_height` from the pivot marker (`src/node/hypersnap_main.rs:804-808`) into `Shard0Params::new(network, pivot_height)` (`shard0/mod.rs:121-124`, `hypersnap_main.rs:296-301`). FIP §17.7: `PIVOT_HEIGHT_0 = PIVOT_HEIGHT`, the snapchain shard-0 height of the pivot (spec line 2136). Snapchain mainnet shard 0 has been producing blocks for over a year, so `P` is in the millions.

## Failure path

1. Mainnet pivots at `PIVOT_HEIGHT_0 = P ≫ 25`.
2. In epoch `e`, every validator answers its 100 challenges inside the 25-block window. Each answer stores its absolute height (fact 1).
3. At `boundary(e+1) + SCORING_DELAY`, every node computes the `ScoringResult` with boundary `(e−1)·36_000`. Every validator gets `avg_offset ≈ P`, latency 0, score 0. The DA market is empty.
4. All nodes agree, so the block is valid. `minted = growth + app ≈ 50%` of `emission(e)`.
5. This repeats every epoch. With `MAINNET_RETRO_MINTED`, `E0 = 6,849,315` tokens, so the DA pool is **≈ 3,424,657 tokens per epoch** (about every 5 days) that are neither minted nor paid. Over the full schedule, about half of forward emission (≈ 975M of 1.95B tokens) is never minted.

**Devnet masking.** A devnet sets `[hypersnap] epoch_length` (`hypersnap_main.rs:302-304`), but scoring still uses 36,000. For `e ≥ 2` the scoring boundary `(e−1)·36_000` is *above* the real response heights, so `saturating_sub` gives `offset_sum = 0` and latency 1.0 for everyone. Devnet DA rewards look correct (all perfect). This is why end-to-end devnet runs would not show the bug. With the default devnet `pivot_height = 1` and the default epoch length, the distortion is only 1 block (−4% latency).

## Red-team

1. *Is `pivot_height_0` set elsewhere before scoring?* No. `params_for` is the only producer for live results (fact 3). `ScoringService` keeps `params: Shard0Params` (it has the right pivot) but passes it only to the reader, never into `ScoringParams` (`scoring.rs:385-424`).
2. *Is the stored value maybe an offset, not a height?* No. `work.rs:138` stores `ctx.height`. The project's own reader test writes raw heights (`scoring.rs:478`).
3. *Does the PoQ crate test cover it?* Only with an explicit `pivot_height_0: 1_000_000` (`crates/proof-of-quality/src/scoring.rs:961-985`, test `da_latency_uses_epoch_boundary_from_params`). It proves the crate needs the value. It does not test the node glue.
4. *Could mainnet `PIVOT_HEIGHT_0` be < 25?* Only if shard 0 started at height 0 at the pivot. It doesn't: the pivot block of shard 0 is `PIVOT_HEIGHT_0 = PIVOT_HEIGHT` on the existing snapchain chain (FIP §17.7). Even a few dozen blocks zero the score.
5. *Does it cause a halt or split?* No. It is deterministic. This rules out Critical.
6. *Maybe the DA budget gets redistributed to the other markets?* No. Each market is allocated separately (`scoring.rs:566-590`), and an empty market mints nothing.
7. *Is "not minting" harmless, since supply is only lower?* No. The FIP §9 split (50% DA) is the validator incentive. Validators would get only the 40% non-burned fee share. The PoQ DA uptime signal (a seed forfeit removes DA reward, FIP §4.9) also loses its teeth, because there is no reward left to forfeit.
8. *Already filed?* No F00x covers DA scoring. F045 is the scoring thread stall. F021 is the DA-response check. This is distinct.

## Related spec divergences (same code, Low, not filed separately)

- FIP §5.4 has `da_score = ratio × latency × uptime_factor`. §15 also gives `DA_LATENCY_WEIGHT = 0.3` / `DA_CORRECTNESS_WEIGHT = 0.7` and `CHALLENGES_PER_NODE_PER_EPOCH = 10` (spec lines 498-509, 1438-1441). The code multiplies `ratio × latency` with full weight, has no uptime factor, and uses 100 challenges (`da_pow.rs:1-16`, `shard0/mod.rs:147`, `lib.rs:352`). The PoQ copies of `da_challenges_per_epoch` and `CHALLENGE_RESPONSE_WINDOW_BLOCKS` are separate constants that currently match `Shard0Params` but are not wired to it (`da_pow.rs:24`, `lib.rs:352`).

## Fix

- `params_for` should take `&Shard0Params` and set `pivot_height_0 = p.epochs.pivot_height_0`, `epoch_length_blocks = p.epochs.epoch_length` and `da_pow_challenges_per_epoch = p.da_challenges_per_epoch`. Pass `challenge_response_window` as a parameter instead of the `CHALLENGE_RESPONSE_WINDOW_BLOCKS` constant.
- Make `ScoringParams::pivot_height_0` non-defaultable for production: no `Default`, or a constructor that requires it.
- Add a node-level regression test with a non-zero pivot and a shortened epoch: the DA market must be non-empty and sum to `pools(e).da`.
- Defense in depth: in `compute`, log (or assert in tests) when `da_answered` is non-empty but the DA market is empty.

## Files

- `src/chain/scoring.rs:263-290, 327-342, 424`
- `crates/proof-of-quality/src/lib.rs:203-208, 241-249, 351-357, 407-408`
- `crates/proof-of-quality/src/scoring.rs:417, 563-590`
- `crates/proof-of-quality/src/da_pow.rs:37-84`
- `src/chain/shard0/work.rs:94-96, 138`
- `src/chain/epoch.rs:37-40`
- `src/node/hypersnap_main.rs:296-304, 804-808`
