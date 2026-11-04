# F049 PoC: the DA pool is never minted because `params_for` leaves `pivot_height_0` at 0

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`). Recipe: the internal validation notes, "Exact minimal build-backed PoC recipe".

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`, `CARGO_TARGET_DIR=<build-tree>/target`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/f049_poc_test.rs`, wired as `#[cfg(test)] mod f049_poc_test;` at the end of `src/chain/mod.rs`. A copy is here as `f049_poc_test.rs`. The recipe suggested `scoring.rs` `mod tests`; a separate module (as in `poc/F046`) uses the same public items (`compute`, `params_for`, `HypersnapReader::new`) and leaves `scoring.rs` untouched.
- Run script: a local helper (not included) that copies the test in, wires the module and runs cargo.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f049_poc_test -- --nocapture --test-threads=1`
- Incremental build 1 min 20 s, test run 0.9 s.
- Output: `F049-test-output.txt`.

## Fixture

- A copy of `scoring::tests::a_seed_forfeit_removes_the_da_answers_of_the_epoch`: RocksDB in a TempDir, two node key hashes `a = [1;32]`, `b = [2;32]`, `HyperValidatorSetRecord { epoch: 2, members: [a -> FID 1001, b -> FID 1002] }`, and the production `HypersnapReader::new(db, {}, params, set)`. No seed forfeit.
- 100 answers per validator (`keys::da_answered(2, hash, i)` for `i in 0..100`), each stored as an **absolute** shard-0 height, as `shard0::work::da_response` does: `a` at `boundary_height(2) + 2`, `b` at `boundary_height(2) + 20`. Both are inside the 25-block window and answer 100 of 100 challenges.
- `Shard0Params::new(Devnet, P)` with `P = 5,000,000` and the default `epoch_length = 36,000` (the mainnet and testnet value), so `boundary_height(2) = 5,036,000`.
- Scoring goes through the production `scoring::compute(&reader, 2, now, &params_for(2, &Schedule::new(0)))`, which is what `ScoringService::try_run` calls. The social universe is empty, so the DA market is the only possible source of rewards.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `f049_live_params_for_mints_no_da_pool` (headline) | The reader returns 100 answers per FID and raw height sums `100 * (b2 + 2)` / `100 * (b2 + 20)`. `params_for(2).pivot_height_0 = 0` (the PoQ default) while the node's `Shard0Params` pivot is 5,000,000, so the scoring boundary is `36,000` instead of `5,036,000`. `da_score_fp` is 0 for both validators. `compute` returns no `DataAvailability` rows and `minted = 0`, against `pools(2).da = 3,424,657.534246` tokens. `pools(3)` is a pure function of the epoch (no rollover). The mainnet schedule (`MAINNET_RETRO_MINTED`) gives a DA pool of 2,397,260.27 tokens in epoch 1 and 3,424,657.53 in epoch 2. | **RED** (pass, claim reproduced) |
| `f049_threshold_any_pivot_at_least_window` | Answers at `boundary + 0`, pivots 1, 24, 25, 26, 1,000,000. The DA market is non-empty for `P = 1` and `P = 24`, and empty for every `P >= 25`. This matches the validation's `P >= 25` bound: any real pivot (mainnet, testnet, any devnet forked off a real chain) zeroes the market. | **RED** (pass) |
| `f049_control_wired_pivot_mints_full_pool` (control 1) | Same data, `params_for(2)` with `pivot_height_0 = P` patched in. The scoring boundary equals `b2`. `da_score_fp` = 0.92 for `a` and 0.20 for `b`. `compute` gives two DA rows that sum to exactly `pools(2).da`: FID 1001 gets 2,813,111.55 and FID 1002 gets 611,545.99 tokens (0.92/1.12 of the pool, within 1 unit). | pass (control) |
| `f049_control_devnet_shape_masks_bug_and_ranking` (control 2) | The devnet harness shape (`pivot 1`, `epoch_length 20`), answers at heights 23 and 41. All heights are below the wrong scoring boundary 36,000, so `saturating_sub` gives offset 0 and latency 1.0. The DA market is non-empty and sums to the pool, and both validators get equal shares (1,712,328.77 each) although `a` answered 18 blocks faster. The devnet hides both the zero and the latency ranking. | pass (control) |

**All 4 tests pass.** The claim reproduces exactly: with a real pivot, the live scoring path pays nothing from the DA market (50% of each epoch's emission) to validators that answered every challenge on time. With the pivot threaded into `ScoringParams`, the same data mints the full pool and ranks by latency.

## What was and was not exercised

- Exercised with real code: `HypersnapReader::new`, `da_answered_counts_for_epoch` / `da_response_block_sum_for_epoch` (including `da_fid` and the forfeit check), `scoring::params_for`, `scoring::compute` -> PoQ `evaluate_epoch` -> `epoch_boundary_height` -> `da_pow::compute_da_pow_rewards` / `da_score_fp` / `allocate_proportional`, `Schedule::pools` and `MAINNET_RETRO_MINTED`.
- Source-only:
  - The DA answers are written to the DB directly with the key and value layout of `shard0::work::da_response` (`work.rs:138`). The test does not drive `DaResponse` messages through `Shard0Engine`.
  - `ScoringService::try_run` was not driven. The test calls the same `compute(&reader, epoch, now, &params_for(epoch, &self.schedule))` that `try_run` calls (`scoring.rs:424`), with a reader built from a `Shard0Params` that carries the pivot, as the service's does.
  - `apply_scoring_result` (`boundary.rs:160-170`) and the absence of a `minted` vs `emission(e)` check were not exercised. A zero `ScoringResult` simply credits no DA rows.
  - That the mainnet `pivot_height` is still `None` at 7eb981b (latent until release) is from source, as in the validation note.

## Caveats

- Latent until a pivot is configured, and deterministic: every node computes the same zero, so there is no split. The harm is a release blocker on the validator incentive, not a theft.
- The pool lost is about 3.42M tokens per epoch (the never-fixed upper bound is half of all forward emission). Missed epochs are not back-filled, because `pools(e)` has no carry state.
