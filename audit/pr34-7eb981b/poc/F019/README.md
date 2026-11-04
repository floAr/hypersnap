# F019 PoC: shard-0 `ScoringResult` exceeds `MAX_BLOCK_BYTES` at mainnet scale

Target: farcasterorg/hypersnap @ `7eb981b`. This uses the same WSL build tree as F022 (`<build-tree>`, with malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`, debug test profile.
- Source copy: `<build-tree>`. The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/f019_poc_test.rs`, wired as `#[cfg(test)] mod f019_poc_test;` in `src/chain/mod.rs` (after `f022_poc_test`). A copy is here as `f019_poc_test.rs`.
- Run:
  - `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f019 -- --nocapture --test-threads=1`. Test time is about 110 s. Output: `F019-test-output.txt`.
  - The full-scale real compute test is `#[ignore]`. Run it with `... cargo test -p hypersnap --lib f019_real_compute_at_mainnet_scale -- --ignored --nocapture`. It takes about 44 s. Output: `F019-test-output-full-compute.txt`.
- FID count: 3,357,387, which is OP mainnet `IdRegistry.idCounter()`. It comes from the coordinator addendum in the internal validation notes and was not re-measured here. The tests make no network calls.

## Key numbers

- **Eligibility mask of a zero-activity FID: `0x79`** (F0, F3, F4, F5 and F6 pass).
  - It comes from the real `classify_one(&FidMetrics::new(fid), &ScoringParams::default().eligibility, &compute_thresholds(zero cohort))`. Default thresholds give the same mask.
  - Because the mask is nonzero, the `scoring.rs:330` filter keeps every FID.
  - The validator estimated `0x31`. F3 and F6 also pass because the data-derived thresholds are 0 when the cohort is empty. Either way the mask is below 128, so it encodes in 1 byte.
- **Trust-only `ScoringResult` for FIDs 1..=3,357,387:** each entry has `trust_fp = 0` and mask `0x79`.
  - `encoded_len()` is **28,102,824 B (26.80 MiB)**. That is 1.675x `MAX_BLOCK_BYTES` (16,777,216 B).
  - This matches the coordinator's estimate of 28,102,822 B to within the 2-byte `epoch` field.
- **Real `scoring::compute` over a zero-activity universe of 3,357,387 FIDs:**
  - `trust.len()` is **3,357,387**. Of these, **50,000 have `trust_fp > 0`**: the seeds, FID ≤ `SEED_MAX_FID`.
  - `encoded_len()` is **28,302,824 B (26.99 MiB)**. The run took 30 s.
- **Sealed shard-0 block carrying it as `HypersnapSystemMessage::ScoringResult`:** 28,302,908 B, and `validate_body` returns **`Err(TooLarge(28302908))`**. The trust-only variant gives 28,102,908 B and is also `TooLarge`.
- **Proposer budget:** `MAX_BLOCK_BYTES.saturating_sub(BLOCK_RESERVE_BYTES + field_len(sys))` is **0**.
- **Crossover:** the trust-only shard-0 block is larger than 16 MiB from **N = 2,098,977** FIDs onward. Mainnet is about 1.26 M FIDs past that point.

## Tests and results

| Test | Level | What it asserts | Result |
|---|---|---|---|
| `f019_mainnet_scoring_result_exceeds_max_block_bytes` | 1 + 3 | (1) The real `classify_one` gives a nonzero mask. (2) A `proto::ScoringResult` with 3,357,387 entries has `encoded_len > MAX_BLOCK_BYTES`. (3) The proposer's `room` arithmetic comes to 0. (4) A binary search finds the crossover N. (5) A sealed shard-0 block with that system message gets `validate_body == Err(TooLarge(len))`. Control: the same block with 1,000 FIDs is `Ok(())`. | **RED** (pass, claim reproduced) |
| `f019_real_compute_keeps_every_zero_activity_fid` | 2 | The real `scoring::compute` (→ `evaluate_epoch`) runs over `InMemoryReader` universes of 10k and 100k zero-activity FIDs. It returns `trust.len() == N`, and every FID has the same mask (`0x79`). The encoded size is at least the synthetic trust-only size: 109,875 B vs 69,875 B at 10k, and 983,492 B vs 783,492 B at 100k. | **RED** |
| `f019_real_compute_at_mainnet_scale` (`#[ignore]`) | 2 + 3 | The real `scoring::compute` at N = 3,357,387 gives a 28,302,824 B result, and the shard-0 block is `TooLarge`. | **RED** |

## Level reached and caveats

- **Level reached:** the real `scoring::compute` output, at full mainnet scale and wrapped in a sealed shard-0 block, is rejected by the real `block::validate_body`.
  - `validate_body` is the first statement of `Shard0Engine::check_structure` (`engine.rs:1038`), so every validator and the sync path run this check.
  - The size and the rejection are build-backed, not estimated.
- **Not exercised:**
  - `HypersnapReader`/`registered_fids` over a real shard-0 RocksDB. The universe comes from `InMemoryReader`. The step "universe = every IdRegistry FID" rests on the source (`scoring.rs:124-155`, `pivot.rs:3`).
  - `derived_system`, `Shard0Engine::propose` and `check_structure` on a live engine at `scoring_height`, and `ScoringService`. Genesis and boundary setup is heavy, so the proposer's `room` saturation is shown only arithmetically, with the real `BLOCK_RESERVE_BYTES`. `execute(Mode::Propose)` was not run.
  - Consensus rounds and the halt itself.
- **The size is a lower bound for mainnet:**
  - `ScoringParams::default()` has no market budgets (`params_for` adds them), so `rewards` is empty.
  - `vouches` is empty, because `due_vouches` was not run.
  - Real activity adds entries with nonzero `trust_fp` (2-4 B each).
  - Every FID was given the same `effective_ts` (400 days old) and no social or app activity.
  - Real data can only add bytes. It cannot drop FIDs, because a mask of 0 would need F0, F3, F4, F5 and F6 all to fail.
- The FID count is the coordinator's on-chain reading and was not re-measured here. The test assumes FIDs are the contiguous range 1..=idCounter, which is how IdRegistry assigns them.
