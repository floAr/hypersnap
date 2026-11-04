# F055 PoC: `build_metrics` linear `Vec::contains` per first-30-day edge

Target: farcasterorg/hypersnap @ `7eb981b`. This uses the same WSL build tree as F019/F022/F033 (`<build-tree>`, with malachite at `<malachite>`; malachite is not needed here because `proof-of-quality` has no node dependencies).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`, **release** profile (opt-level 3, as a production node binary). 16 cores, 50 GB RAM.
- Source copy: `<build-tree>`. The audit checkout was not modified, and no crate source in the build tree was modified.
- Test file: `<build-tree>/crates/proof-of-quality/tests/f055_build_metrics_timing.rs` (a crate integration test; no `mod` wiring needed). A copy is here as `f055_build_metrics_timing.rs`.
- Runner: `run_f055.sh` (copies the test into the tree and runs it). Invoke as `bash -lc 'bash poc/F055/run_f055.sh high:5000,high:20000,high:50000,uniform:20000,low:20000,absent:20000'`.
- Underlying command: `cd <build-tree> && F055_CONFIGS=... F055_N=3357387 RUSTFLAGS="--cap-lints allow" cargo test -p proof-of-quality --release --test f055_build_metrics_timing -- --nocapture --test-threads=1`.
- Outputs: `F055-test-output.txt` (the measured run, about 7 min) and `F055-smoke.txt` (first 2,000-edge smoke run).
- FID count: 3,357,387 (OP mainnet `IdRegistry.idCounter()`, as in `poc/F019`). No network calls.

## Fixture

- One `InMemoryReader` with FIDs `1..=3,357,387` (`add_fid`, `effective_ts` 400 days old), built in 0.5 s. `all_active_fids` returns a `BTreeSet`, so `fids` in `build_metrics` is the **sorted** universe and `contains` stops at the match: the cost of one edge is proportional to the target's rank.
- 1,000 source FIDs (the newest FIDs, `N-999..=N`), each given `E/1000` distinct targets. Target modes:
  - `high`: targets at the top of the FID range (rank ≈ N). This is the attacker case: new FIDs engaging with each other.
  - `uniform`: pseudo-random targets over `1..N` (mean rank ≈ N/2).
  - `low`: targets `1..T` (old, popular accounts; the scan ends almost immediately).
  - `absent`: targets outside the universe (full scan, never found).
- Each configuration runs the real `proof_of_quality::metrics::build_metrics` twice on identical edges: with `first_30d = 1` (the `fids.contains(&k)` scan runs per edge), and a control with `first_30d = 0, later = 1` (the filter short-circuits before `contains`; everything else is identical). `scan_cost = run − control`. The test asserts that every in-universe edge is kept in `outbound_first_30d` and none in the control.

## Results (N = 3,357,387)

| Mode | Edges | First-30d run | Control | Scan cost | Per edge |
|---|---|---|---|---|---|
| high | 2,000 (smoke) | 8.55 s | 3.44 s | 5.11 s | 2.56 ms |
| absent | 2,000 (smoke) | 8.27 s | 2.46 s | 5.81 s | 2.90 ms |
| high | 5,000 | 20.57 s | 3.96 s | 16.61 s | 3.32 ms |
| high | 20,000 | 85.02 s | 3.31 s | 81.71 s | 4.09 ms |
| high | 50,000 | 144.89 s | 2.89 s | 142.00 s | 2.84 ms |
| uniform | 20,000 | 29.67 s | 2.51 s | 27.16 s | 1.36 ms |
| low | 20,000 | 2.57 s | 2.51 s | 0.06 s | 0.003 ms |
| absent | 20,000 | 73.27 s | 3.08 s | 70.19 s | 3.51 ms |

- Cost is linear in the edge count (5k → 50k scales ~8.5x for 10x edges; the per-edge spread 2.8-4.1 ms is run-to-run noise on a shared WSL host). A full 3.36M-entry `u64` scan is ~27 MB, so it is memory-bandwidth bound at about 7-10 GB/s.
- Extrapolation (high/absent targets, ~2.8-4.1 ms per edge): **~0.9-1.3M edges fill the 60-minute window** (`SCORING_DELAY` 300 blocks × `BLOCK_TIME` 12 s). 1M edges ≈ 47-68 min; 10M ≈ 8-11 h; 20M ≈ 16-23 h.
- Uniform targets cost about half (1.36 ms per edge). Targets among the oldest FIDs cost ~nothing.

## Level reached and caveats

- **Level reached:** the real `build_metrics` at full mainnet universe size, release build. The quadratic term is isolated by an exact control.
- **Not exercised:**
  - `HypersnapReader` over a real data-shard checkpoint, `ScoringService`, and the shard-0 `ScoringResult not ready` halt (source-only, `src/chain/shard0/engine.rs:622-625`).
  - The other parts of `scoring::compute` (EigenTrust etc.); F019 measured the whole pipeline at 30 s with zero activity.
  - How many first-30-day edges mainnet really has, and their target-rank distribution. Honest new users mostly engage with older, low-FID accounts, which are cheap here, so the honest baseline is not established by this PoC.
  - Attacker cost of ~1.2M distinct (source, target) first-30-day reactions: reactions are fee-free (F054), but storage limits and rate limits on new FIDs were not checked.
- Production machines may scan faster or slower than this WSL host; the per-edge figure scales with memory bandwidth.
