---
finding_id: F055
title: build_metrics does a linear scan over every FID per first-30-day engagement edge, so about 1M planted edges push scoring past its 60-minute
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.75
poc:
  path: poc/F055
  kind: build-backed
  result: null
related_findings:
- F045
- F054
- F019
---
# F055 — `build_metrics` checks each first-30-day engagement edge against the PoQ universe with `Vec::contains`, which is a linear scan of every registered FID (over 1M on mainnet), done once per edge on one thread. Scoring cost is O(edges_30d × |FIDs|). Because reactions are free (F054) and stores no longer prune, anyone can add edges. The result is needed by `boundary + SCORING_DELAY` (300 blocks). If it isn't ready, no node can propose or validate that shard-0 height, so a slow scoring run halts shard 0 at every epoch's scoring height until it finishes.

> **Status (2026-11-04):** Severity **High** (validated 0.75, HAS_CAVEATS). PoC: poc/F055 (build-backed). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Scale note: the arithmetic below assumes about 1.1M FIDs, but F019 measured 3,357,387 on mainnet, so every estimate grows about 3×, which may cross this finding's own "raise to High if over about an hour" line. Pending a timing run.


- **Confidence:** 0.55. The quadratic path is certain. Its wall-clock impact is estimated (see the arithmetic below).
- **Category:** DoS / scoring liveness (complexity)
- **Specialist:** chain-economics · task H026
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`crates/proof-of-quality/src/metrics.rs`, `src/chain/poq_reader.rs` are new).

## Code facts

1. **`fids` is a `Vec<u64>` of the whole universe.** `let fids: Vec<u64> = reader.all_active_fids()?.into_iter().collect();` (`crates/proof-of-quality/src/metrics.rs:226`). The production universe is every IdRegister FID plus every `HyperFidCustody` FID (`src/chain/scoring.rs:124-155`).
2. **It is searched linearly once per first-30-day edge, in a serial loop.**
   ```rust
   for (&fid, m) in out.iter_mut() {           // serial
       ...
       m.outbound_first_30d = edges.map(|e| e.iter()
           .filter(|(&k, c)| k != fid && c.first_30d > 0 && fids.contains(&k))
   ```
   (`metrics.rs:277-300`). `<[u64]>::contains` is an O(n) scan. `out` is a `BTreeMap` with O(log n) `contains_key` and was right there.
3. **An edge counts as first-30-day when the source engaged in its own first 30 days.** `engagement_from` adds to `first_30d` when `ts ≤ source_eff + 30 days` (`src/chain/poq_reader.rs:356-372`). Likes, recasts and replies all count.
4. **A late result stops shard 0.** At a scoring height, `inputs.scoring_result(epoch).ok_or_else(|| Internal("ScoringResult not ready"))` (`src/chain/shard0/engine.rs:622-625`). The scoring height is `boundary(e+1) + SCORING_DELAY`, with `SCORING_DELAY = 300` (`src/chain/shard0/boundary.rs:59-66`, `src/chain/epoch.rs:8`). Every node runs the same computation, so all of them are late together.

## Arithmetic (estimate)

- With `|FIDs| ≈ 1.1M`, a found key scans about 550k entries on average, and a key not in the universe scans all 1.1M. At about 1 compare per cycle on a 3 GHz core, that is about 0.2-0.4 ms per edge.
- Honest baseline: if mainnet has about 10-20M (source, target) pairs with first-30-day engagement (each FID's onboarding month), that is about 30-120 minutes on one thread, on the order of `SCORING_DELAY` (about 1 h at 12 s blocks). **Unmeasured.**
- Attacker: new FIDs (30-bit hashcash) are inside their first 30 days by construction. Reactions cost 0 (F054). Each attacker FID that likes casts of `T` distinct authors adds `T` edges. 200 FIDs × 100k targets = 20M edges ≈ +1-2 h per epoch, using 20M free reactions spread over the data shards. These are renewable: new attacker FIDs each month.

## Red-team

1. *Does `read_per_fid` parallelize this?* No. Only the reads are parallel (`metrics.rs:231-244`). The derivation loop at `:277` is serial.
2. *Does the compiler turn `contains` into a hash lookup?* No. It is a slice scan. Maybe SIMD-unrolled, which is a constant factor and not a different complexity class.
3. *Are edges to non-universe targets filtered first?* The filter order is `k != fid`, then `first_30d > 0`, then `contains`. Non-universe targets cost a *full* scan, which is the worst case.
4. *Does late scoring just delay one block?* It delays the scoring height of every epoch until the slowest required validator finishes. Malachite rounds keep timing out, so nothing is lost permanently, unlike F045. But data shards stall at `MAX_EPOCH_REF_LAG` while shard 0 waits (see F045).
5. *Is the EigenTrust step the real bottleneck?* `compute_eigentrust` is O(30 · E_follow) with a `binary_search` index (`scoring.rs:52-111`), which is linear-ish. The only super-linear term found in the pipeline is this one.
6. *Already filed?* F045 is the scoring thread's permanent stall (checkpoint missing). F019 is result size. This is compute time. All three are distinct, so link them.

## Fix

- Replace `fids.contains(&k)` with `out.contains_key(&k)` (or use a `BTreeSet`/`HashSet` once). That makes it O(E log N).
- Add a benchmark at mainnet scale to CI, and log scoring wall time per epoch. Consider a hard budget check against `SCORING_DELAY`.

## Files

- `crates/proof-of-quality/src/metrics.rs:222-300`
- `src/chain/poq_reader.rs:356-372`
- `src/chain/scoring.rs:124-155`
- `src/chain/shard0/engine.rs:622-625`, `src/chain/shard0/boundary.rs:59-66`, `src/chain/epoch.rs:8`
