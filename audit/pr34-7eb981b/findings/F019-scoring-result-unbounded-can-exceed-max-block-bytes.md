---
finding_id: F019
title: The `ScoringResult` has one entry per scored FID and goes into one fixed block with no size check
severity: critical
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F019
  kind: build-backed
  result: null
related_findings:
- F018
- F020
---
# F019 — The `ScoringResult` has one entry per scored FID and goes into one fixed block with no size check. Once it is larger than `MAX_BLOCK_BYTES`, every honest proposal at `boundary + SCORING_DELAY` is rejected, and shard 0 halts permanently.

> **Status (2026-11-04):** Severity **Critical** (validated 0.85, HAS_CAVEATS). PoC: poc/F019 (build-backed). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity **Critical** (measured). At the mainnet FID count of 3,357,387, the real `scoring::compute` gives a 28,302,824 B `ScoringResult`, and `validate_body` returns `TooLarge`; the crossover is 2,098,977 FIDs. PoC: poc/F019. The body's ~1.1M-FID arithmetic predates the measurement.


- **Category:** proposer-validator-divergence (resource limit) / consensus-liveness
- **Specialist:** shard0-ledger-state · attack class: proposer-validator-divergence · task H016
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Code facts

1. **One result, one height.** `boundary::scoring_due` gives the epoch only at `height == scoring_height(epoch)` (`shard0/boundary.rs:65-71`). `derived_system` then requires the local `ScoringResult` and pushes it as one system message (`engine.rs:622-631`). No later height can carry it instead, and it cannot be split.
2. **Its size has no limit.** `scoring::compute` (`src/chain/scoring.rs:310-350`) emits a `ScoredFid` for every FID in the universe with `trust_fp > 0 || eligibility > 0`. The universe is every IdRegistry FID plus every hyper-native FID (`registered_fids`, `scoring.rs:124-155`; `all_active_fids` returns it). Flag F0 is "app signal below `app_threshold` (100)" and F4 auto-passes (`enable_f4: false`) (`proof-of-quality/src/eligibility.rs:117-131`, `lib.rs:282-288`). So almost every FID has `eligibility > 0` and is listed, including FIDs that never cast. `rewards` and `vouches` add more entries.
3. **The proposer does not check the size.** In `execute(Mode::Propose)`, `room = max_block_bytes.saturating_sub(reserve + parent_cert + system)` (`engine.rs:747-757`). With an oversized `ScoringResult`, `room` becomes 0, user messages and watcher items are skipped, and the block is still built and proposed.
4. **The validator does check it.** `check_structure` → `validate_body` rejects `block.encoded_len() > MAX_BLOCK_BYTES` (16 MiB) (`block.rs:155-159`). Every honest proposer builds the same oversized block, because the result is deterministic. Every honest validator rejects it. Sync cannot help either, because `check_structure` runs on synced values too, and no valid block for this height exists.

## Size arithmetic (proto3 varint encoding)

Each `ScoredFid` entry costs 2 bytes (field tag and length in `ScoringResult.trust`) plus:
- `fid`: 1 + 3 bytes for a legacy FID below 2^21, or **1 + 10 bytes for a hyper-native FID (≥ 2^63)**;
- `trust_fp`: 0 bytes if zero, else 1 + 1..3;
- `eligibility`: 1 + 1.

That is about **8-12 bytes per legacy FID** and **~15 bytes per hyper-native FID**. With N legacy FIDs, the `trust` list alone is about 8N to 12N bytes. At N ≈ 1.1 × 10^6 that is roughly 9-13 MB of the 16.78 MB limit, before `rewards` (~10-15 B per paid (fid, market)) and vouch evaluations. The rest is a few MB:
- **Attacker:** about 3.5 MB / 15 B ≈ 230k hyper-native onboardings (more if mainnet is at the low end). At 2^30 hashes each, that is GPU-days of work. Onboarding is an FID-0 message with no stake while `onboarding_stake_gate` is false (`mod.rs:154-157`).
- **Organic:** FID growth alone gets there. The trust list is linear in registered FIDs, including inactive ones.

I have not measured the real mainnet FID count. The point is that the design puts an O(#FIDs) record into a fixed 16 MiB block with no fallback.

## Red-team walk

1. *Is the result chunked somewhere?* No. There is one `Sys::ScoringResult` at one height, and `apply_scoring_result` assumes it is complete: it deletes all old trust and eligibility keys first (`boundary.rs:139-147`).
2. *Do zero-score FIDs get filtered?* Only when both `trust_fp` and `eligibility` are 0. F0 and F4 make eligibility nonzero for most FIDs.
3. *Can validators skip the scoring block?* No. `Validate` requires the derived list to match exactly (`engine.rs:731-739`). A block without the result fails "fee settlements or ScoringResult differ".
4. *Gossip/transport?* `HYPERSNAP_MAX_VALUE_BYTES = MAX_BLOCK_BYTES + 1 MiB`, so transport is not the binding limit. `validate_body` is.
5. *Is it the same on all nodes, so no fork?* Yes. This is a halt, not a fork.
6. *Is it already reported?* F009 and F017 are other unbounded scans. None covers block size.

## Spec note

FIP §8.5 / §17.7 say the proposer "includes the results as `ScoringResult` records". The spec does not size them or say how they are split across blocks. §8.5 also stores trust as `u16 (0-10000)`, while the code uses `u32 trust_fp (0-1e6)`. That is a spec divergence (left to chain-economics).

## Recommendation

- Split the result across the blocks of a window, for example by FID range in `[scoring_height, scoring_height + k)`, with a per-chunk byte bound. Commit to the full result by hash, so validators can check each chunk.
- Or store only `trust_fp > 0`, or only fully eligible FIDs, and treat a missing FID as 0. Keep a hard bound and fail the build if it is exceeded, not consensus.
- Have the proposer check `block.encoded_len() <= MAX_BLOCK_BYTES` before proposing. That does not fix this deterministic case, but it turns silent rejection into a clear error.

## Evidence

- `src/chain/shard0/engine.rs:601-633, 714-757, 1038`
- `src/chain/shard0/boundary.rs:65-71, 119-150`
- `src/chain/scoring.rs:124-160, 300-350`
- `crates/proof-of-quality/src/eligibility.rs:110-131`; `crates/proof-of-quality/src/lib.rs:257-288`
- `src/chain/block.rs:11, 155-159`; `proto/definitions/hypersnap_state.proto:106-131`
