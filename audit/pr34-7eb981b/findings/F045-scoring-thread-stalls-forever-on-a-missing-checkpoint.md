---
finding_id: F045
title: The scoring thread scores epochs strictly in order, starting at epoch 1, and never skips one
severity: medium
status: pending-validation
related_findings:
- F021
- F029
---
# F045 — The scoring thread scores epochs strictly in order, starting at epoch 1, and never skips one. If a boundary checkpoint it needs was pruned or never taken, it stops for good. The node then can never again propose or validate a block at a scoring height (`boundary(e+1) + SCORING_DELAY`). Pruning follows the shard-0 commit height, not scoring progress, so a node that syncs more than about one epoch (a new validator, or one that was offline) races the pruner. A crash between a boundary commit and its `take` has the same effect.

- **Severity:** Medium, source-only. For one node it is a permanent liveness failure (no in-code recovery; an operator would have to copy `scoring/epoch<N>.bin` from another node and trust it). For the network it becomes a recurring halt of shard 0 at every scoring height once nodes in this state hold ≥ 1/3 of the voting weight. Raise to High if validator churn makes that plausible: every validator that joins after epoch ~2 does so by syncing, and that is exactly the case that loses the race. Confidence 0.75.
- **Category:** checkpoint-input-nondeterminism / proposer-validator-divergence (local result required for validity)
- **Specialist:** pivot-genesis-epoch · task H025
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`scoring.rs`, `checkpoints.rs` and the boundary scoring are new; snapchain v0.15 has none of this).
- **PoC:** None (reasoned from source; not built). Test sketch: build a `ScoringService` over a `Checkpoints` dir. Take checkpoints for boundaries 2 and 3, call `prune_before(3)`, then `spawn`. `scoring_result(2)` stays `None` forever even though boundary 3's checkpoints exist. In an engine test, a validator built this way returns `Validity::Invalid` for every block at `scoring_height(2)`.

## Code facts

1. **The loop never skips.** `ScoringService::spawn` starts at `epoch = 1` on every process start and only advances on `Ok(Some(_))`. `Ok(None)` (a missing checkpoint) and `Err` both sleep 5 s and retry the same epoch forever (`src/chain/scoring.rs:441-451`). `try_run` returns `Ok(None)` when the shard-0 checkpoint or any data-shard checkpoint of `boundary_epoch = epoch + 1` is missing (`scoring.rs:396-411`). Results already on disk under `<data>/scoring/epoch<N>.bin` short-circuit (`scoring.rs:372-383, 397-399`; `results_dir` is always set, `src/node/hypersnap_node.rs:287-292`).
2. **Pruning ignores scoring progress.** Every 10 shard-0 heights, `commit` calls `prune_before(header.epoch)` once `height > boundary(epoch) + max(SCORING_DELAY, challenge_response_window)` (`src/chain/shard0/engine.rs:1146-1157`). `prune_before` deletes the directories of all shards (`src/chain/checkpoints.rs:112-133`). So checkpoint `(·, e+1)` lives only from `boundary(e+1)` to `boundary(e+2) + 300` shard-0 heights. This runs in sync (`Mode::Commit`) too, because it is in the shared commit path.
3. **Takes are one-shot.** The shard-0 checkpoint is taken right after the boundary block's DB commit (`engine.rs:1137-1142`). The data-shard checkpoint is taken after the first block that references the new boundary (`src/chain/shard_blocks.rs:555-565`). A failed `take` is only logged. Nothing retakes a checkpoint after a crash between the commit and the `take`, because the trigger block is already committed.
4. **A missing result invalidates every block at the scoring height.** In Propose and Validate mode, `derived_system` needs `inputs.scoring_result(epoch)`, or it returns `Internal("ScoringResult not ready")` (`engine.rs:621-629`). `Shard0Proposer` maps any error to `Validity::Invalid` (`src/chain/shard0/proposer.rs:83-89`). The proposer cannot build a block at that height either.

## Attack / failure path

- **Syncing node (the common case).** A validator that joins at epoch 30, or one that comes back after a few days offline, syncs shard 0 and the data shards. Sync passes `boundary(e+2)+300` long before the scoring thread finishes epoch `e`. PoQ over the full FID graph takes minutes per epoch, while an epoch of shard-0 sync can take much less. Data shards syncing behind shard 0 make it worse: shard 0's pruner deletes `(s, e+1)` almost as soon as the data shard creates it, and `(0, e+1)` is already gone. The thread then stops at the first such `e` and never produces a result for the current epoch.
- **Crash at a boundary.** The node exits between the boundary-block commit and `take` (or `take` fails on a full disk). The thread stops at that epoch permanently.
- **Consequence.** At `scoring_height(E−1)` in every later epoch, the node votes nil on all proposals and cannot propose. If such nodes hold ≥ 1/3 of the weight, shard 0 cannot pass that height. The data shards then stall on `MAX_EPOCH_REF_LAG`.

No attacker is needed. A peer that slows a victim's sync (or simply time) is enough.

## Red-team

1. *Long-running validators have every result on disk.* True. The bootstrap set is safe until it restarts with a lost data dir, crashes at a boundary, or is offline for more than about one epoch. Joiners are always exposed. That is why this is Medium, not High.
2. *Maybe sync is slower than scoring.* Possibly on small networks. On mainnet-sized PoQ (~1M FIDs and tens of millions of links), scoring is unlikely to beat a 36,000-block shard-0 sync. The crash case doesn't depend on speed at all.
3. *Does `synced` validation avoid the need?* `add_proposed_value` uses `check_structure` only for already-decided blocks (`proposer.rs:74-76`). Live rounds use `validate`, which needs the result.
4. *Could the thread skip to the current epoch?* No code does that. `try_run` is only called from `spawn` (grep `try_run`: `scoring.rs:443` and tests).
5. *Overlap with F021?* F021 is the DA-response check over a missing checkpoint (25-block window, recoverable next epoch). This finding is the scoring loop's permanent stall and the pruner/scorer race. The root causes differ; link them.

## Recommendations

- Prune a checkpoint only after `scoring_result(e)` exists locally and the DA window closed: gate `prune_before` on the scoring service's progress.
- Make the scoring loop skip epochs it can no longer score, and score the epoch needed next (`current_epoch − 1`) first.
- Retake a missing checkpoint on start-up when the committed tip is still inside the boundary window. Otherwise, fall back to the certified `ScoringResult` carried in the decided block (a node that cannot score can still check `minted` against the pool and adopt the result after commit).
- Add a regression test: prune before scoring, then check that the next epoch still scores.
