---
finding_id: F021
title: Whether a DA challenge response is valid depends on the validator's local boundary checkpoint
severity: low
status: pending-validation
related_findings:
- F015
---
# F021 — Whether a DA challenge response is valid depends on the validator's local boundary checkpoint. A validator without that checkpoint rejects the whole block that carries the response.

- **Severity:** Low (shard-0 liveness inside the DA response window, plus honest validators losing DA credit). Nobody can cause it on purpose. It needs ≥ 1/3 of the voting weight to lack the checkpoint, either briefly because of a race or persistently because a checkpoint failed. It can only last `challenge_response_window` (25) blocks per epoch.
- **Category:** proposer-validator-divergence (local view feeds validity), the same pattern as F015 but for `DA_CHALLENGE_RESPONSE`
- **Specialist:** shard0-ledger-state · attack class: proposer-validator-divergence · task H016
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Code facts

- `execute` passes `inputs.da_checkpoints()` in Propose and Validate mode, and `Certified` only in sync Commit mode (`engine.rs:654-658`).
- `work::da_response` with a non-certified source calls `checkpoints.expected_leaf(epoch, shard, path)`. `None` gives `Shard0Error::Internal("no checkpoint for the challenge")` (`work.rs:120-123`). `expected_leaf` opens the on-disk checkpoint `(shard, epoch)` and returns `None` if it does not exist (`checkpoints.rs:84-91, 207-217`).
- In Propose, any message error drops the message. In Validate, any message error, `Internal` included, rejects the block (`engine.rs:838-849`).
- Shard-s checkpoints are taken when the node commits the first shard-s block that references the new shard-0 boundary (`shard_blocks.rs:555-565`). The shard-0 checkpoint is taken after the boundary block commits (`engine.rs:1137-1142`). **Both only log a failed `take`** (disk full, I/O error).
- Shard links do not cover this. `shard_tips` links to `tip − link_lag` (`views.rs:130-143`), so a validator can pass `shard_link_ok` and still not have committed the shard-s block that triggers the checkpoint, while the proposer has.

## Divergence

The proposer P and the responder R both have checkpoint `(s, e)`. A validator V either has not yet committed shard s to the triggering block (a race of a few seconds in the first blocks of the window), or its `take` failed (persistent for that epoch). V rejects every block that contains a response for shard s. If V-type validators hold ≥ 1/3 of the weight, those rounds fail. The response was popped from P's mempool and is not re-added, so R's answer can be lost. R then loses DA credit for that challenge, which feeds the `da_answered` counts in scoring.

## Red-team walk

- *Is the race real?* It is narrow. Responses can come only after R's own checkpoint exists, and validators commit shard blocks at almost the same time. The persistent case (a failed `take` on ≥ 1/3) is an operational fault. That is why the severity is Low.
- *Is it deterministic otherwise?* Yes. The checkpoint contents are the boundary state, the same on every node.
- *Does a missing checkpoint make V accept a bad response?* No. V rejects. The failure is a liveness issue only.

## Recommendation

When the checkpoint is missing, Validate should not fail. Options: treat "cannot check" as accept, relying on the ≥ 2/3 that can check, the way Commit trusts the certificate. Or require the block's shard links to be at or above the checkpoint-triggering block, so every validator that accepts the link has the checkpoint. Also, a failed `take` should be retried, or the node should halt.

## Evidence

`src/chain/shard0/engine.rs:654-658, 827-850, 1137-1142`; `src/chain/shard0/work.rs:77-137`; `src/chain/checkpoints.rs:64-91, 207-217`; `src/chain/shard_blocks.rs:550-566`; `src/chain/shard0/views.rs:84-89, 126-143`
