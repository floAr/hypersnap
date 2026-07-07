# Revalidation `ab73681` — per-cluster detail & method

Fix commit [`ab73681`](https://github.com/farcasterorg/hypersnap/commit/ab73681) ("audit pass", 2026-07-07), child of `573d671`. Full memo: [../../REVALIDATION-ab73681.md](../../REVALIDATION-ab73681.md).

## Method

- **3-lane parallel adversarial revalidation** of the reworked native-onboarding subsystem:
  1. **Storage/atomicity boundary** — mirror↔tree divergence, verkle key domains, mirror-sync failure, stake-batch atomicity, next-FID split-brain.
  2. **Actor/consensus lifecycle** — speculative produce-time tree mutation, produce↔import re-validation asymmetry, double-apply idempotency, import-halt determinism, restart-replay ordering.
  3. **Deliberate-disagreement validator** — 8-hypothesis red-team of every ONBD-1..7 "fixed" verdict.
- **WSL/Linux build** (rustc 1.95, `--cap-lints allow`, malachite sibling `13bca14c` staged) of the full crate — clean in 5m25s; commit's own `native_onboard` suite 17/17 pass.
- **Three authored PoCs**, all build-verified (2 green fix-confirmations + 1 red regression).

## Fix verdicts (prior ONBD-1..7)

| # | Verdict | Confidence | Evidence |
|---|---|---|---|
| ONBD-1 | FIXED (onboarding mechanism); INCOMPLETE for rotation → ONBD-9/10 | 0.9 | on-root fold + import root-check; old assigner dead |
| ONBD-2 | FIXED | 0.95 | atomic batch, nonce-before-commit; **green PoC** |
| ONBD-3 | FIXED | 0.9 | single-batch lock+debit+nonce |
| ONBD-4 | FIXED (2nd-FID mint) | 0.9 | permanent `ever` marker; **green PoC** |
| ONBD-5 | PARTIAL (by design) | 0.85 | 30-bit floor; soft gate; governance-tunable is doc-only |
| ONBD-6 | FIXED | 0.95 | gate off in prod; cheap reject before ecrecover |
| ONBD-7 | FIXED (core) | 0.85 | 3 readers fail-closed; 2 minor readers remain |

## New findings

| # | Sev | One-line | Lane(s) | Blocker |
|---|---|---|---|---|
| ONBD-9 | High | custody rotation off-root + gossip-time apply → per-node divergence | storage S1 + validator | B8 |
| ONBD-10 | High | onboard replay resurrects rotated-away binding → revocation bypass | storage (Critical) + validator + **red PoC** | B8 |
| ONBD-11 | High | speculative produce tree pollution → unrecoverable fork/self-halt (ONBD-1-worsened) | lifecycle F1 | B9 |
| ONBD-12 | Med | aged-onboard produce/import asymmetry + no eviction → proposer stall | lifecycle F2 | — |

**Shared root cause (ONBD-9 + ONBD-10):** custody rotation mutates only the off-root RocksDB mirror, never the on-root verkle binding; `sync_onboarding_mirror_from_tree` treats the frozen tree binding as authoritative.

## Sound negatives (refuted)

Verkle key collision · next_hyper_fid split-brain · double-apply self-halt · import-time nondeterminism fork · restart-replay ordering divergence. (Citations in the lane notes / main memo Part C.)

## Minor residuals (informational)

Two remaining fail-open readers (`read_onboard_seq`, `read_onboarding_stake_lock`) · mirror-sync failure leaves tree/mirror inconsistent with no retry · ONBD-5 governance-tunability not wired.

## Merge-gate delta

B6 (ONBD-1), B7 (ONBD-2) **close**. **B8** (ONBD-9+10), **B9** (ONBD-11) **open**. Bridge B2/F049, B3/F047, B4/F048 **unchanged** (`HypersnapBridge.sol` byte-identical).

## Reproduction

WSL build tree `~/hs-ab73681` (git-init'd; target in-tree for the `pre-commit` build-script). PoC files: [../../poc/onbd/ONBD-4-tree-rotate-replay-green/](../../poc/onbd/ONBD-4-tree-rotate-replay-green/), [../../poc/onbd/ONBD-10-mirror-resurrection/](../../poc/onbd/ONBD-10-mirror-resurrection/), and the reused [../../poc/onbd/ONBD-2-stake-release-burn/](../../poc/onbd/ONBD-2-stake-release-burn/).
