# Revalidation `f4fc4af` — per-cluster detail

Fix commit `f4fc4af` ("Resolve last audit run", Cassandra Heart, 2026-07-07), direct child of `ab73681`.
Responds to ONBD-9/10/11/12 (blockers B8, B9). 12 files, +540/−130, no Solidity. See
[../../REVALIDATION-f4fc4af.md](../../REVALIDATION-f4fc4af.md) for the full report.

## Method

- Static call-site tracing on a worktree at `f4fc4af`.
- 3-lane parallel adversarial revalidation:
  - **Lane A (lifecycle/self-halt):** ONBD-11 scratch clone, four-way root determinism, no-op rotation
    determinism, ONBD-12 asymmetry.
  - **Lane B (storage/mirror):** tree↔mirror consistency, tombstone semantics, ONBD-7 readers, restart
    mirror rebuild.
  - **Lane C (mempool/DoS):** rotation admission/dedup/eviction, submit-vs-import, ecrecover DoS.
- WSL/Linux build (rustc 1.95, `--cap-lints allow`, malachite sibling) — whole crate clean.

## Fix verdicts

| Finding | Verdict | Confidence | Evidence |
|---|---|---|---|
| ONBD-9 | FIXED | 0.95 | rotation on-root, block-ordered; import re-validates + StateRootMismatch; four-way determinism PoC |
| ONBD-10 | FIXED | 0.95 | tombstone-aware read + mirror-reflects-tree; ported red PoC now green |
| ONBD-11 | FIXED | 0.95 | deep-clone scratch tree; only import_block mutates self.tree (grep-confirmed) |
| ONBD-12 | FIXED | 0.90 | produce-time drop; validate_onboarding failures permanent; verify_anchor chain-state-derived |

**B8 and B9 close.** No native-onboarding merge blockers remain. Bridge B2–B4 unchanged (untouched).

## New residuals (all Low, non-blocking)

- **ONBD-13** — mirror sync non-atomic with block persist + restart rebuilds tree-only. Independently
  surfaced by Lane A **and** Lane B. Non-consensus, self-healing (only live mirror reader is the
  optimistic onboard-dedup at `runtime.rs:4097`).
- **ONBD-14** — no-op rotations not produce-filtered; `forget_rotation` unconditional → reloopable
  block-slot/ecrecover waste, bounded by PoW-onboarded FID ownership. Char PoC
  `poc_q4_noop_rotation_can_reloop_through_mempool`.
- **ONBD-15** — rotation ecrecover (state-independent, PoW-free) runs before the block sig check.
  Minor new instance of a pre-existing class (transfers already re-validate pre-sig, more expensively).
  Char PoC `poc_q5_rotation_validate_is_not_fid_bounded` (64 FID-less rotations pass validate).

## Refuted hypotheses (mechanism-backed)

same-block mirror inconsistency · tombstone/empty-value length collision · rotation dedup censorship
(`poc_q1_junk_rotation_cannot_squat_victim_fid_slot`) · submit-vs-import fork · `forget_rotation`
stranding · rotation-amplified cross-type eviction · ONBD-7 fail-open readers driven to wrong
FID/stake bypass (readers only ever see 8-byte-or-absent authoritative values; absent is correct default).

## Build/test evidence

```
native_onboard:  19 passed  (incl. onboard_replay_must_not_resurrect_rotated_away_custody_binding,
                             onbd4_rotate_then_replay_via_tree_mints_no_second_fid — ported red→green)
builder:         onbd_four_way_rotation_apply_order_determinism ... ok
broad suite:     170 passed (runtime/importer/mempool/builder/block_index,
                             incl. verkle_tree_replays_from_block_index_on_restart)
residual PoCs:   poc_q4_noop_rotation_can_reloop_through_mempool ... ok
                 poc_q5_rotation_validate_is_not_fid_bounded ... ok
                 poc_q1_junk_rotation_cannot_squat_victim_fid_slot ... ok
```

Green PoC bundle: [../../poc/onbd/ONBD-9-10-11-rotation-in-tree-green/](../../poc/onbd/ONBD-9-10-11-rotation-in-tree-green/).
