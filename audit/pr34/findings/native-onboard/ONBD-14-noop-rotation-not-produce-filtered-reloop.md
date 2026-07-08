# ONBD-14 — no-op rotations are not produce-filtered and can be re-looped through every block

- **Severity:** Low (griefing / resource-waste; bounded by PoW-onboarded FID ownership)
- **Status:** OPEN (new at `f4fc4af`; **not** a merge blocker)
- **Component:** `src/hyper/runtime.rs`, `src/hyper/importer.rs`, `src/hyper/mempool.rs`
- **Introduced by:** the `f4fc4af` rotation-in-tree fix — onboards received a produce-time
  re-validation-and-drop (ONBD-12) but rotations did not.
- **Corroboration:** mempool-admission lane; build-verified.

## Summary

Onboards are re-validated at produce time and dropped from the drained set if they no longer
validate (the ONBD-12 fix, `runtime.rs:5151-5160`). **Rotations get no equivalent filter** — they
are drained straight into the produced block (`runtime.rs:5168-5170`). Separately, `import_hyper_block`
calls `forget_rotation(fid)` **unconditionally** for every rotation in a block (`importer.rs:351-353`),
even when `apply_rotation_to_tree` was a deterministic no-op (tree unchanged, e.g. stale nonce —
`builder.rs:117` returns `false` without tombstoning `current`).

Consequence: a rotation for an attacker-owned FID whose apply is a permanent no-op leaves `current`
still holding the FID, so the *same* body re-passes the submit optimistic check (`runtime.rs:4124-4138`),
is re-admitted to the mempool, re-drained, re-included as a no-op, and re-forgotten — **every block**,
as long as the attacker re-gossips it. Each cycle burns one block message-slot and one import-time
ecrecover across the whole network, with no state change.

## Impact / why Low

- Bounded by **FID ownership**: the submit gate limits admitted rotations to FIDs the attacker
  actually holds (valid EIP-712 sig from `current` + `current` currently holds `fid`), one pending
  rotation per FID. Acquiring each FID requires a PoW onboarding (30-bit), so the reloop breadth is
  PoW-gated at the FID-acquisition level.
- No fork, no halt, no state corruption — the rotation is a *correct* no-op on every path; only a
  block slot + one ecrecover per owned-FID per block are wasted.
- `forget_rotation` itself is correct (removes the map entry and scrubs `insertion_order`).

## PoC (build-verified, green — characterizes the reloop)

`poc_q4_noop_rotation_can_reloop_through_mempool` (mempool.rs) drives the submit→forget→re-submit
cycle five times with a single body and zero state change; every re-admission succeeds. This is a
characterization test (documents the loop is admissible), not a security-property red test — the
"bug" is a missing efficiency guard, not a violated invariant.

## Fix direction

Give rotations the same produce-time treatment onboards got: re-evaluate `apply_rotation_to_tree`
against the current tip at produce and **drop no-op rotations** from the drained set, or make
`forget_rotation` conditional on a successful (non-no-op) apply at import so a stale body is not
silently re-admissible.

## Key locations

`runtime.rs:5151-5160` (onboard produce filter — the pattern rotations lack) ·
`runtime.rs:5168-5170` (rotations drained unfiltered) · `importer.rs:351-353` (unconditional
`forget_rotation`) · `builder.rs:103-137` (no-op apply) · `runtime.rs:4116-4142` (submit re-admits).
