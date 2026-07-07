# ONBD-12 — Aged-onboard produce/import re-validation asymmetry + no mempool eviction → proposer stall

- **Severity:** Medium
- **Status:** OPEN (new at `ab73681`)
- **Component:** `src/hyper/runtime.rs`, `src/hyper/mempool.rs`, `src/hyper/importer.rs`, `src/hyper/native_onboard.rs`
- **Corroboration:** actor/consensus-lifecycle lane (Finding 2).

## Summary

Onboards are validated at submit and re-validated at import, but **not** re-validated at produce. An onboard that was valid at submit but ages past the anchor-freshness window before inclusion gets folded into a produced block and signed over, then is **uniformly rejected at import** (including the producer's own self-import). Because import errors out before the onboard is forgotten, and mempool eviction is capacity-only, the poison onboard is re-drained into every subsequent block indefinitely → proposer stall.

## Mechanism (code-traced)

- Submit validates against the submit-time tip (`runtime.rs:4085-4091`), then enqueues.
- `produce_envelope_with_full_anchor` does **not** re-validate — it only drains + applies (`runtime.rs:5081-5103`).
- Import re-validates every onboard via `validate_onboarding` → `verify_anchor` (`runtime.rs:4837-4850`, `native_onboard.rs:425-457`); freshness test is `tip.saturating_sub(anchor_block_height) > ONBOARD_ANCHOR_WINDOW` (=1024, `native_onboard.rs:45,435-443`).
- On import failure the whole block errors **before** `mempool.forget_onboard` (`importer.rs:333-338`), so the onboard stays pending and is re-drained next block (`mempool.rs:235-248`). Eviction is capacity-only (`evict_if_full`, `mempool.rs:202`), so under low load the poison onboard is never removed.

## Failure scenario

An onboard submitted with `anchor_block_height` near the window edge (valid at submit) is not included promptly (gossip lag / proposer churn). The tip advances so that by inclusion `tip − anchor_block_height > 1024`. `produce` folds it (mutating `self.tree` — see [ONBD-11](ONBD-11-speculative-produce-tree-pollution-selfhalt.md)) and signs a root over it; every importer, including the producer at self-import (`actor.rs:3014`), deterministically rejects with `AnchorTooOld`. The block dies; the onboard re-drains next block → the same rejection, indefinitely, for any proposer holding it. It also feeds the ONBD-11 self-halt (the produced block pollutes `self.tree`).

**Not a fork:** freshness is measured against the hyper tip height (`current_hyper_block_height` = `chain.last_height`) and committed block hashes — both identical on all nodes importing block H (all at parent height H−1). Rejection is uniform, not divergent.

## Fix direction

Re-validate onboards at produce time (drop-and-skip aged ones instead of folding+signing), and evict an onboard from the mempool when a block containing it fails import (or when it ages past the window). Combine with the ONBD-11 scratch-tree fix so a rejected produced block leaves no residue.

## Key locations

`runtime.rs:4085-4091` (submit validate) · `runtime.rs:5081-5103` (produce: no re-validate) · `runtime.rs:4837-4850` + `native_onboard.rs:425-457` (import re-validate) · `importer.rs:333-338` (forget skipped on failure) · `mempool.rs:202,235-248` (capacity-only eviction, re-drain).
