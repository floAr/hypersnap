# PoC / Regression Test — F028 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F028 — DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set size), so any single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations](../../findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md).
See also the [reachability trace](../../traces/F028-trace.md), the [validation record](../../notes/F028-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** critical  |  **Validation verdict:** WATERPROOF (0.9)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F028_dkls_threshold_floor_test.rs`](F028_dkls_threshold_floor_test.rs)

## What it asserts

The DKLS23 reconstruction threshold used to run the per-epoch DKG is taken verbatim from a single static config field (`DklsSupervisorInputs.threshold`) and is **never validated against the active-validator-set size** and **never floored to a BFT-safe value**. In the production node-bootstrap path that field is hard-coded:

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
