# PoC / Regression Test — F002 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F002 — F026 cross-epoch evidence slashes innocent validators who signed only one of the two epochs](../../findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md).
See also the [reachability trace](../../traces/F002-trace.md), the [validation record](../../notes/F002-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.72)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F002_cross_epoch_union_slash_test.rs`](F002_cross_epoch_union_slash_test.rs)

## What it asserts

The F026 cross-epoch slashing path (PR #34) accepts two blocks at the same `canonical_block_id` carrying *different* epoch tags (`epoch_a != epoch_b`) as a single "equivocation" conflict, then at enforcement time slashes the **union** of both blocks' signer sets — block_a's signers resolved against epoch_a's active set AND block_b's signers resolved against epoch_b's active set.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
