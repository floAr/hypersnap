# PoC / Regression Test — F035 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F035 — HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed verkle state root with no balance closure, range proof, or signature verification](../../findings/F035-hyperlockevent-mint-without-balance-closure.md).
See also the [reachability trace](../../traces/F035-trace.md), the [validation record](../../notes/F035-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.7)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F035_hyperlockevent_balance_closure_test.rs`](F035_hyperlockevent_balance_closure_test.rs)

## What it asserts

The `HyperLockEvent` bridge-lock pipeline writes a caller-supplied plaintext `amount` directly into a verkle-tree leaf with **no source-side balance enforcement of any kind**: no Pedersen balance closure, no range proof, and no verification of the proto `lock_signature` field. The verkle root containing that leaf is then threshold-signed and posted as the cross-chain `hyper_state_root`, and `lock_event.rs`'s own module doc + end-to-end test assert the L1 bridge proves inclusion of this leaf "before minting wrapped tokens."

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
