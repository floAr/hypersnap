# PoC / Regression Test — F049 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F049 — A single max-block universal signature saturates the shared watermark, permanently disabling rotateOwner/cancelUpgrade while the watermark-independent executeUpgrade still fires the pending (malicious) implementation](../../findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md).
See also the [reachability trace](../../traces/F049-trace.md), the [validation record](../../notes/F049-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** WATERPROOF (0.88)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F049_WatermarkSaturation.t.sol`](F049_WatermarkSaturation.t.sol)

## What it asserts

`HypersnapBridge` gates every *universal* control-plane ceremony (`claim` root-update, `rotateOwner`, `proposeUpgrade`, `cancelUpgrade`, `pause`) on a single shared 64-bit watermark `latestBlock` with the rule "`blockNumber > latestBlock`, then `latestBlock = blockNumber`". There is **no upper bound / sanity cap** on the signed `blockNumber` anywhere — not in the contract, not in the Rust digest builders (`bridge_payload.rs`).

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Drop into `contracts/test/` and run with `forge test`. Extends the existing `BridgeTest` harness. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
