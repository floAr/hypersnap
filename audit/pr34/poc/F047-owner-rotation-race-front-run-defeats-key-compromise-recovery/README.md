# PoC / Regression Test — F047 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F047 — Owner rotation has no priority over other watermark-consuming actions; a compromised old owner front-runs the recovery `rotateOwner` to retain power or seize permanent ownership, defeating the documented "immediate rotation" key-compromise recovery](../../findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md).
See also the [reachability trace](../../traces/F047-trace.md), the [validation record](../../notes/F047-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.85)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F047_OwnerRotationFrontRun.t.sol`](F047_OwnerRotationFrontRun.t.sol)

## What it asserts

`rotateOwner` is an atomic one-shot rotation gated solely by the shared strictly-monotonic 64-bit watermark (`blockNumber > latestBlock`). It shares that single watermark namespace with every other owner-signed universal action (`pause`, `proposeUpgrade`, `cancelUpgrade`, the `claim` root-advancement) and with `recoverERC20`. Rotation has **no priority** over those actions and the on-chain digests are public the instant a rotation transaction enters the mempool.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Drop into `contracts/test/` and run with `forge test`. Extends the existing `BridgeTest` harness. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
