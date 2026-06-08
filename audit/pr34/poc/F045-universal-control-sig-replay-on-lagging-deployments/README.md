# PoC / Regression Test — F045 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F045 — Universal control-plane signatures (propose/cancel-upgrade, pause, owner-rotate) replay onto lagging canonical deployments; the per-deployment watermark is not a sound cross-deployment replay defense](../../findings/F045-universal-control-sig-replay-on-lagging-deployments.md).
See also the [reachability trace](../../traces/F045-trace.md), the [validation record](../../notes/F045-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.85)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F045_UniversalSigCrossDeploymentReplay.t.sol`](F045_UniversalSigCrossDeploymentReplay.t.sol)

## What it asserts

`HypersnapBridge` deliberately makes six payloads **universal** (no chainId, no contract-address binding): `MERKLE_ROOT_UPDATE`, `OWNER_UPDATE`, `OWNER_ACCEPTANCE`, `UPGRADE`, `UPGRADE_CANCEL`, `PAUSE`. The same threshold group key signs them, and the same signature is intended to be relayed to **every** canonical deployment on every chain. The only stated defense against cross-deployment / cross-chain replay is the "strictly-monotonic 64-bit block-number watermark" (`latestBlock`).

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Drop into `contracts/test/` and run with `forge test`. Extends the existing `BridgeTest` harness. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
