# PoC / Regression Test — F016 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F016 — F023a pre-StartDkls buffer keyed by attacker-controlled target_epoch with no global cap or stale-epoch eviction, enabling unbounded memory growth from unauthenticated gossip](../../findings/F016-pending-dkls-inbound-unbounded-epoch-keys.md).
See also the [reachability trace](../../traces/F016-trace.md), the [validation record](../../notes/F016-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** WATERPROOF (0.9)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F016_pending_dkls_inbound_bound_test.rs`](F016_pending_dkls_inbound_bound_test.rs)

## What it asserts

The F023a fix buffers `InboundDkls` round messages that arrive before the matching `StartDkls` in `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>`, keyed by `target_epoch`. The ordering assumption baked into this design is: "every buffered epoch will eventually be drained by a matching `StartDkls`." An adversary who controls gossip arrival (the threat model the buffer was written for) violates that assumption. `target_epoch` is fully attacker-controlled and the buffering path performs **no authentication**, so an attacker can allocate an unbounded number of 256-entry per-epoch buffers that are never drained — a memory-exhaustion DoS against every node on the topic.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
