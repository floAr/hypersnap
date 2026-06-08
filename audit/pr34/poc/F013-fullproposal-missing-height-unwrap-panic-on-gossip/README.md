# PoC / Regression Test — F013 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F013 — FullProposal gossip arm calls height().unwrap() before the shard-id guard, so a peer can crash any node with a height-less FullProposal frame](../../findings/F013-fullproposal-missing-height-unwrap-panic-on-gossip.md).
See also the [reachability trace](../../traces/F013-trace.md), the [validation record](../../notes/F013-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** WATERPROOF (0.92)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F013_fullproposal_missing_height_test.rs`](F013_fullproposal_missing_height_test.rs)

## What it asserts

On the shard-routing decode path for inbound gossip (`GossipReadActor`/`Gossip::map_gossip_bytes_to_system_message`), the `GossipMessage::FullProposal` arm calls `full_proposal.height()` on a prost-decoded, fully attacker-controlled message. `FullProposal::height()` is `self.height.clone().unwrap()`. In proto3 the `Height height = 1` field of `FullProposal` is an optional (message-typed) field that maps to `Option<Height>` in Rust, so a peer can emit a `FullProposal` frame with `height` omitted. The `.unwrap()` then panics, aborting the node — a single unauthenticated gossip frame is a remote crash / DoS.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
