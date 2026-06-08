# PoC / Regression Test — F012 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F012 — Block/ShardChunk `hash` is the consensus-committed value but is never re-derived from blake3(header) on validate/commit/read-node paths, decoupling the signed value from the header and body that actually get committed](../../findings/F012-block-hash-never-rederived-from-header-decouples-signed-value-from-committed-content.md).
See also the [reachability trace](../../traces/F012-trace.md), the [validation record](../../notes/F012-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.6)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F012_block_hash_rederivation_test.rs`](F012_block_hash_rederivation_test.rs)

## What it asserts

The Malachite consensus value for a snapchain block/shard chunk is `FullProposal::shard_hash()` = `ShardHash { shard_index, hash: block.hash }` (`proto/src/lib.rs:147-161`). Precommit signatures are computed over exactly this `ShardHash` and nothing else (`core/util.rs:147-155`, `Vote::to_sign_bytes` → `proto::Vote{ value: shard_hash }`). So the only thing 2/3 of validators ever sign is the opaque `hash` byte string.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
