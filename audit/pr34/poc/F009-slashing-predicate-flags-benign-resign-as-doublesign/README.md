# PoC / Regression Test — F009 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F009 — Slashing predicate keys 'conflict' on signature-inclusive block hash; two valid threshold signatures over identical block content (sign-ceremony restart / round retry) are mis-classified as double-sign evidence and slash honest signers](../../findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md).
See also the [reachability trace](../../traces/F009-trace.md), the [validation record](../../notes/F009-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.6)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F009_slashing_conflict_on_signed_content_test.rs`](F009_slashing_conflict_on_signed_content_test.rs)

## What it asserts

The hyper slashing path's notion of "conflicting blocks" is **strictly broader** than consensus's notion of equivocation. `detect_conflicting_blocks` (`slashing.rs:52`) declares two blocks at the same `canonical_block_id` a slashable conflict whenever their `hyper_block_hash` differs. But `hyper_block_hash` (`chain.rs:25`) mixes the **non-deterministic threshold ECDSA signature bytes** (`ecdsa_signature`, and `group_address`) into the digest. The actual consensus commitment — the *signed content* — is `HyperBlockMetadata::signing_payload` (`mod.rs:403`), which does **not** contain the signature.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
