# PoC / Regression Test — F025 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F025 — Committee membership is grindable via attacker-chosen validator_key because party indices are assigned by lexicographic key order against a fully predictable per-epoch committee seed](../../findings/F025-committee-index-grinding-via-attacker-chosen-validator-key.md).
See also the [reachability trace](../../traces/F025-trace.md), the [validation record](../../notes/F025-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.78)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F025_committee_index_grinding_test.rs`](F025_committee_index_grinding_test.rs)

## What it asserts

The DKLS23 signing committee for any future epoch is selectable in advance by an attacker who grinds the bytes of their `validator_key` (a 32-byte Ed25519 public key freely chosen at registration). The F036 fix made the committee *seed* non-grindable, but committee selection runs over **party indices** `1..=share_count`, and the index→validator mapping is simply the lexicographic (BTreeMap) sort order of the active validator keys. Because the per-epoch committee seed is deterministic and known far in advance, an attacker can pre-compute which indices win for a target epoch, then grind an Ed25519 keypair whose public key sorts into a winning index slot — biasing committee membership toward their own (sybil) validators.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
