# PoC / Regression Test — F070 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F070 — Validator-registration custody-signature gate is never wired into the production ingestion path — the router is built without a CustodyResolver, so the lenient validate_event branch runs and the EIP-712 custody cross-sign is never checked, letting an attacker register arbitrary validator keys under any FID](../../findings/F070-custody-sig-gate-unwired-in-production-router.md).
See also the [reachability trace](../../traces/F070-trace.md), the [validation record](../../notes/F070-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** WATERPROOF (0.9)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F070_validator_registration_custody_gate_test.rs`](F070_validator_registration_custody_gate_test.rs)

## What it asserts

`validator_registry.rs` implements a correct, well-tested EIP-712 custody cross-signature gate (`verify_custody_signature`, required by `validate_and_check_quota` / `validate_register_with_trust`) intended to ensure a validator slot can only be registered/rotated with the authorization of the FID's on-chain custody key. **That gate is never reached in production.** Every inbound validator event flows through `HyperRuntime::submit_message`, which constructs the `HyperRouter` **without** calling `with_custody_resolver(...)`. With `custody_resolver == None`, `HyperRouter::route_inbound` takes the lenient branch `ValidatorRegistry::validate_event(&event, epoch, None)`, which skips custody-signature verification entirely (it only verifies a custody sig when a custody address is supplied). The strict `validate_and_check_quota` path — the only one that resolves a custody address and enforces the cross-sign and the per-FID 3-cap — is dead code in production.

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
