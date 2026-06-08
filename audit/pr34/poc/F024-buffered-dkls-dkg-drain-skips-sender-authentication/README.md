# PoC / Regression Test — F024 (PR #34, [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9))

Regression test for [F024 — Pre-StartDkls buffered DKG drain feeds round messages to the ceremony state machine without the F018 sender/peer-id check, enabling broadcast-sender spoofing](../../findings/F024-buffered-dkls-dkg-drain-skips-sender-authentication.md).
See also the [reachability trace](../../traces/F024-trace.md), the [validation record](../../notes/F024-validation.md), and the [condensed report](../../REPORT-critical-high.md) / [full report](../../REPORT.md).

- **Severity:** high  |  **Validation verdict:** HAS_CAVEATS (0.84)
- **Audited commit:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — branch `pow`, PR #34 "proof of work (restored)"
- **Test file:** [`F024_buffered_dkls_drain_sender_auth_test.rs`](F024_buffered_dkls_drain_sender_auth_test.rs)

## What it asserts

DKLS23 DKG broadcast round messages carry a claimed `sender: u8` party index that the protocol state machine uses as a map key (`proof_commitments[sender]`, `bip_broadcasts_2to4[sender]`, `bip_broadcasts_3to4[sender]`). The codec itself does NOT authenticate this field (it is documented as an "untrusted hint" in `dkls_wire_codec.rs:256-283`). Authentication lives one layer up, in the actor: `HyperActor::check_dkls_sender_against_propagation_source` (`actor.rs:2462`) binds the claimed inner `sender` to the libp2p gossipsub originator (`message.source`, cryptographically authenticated because gossipsub runs `ValidationMode::Strict` + `MessageAuthenticity::Signed`, `network/gossip.rs:314,324`).

The test is written to assert the **secure / expected** behavior, so it **FAILS (or panics) on the vulnerable `cab225f` code and PASSES once the documented fix lands**.

## How to run / placement

Splice the `#[cfg(test)]` test fn(s) into the target module's test block named in the file header (it uses crate-internal/private items, so it must live in-crate, not under `tests/`). Run with `cargo test`. The file's header comment documents the exact target module/file and the expected pre-fix vs post-fix result.

> **STATUS: UNVERIFIED** — authored against the real APIs/signatures at `cab225f`, but not compiled or run in the audit workspace. Expect minor compile adjustments when dropped into the crate / `contracts/test/`. Note this checkout's `HEAD` is a different commit than `cab225f`, so line numbers in the header refer to the PR #34 source.
