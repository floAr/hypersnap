---
id: ONBD-6
specialist: http-api-rocksdb
attack_class: ingestion-cpu-dos
title: The stake-gated onboarding arm performs a full secp256k1 ecrecover before any cheap rejection and is reachable unauthenticated with no rate-limit or size-cap; the stake gate is fully live despite a comment claiming it is a not-yet-enabled Phase-2 feature
severity_initial: medium
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/native_onboard.rs
  - src/hyper/runtime.rs
  - src/hyper/http_handler.rs
validation:
  validator: storage lane
  verdict: PLAUSIBLE
  confidence: 0.75
  hypotheses_walked: 1
---

## Summary

`validate_onboarding` (`native_onboard.rs:436-514`) orders its checks anchor →
custody-length → gate arm → ecrecover. For the **POW** arm, `verify_pow`
(`458`) rejects a bogus solution after ~1 SHA-256, *before* the ecrecover —
cheap, good. But the **stake** arm (`461-492`) performs only length /
`amount≥MIN` / `duration≥MIN` checks plus one SHA-256 commitment, then falls
straight through to `build_typed_data` + `eip712_prehash` + `recover_custody`
(**full secp256k1 ecrecover**, `504-505`). The stake-lock's existence and
binding are checked only later in `apply_onboarding` (`545-573`), i.e. *after*
the ecrecover.

An attacker sends onboarding messages carrying a real (public) recent anchor, a
20-byte custody, a `StakeProof` claiming `amount=MIN, duration=MIN` (no lock
need exist), and a garbage 65-byte signature. Each costs the attacker nothing
yet forces the validator through a full ecrecover before rejection at the
custody-mismatch (`506-511`). The `POST /messages` HTTP handler
(`http_handler.rs:190-200`) decodes and enqueues with **no auth, no size cap,
no rate limit**, returning 202; the gossip `InboundMessage` path is the same.

Note the header comment (`native_onboard.rs:16`) claims the stake gate is
"Phase 2, currently `StakeGateNotYetEnabled`", but **no such gate exists** in
`validate_onboarding` — the stake path is fully live. (This also makes ONBD-2
and ONBD-3 reachable at launch rather than dormant.)

Storage-growth is *not* a vector here: `HyperNativeCustodyToFid` requires a
solved POW or a funded lock, and `HyperOnboardingStakeLock` requires a real
signer + balance ≥ MIN — both gated. The exposure is pure CPU.

## Impact / Severity

Unauthenticated CPU-amplification DoS: cheap-to-produce messages force an
expensive ecrecover each, over both the HTTP and gossip ingress, with no
rate-limit or per-variant size cap (the F022 gap is inherited by these new
message types). **Medium.**

## Fix

Actually enforce `StakeGateNotYetEnabled` (reject the stake arm) until Phase 2,
and/or reorder so a cheap precondition (stake-lock existence, or a mandatory
POW even on the stake path) is checked before the ecrecover. Add a per-peer /
per-variant rate-limit and size cap on the onboarding message types (close the
inherited F022 gap for `NativeOnboard` / `NativeCustodyRotation` /
`OnboardingStakeLock` / `OnboardingStakeRelease`).
