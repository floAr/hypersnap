---
id: ONBD-4
specialist: rust-crypto-primitives
attack_class: anti-sybil-replay-bypass
title: Onboarding has no per-message nonce and no consumed-POW marker; its only anti-replay guard is the custody→FID index, which custody rotation deletes, so an attacker can rotate-then-replay the same signed onboarding body to mint unbounded FIDs from a single POW solve within the anchor window
severity_initial: high
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/native_onboard.rs
validation:
  validator: crypto lane
  verdict: PLAUSIBLE
  confidence: 0.7
  hypotheses_walked: 1
---

## Summary

Onboarding messages carry **no per-onboarding nonce and no "POW/anchor
consumed" marker**. The entire anti-replay property rests on the uniqueness
check `lookup_custody_fid(custody) == None` (`native_onboard.rs:535-540`) — but
`apply_custody_rotation` intentionally **clears** that entry
(`native_onboard.rs:777`: `batch.delete(custody_to_fid_key(&current))`). So a
custody that rotates its FID away becomes "un-onboarded" again and can replay
its original, still-valid onboarding body for a fresh FID.

## Trace

1. Attacker custody `A` solves POW once, onboards → FID `X`. State:
   `custody_to_fid[A] = X`. The signed EIP-712 body is self-contained and
   remains valid while its anchor is within `ONBOARD_ANCHOR_WINDOW` (1024
   blocks; `native_onboard.rs:45`).
2. `A` rotates FID `X` to a fresh address `B` (`apply_custody_rotation`) →
   `lookup_custody_fid(A) == None`.
3. `A` **re-submits the byte-identical original onboarding body**.
   `verify_anchor` still passes (same anchor, still in window), `recover_custody`
   → `A`, `verify_pow` re-passes (pre-image `H(domain‖A‖anchor_hash‖nonce)` is
   unchanged), and the uniqueness check now passes because `A` was freed →
   **second FID `Y` issued to `A`, reusing the same POW.**
4. Repeat (rotate `Y`→`C`, replay → `Z`, …). One POW solve is amortized across
   as many FIDs as the attacker can rotate within the anchor window; a fresh
   POW per window sustains it indefinitely.

The shipped `double_onboard_same_custody_rejected` test (`native_onboard.rs:1231`)
only proves replay is blocked *while the custody still holds the FID* — it never
exercises the post-rotation window.

## Impact / Severity

Defeats the sole Phase-1 anti-sybil mechanism (POW) using legitimately-signed
messages: cost drops from "1 POW per FID" to "1 POW per 1024-block window,"
amortized across unbounded FIDs. Combined with ONBD-5 (22-bit POW is already
cheap), the FID-minting cost is negligible. **Medium–High** — the impact of
cheap hyper-native FIDs is currently bounded because they cannot become
validators (see the ONBD verified-sound note on `StoreBackedCustodyResolver`),
but the FID space and any per-FID functionality remain floodable.

## Fix

Write a permanent, rotation-immune marker on successful onboarding and check it
in `apply_onboarding`, e.g. `HyperNativeCustodyEverOnboarded[custody]`, or a
spent-POW key `PowSpent[H(custody‖anchor_hash‖nonce)]`, added to the atomic
batch at `native_onboard.rs:581-589` and consulted alongside
`lookup_custody_fid`. This decouples "does this custody currently hold a FID"
(rotation-mutable) from "has this work already been spent" (permanent). If
re-onboarding a freed custody is desired, still require a *fresh* POW by
maintaining a spent-nonce set.

## PoC

Red property test: [`poc/onbd/ONBD-4-rotate-replay/`](../../poc/onbd/ONBD-4-rotate-replay/)
— asserts that after onboard→rotate, replaying the original onboarding body is
rejected; FAILS on `573d671` (a second FID is issued from the same POW), passes
once a consumed-POW/ever-onboarded marker is enforced.
