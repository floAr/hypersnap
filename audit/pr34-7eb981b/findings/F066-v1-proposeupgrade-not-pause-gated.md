---
finding_id: F066
title: V1 `proposeUpgrade` is not `whenNotPaused`
severity: info
status: pending-validation
related_findings:
- F005
- F008
---
# F066 — V1 `proposeUpgrade` is not `whenNotPaused`. During a 72h pause, the owner key can still propose an upgrade. Its 48h timer runs during the pause, so the pause does not give the recovery the lockout window that the NatSpec describes. Regression of old F048 (unchanged since `cab225f`).

> **Status (2026-11-04):** Severity **Informational** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from regression pass 2026-11-04

- **Severity:** Informational, source-only. The precondition is a compromised V1 owner key. F005 shows that key can already mint without limit and make every upgrade unstoppable with one signature at `blockNumber = 2^64−1`. This finding adds nothing to that today. It matters only after F005's watermark fix, as a remaining gap in the pause design.
- **Confidence:** 0.9 (code path). The contract is byte-identical to `f4fc4af` (`git diff f4fc4af 7eb981b -- contracts/src/HypersnapBridge.sol` is empty). The old Foundry PoC (`poc/residual-5c25945-bridge/`) still applies.
- **Category:** pause scope / upgrade timelock
- **Specialist:** regression pass vs. old lineage, 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `HypersnapBridge.sol` is new in this PR. **Regression of old F048** (blocker B4 in `MERGE-BLOCKERS-f4fc4af.md`). It was not fixed.

## Code facts

1. `pause` halts `claim`, `burn` and `executeUpgrade` for `PAUSE_DURATION` = 72h (`contracts/src/HypersnapBridge.sol:357-372`). `executeUpgrade` is `whenNotPaused` (`:346`).
2. `proposeUpgrade` has no `whenNotPaused` (`:271-311`). It sets `pendingUpgradeEffectiveAt = block.timestamp + 48h` (`:307`).
3. The NatSpec says to pause first so that "cancel [has] ample time to land on every chain" (`:341-345`). It also gives the recovery sequence rotate → cancel (`:266-270`).

## Why it is minor now

A key holder who proposes at pause+71h gets `effectiveAt = pause+119h`. That is no better than proposing just after the pause expires. The real difference: honest operators who pause expect no new proposal to be pending when the pause ends, and that expectation is wrong. The pending slot also blocks an honest re-proposal (`UpgradeAlreadyPending`, `:278-280`) until the slot is cancelled.

## Fix

Add `whenNotPaused` to `proposeUpgrade`, or start the 48h timer at `max(now, pauseExpiry)`. Ship it with the F005 watermark bound.

## Files

- `contracts/src/HypersnapBridge.sol:266-311, 341-372`
