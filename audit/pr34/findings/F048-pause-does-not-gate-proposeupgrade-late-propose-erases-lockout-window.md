---
id: F048
specialist: solidity-bridge
attack_class: pause-bypass
title: Pause does not gate proposeUpgrade, so an attacker who defers the malicious propose to land effectiveAt at/after pauseExpiry erases the documented 24h "guaranteed lockout" cushion
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: medium
related_findings:
  - F045
  - F047
  - F049
relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

`HypersnapBridge` documents a pause-vs-upgrade timing guarantee (L64-71 and
L341-345): because `PAUSE_DURATION` (72h) is strictly longer than
`UPGRADE_DELAY` (48h), a defensive `pause` is claimed to give validators a
"24h guaranteed lockout window" to land `cancelUpgrade` against a malicious
`proposeUpgrade`, and `pause` is claimed to "block all execute attempts for 48h,
giving cancel ample time to land."

That guarantee holds **only** for the specific scenario analyzed in the comment:
the malicious `proposeUpgrade` landing in the *same* `block.timestamp` as (or
earlier than) the defensive `pause`. It does **not** hold for the genuine worst
case, because **`proposeUpgrade` is not gated by `whenNotPaused`** (L271-311).
Only `claim`, `burn`, and `executeUpgrade` carry the modifier. An attacker can
therefore call `proposeUpgrade` *during* an active pause and freely choose the
propose timestamp so that the upgrade's `effectiveAt` coincides with — or
exceeds — `pauseExpiry`, collapsing the defender's cushion to zero. A single
pre-signed pause does not durably outlast a late-proposed upgrade.

## Where

`contracts/src/HypersnapBridge.sol`:

- `whenNotPaused` modifier (L165-168): reverts when `block.timestamp <
  pauseExpiry` (strict `<`; pause is inactive at `block.timestamp ==
  pauseExpiry`).
- `pause` (L361-372): sets `pauseExpiry = uint64(block.timestamp) +
  PAUSE_DURATION` (L369). One-shot, auto-expiring, no unpause.
- `proposeUpgrade` (L271-311): **no `whenNotPaused`**. Sets `effectiveAt =
  uint64(block.timestamp) + UPGRADE_DELAY` (L307). Callable while paused; the
  only structural gate is the watermark (L276) and the single-pending-slot
  guard `pendingImplementation == address(0)` (L278).
- `executeUpgrade` (L346-355): `whenNotPaused` (L346) + `block.timestamp <
  effectiveAt` (L350).
- The asserted guarantee lives in the L64-71 storage-comment block and the
  L341-345 `executeUpgrade` doc-comment.

## Why the documented arithmetic is incomplete

The comment models the worst case as `T_prop == T_pause == T`:

- `pause`  → effective on `[T, T + 72h)`
- `propose`→ execute-ready on `[T + 48h, inf)`
- execute blocked by pause until `T + 72h`; defender cushion =
  `[T + 48h, T + 72h)` = 24h. (Correct, for this ordering.)

But `T_prop` is attacker-controlled and unconstrained by the pause. Let the
defender pause at `T_pause = 0`, so `pauseExpiry = 72h`. The attacker waits
inside the pause window and proposes late:

- Attacker calls `proposeUpgrade(evilImpl)` at `T_prop = 24h` (pause still
  active; propose is not pause-gated). Then `effectiveAt = 24h + 48h = 72h`.
- `executeUpgrade` is blocked while `block.timestamp < pauseExpiry (= 72h)` and
  while `block.timestamp < effectiveAt (= 72h)`. **Both gates clear at exactly
  `block.timestamp == 72h`**, so the attacker executes the upgrade in the same
  block the pause lapses. Defender cushion = **0h**.
- If the attacker proposes at `T_prop = 24h + epsilon`, then `effectiveAt =
  72h + epsilon > pauseExpiry`; execute fires immediately once the pause
  expires, again with no protective overlap.

Generalizing: a single pause beginning at `T_pause` only blocks execute of an
upgrade whose `effectiveAt` falls before `pauseExpiry`. The attacker sets
`effectiveAt = T_prop + 48h >= pauseExpiry` by choosing
`T_prop >= pauseExpiry - 48h` (i.e. any time in the final 24h before the pause
expires, all of which is inside the pause window). The "24h guaranteed lockout"
and the "block all execute attempts for 48h" claims are both violated for this
ordering.

## Impact

The pause backstop the code relies on for upgrade incident response is not the
fire-and-forget guarantee it is documented to be. A single threshold-signed
pause does not durably hold off a malicious upgrade; the attacker, who can
relay `proposeUpgrade` permissionlessly even while paused, drives the
defender's guaranteed cancel-landing window to zero by deferring the propose
to the tail of the pause window.

The primary remedy — `cancelUpgrade`, signed by the (possibly freshly rotated)
owner — remains available and, on a current-watermark deployment, an attacker
cannot bump `latestBlock` past the defender's fresh cancel signature, so the
incident is still recoverable *if* validators produce and land a fresh cancel
in time. This is therefore a degradation of a documented defense-in-depth
guarantee (shrinking, to zero, the window the protocol promises defenders) and
a contradiction between the security comments and the implementation, rather
than unconditional standalone fund loss. It compounds with F045: on a lagging
deployment where the cancel guarantee is already void, the pause backstop being
defeatable removes the last line of defense before a UUPS implementation swap
and total custody loss. Severity: medium.

## Recommended fix

Make the pause actually halt the upgrade *pipeline*, not just the final
`executeUpgrade` step, so the documented arithmetic becomes sound:

1. Gate `proposeUpgrade` with `whenNotPaused` (and/or reset any in-flight
   pending-upgrade timer when a pause lands). If propose cannot occur during a
   pause, the same-timestamp worst case in the comment becomes the actual worst
   case and the 72h > 48h cushion holds.
2. Alternatively, on `pause`, push any existing `pendingUpgradeEffectiveAt`
   out to at least `pauseExpiry` (and forbid `effectiveAt < pauseExpiry` at
   propose time while paused), so no upgrade can become executable before the
   pause it raced is guaranteed to have expired plus the cancel margin.
3. Correct the L64-71 / L341-345 comments: a single pause only blocks upgrades
   whose `effectiveAt < pauseExpiry`; without (1)/(2), validators must be told
   they may need to re-pause (fresh signature, higher watermark) rather than
   rely on one pre-signed pause.
