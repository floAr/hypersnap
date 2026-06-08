---
id: F049
specialist: solidity-bridge
attack_class: upgrade-race
title: A single max-block universal signature saturates the shared watermark, permanently disabling rotateOwner/cancelUpgrade while the watermark-independent executeUpgrade still fires the pending (malicious) implementation
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
  - code/hypersnap/crates/hypersnap-crypto/src/bridge_payload.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
related_findings:
  - F045
  - F047
  - F048
relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.88
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

`HypersnapBridge` gates every *universal* control-plane ceremony
(`claim` root-update, `rotateOwner`, `proposeUpgrade`, `cancelUpgrade`, `pause`)
on a single shared 64-bit watermark `latestBlock` with the rule
"`blockNumber > latestBlock`, then `latestBlock = blockNumber`". There is **no
upper bound / sanity cap** on the signed `blockNumber` anywhere — not in the
contract, not in the Rust digest builders (`bridge_payload.rs`).

The contract's documented incident-response (L266-270) is: rotate the owner to a
fresh key `O2` (immediate, no delay), then have `O2` sign `cancelUpgrade` so "the
malicious upgrade's 48h timer never fires." That recovery path depends on
`rotateOwner` and `cancelUpgrade` still being callable. Both require
`blockNumber > latestBlock`.

A signer who can produce one universal signature with `blockNumber =
type(uint64).max` (2^64-1) sets `latestBlock = 2^64-1`. After that, **every**
universal ceremony reverts `StaleBlock` forever, because no `uint64` can be
strictly greater than `2^64-1`. `rotateOwner` is dead, `cancelUpgrade` is dead,
`claim` root advancement is dead, and re-`pause` is dead — **permanently, even
after a fresh DKG produces a clean key**.

Meanwhile `executeUpgrade()` (L346-355) reads **only** `pendingImplementation`,
`pendingUpgradeEffectiveAt`, and `pauseExpiry` — it has **no watermark
dependency, no signature, and is permissionless**. So if a pending malicious
upgrade exists, the attacker:

1. lands `proposeUpgrade(N, evilImpl, sig)` (starts 48h timer), and
2. lands `pause(2^64-1, sig)` and/or any universal payload at `2^64-1` to
   saturate the watermark — this simultaneously blocks `executeUpgrade` for the
   pause window AND **permanently disables the rotate-then-cancel recovery the
   contract relies on**, then
3. after the 72h pause auto-expires, calls the permissionless `executeUpgrade()`
   — which still fires because it never consults `latestBlock`.

The defenders can never cancel (watermark saturated) and can never rotate to a
key that could cancel (watermark saturated). The pending implementation
executes. This is a direct, total custody-loss path and a permanent brick of the
control plane.

## Where

`contracts/src/HypersnapBridge.sol`:

- Watermark is a raw `uint64 latestBlock` (L90) with no max guard.
- Saturation-capable gates (each is `blockNumber <= latestBlock` revert, then
  `latestBlock = blockNumber`, with no cap on the supplied value):
  - `rotateOwner` L235 / L255
  - `proposeUpgrade` L276 / L306
  - `cancelUpgrade` L321 / L331
  - `pause` L362 / L368
  - `claim` root-update L188 / L195
  - `recoverERC20` L399 / L411
- `executeUpgrade` L346-355: gated only by `whenNotPaused` and
  `block.timestamp >= pendingUpgradeEffectiveAt`. **No `latestBlock` read, no
  signature, `external` and permissionless.**
- `rotateOwner` does NOT clear `pendingImplementation` / `pendingUpgradeEffectiveAt`
  (L255-257), so a pending upgrade survives any rotation by construction — the
  only way to remove it is `cancelUpgrade`, which the saturation has disabled.

Rust side (`crates/hypersnap-crypto/src/bridge_payload.rs`): every digest builder
(`pause_digest` L158, `upgrade_digest` L133, `owner_update_digest` L108, etc.)
takes a raw `block_number: u64` and serializes `block_number.to_be_bytes()` with
no range check. The off-chain side imposes no ceiling either; the contract is the
sole gate and it has none.

## Attack walk (key-compromise scenario — the contract's own threat model)

The upgrade-flow doc (L266-270) explicitly scopes "a key-compromise scenario."
In that model the attacker holds the threshold key and can sign any universal
payload at any block number.

Pre-conditions: attacker holds owner key `O1`; a fresh DKG yields clean key `O2`
that defenders will rotate to.

1. Attacker signs and lands `proposeUpgrade(blockNumber = 10, evilImpl, O1sig)`.
   `pendingImplementation = evilImpl`, `effectiveAt = now + 48h`,
   `latestBlock = 10`.
2. Attacker signs and lands `pause(blockNumber = 2^64-1, O1sig)`.
   `pauseExpiry = now + 72h`, **`latestBlock = 2^64-1`**.
3. Defenders run DKG → `O2` and try the documented recovery:
   - `rotateOwner(blockNumber = X, O2, ...)` — for any `X <= 2^64-1` this reverts
     `StaleBlock(2^64-1, X)`. There is no valid `X`. **Rotation impossible.**
   - `cancelUpgrade(blockNumber = X, evilImpl, ...)` — same `StaleBlock` revert
     regardless of who signs. **Cancel impossible.**
   - re-`pause` — same. Defenders cannot even extend the pause.
4. 72h later `pauseExpiry` is in the past. Anyone (the attacker) calls
   `executeUpgrade()`. It passes `whenNotPaused` (pause expired) and
   `block.timestamp >= effectiveAt` (48h < 72h elapsed), and swaps the proxy to
   `evilImpl` via `ERC1967Utils.upgradeToAndCall`. **Total custody theft.**

The contract's L64-71 "24h guaranteed lockout window" arithmetic
(PAUSE 72h > UPGRADE 48h) is the analysis the attacker inverts: the pause is used
*by the attacker* not to protect but to (a) run out the clock cheaply and (b)
saturate the watermark in the same step. Even ignoring the pause, step 2's
saturation alone permanently kills the rotate/cancel recovery; the pending
upgrade then executes on its own 48h timer.

## Lower-bound variant (no pending upgrade)

Even with no malicious upgrade, a single `pause(2^64-1)` (or root-update at
`2^64-1` via the `claim` path) permanently bricks the entire control plane:
the owner can never be rotated, the root can never be advanced again (freezing
all future inbound claims), and the bridge can never be re-paused or recovered.
This is an unrecoverable denial-of-service of the bridge with one signature.

## Why existing mitigations do not close it

- **Monotonic watermark:** the very mechanism abused. Monotonicity guarantees the
  counter can only go up; the absence of a cap lets it go up to the type max in a
  single step, after which monotonicity guarantees it can never move again.
- **Two-step owner rotation / acceptance:** irrelevant — `rotateOwner` itself is
  gated by the saturated watermark and never reaches the acceptance check.
- **Pause backstop / 72h > 48h timing:** does not help, because the recovery
  actions the timing is meant to enable (rotate + cancel) are exactly what the
  saturation disables; and `executeUpgrade` ignores the watermark entirely.
- **F045** documents *cross-deployment* replay of universal sigs (a different
  failure mode: superseded sigs surviving on lagging deployments). This finding
  is **single-deployment**: the permanent saturation/brick of the watermark
  namespace and the resulting inability to cancel a surviving pending upgrade,
  combined with `executeUpgrade`'s watermark-independence. The two are
  complementary, not duplicates.

## Impact

- Permanent, unrecoverable disablement of `rotateOwner`, `cancelUpgrade`,
  `pause`, and `claim` root-advancement via one max-block universal signature.
- When chained with a pending `proposeUpgrade`, the documented key-compromise
  recovery becomes impossible while the permissionless `executeUpgrade` still
  fires the attacker's implementation → total loss of the deployment's custody.
- Severity: high (direct custody-theft path under the contract's own stated
  threat model, plus an unconditional permanent-DoS variant).

## Recommended fix

- Bound the accepted `blockNumber` on every universal entry point to a sane
  forward window relative to a trusted reference (e.g. require
  `blockNumber <= latestBlock + MAX_BLOCK_ADVANCE`, or bind/clamp to the real
  L1 `block.number`/an oracle of the hyperchain height) so a single signature
  cannot jump the watermark to `type(uint64).max`. Apply the same bound in
  `bridge_payload.rs` so honest signers never produce out-of-range block numbers.
- Decouple the upgrade-recovery actions from the saturable namespace: gate
  `cancelUpgrade` (and ideally `rotateOwner`) on a *separate* monotonic counter,
  or allow `cancelUpgrade` by the current owner without consuming/advancing the
  shared watermark, so cancel can never be locked out by an unrelated payload.
- Consider giving `executeUpgrade` a defensive check that the current owner has
  not changed since `proposeUpgrade` (snapshot `ownerAddress` at propose time and
  require it unchanged, or require a fresh owner co-sign at execute), so a
  surviving pending upgrade cannot outlive the key that authorized it.
