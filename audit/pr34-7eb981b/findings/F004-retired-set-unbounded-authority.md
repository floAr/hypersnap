---
finding_id: F004
title: 'Retired validator sets keep full bridge authority forever: nothing binds `h.epoch` to `h.height`, so >2/3 of any past `set(e)` can mint'
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F004
  kind: build-backed
  result: 12/12
related_findings:
- F002
- F005
- F008
---
# F004 — Retired validator sets keep full bridge authority forever: nothing binds `h.epoch` to `h.height`, so >2/3 of any past `set(e)` can mint without limit and push `latestHeight` / `lastActionHeight` to 2^64−1, which makes a malicious upgrade unstoppable

> **Status 2026-11-04 (post-validation):** Severity High (validated, recalibration unchanged). Drop the body's argument that validator keys protect nothing after `UNSTAKING_PERIOD`; validators are stakeless. The defect is the missing `epoch(h)` binding plus uncapped watermarks. PoC: poc/F004 (Foundry, 12/12).


- **Severity:** High. The impact is Critical: unlimited SNAP mint, a permanent freeze of anchors, and an upgrade that the current validators cannot pause or cancel, so the attacker takes over the bridge. The precondition is that holders of more than 2/3 of the weight of *some past* epoch's set collude, or that their keys are compromised. That set has left the validator set, so it has no stake at risk (there is no equivocation slashing in `src`, see F002 H8). No time limit applies. This is a strictly weaker assumption than the one the spec states ("more than 2/3 of the validator weight is honest", §13.5, §13.7), and the spec does not intend it. If the program puts every ">2/3 validator collusion" scenario out of scope, rate this Medium. The design flaw still stands: the spec's mitigation of a malicious upgrade (§13.7) does not hold.
- **Category:** merkle-root-monotonicity / light-client long-range. Also a spec divergence: the node enforces `epoch(h)`, but neither the bridge nor §13.4 checks it.
- **Specialist:** solidity-bridge · task H003
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** `poc/H003/test/H003RetiredSet.t.sol`. It passes 4/4 (`poc/H003/H003-forge-output.txt`) against unmodified copies of `contracts/src` and `contracts/test/utils`, built with OZ v5.1.0.

## Summary

`_verifyCertificate` (`contracts/src/HypersnapBridgeV2.sol:458-469`) trusts the epoch that the header claims for itself. It loads `setRoot[h.epoch]` and accepts the header if that set certified it. The only check on the epoch is `setRoot[h.epoch] != 0` (`:463`). Once a root is stored, it is never removed or expired. Three things are missing:

1. **No `epoch ↔ height` binding.** The node rejects any shard-0 header with
   `header.epoch != 1 + (height − PIVOT_HEIGHT_0) / EPOCH_LENGTH` (`src/chain/block.rs:221-228`,
   `src/chain/epoch.rs:30-34`). The bridge has no `PIVOT_HEIGHT_0` or `EPOCH_LENGTH` and does not
   perform this check. So `set(1)` can certify a header that claims `epoch = 1` at any height,
   including heights in epoch 1000 or `2^64−1`.
2. **No upper bound on heights.** `advanceRoot` only needs `h.height > latestHeight`
   (`:279`), and `_applyAction` only needs `h.height > lastActionHeight` (`:491`). Both
   watermarks are `uint64`. If either is set to `type(uint64).max`, the matching entry point is
   dead for good, because no header can be higher.
3. **No retirement of old sets.** `advanceRoot`, `advanceEpoch` (anchor part) and all three
   governance actions accept a certificate of any epoch `≤ latestEpoch`. The test suite
   requires this (`contracts/test/HypersnapBridgeV2.t.sol:65-73`,
   `test_advanceRoot_oldEpochStaysValid`).

Together, these give any set that ever held power on the bridge (starting with the
`MIN_VALIDATORS = 3`-sized bootstrap set of epochs 1–2, `src/chain/epoch.rs:9`, spec §4.1) the
same authority as the current set, permanently.

## Attacker model

- **Who:** holders of more than 2/3 of the weight of `set(e)` for some epoch `e < latestEpoch`
  that has been handed off on the bridge. Every member has weight 1
  (`src/chain/shard0/validators.rs:126-137`), so this is more than 2/3 of the members by count.
  For the bootstrap set (epochs 1 and 2, from the genesis validator file) that can be 3 of 3
  or 3 of 4 operators.
- **Why plausible over time:** once those validators deregister and unstake
  (`UNSTAKING_PERIOD` is 6 epochs, spec line 1494), their consensus keys protect nothing they
  own. Nothing requires the keys to be destroyed, and the node does not slash equivocation.
  The same holds if an attacker later buys or steals the decommissioned keys. The Hypersnap
  chain itself is not at risk: honest nodes check `epoch(h)` and the current set. Only the
  bridge accepts these keys.
- **No other capability needed:** anyone can relay the result. `advanceRoot`, `proposeUpgrade`
  and `executeUpgrade` are permissionless.

## Attack paths (all shown in the PoC; bridge state: handed off 1→2→3, honestly anchored in epoch 3)

1. **Unlimited mint** (`test_retiredSet_anchorsForgedRoot_andMints`). `set(1)` signs a forged
   header `{epoch: 1, height: <any height above latestHeight>, bridge_lock_root: R}`. `R` is a
   tree with the leaf `(fakeLock, chainid, attacker, 1e30)`. The attacker then calls
   `advanceRoot` (`:276-282`) and `claim` (`:289-310`), and the contract mints `1e30` units.
2. **Permanent anchor freeze** (`test_retiredSet_freezesAnchorsForever`). The forged header
   uses `height = 2^64−1`. Afterwards `latestHeight == type(uint64).max`, so every honest
   `advanceRoot` reverts `StaleHeight`. `advanceEpoch` still hands off, but its anchor branch
   (`:271`) never fires again. `latestLockRoot` stays at the attacker's root for good, and every
   legitimate lock created afterwards cannot be claimed.
3. **Unstoppable malicious upgrade** (`test_retiredSet_unstoppableUpgrade`). `set(1)` signs an
   action header `{epoch: 1, height: 2^64−1, bridge_action_hash: bridgeActionHash(ACTION_UPGRADE, 0, evil)}`.
   `proposeUpgrade` (`:337-352`) sets `lastActionHeight = 2^64−1` (`:497`). The current set's
   `pause` and `cancelUpgrade` then both revert with `StaleAction(2^64−1, h)` (`:491`). After
   `UPGRADE_DELAY`, anyone calls `executeUpgrade` (`:380-389`) and the proxy runs the attacker's
   implementation. This breaks the §13.7 guarantee "`PAUSE_DURATION` is longer than
   `UPGRADE_DELAY`, so validators can stop a malicious upgrade". That guarantee assumes the
   honest set can always land a later action, and the `2^64−1` watermark removes that.
   Paths 2 and 3 together take the bridge over permanently, and with the upgrade in place
   nothing can recover it.

Even without the `2^64−1` trick, path 1 alone is enough: the forged header only needs to be
above `latestHeight`.

## Spec vs code

- §13.4: *"The roots of old epochs stay valid, so a proof against an old header uses the set of
  its epoch."* and *"`advanceRoot` verifies a CERT-STARK by the set of the epoch of `header`."*
  The text assumes that "the epoch of `header`" is a property of the header's position in
  the chain. Neither the spec nor the contract defines how the bridge establishes it. The code
  takes the self-declared field. §4.3 defines `epoch(h)`, and the node enforces it
  (`block.rs:221-228`). The bridge does not. **The code is the side that is wrong**, and the
  spec should state the check explicitly.
- §13.7, "Fake anchor": *"If an attacker can break it, consensus is also broken."* This is false
  for old sets. A retired `set(e)` can break the bridge without any ability to affect Hypersnap
  consensus. The spec's trust model ("more than 2/3 of the validator weight is honest",
  §13.5) silently extends to *every historical* validator set, for all time.

## Red-team (invalidation hypotheses walked)

1. *Upstream gate: does the verifier bind the epoch to the height?* No. The
   `ICertificateVerifier` inputs are `(epoch, setRoot, totalWeight, d, bitmap, proof)`
   (`ICertificateVerifier.sol:33-40`). `d` binds `height` and `block_hash`, and `block_hash`
   binds the header's own `epoch` field, but nothing relates the two. A sound verifier returns
   true for the forged certificate, because `set(1)` really signed `d`. **STANDS.**
2. *Does the node refuse to produce such headers?* Yes. That is why this needs collusion, not
   a bug in honest nodes. Equivocating signers face no consequence: no slashing exists, and
   retired members have no stake anyway. **STANDS (precondition stated).**
3. *Is a long-range attack by old sets intended by the spec?* Old roots are kept for *old
   headers* (§13.4, §13.7 "Validator set rotation during a bridge operation"). The spec never
   says that an old set may certify heights outside its epoch, and §13.7 claims fake anchors
   need consensus to be broken. **The divergence stands.** The narrower residual (a set signs
   inside its own epoch range before the next handoff is posted) is inherent to light clients
   and is out of this finding's scope.
4. *Can the current set recover?* After path 2 alone, yes: it can still `proposeUpgrade` to a
   fixed implementation, because `lastActionHeight` is separate from `latestHeight`
   (`test_action_independentOfAnchorHeight`). After path 3, no. Every action reverts, and the
   evil upgrade executes once the delay passes. **STANDS for path 3.**
5. *Is `2^64−1` really accepted (no overflow or decoder cap)?* The PoC encodes `height = 2^64−1`
   through `HypersnapProto.decodeHeader`, and it is stored. **STANDS.**
6. *Reachability today:* V2 is not deployed yet, and the outbound bridge is off on every
   network (`bridge_outbound_activation_epoch: u64::MAX`, `src/chain/shard0/mod.rs:144`).
   The forged mint (path 1) does not depend on real locks existing; the outbound switch only
   decides whether honest users also have locks frozen by path 2. All paths work as soon as V2
   is live and `latestEpoch ≥ 2` (at `latestEpoch = 1` the only set is the current one).
   **STANDS.**
7. *Duplicate of F002?* No. F002's root cause is the missing *network* binding and its
   precondition is honest key reuse across networks. F004's root cause is the missing
   *epoch/height* binding and the absence of expiry and height bounds, and it needs no second
   network. F002 impact 4 (`latestHeight` inflation) is a separate route to the same symptom.
   Fix item 1 below also caps that route at the end of the signing epoch. **Related, distinct.**
8. *PoC mechanics:* the mock verifier returns true only for `(epoch, setRoot, weight, d, bitmap)`
   tuples it issued (`test/utils/MockCertificateVerifier.sol`). The PoC issues them only for
   `SET_ROOT_1`/epoch 1, which models "only the retired set signed". The control test confirms
   that an unknown epoch is still rejected. **Sound.**

Verdict: HAS CAVEATS (trust precondition). Confidence 0.85.

## Fix

1. **Bind the epoch to the height in `_verifyCertificate`.** Add immutables `PIVOT_HEIGHT_0` and
   `EPOCH_LENGTH` (committed by the v1 owner's upgrade signature, like `SET_ROOT_EPOCH1`), and
   require `h.height >= PIVOT_HEIGHT_0 && 1 + (h.height − PIVOT_HEIGHT_0) / EPOCH_LENGTH == h.epoch`.
   A set can then only sign heights inside its own epoch. That removes the `2^64−1` trick, and
   F002 impact 4 is likewise capped at the end of the signing epoch.
2. **Retire old sets for state-moving calls.** Once the bridge has the binding, every
   `advanceEpoch(e+1)` anchors the boundary header of `e+1`, so `advanceRoot` already rejects
   older-epoch headers as stale. Governance has its own watermark, so also require
   `h.epoch + 1 >= latestEpoch` (or `h.height >= boundaryHeight(latestEpoch − 1)`) in
   `_applyAction`. Otherwise a retired set can still land an action inside its own epoch range
   whenever no later action has been applied.
3. **`advanceEpoch` hardening:** require `h.height == boundaryHeight(e)` and reject
   `r.nextSetRoot == 0` or `r.nextTotalWeight == 0`. These values are not reachable from an
   honest node (deregistration enforces `MIN_VALIDATORS`, `validators.rs:284-292`; an empty
   `set_root` would be `0x00…0`, `src/chain/merkle.rs:17`), but a zero root would brick every
   epoch after it (`UnknownEpoch`).
4. **Spec:** in §13.4, state the `epoch(h)` check and the rule that old sets are retired. Fix the
   "consensus is also broken" claim in §13.7. Document that handoffs must be posted promptly,
   because `set(latestEpoch)` stays authoritative on the bridge until the next handoff is
   posted, even after it has left on Hypersnap.

## Requirements for the future CERT-STARK verifier

- The verifier cannot fix this alone, because `d` does not contain the epoch. It must treat
  `epoch`, `setRoot` and `totalWeight` as caller-supplied public inputs bound into the proof
  (Fiat–Shamir transcript). The bridge is responsible for checking that `epoch` matches the
  header's height. The verifier documentation should say this so that no integrator assumes
  the verifier does it.
- It must return `false` (not `true`) for `totalWeight == 0` or an empty `signerBitmap`. The
  check `3·w > 2·W` with `W = 0` and `w = 0` is false, but an implementation that uses `>=` or
  a ceiling division could pass. This is defense in depth for fix 3.
