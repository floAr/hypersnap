---
id: F045
specialist: solidity-bridge
attack_class: claim-signature-replay
title: Universal control-plane signatures (propose/cancel-upgrade, pause, owner-rotate) replay onto lagging canonical deployments; the per-deployment watermark is not a sound cross-deployment replay defense
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
  - code/hypersnap/crates/hypersnap-crypto/src/bridge_payload.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
related_findings:
  - F047
  - F048
  - F049
relationship: related-but-distinct
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

`HypersnapBridge` deliberately makes six payloads **universal** (no chainId,
no contract-address binding): `MERKLE_ROOT_UPDATE`, `OWNER_UPDATE`,
`OWNER_ACCEPTANCE`, `UPGRADE`, `UPGRADE_CANCEL`, `PAUSE`. The same threshold
group key signs them, and the same signature is intended to be relayed to
**every** canonical deployment on every chain. The only stated defense against
cross-deployment / cross-chain replay is the "strictly-monotonic 64-bit
block-number watermark" (`latestBlock`).

The watermark is **per-deployment storage that advances independently and at an
attacker-influenceable rate**. It only rejects a signature whose `blockNumber`
is `<=` *that deployment's local* `latestBlock`. It does **not** prevent a
universal signature from being applied to any deployment that has not yet
locally advanced past its block number. Because relay is permissionless and
unsynchronized — and an attacker is also a relayer who can withhold newer
signatures from a chosen deployment — a low-traffic / lagging deployment can be
kept at a stale watermark and then fed an old, **already-superseded** universal
signature that it has never consumed. The watermark provides no protection in
this case: it cannot tell that a `proposeUpgrade(block=N)` was later
`cancelUpgrade`d on a different deployment; it only checks `N > localWatermark`.

The value/claim path is **not** affected (leaf embeds `destinationChainId`,
`claim` enforces it at L183, and `claimed[lockId]` is per-deployment), so
cross-chain double-claim of a value leaf is correctly blocked. The defect is
confined to — and is serious in — the **control plane**, where the worst case
is an attacker-driven UUPS implementation swap (total custody theft) on the
lagging deployment.

## Where

`contracts/src/HypersnapBridge.sol`:

- Domain constants L53-58 — all six universal domains.
- Watermark gate, repeated per universal entry point:
  - `claim` root-update: `if (blockNumber > latestBlock)` (L188), else exact
    `(blockNumber, merkleRoot)` match (L199).
  - `rotateOwner`: `if (blockNumber <= latestBlock) revert StaleBlock` (L235).
  - `proposeUpgrade`: L276.
  - `cancelUpgrade`: L321.
  - `pause`: L362.
- Universal digests bind only `(domain, bytes8(blockNumber), payloadFields)` —
  e.g. `proposeUpgrade` digest L281-285, `cancelUpgrade` digest L325-329.
  Neither `block.chainid` nor `address(this)` is in any universal preimage.
- Per-deployment state: `latestBlock` (L90), `pendingImplementation` /
  `pendingUpgradeEffectiveAt` (L96, L98) all live in this contract's storage,
  independent of every other deployment.

Rust side (`crates/hypersnap-crypto/src/bridge_payload.rs`) matches byte-for-byte
and is pinned to the Solidity vectors (`cross_side_pinned_vectors`, L382). The
module header (L8-18) states the universal-vs-chain-specific split explicitly;
`upgrade_digest` (L133) and `upgrade_cancel_digest` (L147) bind only
`(tag, u64_be(block), addr)`. So this is **not** an encoding-asymmetry bug — the
two sides agree. The flaw is in the replay-defense model itself.

## Attack walk (no key compromise required)

Two canonical deployments share owner key `O`:
- Deployment A (busy chain): `latestBlock = 5000`.
- Deployment B (low-traffic chain holding real custody): `latestBlock = 100`.

1. Validators legitimately sign `proposeUpgrade(block=4000, implX, sigO)`,
   intending it for all chains. A relayer applies it on A.
2. A defect in `implX` is found. Validators sign
   `cancelUpgrade(block=4001, implX, sigO)`; a relayer applies it on A. A is
   clean — no pending upgrade.
3. The attacker (also a relayer) has the still-valid
   `proposeUpgrade(block=4000, implX, sigO)` bytes and **never relayed steps
   1-2 to B**, keeping B's watermark at 100.
4. Attacker submits `proposeUpgrade(4000, implX, sigO)` to **B**. B's gate
   `4000 > latestBlock(100)` passes (L276). `implX` becomes pending on B with a
   48h timer; B's watermark advances to 4000.
5. The `cancelUpgrade(4001)` exists, but the attacker withholds it from B; even
   if a defender relays it, the attacker only has to win the
   `executeUpgrade()` race after 48h. After execute, the cancelled-on-A
   implementation is live on B.

The monotonic watermark gives **zero** protection in step 4: cancellation does
not propagate across deployments, and `latestBlock` cannot encode "this propose
was superseded." Any superseded universal action stays live on every deployment
that has not locally advanced past its block number, and the attacker controls
B's advancement by selectively relaying.

## Higher-impact variant (compromised / rotated-out key)

The contract documents a key-compromise recovery (L266-270): rotate to `O2`
(immediate), then `O2` signs `cancelUpgrade`, so "the malicious upgrade's 48h
timer never fires." The lockout arithmetic in L64-71 (PAUSE 72h > UPGRADE 48h,
"24h guaranteed lockout") is **only valid on a deployment whose watermark is
current**. On a lagging deployment B, the holder of the old `O1` key can replay
any `O1`-signed universal payload whose block number lies in
`(B.latestBlock, rotationBlock)` — including a malicious
`proposeUpgrade(block, evilImpl, O1sig)` — because B never consumed those block
numbers and the rotation to `O2` (higher block) has not yet landed on B. The
attacker thus gets a head start that the contract's same-block-timestamp
analysis assumes away. The pause backstop helps only if defenders detect and
pause B in time; the watermark itself does not stop the replay.

## Watermark-coupling aggravator: `recoverERC20`

`recoverERC20` is the one chain-bound payload (digest binds `block.chainid`,
L402-409) yet it consumes the **same** global watermark (`latestBlock =
blockNumber`, L411). A recover applied on one chain burns a watermark slot that
universal payloads on *other* chains may also want, and vice-versa. Because the
signer must allocate one shared monotonic 64-bit counter across both
chain-bound and universal actions, the per-deployment watermarks legitimately
diverge over time — which is exactly what widens every universal payload's
cross-deployment replay window. This coupling makes "keep all deployments at the
same watermark" operationally impossible, so lagging deployments are the
expected state, not an edge case.

## Why this is not closed by existing mitigations

- **Watermark monotonicity:** rejects only sigs older than the *local*
  watermark. Superseded-but-newer-than-local sigs pass. Attacker controls local
  advancement by withholding relays.
- **`OWNER_ACCEPTANCE` has no watermark at all** (digest binds only `newOwner`,
  L247-250 / `owner_acceptance_digest` L127). It is replayable forever and
  everywhere; not directly exploitable alone (rotation still needs a fresh `O1`
  authorization sig), but it is a strict watermark-coverage gap worth recording.
- **Pause backstop:** mitigates but does not prevent; requires defenders to
  detect the targeted lagging deployment and land a higher-block pause before
  `executeUpgrade`.

## Impact

Cross-deployment replay of control-plane signatures on any deployment the
attacker can keep watermark-stale. Worst case: a superseded or
old-key-signed `proposeUpgrade` is replayed and executed, swapping the UUPS
implementation on a deployment holding live custody → total loss of that
deployment's funds. Lower-bound case: cancelled/superseded upgrades and pauses
remain live across the deployment set, defeating the documented incident-
response guarantees. Severity: high.

## Recommended fix

Bind every universal control-plane digest to the deployment identity so a
signature is no longer replayable across deployments:

- Include `block.chainid` AND `address(this)` (or a per-deployment
  `bytes32 deploymentId` set at `initialize`) in the preimage of
  `UPGRADE`, `UPGRADE_CANCEL`, `OWNER_UPDATE`, `OWNER_ACCEPTANCE`, and `PAUSE`
  on both the Solidity and `bridge_payload.rs` sides, and re-pin the cross-side
  vectors. The root-update path can remain universal because the leaf's embedded
  `destinationChainId` already isolates value per chain.
- Alternatively keep universal payloads but add a per-deployment, signed,
  monotonic *cancellation epoch* so a cancel on one chain cannot be out-run by a
  stale propose on another — but per-deployment digest binding is simpler and
  removes the entire class.
- Add a watermark (or full deployment binding) to `OWNER_ACCEPTANCE`.
- Decouple `recoverERC20` from the universal watermark namespace (e.g. a
  separate per-chain recover nonce) so chain-bound actions stop perturbing the
  universal watermark.
