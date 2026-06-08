---
id: F047
specialist: solidity-bridge
attack_class: owner-rotate-race
title: Owner rotation has no priority over other watermark-consuming actions; a compromised old owner front-runs the recovery `rotateOwner` to retain power or seize permanent ownership, defeating the documented "immediate rotation" key-compromise recovery
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
  - code/hypersnap/crates/hypersnap-crypto/src/bridge_payload.rs
  - code/hypersnap/src/hyper/runtime.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
related_findings:
  - F045
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

`rotateOwner` is an atomic one-shot rotation gated solely by the shared
strictly-monotonic 64-bit watermark (`blockNumber > latestBlock`). It shares
that single watermark namespace with every other owner-signed universal action
(`pause`, `proposeUpgrade`, `cancelUpgrade`, the `claim` root-advancement) and
with `recoverERC20`. Rotation has **no priority** over those actions and the
on-chain digests are public the instant a rotation transaction enters the
mempool.

The contract's documented key-compromise recovery (L266-270) rests on the
premise that `rotateOwner(... O2 ...)` is "immediate, no delay" and therefore
out-runs the 48h upgrade timer. That premise is false in the exact scenario it
is written for. Because the **compromised old key `O1` is still the owner until
the rotation actually lands**, the attacker holding `O1` can watch the mempool
for the defenders' `rotateOwner(block=N, O2, …)` and front-run it with any
`O1`-signed, watermark-consuming action whose `blockNumber >= N`. That bumps
`latestBlock >= N`, so the legitimate rotation reverts with `StaleBlock` and
never lands. Repeated each round, the attacker indefinitely starves the
rotation — the compromised owner retains power.

The decisive escalation: the attacker can front-run with their **own**
`rotateOwner(block=N, O_attacker, authSig_O1, acceptSig_O_attacker)`. The
attacker holds `O1` (signs the authorization) and controls `O_attacker` (signs
the acceptance), so both gates pass and `ownerAddress` becomes `O_attacker`
**permanently** — the attacker wins the rotation race outright and the
legitimate `O2` rotation is now stale forever. This directly realizes the
hunt's "attacker becomes owner / old owner retains power after rotation."

## Where

`contracts/src/HypersnapBridge.sol`:

- `rotateOwner` (L229-258). Gate `if (blockNumber <= latestBlock) revert
  StaleBlock` (L235); on success `latestBlock = blockNumber; ownerAddress =
  newOwner` (L255-256). No priority, no commit/reveal, no per-action nonce.
- Authorization digest binds only `(DOMAIN_OWNER_UPDATE, bytes8(blockNumber),
  bytes20(newOwner))` (L238-242). Acceptance digest binds only
  `(DOMAIN_OWNER_ACCEPTANCE, bytes20(newOwner))` (L247-250) — no block, no
  chainId, so an `O_attacker` acceptance sig is trivially producible offline by
  the attacker and is reusable forever.
- Shared watermark consumers that an attacker holding `O1` can use to front-run
  / bump `latestBlock`: `proposeUpgrade` L276/L306, `cancelUpgrade` L321/L331,
  `pause` L362/L368, `recoverERC20` L399/L411, and the `claim` root-advancement
  L188/L195. All set `latestBlock = blockNumber` after an `O1` ecrecover, so any
  of them at `block >= N` invalidates a pending `rotateOwner(block=N)`.
- The recovery narrative that this breaks: L266-270 ("rotate … immediate, no
  delay") and the lockout arithmetic L64-71.

Rust side encodes the identical preimages and is pinned to the Solidity vectors
(`crates/hypersnap-crypto/src/bridge_payload.rs::owner_update_signing_payload`
L97, `owner_acceptance_signing_payload` L115, `cross_side_pinned_vectors`
L382). `src/hyper/runtime.rs::produce_signed_owner_rotation_local` (L1066) /
`apply_owner_rotation` (L1130) drive the same `(block_number, new_owner)`
authorization + `new_owner`-only acceptance, confirming the off-chain pipeline
matches and offers no extra anti-front-run binding. This is **not** an encoding
asymmetry; the defect is the on-chain race model.

## Attack walk (key-compromise recovery, single deployment, no cross-deployment lag required)

Preconditions: validator group key `O1` is compromised (the only scenario the
contract's recovery flow is designed for). Validators run a fresh DKG and obtain
`O2`; they sign `rotateOwner(block=N, O2, authSig_O1, acceptSig_O2)` and relay
it. `latestBlock` is currently `< N`.

1. The rotation tx sits in the public mempool. The attacker observes block `N`
   and `newOwner=O2`.
2. The attacker, still holding `O1`, signs and submits with higher priority fee
   **either**:
   - a grief: `pause(block=N, O1)` or `proposeUpgrade(block=N, evilImpl, O1)` —
     bumps `latestBlock = N`; the defenders' `rotateOwner(block=N)` now reverts
     `StaleBlock`; **or**
   - a seizure: `rotateOwner(block=N, O_attacker, authSig_O1,
     acceptSig_O_attacker)` — both signatures verify, `ownerAddress =
     O_attacker`, `latestBlock = N`. The defenders' rotation to `O2` is now
     permanently stale.
3. Defenders re-sign the rotation at `N+1` (another DKG-coordinated signing
   ceremony). The attacker repeats step 2 against `N+1`. The attacker only needs
   to win one mempool race per round and can keep `latestBlock` perpetually at
   or above the defenders' freshest rotation block. The compromised owner never
   relinquishes control; with the seizure variant the attacker is already the
   sole owner after a single won race.

No 48h timer, no lagging secondary deployment, and no withheld-relay setup is
required — the race is decided in the mempool of the very deployment under
recovery.

## Why existing mitigations do not close it

- **Watermark monotonicity**: it is precisely the weapon here. The attacker uses
  the shared counter to invalidate the rotation; monotonicity gives the
  *first-landed* `block>=N` action the win, and the attacker can always be first
  by fee.
- **Acceptance "proof of key possession"**: only proves the named `newOwner`
  controls a key. The attacker names `O_attacker` and supplies its own
  acceptance, so the gate is satisfied by the attacker, not bypassed.
- **Pause backstop**: pause is itself an `O1`-signed, watermark-consuming action
  — using it as a defense consumes the same counter and is equally front-runnable
  by the attacker; it cannot be landed "for free" ahead of the attacker.
- **Two-step nature**: there is no on-chain pending-owner state, so there is no
  accept-window to protect; the entire rotation is one tx and the race is on
  *landing* that tx, not on a separate accept.

## Dedup note

Related to **F047 (this finding)** is **F045** (claim-signature-replay):
F045 concerns *cross-deployment* replay of already-superseded universal
signatures onto a deliberately lagging deployment B, and notes the
`OWNER_ACCEPTANCE` watermark gap in passing. This finding is a distinct
*owner-rotate-race* on a *single* deployment: a same-mempool front-run that
defeats the documented immediate-rotation recovery and lets the attacker seize
or retain ownership without any second deployment or withheld relay. Shared root
cause family (universal/shared-watermark control plane) but different exploit
primitive and different broken guarantee; should be linked, not merged.

## Impact

In the one scenario the recovery flow exists to handle — a stolen group key —
the recovery is defeatable: the attacker either livelocks every rotation attempt
(old compromised owner retains full bridge control: mint via `claim`
root-advancement, `proposeUpgrade` to a custody-draining implementation, etc.)
or, in the stronger variant, becomes the permanent sole owner in a single won
mempool race. This is total, persistent loss of bridge control during incident
response. Severity: high.

## Recommended fix

Give rotation a path that cannot be starved by other watermark consumers, and
remove the front-run primitive:

- Decouple `rotateOwner` from the shared monotonic watermark: gate it on a
  **dedicated, rotation-only** monotonic counter (`ownerRotationBlock`) so that
  `pause` / `proposeUpgrade` / `cancelUpgrade` / `recoverERC20` / root-update can
  never invalidate a pending rotation, and vice versa.
- Bind the authorization digest to the **current** `ownerAddress` (the key being
  rotated out) and to deployment identity (`block.chainid` + `address(this)`),
  so an attacker cannot reuse a captured `O1` authorization to install a
  *different* `newOwner` of their choosing — the captured sig is valid only for
  the exact `(currentOwner -> O2)` transition the defenders signed. (Combine with
  F045's deployment-binding recommendation.)
- Bind the acceptance digest to `blockNumber` (and deployment identity) so an
  acceptance cannot be pre-fabricated/relayed independently of the specific
  rotation it belongs to.
- Consider a short commit/reveal or a "highest-block-wins within the tx"
  selection that lets a freshly signed legitimate rotation supersede an
  attacker's same-block action deterministically, rather than first-to-land.
