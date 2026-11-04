---
finding_id: F008
title: V2 governance actions share one watermark and never expire, so whoever relays first decides which of two decided actions takes effect
severity: low
status: pending-validation
related_findings:
- F004
- F009
---
# F008 — V2 governance actions share one watermark and never expire, so whoever relays first decides which of two decided actions takes effect. Relaying a later pause first kills an honest cancel. The node cannot decide the same action again in that epoch.

- **Severity:** Low. Nobody can forge, double-apply or move an action to another chain. Every action involved was decided by more than 2/3 of the set. But any relayer chooses the **order**, and so **which** of the decided actions takes effect, and **when**. In the worst case shown, an upgrade that the validators decided to cancel still executes. That needs the validators to miss the problem for the whole 72h pause and not use the workaround (described below). That is a governance-liveness and operations hazard, not a direct loss of funds.
- **Category:** claim-signature-replay (action ordering / freshness). Also spec-divergence / under-specification: §13.7 does not mention the watermark or what happens to actions that are decided but not yet relayed.
- **Specialist:** solidity-bridge · task H007
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** `poc/H007/test/H007.t.sol`. It passes 4/4 (`poc/H007/H007-forge-output.txt`) against unmodified copies of `contracts/src` and `contracts/test/utils` (diff-verified), built with OZ v5.1.0 and `MockCertificateVerifier`.
- **Related:** F004 is a different issue. There, a retired set pushes `lastActionHeight` to 2^64−1, which needs a malicious >2/3 of a past set. Here only honest decisions are involved. F002 covers cross-network replay. Not refiled.

## Summary

`_applyAction` (`contracts/src/HypersnapBridgeV2.sol:479-499`) accepts an action header only
if `h.height > lastActionHeight`, then sets `lastActionHeight = h.height`. `proposeUpgrade`,
`cancelUpgrade` and `pause` share this one watermark (`:149-150`, NatSpec `:58-60`). Relaying is
permissionless. The action hash, `keccak("hypersnap-bridge-action-v1"‖kind‖chainId‖target)`
(`:436-442`), has no height, no expiry and no link to the previous action.

The node side (`src/chain/shard0/bridge_actions.rs`) does three things:
- `decide` (`:98-143`, called once per block at `engine.rs:877`) puts **at most one** action per
  header. When several actions have passed 2/3, it picks them in **action-hash order**, not
  in the order of voting or urgency. Concurrent actions therefore land in consecutive blocks
  in an order nobody chose.
- `vote` (`:69-76`) rejects a vote for an action that is already `BRIDGE_DECIDED` **in the
  current epoch**. So the identical `(kind, chainId, target)` cannot be decided twice in one
  epoch. `EPOCH_LENGTH` is 36,000 blocks, about 5 days (FIP §4 / §14), which is longer than
  `PAUSE_DURATION` (72h).
- `on_boundary` (`:154-168`) drops earlier epochs' votes and decisions. The same action can
  be decided again in the next epoch, but only with fresh >2/3 votes.

Together these give:

1. **Relay order decides the outcome.** Take two actions decided at `H1 < H2`, both applicable
   on chain C. If `H2` is relayed first, `H1` is unappliable forever (`StaleAction`). Certified
   headers are public, and anyone can produce the CERT-STARK (§16.6 "Production"). Any relayer,
   or a front-runner, chooses the order.
2. **Recovery is limited.** The validators cannot re-decide the lost action in the same epoch.
   The only immediate workaround is the *other chainId variant*: `chainId = 0` becomes
   `chainId = C`, or the reverse. That is a different hash. Each kind/target therefore has two
   tries per chain per epoch.
3. **No expiry.** A decided action that was never relayed stays valid until some later action
   is relayed on that chain. Anyone can apply it at any later time. A stale pause halts
   `claim`/`burn`/`executeUpgrade` for 72h counted from **relay** time
   (`pause`, `:372-377`). A stale `proposeUpgrade` starts the 48h clock whenever the
   relayer wants.

## Attacker model

- Anyone with gas. No keys are needed. The attacker only reorders or delays the relay of
  certified headers that the honest >2/3 already produced.
- Motive for (1): someone who wants a cancelled upgrade `X` to execute anyway, for example
  because `X` has a bug they can exploit, or someone who wants to drop an incident pause by
  relaying a later action first.
- Trust assumptions: an honest >2/3 in the current epoch, and a CERT-STARK verifier that is
  sound. The finding does not depend on the verifier.

## Attack paths (in the PoC)

**(a) An honest cancel dies behind a pause**: `test_relayOrderKillsHonestCancel`
1. `proposeUpgrade(X)` is decided at `h0` and relayed. `X` is pending, with 48h delay.
2. The validators then decide `cancel(0, X)` at `h0+5` and `pause(0)` at `h0+6`. They might
   vote both together, and `decide` emits them one block apart in hash order.
3. The attacker relays the pause first. The cancel now reverts `StaleAction(h0+6, h0+5)`
   and can never be applied.
4. Unless someone acts within the 72h pause, `executeUpgrade()` installs `X` at `pauseExpiry`.
   The PoC shows `version() == 3`.

**(b) Recovery only through the other variant**: `test_recoveryNeedsOtherChainIdVariant`.
The node rejects `cancel(0, X)` for the rest of the epoch ("the bridge action is decided").
`cancel(block.chainid, X)` is a different hash, can be decided at a later height, and works.
If both variants are used up (each killed by a later relayed action), nothing can be done
until the next epoch boundary, which can be up to about 5 days away. The pause gives only 72h.
The validators can extend the pause with `pause(C)` (the other pause variant), but that is
also limited to once per epoch.

**(c) A stale action is applied at the attacker's chosen time**: `test_stalePauseRelayedLater`.
A pause decided at `h0` and never relayed is relayed 30 days later. The bridge halts for 72h
from that moment.

**Negative controls**: `test_noDoubleApply_noCancelReplayOnLaterProposal`. The same header
cannot be applied twice. An old `cancel(X)` cannot be replayed against a *later* re-proposal
of the same `X`, because the re-proposal raised the watermark above the cancel's height.

## Answers to the H007 questions

| Question | Result |
|---|---|
| Same decided action applied twice on one chain? | No. Strict `>` watermark (`:491`); also the existing test `test_action_replay_reverts`. |
| On another EVM chain? | Only by design: `chainId = 0` applies on every chain, and each chain has its own watermark. A chain-specific action reverts `WrongActionChain` elsewhere (`:486-488`). Cross-*network* replay is F002. |
| Re-decided after an epoch boundary and replayed? | `on_boundary` makes re-deciding possible, but only with fresh >2/3 votes of the new epoch. The new header has a new height and is a legitimate new decision, not a replay. A header can only be replayed if its height is above the watermark, which brings us back to (c). |
| `cancel(X)` replayed against a later legitimate proposal of `X`? | No. The later proposal's height is above the cancel's height. The only window is a cancel that was never relayed for a proposal that was never relayed, both below the watermark: they are dead together. |
| Can universal and chain-specific actions interfere? | Only through the shared watermark. A later `chainId = 0` action kills an earlier unrelayed `chainId = C` action on C, and the reverse. The two variants are also the only way to re-decide inside one epoch. |

## Spec vs code

- §13.7 says "`PAUSE_DURATION` is longer than `UPGRADE_DELAY`, so validators can stop a
  malicious upgrade". It does not say that actions must be relayed **in height order**, that
  a later relayed action invalidates earlier unrelayed ones, or that decided actions do not
  expire. The code and `contracts/README.md:27-29` intend the shared watermark, which carries
  over V1's design, and `test_action_watermarkSharedAcrossKinds` tests it. The divergence is
  that the spec is silent, not that the code is wrong.
- The node-side `bridge_actions.rs:8-9` says "a later pause extends it". Inside one epoch,
  the identical pause cannot be decided again (`vote` `:70-76`). `test_pause_extendsWithNewAction`
  (two `pause(0)` headers at `PIVOT+5`/`PIVOT+6`, both epoch 1) is therefore unreachable on
  the node: a same-epoch extension needs the other chainId variant.
- On Hypersnap the pause counts from the decision timestamp (`decide` `:130-136`). On the EVM
  side it counts from relay time. These differ by any relay delay, and (c) makes that delay
  unbounded.

## Red-team (invalidation hypotheses walked)

1. *"The shared watermark is intended, so this is not a bug."* The watermark is intended and
   tested. The consequences are not documented: relayer-chosen order, no expiry, and the
   once-per-epoch re-decide rule interacting with the 72h pause. That is the reason for Low
   and not Medium.
2. *"Honest operators relay immediately, so ordering never matters."* For (a) the two headers
   are about 12s apart and both are public. A front-runner needs one transaction. On OP the
   ordering is priority-fee based. The race is real.
3. *"Validators simply re-vote."* Not for the same hash in the same epoch, which can last up
   to about 5 days. The other chainId variant does work (PoC b). This is the main mitigating
   factor, and it caps severity.
4. *"Can the attacker kill a cancel with no pause buffer?"* While `X` is pending,
   `proposeUpgrade` reverts `UpgradeAlreadyPending` and does not move the watermark. So the only
   later applicable actions are `pause` (which buffers `executeUpgrade` for 72h) or another
   `cancel(X)` (which cancels anyway). A cancel can never be silently killed without the
   72h buffer. This also limits severity.
5. *"Is (c) reachable without honest misbehaviour?"* Only if a decided action was not relayed
   on some chain. That is plausible for a chain-specific action that operators decided not to
   use, or for a chainId-0 action that operators relayed only on the chain they cared about.
   Each case is an operational slip, so impact is griefing (a 72h halt) or a 48h clock that
   validators must notice.
6. *"Does F004 already cover this?"* No. F004 needs a malicious retired set and pins the
   watermark at max. This finding needs no malicious key.
7. *"Is the PoC realistic?"* It uses unmodified contracts and the mock verifier, which checks
   all five public inputs. The ordering behaviour does not depend on the verifier.
8. *"Is anything above Low?"* Only if validators lack monitoring for a full 72h after a
   relay-order attack. I do not assume that.

## Fix

Pick one or combine:
- **Per-kind watermarks** (`lastPauseHeight`, `lastUpgradeHeight`, `lastCancelHeight`), so
  that a pause cannot invalidate a cancel. Keep the per-header single-use property by
  recording `appliedActionHeight[height] = true`, or keep a strict per-kind `>` check.
- Or **make cancel and pause always applicable**: accept a cancel for the pending
  implementation whose height is above the *proposal's* height (store
  `pendingProposalHeight`), whatever `lastActionHeight` is. Accept a pause if its height is
  above `lastPauseHeight`. Defensive actions should not be ordering-sensitive.
- **Expiry**: reject an action header whose epoch is older than `latestEpoch − k`, or bind
  an expiry/epoch into the action hash. That bounds (c).
- Node side: let an action be decided again when the previous decision is older than N
  blocks, or document the chainId-variant workaround in the operator runbook.
- Spec §13.7: state the ordering rule and the "relay in height order" requirement.

## Requirements for the future CERT-STARK verifier

None beyond F002/F004. This issue is in the contract's action-freshness logic, and it
appears with a perfectly sound verifier.

## Leads (not in this finding)

- [H008] `decide` (`bridge_actions.rs:110`) compares the vote **count** (`add_u64(count, 1)`, `:83`)
  against `set.total_weight`. That is only correct while every weight is 1. It also scans the actions in
  **hash order** and takes the first one past the threshold, so an action that passes later
  can be emitted before one that passed earlier. Together with this finding, the vote
  sequence does not control the relay-critical order.
- [H008] `vote` requires that the voter is a member of `set(ctx.epoch)` by `node_key_hash` and
  `fid` (`:62-68`). Check for duplicate members with the same fid but different node keys,
  which would count twice.
