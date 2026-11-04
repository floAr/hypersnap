---
finding_id: F007
title: Unclaimed V1 retroactive allocations become permanently unclaimable at the V2 upgrade, and nothing on-chain or in the upgrade script checks
severity: low
status: pending-validation
related_findings:
- F003
---
# F007 — Unclaimed V1 retroactive allocations become permanently unclaimable at the V2 upgrade, and nothing on-chain or in the upgrade script checks that the retroactive distribution is complete (spec §10.1 assumes it is)

> **Status (2026-11-04):** Severity **Low** (unvalidated). PoC: none. State: pending-validation.

> **Status 2026-11-04 (post-validation):** Severity **Low** (recalibrated 2026-11-04 from Info).


- **Category:** spec-divergence / upgrade-race (state that does not survive the upgrade)
- **Specialist:** solidity-bridge · task H004
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** none needed. The project's own test `contracts/test/HypersnapBridgeV2Upgrade.t.sol:293-323` (`test_upgrade_retroClaimPathClosed`) shows that after the upgrade, carol's unclaimed retro leaf can no longer be claimed, either against an anchor or through the removed V1 `claim` selector.

## Behaviour

- In V1, retro allocations are claimed through the owner-signed `claim` against `latestRoot` (`contracts/src/HypersnapBridge.sol:173-220`).
- V2 removes that entry point. Slot 1 (`__v1LatestRoot`) is kept but never read (`HypersnapBridgeV2.sol:112`, `:128`). V2 `claim` verifies only against `latestLockRoot` (`:300-306`), which comes from certified shard-0 headers. The NatSpec says so: *"The v1 retro root is not a v2 claim root."* (`:53`).
- The spec rules out putting retro leaves into the V2 lock set: §10.1 *"Hypersnap does not mint retroactive tokens. The genesis state (Section 17.4) contains no retroactive records."* and §17.4 item 4.
- `UpgradeToV2.s.sol` has no precondition about retro completeness (for example, claimed supply == `RETROACTIVE_POOL`, or an end-of-claim date). V1 has no claim deadline and no "distribution closed" flag either.

## Spec vs code

- §10.1: *"An Ethereum contract distributed the allocations, with their vesting schedule. The vesting schedule is complete. All allocations are fully vested."* V1 has no vesting logic. Any vesting must have been done off-chain through the sequence of owner-signed roots, which the spec does not describe. The spec treats "complete" as a fact. The code treats it as an assumption that the upgrade enforces by cutting off all remaining claims. **Both sides are incomplete:** the spec should define what "complete" means (all leaves claimed? a deadline?), and the upgrade ceremony should check it, or announce the cut-off.
- §10.1 also says the bridge contract "must control the mint and the burn of this token". It does, but the retro supply that is actually minted can be lower than `RETROACTIVE_POOL` (`TOTAL_SUPPLY × 0.10`, spec line 916) without anyone noticing. Supply accounting that assumes the full pool is circulating would be off by the unclaimed amount.

## Recommended fix

- Before signing the V2 upgrade, publish a retro claim deadline. In the ceremony (`UpgradeToV2.s.sol` phase 2), check and log `totalSupply()` against the retro total and the number of unclaimed leaves.
- Alternatively, keep a sunset retro-claim path in V2 that verifies against the frozen `__v1LatestRoot` (no new roots can be signed, because V2 clears the owner), possibly with a deadline. The `claimed` mapping already prevents double claims. Lock-ID domain separation between retro and V2 locks is the subject of F003; check it there before you enable this.
- Make the spec text match whichever option is chosen.
