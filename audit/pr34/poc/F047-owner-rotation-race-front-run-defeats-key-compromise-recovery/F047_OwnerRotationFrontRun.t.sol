// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

// ============================================================================
// Finding:  F047 — owner-rotate-race
// Title:    Owner rotation has no priority over other watermark-consuming
//           actions; a compromised old owner (O1) front-runs the recovery
//           `rotateOwner` to either starve it (grief) or seize permanent
//           ownership, defeating the documented key-compromise recovery.
//
// Placement (intended): code/hypersnap/contracts/test/F047_OwnerRotationFrontRun.t.sol
//           (lives here under findings/tests/ as a deliverable; copy into the
//            contracts test dir to run — it reuses utils/BridgeTest.sol).
//
// Target:   code/hypersnap/contracts/src/HypersnapBridge.sol  (READ-ONLY)
// Commit:   cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
//
// These are REGRESSION tests asserting the SECURE post-fix behavior. They are
// expected to FAIL on cab225f (the vulnerable code) and PASS once rotation is
// decoupled from the shared monotonic watermark and given race priority over
// the compromised old owner (see finding "Recommended fix").
//
// Test 1  testRecoveryRotationCannotBeFrontRun
//   Assertion: after O1 is compromised and front-runs a recovery with a
//   competing higher-watermark action (`pause(block=N)`), the legitimate
//   recovery `rotateOwner(N, O2)` STILL SUCCEEDS — ownerAddress becomes O2.
//   Expected on cab225f: FAILS — recovery reverts StaleBlock(N, N) because
//   the grief action already set latestBlock = N.
//
// Test 2  testOldOwnerCannotSeizeViaRotate
//   Assertion: once a recovery rotation to the safe owner O2 has been signed,
//   the compromised O1 must NOT be able to front-run it with its own
//   `rotateOwner(N, attacker)` and become/install the attacker as owner; the
//   legitimate recovery to O2 must prevail.
//   Expected on cab225f: FAILS — O1's seizure rotation lands first, sets
//   ownerAddress = attacker permanently, and the O2 recovery is then stale.
//
// Expected result:  FAILS on cab225f, PASSES after fix.
// STATUS: UNVERIFIED
// ============================================================================

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract F047OwnerRotationFrontRunTest is BridgeTest {
    // Role aliases mapping the finding's actors onto the harness keys:
    //   O1        = OWNER_PK     (the COMPROMISED group key; current owner)
    //   O2 (safe) = NEW_OWNER_PK (the freshly-DKG'd recovery owner)
    //   attacker  = ATTACKER_PK  (an EOA the O1-holder also controls)

    // -----------------------------------------------------------------------
    // Test 1 — recovery rotation must not be starvable by a competing
    //          watermark-consuming action from the compromised old owner.
    // -----------------------------------------------------------------------
    function testRecoveryRotationCannotBeFrontRun() public {
        uint64 N = 100;

        // Defenders ran a fresh DKG and signed the recovery rotation O1 -> O2
        // at block N. (Both sigs are valid; O1 still owns until it lands.)
        bytes memory recoveryAuth   = _signOwnerUpdate(N, newOwnerEOA, OWNER_PK);
        bytes memory recoveryAccept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);

        // Compromised O1 observes the mempool and front-runs with a grief:
        // a `pause` at the same block N, which bumps the shared watermark to N.
        bytes memory griefPause = _signPause(N, OWNER_PK);
        bridge.pause(N, griefPause);
        assertEq(bridge.latestBlock(), N, "grief pause should have bumped watermark");

        // SECURE behavior: the legitimate recovery rotation still lands.
        // On cab225f this reverts StaleBlock(N, N) because rotateOwner shares
        // the watermark gate (`blockNumber <= latestBlock`).
        bridge.rotateOwner(N, newOwnerEOA, recoveryAuth, recoveryAccept);

        assertEq(
            bridge.ownerAddress(),
            newOwnerEOA,
            "recovery rotation to O2 must succeed despite the front-run grief"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — the compromised old owner must not be able to seize ownership
    //          by front-running the signed recovery rotation with its own
    //          rotation to an attacker-controlled EOA.
    // -----------------------------------------------------------------------
    function testOldOwnerCannotSeizeViaRotate() public {
        uint64 N = 100;

        // Defenders signed the recovery rotation O1 -> O2 at block N.
        bytes memory recoveryAuth   = _signOwnerUpdate(N, newOwnerEOA, OWNER_PK);
        bytes memory recoveryAccept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);

        // Compromised O1 front-runs with a SEIZURE: it holds O1 (signs the
        // authorization over `attacker`) and controls `attacker` (self-signs
        // the acceptance, since the acceptance digest binds neither block nor
        // chainId nor address(this)). On cab225f both gates pass.
        bytes memory seizeAuth   = _signOwnerUpdate(N, attackerEOA, OWNER_PK);
        bytes memory seizeAccept = _signOwnerAcceptance(attackerEOA, ATTACKER_PK);

        // SECURE behavior: O1's seizure attempt must not be able to make the
        // attacker the owner ahead of / instead of the signed O2 recovery.
        // We allow the seizure tx to revert (acceptable secure outcome) by
        // wrapping in try/catch; what we forbid is the attacker ending up owner.
        try bridge.rotateOwner(N, attackerEOA, seizeAuth, seizeAccept) {
            // If it did not revert, the attacker must NOT have become owner.
        } catch {
            // Reverting the seizure is an acceptable secure outcome.
        }

        assertTrue(
            bridge.ownerAddress() != attackerEOA,
            "compromised O1 must not be able to seize ownership to an attacker EOA"
        );

        // And the legitimate recovery to O2 must remain landable. On cab225f
        // the seizure already set latestBlock = N and ownerAddress = attacker,
        // so this recovery reverts (StaleBlock and/or BadOwnerSignature),
        // confirming the recovery has been permanently defeated.
        bridge.rotateOwner(N, newOwnerEOA, recoveryAuth, recoveryAccept);
        assertEq(
            bridge.ownerAddress(),
            newOwnerEOA,
            "the signed recovery rotation to O2 must prevail over the old owner's seizure"
        );
    }
}
