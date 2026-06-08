// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

// =============================================================================
// F049 — Watermark saturation bricks rotateOwner/cancelUpgrade while the
//        watermark-independent executeUpgrade survives.
//
// Finding:  findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-
//           execute-upgrade-survives.md  (specialist: solidity-bridge,
//           attack_class: upgrade-race, severity: high, verdict: WATERPROOF)
// Trace:    findings/traces/F049-trace.md
// Target:   code/hypersnap/contracts/src/HypersnapBridge.sol @ cab225f
//
// WHERE THIS BELONGS IN THE REPO:
//   Move this file to  code/hypersnap/contracts/test/F049_WatermarkSaturation.t.sol
//   (sibling of UpgradeFlow.t.sol / RotateOwner.t.sol / Pause.t.sol). The import
//   path `./utils/BridgeTest.sol` and `../src/HypersnapBridge.sol` below assume
//   that location, matching every existing test file's imports. As authored here
//   under findings/tests/ those relative paths do NOT resolve; copy into
//   contracts/test/ before running `forge test`.
//
// ROOT CAUSE: every universal control-plane ceremony is gated only by
//   `blockNumber > latestBlock` (lower bound) and then commits
//   `latestBlock = blockNumber` with NO upper / sanity cap. One universal
//   signature with `blockNumber == type(uint64).max` saturates the shared
//   `uint64 latestBlock`; afterwards no uint64 can be strictly greater, so
//   rotateOwner / cancelUpgrade / pause / claim-root-advance / recoverERC20 all
//   revert StaleBlock forever — while the permissionless, watermark-independent
//   executeUpgrade() still fires any surviving pending implementation.
//
// WHAT EACH TEST ASSERTS (all written as SECURE-behavior regression tests):
//   1. testRejectsOutOfRangeBlockNumber
//        A universal action (pause) at blockNumber == type(uint64).max MUST
//        revert (out-of-range / exceeds a forward MAX_ADVANCE window).
//        Today it is ACCEPTED and saturates latestBlock -> test FAILS now.
//   2. testRotateOwnerSurvivesAfterHighWatermarkAction
//        After a legitimately high (but in-range) watermark action, a
//        subsequent rotateOwner MUST still succeed. The exploit (saturation)
//        bricks rotation; this asserts rotation stays alive -> demonstrates the
//        brick. With the unbounded saturating action it FAILS now.
//   3. testExecuteUpgradeGatedAfterSaturation (optional)
//        A pending upgrade MUST NOT remain executable after the recovery plane
//        has been bricked: defenders must be able to cancelUpgrade. Asserts
//        cancelUpgrade still works post-saturation -> FAILS now (StaleBlock).
//
// EXPECTED RESULT: FAILS on cab225f (vulnerable), PASSES after the documented
//   fix (bound blockNumber to a forward window e.g.
//   `blockNumber <= latestBlock + MAX_BLOCK_ADVANCE`, and/or decouple
//   cancelUpgrade/rotateOwner from the saturable watermark).
//
// STATUS: UNVERIFIED — authored from source, not compiled/run in audit workspace.
// =============================================================================

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract F049_WatermarkSaturationTest is BridgeTest {
    // A legitimately "high" but plausibly in-range Hypersnap block height. The
    // fix's forward window should comfortably accommodate values like this; it
    // is the jump straight to type(uint64).max that must be rejected.
    uint64 internal constant HIGH_IN_RANGE_BLOCK = 1_000_000;

    HypersnapBridge internal nextImpl;

    function setUp() public override {
        super.setUp();
        nextImpl = new HypersnapBridge();
    }

    // -------------------------------------------------------------------------
    // 1. A universal action at blockNumber == type(uint64).max must be rejected.
    //
    //    SECURE behavior: a single signature cannot jump the shared watermark to
    //    the type maximum. The fix bounds the supplied block to a forward window
    //    (e.g. latestBlock + MAX_BLOCK_ADVANCE), so this call reverts.
    //
    //    VULNERABLE (cab225f): pause(type(uint64).max, sig) is accepted; the gate
    //    `blockNumber <= latestBlock` passes (max > 0) and latestBlock is set to
    //    type(uint64).max. No revert -> this test FAILS today.
    // -------------------------------------------------------------------------
    function testRejectsOutOfRangeBlockNumber() public {
        uint64 saturating = type(uint64).max;
        bytes memory sig = _signPause(saturating, OWNER_PK);

        // Expect ANY revert: the contract under the documented fix introduces a
        // new out-of-range guard (its exact selector is fix-defined), so we do
        // not pin one. On cab225f no revert occurs and the assertion below would
        // never be reached — the call returns and latestBlock saturates.
        vm.expectRevert();
        bridge.pause(saturating, sig);

        // Defense-in-depth: even if the revert expectation is loosened, the
        // watermark must not be saturable to the type maximum by one signature.
        assertLt(
            bridge.latestBlock(),
            type(uint64).max,
            "F049: latestBlock saturated to uint64 max by a single universal signature"
        );
    }

    // -------------------------------------------------------------------------
    // 2. After a high (but in-range) watermark action, rotateOwner must survive.
    //
    //    This is the brick demonstrator. We advance the watermark via a normal
    //    pause to a high value, then perform the documented key-compromise
    //    recovery (rotateOwner to a fresh key). It MUST succeed.
    //
    //    To exhibit the actual brick we drive the watermark to type(uint64).max
    //    (the exploit). On cab225f that pause is accepted and the subsequent
    //    rotateOwner reverts StaleBlock(type(uint64).max, X) for every X, so the
    //    final assertEq(ownerAddress, newOwnerEOA) is never reached -> FAILS.
    //
    //    After the fix the saturating pause itself reverts (caught), the
    //    watermark stays at the in-range value, and rotation succeeds -> PASSES.
    // -------------------------------------------------------------------------
    function testRotateOwnerSurvivesAfterHighWatermarkAction() public {
        // A legitimately high, in-range watermark action: should always be fine.
        bridge.pause(HIGH_IN_RANGE_BLOCK, _signPause(HIGH_IN_RANGE_BLOCK, OWNER_PK));
        assertEq(bridge.latestBlock(), HIGH_IN_RANGE_BLOCK);

        // The exploit: attacker (holding the compromised owner key) lands a
        // universal pause at the type maximum, saturating the shared watermark.
        // SECURE: this reverts (fix's range guard). We tolerate either outcome
        // so the test isolates the brick on the recovery action below.
        uint64 saturating = type(uint64).max;
        bytes memory satSig = _signPause(saturating, OWNER_PK);
        try bridge.pause(saturating, satSig) {
            // Accepted (vulnerable path) — watermark now saturated.
        } catch {
            // Rejected (fixed path) — watermark unchanged.
        }

        // Documented recovery (HypersnapBridge.sol L266-270): rotate to a fresh
        // DKG key. This MUST remain possible. Pick a block strictly above the
        // legitimate in-range watermark; under the fix it is also within range.
        uint64 rotateBlock = HIGH_IN_RANGE_BLOCK + 1;
        bridge.rotateOwner(
            rotateBlock,
            newOwnerEOA,
            _signOwnerUpdate(rotateBlock, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // On cab225f this line is unreachable (rotateOwner reverted StaleBlock).
        assertEq(
            bridge.ownerAddress(),
            newOwnerEOA,
            "F049: rotateOwner permanently bricked by saturated watermark"
        );
    }

    // -------------------------------------------------------------------------
    // 3. (optional) A pending upgrade must stay cancellable after a saturation
    //    attempt — i.e. executeUpgrade must not become an unstoppable sink.
    //
    //    The contract's own recovery story is: proposeUpgrade(evil) -> defenders
    //    cancelUpgrade before the 48h timer fires. We assert that cancelUpgrade
    //    survives a max-block universal action so the surviving pending impl can
    //    be cleared (and thus executeUpgrade later reverts NoPendingUpgrade).
    //
    //    On cab225f: the saturating pause is accepted, cancelUpgrade reverts
    //    StaleBlock, the evil impl survives, and executeUpgrade fires it after
    //    the delay -> the cancel assertion FAILS.
    //
    //    After the fix: saturating pause reverts (caught), cancelUpgrade
    //    succeeds, pendingImplementation == 0, executeUpgrade reverts -> PASSES.
    // -------------------------------------------------------------------------
    function testExecuteUpgradeGatedAfterSaturation() public {
        // Attacker proposes a (would-be malicious) upgrade, starting the 48h
        // timer. `nextImpl` is UUPS-compatible so the propose-time guard passes.
        bridge.proposeUpgrade(
            1,
            address(nextImpl),
            _signUpgrade(1, address(nextImpl), OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(nextImpl));

        // Attacker attempts to saturate the watermark with a max-block pause.
        // SECURE: reverts. VULNERABLE: accepted, latestBlock = type(uint64).max.
        uint64 saturating = type(uint64).max;
        bytes memory satSig = _signPause(saturating, OWNER_PK);
        try bridge.pause(saturating, satSig) {
            // vulnerable path
        } catch {
            // fixed path
        }

        // Documented defense: cancel the pending upgrade. MUST remain possible.
        uint64 cancelBlock = 2;
        bridge.cancelUpgrade(
            cancelBlock,
            address(nextImpl),
            _signUpgradeCancel(cancelBlock, address(nextImpl), OWNER_PK)
        );

        // On cab225f cancelUpgrade reverted StaleBlock above; this is unreached.
        assertEq(
            bridge.pendingImplementation(),
            address(0),
            "F049: cancelUpgrade bricked by saturated watermark; pending upgrade survives"
        );

        // With the pending upgrade cleared, the permissionless sink is dead even
        // after the delay elapses.
        vm.warp(block.timestamp + bridge.UPGRADE_DELAY() + 1);
        vm.prank(attackerEOA);
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        bridge.executeUpgrade();
    }
}
