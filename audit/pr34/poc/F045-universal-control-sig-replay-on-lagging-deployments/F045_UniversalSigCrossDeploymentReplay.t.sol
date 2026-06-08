// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

// ============================================================================
// REGRESSION TEST — Finding F045
//
// Title:    Universal control-plane signatures (propose/cancel-upgrade, pause,
//           owner-rotate) replay onto lagging canonical deployments; the
//           per-deployment block-number watermark is not a sound
//           cross-deployment / cross-chain replay defense.
// Attack:   claim-signature-replay (control-plane variant)
// Target:   code/hypersnap/contracts/src/HypersnapBridge.sol
//           code/hypersnap/crates/hypersnap-crypto/src/bridge_payload.rs
// Commit:   cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
//
// PLACEMENT: drop into code/hypersnap/contracts/test/ alongside
//            UpgradeFlow.t.sol / CrossSideDigests.t.sol so it inherits the
//            shared BridgeTest harness (./utils/BridgeTest.sol). The import
//            paths below assume that location.
//
// ROOT CAUSE: every universal digest binds only
//   keccak256(abi.encodePacked(DOMAIN_*, bytes8(blockNumber), <fields>))
// (HypersnapBridge.sol L281-285 for UPGRADE, L325-329 for UPGRADE_CANCEL,
// L363-366 for PAUSE; mirrored in bridge_payload.rs upgrade_digest L133,
// upgrade_cancel_digest L147, pause_digest L158). Neither block.chainid nor
// address(this) appears in any universal preimage, so one owner-group
// signature verifies on EVERY deployment forever. CreateX CREATE3 also yields
// the SAME proxy address on every chain, so even address(this) would not
// disambiguate — only block.chainid would, and it is absent. The only stated
// defense is the per-deployment monotonic `latestBlock` watermark, which an
// attacker-relayer can keep stale on a low-traffic sibling deployment.
//
// EXPECTED RESULT:
//   - On commit cab225f (vulnerable): BOTH tests FAIL. The replayed signature
//     is accepted on the second deployment, so the vm.expectRevert assertions
//     do not fire (the calls succeed) and the post-conditions diverge.
//   - After the recommended fix (bind block.chainid AND address(this) / a
//     per-deployment id into every universal digest on both the Solidity and
//     bridge_payload.rs sides, re-pinning the cross-side vectors): BOTH tests
//     PASS. A signature minted for deployment A no longer verifies on B.
//
// STATUS: UNVERIFIED
// ============================================================================

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract F045_UniversalSigCrossDeploymentReplay is Test {
    // --- Domain tags (must match HypersnapBridge + bridge_payload.rs) ------
    bytes32 internal constant DOMAIN_UPGRADE        = keccak256("HYPERSNAP_UPGRADE_V1");
    bytes32 internal constant DOMAIN_UPGRADE_CANCEL = keccak256("HYPERSNAP_UPGRADE_CANCEL_V1");

    // --- Keys --------------------------------------------------------------
    // OWNER_PK is the shared off-chain threshold group key `O`; every canonical
    // deployment is initialized with the SAME owner address derived from it.
    uint256 internal constant OWNER_PK    = 0xA11CE;
    uint256 internal constant ATTACKER_PK = 0xBAD;

    address internal ownerEOA;
    address internal attackerEOA;

    // Two sibling deployments sharing owner group key `O`, distinguished only
    // by the EVM chainId active at the time each is exercised.
    HypersnapBridge internal bridgeA; // busy chain (chainId A)
    HypersnapBridge internal bridgeB; // low-traffic chain holding live custody (chainId B)

    uint256 internal constant CHAIN_A = 1;       // e.g. Ethereum mainnet
    uint256 internal constant CHAIN_B = 8453;    // e.g. Base — lagging deployment

    // Implementation candidate proposed on A and replayed onto B.
    HypersnapBridge internal implX;

    function setUp() public {
        ownerEOA    = vm.addr(OWNER_PK);
        attackerEOA = vm.addr(ATTACKER_PK);

        // Deploy A under chainId A.
        vm.chainId(CHAIN_A);
        bridgeA = _deployProxy();

        // Deploy B under chainId B — SAME owner group key, different chain.
        vm.chainId(CHAIN_B);
        bridgeB = _deployProxy();

        // A separately deployed, UUPS-shaped implementation. Reusing the bridge
        // bytecode means proxiableUUID() returns the canonical IMPLEMENTATION
        // slot, so the L298-304 compatibility check is satisfied — exactly the
        // structural-only guard the trace notes any UUPS-shaped impl passes.
        implX = new HypersnapBridge();
    }

    function _deployProxy() internal returns (HypersnapBridge) {
        HypersnapBridge impl = new HypersnapBridge();
        bytes memory initCalldata = abi.encodeCall(
            HypersnapBridge.initialize,
            (ownerEOA, "Hypersnap", "SNAP")
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initCalldata);
        return HypersnapBridge(address(proxy));
    }

    // --- Digest reproducers (byte-for-byte with the contract today) --------
    // These intentionally omit chainId + address, mirroring the vulnerable
    // preimage. After the fix lands, the contract will demand additional bound
    // fields and these signatures will no longer recover to `ownerAddress` on
    // deployment B — which is precisely what flips both tests to PASS.

    function _upgradeDigest(uint64 blockNumber, address newImpl) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(DOMAIN_UPGRADE, bytes8(blockNumber), bytes20(newImpl)));
    }

    function _upgradeCancelDigest(uint64 blockNumber, address pendingImpl) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(DOMAIN_UPGRADE_CANCEL, bytes8(blockNumber), bytes20(pendingImpl)));
    }

    function _sign(bytes32 digest, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // =======================================================================
    // TEST 1 — testUniversalSigBoundToDeployment
    //
    // ASSERTION: a universal proposeUpgrade signature minted once by the owner
    // group and accepted on deployment A (chainId A) MUST be rejected when the
    // identical bytes are replayed onto deployment B (chainId B, lower
    // watermark). Secure behavior: the replay reverts with BadOwnerSignature
    // (the digest no longer recovers to B's owner because it now binds B's
    // chainId/address) and B has NO pending implementation.
    //
    // ON cab225f: the digest omits chainId + address, so the same signature
    // recovers to ownerAddress on B; the watermark gate `4000 > 100` passes;
    // implX becomes pending on B. The expectRevert never fires (call succeeds)
    // and the no-pending assertion fails. => TEST FAILS (vulnerable).
    // =======================================================================
    function testUniversalSigBoundToDeployment() public {
        uint64 proposeBlock = 4000;

        // Owner group signs the universal upgrade payload ONCE. On the
        // vulnerable build this single signature is valid on every deployment.
        bytes memory sigO = _sign(_upgradeDigest(proposeBlock, address(implX)), OWNER_PK);

        // --- Deployment A (busy chain): legitimately apply the proposal. ----
        vm.chainId(CHAIN_A);
        bridgeA.proposeUpgrade(proposeBlock, address(implX), sigO);
        assertEq(bridgeA.pendingImplementation(), address(implX), "A: proposal should land normally");
        assertEq(bridgeA.latestBlock(), proposeBlock, "A: watermark advances");

        // --- Deployment B (lagging chain): attacker replays the SAME bytes. -
        // B has never consumed any signature, so latestBlock == 0 < 4000 and
        // the watermark gate offers no protection.
        vm.chainId(CHAIN_B);
        assertLt(bridgeB.latestBlock(), proposeBlock, "precondition: B is watermark-lagging");

        vm.prank(attackerEOA);
        // SECURE expectation: replay onto a different deployment must revert.
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridgeB.proposeUpgrade(proposeBlock, address(implX), sigO);

        // And B must remain clean — no attacker-driven pending upgrade.
        assertEq(
            bridgeB.pendingImplementation(),
            address(0),
            "SECURE: a sig minted for A must not land a pending upgrade on B"
        );
        assertEq(bridgeB.latestBlock(), 0, "SECURE: B watermark must not advance on a rejected replay");
    }

    // =======================================================================
    // TEST 2 — testSupersededActionDoesNotReplayOnLaggingDeployment
    //
    // ASSERTION: a propose-then-cancel sequence on A whose NET effect is
    // "cancelled / no pending upgrade" must not be resurrectable on a lagging
    // deployment B by replaying the (still signature-valid) propose bytes while
    // withholding the cancel. Secure behavior: the replayed propose reverts on
    // B (deployment-bound digest) and B never ends up with a pending impl.
    //
    // ON cab225f: cancellation mutates only A's local state; the propose sig
    // stays valid forever and is not chain/address-bound, so replaying it on B
    // (watermark still 100) lands implX as pending on B — the exact superseded
    // action the cancel was meant to neutralize. expectRevert never fires.
    // => TEST FAILS (vulnerable).
    // =======================================================================
    function testSupersededActionDoesNotReplayOnLaggingDeployment() public {
        uint64 proposeBlock = 4000;
        uint64 cancelBlock  = 4001;

        // Owner group signs BOTH the propose and the superseding cancel. Both
        // are universal on the vulnerable build.
        bytes memory proposeSig = _sign(_upgradeDigest(proposeBlock, address(implX)), OWNER_PK);
        bytes memory cancelSig  = _sign(_upgradeCancelDigest(cancelBlock, address(implX)), OWNER_PK);

        // --- Deployment A: propose, then cancel. Net effect: nothing pending.
        vm.chainId(CHAIN_A);
        bridgeA.proposeUpgrade(proposeBlock, address(implX), proposeSig);
        bridgeA.cancelUpgrade(cancelBlock, address(implX), cancelSig);
        assertEq(bridgeA.pendingImplementation(), address(0), "A: net effect is cancelled");
        assertEq(bridgeA.latestBlock(), cancelBlock, "A: watermark advanced past the cancel");

        // --- Deployment B: attacker replays ONLY the superseded propose,
        // withholding the cancel. B is still at watermark 0.
        vm.chainId(CHAIN_B);
        assertLt(bridgeB.latestBlock(), proposeBlock, "precondition: B is watermark-lagging");

        vm.prank(attackerEOA);
        // SECURE expectation: the cross-deployment replay must revert.
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridgeB.proposeUpgrade(proposeBlock, address(implX), proposeSig);

        // SECURE post-condition: a sequence whose net effect was "cancelled"
        // must NOT leave a live pending upgrade on the lagging deployment.
        assertEq(
            bridgeB.pendingImplementation(),
            address(0),
            "SECURE: superseded propose must not resurrect on lagging B"
        );
        assertEq(
            bridgeB.pendingUpgradeEffectiveAt(),
            0,
            "SECURE: no upgrade timer should be armed on B"
        );
    }
}
