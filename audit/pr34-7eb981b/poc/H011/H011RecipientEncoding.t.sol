// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {BridgeV2Test} from "./utils/BridgeV2Test.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";

/// H011 / F014: the node watcher's recipient decoder vs the encoding the
/// repo's own Solidity tests use for `hypersnapRecipient`.
contract H011RecipientEncoding is BridgeV2Test {
    address internal alice = makeAddr("alice");

    function setUp() public override {
        super.setUp();
        _upgradeToV2();
        bytes32 leaf = _leafV2(keccak256("fund"), alice, 10_000_000);
        _anchor(PIVOT + 1, 1, leaf);
        v2.claim(keccak256("fund"), alice, 10_000_000, uint32(block.chainid), new bytes32[](0));
    }

    /// Port of `decode_hypersnap_recipient` (src/chain/bridge_burn_watcher.rs:300-313):
    /// trailing 24 bytes must be zero, FID = first 8 bytes BE, FID != 0.
    function decodeLikeWatcher(bytes32 r) internal pure returns (bool ok, uint64 fid) {
        for (uint256 i = 8; i < 32; i++) {
            if (r[i] != 0) return (false, 0);
        }
        fid = uint64(bytes8(r));
        ok = fid != 0;
    }

    function _burnAndDecode(bytes32 recipient) internal returns (bool ok, uint64 fid) {
        vm.recordLogs();
        vm.prank(alice);
        v2.burn(2_000_000, recipient);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        Vm.Log memory l = logs[logs.length - 1];
        assertEq(l.topics[0], HypersnapBridgeV2.Burned.selector);
        return decodeLikeWatcher(l.topics[3]); // watcher reads topics[3]
    }

    /// The form used by contracts/test/HypersnapBridgeV2.t.sol:906 and Burn.t.sol:11.
    function test_rightAlignedFid_isBurnedButSkippedByWatcher() public {
        uint256 supplyBefore = v2.totalSupply();
        (bool ok,) = _burnAndDecode(bytes32(uint256(12_345)));
        assertFalse(ok, "watcher would skip this burn");
        assertEq(v2.totalSupply(), supplyBefore - 2_000_000, "tokens destroyed on EVM");
        assertEq(v2.balanceOf(alice), 8_000_000);
    }

    /// The form `encode_hypersnap_recipient` produces.
    function test_leftAlignedFid_isCredited() public {
        (bool ok, uint64 fid) = _burnAndDecode(bytes32(bytes8(uint64(12_345))));
        assertTrue(ok);
        assertEq(fid, 12_345);
    }
}
