---
finding_id: F003
title: The spec (§13.5/§13.9) leaves the escrow lock ID, the lock-ID field widths, the leaf domain tag form and the v1/v2 `claimed` namespace
severity: info
status: pending-validation
related_findings:
- F007
---
# F003 — The spec (§13.5/§13.9) leaves the escrow lock ID, the lock-ID field widths, the leaf domain tag form and the v1/v2 `claimed` namespace undefined, and there is no Rust-side pinned lock-leaf vector

- **Severity:** Informational (spec-divergence; the code is internally consistent at `7eb981b`)
- **Specialist:** solidity-bridge · attack class: cross-side-encoding-asymmetry · task H002
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Summary

The lock leaf is byte-identical between Rust and Solidity (see "Verified" below). The spec that
an independent implementation would follow has four gaps. Each one leads to a lock that cannot
be claimed or to a broken leaf if implemented as written:

1. **Escrow lock ID is undefined.** §13.5 (spec line 1217) defines only the `TOKEN_LOCK` ID
   `keccak256("hypersnap-lock-v1" || sender_fid || nonce)` and the `QCT_LOCK` ID, and says
   "Two locks cannot have the same ID". §13.9 (line 1297) says that `TOKEN_ESCROW_BRIDGE`
   "makes a `TokenLockState` and follows the outbound bridge flow" with no ID rule. The code
   invents `keccak256("hypersnap-escrow-lock-v1" || escrow_id || nonce)`
   (`src/chain/shard0/ledger.rs:535-544`). Its comment explains why: escrow messages have
   `fid = 0`, so the `TOKEN_LOCK` form collides between escrows (each escrow nonce starts at 1,
   `ledger.rs:484-491`). A spec-conformant node would fail the second escrow bridge at
   `"lock ID already used"` (`ledger.rs:575-578`). Its leaf would also differ from this node's,
   which splits consensus on `bridge_lock_root`.
2. **Field widths are not stated.** The spec writes `sender_fid || nonce` and
   `... || chain_id || recipient || amount` without widths. The code uses u64 BE / u64 BE
   (`ledger.rs:527-533`), and u8 family, u32 BE chain ID, 20-byte recipient, and u256 BE
   amount (`crates/hypersnap-crypto/src/bridge_payload.rs:243-258`,
   `contracts/src/HypersnapBridgeV2.sol:406-421`). Only the Solidity NatSpec gives the widths.
3. **`DOMAIN_LOCK_LEAF` form.** The spec writes `keccak256(DOMAIN_LOCK_LEAF || lock_id || ...)`
   (line 1201). Both implementations prepend `keccak256("HYPERSNAP_LOCK_LEAF_V1")` (32 bytes),
   not the 22-byte string. The spec does not say which.
4. **Shared `claimed` namespace with v1 retro claims.** V2 marks lock IDs in the v1 `claimed`
   mapping (`HypersnapBridgeV2.sol:137-138`, `:299`, `:307`). v1 retro lock IDs come from
   arbitrary ceremony JSON (`crates/hypersnap-bridge-ceremony/src/main.rs:81`, `:297-315`), and
   no in-tree producer or rule keeps them out of the `"hypersnap-lock-v1"` /
   `"hypersnap-escrow-lock-v1"` ID space. If a retro lock ID were ever derived with the v2 scheme
   (for example `fid`/`nonce`-based), the v2 lock with that ID would be permanently unclaimable
   (`AlreadyClaimed`). Its tokens were already debited on Hypersnap.

There is also no Rust test that pins the hex of the lock leaf. `lock_leaf_evm_is_stable`
(`bridge_payload.rs:397-414`) recomputes the same concatenation inside the test, which is
tautological. The only pinned value is Solidity-side
(`contracts/test/CrossSideDigests.t.sol:166-184`), and it recomputes the leaf with
`abi.encodePacked` instead of calling `HypersnapBridgeV2.lockLeaf`.

## Attacker model / impact

No attacker today. The risks are an alternative client, or a future change, that follows the
spec or edits one side only. That gives either a consensus split on `bridge_lock_root`, or
locks whose leaves the bridge never accepts. For locks, that means funds debited on Hypersnap
and never minted. Item 4 is a latent fund-loss trap that depends on how the retro lock IDs
were chosen.

## Verified (holds at 7eb981b)

- Leaf parity: `poc/H002/leaf_parity.sh` builds the Rust layout byte by byte (121 bytes) and
  gets `0x946e398b…818996`, which equals the Solidity pinned vector.
- `amount` u64 → U256 with no truncation, and `uint256` on Solidity. The recipient must be
  exactly 20 bytes (`ledger.rs:562-564`). The chain ID is u32 on both sides, and V2 compares it
  with `block.chainid` without truncation (`BridgeV2.sol:296`).
- Lock-ID uniqueness: the account nonce is strictly next (`ledger.rs:43-53`), the escrow nonce
  is strictly next (`:484-491`), and escrow IDs are prefix-free (`0x01‖20 B` vs `0x02‖32 B`,
  `keys.rs:114-127`). The two lock-ID domains differ from their first bytes onwards. A
  duplicate is rejected (`ledger.rs:575-578`).
- Second preimage: the leaf preimage is 121 bytes and internal nodes are 64 bytes, and `claim`
  computes the leaf itself, so no internal node can be passed as a leaf.

## Fix

Add to §13.5: the exact widths, the hashed-tag form of `DOMAIN_LOCK_LEAF`, and the escrow lock
ID `keccak256("hypersnap-escrow-lock-v1" || escrow_id || u64_be nonce)` with the `escrow_id`
encoding of §13.9. State that v1 retro lock IDs must use a separate domain, such as
`"hypersnap-retro-lock-v1"`, and check that for the actual retro set before V2 ships. Add a Rust
test that asserts `lock_leaf_evm(...) == 0x946e398b…818996`, and change the Solidity test to call
`v2.lockLeaf`.
