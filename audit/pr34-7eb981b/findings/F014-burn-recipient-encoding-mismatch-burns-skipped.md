---
finding_id: F014
title: A burn to `bytes32(uint256(fid))`, the encoding the repo's own tests use, destroys the tokens on the EVM side, and the watcher skips it, so
severity: medium
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.8
poc:
  path: poc/H011
  kind: null
  result: 2/2
related_findings:
- F016
---
# F014 — A burn to `bytes32(uint256(fid))`, the encoding the repo's own tests use, destroys the tokens on the EVM side, and the watcher skips it, so the FID is never credited

> **Status (2026-11-04):** Severity **Medium** (validated 0.8, HAS_CAVEATS). PoC: poc/H011 (2/2). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity **Medium** (validated from High). Funds are frozen, not lost permanently: a coordinated node release can recover them. PoC: poc/H011.


- **Category:** loss-of-funds / spec-gap
- **Specialist:** shard0-ledger-state · attack class: inbound-burn-double-credit-or-loss · task H011
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Finding

`HypersnapBridge.burn` and `HypersnapBridgeV2.burn(uint256 amount, bytes32 hypersnapRecipient)`
(`HypersnapBridge.sol:378-386`, `HypersnapBridgeV2.sol:317-328`) accept any `bytes32`. They
call `_burn(msg.sender, amount)` and emit `Burned(burnId, sender, hypersnapRecipient, amount,
chainId)`. The contract has no recipient validation.

The node's watcher decodes the recipient in `decode_hypersnap_recipient`
(`src/chain/bridge_burn_watcher.rs:304-317`):

```rust
if raw[8..].iter().any(|&b| b != 0) { return None; }   // FID must be in the FIRST 8 bytes
let fid = u64::from_be_bytes(raw[..8]);
if fid == 0 { return None; }
```

When the result is `None`, `scan_range` logs a warning and `continue`s
(`bridge_burn_watcher.rs:248-258`). The burn is never written to `BridgeBurnStore`, so it never
becomes an `InboundBurn`. The watermark then moves past the block (`advance_watermark`,
`:190`), and a restart re-scans only `REORG_GUARD = 32` blocks. The watcher never sees the
event again.

The natural Solidity encoding of an FID is `bytes32(uint256(fid))`, which right-aligns it: FID
12345 becomes `0x00…003039`, with the non-zero bytes at the end. **The repo itself uses this
form** in both Solidity burn suites:

- `contracts/test/HypersnapBridgeV2.t.sol:906`: `bytes32 internal constant FID = bytes32(uint256(12_345));`
- `contracts/test/Burn.t.sol:11`: `bytes32 internal constant TARGET_FID = bytes32(uint256(42));`

`test_burn_eventIsV1Compatible` (`HypersnapBridgeV2.t.sol:938-954`) even says it is checking the
layout that "the node's watcher decodes", and it uses this encoding. The watcher rejects every
one of these burns.

Only node-internal places document the left-aligned convention: the watcher module doc, the
`encode_hypersnap_recipient` helper, and comments in `proto/definitions/hyper.proto:137-139,
173-176`. The following say nothing about it:

- the FIP (§13.6 only says `burn(amount, hypersnapRecipient)`),
- the contract NatSpec,
- `contracts/README.md:74-81`,
- the deployer UI's `BurnRunner`, which labels the field "32-byte hex; opaque to bridge" and
  accepts any 66-character hex string (`contracts/deployer-ui/src/components/BurnRunner.tsx:93,182`),
- the wallet crate, which has no EVM burn builder.

**Result.** The ERC-20 supply drops and the user's balance is burned on Ethereum/Optimism.
Shard 0 never credits anyone, and `Meta::BridgedIn` never rises. No consensus path recovers
the value: `bridge_actions` has only UPGRADE, CANCEL and PAUSE (`bridge_actions.rs:19-21`), and
the skipped burn is not in any store that a later release could replay. Recovery would need a
new node release that re-scans history with a different decoder and applies a one-off credit
(effectively a hard fork).

The same silent-skip path also applies to `hypersnapRecipient == 0` and to any other non-FID
layout, such as an EVM address padded into `bytes32`.

## Proof of concept

`poc/H011/test/H011RecipientEncoding.t.sol` runs against the unmodified `HypersnapBridgeV2.sol`
(byte-identical to `contracts/src`) through the repo's own `BridgeV2Test`
harness. It burns 2 tokens with `bytes32(uint256(12_345))`, reads `topics[3]` of the emitted
`Burned` log (the topic the watcher reads), and runs a line-for-line Solidity port of
`decode_hypersnap_recipient` on it:

```
[PASS] test_leftAlignedFid_isCredited()                     // bytes32(bytes8(uint64(12345))) -> FID 12345
[PASS] test_rightAlignedFid_isBurnedButSkippedByWatcher()   // decoder returns None; totalSupply -2_000_000
```

Output: `poc/H011/H011-forge-output.txt`. Run it with
`cd poc/H011 && forge test --match-contract H011 -vv`.

## Red-team walk

1. *"Users are expected to use `encode_hypersnap_recipient`."* That is a Rust helper inside the
   node crate. No user-facing artefact (spec, contract, README, UI) states the layout, and the
   only Solidity examples in the repo use the opposite one.
2. *"The watcher logs a warning, so operators can fix it."* The log does not lead to a credit.
   No consensus path credits a burn that is not in the watchers' stores.
3. *"The amount is small / it is dust."* V2 enforces `MIN_BRIDGE_AMOUNT` (1 token), and there is
   no upper bound. The user loses the whole burn.
4. *"Every validator would skip it the same way, so there is no consensus divergence."* Correct.
   This is purely a loss, not a fork.
5. *"The encoding is opaque to the bridge by design."* An opaque field is fine only if the
   consumer documents its layout and can handle any value. Here the consumer drops values it
   does not understand and gives no refund.
6. *"The decoder could be changed to accept right-aligned FIDs."* That is the fix. At this
   commit it rejects them.
7. *"Is the PoC decoder faithful?"* It ports `bridge_burn_watcher.rs:304-317` exactly: trailing
   24 bytes zero, FID from the first 8 bytes big-endian, non-zero. The Rust unit test
   `decode_rejects_non_zero_trailing_bytes` confirms the same behaviour.
8. *Trust assumptions:* none. Honest validators and an honest RPC still lose these burns.

## Recommendation

Pick one canonical layout and enforce it at the source:

- **Preferred:** make the node accept the natural `bytes32(uint256(fid))` (FID = low 8 bytes,
  high 24 zero). Also validate on-chain in `burn`: `require(uint256(r) >> 64 == 0 &&
  uint64(uint256(r)) != 0)` (or `burn(uint256 amount, uint64 fid)`). A malformed recipient then
  reverts instead of burning.
- Whatever layout is chosen, state it in FIP §13.6, the contract NatSpec and the README, and fix
  the two Solidity test constants.
- Optionally, have the watcher record undecodable burns, for example as "unroutable" in the
  store, so that a governance or refund path can exist.

## Evidence

- `src/chain/bridge_burn_watcher.rs:20-27, 248-258, 190, 304-326`
- `contracts/src/HypersnapBridgeV2.sol:316-328`; `contracts/src/HypersnapBridge.sol:374-386`
- `contracts/test/HypersnapBridgeV2.t.sol:906, 936-954`; `contracts/test/Burn.t.sol:11`
- `contracts/deployer-ui/src/components/BurnRunner.tsx:93, 182`
- `poc/H011/test/H011RecipientEncoding.t.sol`, `poc/H011/H011-forge-output.txt`
