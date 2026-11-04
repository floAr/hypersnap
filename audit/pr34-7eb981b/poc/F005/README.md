# F005 PoC: one V1 owner key mints without limit, and one signature at `blockNumber = 2^64-1` disables all recovery

Target: farcasterorg/hypersnap @ `7eb981b` (`contracts/src/HypersnapBridge.sol`). Solidity only, Foundry on Windows.

## Environment and commands

- `forge 1.2.3` (Windows), solc 0.8.24, `optimizer_runs = 1000` (the repo's `foundry.toml`).
- Scratch project: `git archive 7eb981b contracts` into a scratch directory. `lib/` was copied from `poc/H003/lib`: OZ contracts and contracts-upgradeable v5.1.0, forge-std. The archive has no submodules. `src/` and `test/utils/` are unmodified. The only addition is `test/F005V1OwnerKey.t.sol`. The audit checkout was not modified.
- Test file copy: `F005V1OwnerKey.t.sol` (here).
- Run: `cd <scratch>/contracts && forge test --match-contract F005 -vv`
- Output: `F005-test-output.txt`. As a sanity check, the repo's whole suite also passes in the same scratch project (268 passed, 2 skipped).

## Fixture

- The V1 proxy is deployed as in `BridgeTest.setUp` (ERC1967 proxy, `initialize(ownerEOA, ...)`). The owner is the single key `OWNER_PK`, as with the default `Deploy.s.sol` path (`genesisOwner = msg.sender`).
- An honest history runs first in most tests: one genuine root at block 100 that pays `holder` 1,000 SNAP.
- `EvilImpl` is a UUPS-compatible implementation (it inherits `UUPSUpgradeable`, so it passes the `proxiableUUID` check in `proposeUpgrade`). It can move any holder's balance by writing the ERC-7201 ERC20 storage slot directly.
- "Compromised key" and "honest key" are the same `OWNER_PK`. That models theft, where the honest operators still hold the key. The rotation target is `NEW_OWNER_PK`.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `test_F005_singleSig_mintsUnbounded_noDelay` | One owner signature over a root with a fake leaf mints `1e30` units to the attacker in the same block. `totalSupply` grows by `1e30`. Nothing caps or delays it. | **RED** (pass, reproduced) |
| `test_F005_singleRootSig_mintsOnTwoChains` | The root signature is universal. One signature over a root with a leaf for chain 1 and a leaf for chain 8453 mints `1e30` on both deployments. | **RED** (pass) |
| `test_F005_maxBlockPoison_upgradeUnstoppable_andSeizesHolders` | The key calls `proposeUpgrade(2^64-1, evil)`. After that, `rotateOwner` (to a fresh key), `cancelUpgrade` and `pause` all revert `StaleBlock(MAX, MAX)`. 48h later a third party runs `executeUpgrade`. `version() == 666`, and the evil implementation moves the honest holder's 1,000 SNAP to the attacker without approval. | **RED** (pass) |
| `test_F005_prePoisonPause_onlyDelaysExecution` | A defensive pause that lands *before* the poison does not help. `proposeUpgrade` is not pause-gated, re-pausing reverts `StaleBlock`, and `executeUpgrade` succeeds when the 72h pause expires. | **RED** (pass) |
| `test_F005_honestRootAtMax_freezesAllGovernance` | An honest root signed at `2^64-1` (operator mistake). Every later root reverts `RootMismatch`. `proposeUpgrade`, `pause` and `rotateOwner` revert `StaleBlock`. Existing balances still transfer and `burn`. | **RED** (pass) |
| `test_control_nonOwnerRootRejected` | A non-owner key gets `BadOwnerSignature`. | pass (control) |
| `test_control_recoveryWorksWithoutPoison` | The documented recovery (propose evil at 10, rotate at 11, new owner cancels at 12) works when the malicious proposal uses a normal block number. | pass (control) |
| `test_control_maxMinusOne_stillCancellable` | A proposal at `2^64-2` can still be cancelled at `2^64-1`. Only the exact maximum fully locks out the defender. | pass (control) |
| `test_control_msTimestampJump_recoverable` | A wrong-unit jump to a millisecond timestamp (`1.76e12`) is recoverable. The owner keeps signing above it (pause, propose, cancel all succeed). | pass (control) |
| `test_control_executeBeforeDelayReverts` | `executeUpgrade` one second before `UPGRADE_DELAY` reverts. The timer itself works. | pass (control) |

**All 10 tests pass. Claims 1 and 2 of the finding reproduce, and claim 3 reproduces for a value at `2^64-1`.** The controls show that the signature check, the timer and the documented recovery work in the absence of the poison. The defect is the uncapped shared watermark, plus the absence of any mint cap or delay.

## Correction to the finding (claim 3)

The finding says that an honest operator freezes the contract by signing "a millisecond timestamp or a wrong unit". `test_control_msTimestampJump_recoverable` shows that is not so. Any value well below `2^64-1` only moves the watermark forward, and the owner can keep signing above it. Off-chain tooling that keys on real Hypersnap heights would stall until it learns the new floor, but the contract stays governable. The permanent freeze needs a value at `2^64-1` (or within a few steps of it), for example a `-1` / `u64::MAX` sentinel passed to `bridge-ceremony`, whose `block` arguments are unbounded `u64`.

## What was exercised vs source-only

- Exercised: the real `HypersnapBridge` V1 behind a real ERC1967 proxy, covering `claim` (root advance and Merkle check), `rotateOwner`, `proposeUpgrade` (including the `proxiableUUID` check), `cancelUpgrade`, `pause`, `executeUpgrade` and `burn`.
- Source-only:
  - The genesis owner is an EOA in production. `Deploy.s.sol:89-95` defaults to `msg.sender`. No DKLS23 code is in the tree.
  - The minted supply enters the Hypersnap ledger through `inbound_burn` (`src/chain/shard0/ledger.rs:751-770`). The Rust side is not run here.
  - The key compromise or operator mistake itself.
- Not reproduced: V2 interaction. The V2 path (F004) is a separate PoC.
