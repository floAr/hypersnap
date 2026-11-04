# F004 PoC: a retired validator set keeps unbounded authority on `HypersnapBridgeV2`

Target: farcasterorg/hypersnap @ `7eb981b`. Solidity only, Foundry on Windows.

## Environment and commands

- `forge 1.2.3` (Windows), solc 0.8.24, `optimizer_runs = 1000` (the repo's `foundry.toml`).
- Scratch project: `git archive 7eb981b contracts` into a scratch directory. `lib/` was copied from `poc/H003/lib`: OZ contracts and contracts-upgradeable v5.1.0, forge-std 1.17.0. The archive has no submodules. `src/` and `test/utils/` are unmodified. The only addition is `test/F004RetiredSet.t.sol`. The audit checkout was not modified.
- Test file copy: `F004RetiredSet.t.sol` (here).
- Run: `cd <scratch>/contracts && forge test --match-contract F004 -vv`
- Compile plus run took about 10 s.
- Output: `F004-test-output.txt`.

## Fixture

- The v1 proxy is deployed as in `BridgeTest.setUp`. The v1 owner then runs its last `proposeUpgrade` -> `UPGRADE_DELAY` -> `executeUpgrade` to the real `HypersnapBridgeV2`, followed by `initializeV2(setRoot(1), 4)`.
- **`SigningSetVerifier`** (in the test file) implements `ICertificateVerifier`. It checks the interface's three-part statement against **real signatures**:
  1. The proof carries the ordered member list, and `keccak` of that list must equal `setRoot`.
  2. `totalWeight == |members|` (weight 1 each, `validators.rs:126-137`). The bitmap is exact (correct length, zero padding). The signer count must satisfy a strict `3w > 2W`.
  3. Every set bit needs an ECDSA signature by that member over `keccak("hypersnap-consensus-vote-v1" || d)`.

  ECDSA via `vm.sign` stands in for Falcon-512. Like the interface statement, the verifier ignores `epoch`. So it is a **sound** verifier: it returns true iff more than 2/3 of the set committed in `setRoot` really signed `d`. This is stricter than the H003 mock, which accepted a hash commitment that the test issued.
- Validator sets are disjoint key sets: `set(1)` = 4 keys (bootstrap-sized), `set(2)` = 5, and `set(3..5)` = 7 each. The retired set therefore has no member in the current set.
- Honest bridge history: the handoffs 1->2 and 2->3 are boundary headers at `first(e)` with an `EpochBoundaryRecord`, signed by all of `set(e)`. An anchor follows at `first(3)+10`, signed by `set(3)`. `PIVOT = 25,000,000` and `EPOCH_LENGTH = 36,000` (the `BridgeV2Test` values). `_epochOf(h)` reproduces the node rule `epoch.rs:30-34`.
- The "attacker" is **3 of the 4 retired `set(1)` keys** (or 4 of the 5 `set(2)` keys). It signs genuine certificates over headers that declare their own epoch to be 1 (or 2) at heights in later epochs.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `test_F004_retiredSet1_anchorsForgedRoot_andMints` | Path 1. After the handoff to epoch 3, 3/4 of `set(1)` certify `{epoch: 1, height: first(3)+11}`, where the node says `epoch_of = 3`, with a forged lock root. `advanceRoot` accepts it, and `claim` mints `1e30` to the attacker. | **RED** (pass, reproduced) |
| `test_F004_retiredSet1_freezesAnchorsForever` | Path 2. Retired `set(1)` anchors at `height = 2^64-1`. The current `set(3)` (all 7 keys) then hits `StaleHeight(MAX, h)`. The honest handoff 3->4 still succeeds but never anchors again, so `latestLockRoot` stays the attacker's root. | **RED** (pass) |
| `test_F004_retiredSet1_unstoppableUpgrade` | Path 3. Retired `set(1)` calls `proposeUpgrade` with an evil implementation at `height = 2^64-1`. The current `set(3)` `pause` and `cancelUpgrade` both revert with `StaleAction(MAX, h)`. After `UPGRADE_DELAY`, `executeUpgrade` installs the evil implementation (`version() == 3`). | **RED** (pass) |
| `test_F004_retiredSet2_stillAuthorisesAfterTwoMoreHandoffs` | The attack is not specific to the bootstrap set. After the handoffs reach epoch 5, 4/5 of retired `set(2)` anchor a root at an epoch-5 height labelled epoch 2. | **RED** (pass) |
| `test_control_currentSetAnchors` | The current `set(3)` anchors normally at an epoch-3 height. | pass (control) |
| `test_control_currentSetCanPauseAndCancel` | Without the attack, the §13.7 defence works: `set(3)` proposes an upgrade, cancels it (`pendingImplementation == 0`) and pauses. | pass (control) |
| `test_control_retiredKeysRejectedUnderCurrentEpochLabel` | `set(1)` keys on a header labelled epoch 3 get `BadCertificate`, because the members are not in `setRoot[3]`. | pass (control) |
| `test_control_retiredSetBelowQuorumRejected` | 2/4 retired keys get `BadCertificate` (3·2 > 2·4 is false). | pass (control) |
| `test_control_signaturesForOtherHeaderRejected` | Signatures over a different header get `BadCertificate`, because the digest binds `keccak(header)`. | pass (control) |
| `test_control_retiredSetStaleHeightRejected` | A retired set at `height == latestHeight` gets `StaleHeight`. The watermark is the only height check. | pass (control) |
| `test_control_unknownEpochRejected` | An epoch with no stored root gets `UnknownEpoch(9)`. | pass (control) |
| `test_control_outsiderKeysRejected` | Keys from no set get `BadCertificate`. | pass (control) |

**All 12 tests pass, and all three paths reproduce with a sound, signature-checking verifier.** The contract correctly rejects the following: wrong set for the declared epoch, sub-quorum, digest mismatch, stale height, unknown epoch and outsiders. It does **not** check the declared `epoch` against `height`. Old `setRoot`s never expire, and both `uint64` watermarks are uncapped. So a quorum of any retired set has the same authority as the current set, permanently.

## What was exercised vs source-only

- Exercised: the real `HypersnapBridgeV2` behind the real ERC1967 proxy after the real v1->v2 upgrade flow, covering `advanceEpoch`, `advanceRoot`, `claim`, `proposeUpgrade`, `pause`, `cancelUpgrade`, `executeUpgrade`, `_verifyCertificate`, `_applyAction`, and the `HypersnapProto` header and record decoders (including a `2^64-1` varint height).
- Modelled: the CERT-STARK verifier, which does not exist at 7eb981b. The model follows the statement in `ICertificateVerifier.sol`, with ECDSA instead of Falcon-512 and a flat keccak over the member list instead of the Keccak Merkle `set_root`. Neither substitution affects the result, because the defect is in what the bridge passes to the verifier (a self-declared `epoch`), not in how the verifier checks it.
- Source-only:
  - Reachability. V2 is not deployed, the verifier is absent and outbound is off (`bridge_outbound_activation_epoch: u64::MAX`), so this is not exploitable at 7eb981b.
  - The collusion or key-compromise precondition on the retired set.

## Caveats

- Disjoint sets are the cleanest "retired" case. Overlapping real sets do not change the result: what matters is that more than 2/3 of `set(e)` signed, for any `e` that has a stored root.
- The "old roots stay valid" behaviour is spec-intended (§13.4, `test_advanceRoot_oldEpochStaysValid`). The PoC shows the part that is not intended: the missing `epoch(h)` binding plus the uncapped watermarks.
- Compared with `poc/H003` (the original finding PoC), the new parts are the signature-checking sound verifier, the controls showing that the current set and the §13.7 defence work in the absence of the attack, and the retired `set(2)` case.
