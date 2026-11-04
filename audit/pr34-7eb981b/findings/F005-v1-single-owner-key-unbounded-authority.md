---
finding_id: F005
title: 'V1 bridge: one ECDSA key has instant, uncapped mint authority, and a single signature at `blockNumber = 2^64−1` disables `pause`'
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F005
  kind: foundry
  result: 10/10
related_findings:
- F002
- F004
- F006
---
# F005 — V1 bridge: one ECDSA key has instant, uncapped mint authority, and a single signature at `blockNumber = 2^64−1` disables `pause`, `cancelUpgrade` and `rotateOwner`, so the documented compromise recovery and the 48h upgrade timelock do not protect anything

> **Status (2026-11-04):** Severity **High** (validated 0.85, HAS_CAVEATS). Preconditions: V1 owner key (single EOA by default, Deploy.s.sol:89-95) is compromised or misused; Honest-freeze variant needs an operator to sign a universal payload at blockNumber = 2^64-1 (e.g. -1/MAX sentinel); values well below MAX are recoverable; Planned DKLS23 threshold owner is not in the tree; if built and used, compromise would need a validator threshold. PoC: poc/F005 (foundry, 10/10). State: validated. Notes: owner applied both body corrections (claim 3 scoped to 2^64-1; red-team item 6 rating)

> **Status 2026-11-04 (post-validation):** Severity **High** (recalibrated 2026-11-04 from Medium; impact if shipped). See the internal validation notes.


- **Category:** trust / centralisation; upgrade-race; spec divergence (the spec states no V1 trust assumption; the code and README describe a DKLS23 threshold key that is not in the tree).
- **Specialist:** solidity-bridge · task H004
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** `poc/H004/test/H004.t.sol`, tests `test_F005_singleSigUnlimitedMint_survivesUpgrade` and `test_F005_maxBlockPoison_makesUpgradeUnstoppable`. Both pass (`poc/H004/H004-forge-output.txt`). They run against unmodified copies of `contracts/src` and `contracts/test/utils`, built with OZ v5.1.0. The libraries are reused from `poc/H003/lib`.

## Summary

`HypersnapBridge` (V1, new in this PR) authorises every privileged action with one `ecrecover` against `ownerAddress`. The contract NatSpec (`contracts/src/HypersnapBridge.sol:14-17`) and `contracts/README.md:3-5` say that this address is a DKLS23 threshold key of the validator set. The tree has no DKLS code (`docs/00-OVERVIEW.md`, trust model). `Deploy.s.sol` sets the genesis owner to the broadcasting EOA by default (`contracts/script/Deploy.s.sol:89-95`). The live trust model is therefore one key, normally the deployer's hardware wallet.

That key can do the following:

| Action | Code | Delay | Cap / limit |
|---|---|---|---|
| Mint any amount to anyone: sign a root over any leaves, then `claim` | `HypersnapBridge.sol:173-220` (signature check `:188-197`) | none | none (only the ERC-20 `totalSupply` overflow limit) |
| Rotate ownership to any key it controls | `:229-258` | none | none |
| Propose an upgrade to any UUPS implementation | `:271-311` | 48h before `executeUpgrade` (`:346-355`) | — |
| Cancel a pending upgrade | `:316-335` | none | — |
| Pause `claim`/`burn`/`executeUpgrade` for 72h | `:361-372` | none | no unpause |
| Move any non-SNAP token held by the proxy | `:392-414` | none | — |
| Choose V2's verifier and epoch-1 validator set (the immutables of the V2 implementation that the key approves) | `:271-311`, `HypersnapBridgeV2.sol:206-231` | 48h | — |

All universal payloads (root, owner update, upgrade, cancel, pause) share one watermark, `latestBlock`. Each action requires `blockNumber > latestBlock` and then sets `latestBlock = blockNumber` (`:188/195`, `:235/255`, `:276/306`, `:321/331`, `:362/368`, `:399/411`). Nothing bounds `blockNumber` from above, and it is not tied to any real Hypersnap height. This is the V1 counterpart of the `2^64−1` watermark issue that F004 reports for V2 (`lastActionHeight`). F004 needs a retired validator set; here one key is enough.

## Why the documented defences fail

The README (`contracts/README.md:105-136`) and the NatSpec (`HypersnapBridge.sol:64-69`, `:266-270`, `:341-345`) present the upgrade timelock and pause as protection against a compromised key:

> Three-step flow with a 48h delay protecting against single-block exploitation of a compromised threshold key …
> **Compromise-recovery sequence**: validators run a fresh DKG → relay `rotateOwner(... newOwner ...)` (immediate) → new owner signs and relays `cancelUpgrade(... pendingImpl ...)` (immediate). The malicious 48h timer never fires.

1. **The timelock does not limit the key's damage.** `claim` mints without any delay or cap. A compromised key does not need an upgrade: it signs one root over a leaf `(fakeLockId, chainid, attacker, X)` and mints `X` in the same transaction. The root signature is universal, so one root that contains a leaf for each chain mints on every chain. The PoC mints `1e30` units with one signature. The minted supply carries into V2 unchanged (`UpgradeToV2.s.sol:157` even asserts `totalSupply` equality), and the inbound path credits any `Burned` event from the proxy without a supply check (`src/chain/shard0/ledger.rs:749-770`). So the forged supply also enters the Hypersnap ledger after the pivot.
2. **One signature makes the upgrade unstoppable.** The key calls `proposeUpgrade(2^64−1, evil, sig)`. After that, `rotateOwner`, `cancelUpgrade` and `pause` all revert `StaleBlock(2^64−1, …)`, because no `uint64` is greater than `2^64−1`. `executeUpgrade` does not check `latestBlock`, so anyone runs it 48h later (PoC `test_F005_maxBlockPoison_makesUpgradeUnstoppable`). This works even if the honest operators notice at once and still hold the key. The README's "tail risk" note (`:133-136`) covers only a rotate-to-self race. It does not mention that a single transaction ends recovery, and that the 24h "guaranteed lockout window" (`HypersnapBridge.sol:64-69`) does not exist in this case.
3. **Also fatal by mistake, at exactly `2^64−1`.** The same watermark freezes the contract if an honest operator signs `blockNumber = 2^64−1`, for example a `-1` or `type(uint64).max` sentinel. A merely large value such as a millisecond timestamp (about 1.76e12) is recoverable, because the owner can keep signing above it, and a proposal at `2^64−2` can still be cancelled at `2^64−1` (poc/F005 controls). Once the watermark is `2^64−1`, `claim` can no longer advance the root (`RootMismatch` for any new root), and no pause, rotation, upgrade or recovery is possible. The bridge stays on its last root for good. `UpgradeToV2.s.sol:38-39` only says that `$BLOCK` must be above `latestBlock()`. Nothing gives an upper bound.

## Attacker model

- **Who:** whoever holds the V1 owner key (theft, insider, or a coerced or careless operator). Today this is one EOA. The README's threshold design is not in the tree.
- **When:** from deployment until V2's `executeUpgrade`. V2 needs `SET_ROOT_EPOCH1` from the `PivotRecord` (`HypersnapBridgeV2.sol:99-101`), so V1 has to stay live at least until after the pivot, plus 48h. While the V2 upgrade is pending, the key can still mint (point 1), pause (and so delay `executeUpgrade`), or cancel the V2 upgrade (`:316-335`).
- **No other capability needed.** All entry points are permissionless relays of the signature.

## Spec vs code

- The FIP never describes a V1 owner key. §13.5 states: *"The only trust assumption is the assumption of all Hypersnap state: more than 2/3 of the validator weight is honest."* §13.7 states: *"An upgrade must have a CERT-STARK … so validators can stop a malicious upgrade."* Both hold only for V2. Until the upgrade, and for the choice of V2 itself (its verifier and genesis set), the trust root is one ECDSA key. **The spec is the side that is incomplete.** It should state the V1 trust model and the transition. Also, §10.1 says the retroactive emission ended, yet V1 can still mint without limit until it is replaced.
- The NatSpec and README say "threshold ECDSA (DKLS23)" (`HypersnapBridge.sol:14-17`, `README.md:3-5`, `:167-171`). No DKLS23 code is in the tree. **The documentation is wrong**, or the threshold key is planned but not built.

## Red-team walk

1. *Documented and accepted?* Partly. The README accepts the rotate-to-self race. It does not cover point 1 (the timelock gives no protection, because mint is instant) or point 2/3 (one signature at `2^64−1` disables all recovery, including by mistake). Kept, with a severity that reflects a privileged role.
2. *Does `executeUpgrade` check `latestBlock`?* No (`:346-355`). Confirmed by the PoC.
3. *Can a pause placed before the poison help?* Only for 72h. The poison also blocks any later pause, so the upgrade runs once the earlier pause expires.
4. *Is V1 really live after the pivot?* Yes. V2 cannot be built before `PivotRecord.set_root_epoch1` exists, and the upgrade path assumes the V1 proxy is the live token (`UpgradeToV2.s.sol:13-14`).
5. *Is the inbound credit capped?* No supply or outstanding-balance check exists in `ledger.rs:749-770`. It checks only dedup and FID registration.
6. *Overstatement check.* Without key compromise or misuse, nothing happens. The impact if shipped is Critical (direct theft and a permanent freeze); the key-compromise or operator-error precondition moves it one bucket down, so the rating is **High** (recalibrated 2026-11-04, validated with poc/F005 10/10). Uncapped minting by itself is the documented V1 trust model; the undocumented parts are the `2^64−1` recovery kill and the timelock giving no protection against an instant mint.

## Recommended fix

- Put an upper bound on `blockNumber` in every V1 action, for example `blockNumber <= latestBlock + MAX_STEP`, or bind it to a real time or height. Or keep a separate watermark for governance (pause/cancel/rotate) so that a root or upgrade nonce cannot block it. In particular, `cancelUpgrade` and `pause` should not be blockable by the pending proposal's own nonce.
- Add a mint rate limit or cap to V1 `claim` (per root and per time window). Or close the V1 claim path once the retroactive distribution is complete (§10.1 says it is), so the key can no longer mint during the long V1→V2 window.
- Use a real multisig or threshold key, as documented, or correct the README and NatSpec. Write the V1 trust model and the transition window into the FIP.
- Have `UpgradeToV2.s.sol` / the ceremony reject a `blockNumber` far above `latestBlock`.

## Leads

- H005/H006: none from this finding.
- F004 is the same watermark pattern on V2 (`lastActionHeight`). The report should present them together, and the fix should be the same pattern.

## Corrections

- **2026-11-04** (poc, validator): Claim 3 overstated: a millisecond timestamp or wrong-unit blockNumber does NOT freeze V1; the owner can keep signing above it (poc/F005 test_control_msTimestampJump_recoverable). Only a value at 2^64-1 (e.g. a -1/u64::MAX sentinel; bridge-ceremony block args are unbounded u64) permanently disables root advance, pause, cancelUpgrade, rotateOwner and proposeUpgrade.
- **2026-11-04** (validate, validator): Red-team item 6 still says 'That is why the rating is Medium'; severity is High (impact if shipped: Critical theft/permanent freeze, one bucket down for the key-compromise/operator-error precondition).
