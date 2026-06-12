# Residual bridge-recovery PoCs — commit `5c2594563df84c374fdce7cdeae06d3444da3b72`

Runnable Foundry PoCs proving three still-live `HypersnapBridge` recovery
vulnerabilities are PRESENT in the post-"audit fixes" commit
`5c2594563df84c374fdce7cdeae06d3444da3b72`.

The Solidity contract (`contracts/src/HypersnapBridge.sol`) is unchanged from the
audited base in this commit. The only relevant change in the fix was a Rust-side
honest-signer block-number cap, which does not bind the on-chain contract and is
irrelevant to a Byzantine/compromised signer who holds the owner key (as in
these tests). Single canonical deployment is assumed (cross-deployment replay
F045 is out of scope).

Each test is a positive reproduction: **PASS == bug demonstrated.**

## Files

- `Residual5c25945.t.sol` — the three PoC tests (one per finding).
- `forge-output.txt` — raw `forge test -vvv` run log.

## How to run

The Foundry project lives at `<repo>/contracts` (solc 0.8.24, forge-std + OZ
v5.0.2 under `lib/`). From that directory:

```
forge test --match-path test/Residual5c25945.t.sol -vvv
```

(Dependencies for the isolated worktree were installed with
`forge install foundry-rs/forge-std --no-git`,
`forge install OpenZeppelin/openzeppelin-contracts@v5.0.2 --no-git`,
`forge install OpenZeppelin/openzeppelin-contracts-upgradeable@v5.0.2 --no-git`;
the contract compiles cleanly against these. Baseline suite: 112 tests pass.)

## Observed result

```
Ran 3 tests for test/Residual5c25945.t.sol:Residual5c25945
[PASS] test_F047_rotationFrontRun_attackerSeizesOwnership()
[PASS] test_F048_pauseDoesNotGateProposeUpgrade_lockoutDefeated()
[PASS] test_F049_watermarkSaturationBricksRecovery_executeUpgradeSurvives()
Suite result: ok. 3 passed; 0 failed; 0 skipped
```

## What each test proves

### F049 — `test_F049_watermarkSaturationBricksRecovery_executeUpgradeSurvives` — REPRODUCED

An owner-signed `pause` with `blockNumber = type(uint64).max` saturates the
shared monotonic watermark `latestBlock` (no upper bound exists at the gate,
`HypersnapBridge.sol` L362; same for L235/L321 etc.). After saturation:

- `rotateOwner(MAX, ...)` reverts `StaleBlock(MAX, MAX)` (gate L235) — recovery
  rotation to a fresh clean key is permanently impossible.
- `cancelUpgrade(MAX, ...)` reverts `StaleBlock(MAX, MAX)` (gate L321) — the
  malicious pending upgrade can never be cancelled.
- `pause(MAX, ...)` reverts `StaleBlock(MAX, MAX)` (gate L362) — defenders cannot
  even refresh the pause.

Meanwhile the permissionless, watermark-independent `executeUpgrade()`
(L346-355, reads only `pendingImplementation` / `pendingUpgradeEffectiveAt` /
`pauseExpiry`) still fires after the 72h pause auto-expires, swapping the ERC-1967
implementation slot to the attacker's impl. Test asserts the impl slot now holds
`address(evilImpl)`.

### F047 — `test_F047_rotationFrontRun_attackerSeizesOwnership` — REPRODUCED

The cleanest variant (seizure, F047 sub-case (b)). A compromised old owner
(holds `O1`) front-runs the victim's recovery `rotateOwner(N, O2, sigByO1)` by
landing its own `rotateOwner(N, O_attacker, authSigByO1, acceptSigByO_attacker)`
first. The authorization digest binds only `(DOMAIN, block, newOwner)`
(L238-242) — not the current owner — so `O1` can authorize a rotation to any
address; the acceptance digest binds only `newOwner` (L247-250) and is trivially
produced by the attacker for their own key. Result: `ownerAddress` becomes
`O_attacker` permanently (L256), and the victim's rotation at the same block `N`
now reverts `StaleBlock(N, N)` (gate L235). Test also confirms `O1`'s signature
is no longer accepted afterward.

### F048 — `test_F048_pauseDoesNotGateProposeUpgrade_lockoutDefeated` — REPRODUCED

`proposeUpgrade` (L271-311) has no `whenNotPaused` modifier (unlike `claim`
L182, `burn` L380, `executeUpgrade` L346). With a defensive pause landed at
`T0` (`pauseExpiry = T0 + 72h`), the attacker waits inside the pause window and
calls `proposeUpgrade` at `T0 + 24h` — the call does NOT revert (key assertion).
Then `effectiveAt = T0 + 24h + 48h = T0 + 72h == pauseExpiry`. The documented
"24h guaranteed lockout" cushion (L64-71) collapses to exactly zero: both the
pause gate and the upgrade-ready gate clear at the same instant, and the attacker
calls `executeUpgrade()` in the very block the pause lapses. Test asserts
`effectiveAt == pauseExpiry` and that the upgrade executes at the pause-lapse
instant.

## Caveats

- All three are demonstrated under the contract's own stated key-compromise
  threat model: the attacker holds the owner (threshold) key, which in tests is
  the deterministic `OWNER_PK`. This is exactly the scenario the documented
  recovery flow (L266-270) exists to handle.
- F049 step 4 and F048 use the bridge contract itself as the "evil"
  implementation purely so it satisfies the `proxiableUUID()` UUPS-compatibility
  guard (L298-304). The PoCs prove the upgrade *executes / the recovery is
  bricked*; the maliciousness of the installed impl is orthogonal and assumed.
- OZ pinned at v5.0.2 for the isolated worktree (the repo gitignores `lib/` and
  ships no `.gitmodules` in this clone). The contract API (ERC1967Utils,
  UUPSUpgradeable `upgradeToAndCall(address,bytes)` override) is OZ v5; behavior
  exercised here (ECDSA recover, watermark gates, pause timing) is not
  version-sensitive across OZ 5.0.x.
