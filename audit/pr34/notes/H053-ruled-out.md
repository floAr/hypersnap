---
id: H053
specialist: solidity-proxy-access
attack_class: upgrade-bricking
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
---

# H053 — upgrade-bricking via malicious/zero implementation — RULED OUT

## Scope

`contracts/src/HypersnapBridge.sol` `_authorizeUpgrade` gating and the
`proposeUpgrade` → `executeUpgrade` flow. Hunt: can the proxy be permanently
bricked by upgrading to a zero address, an EOA / codeless address, or a
non-UUPS implementation? Can `executeUpgrade` target an implementation
different from the one proposed?

## Upgrade architecture

The inherited UUPS entry point is hard-disabled. `upgradeToAndCall` is
overridden to `revert UseUpgradeFlow()` (L418-420) and `_authorizeUpgrade`
unconditionally `revert UpgradeNotAuthorized()` (L426-428). All upgrades flow
through the custom timelocked path: owner-signed `proposeUpgrade` records
`pendingImplementation` + a 48h timer, then permissionless `executeUpgrade`
calls `ERC1967Utils.upgradeToAndCall(impl, "")` directly after the delay. Both
the override and the lockdown are exercised by `test/ImplLockdown.t.sol` and
`test/UpgradeFlow.t.sol`.

## Why each bricking vector is blocked

**Zero address — rejected.** `proposeUpgrade` L277:
`if (newImplementation == address(0)) revert ZeroAddress();`
(`test_proposeUpgrade_zeroAddress_reverts`).

**EOA / codeless address — rejected at BOTH propose and execute.**
At propose time the UUPS check is a high-level external call with a declared
return value: `try IERC1822Proxiable(newImplementation).proxiableUUID()
returns (bytes32 slot)` (L298). For a high-level call that ABI-decodes a
return value, solc 0.8.24 emits an `extcodesize(target) > 0` guard before the
call; a codeless target makes the call construct revert, which the `catch`
turns into `NotUUPSCompatible(bytes32(0))`. Independently, at execute time OZ
v5 `ERC1967Utils.upgradeToAndCall` → `_setImplementation` reverts
`ERC1967InvalidImplementation` when `newImplementation.code.length == 0`. An
EOA can never become the active implementation.

**Non-UUPS contract — rejected.** A contract lacking `proxiableUUID()` takes
the `catch` branch → `NotUUPSCompatible(bytes32(0))`
(`test_proposeUpgrade_notUUPSCompatible_missingFn_reverts`). A contract whose
`proxiableUUID()` returns a non-ERC1967 slot is rejected at L299-301 →
`NotUUPSCompatible(slot)`
(`test_proposeUpgrade_notUUPSCompatible_wrongSlot_reverts`). The check
replicates exactly the guard OZ's stock `UUPSUpgradeable.upgradeToAndCall`
applies, which the custom flow correctly re-adds because it bypasses that path.
The `proxiableUUID` interface is `view`, so solc uses STATICCALL and the impl
cannot mutate state or reenter during the check.

**Execute cannot target a different impl than proposed.** `executeUpgrade()`
(L346-355) takes no parameters; it reads `pendingImplementation` from storage
(L347) and passes that exact value to `upgradeToAndCall`. There is no
caller-supplied implementation argument anywhere in the execute path, so the
proposed/executed implementation are necessarily identical. The single-pending
slot (`UpgradeAlreadyPending` guard, L278) means only one proposal can be
in flight at a time.

**Execute-time revert does not strand state.** `executeUpgrade` zeroes
`pendingImplementation`/`pendingUpgradeEffectiveAt` (L351-352) before the
external `upgradeToAndCall`. If that call reverts (e.g. impl self-destructed
between propose and execute → `code.length == 0`), the whole transaction
reverts and the pending state is restored; the upgrade simply cannot execute
until re-proposed or cancelled. No permanent brick.

## Residual considerations (out of class / accepted)

- A metamorphic/CREATE2-redeployed impl could in principle present
  UUPS-compatible code at propose time and different code at execute time
  (execute re-checks only `code.length > 0`, not `proxiableUUID`). This
  requires owner-key control of the propose signature; a malicious owner can
  already brick future upgradeability by legitimately proposing a
  non-re-upgradeable (but genuinely UUPS) impl. This is the standard accepted
  UUPS residual, not a gating defect in this contract.
- Permanent disablement of the cancel/rotate recovery via watermark
  saturation, and the pause-vs-upgrade timing cushion collapse, are real but
  belong to different attack classes and are already captured by **F049**
  (upgrade-race) and **F048** (pause-bypass) respectively. Neither concerns the
  new-implementation validation that is H053's scope.

## Conclusion

The `_authorizeUpgrade` lockdown plus the `proposeUpgrade`/`executeUpgrade`
validation reject zero, codeless/EOA, and non-UUPS implementations at propose
time (with a code-length backstop at execute time), and execute is
structurally incapable of targeting a different implementation than the one
proposed. No upgrade-bricking exposure in this scope. Ruled out.
