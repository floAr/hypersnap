# H051 — UUPS uninitialized-implementation takeover — RULED OUT

- specialist: solidity-proxy-access
- attack_class: uninitialized-implementation
- file: contracts/src/HypersnapBridge.sol (constructor lines 143-146; upgrade paths 271-355, 418-428)
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- outcome: not-a-finding

## Hunt

Classic UUPS uninitialized-implementation takeover: can an attacker call
`initialize()` directly on the implementation contract (bypassing the proxy),
become its owner, and then `upgradeToAndCall` the impl to a self-destructing
contract — bricking every proxy that delegate-calls it? Verify the impl
constructor disables initializers and that no direct-impl path reaches
`ERC1967Utils.upgradeToAndCall`.

## Why ruled out

1. **Constructor disables initializers.** Lines 143-146:

   ```solidity
   /// @custom:oz-upgrades-unsafe-allow constructor
   constructor() {
       _disableInitializers();
   }
   ```

   `_disableInitializers()` sets the OZ `Initializable` `_initialized`
   sentinel to `type(uint64).max`, so `initialize()` (guarded by the
   `initializer` modifier, line 152) reverts with
   `Initializable.InvalidInitialization` when called on the impl directly.
   Confirmed by `test_impl_initialize_blocked` (ImplLockdown.t.sol:15-18).
   Consequently the impl's `ownerAddress` is permanently `address(0)`
   (asserted by `test_impl_state_isZero`, ImplLockdown.t.sol:79-88).

2. **No direct-impl path reaches `ERC1967Utils.upgradeToAndCall`.** The
   classic takeover needs to point the impl's ERC-1967 slot at a
   self-destructing contract. Every route is closed:
   - The inherited UUPS `upgradeToAndCall` is overridden (lines 418-420) to
     `revert UseUpgradeFlow()` unconditionally — no auth path through it.
     (`test_impl_upgradeToAndCall_blocked`, ImplLockdown.t.sol:74-77.)
   - The only call site of `ERC1967Utils.upgradeToAndCall` is
     `executeUpgrade` (line 354), reachable only when
     `pendingImplementation != address(0)`. Setting that requires
     `proposeUpgrade`, which is sig-gated:
     `digest.recover(ownerSig) != ownerAddress` (line 286). On the impl
     `ownerAddress == address(0)` and `ECDSA.recover` never returns
     `address(0)` for a well-formed sig (malformed sigs revert), so the
     check always fails → `BadOwnerSignature`. `executeUpgrade` itself
     reverts `NoPendingUpgrade` with no pending set
     (`test_impl_executeUpgrade_blocked`, ImplLockdown.t.sol:46-50;
     `test_impl_proposeUpgrade_blocked`, :39-44).
   - `_authorizeUpgrade` (lines 426-428) is `revert UpgradeNotAuthorized()`
     unconditionally — the OZ hook can never authorize an upgrade.

3. **No `selfdestruct` reachable, and bricking is moot anyway.** The
   contract contains no `selfdestruct`/`SELFDESTRUCT` opcode source. Even
   if an attacker could initialize the impl (they cannot), there is no
   self-destruct sink to invoke, and no path to make the impl delegatecall
   a foreign destructor.

4. **Every other state-mutating function is inert on the impl.** All
   sig-gated entry points (`claim`, `rotateOwner`, `cancelUpgrade`, `pause`,
   `recoverERC20`) compare `recover(sig)` against `ownerAddress == 0` and
   revert `BadOwnerSignature`; `burn` reverts on empty `_balances`. The
   `ImplLockdown.t.sol` surface exercises each of these against the bare
   impl and confirms the revert.

## Conclusion

The implementation contract is correctly and permanently locked down. The
`_disableInitializers()` constructor follows the recommended OZ pattern, the
inherited UUPS entry point is neutered, and the only internal upgrade path is
unreachable on the impl due to the `ownerAddress == address(0)` sig gate. The
uninitialized-implementation takeover class does not apply here.
