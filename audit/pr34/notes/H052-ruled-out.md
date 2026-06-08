---
id: H052
specialist: solidity-proxy-access
attack_class: initializer-replay
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
---

# H052 — initializer-replay on HypersnapBridge.initialize() — RULED OUT

## Scope

`contracts/src/HypersnapBridge.sol` `initialize()` (lines 148-159). Hunt:
can `initialize` run more than once on the proxy — directly or by reusing a
`reinitializer(n)` version across an upgrade — to reset owner / group-key /
watermark?

## Findings

**Guarded once, correctly.** `initialize()` carries the OZ v5
`initializer` modifier (line 152):

```solidity
function initialize(address genesisOwner, string calldata name_, string calldata symbol_)
    external initializer { ... }
```

OZ v5 `Initializable.initializer` allows exactly one successful execution on
a given storage context: it advances `_initialized` from 0 to 1 and reverts
`InvalidInitialization()` on any later call. The proxy is initialized exactly
once, atomically, via the `ERC1967Proxy` constructor in `script/Deploy.s.sol`
(`_broadcastDeploys`, init calldata `abi.encodeCall(HypersnapBridge.initialize, ...)`).
`test/Initialize.t.sol::test_cannotReinitialize` asserts a second call reverts
with `Initializable.InvalidInitialization.selector`.

**No `reinitializer` reuse vector.** There is only one implementation
contract (`HypersnapBridge.sol`); no V2/V3 implementation exists anywhere in
the repo, and `reinitializer(` does not appear in any `.sol` file. There is
therefore no upgrade path that re-enters an initializer to reset
`ownerAddress`, the threshold-derived owner key, or the `latestBlock`
watermark. (Owner and watermark are only mutated through the separately
signature-gated `rotateOwner` / `pause` / `proposeUpgrade` / etc. flows —
outside this hunt's class.) A future V2 that adds a `reinitializer(2)` would
be the place to recheck, but no such code exists at this commit.

**Implementation contract locked down.** Constructor calls
`_disableInitializers()` (line 145), forcing `_initialized = type(uint64).max`
on the impl so `initialize` can never run against the implementation's own
storage. Confirmed by `test_implementationCannotBeInitialized` and
`test_implementationOwnerIsZero` (impl `ownerAddress() == address(0)`).

**Zero-owner guard.** `initialize` reverts `ZeroAddress()` on
`genesisOwner == address(0)`, so even the single permitted call cannot leave
an unspendable owner.

## Conclusion

`initialize()` is a single-shot `initializer`-guarded function with the
implementation disabled in the constructor; no reinitializer version is
defined or reusable. No initializer-replay exposure. Ruled out.
