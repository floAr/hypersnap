---
id: H054
specialist: solidity-proxy-access
attack_class: storage-slot-collision
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
outcome: ruled-out
---

# H054 — packed storage layout collision with OZ base contracts — RULED OUT

Scope: `contracts/src/HypersnapBridge.sol` packed storage — slot0
(`ownerAddress` 20B + `latestBlock` 8B), slot3 (`pauseExpiry` 8B +
`pendingImplementation` 20B) — versus inherited OZ-upgradeable base storage,
and versus a future upgrade that reorders/extends the packed slots.

## Determination of OZ major version (load-bearing)

The contract uses the `ERC1967Utils` **library** —
`ERC1967Utils.IMPLEMENTATION_SLOT` (line 299) and
`ERC1967Utils.upgradeToAndCall` (line 354) — imported from
`@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol` (line 9), plus
`draft-IERC1822` (line 11), `_disableInitializers()` (line 145), and
`__UUPSUpgradeable_init()` (line 156). The `ERC1967Utils` library replaced
v4's `ERC1967Upgrade` abstract contract and exists **only in OpenZeppelin
Contracts v5.x**. `foundry.toml` pins `solc 0.8.24`, a v5-era compiler. The
overview doc (`docs/00-OVERVIEW.md:71`) confirms OZ is the proxy base. OZ is
not vendored in the read-only tree (`contracts/lib/` absent), but the API
surface is unambiguously v5.

## Why no collision exists (sub-question 1)

C3 linearization: `HypersnapBridge` → `UUPSUpgradeable` →
`ERC20PermitUpgradeable` → `EIP712Upgradeable` / `NoncesUpgradeable` →
`ERC20Upgradeable` → `ContextUpgradeable` → `Initializable`.

In **OZ Contracts v5**, every one of these bases uses **ERC-7201 namespaced
storage** (`@custom:storage-location erc7201:openzeppelin.storage.*`). Each
base keeps its entire state inside a single struct anchored at a
pseudo-random, hash-derived high slot (e.g. the ERC20 namespace anchor
`0x52c6...00`, Initializable `0xf0c5...00`, etc.). The bases therefore occupy
**zero contiguous low slots** and append **no `__gap`** to the derived
layout.

Consequences:
- `HypersnapBridge` legitimately owns the contiguous low slots from **slot 0**.
  The packed slot0 (`ownerAddress`+`latestBlock`) and slot3
  (`pauseExpiry`+`pendingImplementation`) sit in the derived contract's own
  low-slot region.
- A low slot (0–49, including the packed ones) colliding with any ERC-7201
  namespace anchor (a keccak256-derived 256-bit value) is cryptographically
  negligible. No overlap with ERC20 balances/allowances, EIP712 cache, Nonces,
  Initializable's `_initialized`/`_initializing`, or the ERC-1967
  implementation/admin slots (which are themselves fixed high `keccak-1`
  pseudo-slots, not low slots).
- Initialization state (`initializer` guard) lives in the `Initializable`
  ERC-7201 namespace in v5, **not** slot 0 — so the packed slot0 cannot clobber
  or be clobbered by the init guard.

The in-code comment's "Total reserved = 50 slots" framing (lines 83–87) is
mildly misleading — under v5 namespaced storage the bases need no gap
reservation, so the `__gap[44]` is purely a forward-compat buffer for the
derived contract's *own* future fields, not a coexistence device with base
slots. This imprecision is harmless; the layout is correct.

## Future-upgrade packing hazard (sub-question 2) — latent, not a live bug

The packed slots do make a *future* upgrade easier to get wrong than
one-var-per-slot:
- Widening `latestBlock` (uint64→uint256), reordering the two fields inside a
  packed slot, or inserting a field before `claimed` would silently shift byte
  offsets / subsequent slots and corrupt storage on upgrade — without changing
  the *number* of declared slots, so it can pass a naive eyeball review.

However, at commit `cab225f` there is **no V2 implementation**. The single
current layout is internally self-consistent, and the in-code comment
(lines 73–87) already documents the exact discipline required ("V2 must declare
these fields in this exact order ... new fields go after `claimed` and shrink
`__gap`"). `test/UpgradeFlow.t.sol::test_executeUpgrade_afterDelay`
(lines 44–57) exercises an upgrade to an identical-layout impl and asserts
`ownerAddress` survives. No reorder/extend exists to evaluate, so there is no
confirmed collision to report — only a documented forward-looking caveat.

## Verdict

No storage-slot collision between the packed custom slots and any inherited OZ
v5 base contract: v5 namespaced (ERC-7201) storage places all base state at
hash-derived high slots, leaving the derived contract's low slots (0–49) free,
and the packed slot0/slot3 are internally consistent. The only residual is a
forward-looking upgrade-discipline note already captured in the source. Does
not meet the bar for a confirmed finding.
