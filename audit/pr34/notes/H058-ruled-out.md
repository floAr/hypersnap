---
id: H058
specialist: evm-tokens
attack_class: fee-on-transfer-mismatch
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
outcome: ruled-out
---

# H058 — fee-on-transfer / rebasing mismatch in `recoverERC20` (and any path) — RULED OUT

PR #34's `HypersnapBridge` has no internal accounting that a fee-on-transfer,
deflationary-burn, or rebasing token could desync. `recoverERC20` is a pure
"push `amount` out" operation, and the only token with on-contract supply
accounting (SNAP) is standard non-fee/non-rebasing and is explicitly excluded
from the recover path.

## Scope reviewed

`contracts/src/HypersnapBridge.sol` is the entire EVM contract surface
(`contracts/src/` contains only this file). Every token touchpoint:

- `recoverERC20` (lines 392-414) — arbitrary external ERC20, outbound only.
- `claim` (218) `_mint` / `burn` (383) `_burn` — SNAP, the bridge's own
  `ERC20PermitUpgradeable` wrapped token.

## Why `recoverERC20` does not mismatch (lines 392-414)

```solidity
SafeERC20.safeTransfer(IERC20(token), to, amount);
emit ERC20Recovered(blockNumber, token, to, amount);
```

- It moves exactly `amount` out and emits. There is **no** `balanceOf`
  read, **no** before/after delta, **no** `balanceAfter - balanceBefore ==
  amount` assumption anywhere in the contract (grep for
  `balanceOf|balanceBefore|balanceAfter|transferFrom` returns nothing).
- There is **no** per-token internal ledger. The contract stores no mapping of
  "how much of token X this bridge holds." Nothing exists to drift out of sync.
- `amount` is whatever the owner threshold-signed (digest at 402-409 commits
  `token`, `to`, `amount`, `block.chainid`, watermark). If `token` charges a
  fee or burns on transfer, `to` simply receives less than `amount`; if the
  contract holds less than `amount`, `SafeERC20.safeTransfer` reverts. Neither
  case corrupts state, over-withdraws, double-spends, or unlocks SNAP.
- Rebasing tokens (stETH/aTokens) rebase on *their own* ledger, not the
  bridge's. The bridge never records a fixed share/balance for an external
  token, so accrual/decay has nothing to desync against. A recover simply
  sends the signed `amount` of the current balance.

The only state `recoverERC20` writes is `latestBlock` (the monotonic
watermark, line 411), which is token-agnostic and unaffected by transfer
semantics.

## Why the SNAP paths are out of scope for this class

- SNAP is `ERC20PermitUpgradeable` (`_mint`/`_burn`), standard OZ — no
  fee-on-transfer, no rebase, no burn-on-transfer hook. Its supply accounting
  is internal and exact.
- `recoverERC20` rejects `token == address(this)` (line 400,
  `CannotRecoverWrappedToken`), so the recover path cannot touch SNAP supply.
- `claim`/`burn` operate solely on SNAP via `_mint`/`_burn`; no external
  token transfer participates, so fee/rebase semantics never enter the mint/
  burn ledger.

## No ERC-777 / ERC-721 / ERC-4626 surface

No `safeTransferFrom`/`onERC721Received`/`tokensReceived`/ERC-4626 vault logic
exists. `recoverERC20`'s outbound `safeTransfer` to a potentially-ERC777 `to`
could trigger a `tokensReceived` hook on the recipient, but the function does
no post-transfer state mutation (the only write, `latestBlock`, precedes the
transfer at line 411), so reentrancy yields nothing — and that is an ERC-777
hook concern, not a fee-on-transfer accounting mismatch (out of class H058).

## Verdict

Ruled out (would have been low/info even if a drift existed). The contract
keeps no external-token internal accounting, reads no balance deltas, and
isolates its only fee/rebase-sensitive ledger (SNAP) from the arbitrary-token
recover path. Fee-on-transfer / deflationary / rebasing tokens cannot corrupt
any bridge accounting.
