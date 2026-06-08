---
id: H055
specialist: evm-state-machine
attack_class: reentrancy-classic
outcome: ruled-out
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H055 — reentrancy-classic on claim / burn / recoverERC20 — RULED OUT

## Scope

`HypersnapBridge.sol` functions with external token interactions:
`claim` (L173-220), `burn` (L378-386), `recoverERC20` (L392-414).
Hunt: is the claim/nullifier marker set BEFORE the external transfer
(checks-effects-interactions)? Is there a reentrancy guard? Could a
re-entrant token/recipient replay a claim?

## Analysis

### claim (L173-220) — CEI correct, no reentrant surface

- Check: `if (claimed[lockId]) revert AlreadyClaimed(lockId);` (L186).
- Effect: `claimed[lockId] = true;` (L217) — set BEFORE the interaction.
- Interaction: `_mint(recipient, amount);` (L218).

The replay marker is set before `_mint`, so even a reentrant call sees
`claimed[lockId] == true` and reverts at L186. Ordering is textbook CEI.

Moreover the "interaction" here is an internal `_mint`, not an arbitrary
external call. The contract uses OpenZeppelin v5 `ERC20Upgradeable`
(split `contracts` / `contracts-upgradeable` package layout, foundry
remappings confirm; `ERC20PermitUpgradeable` extends `ERC20Upgradeable`).
In OZ v5, `_mint` routes through `_update`, which performs no recipient
callback and exposes no `_afterTokenTransfer` user hook (those were
removed in v5). `SNAP` is a plain ERC20, not ERC777, so there is no
`tokensReceived` hook either. Recipient cannot gain execution during
`_mint`. No reentrancy vector exists regardless of ordering — and the
ordering is correct anyway.

Also note: the root-advance branch (L188-202) writes `latestBlock` /
`latestRoot` before the merkle check + mint, and the merkle verification
binds `lockId, recipient, amount` to `latestRoot`. No state to replay.

### burn (L378-386) — no arbitrary external call

`_burn(msg.sender, amount)` (L383) is internal; OZ v5 `_burn` → `_update`
has no callback. `burnNonce` increment and `Burned` emit follow. There is
no transfer to an arbitrary party, hence no reentrancy surface at all.

### recoverERC20 (L392-414) — watermark effect precedes the transfer

This is the only path with a genuinely attacker-influenceable external
call: `SafeERC20.safeTransfer(IERC20(token), to, amount)` (L412) where
`token` is a caller-supplied address that could be a malicious contract
re-entering during `transfer`.

- Effect: `latestBlock = blockNumber;` (L411) — the monotonic watermark
  is advanced BEFORE the transfer.
- Interaction: `safeTransfer(...)` (L412).

There is no per-call "recovered" boolean that gets set after the transfer
to replay. Authorization is a one-shot owner signature over
`(chainid, blockNumber, token, to, amount)` and is consumed by the
strictly-increasing `latestBlock` guard at L399 (`blockNumber <=
latestBlock` reverts). A reentrant `token` callback that re-invokes
`recoverERC20` would need a fresh `blockNumber > latestBlock` AND a valid
owner signature over it, which it cannot forge. Re-using the same sig
fails the watermark check. So even with reentrancy the call cannot be
replayed or amplified. CEI is honored (effect before interaction).

## Reentrancy guard

No OZ `ReentrancyGuard` / `nonReentrant` is present. It is not required on
any in-scope path: `claim`/`burn` have no arbitrary external call, and
`recoverERC20` already sequences its replay-defeating effect (the
watermark bump) before its single external call. Cross-function reentry
into other state-changers (rotateOwner, proposeUpgrade, pause, etc.) is
likewise gated by the same monotonic `latestBlock` watermark plus owner
signatures, none of which a reentrant token can satisfy.

## Conclusion

No reentrancy-classic / CEI-ordering defect. All in-scope external-call
paths either make no arbitrary external call or set their replay-defeating
state before the interaction. Ruled out.
