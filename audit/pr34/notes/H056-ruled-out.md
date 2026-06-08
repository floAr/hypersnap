---
hunt_id: H056
specialist: evm-state-machine
attack_class: return-bomb
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/contracts/src/HypersnapBridge.sol
---

# H056 — return-bomb / gas-griefing on relayed claims — RULED OUT

## Scope

`contracts/src/HypersnapBridge.sol` low-level/token calls. Hypothesis: a
permissionlessly-relayed claim (third party pays gas) could be griefed if a
token transfer returns a huge bytes payload (return-bomb) or consumes all
gas, or if one bad claim in a batch reverts the whole batch.

## Why ruled out

### 1. The claim path makes no external token call

`claim` (lines 173–220) credits the recipient via `_mint(recipient, amount)`
(line 218). `_mint` is OpenZeppelin ERC20Upgradeable's internal mint: it
mutates `_balances` / `_totalSupply` and emits `Transfer`. The minted token
*is this contract* (`SNAP`), so there is no external token contract to call.

OZ Contracts v5 ERC20 has no `_afterTokenTransfer` / ERC777-style recipient
hook — `_mint` never calls into `recipient`. A grep of the file for
`_update`, `_afterTokenTransfer`, `_beforeTokenTransfer`, `.call`,
`delegatecall`, `.send`, `.transfer`, `functionCall`, `returndatacopy`
returns **no matches**. There is therefore no external call on the claim
critical path, and no attacker-controlled RETURNDATACOPY. A return-bomb needs
an external `call` whose returndata the caller copies; that surface does not
exist in `claim`.

### 2. There is no on-chain batch claim

`claim` verifies and mints exactly one lock leaf per call (single `lockId`,
single `merkleProof`). There is no `claimBatch` / loop over multiple claims.
The "first claim at a new block number advances the root, later claims ride
free" optimisation (lines 188–202) is still one leaf per transaction. Each
relayer submits its own transaction and pays its own gas; a revert in one
claim fails only that relayer's own tx — it cannot brick other claims or a
shared batch. The "one bad claim reverts the whole batch" vector is **not
applicable** because no batch primitive exists. (Docs confirm claims are
"relayed permissionlessly to HypersnapBridge on each chain" as individual
relayed calls — `docs/00-OVERVIEW.md:49`, `docs/attack-surface.md:100`.)

### 3. The only arbitrary-token call is owner-authorized and out of scope

The single external call to an arbitrary token is
`SafeERC20.safeTransfer(IERC20(token), to, amount)` in `recoverERC20`
(line 412). This is not a relayed claim:

- `token`, `to`, `amount` are all covered by an owner (threshold-validator)
  signature that is chain-bound (`bytes32(block.chainid)` in the digest,
  lines 402–410). `token` is **not** attacker-controlled — a malicious token
  address would have to be signed by the threshold owner.
- `SafeERC20.safeTransfer` (OZ v5) bounds its own returndata handling
  (`_callOptionalReturn` checks `returndatasize` and decodes at most a bool),
  so a return-bomb cannot be amplified through it into unbounded memory copy.
- Even in the worst case, a misbehaving recovered token could only revert /
  burn gas in the owner's own `recoverERC20` transaction. It is not on a
  permissionless-relay critical path and cannot grief a third-party relayer
  or brick claims. Recovering a griefing token is also a one-shot,
  owner-discretionary action, not a batched or repeatable relay flow.

### 4. No other griefing primitives present

No `payable(to).send(value)` / `.transfer` (2300-gas) patterns, no raw
`(bool ok,) = to.call{value:...}("")`, no `delegatecall`, and no transient
storage (`tload`/`tstore`). `burn` (lines 378–386) only calls internal
`_burn`. `executeUpgrade` calls `ERC1967Utils.upgradeToAndCall(impl, "")`
with empty calldata to an owner-proposed, UUPS-validated implementation
(out of return-bomb scope and owner-authorized).

## Conclusion

No return-bomb or gas-griefing surface on the relayed-claim path: the claim
path performs no external call, no batch primitive exists so one bad claim
cannot brick others, and the sole arbitrary-token transfer is
owner-authorized, chain-bound, and uses bounded SafeERC20 returndata
handling. Ruled out.
