# H050 — recoverERC20 SNAP/locked-balance drain — RULED OUT

- specialist: solidity-bridge
- attack_class: erc20-recovery-misuse
- file: contracts/src/HypersnapBridge.sol (recoverERC20, lines 392-414)
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- outcome: not-a-finding

## Hunt

Can `recoverERC20` be used by the owner (or a replayed sig) to drain the
bridge's own SNAP / actively-locked token balance, bypassing lock/claim
accounting? Is there a guard against recovering the canonical bridged token?

## Why ruled out

1. **The bridge IS the SNAP token (mint-and-burn, not lock-and-custody).**
   `HypersnapBridge` inherits `ERC20PermitUpgradeable`; SNAP is `_mint`-ed in
   `claim` directly to the recipient and `_burn`-ed from `msg.sender` in `burn`.
   Per docs (architecture.md 3.7, 00-OVERVIEW.md): the EVM side "mints wrapped
   SNAP on merkle-proof... observes EVM-side burn events." There is **no
   escrow pool** of third-party ERC20s and **no custody balance** of SNAP at
   `address(this)` — total supply lives distributed across `_balances`. So
   there is no "locked balance" for recovery to drain.

2. **The SNAP self-drain path is explicitly blocked.** The only way
   `recoverERC20` could transfer SNAP is `token == address(this)` (sweeping
   `balanceOf(address(this))` via `SafeERC20.safeTransfer`). Line 400 —
   `if (token == address(this)) revert CannotRecoverWrappedToken();` — forbids
   exactly this. The guard is present and, if anything, over-conservative
   (it blocks recovering SNAP even when SNAP is accidentally sent to the
   bridge address).

3. **No bypass of lock/claim accounting.** With `token != address(this)`,
   `safeTransfer(IERC20(token), to, amount)` operates on an *external* token
   contract's storage. It cannot touch the SNAP `_balances`/`_totalSupply`
   mapping nor the `claimed[lockId]` nullifier set. Recovery and the
   mint/burn accounting are storage-disjoint.

4. **Replay angle closed.** The recover digest binds `block.chainid`
   (`bytes32(block.chainid)`, line 404) so a recover sig cannot replay across
   deployments where the same `token` address resolves differently, and the
   shared strictly-monotonic `blockNumber > latestBlock` watermark
   (line 399 + `latestBlock = blockNumber` at 411) invalidates stale sigs
   within a deployment. The Rust builder `recover_erc20_digest`
   (crates/hypersnap-crypto/src/bridge_payload.rs:170-186) encodes
   `tag || chainId[32] || block[8] || token[20] || to[20] || amount[32]`,
   byte-for-byte identical to the Solidity preimage — no cross-side encoding
   asymmetry weakens the binding. Chain-binding is unit-tested
   (`recover_erc20_digest_binds_chain`, bridge_payload.rs:336).

## Residual (in-scope-trust, not a finding)

A compromised threshold/owner key can sweep stray *non-SNAP* tokens
accidentally sent to the contract. This is the intended purpose of the
function and is strictly weaker than the owner's existing ability to mint
arbitrary SNAP via a signed merkle root (same trust assumption). No
privilege escalation, no accounting bypass, no SNAP/locked-balance drain.
