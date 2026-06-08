---
id: H057
specialist: evm-tokens
attack_class: permit-nonce-confusion
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H057 — permit nonce confusion / EIP-6492 SCW-signature reuse: NOT PRESENT

The hunt hypothesis is that the SNAP token's EIP-2612 permit nonce handling
interacts with the EIP-6492 / contract-signature validation such that a permit
can be replayed, or a smart-contract-wallet (ERC-1271/6492) signature can be
reused across nonces/deployments. After tracing both subsystems, **the two are
architecturally disjoint and never meet** — the prerequisite interaction does
not exist.

## 1. The permit path is stock OZ, EOA-only, on-chain nonce, chain-bound domain

`contracts/src/HypersnapBridge.sol`:
- Inherits `ERC20PermitUpgradeable` (line 6, 50); initialized via
  `__ERC20Permit_init(name_)` (line 155). There is **no** custom `permit`,
  `_permit`, `nonces`, `_useNonce`, `DOMAIN_SEPARATOR`, or `isValidSignature`
  override anywhere in `contracts/src` (grep for
  `isValidSignature|ERC1271|_permit|function permit|SignatureChecker` →
  no matches). Nonce handling is therefore OZ's unmodified `Nonces` per-owner
  on-chain counter, consumed exactly once per `permit`.
- The bridge never calls `permit()` internally for any of its own flows
  (claim/burn/rotate/upgrade/pause/recover all use raw `ecrecover` over the
  domain-separated payloads, not the token allowance path). So there is no
  protocol-side cached nonce that could drift from the token's nonce —
  the canonical permit-nonce-confusion anti-pattern (a protocol caching the
  nonce locally) is absent.
- Stock OZ `ERC20Permit.permit` recovers via `ECDSA.recover` only — it does
  **not** route through `SignatureChecker`/ERC-1271, so a smart-contract-wallet
  signature is not even accepted by `permit`. There is no SCW-signature-reuse
  surface in the permit path at all.
- Domain separator binds `block.chainid` (EIP-712 `_domainSeparatorV4`), so a
  permit sig is bound to one chain. `test/Permit.t.sol`:
  - `test_permit_grantsAllowance` asserts `nonces(lpEOA)` advances `0 → 1`
    (per-owner, single-use).
  - `test_permit_chainSpecific` documents/asserts the chainId binding in the
    domain separator.
  - `test_permit_expiredDeadline_reverts` confirms `ERC2612ExpiredSignature`
    deadline enforcement.

A replayed permit fails because the on-chain nonce already advanced; a
cross-chain replay fails because the domain separator commits chainId. Standard,
correct EIP-2612.

## 2. The EIP-6492 validator is wired ONLY to Farcaster verification claims

`src/core/validations/contract_signature.rs` (`verify_signature`) + the vendored
AmbireTech `Erc6492.sol` / `ValidateSigOffchain` helper have exactly one caller:
`src/core/validations/verification.rs:306`
(`validate_verification_contract_signature`). The hash it validates is the
Farcaster `VerificationClaim` EIP-712 digest built at `verification.rs:281-304`
(`fid`, `address`, `blockHash`, `network` under the address-verification domain).
It proves a (counterfactual) wallet controls an address for a Farcaster
verification add-address message.

This subsystem:
- never touches the SNAP token, the bridge contract, an ERC-20 allowance, or a
  `Permit(...)` typed-data struct;
- never reads or writes any EIP-2612 nonce;
- runs off-chain in Rust (an `eth_call` deploy-and-validate), not in the token
  contract.

## 3. No interaction surface → hypothesis falsified

For the hunt's scenario to be possible there would need to be a code path where
a permit signature is validated via the EIP-6492/ERC-1271 helper (giving a
nonce-less `isValidSignature` check that could be replayed), or where the
Farcaster claim validation consumed/advanced a token nonce. Neither exists:

- Permit verification is on-chain, ecrecover-only, nonce-gated, chain-bound.
- EIP-6492 verification is off-chain, for Farcaster claims only, and carries no
  nonce semantics of its own.

The Farcaster verification claim's own replay posture (it has no nonce; an
ERC-1271/6492 SCW signature over a fixed claim digest is inherently replayable
until the underlying message is itself invalidated) is a property of the
Farcaster verification subsystem and is **out of scope for H057** (permit-nonce
confusion on the SNAP token) and out of the named scope files' token-permit
concern. It is noted here only to record that it was considered and found
unrelated to the permit/2612 nonce mechanism.

## Verdict
No permit-nonce-confusion and no EIP-6492 SCW-signature-reuse-across-nonces/
deployments vulnerability. The EIP-2612 permit path and the EIP-6492
contract-signature validator do not interact; the permit path is stock OZ
(EOA-only, single-use on-chain per-owner nonce, chainId-bound domain). Ruled out.

## Files reviewed
- `contracts/src/HypersnapBridge.sol`
- `contracts/test/Permit.t.sol`
- `contracts/foundry.toml`
- `src/core/validations/contract_signature.rs`
- `src/core/validations/contract_signature/Erc6492.sol`
- `src/core/validations/contract_signature/README.md`
- `src/core/validations/verification.rs` (caller of `verify_signature`)
