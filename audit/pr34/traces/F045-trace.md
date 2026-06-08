# F045 trace — universal control-plane signature replay onto a watermark-lagging sibling deployment

Finding: F045 (claim-signature-replay / cross-side control plane). Verdict carried forward: **HAS_CAVEATS** (not re-judged here).
Commit: `cab225f`. Code is READ-ONLY.

Headline path traced: a universal (chainId-agnostic, address-agnostic) `proposeUpgrade`
signature, observed/superseded on busy deployment A, is replayed by any party onto a
low-traffic sibling deployment B that has been kept at a stale `latestBlock`, lands a
pending UUPS implementation, and (after the 48h timer) is permissionlessly executed via
`executeUpgrade` → `ERC1967Utils.upgradeToAndCall`, taking custody control of B.

## Entry point(s)

Public, unauthenticated (no `onlyOwner`; only an in-payload owner ECDSA sig is checked),
all in `code/hypersnap/contracts/src/HypersnapBridge.sol`:

- `proposeUpgrade(uint64,address,bytes)` — `HypersnapBridge.sol:271` (primary, custody-theft path)
- `cancelUpgrade(uint64,address,bytes)` — `HypersnapBridge.sol:316`
- `pause(uint64,bytes)` — `HypersnapBridge.sol:361`
- `rotateOwner` / owner-acceptance (universal owner-update domain) — `HypersnapBridge.sol:238`/`:247`
- merkle-root update via `claim` root branch — `HypersnapBridge.sol:188` (value path is NOT affected; leaf binds `destinationChainId`)
- `executeUpgrade()` — `HypersnapBridge.sol:346` (downstream sink; permissionless, no fresh sig)

## Trust boundary crossed

Off-chain threshold-signer group key `O` (shared by every canonical deployment) → public
EVM call on a *specific* deployment. The signature authorizes an *action* but the digest
preimage omits any binding to *which deployment* the action is for. Because relay is
permissionless, the submitter is untrusted; the only trust assertion is "the owner group
signed this action," which is true on every deployment simultaneously.

A second boundary is crossed at execution: `executeUpgrade` (`:346`) hands control to
attacker-chosen bytecode via `ERC1967Utils.upgradeToAndCall(impl, "")` (`:354`), the proxy
that custodies wrapped SNAP.

## Signed-digest construction (omits chainId + address)

Solidity preimage for the primary path, `HypersnapBridge.sol:281-285`:

```
keccak256(abi.encodePacked(
    DOMAIN_UPGRADE,          // L282, constant, same on every chain (L56)
    bytes8(blockNumber),     // L283
    bytes20(newImplementation) // L284
))
```

No `block.chainid`, no `address(this)`, no per-deployment id. Same for
`cancelUpgrade` (`:325-329`) and `pause` (`:363-366`). Recovery: `digest.recover(ownerSig)
!= ownerAddress` (`:286`).

Rust payload builder (signer side) agrees byte-for-byte, so the captured-on-A bytes verify
on B unchanged:

- `bridge_payload.rs:133` `upgrade_digest` = `keccak256(tag(DOMAIN_UPGRADE) || u64_be(block) || impl)` (`:134-139`) — no chainId/address.
- `bridge_payload.rs:147` `upgrade_cancel_digest` (`:148-153`) — no chainId/address.
- `bridge_payload.rs:158` `pause_digest` (`:159-163`) — block only.
- `bridge_payload.rs:127` `owner_acceptance_digest` — `newOwner` only, no block at all.
- Contrast: `bridge_payload.rs:170` `recover_erc20_digest` IS chain-bound (`u256_be(chain_id)`), proving the omission elsewhere is by design, not oversight.

Cross-side equality is pinned at `bridge_payload.rs:382` (`cross_side_pinned_vectors`), so
the trace confirms this is a replay-model defect, not an encoding asymmetry.

## Call path (ordered hops)

Off-chain (one-time): validators sign `upgrade_digest(block=4000, implX)` →
`bridge_payload.rs:133`. Sig is universal; valid on A and B forever.

On deployment A (legitimate, then superseded):
1. Relayer → `proposeUpgrade(4000, implX, sigO)` → `HypersnapBridge.sol:271`; gate `4000 > A.latestBlock` passes (`:276`); pending set, `A.latestBlock = 4000` (`:306-309`).
2. Defect found; validators sign cancel(4001); relayer → `cancelUpgrade(4001, implX, sigO)` `:316`; A cleared, `A.latestBlock = 4001` (`:331-333`). A is clean.

On deployment B (attacker-driven replay; B kept at `latestBlock = 100`):
3. Attacker (also a relayer) withholds steps 1-2 from B → B.latestBlock stays 100.
4. Attacker → `proposeUpgrade(4000, implX, sigO)` on B → `HypersnapBridge.sol:271`.
   - Watermark gate `4000 > 100` → PASSES (`:276`).
   - `newImplementation != 0` ok (`:277`); no pending yet (`:278`).
   - Digest rebuilt `:281-285` == the bytes signed off-chain → `recover == ownerAddress` PASSES (`:286`).
   - `proxiableUUID` shape check (`:298-304`) — satisfied by any UUPS-shaped impl, no identity check.
   - State mutated: `B.latestBlock = 4000` (`:306`), `pendingImplementation = implX` (`:308`), `pendingUpgradeEffectiveAt = now + 48h` (`:307,:309`).
5. Attacker withholds cancel(4001) from B (and/or wins the post-48h race).
6. After 48h, anyone → `executeUpgrade()` → `HypersnapBridge.sol:346`; timer check `:350`; sink `ERC1967Utils.upgradeToAndCall(implX, "")` (`:354`). Cancelled-on-A implementation now governs B's custody.

## Attacker capability / preconditions

- No owner-key compromise required for the headline (resurrect-a-superseded-honest-propose) variant: the propose sig stays signature-valid forever; cancel only mutated A's *local* state.
- ≥2 live canonical deployments sharing owner group key `O` — documented topology (validation notes, README L344-350; deploy script). CreateX CREATE3 yields the *same proxy address* on every chain, so `address(this)` would not even disambiguate — only `block.chainid` would; it is absent.
- Attacker is one of the permissionless relayers and can withhold newer sigs from B (low-traffic chain lags naturally; `recoverERC20` sharing the global watermark, `:411`, makes divergence the expected state).
- Holds the superseded-but-valid universal payload bytes (observable on-chain from A's calldata).
- Upper-bound "push brand-new evilImpl" additionally needs owner-key compromise (the contract's own stated threat model, `:266-270`) — see finding caveats; not required for the resurrection path.

## Guards on the path (and why each fails to stop replay)

- `blockNumber > latestBlock` watermark (`:276`/`:321`/`:362`): per-deployment `uint64` (`HypersnapBridge.sol:90`). Rejects only sigs older than B's *local* watermark; a superseded-but-newer-than-100 sig passes. Cannot encode "cancelled on another deployment."
- Owner ECDSA recovery (`:286`): passes — the sig is genuinely owner-signed and universal.
- `pendingImplementation == 0` precondition (`:278`): no cross-deployment awareness.
- `proxiableUUID` UUPS shape check (`:298-304`): structural only; attacker impl satisfies it.
- 48h `UPGRADE_DELAY` + `pause` backstop (`:346` `whenNotPaused`, PAUSE 72h > UPGRADE 48h): mitigates but does not prevent; requires defenders to detect the targeted lagging B and land a higher-block pause before `executeUpgrade`. `pause` is itself universal/replayable and shares the same watermark namespace.
- `OWNER_ACCEPTANCE` (`:247-250`): no watermark at all — replayable forever/everywhere (coverage gap; not solely exploitable).

## Reachability verdict

**RELAYER-ANY** (unauthenticated relay of a previously-owner-signed, superseded universal
payload) for the headline resurrect-a-cancelled-propose path: any party holding the
observed universal sig can reach `proposeUpgrade` → (48h) → permissionless `executeUpgrade`
on a watermark-lagging deployment; no key and no privileged role required, only relayer
positioning to keep B stale. The strongest brand-new-evilImpl variant escalates to
**OWNER-KEY** (matches the contract's documented key-compromise threat model). Lower-bound
(defeated incident response / resurrected disavowed implementation) is RELAYER-ANY and
needs zero attacker capability beyond withholding relays.
