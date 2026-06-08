# F049 Trace — watermark-saturation brick

Code @ `cab225f`. READ-ONLY trace; verdict (WATERPROOF, high) unchanged.

## Entry point(s)

The saturating entry point is any universal watermark-consuming `external`
function reached with `blockNumber = type(uint64).max` (2^64-1). The
canonical/cheapest is:

- `HypersnapBridge.pause(uint64 blockNumber, bytes ownerSig)` —
  `code/hypersnap/contracts/src/HypersnapBridge.sol:361` (single owner sig, no
  acceptance sig, no pending-state precondition).

Equivalent saturating entries (same gate pattern):
- `claim` root-update path — `HypersnapBridge.sol:188`
- `rotateOwner` — `HypersnapBridge.sol:235`
- `proposeUpgrade` — `HypersnapBridge.sol:276`
- `cancelUpgrade` — `HypersnapBridge.sol:321`
- `recoverERC20` — `HypersnapBridge.sol:399`

Custody-theft sink entry point (no watermark, permissionless):
- `HypersnapBridge.executeUpgrade()` — `HypersnapBridge.sol:346`.

## Trust boundary crossed

Off-chain threshold signer → on-chain. The off-chain Rust digest builders in
`bridge_payload.rs` emit a signature over a `block_number: u64` that is
serialized verbatim with **no upper bound**, e.g. `pause_digest`
(`crates/hypersnap-crypto/src/bridge_payload.rs:158`) →
`buf.extend_from_slice(&block_number.to_be_bytes())`
(`bridge_payload.rs:162`). The same unbounded `u64 .to_be_bytes()` serialization
appears in every universal builder: `merkle_root_update_signing_payload:80`,
`owner_update_signing_payload:101`, `upgrade_digest:137`,
`upgrade_cancel_digest:151`, `recover_erc20_digest` (block field). No range
check exists on either side; the on-chain contract is the sole gate and it
imposes no ceiling.

The exploit assumes the signer can produce one valid threshold signature over a
max-block payload — exactly the contract's own documented key-compromise threat
model (`HypersnapBridge.sol:266-270`).

## Call path (ordered hops)

Saturation leg (brick):

1. Off-chain: `pause_digest(block_number = u64::MAX)` —
   `bridge_payload.rs:158` → serializes `block_number.to_be_bytes()` unbounded —
   `bridge_payload.rs:162`. Threshold-signed over this digest.
2. On-chain: `pause(2^64-1, ownerSig)` — `HypersnapBridge.sol:361`.
3. Gate `blockNumber <= latestBlock` — `HypersnapBridge.sol:362`. With prior
   `latestBlock < 2^64-1` the gate passes (2^64-1 is strictly greater).
4. Signature recover/identity check — `HypersnapBridge.sol:367`. Passes under
   key-compromise.
5. `latestBlock = blockNumber` (= 2^64-1) — `HypersnapBridge.sol:368`. The
   shared `uint64 latestBlock` (`HypersnapBridge.sol:90`) is now permanently
   saturated.

Post-saturation, every universal gate `blockNumber <= latestBlock` is
unsatisfiable (no `uint64` exceeds 2^64-1), so each reverts `StaleBlock`
forever:
- `rotateOwner` — revert at `HypersnapBridge.sol:235` (never reaches the
  `latestBlock`/`ownerAddress` writes at `:255-256`).
- `cancelUpgrade` — revert at `HypersnapBridge.sol:321` (never reaches the
  pending-impl clear at `:332-333`).
- `pause` (re-pause) — revert at `HypersnapBridge.sol:362`.
- `claim` root-advance — gate `:188` falls to the `else` mismatch branch
  `:198-201`, freezing root advancement.
- `recoverERC20` — revert at `HypersnapBridge.sol:399`.

Sink leg (custody theft, watermark-independent):

6. Pre-saturation: attacker lands `proposeUpgrade(N, evilImpl, sig)` —
   `HypersnapBridge.sol:271`; sets `pendingImplementation`,
   `pendingUpgradeEffectiveAt = now + 48h` — `:308-309`. (UUPS-compat guard
   `:298-304` is trivially satisfiable by a malicious impl exposing the correct
   `proxiableUUID`.)
7. After the 72h pause auto-expires, anyone calls `executeUpgrade()` —
   `HypersnapBridge.sol:346`. Reads ONLY `pendingImplementation` (`:347`) and
   `pendingUpgradeEffectiveAt` (`:349`); no `latestBlock` read, no signature, no
   caller check.
8. `block.timestamp < effectiveAt` check — `:350` (48h < 72h elapsed, passes) →
   `ERC1967Utils.upgradeToAndCall(impl, "")` — `HypersnapBridge.sol:354`. Proxy
   swapped to attacker implementation → custody theft.

`rotateOwner` (`:255-257`) writes only `latestBlock` + `ownerAddress` and does
NOT clear `pendingImplementation`/`pendingUpgradeEffectiveAt`; only
`cancelUpgrade` (`:332-333`) or `executeUpgrade` (`:351-352`) clears the pending
upgrade. Since saturation disables `cancelUpgrade` and `rotateOwner`, the
surviving pending upgrade fires at step 8.

## Attacker capability / preconditions

- Holds the threshold owner key `O1` (or can otherwise land one valid universal
  signature). This is the contract's stated key-compromise threat model
  (`HypersnapBridge.sol:266-270`), not an added assumption.
- For the brick-only variant: a single signed `pause(2^64-1)` (or any universal
  payload at 2^64-1). No pending upgrade required.
- For the custody-theft chain: additionally a `proposeUpgrade(evilImpl)` landed
  before/with the saturation, and the ability to wait out the 72h pause then
  call permissionless `executeUpgrade()`.
- `executeUpgrade` itself requires no key — it is `external` and permissionless.

## Guards on the path

- Strict-monotonic watermark gate `blockNumber <= latestBlock`
  (`:188/:235/:276/:321/:362/:399`) — bounds only the lower edge; provides NO
  upper cap, and once saturated its monotonicity makes the brick permanent.
- ECDSA `digest.recover(...) == ownerAddress` (`:194/:243/:286/:330/:367`) —
  satisfied under the key-compromise model; does not bound block magnitude.
- `whenNotPaused` on `executeUpgrade` (`:346`) — only delays the sink until the
  72h pause expires (72h > 48h upgrade delay, so it always elapses first).
- UUPS-compat guard (`:298-304`) — propose-time only, trivially satisfiable.
- No unpause/admin-reset, no watermark reset, no out-of-band UUPS path
  (`upgradeToAndCall` reverts `UseUpgradeFlow` :418-420; `_authorizeUpgrade`
  reverts :426-428), `initialize` is `initializer`-guarded. No recovery exists
  below the saturated watermark at `cab225f`.

## Reachability verdict

REACHABLE (conditional on signer capability). Justification: the digest builders
serialize `block_number` as raw unbounded `u64` (`bridge_payload.rs:162` and
peers), the on-chain gates accept `2^64-1` (`HypersnapBridge.sol:362` et al.) and
commit it to the shared `latestBlock` (`:90`/`:368`), permanently reverting every
universal control-plane recovery action (rotate `:235`, cancel `:321`, re-pause
`:362`, root-advance `:188`), while the surviving pending upgrade is executed by
the watermark-independent, permissionless `executeUpgrade()` (`:346` → `:354`).
The sole precondition — one valid threshold signature over a max-block payload —
is the contract's own documented key-compromise threat model. No on-chain
recovery path exists below the saturated watermark.

## Shared root cause

RELATED (shared root cause, distinct mechanics) with F045/F047/F048: a single
shared strictly-monotonic `latestBlock` namespacing all universal actions, plus
a watermark-independent permissionless `executeUpgrade`. F049's distinct
mechanic is permanent saturation to `uint64.max`; its fix (a max-advance bound /
separate cancel counter) differs from the others'. Link, do not merge.
