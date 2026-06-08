# F047 trace — owner-rotation front-run / seizure defeats key-compromise recovery

Finding: F047 (owner-rotate-race, severity high, validation HAS_CAVEATS / 0.85)
Commit: cab225f (READ-ONLY `code/hypersnap`)
Contract: `code/hypersnap/contracts/src/HypersnapBridge.sol`

This trace documents the entry→sink reachability for the front-run/seizure of
the recovery `rotateOwner`. It does not re-judge the verdict.

## Entry point(s) (file:line)

Two distinct attacker-controlled entry points, both `external`, both
permissionless relays (no `msg.sender` check — auth is by recovered signature
only):

- SEIZURE entry: `rotateOwner(uint64,address,bytes,bytes)` —
  `HypersnapBridge.sol:229` (gate `:235`, auth recover `:243`, accept recover
  `:251`, sink `:255-256`).
- GRIEF entry (any one of the shared-watermark consumers, all set
  `latestBlock = blockNumber` after an `ownerAddress` ecrecover):
  - `claim` root-advancement — `HypersnapBridge.sol:188` (recover `:194`, sink `:195`)
  - `proposeUpgrade` — `HypersnapBridge.sol:271` (gate `:276`, recover `:286`, sink `:306`)
  - `cancelUpgrade` — `HypersnapBridge.sol:316` (gate `:321`, recover `:330`, sink `:331`)
  - `pause` — `HypersnapBridge.sol:361` (gate `:362`, recover `:367`, sink `:368`)
  - `recoverERC20` — `HypersnapBridge.sol:399` (gate `:399` region, recover/sink `:410-411`)

The VICTIM transaction whose reachability is being denied/overtaken is the
defenders' recovery `rotateOwner(block=N, O2, authSig_O1, acceptSig_O2)` —
same function, `:229`.

## Trust boundary crossed

Off-chain signer identity → on-chain owner authority. Authorization is
established purely by `ECDSA.recover(...) == ownerAddress` (`:243`, and `:194 /
:286 / :330 / :367 / :410` for the grief consumers). The boundary is crossed by
whoever holds the `O1` private key. The finding's precondition is that `O1` is
the COMPROMISED group key (the exact and only scenario the documented recovery
at `:266-270` exists for), so the attacker is on the trusted side of this
boundary until the rotation lands. No second boundary (timelock, guardian,
pending-owner accept window, pause gate on `rotateOwner`) sits between entry and
sink.

## Call path (ordered file:line hops in HypersnapBridge.sol)

The mechanism is a race between two transactions over the SHARED `latestBlock`
watermark. Both paths are linear, single-function, no internal cross-calls.

Attacker SEIZURE path (`rotateOwner`, attacker-chosen `newOwner = O_attacker`):
1. `:235` `if (blockNumber <= latestBlock) revert StaleBlock` — passes (attacker picks `blockNumber = N`, `latestBlock < N`).
2. `:236` `if (newOwner == address(0)) revert ZeroAddress` — passes (`O_attacker != 0`).
3. `:238-242` build `authDigest = keccak256(DOMAIN_OWNER_UPDATE, bytes8(N), bytes20(O_attacker))`.
4. `:243` `authDigest.recover(authorizationSig) != ownerAddress` — passes: attacker holds `O1`, signs over `O_attacker`; `ownerAddress` is still `O1`.
5. `:247-250` build `acceptDigest = keccak256(DOMAIN_OWNER_ACCEPTANCE, bytes20(O_attacker))`.
6. `:251` `acceptDigest.recover(acceptanceSig) != newOwner` — passes: attacker controls `O_attacker`, signs the (block-free, chainId-free) acceptance offline.
7. SINK `:255` `latestBlock = blockNumber` (= N); `:256` `ownerAddress = newOwner` (= O_attacker); `:257` `OwnerRotated` emitted.

Victim recovery path (defenders' `rotateOwner(block=N, O2, …)`), AFTER attacker lands:
1. `:235` `if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber)` — REVERTS, because attacker's tx set `latestBlock = N` and the victim's `blockNumber == N` (or any `<= N`). Legitimate rotation never reaches its sink.

Attacker GRIEF path (e.g. `pause` to bump the watermark without seizing):
1. `pause:362` gate passes (`blockNumber = N > latestBlock`).
2. `pause:363-366` build `DOMAIN_PAUSE` digest; `:367` recover `== ownerAddress` (O1) passes.
3. SINK `pause:368` `latestBlock = blockNumber` (= N).
4. Victim `rotateOwner(block=N)` then hits `:235` and REVERTS `StaleBlock` exactly as above.
   (Identical shape via `claim:195`, `proposeUpgrade:306`, `cancelUpgrade:331`, `recoverERC20:411`.)

## Attacker capability / preconditions

- Holds the compromised `O1` key (the recovery scenario's stated precondition;
  per validation H2 the attacker therefore already has bridge control — the NEW
  harm is that recovery becomes impossible and the attacker can become sole
  permanent owner).
- Can observe the public mempool and submit a higher-priority-fee transaction
  (standard EVM front-running capability; validation H6 affirms realistic).
- Controls an EOA `O_attacker` for the seizure variant — can self-produce
  `acceptSig_O_attacker` offline because the acceptance digest (`:247-250`)
  binds neither `blockNumber`, `chainId`, nor `address(this)`.
- No 48h timer, no second/lagging deployment, no withheld relay required
  (distinct from F045). Single won mempool race per round; seizure is a single
  won race, permanent.

## Guards on the path

- `:235` `StaleBlock` (shared monotonic 64-bit `latestBlock`): NOT a defense —
  it is the weapon. First `block >= N` action to land wins; attacker wins by
  fee. Simultaneously the guard that REVERTS the victim's recovery.
- `:236` `ZeroAddress`: irrelevant — attacker uses a non-zero EOA.
- `:243` auth ecrecover: passes for the attacker (still-owner `O1`); digest does
  NOT bind current owner, chainId, or `address(this)`, so a fresh `O1`→
  `O_attacker` authorization is producible.
- `:251` accept ecrecover: passes for the attacker (`O_attacker` self-signed);
  no block/chainId binding, pre-fabricable.
- No `whenNotPaused` modifier on `rotateOwner` or on the grief consumers'
  watermark-bump (pause itself is a watermark consumer); no `msg.sender` gate;
  no pending-owner accept window; no timelock; `_authorizeUpgrade` (`:426`)
  offers no override. No guard stops either attacker path or saves the victim.

## Reachability verdict

REACHABLE (confirmed). Both the seizure entry (`rotateOwner:229`) and the grief
entries (`pause:361`, `proposeUpgrade:271`, `cancelUpgrade:316`, `claim:188`
root-advancement, `recoverERC20:399`) are live `external` functions whose only
gate is a signature recovering to `ownerAddress` plus `blockNumber > latestBlock`
— all satisfiable by an attacker holding the compromised `O1`. The sink
`latestBlock = blockNumber` (`:255`, and `:195/:306/:331/:368/:411`) deterministically
forces the defenders' recovery `rotateOwner` to revert `StaleBlock` at `:235`.
The only non-mechanical element is winning the public-mempool fee race, a
standard EVM capability (validation H6). No PoC shipped (validation H8 =
NEEDS_MORE_DATA), but every hop is verified against source; reachability of the
harm is sound.

## Shared root cause (related-but-distinct)

Same root cause family as F045 / F048 / F049: a single strictly-monotonic 64-bit
watermark `latestBlock` (`:235/:276/:321/:362/:399` gates; `:255/:306/:331/:368/:411`
bumps) governs every universal control-plane action with no per-action namespace
and no rotation priority. F047's distinct primitive: same-deployment mempool
front-run of the recovery rotation — grief via any watermark consumer, or
seizure via attacker-chosen `rotateOwner`. Closest sibling is F049 (watermark
saturation); F048 (pause/propose timing window); F045 (cross-deployment replay).
LINK, do not merge.
