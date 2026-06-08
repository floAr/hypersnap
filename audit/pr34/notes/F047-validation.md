# F047 validation — owner-rotation race front-runs key-compromise recovery

Validator: validator (deliberate-disagreement role)
Finding: F047 (specialist solidity-bridge, attack_class owner-rotate-race, severity_initial high)
Commit audited: cab225f (workspace HEAD == pinned commit; verified `git log -1`)

## Mechanics re-derived from source (HypersnapBridge.sol)

- `rotateOwner` L229-258: gate L235 `if (blockNumber <= latestBlock) revert StaleBlock`;
  on success L255-256 `latestBlock = blockNumber; ownerAddress = newOwner`. No dedicated
  counter, no commit/reveal, no pending-owner state, no priority over peers. CONFIRMED.
- Authorization digest L238-242 binds only `(DOMAIN_OWNER_UPDATE, bytes8(blockNumber),
  bytes20(newOwner))`. No binding to the *current* owner, no chainId, no address(this). CONFIRMED.
- Acceptance digest L247-250 binds only `(DOMAIN_OWNER_ACCEPTANCE, bytes20(newOwner))`.
  No block, no chainId. An attacker who picks `newOwner = O_attacker` (an EOA it controls)
  can produce `acceptSig_O_attacker` offline. CONFIRMED.
- Shared watermark consumers that bump `latestBlock` after an `ownerAddress` ecrecover:
  `claim` root-update L188/L194-196, `proposeUpgrade` L276/L286/L306, `cancelUpgrade`
  L321/L330-331, `pause` L362/L367-368, `recoverERC20` L399/L410-411. All set
  `latestBlock = blockNumber`. CONFIRMED — any of them landed at `block >= N` makes a
  pending `rotateOwner(block=N)` revert StaleBlock.
- Documented recovery narrative L266-270 names `rotateOwner(... O2 ...)` "immediate, no
  delay" as step 2 of the key-compromise response. CONFIRMED — this is the guarantee the
  finding breaks.

Rust side (bridge_payload.rs): `owner_update_signing_payload` L97-104 = tag||u64_be(block)||
new_owner; `owner_acceptance_signing_payload` L115-121 = tag||new_owner. Preimages match the
Solidity contract exactly — no off-chain anti-front-run binding exists either. CONFIRMED. This
is an on-chain race-model defect, not an encoding asymmetry; the two-pipeline-confusion lesson
does not apply (single rotation pipeline, Rust merely mirrors it).

Seizure variant verified end-to-end: attacker holds compromised `O1` => L243 auth recover ==
ownerAddress (still O1) passes; attacker controls `O_attacker` => L251 accept recover ==
newOwner passes; `ownerAddress = O_attacker`. The attacker does NOT need to reuse the
defenders' O2-authorization (which is bound to O2) — it signs a fresh O1-authorization over
O_attacker. The finding's logic holds.

## 8-hypothesis walk

### H1 — Upstream auth / gate. STANDS
The only gates upstream of the StaleBlock check are `blockNumber > latestBlock`, `newOwner !=
0`, and the two ecrecovers. There is no access-list, no msg.sender restriction (rotateOwner is
permissionless relay), no pause gate on rotateOwner. Nothing upstream prevents the attacker
(holding O1) from satisfying every gate. No missed upstream protection.

### H2 — Consumer-side impact. PARTIALLY INVALIDATED (impact framing, not existence)
The consumer of the corrupted state is `ownerAddress` / `latestBlock`. The grief ("retain
power") variant: the attacker *already* holds O1 and therefore already has full bridge control
(claim-mint, proposeUpgrade, pause) BEFORE any front-run. So "old compromised owner retains
power" is largely a restatement of the precondition, not new harm — the attacker loses nothing
by NOT front-running, and gains nothing it didn't already have, in the grief case. The
load-bearing harm is narrower and real: the *defenders' recovery is defeated*, i.e. the
compromise transitions from recoverable to UNRECOVERABLE. The seizure variant adds genuinely
new harm beyond holding O1: `ownerAddress` becomes a single EOA the attacker solo-controls, so
even a partial/social recovery of the threshold key O1 no longer helps — the defenders are
permanently locked out of the owner role. Net: finding is real, but the "retain power" phrasing
overlaps the precondition; the defensible impact is "key-compromise recovery is defeatable /
compromise made unrecoverable," which is High.

### H3 — Downstream enforcement. STANDS
No layer below re-checks rotation legitimacy. There is no pending-owner accept window, no
guardian/timelock on rotateOwner, no higher authority (the contract owner IS the threshold
key; there is no separate admin). `_authorizeUpgrade` reverts (L426) so even the UUPS path
offers no override. Nothing downstream catches the seized ownership.

### H4 — PR HEAD currency. STANDS
Workspace HEAD == pinned cab225f (detached at cab225f, `git log -1` confirms). No drift.

### H5 — Spec carve-out. STANDS (and is the opposite of a carve-out)
The contract docstring L266-270 affirmatively *promises* immediate rotation as the recovery
mechanism. Far from saying "this is intentionally deferred," the docs assert the exact
guarantee the finding shows is false. No carve-out; the doc strengthens the finding.

### H6 — Reachability of harm. STANDS (with H2's framing caveat)
The harm is reachable in the mempool of the single deployment under recovery: the attacker
observes the defenders' `rotateOwner(block=N, O2)` tx, submits a higher-fee O1-signed
watermark-consumer at `block >= N`, and the legitimate rotation reverts. No 48h timer, no
second/lagging deployment, no withheld relay required — distinct from F045. The seizure variant
is a single won race. Public mempool front-running of an EVM tx is a standard, realistic
capability. Reachable.

### H7 — Test wiring. STANDS
`rotateOwner` is a production external function and the contract-documented recovery step; the
watermark consumers are all live external functions. Not a test-only path.

### H8 — PoC mechanics. NEEDS_MORE_DATA (no PoC supplied)
The finding ships no executable PoC, only an attack walk. The walk is mechanically sound
against the source (verified line-by-line above), so the absence of a PoC does not invalidate
it, but it also is not independently demonstrated. A Foundry test would strengthen submission:
(a) grief — pause(N) then assert rotateOwner(N) reverts StaleBlock; (b) seizure — assert
rotateOwner(N, O_attacker, O1-auth, O_attacker-accept) sets ownerAddress = O_attacker. Both
follow directly from the code; confidence is high without them but not maximal.

## Shared-root-cause / dedupe notes

- F047, F048, F049 (and F045) all stem from the SAME root cause: one shared strictly-monotonic
  64-bit watermark `latestBlock` governs every universal control-plane action, with no
  per-action namespace and no rotation priority.
- F047's distinct primitive: same-deployment mempool front-run of the recovery rotation
  (grief via any watermark consumer, or seizure via attacker-chosen rotateOwner).
- F049's distinct primitive: watermark *saturation* (block=2^64-1) permanently bricking
  rotate/cancel while watermark-independent executeUpgrade survives.
- F048: pause/proposeUpgrade timing window.
- The finding's own dedup note links only F045 (cross-deployment replay). It should ALSO be
  cross-linked to F049, which is the closest sibling (both defeat the rotate-based recovery via
  the shared watermark). Recommend: LINK (same root-cause family), do NOT merge — each exposes
  a different exploit primitive and a different broken guarantee. This matches F047's stated
  link-not-merge posture.

## Open follow-ups (not new findings — for specialist consideration)

- The acceptance digest's lack of block/chainId binding (L247-250) also means an `O_attacker`
  acceptance is replayable across deployments and across time; if F045 covers cross-deployment
  replay it may want this datapoint. Datapoint only; no new finding filed.

## Overall verdict

WATERPROOF on mechanics and existence; one impact-framing caveat (H2) — the "old owner retains
power" half overlaps the precondition (attacker already holds O1), so the defensible headline is
"documented key-compromise recovery is defeatable / compromise made unrecoverable, and attacker
can become sole permanent owner." That is squarely High. Because the core defect, reachability,
and severity all survive and only a sub-claim's framing is trimmed, overall verdict HAS_CAVEATS.

Verdict: HAS_CAVEATS
Confidence: 0.85
