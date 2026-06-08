# F049 Validation — watermark saturation bricks rotate/cancel while executeUpgrade survives

Validator: validator (deliberate-disagreement). Code @ `cab225f` (HEAD confirmed == pinned commit).
Finding specialist: solidity-bridge. Severity_initial: high.

## Core mechanics re-derived independently (file:line)

- `latestBlock` is a raw `uint64` (HypersnapBridge.sol L90). No max-bound constant, no
  sanity cap anywhere in the contract.
- Every universal gate is `if (blockNumber <= latestBlock) revert StaleBlock(...)` then
  `latestBlock = blockNumber` with NO upper bound on the supplied value:
  - `claim` root-update path L188 / L195
  - `rotateOwner` L235 / L255
  - `proposeUpgrade` L276 / L306
  - `cancelUpgrade` L321 / L331
  - `pause` L362 / L368
  - `recoverERC20` L399 / L411
- `executeUpgrade` L346-355: `external whenNotPaused`; body reads ONLY
  `pendingImplementation` (L347), `pendingUpgradeEffectiveAt` (L349). No `latestBlock`
  read, no signature, no caller restriction. Confirmed permissionless + watermark-independent.
- `rotateOwner` (L255-257) writes only `latestBlock` + `ownerAddress`; does NOT touch
  `pendingImplementation`/`pendingUpgradeEffectiveAt`. A pending upgrade survives rotation.
  Confirmed: only `cancelUpgrade` (L332-333) or `executeUpgrade` (L351-352) clears it.
- Rust side bridge_payload.rs: `pause_digest` L158, `upgrade_digest` L133,
  `owner_update_digest` L108, `merkle_root_update_digest` L87 etc. each take a raw
  `block_number: u64` and serialize `.to_be_bytes()` with NO range check. Off-chain
  imposes no ceiling. Confirmed: contract is sole gate and has none.

Saturation logic is sound: setting `latestBlock = type(uint64).max` (2^64-1) means no
`uint64` can satisfy `blockNumber > latestBlock`, so every `> latestBlock`-gated entry
point reverts `StaleBlock` permanently. Monotonicity guarantees it can never recede.

## 8-hypothesis walk

### H1 — Upstream auth / gate. STANDS
Is there an upstream check on `blockNumber` magnitude the finder missed? No. The ONLY
checks before `latestBlock = blockNumber` are the strict-monotonic `<=` revert and a
signature recover. Neither bounds the magnitude. The signature gate does not help here
because the threat model (L266-270, "key-compromise scenario") explicitly assumes the
attacker holds the threshold key and can sign any payload. Off-chain (bridge_payload.rs)
imposes no ceiling either. No upstream gate caps the value.

### H2 — Consumer-side impact. STANDS
What consumes the saturated `latestBlock`? Every universal control-plane entry point. Once
saturated, `rotateOwner`/`cancelUpgrade`/`pause`/`claim`-root-advance/`recoverERC20` all
revert forever. These are exactly the value/control-bearing consumers; the corrupted state
is not inert. The "lower-bound variant" (saturate with no pending upgrade) is an
unconditional permanent control-plane DoS — also a real consumer impact.

### H3 — Downstream enforcement / alternate recovery path. STANDS (with one nuance noted)
Is there any recovery path below the saturated watermark? Searched the contract:
- No unpause/admin-reset function. `pause` auto-expires (L359 comment "no unpause path").
- No owner-override that bypasses the watermark. `_authorizeUpgrade` reverts unconditionally
  (L426-428); `upgradeToAndCall` reverts `UseUpgradeFlow` (L418-420). The inherited UUPS
  path is sealed, so there is genuinely no out-of-band upgrade to a fixed implementation.
- `initialize` is `initializer`-guarded (already initialized). No re-init escape.
Nuance: a future V2 reached via `executeUpgrade` BEFORE saturation could add a reset — but
in the attack ordering the saturation lands first and disables the very path (cancel/rotate)
needed to deploy a benign V2. No alternate recovery exists at `cab225f`.

### H4 — PR HEAD currency. STANDS
`git log -1` on code/hypersnap == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, identical to
the finding's pinned `commit`. Branch has not moved. No drift.

### H5 — Spec carve-out. STANDS (and strengthens the finding)
Does any doc say this is intentionally deferred? The opposite. The contract DOC-COMMENTS
the recovery sequence as a guarantee: L266-270 ("rotateOwner ... immediate, no delay" →
"O2 signs cancelUpgrade" → "malicious upgrade's 48h timer never fires"), and L64-71 claims
a "24h guaranteed lockout window." The finding shows those documented guarantees are false
under saturation. No carve-out says "saturation/unbounded block number is a known
limitation." This converts to "operator-facing docs assert a recovery that the code does
not actually provide."

### H6 — Reachability of harm. STANDS
Two-pipeline check (per lesson): is the harm path the one that reaches value? Yes, and it is
single-deployment / single-pipeline — no confusion with a sibling structure. Path: attacker
holds O1 → `proposeUpgrade(evilImpl)` (L271) sets pending + 48h timer → `pause(2^64-1)`
(L361) saturates watermark + sets 72h pauseExpiry → defenders cannot `rotateOwner` or
`cancelUpgrade` (both `StaleBlock`) → after pauseExpiry passes, permissionless
`executeUpgrade()` (L346) passes `whenNotPaused` (expired) and `block.timestamp >=
effectiveAt` (72h > 48h) → `ERC1967Utils.upgradeToAndCall(evilImpl, "")` swaps the proxy.
Custody theft reachable. The UUPS-compatibility guard at propose-time (L298-304) does not
block this — a malicious impl can trivially expose a correct `proxiableUUID`.

### H7 — Test wiring. STANDS
All entry points are production `external` functions on the deployed contract, not test
shims. `executeUpgrade`, `pause`, `rotateOwner`, `cancelUpgrade` are all real ABI surface.
The buggy gate pattern is the actual production code path.

### H8 — PoC mechanics. PARTIALLY — NEEDS_MORE_DATA (no PoC artifact present)
The finding ships a prose attack walk, not an executable PoC. The walk's arithmetic is
internally consistent and each step maps to a verified file:line. Caveat I could not fully
discharge: the walk assumes the attacker can produce a valid threshold ECDSA signature at
`block=2^64-1` AND a valid acceptance signature is NOT required for `pause`/`proposeUpgrade`
(correct — only `rotateOwner` needs the acceptance sig, L247-253). For the saturating
`pause`, only one owner sig is needed (L367) — confirmed feasible under key-compromise. The
"signable" precondition (attacker holds the group key) is exactly the contract's own stated
threat model, so it is not an additional assumption. No PoC to mis-assert, so no PoC-level
false-positive risk; but absence of an on-chain reproduction is a (minor) confidence cap.

## Severity judgment
High is appropriate. Under the contract's OWN documented key-compromise threat model the
finding yields total custody theft of a deployment, plus an unconditional permanent
control-plane DoS variant. Both preconditions (key compromise, or merely the ability to land
one valid universal sig) are within the stated model. Not Critical-by-default because it is
scoped to the key-compromise / signer-capable adversary rather than a fully unprivileged
attacker, but the impact ceiling (custody loss + permanent brick) is squarely High.

## Dedupe note (F045 / F047 / F048)
Shared ROOT CAUSE across all four: a single shared strictly-monotonic `latestBlock`
watermark gates all universal control-plane actions, and `executeUpgrade` is
watermark-independent + permissionless. They are RELATED (same structural defect family),
not duplicates — distinct exploit mechanics:
- F045: cross-deployment replay of superseded universal sigs onto a lagging deployment.
- F047: same-deployment front-run race — old owner bumps the watermark to starve the
  recovery `rotateOwner`.
- F048: `proposeUpgrade` not `whenNotPaused`-gated; late propose erases the 24h cushion.
- F049 (this): permanent SATURATION of the watermark to `uint64.max` bricks
  rotate/cancel/pause/root-advance, while the pending upgrade still fires via the
  watermark-independent `executeUpgrade`.
Recommend the dedupe stage LINK F049 to F045/F047/F048 under a shared "watermark-namespace
+ executeUpgrade watermark-independence" theme; do NOT merge. F049's saturation/permanence
is a genuinely separate failure mode and its own fix (a max-advance bound) differs from the
others' fixes.

## Open follow-ups (NOT new findings)
- The UUPS-compat guard (L298-304) is propose-time only and trivially satisfiable by a
  malicious impl exposing the correct `proxiableUUID`; worth a specialist look at whether
  `executeUpgrade` should re-verify owner-unchanged-since-propose (the finding already
  recommends this). Surfaced here for the specialist, not filed.

## Verdict
Overall: WATERPROOF (one minor confidence cap from absence of an executable PoC, H8).
Confidence: 0.88. All 8 hypotheses walked; finding survives every invalidation attempt and
H5 actively strengthens it (documented recovery is contradicted by code).
