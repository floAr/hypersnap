# F045 validation — universal control-plane signature replay onto watermark-lagging deployments

Validator: validator (deliberate-disagreement). Commit `cab225f`.
Finding claims: six universal control-plane payloads (merkle-root-update,
owner-update, owner-acceptance, upgrade, upgrade-cancel, pause) omit both
`block.chainid` and `address(this)`, so a still-signature-valid but superseded
universal sig replays onto any deployment kept watermark-stale; worst case is a
UUPS impl swap (custody theft) on a lagging deployment.

## Core mechanics confirmed (independent re-read)

- **Payloads omit chainId AND contract address — TRUE.** Solidity digests bind
  only `(DOMAIN, bytes8(blockNumber), payloadFields)`:
  - root-update `HypersnapBridge.sol:189-193`
  - owner-update auth `:238-242`, owner-acceptance `:247-250` (no block at all)
  - propose `:281-285`, cancel `:325-329`, pause `:363-366`.
  None include `block.chainid` or `address(this)`. The Rust encoders match
  byte-for-byte: `bridge_payload.rs` `upgrade_digest:133`, `upgrade_cancel_digest:147`,
  `pause_digest:158`, `owner_update_digest:108`, `owner_acceptance_digest:127`,
  `merkle_root_update_digest:87`. Only `recover_erc20_digest:170` binds chainId.
  Cross-side vectors pinned at `cross_side_pinned_vectors:382`. This is not an
  encoding asymmetry — both sides agree the payloads are universal.
- **"Same group key across deployments" precondition — REAL, and it is the
  documented design.** `contracts/README.md` and `script/Deploy.s.sol` describe
  deploying to many chains (Ethereum/Base/Arbitrum/Optimism/Polygon table,
  README L344-350) and rotating each deployment's owner to the *same* threshold
  address; README L143-144 states "Universal — same sig pauses every deployment,"
  L128-131 documents a rotate+cancel recovery that must land on every chain. The
  finding's two-deployment / shared-owner setup is the intended topology, not a
  contrived edge case.
- **No domain separator / deployment id exists.** There is no EIP-712
  `domainSeparator`, no `address(this)`, no per-deployment `deploymentId` in any
  universal preimage. CreateX CREATE3 deploy (README L232-260) gives **the same
  proxy/impl address on every chain**, so even if `address(this)` were added it
  would not disambiguate — only `block.chainid` would. This strengthens, not
  weakens, the finding's fix recommendation (chainId is the load-bearing binding).

## 8-hypothesis walk

**H1 — Upstream auth / gate.** The only upstream gate on each universal entry
point is `blockNumber > latestBlock` (`:188/:235/:276/:321/:362`) plus the owner
`ecrecover`. The signature itself is valid on B (same owner key); the watermark
gate passes whenever B's local `latestBlock < N`. No upstream auth blocks the
replay. STANDS.

**H2 — Consumer-side impact.** The corrupted state is consumed by the real
production upgrade pipeline: `proposeUpgrade` → (48h) → permissionless
`executeUpgrade` → `ERC1967Utils.upgradeToAndCall` (`:346-355`). The swapped
implementation governs the proxy that custodies wrapped SNAP. `UpgradeFlow.t.sol`
exercises propose→execute as a real path. Consumer impact is genuine custody
control. STANDS.

**H3 — Downstream enforcement.** Below the watermark there is no second check:
`proposeUpgrade` only runs the `proxiableUUID` shape check (`:298-304`), which an
attacker-built impl trivially satisfies. `executeUpgrade` consults no chain id,
no fresh sig, no owner snapshot. Nothing downstream re-checks deployment
identity. STANDS.

**H4 — PR HEAD currency.** Workspace is a fixed snapshot pinned at `cab225f`;
no remote configured to diff against. The cited lines all resolve at this commit.
NEEDS_MORE_DATA (cannot fetch), but immaterial to the logic — treated as STANDS
for the pinned commit.

**H5 — Spec carve-out.** Searched README + module docs. The only documented
limitation is the "Tail risk" note (README L133-136 / Solidity L266-270): a
*single-key, single-deployment* propose-and-self-rotate within one block. That
carve-out does NOT cover cross-deployment replay of a superseded universal sig.
The universal-vs-chain-specific split is documented as a *feature* ("same sig
relayable everywhere"), with the watermark presented as the replay defense — the
finding's whole point is that this defense is unsound across deployments, which
no doc acknowledges. No carve-out invalidates the finding; it slightly
reframes it (the docs assert a guarantee the code does not provide). STANDS.

**H6 — Reachability of harm.** Requires: (a) ≥2 live deployments sharing the
owner key — documented topology; (b) the attacker holds a superseded-but-still-
valid universal sig — true in the propose/cancel race (the propose sig stays
signature-valid forever; cancel only mutates *local* state); (c) the attacker
keeps B watermark-stale — feasible because relay is permissionless and the
attacker is also a relayer who can withhold newer sigs from B (low-traffic chain
naturally lags; the `recoverERC20`-shares-watermark coupling at `:411` makes
divergence the expected state). All three are realistic for the *defeated-
incident-response* / *cancelled-upgrade-resurrected* impact. The strongest claim
(attacker pushes a brand-new malicious `evilImpl` propose to B) additionally
requires the attacker to *hold the owner key* (key-compromise scenario, the
contract's own stated threat model L266-270) OR to replay a previously-signed
honest `propose(implX)` that was later cancelled. The replay-of-a-superseded-
honest-propose path needs no key compromise and is the finding's headline. STANDS,
with the impact-severity nuance noted under "Caveats."

**H7 — Test wiring.** The buggy entry points are the production functions
themselves (not test-only). `UpgradeFlow.t.sol`, `RotateOwner.t.sol`,
`Pause.t.sol`, `CrossSideDigests.t.sol` all drive these exact digests; the deploy
script wires the real proxy. Production-reachable. STANDS.

**H8 — PoC mechanics.** No executable PoC is attached; the finding argues from
code. The argument is sound: digest preimages provably exclude chainId/address
(verifiable by inspection of `:281-285` etc. and the pinned hex vectors), and the
watermark gate provably cannot encode "superseded-on-another-deployment" (it is a
single per-contract `uint64`). The claim follows from the encodings, so the
absence of a runnable PoC does not weaken it. A pinned-vector cross-check would
make it airtight. STANDS (NEEDS_MORE_DATA only for a literal harness).

## Dedupe assessment (F045 vs F047 / F048 / F049)

Same **root-cause family** — universal payloads sharing one monotonic watermark
with no deployment binding — but **distinct exploit primitives / broken
guarantees**. Should be LINKED, not merged:

- **F045 (this):** *cross-deployment* replay of an already-superseded universal
  sig onto a deliberately watermark-lagging *second* deployment. Unique lever:
  withheld relay + missing chainId/address binding. Unique to F045: the
  `OWNER_ACCEPTANCE` has-no-watermark gap and the `recoverERC20` watermark-
  coupling aggravator.
- **F047 (owner-rotate-race):** *single-deployment*, same-mempool front-run of
  the recovery `rotateOwner`; attacker seizes/retains ownership. No second
  deployment, no withheld relay. F047's own dedup note (L118-127) already
  distinguishes the two.
- **F048 (pause-bypass):** *single-deployment* timing flaw — `proposeUpgrade`
  not `whenNotPaused`, collapsing the 24h cushion. Different mechanism; F048
  explicitly notes it "compounds with F045" on a lagging deployment.
- **F049 (watermark saturation):** *single-deployment* permanent brick via a
  `blockNumber = 2^64-1` sig disabling rotate/cancel while `executeUpgrade`
  still fires. F049's dedup note (L129-134) calls F045 "complementary, not
  duplicates."

Conclusion: F045 is non-duplicate. Its cross-deployment vector is materially
different from F047/F048/F049, all of which are single-deployment. The shared
universal-watermark root cause warrants a linked cluster, not a merge.

## Caveats (impact calibration)

The finding's **lower-bound** impact (a cancelled/superseded universal action
stays live on lagging deployments; documented incident-response guarantees are
defeated) is fully sound and needs no key compromise. The **upper-bound** "total
custody theft via UUPS swap on B" relies either on the contract's own key-
compromise threat model (attacker holds owner key — explicitly in scope per
L266-270) or on replaying a *previously honest* propose that was later cancelled
elsewhere; both are real but the headline "custody theft without key compromise"
holds only for the resurrected-honest-propose variant, which requires that an
honest `implX` capable of draining custody was ever proposed-then-cancelled. That
is a plausible but conditional precondition. Net: severity **high** is justified
(the contract's stated threat model includes key compromise, and even the no-
key-compromise path defeats documented incident response and can resurrect a
disavowed implementation), but the prose should not be read as "unconditional
custody theft on any chain with zero attacker capability." This is a calibration
note, not an invalidation.

## Open follow-ups (NOT new findings)

- `OWNER_ACCEPTANCE` binds only `newOwner` with no watermark and no chainId
  (`:247-250`) — replayable forever/everywhere. The finding already records this
  as a coverage gap; worth a dedicated entry by the owning specialist if not
  covered elsewhere. (Do not create here.)

## Verdict

Overall: **HAS_CAVEATS** (waterproof on mechanics and on the lower-bound impact;
the only caveat is upper-bound severity calibration, not correctness).
Confidence: **0.85**.
