# Dedupe report

Role: dedupe-curator (LINK-ONLY). No findings were deleted, merged, or edited in
body. Only `related_findings:` / `relationship:` frontmatter entries were added,
symmetrically, to the affected findings.

Library SHA: b2c8f8bade0bf4b91d254eb4d5774b7fd3e3c1ea
Date: 2026-06-08

## Pairs examined

Scanner candidate pairs (`.audit/dedupe.json`), matched by `file_paths_overlap`:

- F045 <-> F047
- F045 <-> F049
- F047 <-> F049

Plus two validator-flagged clusters the scanner heuristic missed (no scanner pair,
but explicitly recommended for cross-linking):

- Bridge-watermark cluster: F048 added to the F045/F047/F049 family.
- Slashing false-positive cluster: F002, F009, F015.

## Same root cause (0)

None. No pair was judged a duplicate warranting merge. Every linked pair shares a
root-cause *family* but exposes a distinct exploit primitive against a distinct
broken guarantee, so all relationships are recorded as related-but-distinct links
rather than merges.

## Related but distinct (2 clusters / 9 linked pairs)

### Bridge-watermark cluster — F045, F047, F048, F049 (full clique, 6 pairs)

Shared root family: `HypersnapBridge.sol` gates heterogeneous *universal*
control-plane actions (`claim` root-update, `rotateOwner`, `proposeUpgrade`,
`cancelUpgrade`, `pause`, and chain-bound `recoverERC20`) on a *single shared
strictly-monotonic 64-bit watermark* `latestBlock`, while the permissionless
`executeUpgrade` is watermark-independent. Applying the two-pipeline-confusion
lens, each finding traces a genuinely different entry-to-consumer path, so they
are linked, not merged:

- **F045 <-> F047:** Both abuse the shared watermark namespace, but F045 is a
  *cross-deployment* replay (an attacker/relayer keeps a lagging deployment B
  watermark-stale and replays a superseded universal signature whose block number
  B never consumed), whereas F047 is a *single-deployment mempool front-run race*
  on `rotateOwner` (the still-valid compromised `O1` bumps `latestBlock` to defeat
  the documented immediate-rotation recovery, or installs `O_attacker` outright).
  Distinct primitive (withheld-relay vs. mempool ordering), distinct guarantee
  broken. F047's own dedup note already recommends link-not-merge with F045.

- **F045 <-> F049:** F045 = superseded universal signatures surviving on a
  watermark-stale deployment (cross-deployment). F049 = a single max-block
  (`type(uint64).max`) universal signature *saturating* the watermark on one
  deployment, permanently bricking `rotateOwner`/`cancelUpgrade`/`pause`/root-update
  while the watermark-independent `executeUpgrade` still fires the pending
  implementation. Complementary failure modes of the same shared counter; F049's
  body explicitly calls them complementary, not duplicates.

- **F047 <-> F049:** Both are *single-deployment* control-plane DoS/seizure paths
  rooted in the shared watermark, but F047 is a fee-priority front-run race
  (attacker must win each round) while F049 is a one-shot permanent saturation to
  the type maximum (no race; the counter can never move again). Different mechanic,
  same family.

- **F048 <-> {F045, F047, F049}:** F048 (pause does not gate `proposeUpgrade`;
  a late propose collapses the documented 24h "guaranteed lockout" cushion to zero)
  belongs to the same `latestBlock`/universal-payload + permissionless-`executeUpgrade`
  root family. Its mechanic is distinct again: it abuses the *missing `whenNotPaused`
  modifier on `proposeUpgrade`* and attacker-chosen propose timestamp rather than the
  watermark counter directly. F048's body explicitly notes it compounds with F045 on
  a lagging deployment (pause is the last line of defense before a UUPS swap), and it
  is the medium-severity defense-in-depth degradation surrounding the same upgrade
  pipeline F049 attacks. Linked across the whole cluster.

### Slashing false-positive cluster — F002, F009, F015 (full clique, 3 pairs)

Shared blast surface: the hyper slashing evidence pipeline
(`detect_conflicting_blocks` -> `verify_evidence_signatures` -> `record_evidence`
-> `slashed_validators_for_epoch`), where each finding causes (or enables) honest
validators to be slashed by *signature-valid* evidence. Distinct root causes:

- **F002 <-> F009:** Both produce false slashing of an honest committee from
  genuinely signature-valid blocks, but the defect is in different predicates.
  F002 is a *set-semantics* bug on the cross-epoch path (union of two disjoint
  committees' signers, so an epoch-A-only signer is slashed for an epoch-B block).
  F009 is a *conflict-identity* bug (the predicate keys "distinct" on the
  signature-inclusive `hyper_block_hash`, so two valid sigs over identical signed
  content — DKLS sign-ceremony restart or round retry — are mis-read as a
  double-sign). Overlapping outcome (honest mis-slash), independent root causes.

- **F002 <-> F015 / F009 <-> F015:** F015 is the *evidence-durability* defect —
  `slashing_store::encode_block` zeroes six `signing_payload`-committed fields, so
  persisted evidence is no longer self-verifying. It does not itself produce a false
  slash today; it sits on the same evidence-store path that F002 and F009 feed and
  could let an equivocator evade slashing (or break re-verification) if/when stored
  evidence is re-checked. Same slashing subsystem and the same
  `signing_payload`-vs-`hyper_block_hash` field-set asymmetry that F009 hinges on,
  but F015's root cause is the storage codec dropping signed-only fields, distinct
  from F002's union semantics and F009's signature-inclusive conflict key.

## Unrelated (0)

No examined pair was judged unrelated. All three scanner pairs and both
validator-flagged clusters are genuine same-family relationships.

## Links written (symmetric, link-only)

- Bridge cluster: F045, F047, F048, F049 each carry `related_findings` to the
  other three, `relationship: related-but-distinct`.
- Slashing cluster: F002, F009, F015 each carry `related_findings` to the other
  two, `relationship: related-but-distinct`.

All edited findings' YAML frontmatter was re-parsed and confirmed well-formed.
