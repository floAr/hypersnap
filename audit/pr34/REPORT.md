# hypersnap — Security Audit Report

**Audited commit:** `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
**Audited branch:** pow
**Repository:** https://github.com/farcasterorg/hypersnap
**Pipeline:** audit-suite + audit-suite-brain @ `b2c8f8bade0b`

## TL;DR

**Revalidation of PR #34 ("proof of work (restored)", `cab225f`) against the prior audit of `pow`@`6449331`.**

- **Prior F001 (Critical — unsigned slashing evidence): FIXED.** `verify_evidence_signatures` now gates evidence ingestion; no bypass path found.
- **Prior [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md) (High — lock admission skips verification): NOT fully fixed** — re-surfaces as **[F035](findings/F035-hyperlockevent-mint-without-balance-closure.md)** (the `HyperLockEvent` path still mints arbitrary value into the threshold-signed verkle root with no balance closure / `lock_signature` check; in-protocol/latent impact since the in-scope L1 `claim` consumes the balance-validated merkle root).

23 findings total (1 invalidated on review): **1 Critical, 12 High, 8 Medium, 1 Low** standing.
Validation verdicts: 8 WATERPROOF · 14 HAS_CAVEATS · 1 INVALIDATED ([F003](findings/F003-ring-vouch-sybil-amplification-no-vouch-caps.md)).

**Most material new issues in the restored branch:** [F028](findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md) (Critical, WATERPROOF) DKLS threshold hard-pinned to 1 → single validator forges group authority; [F070](findings/F070-custody-sig-gate-unwired-in-production-router.md) (High, WATERPROOF) validator-registration custody gate unwired; [F013](findings/F013-fullproposal-missing-height-unwrap-panic-on-gossip.md)/[F016](findings/F016-pending-dkls-inbound-unbounded-epoch-keys.md)/[F022](findings/F022-fullproposal-and-decidedvalue-gossip-paths-lack-per-variant-size-cap.md) (DoS); the [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md)/[F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md)/[F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md)/[F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) bridge-watermark cluster (recovery/upgrade control-plane); and the [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md)/[F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md)/[F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md) slashing-false-positive cluster.

## Findings index

| ID | Severity | Title | Verdict | Related |
|----|----------|-------|---------|---------|
| [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md) | high | F026 cross-epoch evidence slashes innocent validators who signed only one of the two epochs | HAS_CAVEATS (0.72) | [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md), [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md) |
| [F003](findings/F003-ring-vouch-sybil-amplification-no-vouch-caps.md) | high | Ring-vouch sybil clusters cross the crediter trust floor — EigenTrust has no vouch cap, mutual-vouch requirement, or min-vouchee-trust gate | INVALIDATED (0.9) | — |
| [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md) | high | Slashing predicate keys 'conflict' on signature-inclusive block hash; two valid threshold signatures over identical block content (sign-ceremony restart / round retry) are mis-classified as double-sign evidence and slash honest signers | HAS_CAVEATS (0.6) | [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md), [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md) |
| [F011](findings/F011-shard-read-validator-no-protocol-version-enforcement.md) | medium | Shard read-validators have no protocol-version enforcement; stale read-node silently applies post-upgrade chunks under wrong rules and diverges | HAS_CAVEATS (0.8) | — |
| [F012](findings/F012-block-hash-never-rederived-from-header-decouples-signed-value-from-committed-content.md) | high | Block/ShardChunk `hash` is the consensus-committed value but is never re-derived from blake3(header) on validate/commit/read-node paths, decoupling the signed value from the header and body that actually get committed | HAS_CAVEATS (0.6) | — |
| [F013](findings/F013-fullproposal-missing-height-unwrap-panic-on-gossip.md) | high | FullProposal gossip arm calls height().unwrap() before the shard-id guard, so a peer can crash any node with a height-less FullProposal frame | WATERPROOF (0.92) | — |
| [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md) | medium | slashing_store encode_block zeroes signing_payload-committed fields, so persisted equivocation evidence is no longer self-verifying | HAS_CAVEATS (0.85) | [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md), [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md) |
| [F016](findings/F016-pending-dkls-inbound-unbounded-epoch-keys.md) | high | F023a pre-StartDkls buffer keyed by attacker-controlled target_epoch with no global cap or stale-epoch eviction, enabling unbounded memory growth from unauthenticated gossip | WATERPROOF (0.9) | — |
| [F018](findings/F018-dkls-signer-share-keystore-never-pruned-at-epoch-boundary.md) | medium | Per-epoch DKLS23 secret-share keystore (dkls_signers) is never pruned, zeroized, or retired across epoch transitions, so retired threshold shares stay live and signing-capable for the process lifetime | WATERPROOF (0.9) | — |
| [F021](findings/F021-dkls-sender-binding-fail-open-when-party-has-no-registered-peer-id.md) | medium | DKLS inner-sender binding fails open per-party when a committee member registered no libp2p_peer_id, letting any peer spoof that party in a DKLS round | HAS_CAVEATS (0.82) | — |
| [F022](findings/F022-fullproposal-and-decidedvalue-gossip-paths-lack-per-variant-size-cap.md) | medium | FullProposal and DecidedValue gossip ingress paths lack F019 per-variant size caps; full-block payloads bounded only by the 10 MB transport ceiling (memory-amplification DoS) | WATERPROOF (0.82) | — |
| [F024](findings/F024-buffered-dkls-dkg-drain-skips-sender-authentication.md) | high | Pre-StartDkls buffered DKG drain feeds round messages to the ceremony state machine without the [F018](findings/F018-dkls-signer-share-keystore-never-pruned-at-epoch-boundary.md) sender/peer-id check, enabling broadcast-sender spoofing | HAS_CAVEATS (0.84) | — |
| [F025](findings/F025-committee-index-grinding-via-attacker-chosen-validator-key.md) | high | Committee membership is grindable via attacker-chosen validator_key because party indices are assigned by lexicographic key order against a fully predictable per-epoch committee seed | HAS_CAVEATS (0.78) | — |
| [F028](findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md) | critical | DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set size), so any single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations | WATERPROOF (0.9) | — |
| [F035](findings/F035-hyperlockevent-mint-without-balance-closure.md) | high | HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed verkle state root with no balance closure, range proof, or signature verification | HAS_CAVEATS (0.7) | — |
| [F036](findings/F036-confidential-lock-range-proof-defined-but-unwired.md) | low | ConfidentialLockBody.range_proof is carried on the wire but verify_value_range is never wired into the lock-admission path | HAS_CAVEATS (0.9) | — |
| [F039](findings/F039-admin-retry-rpcs-missing-authenticate-request-guard.md) | medium | Admin retry RPCs (retry_onchain_events / retry_fname_events) reachable without authenticate_request guard | HAS_CAVEATS (0.8) | — |
| [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md) | high | Universal control-plane signatures (propose/cancel-upgrade, pause, owner-rotate) replay onto lagging canonical deployments; the per-deployment watermark is not a sound cross-deployment replay defense | HAS_CAVEATS (0.85) | [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md), [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) |
| [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md) | high | Owner rotation has no priority over other watermark-consuming actions; a compromised old owner front-runs the recovery `rotateOwner` to retain power or seize permanent ownership, defeating the documented "immediate rotation" key-compromise recovery | HAS_CAVEATS (0.85) | [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md), [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) |
| [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md) | medium | Pause does not gate proposeUpgrade, so an attacker who defers the malicious propose to land effectiveAt at/after pauseExpiry erases the documented 24h "guaranteed lockout" cushion | WATERPROOF (0.9) | [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md), [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md), [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) |
| [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) | high | A single max-block universal signature saturates the shared watermark, permanently disabling rotateOwner/cancelUpgrade while the watermark-independent executeUpgrade still fires the pending (malicious) implementation | WATERPROOF (0.88) | [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md), [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md) |
| [F068](findings/F068-empty-text-cast-permanently-evades-fee.md) | medium | Empty-text CastAdds (embed/mention/reply-only) permanently evade the per-message fee | HAS_CAVEATS (0.82) | — |
| [F070](findings/F070-custody-sig-gate-unwired-in-production-router.md) | high | Validator-registration custody-signature gate is never wired into the production ingestion path — the router is built without a CustodyResolver, so the lenient validate_event branch runs and the EIP-712 custody cross-sign is never checked, letting an attacker register arbitrary validator keys under any FID | WATERPROOF (0.9) | — |

## F002 — F026 cross-epoch evidence slashes innocent validators who signed only one of the two epochs

## Summary

The F026 cross-epoch slashing path (PR #34) accepts two blocks at the same
`canonical_block_id` carrying *different* epoch tags (`epoch_a != epoch_b`)
as a single "equivocation" conflict, then at enforcement time slashes the
**union** of both blocks' signer sets — block_a's signers resolved against
epoch_a's active set AND block_b's signers resolved against epoch_b's active
set.

Because epoch_a and epoch_b are distinct committees (membership and key
ordering differ), a validator who legitimately participated in **only one**
of the two epochs is slashed for a conflicting block produced by the **other**
epoch's committee, which they never signed and could not have prevented. The
classic same-epoch slashing model ("the epoch's committee collectively
misbehaved") does not transfer to two disjoint committees, but the code
applies it as if it did.

The per-block signature verification (`verify_evidence_signatures`) is
*correct* — each block is genuinely committee-signed for its claimed epoch.
The bug is not unverified evidence; it is that a *validly signed* epoch-A
canonical block is treated as incriminating evidence against epoch-A's
signers merely because some epoch-B block shares its height.

## Affected code (file:line)

- Detection accepts any two same-height blocks with no signer-set-overlap or
  non-canonical guard: `src/hyper/slashing.rs:52-77`
  (`detect_conflicting_blocks`).
- Ingestion verifies each block per-epoch then records, no overlap guard:
  `src/hyper/actor.rs:1587-1620` (`InboundEvidence` handler).
- Enforcement slashes the **union** of both blocks' signers, each resolved
  against its own epoch's active set:
  `src/hyper/runtime.rs:4199-4226` (`slashed_validators_for_epoch`).
- Eviction applied to the active set for `epoch+1`:
  `src/hyper/runtime.rs:4074-4104` (`get_active_validators_enforced` →
  `slashed_validators_for_epoch(prev, ...)`).
- Persisted under `min(epoch_a, epoch_b)`:
  `src/hyper/slashing_store.rs:53-69, 153-168`.

## Attack scenario

1. At height `H`, epoch 5 produces its legitimate canonical block `block_a`,
   threshold-signed by epoch-5's committee. Innocent validator `V` is a
   member of epoch 5's committee and signs `block_a`. `V` is **not** a member
   of epoch 6.
2. An attacker who controls (or colludes with) one member of epoch 6's
   committee gets epoch 6's group key to threshold-sign a junk block
   `block_b` whose `canonical_block_id` is set to the same `H` but with a
   different `hyper_state_root` (and arbitrary `signer_indices`). Since the
   epoch-6 committee can sign anything it agrees to, `block_b` is a *valid*
   epoch-6 signature.
3. Attacker submits `InboundEvidence { block_a, block_b }`.
   - `detect_conflicting_blocks` passes: same `canonical_block_id`, different
     hashes (`slashing.rs:52-77`).
   - `verify_evidence_signatures` passes: `block_a` verifies under epoch-5's
     group key, `block_b` under epoch-6's (`slashing.rs:89-110`).
   - Evidence is persisted under epoch `min(5,6)=5`
     (`slashing_store.rs:163`).
4. At the epoch-6 boundary, `get_active_validators_enforced(6)` calls
   `slashed_validators_for_epoch(5, ...)`, which iterates `block_a`'s signers
   against epoch-5's set — slashing innocent `V` (and every other epoch-5
   signer of the legitimate canonical block) — and `block_b`'s signers
   against epoch-6's set (`runtime.rs:4199-4226`).
5. `V`, who only ever signed epoch 5's honest canonical block, is evicted
   from the active set.

## Impact

False slashing / griefing eviction of honest validators. An adversary needs
only a single validly-signed block in *any* one epoch at a chosen height to
manufacture "cross-epoch equivocation" evidence that evicts the entire
honest committee of the *other* epoch at that height. This:

- Evicts honest validators from the active set (lost rewards, lost
  participation), violating the protocol's slashing-correctness invariant.
- Lets an attacker who can sign one junk block in their own epoch knock out
  the canonical committee of an adjacent epoch, a path to active-set capture
  / liveness degradation.

Severity assessed High: no fund-loss, but direct false-slash of innocent
validators with a low attacker bar (one signed block in one epoch).

## Root cause

The same-epoch equivocation model — "two conflicting blocks signed by the
same group key prove that group misbehaved" (`slashing.rs:3-7`) — is
extended to `epoch_a != epoch_b` without recognizing that the two blocks are
signed by **different committees**. The cross-epoch path therefore lacks the
predicate that actually justifies slashing: that the *same* validators
signed two conflicting blocks. Concretely, there is no check that the
penalized validators appear in *both* blocks' signer sets, and the legitimate
canonical block at `H` is treated as incriminating evidence against its own
honest signers solely because a foreign-epoch block reused its height.

A signature being valid (the F001 fix) is necessary but not sufficient: the
mapping `signer_indices → penalized-validator` correctly resolves each block
against its own epoch, but the *set semantics* (union of two disjoint
committees) is the defect — innocent epoch-A-only signers are penalized for
epoch-B's block.

## Suggested fix

Restrict the penalized set on the cross-epoch path to validators who actually
equivocated, i.e. the **intersection** of the two blocks' resolved signer
sets (validators present and signing in *both* `block_a` and `block_b`).
A validator who signed only one of the two blocks did not equivocate and must
not be slashed.

Equivalently / additionally:
- Require the equivocator to hold shares in both epochs (the stated F026
  justification at `slashing.rs:47-51` is "a validator holding shares for two
  consecutive epochs"), and slash only the resolved validator-keys common to
  both committees.
- Reject cross-epoch evidence where `block_a` is the chain's known canonical
  block at `H` (a canonical block is not equivocation evidence against its
  own signers).
- Constrain `|epoch_a - epoch_b|` to adjacent epochs and re-derive the
  penalized identity by validator-key, not by raw index union, before
  inserting into `slashed`.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.72
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F002 validation — cross-epoch evidence slashes innocent single-epoch signers

Validator: validator (deliberate-disagreement)
Finding: F002 / F026 cross-epoch equivocation false-slash
Commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (HEAD == pinned)
Date: 2026-06-08

## Mechanism confirmed in source

- `detect_conflicting_blocks` (`src/hyper/slashing.rs:52-77`) requires only
  same `canonical_block_id` + different block hash. No same-epoch guard, no
  signer-set-overlap guard, no "is this the chain's canonical block" guard.
  Cross-epoch acceptance is explicit (`epoch_a`/`epoch_b` fields,
  doc-comment lines 47-51, test `accepts_cross_epoch_conflicts` slashing.rs:168).
- Ingest handler `InboundEvidence` (`src/hyper/actor.rs:1587-1620`) detects,
  dedupes, verifies per-block signatures, records — no overlap/canonical guard.
  Reachable from gossip (`gossip_adapter.rs:96-102`, `Body::Evidence`); the
  submitter is unauthenticated (anyone can submit two blocks).
- Persisted under `min(epoch_a, epoch_b)` (`slashing_store.rs:56,163`).
- Enforcement `slashed_validators_for_epoch` (`src/hyper/runtime.rs:4191-4229`)
  iterates BOTH `ev.block_a` and `ev.block_b`, resolves each block's
  `signer_indices` against `get_active_validators_enforced(block_epoch)`
  and inserts ALL resolved keys into one `slashed` BTreeSet — a **union**,
  with **no intersection** / equivocator check. Confirmed: the union-not-
  intersection defect the finding names is present verbatim.
- Consumer: `get_active_validators_enforced` filter excludes any vk in
  `slashed` (`runtime.rs:4090`), feeding proposer selection / DKLS transport
  resolution (`runtime.rs:1217`, `1247`). Production-wired, not test-only.

So the union semantics defect is real and reachable. The eviction of
block_a's honest epoch-5 signers (V) is the code's literal behavior.

## 8-hypothesis walk

### H1 — Upstream auth / gate. PARTIALLY INVALIDATED (impact qualifier)
There is NO upstream gate requiring shared epoch or shared validator set.
Detection/ingest accept disjoint committees. The ONLY upstream check is
per-block threshold-signature verification (`verify_evidence_signatures`,
slashing.rs:89-110), which the finding correctly concedes passes. BUT this
gate does raise the attacker bar that the finding's impact section
understates: to manufacture block_b the attacker needs a VALID epoch-B
threshold signature over a junk block — i.e. control of (or collusion with
enough of) epoch-B's signing committee to produce a real group-key signature.
That is the same capability as "epoch-B committee equivocates," not a
single rogue node. The finding's phrase "an attacker who controls...one
member of epoch 6's committee gets epoch 6's group key" (scenario step 2)
overstates this: one member cannot produce a valid threshold signature
unless the DKLS threshold is 1 (see F028, which is a *separate* finding).
The defect (union slashes block_a's innocent signers) STANDS; the
"low attacker bar / one signed block" characterization is overstated.

### H2 — Consumer-side impact. STANDS
`slashed` is consumed by `compute_active_set_with_filter` → excludes the
validator from the active set at `epoch` (runtime.rs:4088-4104). That set
drives proposer selection and DKLS party/transport resolution
(runtime.rs:1217,1247). Eviction is a real penalty (lost participation /
rewards), not "garbage to disk." Consumer impact is genuine.

### H3 — Downstream enforcement. STANDS
No downstream layer re-checks that the penalized validator signed BOTH
blocks. The filter trusts the `slashed` set wholesale. Nothing rescues the
innocent epoch-5-only signer downstream.

### H4 — PR HEAD currency. STANDS
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` == pinned
commit. Workspace is current; the cited code is live.

### H5 — Spec carve-out. STANDS (no carve-out)
The module doc (slashing.rs:1-11) and F026 doc-comments (slashing.rs:47-51,
85-88) *describe* cross-epoch acceptance as intended, but nowhere is the
union-of-disjoint-committees penalty flagged as "known-incomplete / deferred."
The stated F026 justification ("a validator holding shares for two
consecutive epochs") actually argues FOR the intersection semantics the
finding recommends — so the code contradicts its own stated rationale. No
carve-out protects the union behavior.

### H6 — Reachability of harm. PARTIALLY INVALIDATED (failure-mode caveat)
The path to the *value-bearing consumer* is reachable, BUT the finding's
exact "clean eviction of V" outcome is not what the code produces in the
genuine cross-epoch (epoch_a != epoch_b) case, because of a co-located
recursion bug:
  - At the epoch-6 boundary, `get_active_validators_enforced(6)` calls
    `slashed_validators_for_epoch(5)` (runtime.rs:4074-4075).
  - Inside that call, processing block_a (epoch 5) resolves cleanly
    (`get_active_validators_enforced(5)` → `slashed_validators_for_epoch(4)`
    → empty), and V IS inserted into `slashed`.
  - Then processing block_b (epoch 6) calls
    `get_active_validators_enforced(6)` (runtime.rs:4210-4211), which calls
    `slashed_validators_for_epoch(5)` AGAIN → re-reads the same epoch-5
    evidence → re-enters block_b (epoch 6) → **infinite recursion / stack
    overflow**. `compute_active_set(6)` does not error for a "future" epoch
    (validator_registry.rs:686-689 returns Ok), so there is no Err→continue
    that breaks the loop.
  - Net: in the precise scenario the finding describes, the node ABORTS
    (stack overflow) when computing the enforced active set for epoch 6,
    rather than silently returning a set with V removed.
This means the observable failure is a node crash / chain-halt DoS for any
node that ingested the evidence — arguably as-bad-or-worse, but a DIFFERENT
mechanism than "V silently evicted." The finding's root cause (union
semantics) and the value-consumer wiring are correct; the PoC narrative
(step 4-5: "V is evicted from the active set," function returns enforced
set) does not reproduce verbatim for epoch_a != epoch_b because the
function never returns. For a SAME-height SAME-recursion-safe arrangement
the union still misfires, but the headline cross-epoch case crashes.

### H7 — Test wiring. STANDS
`slashed_validators_for_epoch` is called in production at runtime.rs:4075
(enforced active set) and actor.rs:1721 (SlashedValidators query).
`get_active_validators_enforced` at runtime.rs:1217/1247 (proposer/DKLS).
`InboundEvidence` enters from gossip (gossip_adapter.rs:101). Not test-only.

### H8 — PoC mechanics. PARTIALLY INVALIDATED
No PoC file is attached (source-analysis finding). The prose assertion
"V, who only ever signed epoch 5's honest canonical block, is evicted"
(step 5) is the claim. As shown in H6, the genuine cross-epoch path
stack-overflows before returning, so a PoC asserting "active set for epoch 6
== full set minus V" would NOT pass as written — it would panic. A PoC that
correctly demonstrates the union defect in isolation must either (a) call
`slashed_validators_for_epoch` on evidence whose block epochs avoid the
self-recursion, or (b) assert the crash. Either way the *finding body's
stated assertion* is not directly demonstrable; this is a real caveat the
specialist should address.

## Overall verdict: HAS_CAVEATS (confidence 0.72)

The core defect is REAL and confirmed in source: the cross-epoch enforcement
path slashes the UNION of two disjoint committees' signers with no
intersection / equivocator predicate, so a validator who signed only block_a
(epoch A) is penalized for block_b (epoch B) they never signed. Detection,
ingest, persistence, and the consuming filter are all wired in production and
reachable from unauthenticated gossip. The finding correctly identifies that
per-block signature verification is necessary-but-not-sufficient and that the
fix is intersection-not-union.

Caveats that prevent WATERPROOF:
1. (H1) Attacker-bar overstated. Producing block_b requires a *valid epoch-B
   threshold signature* over junk — i.e. epoch-B committee compromise/
   collusion (or a threshold of 1, which is the separate F028 issue), not
   "one member" / "one signed block." The "low bar / active-set capture"
   framing is stronger than the gated reality.
2. (H6/H8) The exact cross-epoch PoC narrative (V silently evicted at the
   epoch-6 boundary) does not reproduce: `slashed_validators_for_epoch(5)`
   recurses infinitely via block_b's epoch-6 resolution and stack-overflows,
   so the function aborts rather than returning a set with V removed. The
   real-world observable is a node crash / chain-halt DoS — severe, but a
   different mechanism than the false-eviction the body asserts. The
   union-semantics root cause stands; the demonstration as written does not.

Severity: the union defect supports High as a *design* flaw, but the
realized observable in the headline scenario is DoS-via-recursion, and the
clean false-slash requires a non-recursing arrangement plus epoch-B
committee control. Net assessment supports the finding standing with
caveats, not a clean High false-slash.

## Open follow-ups (NOT new findings — for specialist)
- The self-recursion in `slashed_validators_for_epoch` →
  `get_active_validators_enforced(block_epoch)` → `slashed_validators_for_epoch`
  (runtime.rs:4210-4211 re-entering 4191 for any block whose epoch == the
  caller's epoch+1) is an unbounded-recursion / stack-overflow DoS in its own
  right and interacts with this finding's failure mode. The owning specialist
  (chain-economics) should decide whether to fold it into F002's mechanism
  description or whether it warrants its own finding. Validator cannot create
  findings.

---

## F003 — Ring-vouch sybil clusters cross the crediter trust floor — EigenTrust has no vouch cap, mutual-vouch requirement, or min-vouchee-trust gate

## Summary

The EigenTrust power iteration (`run_eigentrust`) propagates trust along the
post-transfer follow graph with **no out-degree cap, no mutual-vouch
requirement, and no minimum-vouchee-trust gate on edges**. A single legit /
seed account that follows ("vouches for") a small set of sybils, combined with
the sybils ring-following each other, recirculates the vouched mass inside the
sybil cluster instead of leaking it back to the seed set. This amplifies the
cluster's raw EigenTrust score by ~6.6× relative to the same vouch with no ring,
and lifts every sybil in the cluster over the `crediter_trust_floor` (0.05) — the
**only** sybil defense in the emission path. Once above the floor, each sybil
becomes a valid crediter in `tally_growth_scores`, so the cluster mints growth
score (and therefore emission share) far in excess of its actual stake/trust.

## Affected code

- `code/hypersnap/src/emission/eigentrust.rs:82-124` — power-iteration loop.
  Lines 86-94 propagate `damping · src_mass · weight` along **every** out-edge,
  regardless of whether the edge is reciprocated and regardless of the target's
  trust. Lines 104-110 redistribute *dangling* mass (nodes with no out-edges)
  back to the seeds, but mass circulating inside a closed follow-cycle is **not**
  dangling, so it is never returned to the seed set — it accumulates on the ring.
  There is no cap on a source node's out-degree and no per-edge weighting by the
  vouchee's own trust.
- `code/hypersnap/src/emission/mutuality.rs:60-68` — `tally_growth_scores` gates
  contributions solely on `trust_a >= params.crediter_trust_floor` /
  `trust_b >= ...`. This is the sole sybil gate, and the amplification above
  defeats it: amplified sybils satisfy `trust >= 0.05`.

## Attack scenario

1. Attacker controls (or buys a follow from) one moderately/high-trust account
   `H` (a seed FID ≤ 50_000, or any account with normalized trust near 1.0).
2. Attacker registers K sybils (FIDs > 50_000, so not seeds) and has `H` follow
   all K of them — a single cheap vouch action.
3. The K sybils follow each other in a closed ring (`s_i → s_{i+1 mod K}`).
4. EigenTrust now injects `damping · score(H) · (1/out_deg(H))` into the ring
   each iteration; the ring's closed cycle recirculates it (damped by `damping`
   per hop) instead of leaking it back to seeds. The cluster's steady-state mass
   is geometrically amplified.
5. After `top_n_avg_normalize`, each sybil's normalized trust exceeds the 0.05
   floor, so each sybil is an accepted crediter. The sybils mutually "engage"
   (also cheap) and `tally_growth_scores` credits each of them, converting the
   inflated reputation directly into emission share via `allocate_emissions`.

### Empirical reproduction (verbatim copy of `run_eigentrust` + `top_n_avg_normalize`)

200-node legit seed core; FID 1 additionally follows K ring-vouching sybils:

```
K=    1 | sybil_max_norm=0.515216 | sybils>=floor=   1/   1
K=   10 | sybil_max_norm=0.283694 | sybils>=floor=  10/  10
K=   50 | sybil_max_norm=0.094647 | sybils>=floor=  50/  50
--- no ring vouch (dangling sybils, same voucher edges) ---
K=   10 | sybil_max_norm=0.042555 | sybils>=floor=   0/  10
--- amplification ratio (K=10) ---
ring raw-mass=0.014163  dangling raw-mass=0.002150  amplification=6.59x
```

With ring vouching, one vouch edge lifts 10–50 sybils over the floor; without the
ring (dangling), the identical vouch leaves all sybils below the floor
(0.0426 < 0.05). The ring provides a 6.59× raw-mass amplification for K=10.

## Impact

A single legit/seed vouch is amplified into an arbitrarily large set of
floor-crossing crediter sybils, each of which then siphons growth-score and
emission. This is silent incentive distortion / Sybil inflation of emission
share well beyond stake — the precise failure mode this attack class targets.
Severity: High (direct, cheap inflation of the Growth emission budget by a
low-cost off-chain action; no fund-loss but quantifiable mis-issuance).

## Root cause

The mitigations standard for EigenTrust-based reputation are all absent:

- **No vouch (out-degree) cap** — `H` may vouch for unlimited sybils; each edge
  carries full `1/out_deg` weight (`eigentrust.rs:91-92`, `compute.rs:52`).
- **No mutual-vouch requirement** — trust flows along directed edges; reciprocity
  is never checked, so a ring of one-directional follows is treated as genuine.
- **No `vouch_boost_min_vouchee_trust` gate** — edges into near-zero-trust nodes
  still propagate full mass, so the ring can bootstrap from nothing.
- **Closed-cycle mass is not anchored to seeds** — the leak correction
  (`eigentrust.rs:104-110`) only recovers *dangling* (no-out-edge) mass; mass
  inside a follow-cycle is retained and amplified.

The `crediter_trust_floor` in `mutuality.rs` is the only backstop and is a fixed
absolute threshold on the normalized score, which the amplification crosses.

## Fix

Add edge-level anti-sybil gating in the EigenTrust input/propagation, in scope:

1. **Cap out-degree contribution / cap vouches**: bound the number of
   trust-bearing out-edges per source (or down-weight beyond a cap) so one
   account cannot vouch for unlimited nodes at full strength.
2. **Require mutual vouching**: when building `outgoing` (or inside
   propagation), keep an edge `a→b` only if `b→a` also exists, or weight the
   edge by the reciprocal-ness of the pair. This destroys one-directional rings.
3. **Gate edges by minimum vouchee trust** (`vouch_boost_min_vouchee_trust > 0`):
   refuse to propagate trust into nodes whose own (prior-iteration / seed-
   reachable) trust is below a floor, preventing ring bootstrap from zero.
4. Make `crediter_trust_floor` relative/percentile rather than a fixed absolute
   normalized value, and/or cap the number of crediters a single voucher can
   transitively create.

### Validation

- Verdict: **INVALIDATED**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F003 validation — ring-vouch sybil amplification (no vouch caps)

Validator: validator (deliberate-disagreement). Commit `cab225f` (HEAD == pinned).

## Verdict: INVALIDATED (confidence 0.9)

The finding analyzes the **wrong pipeline**. It targets the offline/CLI
`src/emission/` module (`eigentrust.rs` + `mutuality.rs`), but the
**production consensus emission path** is
`crates/proof-of-quality/src/scoring.rs::evaluate_epoch`, which contains
every defense the finding claims is absent. Textbook
`two-pipeline-confusion`.

## Pipeline reachability (the decisive walk)

- `src/emission::compute_epoch_emissions` (the function whose
  `run_eigentrust` + `tally_growth_scores` the finding attacks) has
  exactly TWO call sites: `src/bin/compute_emissions.rs:209` (a standalone
  CLI that reads `follows.csv` + `engagement.csv` and writes
  `emissions.csv`) and its own `#[cfg(test)]` module. It is **never**
  reached from runtime/consensus.
- The production path: `actor.rs:2203 maybe_trigger_scoring` →
  `scoring_driver::run_epoch_dkls_local` (actor.rs:2236) →
  `proof_of_quality::scoring::evaluate_epoch` (scoring.rs:372), whose
  `EpochScoringOutput` is then DKLS23 threshold-signed (actor.rs:2012
  doc: "Run `evaluate_epoch` + DKLS23 1-of-1 inline signing"). The
  `compute_emissions` CLI output (a CSV) is never fed back into
  consensus.
- `params.rs:21-27` documents this split explicitly: "The other modes are
  retained for the `compute_emissions` CLI binary and offline
  experimentation only — the production consensus path never reads them."

## The four "absent" defenses all EXIST in the production path

The finding's root-cause list (no vouch cap / no mutual-vouch / no
min-vouchee-trust gate / closed-cycle mass) is refuted by
`crates/proof-of-quality/src/scoring.rs::compute_growth_harmonic` and its
default `ScoringParams` (lib.rs:318-368):

1. **`vouch_boost_min_vouchee_trust` gate** — claimed absent; present at
   scoring.rs:210-214, default **0.3** (lib.rs:334). When the vouchee's
   own trust < 0.3 the vouch boost is forced to 1.0 — exactly the
   "high-trust voucher amplifies a low-trust sybil" pump the finding
   describes. Closed by design (tests
   `vouch_boost_gated_by_vouchee_trust_floor`).
2. **`min_distinct_crediters` gate** — scoring.rs:247, default **3**
   (lib.rs:344). Growth is zero unless ≥3 distinct reciprocating
   crediters; small rings get nothing.
3. **Distribution-aware entropy damping (Layer 2)** — scoring.rs:251-269,
   default skew exponent **2.0** (lib.rs:358). A uniform sybil ring
   (H_norm ≈ 1) is damped toward zero; test
   `distribution_aware_damping_penalizes_uniform_rings` asserts a uniform
   ring lands >10× below a real user. This directly neutralizes the
   ring-recirculation amplification the PoC exhibits.
4. **Crediter trust floor (Layer 0)** — scoring.rs:192, default 0.05
   (lib.rs:320). Same floor the finding cites, but it is the FIRST of a
   layered defense, not the "only" one.

Additionally `evaluate_epoch` runs eligibility gating (scoring.rs:411)
and composite weighting by credibility/entropy (compute_composite) before
budget allocation — further blunting any residual amplification.

## 8-hypothesis walk

1. **Upstream auth/gate — INVALIDATED.** The production scoring path
   applies `crediter_trust_threshold` + `vouch_boost_min_vouchee_trust`
   (0.3) + `min_distinct_crediters` (3) upstream of allocation. The
   finding missed all three because it read the CLI module.
2. **Consumer-side impact — INVALIDATED.** The consumer of the finding's
   buggy `tally_growth_scores` is only `compute_emissions.rs` (CSV →
   CSV). No consensus, no signed issuance, no on-chain mint consumes it.
3. **Downstream enforcement — INVALIDATED.** Even within the production
   pipeline, the entropy damping (L2) + count gate (L1) downstream of
   EigenTrust catch precisely the uniform-ring mass the finding says is
   "never returned to the seed set."
4. **PR HEAD currency — STANDS (no help to finding).** HEAD ==
   `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pinned. No drift.
5. **Spec carve-out — INVALIDATED.** `params.rs:21-27` and `mod.rs:5-7`
   explicitly mark `src/emission` as the offline/retro-mirror path;
   `scoring.rs` is the in-protocol consensus path. The split is
   documented, not a latent bug.
6. **Reachability of harm — INVALIDATED.** No path from the analyzed code
   to emission/value. The PoC inflates a CSV that consensus ignores.
7. **Test wiring — INVALIDATED.** `compute_epoch_emissions` is invoked
   only by the CLI bin and unit tests. The runtime auto-trigger
   (actor.rs:2236) and `EvaluateEpoch` dispatch call
   `evaluate_epoch`, not the finding's functions.
8. **PoC mechanics — PARTIALLY STANDS, but moot.** The 6.59× ring-vs-
   dangling amplification is a faithful copy of `run_eigentrust` (the
   offline solver) and the math is plausible for *that* solver. But it
   proves a property of a non-consensus code path, so the prose impact
   ("siphons emission share") does not follow. The production solver
   `compute_eigentrust` (scoring.rs:24) is a *different* implementation
   (reverse-edge push, alpha restart) and its output is gated by L0/L1/L2
   before reaching any budget.

## Overall

INVALIDATED, confidence 0.9. The amplification math in the offline solver
may be real, but it has no production consumer; the actual consensus
emission path implements the exact anti-sybil controls the finding
asserts are missing. The residual 0.1 reflects that I did not execute the
production pipeline against a 6.6×-style ring to numerically confirm the
L2 damping drives it below the floor — but the code, defaults, and
existing tests (`end_to_end_real_vs_sybil`, `evaluate_epoch_ranks_real_
above_sybil`, `distribution_aware_damping_penalizes_uniform_rings`) all
point the same way.

## Open follow-ups (NOT new findings)

- If the audit scope ever wires the `compute_emissions` CLI output back
  into a consensus/airdrop path, F003's amplification would become live —
  worth a scope note, but currently out of the consensus path.

---

## F009 — Slashing predicate keys 'conflict' on signature-inclusive block hash; two valid threshold signatures over identical block content (sign-ceremony restart / round retry) are mis-classified as double-sign evidence and slash honest signers

## Summary

The hyper slashing path's notion of "conflicting blocks" is **strictly
broader** than consensus's notion of equivocation. `detect_conflicting_blocks`
(`slashing.rs:52`) declares two blocks at the same `canonical_block_id` a
slashable conflict whenever their `hyper_block_hash` differs. But
`hyper_block_hash` (`chain.rs:25`) mixes the **non-deterministic threshold
ECDSA signature bytes** (`ecdsa_signature`, and `group_address`) into the
digest. The actual consensus commitment — the *signed content* — is
`HyperBlockMetadata::signing_payload` (`mod.rs:403`), which does **not**
contain the signature.

Consequently, **two valid threshold signatures over byte-identical signed
content** (same `signing_payload`, i.e. the *same* canonical block / same
consensus decision) hash to two different `hyper_block_hash` values and are
mis-classified as a double-sign conflict. Both blocks pass
`verify_evidence_signatures` (they are genuinely signed by the epoch group
key), so the pair is accepted as authoritative evidence, persisted, and at
the next epoch boundary `slashed_validators_for_epoch` (`runtime.rs:4191`)
slashes the honest committee that produced them.

A second valid signature over identical content is a **normal, expected**
outcome in this codebase, not equivocation:

- **DKLS sign-ceremony restart (F045).** `DklsSignDriver::try_restart_for_recovery_id`
  (`dkls_sign_driver.rs:53`) and `DklsSignCoordinator::restart`
  (`dkls_sign.rs:217`) keep the *same digest* (= `keccak256(signing_payload)`)
  but regenerate the per-ceremony nonce (`instance_key`), so the retried
  attempt produces a **different `R` and thus a different `(r,s)` signature**
  over identical content (comment at `dkls_sign.rs:211-215`). The 65-byte
  ECDSA signature bytes differ; the signed payload does not.
- **Consensus round retry / re-proposal.** Malachite can re-attempt a height
  across rounds. Re-running block production for the same `(epoch, height,
  parent_hash)` selects the same deterministic committee
  (`actor.rs:2657`, `committee_seed_for_block`) and the same `signing_payload`
  — but a fresh sign ceremony yields a fresh nonce and a fresh signature.

DKLS threshold ECDSA here is non-deterministic (not RFC-6979); nothing
normalizes or canonicalizes the signature, and the slashing predicate never
compares the *signed payloads*. So the two notions of "double-sign" diverge:
consensus equivocation = two distinct committed *values* at one height; the
hyper predicate = two distinct *signature-bearing encodings* at one height.

## Impact

A legitimate consensus action (sign-ceremony recovery-id restart, or a round
retry) is mis-classified as double-sign evidence. Because the evidence is
genuinely signature-valid, it survives every existing gate
(`detect_conflicting_blocks` → `verify_evidence_signatures` →
`record_evidence`, `actor.rs:1587-1620`) and is enforced at the epoch
boundary against the **honest** signing committee.

Attack construction (insider griefing, no key compromise required):

1. A byzantine validator participates as a committee member in a block-
   production ceremony for height `H`. Every committee party learns the full
   finalized `EcdsaSignature` (`coordinator.output()`).
2. The ceremony restarts once (a recovery-id retry is common — recovery_id ∈
   {2,3} occurs ~50% of the time, see `dkls_sign.rs:211`), or a consensus
   round retry re-runs production for `H`. The attacker retains the signature
   from both executions: `sig1` and `sig2`, both valid over the identical
   `signing_payload` for `H`.
3. The attacker constructs `block_a` (content of `H` + `sig1`) and `block_b`
   (content of `H` + `sig2`) and gossips them as an `InboundEvidence` frame.
4. Every honest node runs `detect_conflicting_blocks` → distinct
   `hyper_block_hash` (signature bytes differ) → conflict;
   `verify_evidence_signatures` → both valid → persisted; epoch boundary →
   the entire honest committee (including the attacker's honest co-signers)
   is added to `slashed_validators_for_epoch`.

This lets a single committee member slash the rest of an honest committee,
or self-slash to manufacture a griefing/halt vector, **without ever forking
state**. It also means an honest node that legitimately restarted its own
sign ceremony can be slashed by replaying its own two outputs.

This is the inverse of the producer-can't-lie anti-pattern: here the gate is
*over-broad* rather than absent — it treats a non-conflict (same decision,
two valid sigs) as a conflict. The genuine-equivocation direction is fine
(`hyper_state_root` is inside `hyper_block_hash`, so two different state roots
are still caught), so the consistency bug is one-directional: **legitimate →
mis-slashed**.

## Root cause

`hyper_block_hash` (the identity used for "distinct") and `signing_payload`
(the identity used for "what the group committed to") are different field
sets. Specifically `hyper_block_hash` includes `ecdsa_signature` /
`group_address`, while `signing_payload` does not (it cannot sign itself).
The slashing predicate should define "distinct block" by **distinct signed
content**, not by distinct signature encoding.

Note this is *not* subsumed by F026/F028/F153 (those bind epoch tags,
extra-rules/retained-count, and `signer_indices` into the signing payload to
stop a *malicious proposer* manufacturing distinct hashes). Those fixes
hardened the signed payload; they did not change the fact that the *conflict
test* keys on the signature-inclusive `hyper_block_hash`. Two honest,
identical-content blocks with different nonces still differ under
`hyper_block_hash` and still trip the predicate.

## Recommended fix

Define "conflict" on signed content, not on the signature-bearing hash:

- In `detect_conflicting_blocks`, compare `a.envelope.metadata.signing_payload(a.signature.epoch, &a.signature.signer_indices)`
  against the equivalent for `b` (or a content-only digest that excludes
  `ecdsa_signature` / `group_address`). Two blocks are a genuine conflict
  only when the *signed payloads* differ at the same `canonical_block_id`
  (and the signer sets/epochs are consistent). Identical signed payload with
  differing signature bytes = same decision, **not** slashable.
- Equivalently, derive `block_a_hash`/`block_b_hash` from a signature-free
  canonical encoding so the dedupe key, the store key, and the conflict test
  all agree on content-identity.

## Verification notes

- `detect_conflicting_blocks` only checks `canonical_block_id` equality and
  `hash_a != hash_b` (`slashing.rs:52-77`); there is no signed-payload
  comparison.
- `hyper_block_hash` includes `signature.ecdsa_signature` and
  `signature.group_address` (`chain.rs:36-39`).
- `signing_payload` excludes the signature (`mod.rs:403-452`).
- `restart()` preserves `digest` and regenerates the per-ceremony nonce
  (`dkls_sign.rs:211-224`); `try_restart_for_recovery_id` drives it
  (`dkls_sign_driver.rs:51-61`).
- Enforcement reads `signer_indices` of *both* evidence blocks and slashes
  them (`runtime.rs:4191-4225`), so an honest committee on both sigs is
  penalized.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.6
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F009 validation — slashing predicate keys conflict on signature-inclusive block hash

Validator: validator (deliberate-disagreement role)
Finding: F009 (consensus-malachite-tendermint, attack_class double-sign-evidence-gating)
Commit: cab225f (HEAD matches pin)
Date: 2026-06-08

## Core mechanism — CONFIRMED

The structural defect the finding names is real and verified line-by-line:

- `hyper_block_hash` mixes the threshold-signature bytes into the digest:
  `signature.group_address` and `signature.ecdsa_signature`
  (`code/hypersnap/src/hyper/chain.rs:35-39`).
- `signing_payload` (the signed content) excludes the signature
  (`code/hypersnap/src/hyper/mod.rs:403-452`).
- `detect_conflicting_blocks` keys "distinct block" purely on
  `hyper_block_hash` inequality with `canonical_block_id` equality; there is
  **no signed-payload comparison** (`slashing.rs:56-66`).
- The downstream gates do not rescue it: `verify_evidence_signatures` only
  checks each block's signature is valid over its own `signing_payload`
  (`slashing.rs:98-108`) — two benign blocks both pass. Enforcement
  `slashed_validators_for_epoch` slashes purely on `signer_indices` of both
  evidence blocks with no payload/state-root/height re-check
  (`runtime.rs:4191-4229`).

So IF two distinct valid threshold signatures over an identical
`signing_payload` at one `canonical_block_id` can be produced and packaged
into an `InboundEvidence` frame, they survive detect → verify → record →
enforce and slash the honest committee. The over-broad-predicate logic is
sound. The dispute is entirely about **reachability** of the benign
collision.

## 8-hypothesis walk

### H1. Upstream auth / gate — STANDS (no rescue)
`InboundEvidence` (`actor.rs:1587-1620`) calls `detect_conflicting_blocks`
directly on two caller-supplied `HyperBlock`s. There is no upstream gate
comparing signed payloads. The only upstream filters are the dedupe set and
`verify_evidence_signatures` — neither dedupes by payload, both pass a benign
pair. STANDS.

### H2. Consumer-side impact — STANDS (no rescue)
The consumer is `slashed_validators_for_epoch` (runtime.rs:4191). It reads
`signer_indices` from both evidence blocks and adds the resolved validator
keys to the slashed set. It does NOT re-derive or compare `signing_payload`,
`hyper_state_root`, or height beyond what `detect_conflicting_blocks` already
admitted. So a benign-but-admitted pair does cause a real penalty. STANDS.

### H3. Downstream enforcement — STANDS (no rescue)
Walked the epoch-boundary path explicitly. No layer below
`detect_conflicting_blocks` re-checks that the two blocks committed to
different content. Enforcement is index-driven, not content-driven. STANDS.

### H4. PR HEAD currency — STANDS
`git log -1` = cab225f, matches the pinned commit. Branch is detached at the
pin. No drift. STANDS.

### H5. Spec carve-out — NEEDS_MORE_DATA → effectively STANDS
The slashing module doc-comment (`slashing.rs:1-11`) describes evidence as
"two blocks ... with **different state roots**" — i.e., the *intent* is to
catch divergent content. The code keys on signature-inclusive hash, which is
broader than the documented intent. No doc says "benign re-sign is
intentionally slashable," so no carve-out protects the code; if anything the
doc-comment supports the finding (code is broader than documented intent).

### H6. Reachability of the harm — PARTIALLY INVALIDATED (this is the load-bearing hypothesis)
The finding offers two reachability stories for "two valid sigs over the same
payload." Both are weaker than claimed:

(a) **DKLS recovery-id restart (F045).** The finding asserts
    "recovery_id ∈ {2,3} occurs ~50% of the time, see dkls_sign.rs:211."
    This is a **material misreading**. The code states the probability of
    recovery_id ∈ {2,3} (R.x ≥ curve order) is **~2⁻¹²⁸ per attempt**
    (`dkls_sign.rs:464`, `dkls_threshold.rs:439`) — cryptographically
    negligible, essentially never observed. (The ~50% figure plausibly
    conflates with low-s EIP-2 normalization `s' = n-s; recovery_id ^= 1`,
    which is a *deterministic in-place fixup* — `bridge_payload.rs:30-32` —
    NOT a ceremony re-run, and does not yield a second independent
    signature.) Moreover, even on the negligible {2,3} event, the rejected
    attempt returns `Err(RecoveryIdOutOfRange)` *before* `from_rsv` /
    `output = Some(sig)` (`dkls_sign.rs:417-426`); it never materializes an
    `EcdsaSignature`. Only the final accepted signature is finalized into a
    block (`actor.rs:1574-1581`, `2715-2723`). So the attacker cannot
    "retain sig1" — there is no sig1 object. Scenario (a) is INVALIDATED.

(b) **Consensus round-retry / re-proposal.** The finding assumes a
    Malachite round-retry re-runs block production for the same
    `(epoch, height, parent_hash)` and broadcasts two distinct finalized
    blocks. In this codebase the block producer is a **fixed-cadence
    single-proposer scheduler** (`scheduler.rs:179-211`), not a Malachite
    round loop. `is_proposer(...)` is called with **round hardcoded to 0**
    (`scheduler.rs:167`); height is `snapshot.next_height()` which only
    advances on an observed `BroadcastBlock` (`scheduler.rs:222-228`). There
    is no wired re-proposal path that emits two finalized, differently-signed
    blocks for one height. A second `ProduceBlockDkls` for an un-finalized
    height recomputes the *same* digest and overwrites
    `pending_dkls_blocks[digest]` (`actor.rs:2698`); only the *finalized*
    signature is ever attached + broadcast (`actor.rs:2761-2790`). The
    round-aware seed exists only in the proposer-selection abstraction
    (`proposer.rs:26`) and is not exercised by the producer with round != 0.
    Scenario (b) is NOT demonstrated reachable in this code; it is imported
    from a generic Malachite mental model.

(c) **Insider harvesting (attack steps 1-4).** A single byzantine committee
    member cannot unilaterally produce a t-of-n threshold signature; it needs
    t-1 honest co-signers. Honest nodes run one ceremony per height (driven
    by scheduler → finalize) and have no code path that voluntarily
    co-signs a *second* ceremony for the same already-decided payload. So
    even an insider cannot trivially harvest two valid signatures over one
    payload through the wired protocol.

Net: the *predicate is genuinely over-broad and would mis-slash IF a
benign collision occurred*, but no concretely-wired path in this codebase
produces two distinct valid signatures over an identical `signing_payload`
at one height. The harm is latent/defensive (the predicate is wrong and
fragile) rather than presently-triggerable with the stated frequency.
PARTIALLY INVALIDATED — the high-frequency "~50% recovery-id" trigger is
false; remaining triggers are not shown reachable in-tree.

### H7. Test wiring — STANDS (predicate is production code)
`detect_conflicting_blocks` and `slashed_validators_for_epoch` are
production paths reached from `HyperActorEvent::InboundEvidence`
(`actor.rs:1587`) and the epoch boundary. The predicate is genuinely live.
STANDS (the *defect* is in production; only its *trigger* is in question,
covered under H6).

### H8. PoC mechanics — N/A / NEEDS_MORE_DATA
No executable PoC is attached to the finding. The prose attack relies on the
~50% recovery-id claim (H6a), which the code contradicts. Without a PoC that
actually obtains two valid signatures over one payload, the "honest committee
gets slashed" assertion is not demonstrated end-to-end.

## Overall verdict

HAS_CAVEATS (confidence 0.6).

The structural finding is correct and worth fixing: `detect_conflicting_blocks`
should define "conflict" on signed content (`signing_payload`), not on the
signature-inclusive `hyper_block_hash`. The recommended fix is sound, and the
defect is real defense-in-depth/correctness debt — a future change that does
produce two valid signatures over one payload (legit re-sign, alternate
client, protocol evolution) would silently weaponize this predicate against
honest signers.

BUT the finding's impact and exploitability are overstated:
- The "~50% recovery-id restart" trigger is factually wrong (actual ~2⁻¹²⁸);
  the rejected attempt never even yields a signature object.
- The "Malachite round-retry" trigger is not wired in this fixed-cadence,
  round-0 single-proposer producer.
- A single insider cannot harvest two threshold signatures unilaterally.

So this is a real **latent correctness/robustness bug in the slashing
predicate** (the two notions of "distinct block" diverge), not a presently
high-frequency griefing vector. Severity should be reconsidered downward from
"high griefing/halt with no key compromise" toward "medium latent
mis-slashing risk / defense-in-depth" pending a concrete demonstration that
two valid signatures over one payload are reachable in-tree.

## Open follow-ups (NOT new findings)
- Worth confirming whether any *future* or *off-path* component (e.g. an
  alternate signing client, a re-sign-on-restart recovery flow, or a
  multi-region producer) could legitimately generate a second signature over
  an already-decided payload. If such a path is added, F009 becomes directly
  exploitable. This is forward-looking and belongs to the specialists, not a
  new finding here.

---

## F011 — Shard read-validators have no protocol-version enforcement; stale read-node silently applies post-upgrade chunks under wrong rules and diverges

## Summary

The read-node protocol-version guard `ReadValidator::validate_protocol_version`
only enforces a version on the `Block` (shard-0 / `BlockEngine`) variant of a
`DecidedValue`. For the `Shard` (`ShardChunk` / `ShardEngine`) variant — which
is what every per-shard read-validator actually consumes — the match falls into
the `_ =>` no-op arm and returns `true` unconditionally. There is no
producer-asserted version to check either: the `ShardHeader` proto carries
neither a `version` nor a `chain_id` field.

Consequence: a shard read-node never detects a protocol-version mismatch and
never triggers the `ExitWithError("Does your node need an upgrade?")` halt that
is the read node's sole defense against following a chain it can no longer
validate. After a time-gated `EngineVersion` upgrade boundary, a stale read-node
binary keeps committing shard chunks and applies them under its *own* locally
derived version, silently diverging from the network's canonical state instead
of halting.

## Affected code file:line

- `src/consensus/read_validator.rs:173-212` — `validate_protocol_version`.
  Only `Some(Value::Block(block))` is checked (lines 175-205). The `_ =>` arm
  (lines 206-209) returns `true` for `Shard` chunks with a comment asserting
  "Only blocks have protocol version", so shard chunks bypass all enforcement.
- `src/consensus/read_validator.rs:235-238` — the only caller; a `true` return
  means the chunk is accepted and committed.
- `proto/definitions/blocks.proto:165-170` — `ShardHeader` has only
  `height`, `timestamp`, `parent_hash`, `shard_root`. No `version`, no
  `chain_id`. (Contrast `BlockHeader` at lines 135-144 which has both.)
- `src/storage/store/engine.rs:2079-2101` — `commit_shard_chunk` derives the
  version *locally* via `self.version_for(&FarcasterTime::new(header.timestamp))`
  and replays the proposal under it with no cross-check and no halt. The
  `is_read_only()` branch at line 2072 confirms read-nodes reach this replay
  path.

## Attack scenario

1. The network ships a time-gated protocol upgrade: `version_for` (time +
   network → `EngineVersion`) maps timestamps after `active_at` to a new
   `Vn` with changed application semantics (e.g. a new `ProtocolFeature`
   gate, an `EventIdBugFix`, or simply a different `active_at` from a hotfix).
2. Writing validators produce shard chunks under the new version. The
   `ShardChunk.commits` quorum is over the same height-keyed validator set
   (`StoredValidatorSets::get_validator_set`, keyed by height only — identical
   across the upgrade), so `verify_signatures` passes on a stale read-node.
3. A shard read-node running an older binary (older
   `ENGINE_VERSION_SCHEDULE`, or missing newer `Vn` variants) receives the
   chunk over the sync value-response path
   (`read_sync.rs` → `ReadHostMsg::ProcessDecidedValue` →
   `process_decided_value`).
4. `validate_protocol_version` returns `true` (no-op for shard chunks), so the
   chunk is committed. `commit_shard_chunk` replays it under the version the
   *stale* node computes from the timestamp, which differs from the producer's.
5. The read-node's shard state-root diverges from the network. No
   `ExitWithError` fires, so the operator gets no "needs upgrade" signal — the
   node keeps serving queries from silently forked/divergent state.

## Impact

Silent, undetected state divergence on shard read-validators across any
protocol-version boundary, with no halt/alert. Read-nodes serve the query/RPC
surface, so consumers downstream of an un-upgraded read-node observe a forked
view of shard state. The block (shard-0) read-node is protected by the
producer-asserted `BlockHeader.version` halt; shard read-nodes are not — an
asymmetry that defeats the upgrade-safety mechanism precisely for the nodes
that carry per-shard application state. Not a safety break for the writing
validator quorum (quorum is still required), hence Medium rather than High.

## Root cause

The protocol-version enforcement was designed around `BlockHeader.version`,
which only exists on the block (shard-0) path. Shard chunks were assumed to
inherit version safety, but (a) `ShardHeader` carries no version/chain_id to
assert, and (b) the read-node applies chunks under a *locally* computed version
(`engine.rs:2082`) with no cross-check, so a stale node's divergence is
invisible. The `_ =>` no-op arm in `validate_protocol_version` codifies this
gap.

## Fix

For shard read-validators, enforce version consistency at commit time rather
than relying on a (non-existent) header version:

- In `commit_shard_chunk` / the read-validator path, compute the expected
  `EngineVersion` from `header.timestamp` and the configured network and
  compare it against the *binary's own* notion of the maximum/known version;
  if the timestamp maps past the highest schedule entry the binary knows (or
  the binary lacks the variant), emit the same `SystemMessage::ExitWithError`
  upgrade-needed halt that the block path uses, instead of silently replaying.
- Alternatively, add a `version` field to `ShardHeader`, include it in the
  signed chunk payload, and extend `validate_protocol_version` to check the
  `Shard` variant symmetrically with `Block` (removing the no-op `_` arm). This
  gives shard read-nodes the same producer-asserted version signal and halt
  behavior as block read-nodes.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.8
- Hypotheses walked: 8
- Validated at: 2026-06-08 12:30:00+00:00

### Validator notes

# F011 validation — shard read-validator protocol-version enforcement

Validator: validator (deliberate-disagreement). Commit `cab225f`.

Finding claim: shard read-validators skip protocol-version enforcement (only the
`Block` variant of `validate_protocol_version` enforces it), so a stale shard
read-node **silently** applies post-upgrade chunks under the wrong, locally
derived version and **silently diverges** with **no halt / no alert**.

## Key code facts confirmed

- `read_validator.rs:173-212` — `validate_protocol_version` only checks
  `Some(Value::Block(block))`; `Shard` falls into `_ =>` no-op and returns
  `true`. **CONFIRMED.**
- `blocks.proto:165-170` — `ShardHeader` has `height/timestamp/parent_hash/shard_root`,
  no `version`, no `chain_id`. `BlockHeader` (135-144) has `version` + `chain_id`.
  **CONFIRMED** — there is no producer-asserted version on the shard path.
- `engine.rs:2082` — `commit_shard_chunk` replay path derives `version` locally
  from `header.timestamp`. **CONFIRMED.**
- Production reachability: `read_validator.rs:58` (`commit_decided_value` →
  `ShardEngine::commit_shard_chunk`) is the real read-node ingest path.
  **CONFIRMED reachable.**

## The decisive counter-evidence (Hypothesis 3 / 6)

The finding's central claim — "silent divergence, no halt" — is **contradicted
by a downstream enforcement the finding does not address**:

- `engine.rs:593-605` (inside `replay_proposal`, the exact function the read-node
  replay path at 2093 calls): after applying the chunk's transactions, the engine
  recomputes `root1 = self.stores.trie.root_hash()` and compares it against the
  producer-supplied `shard_root` from the chunk header. On mismatch it logs
  `"Shard root mismatch"` and returns `Err(EngineError::HashMismatch)`.
- `engine.rs:2102-2104` — the read-node replay caller treats that `Err` as
  `panic!("State change commit failed: {}", err)`. A panic is a hard crash /
  halt, observable to the operator (process exits, restart loops, alerts fire).
- `version_for` (`version.rs:201-218`) on a stale binary returns the **highest
  schedule entry it knows** (`.filter(active_at<=t).last()`), i.e. an *older*
  version than the producer for a post-upgrade timestamp. A different
  `EngineVersion` that changes application semantics for the chunk's transactions
  produces a **different trie state**, hence a **different `shard_root`**, hence
  the `HashMismatch` panic at commit time.

Therefore the scenario the finding describes (stale node applies post-upgrade
chunk under wrong version) does **not** result in silent divergence: it results
in a panic at the shard-root self-check — a halt, just via crash rather than the
`ExitWithError("needs upgrade?")` message. The state-root self-check is a
version-agnostic integrity gate that catches exactly the divergence the missing
version check was supposed to catch.

Residual gap (genuine, but lower-impact than claimed): the operator signal is a
generic `"State change commit failed"` panic, not the actionable
`"Does your node need an upgrade?"` message the block path emits. So the real
defect is **poor operator diagnostics / wrong halt mechanism**, not "silent fork
serving divergent RPC." The node does NOT keep serving forked state across the
boundary — it crashes on the first divergent chunk.

The only way silent divergence survives is if a wrong-version replay produces a
state that differs from the producer yet collides to the *same* blake3 trie root
— cryptographically negligible. And if the wrong version produces an *identical*
root, no divergence occurred for that chunk in the first place.

## 8-hypothesis walk

1. **Upstream auth / gate** — STANDS (partial). `verify_signatures`
   (`read_validator.rs:228`, height-keyed validator set) does pass on a stale
   node across the boundary, so the chunk is admitted. No upstream version gate
   exists for shard chunks. The version no-op is real.

2. **Consumer-side impact** — PARTIALLY INVALIDATED. The claimed consumer ("RPC
   serves silently forked state to downstream consumers") does not materialize:
   the node panics on the first divergent chunk (engine.rs:2104) rather than
   committing and serving it. Consumers see an unavailable / crash-looping node,
   not a silent fork.

3. **Downstream enforcement** — INVALIDATED (the core). `replay_proposal`
   recomputes and enforces the shard state-root (engine.rs:593-605) version-
   agnostically; mismatch → `HashMismatch` → `panic!` (engine.rs:2104). This is
   the layer the finding says doesn't exist. It does.

4. **PR HEAD currency** — NEEDS_MORE_DATA. Validated against pinned `cab225f`;
   workspace is read-only / not a git repo, branch currency not checkable here.
   Does not affect the verdict (the counter-evidence is in pinned code).

5. **Spec carve-out** — STANDS. The `_ =>` arm comment ("Only blocks have
   protocol version") documents the design assumption but no spec declares shard
   version-divergence "intentionally deferred." Not a carve-out that rescues the
   finding; also not one that strengthens it.

6. **Reachability of harm** — INVALIDATED. The "harm" (persisted silent
   divergence + RPC serving) is gated by the shard-root self-check, which halts
   before persistence. Path to the claimed value/observability harm is blocked.

7. **Test wiring** — STANDS. The buggy no-op and the replay path are both
   genuine production paths (`read_validator.rs:58`, `:235`; `engine.rs:2042+`),
   not test-only.

8. **PoC mechanics** — NEEDS_MORE_DATA. No PoC is attached to the finding. The
   prose's "silent / no halt" assertion is not demonstrated and is contradicted
   by static analysis of the commit path; a PoC would need to show a wrong-
   version replay that yields a *matching* shard_root, which is implausible.

## Overall

The mechanical observation (shard variant has no protocol-version enforcement;
`ShardHeader` carries no version) is **true and confirmed**. But the impact as
written — "silent, undetected state divergence with no halt/alert, node keeps
serving forked state" — is **overstated and largely invalidated** by the
version-agnostic shard-root self-check + panic at commit (engine.rs:594-604,
2104). The genuine residual issue is a **diagnostics / wrong-halt-mechanism**
defect: the shard read-node crashes with a generic message instead of the
actionable "needs upgrade" `ExitWithError`. That is a real but Low-impact
defect, not the Medium-severity silent-fork described.

**Overall verdict: HAS_CAVEATS** (mechanical claim stands; impact materially
overstated — "silent divergence / no halt" is false because the shard-root
self-check panics). Confidence 0.8.

Suggested re-scoping: Low (operator-diagnostics / halt-quality), not Medium.

## Open follow-ups (NOT new findings)

- The generic `panic!("State change commit failed")` at engine.rs:2104 is the
  de-facto upgrade-needed halt for shard read-nodes. Worth confirming whether
  operators have alerting that distinguishes this crash from unrelated
  HashMismatch panics — a docs/runbook item, not a code bug.

---

## F012 — Block/ShardChunk `hash` is the consensus-committed value but is never re-derived from blake3(header) on validate/commit/read-node paths, decoupling the signed value from the header and body that actually get committed

## Summary

The Malachite consensus value for a snapchain block/shard chunk is
`FullProposal::shard_hash()` = `ShardHash { shard_index, hash: block.hash }`
(`proto/src/lib.rs:147-161`). Precommit signatures are computed over exactly
this `ShardHash` and nothing else (`core/util.rs:147-155`,
`Vote::to_sign_bytes` → `proto::Vote{ value: shard_hash }`). So the only thing
2/3 of validators ever sign is the opaque `hash` byte string.

The proposer constructs `block.hash = blake3(block_header.encode_to_vec())`
(`consensus/proposer.rs:569`) and `chunk.hash = blake3(shard_header.encode_to_vec())`
(`consensus/proposer.rs:185`). But **no validation, commit, or read-node code
path ever re-derives that hash from the header and compares it to the supplied
`hash` field.** The `hash` field is therefore a free-floating, proposer/relayer-
set field that is *outside* the header it is supposed to commit to, yet it *is*
the value consensus signs and the value used as the chain's parent-hash link and
canonical block identity.

Because the signed `hash` is not bound to `header` (and `header` in turn binds
the body via `state_root` / `events_hash` / `shard_witnesses_hash`), a peer that
possesses a validly-signed `Commits` for height H can attach to it a block whose
`hash` equals the signed value but whose `header` and body
(`transactions`, `events`, `shard_witness`, `parent_hash`, `state_root`,
`events_hash`) are arbitrary. On the read-node / decided-value path this block is
committed verbatim with no re-derivation and no state replay, so the persisted,
finalized block content is attacker-controlled while still passing signature
verification.

## Affected code (file:line)

- `proto/src/lib.rs:147-161` — `FullProposal::shard_hash()` returns
  `ShardHash { hash: block.hash | chunk.hash }`. The consensus value is the
  raw proposer-supplied `hash` field, not a re-derivation of `blake3(header)`.
- `src/core/util.rs:147-155` — precommit `Vote` is built from
  `certificate.value_id` (= `commits.value` = the `ShardHash`). The signed bytes
  cover only height, round, and the `hash`. Nothing in the header or body is
  signed except transitively *if* `hash == blake3(header)` were enforced.
- `src/consensus/proposer.rs:185, 569` — the only places `blake3(header)` is
  computed are the proposer's *construction* of `hash`. There is no
  corresponding re-derivation on receipt.
- `src/consensus/proposer.rs:206-274` (`ShardProposer::add_proposed_value`) and
  `:593-678` (`BlockProposer::add_proposed_value`) — the validate path checks
  `header.height`, `chain_id`, `version`, `shard_witnesses_hash`, runs
  `validate_state_change` for `state_root`/`events_hash`, but **never checks that
  `block.hash == blake3(header)` / `chunk.hash == blake3(header)`**. The proposal
  is then stored keyed by the unverified `shard_hash()` (`validator.rs:281`,
  `proposer.rs:202/589`).
- `src/consensus/validator.rs:281` — `let value = full_proposal.shard_hash();`
  takes the consensus value straight from the unverified `hash` field; the
  returned `ProposedValue.value` is that hash. Validity is computed from header
  checks that do not include the hash.
- `src/consensus/read_validator.rs:143-171, 175-249` — the decided-value path:
  `verify_signatures` proves a quorum signed `commits.value` (the hash), then
  `process_decided_value` → `commit_decided_value` (`:49-100`) commits the block
  verbatim. There is **no** `blake3(header)` re-derivation and **no** state-
  transition replay binding the body to the signed hash. (`block_engine.commit_*`
  replays only on the full-validator commit path, and only when
  `WriteDataToShardZero` is enabled; the read-node decided-value path does not
  gate the body to the signed value at all.)

## Why the header checks do not save this

The `add_proposed_value` validators do re-run the state transition and check
`state_root`/`events_hash`/`shard_witnesses_hash` *of the header they received*.
That binds the body to the header. But it does **not** bind the header to the
signed value, because the signed value is `block.hash`, and `block.hash` is never
compared to `blake3(header)`. The integrity argument "the hash commits to the
header, the header commits to the body" silently fails at its first link: the
signed `hash` is an independent field, not a digest of the header.

Two consequences follow:

1. **Identity / fork-link corruption (full validators too).** A proposer can set
   `block.hash` to any value; honest validators store and commit it unverified.
   The next block's `parent_hash` is `previous_block.hash` (`proposer.rs:541-543`),
   so the canonical hash chain is built from values never tied to header content.
   A proposer can commit a block whose stored `hash` differs from
   `blake3(header)`, breaking the invariant that block identity = header digest.

2. **Decided-value content forgery (read nodes).** Given any signed
   `Commits{value=H}` (observed on the wire), a relayer can wrap it with a
   `Block`/`ShardChunk` whose `hash == H` but whose `header`+body are arbitrary.
   `verify_signatures` passes (it only checks the quorum signed `H`), and the read
   node commits the forged header (state_root, parent_hash, events_hash) and body
   to its store with no re-derivation and no replay. Read nodes therefore finalize
   attacker-chosen state that no validator endorsed.

## Attack scenario (read node)

1. Honest validators reach consensus on height H and sign
   `ShardHash{ hash: blake3(header_honest) }`. The `Commits` (quorum of
   precommit signatures over that hash) is observable on gossip / sync.
2. A malicious relayer crafts a `Block` with `hash = blake3(header_honest)`
   (the signed value) but replaces `header` with `header_evil`
   (different `state_root`, `parent_hash`, `events_hash`) and replaces
   `transactions`/`events`/`shard_witness` with arbitrary content. It attaches the
   real `Commits`.
3. The relayer delivers this `DecidedValue` to a read node
   (`read_validator::process_decided_value`).
4. `verify_signatures` recomputes the signed `Vote` from `commits.value`
   (= the honest hash) and the quorum signatures verify — the relayer did not
   touch `hash` or `commits`. The check passes.
5. `commit_decided_value` persists `header_evil` + forged body. The read node's
   view of finalized state at height H diverges arbitrarily from the validators'.
   No re-derivation of `blake3(header_evil)` (which would not equal `hash`) is ever
   performed, so the mismatch is invisible.

## Impact

- Read nodes can be made to finalize arbitrary, attacker-chosen block content
  (state root, transactions, events, parent link) while passing quorum-signature
  verification. This is finalized-state forgery against any read node / light
  consumer, i.e. a consensus-safety / fork break on the read path.
- The canonical hash chain (block identity, parent-hash links) is built from a
  field that is never bound to the header it is supposed to digest, undermining
  the integrity of the chain even for full validators.
- Severity initial: high. The signed value does not cover the committed content;
  a quorum-valid signature can be replayed onto forged header/body on a path that
  performs no re-derivation and no replay.

## Root cause

`block.hash` / `chunk.hash` is treated as the consensus value identity but is a
proposer-set proto field, and the system relies on the invariant
`hash == blake3(header)` without ever enforcing it on any receive path. The
construction side computes the digest (`proposer.rs:185, 569`); every validation
and commit side trusts the field as-is.

## Fix

- On every receive path that consumes the `hash` as a value identity, re-derive
  and enforce it before use:
  - In `ShardProposer::add_proposed_value` / `BlockProposer::add_proposed_value`,
    reject the proposal as `Validity::Invalid` unless
    `chunk.hash == blake3(chunk.header.encode_to_vec())` /
    `block.hash == blake3(block.header.encode_to_vec())`.
  - In `read_validator::verify_signatures` (or before `commit_decided_value`),
    after confirming the quorum signed `commits.value`, require that the
    committed block/chunk's `hash` equals `blake3(header)` AND re-run the state
    transition (or otherwise bind body→header) so the signed hash transitively
    covers the committed content. Drop the decided value on mismatch.
- Add regression tests: (a) a proposal whose `hash` does not match
  `blake3(header)` is rejected; (b) a `DecidedValue` carrying a valid `Commits`
  but a header/body whose `blake3(header)` differs from `commits.value` is
  dropped by the read node.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.6
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F012 validation — red-team walk

Finding: Block/ShardChunk `hash` (the Malachite-signed consensus value) is never
re-derived from `blake3(header)` on any receive/validate/commit path, decoupling
the signed value from the header+body that actually get committed.

Validator role: deliberate disagreement. Pinned commit `cab225f`.

## Core technical claim — CONFIRMED

- `blake3(...)` over a header appears ONLY in proposer *construction*
  (`src/consensus/proposer.rs:185` shard, `:569` block). Grep of
  `src/consensus/**` for `blake3` returns only those two construction sites plus
  witness-hash sites — there is **no** `hash == blake3(header)` re-derivation on
  any validate/commit/read path. (Grep confirmed.)
- The signed value is the raw `hash` field: `FullProposal::shard_hash()`
  (`proto/src/lib.rs:147-161`) returns `ShardHash { hash: block.hash | chunk.hash }`,
  and `verify_signatures` (`src/core/util.rs:147-155`) builds the precommit `Vote`
  from `certificate.value_id` = `commits.value` = that `ShardHash`. Nothing ties
  `commits.value.hash` to `block.hash`, nor `block.hash` to `blake3(header)`.
- `read_validator::verify_signatures` (`src/consensus/read_validator.rs:150-170`)
  uses the **block-embedded** `block.commits` (not the sync certificate), so a
  relayer independently controls block content and the embedded Commits. It only
  proves a quorum signed `commits.value`; it never compares to `block.hash` or
  `blake3(header)`.
- `parent_hash = previous_block.hash` (`proposer.rs:542`) — the canonical chain
  link is built from the never-re-derived `hash`. Claim holds.

So the "missing blake3(header) re-derivation" mechanic is real and present at the
pinned commit. The disagreement is about **impact magnitude**, driven by H2/H3/H6.

## 8-hypothesis walk

### H1 — Upstream auth / gate. PARTIALLY INVALIDATED (impact-narrowing)
On the sync path the decided block is forwarded to `ProcessDecidedValue`
(`read_sync.rs:358`) independently of the malachite sync state machine's
certificate check (the `ProcessDecidedValue` cast at :358 precedes and is not
gated by `process_input(... ValueResponse ...)` at :362). So there is no upstream
malachite "value_id == hash(value)" gate that saves the read path. The gossip
path (`spawn_read_node.rs:139`) is likewise ungated. H1 does NOT save the finding.
STANDS on whether a gate exists; noted here because it is the first place a
reviewer would look.

### H2 — Consumer-side impact. PARTIALLY INVALIDATED (significant)
The finding's strongest wording — "the read node commits the forged header + body
to its store with no re-derivation and **no state replay**" (lines 73-74, 100-101,
118-121) — is **incorrect at this commit for the live version**. Both commit
sinks replay and enforce the state root:
- `ShardEngine::commit_shard_chunk` (`engine.rs:2042`) always calls
  `replay_proposal` (`engine.rs:525`), which recomputes the trie and returns
  `EngineError::HashMismatch` if `root1 != shard_root` (`:593-605`); the caller
  `panic!`s on `Err` (`:2102-2104`). Body is bound to header's `shard_root`.
- `BlockEngine::commit_block` (`block_engine.rs:916`) replays via
  `replay_proposal` whenever `ProtocolFeature::WriteDataToShardZero` is enabled
  (`:938`). That feature is `>= V9` (`version.rs:239`); mainnet is V9 since
  2025-09-10 and is V17 today (`version.rs:97,127-130`), so the replay branch is
  the live one. Only the legacy `else` branch (`:980-984`, pre-V9) does a verbatim
  `put_block` with no replay.

Consequence: an attacker **cannot** commit *arbitrary* body/state-root as the
finding claims. The committed body must be a *valid state transition from the read
node's current trie* that reproduces the header's `state_root`/`shard_root`.

What survives H2: the **header is still not bound to the signed `hash`.** An
attacker can craft an *alternate, internally self-consistent* (header, body) pair
— valid transition, matching root — whose `blake3(header)` differs from the signed
H, set its `hash` field = H, embed the honest Commits. Replay passes (consistent),
`verify_signatures` passes (signed H). The read node finalizes a block that no
validator endorsed. That content is attacker-*chosen* (they pick the messages) but
not fully arbitrary (must be a valid transition + replayable against current
state). This is still a read-path safety divergence, but the impact is narrower
than "finalize arbitrary attacker-chosen state root / events / parent link verbatim."

### H3 — Downstream enforcement. PARTIALLY INVALIDATED
The state-root replay (H2) is exactly the downstream layer that re-verifies what
the finding said "is committed verbatim." It does not close the header→hash gap,
but it does close the "body is arbitrary" half of the impact claim. The
`events_hash` / `parent_hash` portions of the header are *not* separately replayed
on the read path, so a header carrying a wrong `parent_hash` or `events_hash`
(while still matching the replayed state_root) is not caught — that residual is
real and supports a fork-link / events-divergence claim.

### H4 — PR HEAD currency. NEEDS_MORE_DATA (no drift evidence here)
Workspace is pinned at `cab225f`; the read path / proposer / version schedule were
all inspected at that commit. No newer HEAD was fetched (no network in scope). The
F005/F033/F185 fix comments already present in the code show this is a
post-hardening snapshot; none of those fixes add a `blake3(header)` check, so the
gap persists at the pinned commit. Treat as STANDS-at-pin.

### H5 — Spec carve-out. NEEDS_MORE_DATA → STANDS
No doc-comment, README, or SECURITY note found asserting "block.hash is trusted /
re-derivation intentionally deferred." The construction-only blake3 is presented as
the canonical identity, implying the invariant is assumed, not intentionally
skipped. No carve-out invalidates the finding.

### H6 — Reachability of harm. PARTIALLY INVALIDATED (impact-narrowing)
Reachable but constrained. The attack requires: (a) a real signed `Commits` for
height H (observable on gossip/sync — yes); (b) an alternate (header, body) that
*replays validly* against the victim read node's current state and reproduces a
matching `state_root`/`shard_root`. (b) is a non-trivial constraint the finding's
"arbitrary content" framing omits — the attacker must construct a valid state
transition (e.g. with their own valid messages), and it must replay against the
read node's exact trie at H-1. Within that envelope the harm (read node finalizes
a header the validators never signed; corrupted `parent_hash`/`events_hash`;
divergent chain identity) is real and reachable. The "full validators' canonical
hash chain is built from an unverified field" sub-claim is also reachable: all
honest nodes do agree on the same (header, hash=X) pair they each received, but
since X is never tied to blake3(header), nothing prevents a proposer from setting
X != blake3(header), permanently breaking the identity invariant on-chain.

### H7 — Test wiring. STANDS
`process_decided_value` → `commit_decided_value` → `commit_block` /
`commit_shard_chunk` is the production read-node path (`read_host.rs:79-80`,
`read_validator.rs:49-93`, :214-255), reached from both sync
(`read_sync.rs:358`) and gossip (`spawn_read_node.rs:139`). Not test-only.

### H8 — PoC mechanics. NEEDS_MORE_DATA
No executable PoC accompanies the finding. The prose attack (step 5: "commit
persists header_evil + forged body … no re-derivation of blake3(header_evil) is
ever performed") would, as written, FAIL at `replay_proposal`'s root check for any
body that does not reproduce the header's root — i.e. the literal "replace body
with arbitrary content" PoC would `panic`, not silently commit. A correct PoC must
use a *replay-valid* alternate block (see H2/H6). The header→hash decoupling itself
is provable (no blake3 check exists), but the "arbitrary content" assertion as
phrased does not hold against the live replay path.

## Overall verdict: HAS_CAVEATS (confidence 0.6)

The root mechanic — `block.hash`/`chunk.hash` (the signed consensus value) is
never re-derived from `blake3(header)` on any receive path — is CONFIRMED and
genuine. The header-to-signed-value binding is absent, enabling (i) a
fork/identity-link corruption where on-chain `hash` need not equal `blake3(header)`
and (ii) a read-node divergence where a relayer substitutes an alternate
self-consistent block carrying a valid quorum signature over a different content's
hash.

Caveats that materially reduce the stated impact:
1. The "no state replay, arbitrary body committed verbatim" claim is wrong for the
   live (V9+) version: both `commit_shard_chunk` and `commit_block` replay and
   enforce the state/shard root, panicking on mismatch. The attacker's body is
   constrained to a valid, replayable state transition — not arbitrary.
2. The verbatim-`put_block` no-replay path exists only pre-V9 (legacy), not the
   current network.
3. The exploit envelope (valid transition reproducing the header root, replayable
   against the victim's current trie) is narrower than "arbitrary attacker-chosen
   state root/events/parent link."

The finding should stand as a real header→signed-value binding gap with
fork-link/identity and read-path-divergence impact, but the impact section
("finalize arbitrary attacker-chosen block content … no re-derivation and no state
replay") is overstated and should be downgraded to "attacker-chosen *valid-
transition* content + arbitrary non-state-root header fields (parent_hash,
events_hash, timestamp)." Severity HIGH is defensible on the safety-divergence /
chain-identity grounds; the "arbitrary finalized state" framing is not.

## Open follow-ups (not new findings)
- `events_hash` and `parent_hash` portions of the header are not independently
  re-derived/verified on the read-node commit path even though the state_root is
  replayed; worth a dedicated look at whether a header with a forged
  `events_hash`/`parent_hash` (but matching state_root) is silently accepted.
- The sync `ValueResponse` handler decodes with `.unwrap()` on
  `proto::Block::decode(value_bytes)` (`read_sync.rs:350,354`) — peer-controlled
  bytes; orthogonal to F012 but a panic-DoS surface (likely already covered by an
  F005-family finding).

---

## F013 — FullProposal gossip arm calls height().unwrap() before the shard-id guard, so a peer can crash any node with a height-less FullProposal frame

## Summary

On the shard-routing decode path for inbound gossip
(`GossipReadActor`/`Gossip::map_gossip_bytes_to_system_message`), the
`GossipMessage::FullProposal` arm calls `full_proposal.height()` on a
prost-decoded, fully attacker-controlled message. `FullProposal::height()`
is `self.height.clone().unwrap()`. In proto3 the `Height height = 1` field
of `FullProposal` is an optional (message-typed) field that maps to
`Option<Height>` in Rust, so a peer can emit a `FullProposal` frame with
`height` omitted. The `.unwrap()` then panics, aborting the node — a
single unauthenticated gossip frame is a remote crash / DoS.

The shard-routing code immediately below (`full_proposal.shard_id()`, which
*does* return `Result` and is guarded with `is_err() -> return None`) was
clearly written to handle the missing-`height` case gracefully. That guard
is dead on arrival: `height()` at the top of the same arm already panicked
before control reaches it. This is the H013 shard-mismatch-panic surface:
the panic sits on the exact frame field used to route by shard.

## Location

`src/network/gossip.rs`, the `FullProposal` arm of
`map_gossip_bytes_to_system_message`:

```
Some(proto::gossip_message::GossipMessage::FullProposal(full_proposal)) => {
    let height = full_proposal.height();          // <-- panics: self.height.clone().unwrap()
    debug!("Received block with height {} from peer: {}", height, peer_id);
    ...
    let shard_result = full_proposal.shard_id();   // returns Result, guarded below — but unreachable on the None case
    if shard_result.is_err() {
        warn!("Failed to get shard id from consensus message");
        return None;
    }
    let shard = MalachiteEventShard::Shard(shard_result.unwrap());
    Some(SystemMessage::MalachiteNetwork(shard, event))
}
```

`FullProposal::height()` in `proto/src/lib.rs`:

```
pub fn height(&self) -> proto::Height {
    self.height.clone().unwrap()
}
```

Proto definition (`proto/definitions/blocks.proto`):

```
message FullProposal {
  Height height = 1;   // optional message field -> Option<Height> in Rust
  ...
}
```

## Reachability / attacker model

- `map_gossip_bytes_to_system_message` is invoked directly on raw
  gossipsub `message.data` for every received frame
  (`gossip.rs` swarm event handler, the `if let Some(system_message) =
  self.map_gossip_bytes_to_system_message(peer_id, data, originator)`
  call). The outer `proto::GossipMessage::decode` is the only gate; there
  is no signature/authentication check before the `FullProposal` arm.
- Unlike the `Consensus` / `Status` / `MempoolMessage` / `ContactInfo`
  arms, the `FullProposal` arm has no per-variant byte-size cap and, more
  importantly, no `height`-presence check — it dereferences `height`
  unconditionally.
- Any peer that can publish to the proposal-parts gossip topic (or any
  forwarding neighbor in a multi-hop mesh) can send a `FullProposal` with
  the `height` field absent and crash the receiving node. The proto itself
  carries the note `// TODO: This probably needs a signature?` confirming
  these frames are unauthenticated.

## Impact

Remote, unauthenticated, single-frame node crash (process abort via panic
on the actor/event thread). Repeatable against every node subscribed to the
topic → network-wide halt. Severity initial: high.

## Variant context

This is the same peer-controlled-`Option::unwrap` family already documented
for this codebase as F185 (F151 residual) — raw `GossipMessage::decode`
paths that bypass the fallible-codec arms and panic on missing
`height`/`value` or non-32-byte signer. The `FullProposal` arm is a fresh,
un-remediated instance of that pattern on the shard-routing decode path.
Worth re-scanning the other direct-decode arms and the `.height()` /
`Address::from_vec` / `round()` (`round.try_into().unwrap()`) helpers in
`proto/src/lib.rs` for the same missing-field unwrap shape.

## Suggested fix

Make the `FullProposal` arm height-fallible before any use: replace the
`full_proposal.height()` call with a check on `full_proposal.shard_id()`
(or a `match full_proposal.height { Some(h) => ..., None => return None }`)
*before* the `debug!`/`height` use, and drop the frame on `None`. The
existing `shard_id()` Result guard then becomes effective. Ideally also add
a fallible `try_height()` accessor and stop exposing the panicking
`height()` on peer-decoded values.

### Validation

- Verdict: **WATERPROOF**, confidence 0.92
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F013 validation — red-team walk

Finding: The inbound-gossip decode path's `FullProposal` arm calls
`full_proposal.height()` (= `self.height.clone().unwrap()`) BEFORE the
fallible `shard_id()` guard. A peer can publish a `GossipMessage::FullProposal`
frame with the message-typed `height` field omitted → `unwrap()` on `None` →
panic → remote unauthenticated single-frame node crash / DoS.

Validator role: deliberate disagreement. Pinned commit `cab225f`
(HEAD verified `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, detached, clean tree).

## Core mechanic — CONFIRMED at file:line

- `src/network/gossip.rs:1019-1039` FullProposal arm. Line **1020**
  `let height = full_proposal.height();` runs FIRST. The `shard_id()` guard
  (`is_err() -> return None`) is at lines **1032-1036**, i.e. STRICTLY AFTER
  the panicking `.height()`. The guard is dead-on-arrival for the missing-height
  case exactly as the finding states. Call order confirmed.
- `proto/src/lib.rs:185-187` `pub fn height(&self) -> proto::Height {
  self.height.clone().unwrap() }` — panics on `None`. Confirmed.
- `proto/src/lib.rs:139-142` `shard_id()` does `if let Some(height) = &self.height`
  → returns `Err` on `None` — so the author KNEW height can be absent, yet the arm
  reaches `.height()` first. Confirmed.
- `proto/definitions/blocks.proto:73-80`: `message FullProposal { Height height = 1; ... }`.
  `Height` is a message type → prost generates `Option<Height>` (proto3 has no
  required fields; message-typed singular fields are always `Option<T>`). A peer
  can omit it on the wire and decode succeeds with `height = None`.
- Same-file corroboration: `StatusMessage { Height height = 2; }`
  (blocks.proto:42). The Status arm at gossip.rs:**1076** does
  `let Some(height) = status.height else { ...return None; }` — the codebase
  itself treats an identical `Height` message field as a `None`-able `Option`
  and GUARDS it. FullProposal uses the panicking `.height()` instead. This is the
  same family as F185/F151 residual unwraps; F022 covers the *size-cap* gap on the
  same arm (distinct root cause — no dedup conflict).

## 8-hypothesis walk

**H1 — Upstream auth / gate. STANDS (the crux; investigated hardest).**
Gossipsub is configured `ValidationMode::Strict` (gossip.rs:314) +
`MessageAuthenticity::Signed(key)` (gossip.rs:324). Strict+Signed authenticates
the libp2p *transport envelope*: it proves the frame was signed by SOME peer's
libp2p keypair and rejects unsigned/badly-signed envelopes. It does NOT validate
the application proto payload, required fields, or that `height` is present.
The single application gate before the arm is `proto::GossipMessage::decode`
(gossip.rs:989), which only fails on malformed wire bytes — a `FullProposal` with
`height` omitted is well-formed proto3 and decodes to `Some(FullProposal{height:None,..})`.
No signature/authority check exists between decode and the FullProposal arm
(dispatch at gossip.rs:780 calls the mapper directly on `message.data`). The proto
even carries `// TODO: This probably needs a signature?` (blocks.proto:72)
confirming these frames are NOT app-authenticated. Upstream gate does NOT save the
node. STANDS.

**H2 — Consumer-side impact. STANDS.**
The "consumer" is the panic itself — the unwrap aborts the gossip/event thread
inside the swarm loop. No corrupted-state-consumer analysis needed; the harm is
the crash, which is immediate and self-contained. STANDS.

**H3 — Downstream enforcement. STANDS.**
There is no layer "below" `.height()` that re-checks height before it executes —
`.height()` is the very first statement in the arm. The `shard_id()` Result guard
that WOULD have caught `None` sits after the panic and never runs. No downstream
re-verification rescues it. STANDS.

**H4 — PR HEAD currency. STANDS.**
Workspace HEAD == pinned `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`; no drift to
re-check against. (Cannot fetch a moving branch from this read-only snapshot; the
finding is anchored to the pinned commit, which is what we validate.) STANDS.

**H5 — Spec carve-out. STANDS.**
No spec/README/doc-comment says missing-height frames are intentionally tolerated.
The only nearby comment (`// TODO: This probably needs a signature?`) cuts AGAINST
safety — it acknowledges the frame is unauthenticated. No carve-out. STANDS.

**H6 — Reachability of harm. STANDS (one honest caveat, non-defeating).**
The arm is reached for any decoded `GossipMessage::FullProposal` on ANY subscribed
topic (dispatch matches on the proto variant, not the topic). Validators subscribe
to the consensus/proposal mesh. Caveat: Strict+Signed means the attacker must be a
*mesh peer with a valid libp2p identity* — i.e. "any peer in the mesh", not literally
"any unauthenticated internet host". There is no validator-only admission shown that
would narrow this to honest validators, and gossipsub meshes admit arbitrary peers,
so "any peer" still equals a remote, non-privileged attacker. This slightly refines
the wording ("any mesh peer" vs "any unauthenticated node") but does not lower the
severity: a single crafted frame crashes any subscribed node, repeatable network-wide.
STANDS.

**H7 — Test wiring. STANDS.**
`map_gossip_bytes_to_system_message` is a `pub fn` on the gossip read actor invoked
from the real swarm event handler (gossip.rs:780) on live `message.data`. Production
path, not test-only. STANDS.

**H8 — PoC mechanics. NEEDS_MORE_DATA (no PoC supplied) → does not weaken the static proof.**
No PoC file accompanies F013. The claim rests on static call-order + type analysis,
all of which is independently verified above (line numbers, `Option<Height>` codegen
confirmed via the parallel Status guard). A PoC would strengthen the submission but
the mechanic is proven by code reading; no PoC assertion can be mis-attributed
because none exists. Recommend the specialist add a unit test encoding a
`FullProposal` with `height: None` and asserting the mapper panics (or, post-fix,
returns `None`).

## Open follow-ups (NOT new findings — for the specialist)
- `proto/src/lib.rs:189-191` `round()` does `self.round.try_into().unwrap()` on a
  peer-controlled `int64 round` — negative round → `try_into::<u..>` Err → panic on
  the same untrusted FullProposal. Same family; if/when the height guard is added,
  `round()` is the next reachable unwrap on this struct. The finding body already
  flags this in "Variant context"; leaving to the specialist.
- Worth confirming whether `MalachitePeerId::from_libp2p` / `encode_to_vec` between
  lines 1025-1031 can also fault, but those are infallible; height/round are the
  live ones.

## Overall verdict
**WATERPROOF**, confidence **0.92**.
Call order (`height()` before the `shard_id` guard), the panicking `.unwrap()`,
the `Option<Height>` peer-controllability, and the absence of any app-layer auth
upstream are all confirmed at file:line. The single caveat (H6: "any mesh peer"
rather than "any internet host") refines wording without reducing severity.
Deduct 0.08 only for the absent PoC (H8) and the standard residual that a moving
branch could add a guard above `cab225f` (out of scope for the pinned commit).

---

## F015 — slashing_store encode_block zeroes signing_payload-committed fields, so persisted equivocation evidence is no longer self-verifying

## Summary

`encode_block` (the storage codec for confirmed conflicting-blocks evidence)
explicitly zeroes six metadata fields that the threshold `signing_payload`
commits to: `missed_proposals`, `snapchain_anchor_block`,
`snapchain_anchor_hash`, `snapchain_range_start_block`, `snapchain_range_root`,
and `snapchain_anchor_timestamp`. For any real block — which carries a non-zero
snapchain anchor block/hash/timestamp (see `builder.rs::build_envelope_with_full_anchor`,
lines 248-264) — the stored evidence can no longer reproduce the bytes that
were signed. The signing payload reconstructed from the re-decoded evidence
(`HyperBlockMetadata::signing_payload`, mod.rs:403) differs from the original,
so the persisted record is **not self-verifying**: any consumer that re-derives
`signing_payload` from the stored block and re-checks the threshold signature
will get a false signature-mismatch.

This does not bypass the current ingest-time gate (that runs on the
field-intact wire block, before storage), but it breaks the durable evidence
invariant the audit task names directly: re-encoded evidence does **not**
reproduce the original `signing_payload`.

## Affected code (file:line)

- `src/hyper/slashing_store.rs:171-196` — `encode_block`. Hard-codes
  `missed_proposals: vec![]`, `snapchain_anchor_block: 0`,
  `snapchain_anchor_hash: vec![]`, `snapchain_range_start_block: 0`,
  `snapchain_range_root: vec![]`, `snapchain_anchor_timestamp: 0`.
- `src/hyper/mod.rs:403-452` — `signing_payload` commits to all six of those
  fields (lines 419-438).
- `src/hyper/chain.rs:25-44` — `hyper_block_hash` does **not** mix those six
  fields in (only id, parent_hash, state_root, extra_rules_version,
  retained_message_count, and signature fields). This is the asymmetry that
  makes the bug subtle: `encode_block` preserves exactly the hash-fields and
  drops exactly the signing-only fields, so block-hash-based idempotency keys
  (`make_key`, slashing_store.rs:153) still work and tests pass, while the
  signed payload silently no longer round-trips.
- `src/hyper/gossip_adapter.rs:186-199` — by contrast the gossip/wire codec
  (`encode_hyper_block`/`decode_hyper_block`) preserves all fields "so every
  field the proposer signs ... is preserved — see F138." The storage codec
  diverges from the wire codec.
- `src/hyper/runtime.rs:4191-4229` — `slashed_validators_for_epoch` reads the
  field-dropped evidence and does not re-verify signatures.

## Attack scenario

1. A malicious 1-of-1 (or any threshold) proposer signs a real block whose
   `signing_payload` includes the snapchain anchor/range fields and any
   `missed_proposals`. They equivocate, producing a second conflicting block at
   the same height. Both blocks gossip with all fields intact.
2. A peer ingests the evidence. `HyperActor::dispatch` (actor.rs:1587-1620)
   calls `verify_evidence_signatures` (slashing.rs:89) against the field-intact
   wire blocks — passes — then `record_evidence` persists via `encode_block`,
   which zeroes the six signing-only fields.
3. The persisted record now carries blocks whose `signing_payload` no longer
   matches the stored `ecdsa_signature`. The block hashes stored in the key
   still match (those fields survive), so the row looks valid by hash.
4. Any node syncing the slashing DB, restarting, or running a future
   re-verification / cross-node consistency check that re-derives
   `signing_payload(epoch, signer_indices)` from the stored block and re-checks
   the threshold signature will see a **false mismatch** and either reject
   legitimate evidence (equivocator evades slashing) or, if the check is a hard
   error, fail the epoch-boundary enforcement pass (liveness/DoS).

The "freely supply dropped fields" variant is also enabled in principle: a node
that reconstructs a block from stored evidence has no committed value for the
six dropped fields, so it must invent zeros — meaning the stored evidence
underdetermines the signed message. Today no consumer reconstructs-and-verifies,
which is why this is medium rather than high, but the invariant ("persisted
evidence is verifiable") that slashing.rs:79-88 relies on is broken.

## Impact

- Persisted conflicting-blocks evidence is not self-verifying for any
  production block (anchor fields are always populated). Re-verification of
  stored evidence yields false-fail.
- Cross-node / post-restart re-validation of the slashing DB is unsound: two
  honest nodes cannot independently confirm a stored row's signature.
- Enables an equivocator to evade slashing if/when any re-verification of
  stored evidence is added or relied on (e.g. light-client/state-sync proofs of
  the slashing set), and creates a liveness/DoS risk if such re-verification is
  a hard error at the epoch boundary.
- Severity initial: medium. Not directly fund-loss and not exploitable through
  the current single ingest-time gate, but it silently violates the durability
  invariant that the slashing subsystem is designed around, and the fix is small.

## Root cause

`encode_block` was written to mirror only the canonical-block-hash fields
(chain.rs) rather than the strictly larger `signing_payload` field set
(mod.rs). The F028 fix correctly extended `signing_payload` to be a superset of
the hash fields, but the storage codec was not updated to persist that superset,
unlike the wire codec which was (F138). Result: storage drops exactly the
signing-only fields.

## Fix

Make `encode_block` round-trip all fields `signing_payload` commits to — i.e.
copy `missed_proposals`, `snapchain_anchor_block`, `snapchain_anchor_hash`,
`snapchain_range_start_block`, `snapchain_range_root`, and
`snapchain_anchor_timestamp` from the source block instead of zeroing them.
Reuse `gossip_adapter::encode_hyper_block` (or share one block codec) so the
storage and wire encodings cannot drift again. Add a regression test that
records evidence whose blocks have non-empty `missed_proposals` and non-zero
anchor/range fields, reads it back, reconstructs `signing_payload`, and asserts
the bytes match the original (and the stored signature still verifies).

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.85
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F015 validation — slashing_store encode_block zeroes signing_payload-committed fields

Validator: validator (deliberate-disagreement role)
Finding: F015 — `encode_block` (storage codec) drops 6 metadata fields that
`signing_payload` commits to, so persisted equivocation evidence is no longer
self-verifying.
Audited commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (== current workspace HEAD)
Validated: 2026-06-08

## Core code re-verified at cab225f

- `src/hyper/slashing_store.rs:171-196` — `encode_block` hard-codes
  `missed_proposals: vec![]`, `snapchain_anchor_block: 0`,
  `snapchain_anchor_hash: vec![]`, `snapchain_range_start_block: 0`,
  `snapchain_range_root: vec![]`, `snapchain_anchor_timestamp: 0`. CONFIRMED
  verbatim — all six fields are zeroed/emptied at encode time.
- `src/hyper/mod.rs:403-452` — `signing_payload` commits to all six of those
  fields (anchor block/hash/range-start/range-root/timestamp at 428-438,
  missed_proposals at 421-426). CONFIRMED superset of the hash fields.
- `src/hyper/chain.rs:25-44` — `hyper_block_hash` mixes only
  canonical_block_id, parent_hash, hyper_state_root, extra_rules_version,
  retained_message_count, epoch, group_address, ecdsa_signature. The six
  dropped fields are NOT in the hash. CONFIRMED asymmetry: `encode_block`
  preserves exactly the hash-fields and drops exactly the signing-only fields,
  so block-hash idempotency keys (`make_key`, 153-168) and all tests still pass.
- `src/hyper/builder.rs:248-264` — real production blocks populate non-zero
  `snapchain_anchor_block/hash/timestamp` (range start/root populated by a
  post-build step in the proposer pipeline). CONFIRMED: for any real block the
  re-encoded evidence cannot reproduce the signed bytes.

So the mechanical claim (re-encoded stored evidence does not round-trip the
original `signing_payload` for production blocks) is TRUE.

## The decisive question: is stored evidence ever re-derived-and-verified?

Whole-codebase trace of every consumer of stored evidence:

- Read API: `slashing_store::get_for_epoch` / `iter_all` (slashing_store.rs:
  106-149), wrapped by `runtime::evidence_for_epoch` (runtime.rs:4164-4170).
- Sole PENALTY consumer: `runtime::slashed_validators_for_epoch`
  (runtime.rs:4191-4229). For each stored block it reads ONLY
  `block.signature.epoch` (sig.epoch, 4209) and `block.signature.signer_indices`
  (4217), resolves indices → validator keys, inserts into the slashed set.
  It does NOT call `signing_payload`, does NOT call any sig-verify, does NOT
  read any of the six dropped metadata fields. Both fields it uses live on the
  *signature* struct, which `encode_block` preserves verbatim (slashing_store.rs:
  189-194). CONFIRMED via Read.
- Call sites of `slashed_validators_for_epoch`: runtime.rs:4075 (epoch-boundary
  `get_enforced_active_set`) and actor.rs:1721. Both feed the active-set
  computation; neither re-verifies signatures.
- Grep for `signing_payload` across `src/hyper`: no call site consumes
  STORED/decoded slashing evidence. The only `signing_payload` use on the
  evidence path is `verify_evidence_signatures` (slashing.rs:89-111), called at
  actor.rs:1605 — on the IN-MEMORY, field-intact wire `evidence` produced by
  `detect_conflicting_blocks` (actor.rs:1588) BEFORE `record_evidence`
  (actor.rs:1608) stores it. Verification precedes the lossy encode and never
  touches the stored form.

Conclusion: today NO production consumer re-derives `signing_payload` from
stored evidence and re-checks the threshold signature. The "not self-verifying"
property has, at cab225f, no consumer that exercises it.

## 8-hypothesis walk

### H1 — Upstream auth / gate — STANDS (does not invalidate)
The finding does not claim an ingest bypass; it explicitly concedes the
ingest-time gate (`verify_evidence_signatures`, actor.rs:1605) runs on the
field-intact wire block before storage. That concession is accurate. No
upstream gate is missed because the claim is about the durable invariant, not
ingest.

### H2 — Consumer-side impact — PARTIALLY INVALIDATED (the key one)
RED-TEAM target. The sole stored-evidence consumer, `slashed_validators_for_epoch`
(runtime.rs:4191), uses only `sig.epoch` + `sig.signer_indices` — both
PRESERVED by `encode_block`. It performs NO signing_payload re-derivation and
NO signature re-verification. Therefore the six dropped fields have ZERO effect
on the actual penalty outcome at cab225f: the equivocator is still slashed
correctly, no legit slashing is DoS'd, no forged evidence verifies. The
"false-FAIL / equivocator evades slashing / liveness-DoS" outcomes in the
finding's Impact section are CONDITIONAL on a re-verification consumer that does
not exist in the codebase ("Today no consumer reconstructs-and-verifies, which
is why this is medium" — the finding says so itself, lines 82-84). So the
present-tense impact is "storage codec drops signed-only fields with no current
consumer" = latent/correctness-debt, not an exploitable or live-DoS condition.
Impact is OVERSTATED where the prose says re-verification "will see a false
mismatch and either reject legitimate evidence ... or fail the epoch-boundary
enforcement pass" — that path is not wired.

### H3 — Downstream enforcement — STANDS (reinforces H2)
The downstream epoch-boundary enforcement (`get_enforced_active_set` →
`slashed_validators_for_epoch`) does NOT re-verify signatures, so it neither
catches nor is broken by the dropped fields. It simply ignores the six fields
entirely. No layer re-checks the signature against stored evidence.

### H4 — PR HEAD currency — STANDS
`git log -1` at the workspace == cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
(2026-06-08), matching the pinned commit; working tree clean. The buggy
`encode_block` is present on the pinned HEAD. No newer fix in the workspace.

### H5 — Spec carve-out — NEEDS_MORE_DATA (leans no carve-out)
The module doc (slashing_store.rs:1-9) describes the store as "durable layer ...
that future epoch-boundary penalty enforcement reads from" but does NOT state
the storage codec intentionally drops signing-only fields. `gossip_adapter`
(the wire codec) is documented to preserve all signed fields, and
`signing_payload`'s own doc (mod.rs:393-402) stresses it must commit to every
hash-mixed field — so the divergence reads as an oversight, not a documented
deferral. No carve-out excuses it, but absence of an explicit "intentional"
note also means it is not formally a spec violation today (no consumer relies on
the property).

### H6 — Reachability of harm — INVALIDATED (for live harm)
There is no reachable path from the dropped fields to any penalty, value
transfer, or hard-error today. The only consumer ignores those fields. The
finding's own "freely supply dropped fields" / forged-evidence-verifies variant
is explicitly hypothetical ("enabled in principle", "if/when any re-verification
of stored evidence is added"). At cab225f the harm is unreachable. This is the
strongest invalidation of the *exploitability* framing; the *correctness-defect*
framing survives.

### H7 — Test wiring — STANDS
`encode_block` is genuinely on the production write path (`record` →
`record_evidence`, actor.rs:1608) and `slashed_validators_for_epoch` is on the
production epoch-boundary path. The lossy codec runs in production. (Note the
existing tests at slashing_store.rs:211-326 use blocks with all-zero
anchor/missed fields, so they cannot catch the round-trip loss — consistent
with the finding's "tests pass" observation.)

### H8 — PoC mechanics — N/A
No PoC accompanies F015 (code-walk finding). The Fix section proposes a
regression test but none is included, so there is no assertion to over-read.

## Overall verdict
HAS_CAVEATS. The mechanical core is WATERPROOF and verified verbatim at
file:line: `encode_block` zeroes six fields that `signing_payload` commits to,
the wire codec preserves them, and real blocks populate them — so persisted
evidence genuinely does not reproduce the signed bytes. However, the IMPACT is
overstated for the current tree: the only consumer of stored evidence
(`slashed_validators_for_epoch`, runtime.rs:4191) reads only signature-struct
fields that survive the codec and performs NO signing_payload re-derivation and
NO signature re-verification, so there is no live false-FAIL, no slashing
evasion, and no liveness/DoS at cab225f. The finding itself acknowledges this
("Today no consumer reconstructs-and-verifies, which is why this is medium"),
so the medium severity with a latent/correctness framing is defensible; the
high-impact conditional outcomes are not live. Confidence 0.85.

Severity assessment: medium is on the generous side for a latent invariant
break with no current consumer; Low–Medium is the honest band. The value is as
a correctness/durability hardening (and a real footgun for any future
re-verification or state-sync/light-client proof of the slashing set), not a
presently exploitable vulnerability. Recommend keeping the finding but framing
it as "latent / defense-in-depth: storage codec drops signing-payload fields;
no current re-verifier, but any future one is silently broken."

## Interaction with F001 (verify_evidence_signatures)
Checked the prompt's specific concern: F015 does NOT break the F001 fix.
`verify_evidence_signatures` (slashing.rs:89, the F001/F153 hardened verifier)
runs at actor.rs:1605 on the in-memory wire `evidence` BEFORE `encode_block` is
ever invoked (record at actor.rs:1608). The lossy storage codec is strictly
downstream of, and never re-invoked by, that verifier. No interaction; the
ingest-time signature gate is intact.

## Open follow-ups (NOT new findings — for specialist owners)
- If a future change adds re-verification of stored evidence (e.g. state-sync /
  light-client proof of the slashing set, cross-node consistency check, or a
  hard sig-recheck at the epoch boundary), F015 becomes live and would flip to
  the high-impact outcomes the body describes. The fix (share the wire codec /
  round-trip all signed fields) should land before any such consumer.
- Dedupe note: F015 references F028 (signing_payload superset) and F138 (wire
  codec preserves all fields) as the sibling fixes the storage codec failed to
  mirror. Dedupe-curator may want to relate F015 to those as the same
  signing-payload-coverage cross-cut, but root cause (storage codec divergence)
  is distinct.

---

## F016 — F023a pre-StartDkls buffer keyed by attacker-controlled target_epoch with no global cap or stale-epoch eviction, enabling unbounded memory growth from unauthenticated gossip

## Summary

The F023a fix buffers `InboundDkls` round messages that arrive before the
matching `StartDkls` in `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>`,
keyed by `target_epoch`. The ordering assumption baked into this design is:
"every buffered epoch will eventually be drained by a matching `StartDkls`."
An adversary who controls gossip arrival (the threat model the buffer was
written for) violates that assumption. `target_epoch` is fully
attacker-controlled and the buffering path performs **no authentication**, so
an attacker can allocate an unbounded number of 256-entry per-epoch buffers
that are never drained — a memory-exhaustion DoS against every node on the
topic.

## Where

`src/hyper/actor.rs`, `dispatch` arm `HyperActorEvent::InboundDkls`
(lines ~1321-1395), buffering branch:

```rust
let is_active = self.active_dkls.as_ref()
    .map(|d| d.driver.target_epoch() == target_epoch)
    .unwrap_or(false);
if !is_active {
    let buf = self.pending_dkls_inbound.entry(target_epoch).or_default();
    if buf.len() < PENDING_DKLS_INBOUND_CAP_PER_EPOCH {   // 256
        buf.push(encoded);
    } else { /* warn + drop */ }
    return Ok(());                 // <-- returns BEFORE any decrypt/auth
}
```

Drain is the only removal path, on the matching `StartDkls` (line ~1430):

```rust
if let Some(buffered) = self.pending_dkls_inbound.remove(&target) { ... }
```

The per-epoch cap (`PENDING_DKLS_INBOUND_CAP_PER_EPOCH = 256`, line ~1045)
is the *only* bound. There is no cap on the number of epoch keys, no eviction
of stale-epoch entries, and no pruning on epoch advance / `DkgFinalized`.
A full-file grep confirms `pending_dkls_inbound` is mutated in exactly two
places: the `entry().or_default()` insert above and the `remove(&target)`
drain above.

## Why it is exploitable

1. **`target_epoch` is attacker-controlled and unvalidated.** The gossip
   adapter (`gossip_adapter.rs`, `wire_to_event`, line ~84) maps
   `proto::HyperWireDkg.target_epoch` straight into
   `HyperActorEvent::InboundDkls { target_epoch: d.target_epoch, .. }` with no
   range/committee check. The full `u64` space is reachable from the wire.

2. **The buffering branch runs before authentication.** On the `is_active`
   path the actor opens the codec frame (`open_dkls_round_message`, which
   decrypts/authenticates) and applies the F018 `propagation_source` ↔
   committee cross-check. On the **buffering** path none of that happens —
   `encoded` is pushed verbatim and the arm returns `Ok(())`. So the attacker
   need not be in any committee, need not hold a transport secret, and need
   not produce a well-formed frame; arbitrary bytes are accepted into the
   buffer.

3. **`StartDkls` only fires for a bounded, honest window of epochs.** The
   supervisor (`dkls_supervisor.rs`, lines ~105-150) dispatches `StartDkls`
   only for `first_undispatched..=next_epoch`, and breaks once
   `blocks_until_target > start_lead_blocks`. `build_driver` may also fail
   (`skip StartDkls`), so even an in-window epoch can lack a `StartDkls`.
   Therefore the vast majority of attacker-chosen epochs (far-future, or any
   epoch in which this node is not a committee member) will **never** receive
   a matching `StartDkls`, so their buffers are never `remove()`d.

4. **Result: unbounded growth.** Each distinct attacker-chosen `target_epoch`
   allocates a fresh `Vec` holding up to 256 `encoded` blobs. By varying
   `target_epoch` per frame, the attacker grows the `BTreeMap` without bound.
   Memory consumed ≈ (number of distinct epochs sent) × up to 256 ×
   |encoded|. No size limit on `encoded` was found at the adapter layer, so
   each entry can be sizable, amplifying the per-frame cost. This wedges the
   actor (OOM / allocator pressure) and is a liveness/availability failure
   for the whole DKG path — a node killed this way cannot participate in DKG
   or threshold signing.

## Ordering-assumption framing

This is squarely a mailbox-ordering-assumption bug. The buffer exists to
tolerate the reorder where `InboundDkls(epoch=E)` arrives before
`StartDkls(epoch=E)`. The implementation assumes the reorder is *transient*
and *bounded* — that a `StartDkls` for `E` is forthcoming. Because gossip
arrival is adversarially controllable and `target_epoch` is unauthenticated,
the attacker supplies the "early" half of the pair (`InboundDkls`) for epochs
whose "late" half (`StartDkls`) the honest supervisor will never emit. The
prerequisite-before-dependent buffer becomes a permanent leak.

## Severity

High. Remote, unauthenticated, low-cost (single gossip topic; no committee
membership or key material required) memory-exhaustion DoS against any node
subscribed to the DKG topic. Availability impact on the DKG/threshold-signing
subsystem; a sustained flood can OOM-kill validators. Not direct fund-loss,
hence not critical, but a network-wide liveness threat.

## Suggested remediation

- Bound the buffer globally: cap the number of distinct epoch keys
  (`pending_dkls_inbound.len()`), evicting lowest/oldest, in addition to the
  per-epoch cap.
- Reject `target_epoch` far outside the plausible window at the adapter or at
  the head of the `InboundDkls` arm (e.g., `target_epoch` must be within
  `[current_epoch - k, current_epoch + start_lead_window]`), so only epochs
  that could plausibly receive a `StartDkls` are bufferable.
- Prune stale-epoch buffers on epoch advance / once an epoch is finalized or
  passes.
- Optionally bound `|encoded|` for buffered (pre-auth) frames.

## Verification notes

- `target_epoch` provenance: `src/hyper/gossip_adapter.rs` ~L84-88.
- Buffering branch returns pre-auth: `src/hyper/actor.rs` ~L1334-1345.
- Sole drain path: `src/hyper/actor.rs` ~L1430.
- No prune/evict/clear of `pending_dkls_inbound` anywhere (grep over
  `actor.rs`: only insert + `remove(&target)`).
- Bounded StartDkls window: `src/hyper/dkls_supervisor.rs` ~L105-150.

### Validation

- Verdict: **WATERPROOF**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F016 validation — pending_dkls_inbound unbounded epoch keys (memory DoS)

Validator: validator (deliberate-disagreement role)
Finding: F016 — F023a pre-StartDkls buffer keyed by attacker-controlled `target_epoch`
Audited commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (== current `origin/pow` HEAD)
Validated: 2026-06-08

## Core code re-verified at cab225f

- Buffer field: `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>`
  — `src/hyper/actor.rs:1004`.
- Per-epoch cap only: `PENDING_DKLS_INBOUND_CAP_PER_EPOCH = 256`
  — `src/hyper/actor.rs:1045`.
- Pre-auth buffering branch: `src/hyper/actor.rs:1334-1346`.
  `if !is_active { entry(target_epoch).or_default(); push(encoded); return Ok(()) }`.
  Returns BEFORE codec-open / F018 sender check.
- F018 sender↔peer-id cross-check runs ONLY on the `is_active` path
  (`src/hyper/actor.rs:1373`), i.e. AFTER the buffer branch has already
  returned. So the buffer path is genuinely pre-authentication.
- Sole drain: `remove(&target)` on StartDkls — `src/hyper/actor.rs:1430`.
- Whole-codebase grep: `pending_dkls_inbound` is mutated in exactly two
  places — insert (1335) and remove-on-StartDkls (1430). No `.clear()`,
  `.retain()`, `.split_off()`, no DkgFinalized/epoch-advance pruning,
  no global epoch-key cap. Confirmed.
- `target_epoch` provenance: `gossip_adapter.rs:84-88` maps
  `proto::HyperWireDkg.target_epoch` straight into the event with no
  range/committee check. Full u64 reachable from the wire.
- Ingress path: `network/gossip.rs:1099-1144` decodes HyperWire frames
  from gossipsub and `tx.try_send`s the event to the actor. Reachable
  from untrusted gossip on topic `hyper/dkg/v1` (`topics.rs:18`).
- Supervisor StartDkls window is bounded: only
  `first_undispatched..=next_epoch`, `break` once
  `blocks_until_target > start_lead_blocks`; `build_driver` may also skip
  — `dkls_supervisor.rs:119-150`. Far-future / non-member epochs never
  get a matching StartDkls → never drained. Confirmed.

## 8-hypothesis walk

### H1 — Upstream auth / gate — STANDS
RED-TEAM target. Gossipsub runs `ValidationMode::Strict` + `MessageAuthenticity::Signed`
(`gossip.rs:314,324`), so the publishing peer-id is *authenticated*, and
F017 enabled peer scoring + greylist (`gossip.rs:328-343`). BUT:
(a) Strict signing authenticates the peer-id, it does NOT restrict WHO
may publish — `hyper/dkg/v1` is a normal public gossipsub topic; any
libp2p peer that connects + subscribes joins the mesh and can publish.
The "validators-only / peer-restricted" notes in `topics.rs:16,36` are
aspirational — only describe which topics *this* node subscribes to; no
publish-side allow-list / committee gate is implemented.
(b) The buffer path returns `Ok(())` and there is NO
`report_message_validation_result(...Reject)` anywhere in `gossip.rs`
(grep: zero matches). So junk DKG frames are accepted by default at the
gossipsub layer and are NOT counted as invalid-message-rate against the
sender's score. Default `PeerScoreParams`/`Thresholds` give only generic
rate protection, not bug-specific. No upstream gate bounds the map.
`target_epoch` is attacker-controlled and unvalidated as claimed.

### H2 — Consumer-side impact — STANDS
The "consumer" of the corrupted state is the allocator: each distinct
attacker epoch allocates a fresh `Vec` (up to 256 × |encoded|). The
harmful consumer is process memory itself — no value-transfer consumer
needed for a memory-exhaustion DoS. Impact is availability, not fund
loss (consistent with High, not Critical).

### H3 — Downstream enforcement — STANDS
The drain path (StartDkls, 1430) re-runs codec-open + would discard junk,
but it is NEVER reached for attacker-chosen epochs that get no StartDkls.
The 256/epoch cap is the only enforced bound and it does nothing to bound
the *number of epoch keys*. No downstream layer prunes the map.

### H4 — PR HEAD currency — STANDS (notable)
`git fetch origin pow` → `origin/pow` HEAD == cab225f (the audited
commit). `git log cab225f..origin/pow` is empty: nothing newer fixes it.
(Stale local `origin/pow`@6cff47c, dated 2026-05-19, predates the F023a
buffer entirely and lacks `pending_dkls_inbound` — that is an OLDER
ancestor, not a fix.) The unbounded buffer is present on the live branch
HEAD. Branches `fix-memory` / `additional-memory-fix` / `main` do not
contain the buffer (it lives only on the `pow` line). No fix upstream.

### H5 — Spec carve-out — PARTIALLY (does not invalidate)
`topics.rs:16-17` comment says the DKG topic is separate "so they can be
rate-limited or peer-restricted independently" — an acknowledgment that
restriction is desired but explicitly NOT yet implemented. No SECURITY.md
/ doc says the unbounded buffer is intentional. No carve-out that excuses
the leak; if anything the comment confirms the gap is known-aspirational.

### H6 — Reachability of harm — STANDS
Path fully reachable: untrusted peer → `hyper/dkg/v1` → `gossip.rs:1099`
→ `wire_to_event_with_source` (`gossip_adapter.rs:84`) → channel →
actor `InboundDkls` arm → buffer insert. Each frame is bounded to 512KB
by `MAX_HYPER_WIRE_BYTES` (`gossip.rs:52,1100`), but the epoch-key
dimension is unbounded, so growth is unbounded regardless of per-frame
size. The bounded `hyper_actor_tx` channel only rate-limits ingestion;
it does not bound the actor-resident map (entries persist after dequeue).

### H7 — Test wiring — STANDS
The buffering branch is in the production `dispatch` arm reached from the
real gossip ingest (`gossip.rs:1120` → `wire_to_event_with_source`), not
test-only. `wire_to_event_with_source` is called from production gossip
(`gossip.rs:1120`); the other call sites are tests. Production-reachable.

### H8 — PoC mechanics — N/A
No PoC accompanies F016 (code-walk finding). Nothing to over-claim.

## Minor inaccuracy in the finding body (not invalidating)
- "No size limit on `encoded` was found at the adapter layer" (point 4)
  is imprecise: `network/gossip.rs:52,1100` caps the whole HyperWire frame
  at `MAX_HYPER_WIRE_BYTES = 512 KB`, so each buffered `encoded` is
  bounded ~512 KB. This caps per-entry size but NOT the number of epoch
  keys, so the unbounded-growth conclusion is unaffected. The amplification
  framing ("each entry can be sizable") is bounded at 512 KB/frame.

## Overall verdict
WATERPROOF (with one minor body imprecision noted above). The central
claim — unauthenticated, attacker-controlled `target_epoch` keying a
`BTreeMap` with a per-epoch cap but NO global epoch-key cap / TTL /
eviction, reachable from untrusted gossip, drained only by an honest
StartDkls that never fires for attacker-chosen epochs — is verified at
file:line. Gossipsub Strict signing + F017 peer scoring are real but
weak/generic mitigations that do not bound the map and do not gate the
pre-auth buffer path. Confidence 0.9.

Severity assessment: High is appropriate (remote, low-cost, unauthenticated
availability DoS on the DKG/threshold-signing subsystem; not fund loss).
Peer-scoring partial mitigation is the only reason this isn't 0.95+.

## Open follow-ups (NOT new findings — for specialist owners)
- F024 in this set ("buffered DKLS DKG drain skips sender authentication")
  targets the SAME buffer from the drain/auth angle. Dedupe-curator should
  decide same-root-cause vs related (both stem from the F023a buffer +
  pre-auth handling). Not a validation issue for F016.
- Consider whether peer-scoring could be strengthened by calling
  `report_message_validation_result(...Reject/Ignore)` for out-of-window
  `target_epoch` DKG frames so the flood costs the attacker score — but
  that is a remediation suggestion, already implied by F016's fixes.

---

## F018 — Per-epoch DKLS23 secret-share keystore (dkls_signers) is never pruned, zeroized, or retired across epoch transitions, so retired threshold shares stay live and signing-capable for the process lifetime

## Summary

`HyperRuntime.dkls_signers: BTreeMap<u64, DklsEpochState>` is the
post-migration authoritative threshold-ECDSA keystore. Each
`DklsEpochState` holds the local DKLS23 `Party` — i.e. this node's
**secret share of the group key plus the pre-computed multiplication
shares used at signing time** (`runtime.rs:324-335`). The map is keyed by
epoch and is **insert-only**: it is mutated in exactly one place
(`install_local_dkls_share`, `runtime.rs:4722`) and read in two
(`dkls_share_for_epoch`, the production path). There is **no removal,
prune, eviction, retirement, or zeroization path anywhere in the
codebase** — a full grep of `src/hyper/**` shows `dkls_signers` is only
ever `insert`ed, `get`/`keys`-read, and `BTreeMap::new()`-initialized.

Consequently a node that participated as a signer in epoch `E` keeps the
epoch-`E` secret share live in process memory indefinitely, long after
epoch `E` has retired and the committee has rotated. The secret material
leaks across every subsequent lifecycle transition. This is a
lifecycle-state-leak: state that the protocol model treats as bound to a
single (now-dead) epoch persists and remains usable in later epochs.

## Where

- State def: `src/hyper/runtime.rs:288`
  `pub dkls_signers: std::collections::BTreeMap<u64, DklsEpochState>`
- Secret material: `src/hyper/runtime.rs:324-335` (`DklsEpochState.party`
  = secret share + mult shares; comment confirms "our share of the group
  secret").
- Sole insert: `src/hyper/runtime.rs:4715-4748` `install_local_dkls_share`
  (called from `genesis.rs`, `dkls_driver.rs`, `dkls_supervisor.rs` on
  every finalized ceremony).
- Sole reads: `src/hyper/runtime.rs:4772-4774` `dkls_share_for_epoch`;
  block-production path `runtime.rs:4832-4838`,
  `runtime.rs:4902-4905`.
- No prune: grep `dkls_signers` over `src/hyper/**` returns only the
  insert, the reads, `next_back()` (a query helper, `actor.rs:1729-1737`),
  and `BTreeMap::new()`. No `.remove(`, `.retain(`, `.clear(`, `.split_off(`.
- No zeroize: grep `Zeroize|zeroize|impl Drop for DklsEpochState` in
  `runtime.rs` returns nothing. `DklsEpochState` derives only `Clone`; the
  `Party` is dropped by the default allocator with no scrubbing.

## Why it is a leak (and the contrast that proves intent)

The struct doc-comment at `runtime.rs:282-287` explicitly states that once
the DKLS path is authoritative "the existing `signer` BLS state is
retired." There is corresponding retirement logic for the BLS signer, but
**no analogous retirement for `dkls_signers`** — the DKLS shares simply
accumulate. The keystore was designed with a notion of per-epoch lifetime
but the lifetime is never enforced.

Two concrete consequences of the stale share remaining *usable*:

1. **Bridge-side local sign helpers accept an arbitrary, retired epoch.**
   - `produce_signed_lock_merkle_root_local(epoch, block_number)`
     (`runtime.rs:940-987`) does `dkls_share_for_epoch(epoch)` with **no
     "epoch must be current" check** and will produce a fresh, valid ECDSA
     signature over a *current* merkle root using a *retired* epoch's
     secret share.
   - `produce_signed_owner_rotation_local(outgoing_epoch,
     incoming_epoch, ...)` (`runtime.rs:1066-1122`) likewise signs with
     whatever epoch shares are still resident.
   Both contrast with the block-production path
   (`produce_unsigned_block_dkls`, `runtime.rs:4824-4838`), which was
   deliberately hardened by a prior fix (F028/F026) to bind signing to
   `epoch_resolver.current_epoch()` precisely because
   "`dkls_signers.iter().next_back()` ... leaks pre-staged future-epoch
   material into current production." That same anti-pattern — using a
   non-current epoch's resident share — is still reachable through the
   bridge helpers because the underlying keystore is never pruned.

2. **Verify side resolves the group key from an attacker-chosen epoch
   against the never-pruned group-address registry.** All threshold-signed
   apply paths key off the caller-supplied `epoch` field via
   `dkls_group_address_for_epoch(...)` (issuance `runtime.rs:566`,
   trust-snapshot `:656`, merkle-root `:1026`, owner-rotation `:1146/:1149`,
   inbound-burn `:1333`). The trust-snapshot path defends against exactly
   this stale-key reuse with an explicit epoch-monotonicity watermark
   (`last_trust_snapshot_epoch`, `runtime.rs:646-653`, whose own comment
   warns "an attacker holding a valid older-epoch threshold signature could
   otherwise clobber a fresh snapshot"). The **lock-merkle-root**
   (`apply_lock_merkle_root_update`, `:995-1055`) and **owner-rotation**
   (`apply_owner_rotation`, `:1130-`) paths enforce only `block_number`
   monotonicity, **not** epoch monotonicity, so the protocol-side store will
   accept a fresh payload signed by a retired epoch's group key.

## Impact / severity rationale

This is a confirmed cross-epoch secret-material leak (lifecycle-state-leak).
Direct fund-loss exploitability is partially blunted by two factors, which
is why this is rated medium rather than high:

- The canonical **block** signing path is pinned to `current_epoch`, so a
  stale share cannot forge a current hyperblock through the normal proposer
  flow.
- The **bridge contract** (`HypersnapBridge.sol`) is the authoritative
  enforcer of the current owner/root; a signature from a *retired* group
  address is rejected on-chain even though the protocol-side
  `apply_lock_merkle_root_update` / `apply_owner_rotation` relay-cache
  accepts it. The protocol-side acceptance is a local-state divergence /
  relay-cache poisoning, not an on-chain fund move on its own.

The real and unavoidable harm is **secret-material hygiene / blast-radius
expansion**:

- A rotated-out validator retains a fully usable secret share for every
  epoch it ever signed in. The protocol treats those epochs as dead; the
  node does not. This is exactly the "state that leaks across transitions"
  the lifecycle-state-leak class targets, and it converts a single-epoch
  committee membership into an indefinite signing capability for that
  epoch's group key.
- A node compromised at time T leaks **every** historical epoch's secret
  share at once (the whole `BTreeMap`), not just the current epoch's. With
  no zeroization on drop, the material also lingers in freed heap pages.
- The lock-merkle-root / owner-rotation verify paths lack the
  epoch-monotonicity guard that the trust-snapshot path has, so a leaked
  retired share can poison the protocol-side relay cache with stale-key
  signatures (local divergence from on-chain truth, a liveness/consistency
  hazard for relayers reading the cached "latest signed root/owner").

## Suggested remediation

- Prune `dkls_signers` at the epoch boundary: on epoch advance / once an
  epoch is finalized and past its signing window, remove the now-retired
  epoch's `DklsEpochState`, retaining only a small bounded window
  (e.g. `current_epoch` and `current_epoch - k` for in-flight rotations).
  Mirror this in the scheduler/actor epoch-transition handler that already
  drives `EvaluateEpochDkls`.
- Implement `Drop`/`Zeroize` for `DklsEpochState` (and ensure the vendored
  `Party` zeroizes its secret share) so retired shares are scrubbed, not
  just dropped.
- Add an epoch-currency check to the bridge-side local sign helpers
  (`produce_signed_lock_merkle_root_local`,
  `produce_signed_owner_rotation_local`): refuse to sign with a share whose
  epoch is not the current (or the explicitly-intended rotation) epoch,
  matching the `current_epoch` binding already enforced on the block path.
- Add epoch-monotonicity replay guards to `apply_lock_merkle_root_update`
  and `apply_owner_rotation` analogous to `last_trust_snapshot_epoch`, so
  the protocol-side relay cache cannot be advanced by a retired epoch's
  group key.

## Verification notes

- `dkls_signers` mutation sites (whole repo): insert at
  `runtime.rs:4722`; no remove/retain/clear/split_off anywhere.
- Block path current-epoch binding (the contrasting, hardened path):
  `runtime.rs:4824-4838`.
- Bridge local-sign helpers take caller-chosen epoch, no currency check:
  `runtime.rs:940-987`, `runtime.rs:1066-1122`.
- Trust-snapshot epoch-monotonicity guard (present) vs merkle-root /
  owner-rotation (absent): `runtime.rs:646-653` vs `:995-1055` / `:1130-`.
- No zeroize/Drop for `DklsEpochState`: `runtime.rs:323-335`.
- Persistence asymmetry confirming design intent: only the group-address
  registry is durable; shares are in-memory and empty after restart
  (test `runtime.rs:5702-5705`) — i.e. the only thing that *does* clear the
  shares is a process restart, never a lifecycle transition.

### Validation

- Verdict: **WATERPROOF**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F018 Validation — DKLS signer share keystore never pruned at epoch boundary

Validator: validator (deliberate-disagreement). Commit `cab225f`. Read-only.

Finding claims: `dkls_signers: BTreeMap<u64, DklsEpochState>` (per-epoch secret
share + mult shares) is insert-only — no prune/zeroize/retire — so retired shares
stay live and signing-capable for process lifetime. Two consequences asserted:
(1) bridge local-sign helpers take a caller-chosen epoch with no currency check;
(2) verify-side resolves group key from a never-pruned registry; lock-merkle-root
/ owner-rotation apply paths lack the epoch-monotonicity guard the trust-snapshot
path has. Rated **medium** (hygiene / blast-radius), explicitly conceding (a) block
path is pinned to current_epoch and (b) on-chain bridge rejects retired group keys.

## Code confirmation (whole-repo)

- `dkls_signers` mutations: insert only at `runtime.rs:4722` (`install_local_dkls_share`).
  Reads: `4773` (`dkls_share_for_epoch`), `4834`/`4903` (block path), query helper
  `actor.rs:1732`. Init `434`. **No `.remove/.retain/.clear/.split_off`** anywhere
  (grep confirmed). Registry `dkls_group_addresses` ALSO never pruned (grep: empty).
- No `Zeroize`/`impl Drop for DklsEpochState` (grep: empty). Struct derives Clone only.
- Block path pinned to `epoch_resolver.current_epoch()` at `runtime.rs:4832-4838`
  (F028/F026 fix) — CONFIRMED. Finder's concession is accurate.
- Bridge helpers take caller-chosen epoch, no currency check: `produce_signed_lock_
  merkle_root_local` `940-987` (only checks threshold==share_count==1, not epoch
  currency); `produce_signed_owner_rotation_local` `1066-1122` (same). CONFIRMED.
- Verify/apply paths resolve key from `dkls_group_address_for_epoch(update.epoch)`
  (caller field): `1025-1027` (merkle) / `1145-1150` (rotation). Only `block_number`
  monotonicity guard (`1020-1023`, `1140-1144`); NO epoch watermark. Contrast
  trust-snapshot `last_trust_snapshot_epoch` guard at `646-653`/`677`. CONFIRMED.
- On-chain bridge: `claim` `ownerSig.recover != ownerAddress -> BadOwnerSignature`
  (`HypersnapBridge.sol:194`); `rotateOwner` `243/251`; recover/pause `286/...`.
  A retired group address does NOT recover to current `ownerAddress` -> L1 reverts.
  CONFIRMED — concession (b) is accurate.

## 8-hypothesis walk

**H1 Upstream auth / gate — PARTIALLY INVALIDATES the verify-side impact.**
The bridge helpers and the gossip ingest of `LockMerkleRootUpdate`/`OwnerRotation`
(`runtime.rs:3744-3756`, `submit_message`) both reach apply with a caller-supplied
epoch and no currency gate. BUT to produce a HONORED signature the actor must hold,
or the network peer must possess, the retired epoch's secret share. A non-share-holder
cannot forge the ECDSA sig. So the only actor that can exercise the stale-epoch path
is one already holding the leaked share (rotated-out / compromised node) — i.e. the
exact threat the finding scopes. No upstream gate invalidates the *root cause* (no
prune/zeroize), but it bounds the attacker set to share-holders. STANDS as scoped.

**H2 Consumer-side impact — PARTIALLY INVALIDATED (impact correctly downgraded).**
Cached `latest_signed_lock_merkle_root`/`latest_owner_rotation` are consumed by
relayers via HTTP (`http_handler.rs:634`/`599`) and posted to L1. On-chain bridge
rejects a retired-key signature (Sol:194/243). So a poisoned protocol-side cache is
a LOCAL divergence / relayer-confusion (liveness/consistency), not an on-chain fund
move. The finding states exactly this. No overstatement: medium, not high.

**H3 Downstream enforcement — STANDS for root cause; bounds impact.**
The L1 contract IS the downstream re-verifier and catches the retired-key forgery.
That is precisely why the finding is hygiene/blast-radius, not fund-loss. The
protocol-side apply path does NOT re-verify epoch currency (only block_number), so
the local cache-poisoning sub-claim survives downstream enforcement.

**H4 PR HEAD currency — STANDS.** Workspace HEAD == pinned `cab225f1f63...` (git
rev-parse matches). No drift.

**H5 Spec carve-out — STANDS (and strengthens finding).** Doc-comment `runtime.rs:
282-287` says BLS signer is "retired" once DKLS authoritative; no analogous DKLS
retirement exists. Helper doc-comments frame local-sign as "1-of-1 devnet" path
(`1057-1065`) but do NOT mark the missing prune/zeroize as intentionally deferred.
No SECURITY.md / FIP carve-out found that says "shares intentionally kept resident."

**H6 Reachability of harm — PARTIALLY INVALIDATED.** The acute harm (forged L1 move)
is unreachable — on-chain owner check blocks it. The reachable harm is: (a) indefinite
resident secret material (a node compromised at T leaks the whole BTreeMap = every
historical epoch's share, no zeroize on freed pages); (b) protocol-side relay-cache
poisoning by a share-holder. Both are real but bounded to share-holders / local state.
Matches the finding's medium framing.

**H7 Test wiring — STANDS (production-wired).** `produce_signed_lock_merkle_root_local`
called in production at `actor.rs:2176` (epoch-boundary refresh, EvaluateEpochDkls);
apply at `actor.rs:2188`/`2837` and gossip ingest `runtime.rs:3746`. Not test-only.
NOTE: in production the *honest* caller passes the protocol-driven scoring epoch from
`EvaluateEpochDkls`, not an attacker-chosen one — so the helper's missing currency
check is only abusable by a misbehaving share-holder, consistent with H1.

**H8 PoC mechanics — N/A / STANDS.** No executable PoC asserted; finding rests on
static grep + path tracing, all independently reproduced above. The replay tests at
`runtime.rs:6333-6341`/`6532-6538` exercise only `block_number` monotonicity — they
do NOT cover epoch monotonicity, corroborating the missing-guard claim rather than
refuting it.

## Overall

The root-cause claim (insert-only, never-pruned, never-zeroized per-epoch secret
keystore + parallel never-pruned address registry; missing epoch-currency check on
bridge helpers; missing epoch-monotonicity guard on lock-root/owner-rotation apply
vs. the present trust-snapshot guard) is fully verified at the cited lines. The
finding does NOT overstate: it explicitly concedes the two mitigations (current_epoch
block binding; on-chain owner enforcement) that I independently confirmed, and lands
on medium = secret-material hygiene / blast-radius expansion + local relay-cache
poisoning. The exploit set is bounded to share-holders (insider/compromised), which
the finding's own threat model assumes.

VERDICT: WATERPROOF (impact already correctly bounded to medium). Confidence 0.9.

## Open follow-ups (NOT new findings — for specialist consideration)
- The gossip ingest path `submit_message` (`runtime.rs:3744-3756`) applies
  network-received `LockMerkleRootUpdate`/`OwnerRotation` with a caller-supplied
  epoch and only block_number monotonicity. If a *current* share is ever multi-held
  this widens the relay-cache poisoning surface beyond local self-sign; worth the
  specialist confirming whether the epoch-monotonicity guard should live in apply_*
  regardless of share residency. Folds under F018's remediation #4.

---

## F021 — DKLS inner-sender binding fails open per-party when a committee member registered no libp2p_peer_id, letting any peer spoof that party in a DKLS round

## Summary

The F018 mitigation that binds a DKLS round message's application-level
inner `sender` byte to the authenticated libp2p originator
(`check_dkls_sender_against_propagation_source`,
`code/hypersnap/src/hyper/actor.rs:2462`) is **fail-open on a per-party
basis**. When the runtime has no registered libp2p peer-id for the
claimed sending party in the target epoch, the check returns `true`
(accept) instead of rejecting.

A committee member can be in the enforced active set / DKLS committee
yet absent from the peer-id registry, because `libp2p_peer_id` is an
**optional, never-validated-non-empty** field of the validator Register
event. For any such party, an attacker controlling a single gossip mesh
peer can broadcast a plaintext DKLS round message claiming
`sender = <that party>`, and honest nodes submit it into their active
DKLS driver as if it came from that committee member. That is exactly
the sender-spoofing-inside-payload class the F018 registry was built to
close, and it is open for the empty-peer-id case.

## Where the binding fails open

`check_dkls_sender_against_propagation_source`
(`code/hypersnap/src/hyper/actor.rs:2462`):

```rust
let registered = match self.runtime.peer_id_for_party(epoch, claimed_sender) {
    Some(p) => p,
    None => {
        // Permissive: no registered peer-id for this party
        // in this epoch. Validator registry rollout is
        // gradual; treat as unverified rather than reject.
        return true;
    }
};
```

The `None` branch unconditionally accepts. The author's doc comment
(`actor.rs:2450-2453`) frames this as a transitional "pre-rollout
permissive mode … until every active validator has registered a
`libp2p_peer_id`." The problem is that this is not a global rollout
flag — it is evaluated **per claimed sender, every frame**, so the
fail-open path persists indefinitely for any party that simply never
supplied a peer-id.

## Why a committee party can have no registered peer-id

`peer_id_for_party` (`code/hypersnap/src/hyper/runtime.rs:1242`) resolves
the party's `validator_key` from the enforced active set, then looks it
up in `validator_registry.compute_active_peer_ids(epoch)`.

`compute_active_peer_ids`
(`code/hypersnap/src/hyper/validator_registry.rs:757`) only inserts a
peer-id when it is **non-empty**:

```rust
if !e.libp2p_peer_id.is_empty() {
    peer_ids.insert(e.validator_key.clone(), e.libp2p_peer_id.clone());
}
```

But the active-set / DKLS-committee computation
(`get_active_validators_enforced`, `runtime.rs:4055`;
`compute_active_set`) does **not** require a peer-id at all — membership
is keyed on the Register event and trust/slashing filters, never on
peer-id presence. So a validator who registers with an empty
`libp2p_peer_id` is a full committee member (gets a party index, gets
DKLS round messages addressed to/from it) yet is missing from the
peer-id map → `peer_id_for_party` returns `None` →
`check_dkls_sender_against_propagation_source` returns `true` for any
frame claiming that party as `sender`.

`libp2p_peer_id` is optional and unvalidated at registration:
`code/hypersnap/src/hyper/http_handler.rs:234-239` parses it with
`.unwrap_or_default()` (empty vec when omitted), and the registry never
rejects an empty peer-id (it is folded into the canonical signed
payload at `validator_registry.rs:167-168` but no non-empty check
exists anywhere). The runtime's own test fixtures register validators
with `libp2p_peer_id: vec![]` (`runtime.rs:6813, 6863, 6899, 6972`),
confirming an empty peer-id is a fully supported registration shape.

## Attack path

1. Victim nodes run a DKLS DKG (or sign) ceremony for epoch E. Committee
   party `Q` registered with an empty `libp2p_peer_id` (permitted).
2. Attacker controls any one peer `A` in the gossip mesh (does not need
   to be a committee member — it just needs to publish on
   `TOPIC_HYPER_DKG`). Gossipsub is `ValidationMode::Strict` +
   `MessageAuthenticity::Signed` (`gossip.rs:314,324`), so `A`'s frames
   carry `A`'s authenticated peer-id as `originator`.
3. `A` publishes a DKLS DKG frame with discriminator
   `DISCRIMINATOR_PLAINTEXT` (a broadcast variant) wrapping a
   `DklsRoundMessage` whose `sender() == Q`. Plaintext broadcasts are
   accepted without any AEAD/transport-pubkey check
   (`dkls_wire_codec.rs:294-298`), and the inner/outer header
   cross-check only runs for the *encrypted* branch — broadcasts skip
   it entirely.
4. Ingress threads `originator = A` as `propagation_source`
   (`gossip.rs:1119-1122`, `wire_to_event_with_source`).
5. In `HyperActorEvent::InboundDkls`
   (`actor.rs:1367-1385`), the opened broadcast message reaches
   `check_dkls_sender_against_propagation_source(E, Q, Some(A))`.
   Because `peer_id_for_party(E, Q)` is `None`, the check returns
   `true`, and `dkls.driver.submit(message)` ingests the spoofed frame
   as if `Q` sent it. The same hole exists on the sign path
   (`actor.rs:1521-1533`).

The libp2p transport authenticated `A`, but the application-level
`sender = Q` was never bound to `A` — the anti-pattern "we trust the
transport for sender-auth" applied selectively to the empty-peer-id
subset of the committee.

## Impact / severity

The codec doc (`dkls_wire_codec.rs:276-283`) argues residual risk is
"liveness-only" because forged round messages cause peer-side aborts per
DKLS23's `sign_id` binding rather than state corruption. Even taking
that at face value, the consequence is a **liveness / griefing**
vector: a single non-committee mesh peer can inject forged round-1/round
messages attributed to `Q`, driving honest drivers into aborts or
inconsistent transcripts and stalling the threshold ceremony that gates
epoch reward issuance, trust-snapshot updates, lock-root and burn
signatures. The defense the whole F018 registry exists to provide is
silently disabled for any committee member who omitted a peer-id, and
nothing forces a committee member to provide one.

Rated **medium**: confirmed authentication bypass of the F018
sender-binding control with a concrete remote, low-privilege trigger
(one mesh peer, no committee membership required), bounded by the
upstream DKLS `sign_id`/abort behavior to liveness/griefing rather than
threshold-secret compromise in the cases reviewed. If a downstream
driver path treats a `submit`-accepted spoofed broadcast as
state-affecting (not re-reviewed exhaustively here), impact rises.

## Suggested direction (non-binding)

Make the binding fail-closed for active committee members: if
`claimed_sender` is a party in the enforced active set for `epoch` but
has no registered peer-id, **drop** rather than accept; and/or require a
non-empty, well-formed `libp2p_peer_id` at validator registration so a
committee party can never be peer-id-absent. The `propagation_source ==
None` (locally-synthesized) accept branch is acceptable; the
registry-miss accept branch for an active party is the hole.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.82
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F021 validation — DKLS sender-binding fail-open for peer-id-absent committee party

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f`. HEAD verified == `cab225f` (no drift).

Finding under test: `check_dkls_sender_against_propagation_source` (actor.rs:2462) returns `true` (accept) when
`peer_id_for_party(epoch, claimed_sender)` is `None`, i.e. the claimed sender is an active committee party that
registered an empty `libp2p_peer_id`. This re-opens the F018 sender-spoofing-inside-payload class for that party.

## Code claims re-verified (file:line)

- Fail-open `None` branch: `actor.rs:2474-2479` — `return true` with "permissive" comment. CONFIRMED verbatim.
- Both ingest paths call it: DKG `actor.rs:1373-1379` (ForUs | Broadcast), Sign `actor.rs:1521-1527`. CONFIRMED.
- `peer_id_for_party` resolves active set then registry peer-ids, returns `None` on miss: `runtime.rs:1242-1256`. CONFIRMED.
- Registry inserts peer-id only when non-empty: `validator_registry.rs:805-806`. CONFIRMED.
- Register validation enforces validator_key/validator_address/transport_pubkey lengths but has NO non-empty
  check on `libp2p_peer_id`: `validator_registry.rs:372-411`. CONFIRMED — registration invariant does NOT
  require a peer-id, while it DOES require a 32-byte transport_pubkey (asymmetry is the root cause).
- HTTP parse uses `.unwrap_or_default()` (empty vec when omitted): `http_handler.rs:234-239`. CONFIRMED.
- Test fixtures register with `libp2p_peer_id: vec![]`: `runtime.rs:6813,6863,6899,6972`. CONFIRMED — empty peer-id
  is a fully supported shape.
- Gossipsub Strict + Signed: `gossip.rs:314,324`. Originator passed as source: `gossip.rs:1119-1122`. CONFIRMED.
- Plaintext broadcast decode (no AEAD): `dkls_wire_codec.rs:294-298`. CONFIRMED.

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a committee-membership gate on the gossip ingress that drops a non-committee publisher before the actor?
NO. `GossipMessage::HyperWire` ingress (`gossip.rs:1099-1135`) checks only size cap, then forwards any Strict-signed
frame to the actor with `originator` as source. There is no "is this peer a committee member" filter at ingress.
The ONLY application-level sender-binding control is `check_dkls_sender_against_propagation_source` itself — the
function that fails open. So the bug is not masked by an upstream gate; it IS the gate. Stands.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (impact bounded, not zero)
What consumes a spoofed `submit`? `dkls.driver.submit(message)` → `coordinator.submit` (dkls_driver.rs:59-61).
The codec doc-comment (`dkls_wire_codec.rs:276-283`) and the finding both assert residual risk is liveness-only:
DKLS23 `sign_id` binding makes a forged round message cause a peer-side Abort, not threshold-secret extraction or
state corruption. I did not find evidence contradicting that bound (no path where a `submit`-accepted spoofed
broadcast writes finalized state without the ceremony's own internal consistency/`sign_id` checks). The finding
already rates this medium and explicitly flags the unbounded case as "not re-reviewed exhaustively." So impact is
real but correctly bounded to liveness/griefing (ceremony abort / stall of reward / lock-root / burn signing).
This does not invalidate the finding; it confirms the finding's own impact ceiling. Partial only re: the
"if downstream treats spoof as state-affecting, impact rises" speculation, which remains NEEDS_MORE_DATA.

### H3 Downstream enforcement — STANDS (with caveat that it bounds severity, see H2)
Does a lower layer re-verify the sender? The DKLS coordinator's `sign_id` binding is exactly that downstream
enforcement — but it enforces *consistency/abort*, not *authentication of who sent the frame*. It converts a forgery
into an abort rather than rejecting the forgery at authentication time. So the F018 control (authenticate sender)
genuinely IS bypassed; the downstream layer only limits the blast radius to liveness. The authentication-bypass
claim stands; the catastrophic-impact claim is correctly downgraded by this layer.

### H4 PR HEAD currency — STANDS
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pinned commit. No drift. Stands.

### H5 Spec carve-out — PARTIALLY INVALIDATED (documented-as-transitional, but stale & not fail-closed)
The author's doc comment (`actor.rs:2447-2455`) explicitly frames the `None` branch as intentional "pre-rollout
permissive mode … until every active validator has registered a `libp2p_peer_id`." So there IS a doc carve-out:
the behavior is documented as deliberate. HOWEVER (a) it is evaluated per-sender per-frame, so it never converges —
any party that simply never supplies a peer-id stays permissive forever, which the comment does not acknowledge;
(b) the codec doc (`dkls_wire_codec.rs:276-283`) is now STALE — it says the registry "is not yet wired" even though
actor.rs:2462 wires it, which weakens any "this is a known, tracked gap" defense. Net: this reframes the finding
slightly toward "documented-as-transitional but the doc is wrong about convergence and a sibling doc is stale,"
rather than "silent undocumented hole." The security gap itself is unchanged. The author intent reduces the
"hidden footgun" framing but the medium rating survives.

### H6 Reachability of harm — STANDS
Can the spoof actually land? Requires: (i) a committee party Q with empty peer-id — confirmed permissible and a
supported registration shape (H-fixtures, no validation); (ii) an in-flight ceremony so `active_dkls` /
`active_dkls_sign` matches `target_epoch` (actor.rs:1380-1384 / 1528-1532) — a normal operating condition during
DKG/sign rounds; (iii) attacker controls one Strict-signed mesh peer publishing a DISCRIMINATOR_PLAINTEXT frame
with `sender()==Q`. No AEAD/transport key needed for the plaintext branch (codec:294-298), no committee membership
needed (H1). All preconditions are attainable. Reachable. Stands.

### H7 Test wiring — STANDS
Is the buggy function actually called in production? `check_dkls_sender_against_propagation_source` is invoked on
the live inbound DKLS DKG (actor.rs:1373) and sign (actor.rs:1521) paths, which are driven by real gossip ingress
(gossip.rs:1099-1135 → wire_to_event_with_source → HyperActorEvent::InboundDkls). Not test-only. Stands.

### H8 PoC mechanics — NEEDS_MORE_DATA
No executable PoC is attached to the finding; the claim rests on static reasoning. The static chain is sound and
each link is line-confirmed above. A live PoC would need to demonstrate that a spoofed broadcast attributed to Q is
actually fed to `submit` (vs silently dropped as NotForUs or rejected by the driver). The DKG broadcast path opens
to `OpenedDklsMessage::Broadcast` (codec:294-298) which the actor matches and submits (actor.rs:1367,1385), so the
ingest is plausible, but the precise driver acceptance of an out-of-context round-1 message was not executed. This
does not undercut the authentication-bypass claim (the bypass is at the binding check, upstream of the driver) but
leaves the downstream abort-vs-other behavior unproven by PoC. Hence the impact ceiling stays as written (medium).

## Overall verdict

WATERPROOF on the core claim (the F018 sender-binding control is bypassed for any active committee party with an
empty registered `libp2p_peer_id`, and nothing forces a committee member to register one). Confirmed by line.
HAS_CAVEATS on impact framing: (a) impact is liveness/griefing-bounded by the DKLS `sign_id`/abort behavior — the
finding already says this; (b) the `None` branch is documented as intentional transitional behavior (actor.rs:2447),
so the public framing should be "documented-as-transitional but non-converging + stale sibling doc," not "silent
hole"; (c) no executable PoC for the downstream driver acceptance.

Verdict: HAS_CAVEATS. Confidence: 0.82.

## Open follow-ups (NOT new findings — for specialist/lead triage)
- The codec doc-comment `dkls_wire_codec.rs:276-283` claims the peer-id registry "is not yet wired" but it IS wired
  at `actor.rs:2462`. Stale doc; worth a doc-correction note, not a security finding on its own.
- `transport_pubkey` is enforced 32-byte at registration but `libp2p_peer_id` has no non-empty check
  (`validator_registry.rs:386-392`) — the asymmetry is the registration-invariant root cause and matches the
  finding's suggested direction.

---

## F022 — FullProposal and DecidedValue gossip ingress paths lack F019 per-variant size caps; full-block payloads bounded only by the 10 MB transport ceiling (memory-amplification DoS)

## Summary

The F019 hardening added per-variant application-level size caps in
`map_gossip_bytes_to_system_message` (`src/network/gossip.rs`) so that
each inbound gossip topic is bounded *below* the 10 MB transport ceiling
(`MAX_GOSSIP_MESSAGE_SIZE`). The stated goal (lines 46-51) is that
"anything larger is a Sybil-flood / amplification vector and is dropped
at ingress."

That coverage is incomplete. Two decode arms carrying full blocks have
**no per-variant cap at all** and are bounded only by the 10 MB transport
limit:

1. `GossipMessage::FullProposal` (consensus topic) — lines 1019-1039.
2. `GossipMessage::ReadNodeMessage` / `DecidedValue`
   (decided-values + read-node-peers topics) — lines 1007-1017.

Both are subscribed by honest nodes (consensus topic: lines 395-401;
decided-values via `SubscribeToDecidedValuesTopic`, read-node-peers:
lines 379-385) and both carry an entire `Block` / `HyperBlock`. Every
other application variant — ContactInfo, Consensus, Status, HyperWire,
Mempool — has an explicit `encoded_len()` cap.

## The evidence-topic question (hunt prompt focus)

The hunt asked specifically whether the **evidence** frame (two full
blocks, `hyper/evidence/v1`) lacks a cap. It does **not**: all four hyper
topics (`blocks`, `messages`, `dkg`, `evidence`) are carried by the outer
`GossipMessage::HyperWire` variant, which IS capped at
`MAX_HYPER_WIRE_BYTES = 512 KB` at line 1100 *before* the inner
`wire_to_event_with_source` decode. `wire.encoded_len()` measures the
full `HyperWireMessage`, including the nested `HyperWireEvidence` with
both `block_a` and `block_b`, so the evidence frame is bounded to 512 KB
total. The evidence path is therefore covered.

(Separately worth noting: a single full hyper block can hold up to
`MAX_MESSAGES_PER_BLOCK = 50_000` messages — see
`src/hyper/builder.rs:67` — so a legitimate two-block evidence frame can
plausibly exceed 512 KB, meaning the shared HyperWire cap may *under*-size
real evidence and silently drop it. That is a functional/availability
concern for the slashing path, not the DoS gap, but it shows the comment
on line 52 — "512 KB ... evidence frames" — does not reflect the true
natural max of an evidence frame.)

## Why the uncapped paths matter (memory amplification)

`proto::GossipMessage::decode(...)` (line 989) eagerly allocates the
entire decoded message tree before any arm-specific check runs. For the
two uncapped arms an attacker (or a Sybil swarm) can gossip frames up to
the full 10 MB transport ceiling, each forcing the recipient to:

- allocate the full decoded `FullProposal` / `DecidedValue` (incl. the
  whole `Block`/`HyperBlock`), then
- for `FullProposal`, immediately re-encode it
  (`full_proposal.encode_to_vec()`, line 1026) into a second `Bytes`
  buffer that is forwarded onward as a `SystemMessage`, and
- for `DecidedValue`, hand the full decoded value downstream as
  `SystemMessage::DecidedValueForReadNode`.

So each oversized frame costs >= 2x its wire size in transient heap on
every subscribed node, with no early-drop. The whole point of F019 was to
clamp this below 10 MB; these two arms were missed. The consensus topic
is the higher-value target because every validator subscribes to it and
the `FullProposal` arm both allocates and re-encodes.

`proto::GossipMessage` definition: `gossip.proto:12-24`.
`FullProposal { ... oneof { Block block; ShardChunk shard } }`:
`blocks.proto:73-81`. `DecidedValue` carries `Block` / `ShardChunk` /
`HyperBlock`: `gossip.proto` (DecidedValue is reached via
`ReadNodeMessage`).

## Affected code

`src/network/gossip.rs`:

- Lines 1007-1017 — `ReadNodeMessage` / `DecidedValue` arm: no
  `encoded_len()` cap before constructing
  `SystemMessage::DecidedValueForReadNode`.
- Lines 1019-1039 — `FullProposal` arm: no `encoded_len()` cap before
  `full_proposal.encode_to_vec()` and `SystemMessage` dispatch.

Contrast the capped arms: ContactInfo (994), Consensus (1041), Status
(1066), HyperWire (1100), Mempool (1146).

## Severity

Medium. Memory-amplification DoS on the consensus and decided-values
gossip topics. Bounded by the 10 MB transport ceiling (so not unbounded),
but the F019 intent — drop oversized frames at ingress before the heavy
decode/re-encode — is defeated for these two arms. Requires a peer with a
valid libp2p key in the mesh (transport is `Strict` + `Signed`), and
peer scoring (F017) provides eventual eviction, which caps sustained
abuse and is why this is medium rather than high.

## Suggested remediation

Add per-variant caps mirroring the other arms, e.g. a
`MAX_FULL_PROPOSAL_BYTES` / `MAX_DECIDED_VALUE_BYTES` (sized to the real
max block) checked via `full_proposal.encoded_len()` /
`decided_value.encoded_len()` at the top of each arm, returning `None`
with a warn! on overflow. Separately, re-evaluate `MAX_HYPER_WIRE_BYTES`
against the true worst-case two-block evidence frame so legitimate
evidence is not dropped.

### Validation

- Verdict: **WATERPROOF**, confidence 0.82
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F022 validation — per-variant size cap gap on FullProposal / DecidedValue gossip arms

Validator: validator (deliberate-disagreement). Commit `cab225f`.

## Code-level confirmation of the core claim

`src/network/gossip.rs`:

- `ReadNodeMessage` / `DecidedValue` arm — lines 1007-1017: constructs
  `SystemMessage::DecidedValueForReadNode(decided_value)` with NO
  `encoded_len()` check.
- `FullProposal` arm — lines 1019-1039: `full_proposal.encode_to_vec()`
  (line 1026) and dispatch with NO `encoded_len()` check.
- Every other application arm IS capped: ContactInfo (994 / 4 KB),
  Consensus (1041 / 64 KB), Status (1066 / 4 KB), HyperWire (1100 /
  512 KB), Mempool (1146 / 256 KB). Caps defined gossip.rs:52-56.
- F019 intent comment (gossip.rs:46-51) explicitly states the
  per-variant caps exist so "anything larger is a Sybil-flood /
  amplification vector and is dropped at ingress." The two arms above
  are genuinely missed.
- Transport ceiling `MAX_GOSSIP_MESSAGE_SIZE = 10 MB` (line 44), applied
  via `.max_transmit_size(...)` (line 316).

So the factual claim — these two arms are bounded only by the 10 MB
transport ceiling, unlike all other arms — is TRUE at file:line.

## 8-hypothesis walk

### H1 — Upstream auth / gate. PARTIALLY INVALIDATES (severity, not existence)
ValidationMode::Strict + MessageAuthenticity::Signed (lines 314, 324):
every gossipsub frame must carry a valid libp2p signature from a mesh
peer, and the 10 MB transport cap is enforced by libp2p BEFORE the
handler runs. So the attacker is not anonymous — they need a peer with a
valid key already in the mesh (the finding acknowledges this, line 105).
This is a genuine upstream gate that bounds *who* can do this, but it
does not bound the per-frame amplification once a peer is in the mesh.
The arm-level gap stands; the precondition lowers it from a remote
unauthenticated DoS to a mesh-member DoS.

### H2 — Consumer-side impact. STANDS (with nuance)
FullProposal → `SystemMessage::MalachiteNetwork` on Channel::ProposalParts;
re-encoded via `encode_to_vec()` at line 1026 (a second full buffer)
before dispatch. DecidedValue → `SystemMessage::DecidedValueForReadNode`,
handed downstream whole. Both consumers exist and are live. The
re-encode for FullProposal is real and is the strongest part of the
amplification claim (raw `message.data.clone()` at line 774 + decoded
tree + re-encoded vec = ~3x wire size transiently). Claim of ">=2x" is
conservative and correct.

### H3 — Downstream enforcement. PARTIALLY INVALIDATES (impact ceiling)
The heavy cost the finding describes (decode + re-encode) happens at the
gossip handler BEFORE any downstream block-validation. Downstream
`validate_block_size` (builder.rs:238/275, MAX_MESSAGES_PER_BLOCK) would
reject an over-large block, but only AFTER the allocate+re-encode has
already occurred. So downstream enforcement does NOT prevent the
transient memory cost — the finding's harm is pre-validation, so this
does not invalidate. It does confirm the harm is transient
(per-frame heap, freed after the message is dropped), not a persistent
leak — consistent with Medium, not High.

### H4 — PR HEAD currency. NEEDS_MORE_DATA (no impact on verdict)
Workspace pinned at `cab225f`; this is a read-only revalidation against
that commit. No fetch performed (no network mandate for revalidation).
The cited lines match the pinned tree exactly. If upstream later added
caps to these arms the finding would be fixed-forward, but at the pinned
commit it stands.

### H5 — Spec carve-out. STANDS
The F019 comment (lines 46-51) is the relevant doc, and it states the
OPPOSITE of a carve-out: it claims oversized frames are "dropped at
ingress." There is no comment marking FullProposal/DecidedValue as
intentionally exempt. The gap is an omission, not a documented deferral.

### H6 — Reachability of harm. STANDS (bounded)
A mesh peer can publish FullProposal frames on the consensus topic
(published there, line 848; validators subscribe, lines 395-401) and
DecidedValue on decided-values (line 849; read nodes subscribe, lines
378-385) up to ~10 MB each. Gossipsub duplicate-suppression
(content-addressed message IDs) means re-sending the IDENTICAL frame is
de-duped, but a malicious peer can trivially vary the payload (round,
proposer bytes, padding) to defeat dedup and force a fresh
decode+re-encode each time. So sustained amplification is reachable.
Harm is real but capped per-frame at 10 MB and per-peer by mesh
membership.

### H7 — Test wiring. STANDS
`map_gossip_bytes_to_system_message` is the production handler, called
from the live `gossipsub::Event::Message` arm (line 780). Not
test-only. The FullProposal/DecidedValue arms are production decode
paths.

### H8 — PoC mechanics. NEEDS_MORE_DATA
No PoC is included in the finding. The claim rests on static code
reading, which I confirmed at file:line. Absence of a PoC is acceptable
for a Medium memory-amplification finding but means the *magnitude* of
real-world amplification (GC pressure, OOM threshold) is asserted, not
measured. This caps confidence rather than invalidating.

## Severity judgement: Medium vs lower

Arguments to DOWNGRADE toward Low:
- 10 MB transport ceiling already bounds each frame; the gap is the
  delta between "10 MB allocate+re-encode" and "drop at a tighter cap,"
  not unbounded memory.
- Requires a valid signed mesh peer (Strict + Signed) — not a remote
  anonymous attacker.
- Peer scoring (F017, lines 328-343) provides eventual eviction of
  invalid-message-rate abusers, capping sustained abuse.
- Harm is transient per-frame heap, freed after drop — no persistent
  corruption or fund loss.

Arguments to HOLD at Medium:
- The consensus topic is subscribed by EVERY validator; a single
  malicious mesh peer amplifies onto all of them simultaneously, and
  gossipsub forwards the frame across the mesh before local drop.
- FullProposal re-encodes (line 1026), giving genuine >=2x (≈3x with the
  raw clone) amplification per frame — the highest-value target.
- The F019 hardening's stated purpose is precisely to prevent this; the
  gap defeats the control's intent on its two heaviest payloads
  (full blocks up to 50k messages each).
- Peer scoring is reactive/eventual, not preventive — a peer can burst
  many oversized frames before greylisting.

Net: Medium is defensible and not overstated. It is bounded (10 MB +
auth gate + eventual eviction), which correctly keeps it out of High.
The finding itself already articulates these bounds (lines 99-107),
so the impact is NOT overstated.

## Overall verdict
WATERPROOF (with the caveat that severity rests on the gap-vs-intent
argument and the per-frame transient cost, both confirmed; no PoC).
Confidence 0.82. The factual claim is exact at file:line; the only soft
spots are the un-quantified amplification magnitude (no PoC) and the
mitigating auth/peer-scoring gates, both of which the finding already
acknowledges and which justify Medium rather than High.

## Open follow-ups (NOT new findings)
- The finding's side-note (lines 50-57): MAX_HYPER_WIRE_BYTES = 512 KB
  may UNDER-size a legitimate two-block evidence frame (each block up to
  MAX_MESSAGES_PER_BLOCK = 50_000 msgs, builder.rs:67), silently dropping
  real slashing evidence. Confirmed the constant (512 KB) and the
  per-block message ceiling. This is an availability/functional concern
  on the slashing path distinct from the DoS gap; flagging for the
  specialist to consider as a separate finding if in scope. I did not
  create a finding per role constraints.

---

## F024 — Pre-StartDkls buffered DKG drain feeds round messages to the ceremony state machine without the F018 sender/peer-id check, enabling broadcast-sender spoofing

## Summary

DKLS23 DKG broadcast round messages carry a claimed `sender: u8` party
index that the protocol state machine uses as a map key
(`proof_commitments[sender]`, `bip_broadcasts_2to4[sender]`,
`bip_broadcasts_3to4[sender]`). The codec itself does NOT authenticate this
field (it is documented as an "untrusted hint" in
`dkls_wire_codec.rs:256-283`). Authentication lives one layer up, in the
actor: `HyperActor::check_dkls_sender_against_propagation_source`
(`actor.rs:2462`) binds the claimed inner `sender` to the libp2p gossipsub
originator (`message.source`, cryptographically authenticated because
gossipsub runs `ValidationMode::Strict` + `MessageAuthenticity::Signed`,
`network/gossip.rs:314,324`).

That guard is applied on the **live** DKG ingress path (`actor.rs:1373`)
and on the sign path (`actor.rs:1521`). It is **NOT** applied on the
**buffered pre-StartDkls drain path**. The F023(a) buffer
(`pending_dkls_inbound`) exists specifically because peers' round-1
messages routinely arrive before this node's supervisor dispatches
`StartDkls` — i.e. the buffered path is on the normal happy path, not an
edge case. When the buffer is drained (`actor.rs:1430-1462`), each frame is
re-opened and handed straight to `driver.submit(m)` with no sender check.
The originator is not even available to check against, because the buffer
stores only `encoded` (`actor.rs:1337`) and discards the
`propagation_source` captured on the `InboundDkls` event.

Net effect: any gossip peer can inject plaintext broadcast variants
(`Phase2ProofCommitment`, `Phase2BipBroadcast`, `Phase3BipBroadcast`)
claiming `sender = <victim committee party>` into a target node's DKG
accumulator, as long as the frame arrives before that node starts its
ceremony (attacker-influenceable ordering).

## Mechanism

1. Gossip ingress for `InboundDkls { target_epoch, encoded, propagation_source }`.
   If no ceremony for `target_epoch` is active yet, the frame is buffered:
   only `encoded` is pushed (`actor.rs:1334-1345`); `propagation_source`
   is dropped.
2. On `StartDkls`, the buffer is drained (`actor.rs:1430-1462`):
   `open_dkls_round_message` decodes the plaintext broadcast and the actor
   calls `driver.submit(m)` directly. There is no
   `check_dkls_sender_against_propagation_source` call here, unlike the
   live path at `actor.rs:1373` and the sign path at `actor.rs:1521`.
3. `DklsCeremonyCoordinator::submit` (`dkls_ceremony.rs:333`) inserts
   broadcast payloads keyed by the attacker-chosen `sender`:
   `proof_commitments.insert(sender, ...)` (line 349),
   `bip_broadcasts_2to4.insert(sender, ...)` (line 355),
   `bip_broadcasts_3to4.insert(sender, ...)` (line 384). Broadcast variants
   have NO inner-vs-outer cross-check (the F114 guard at lines 365-412
   only covers the P2P `Phase*ZeroShareSend` / `Phase3MulSend` variants
   that carry an inner `parties.{sender,receiver}`; broadcasts have no such
   inner field to cross-check).
4. `try_advance_phase23_to_complete` (`dkls_ceremony.rs:526`) collects
   `proof_commitments.values()` and the bip-broadcast maps and feeds them
   to `phase4::<Secp256k1>(...)` (line 558). A forged/garbage commitment in
   the victim's slot makes phase4 return
   `DklsError::Abort { party: abort.index, reason }` (lines 570-573),
   where the blame index is the party whose commitment failed verification
   — i.e. the spoofed `sender` (an innocent committee member).

## Impact

- **DKG abort (liveness):** one forged broadcast in the victim's slot,
  delivered before the victim's genuine commitment, corrupts the
  accumulator and forces a phase4 abort. DKG cannot resume in-place
  (`try_advance` short-circuits once `error`/`output` is set,
  `dkls_ceremony.rs:421`), stalling per-epoch threshold-key generation.
- **Blame mis-assignment:** the abort names the spoofed `sender`, not the
  attacker. If abort blame drives any exclusion / scoring / slashing
  downstream, an honest validator is penalised for an attacker's frame.
- **Last-write-wins races:** `insert` means whoever lands last in a given
  slot wins. The attacker can race the victim's genuine commitment;
  ordering through the buffer/drain is attacker-influenceable.

This is integrity/liveness, not silent key corruption — phase4's
verification catches the garbage and aborts rather than producing a
poisoned group key. Rated **high**: it is a remotely-triggerable,
race-only DKG denial-of-service against per-epoch threshold key generation
plus false-blame against honest committee members, on a code path that is
hit during normal operation (the buffer is the F023(a) happy path).

## Why the live path is not affected

On the live path the originator is the gossipsub `message.source`
(`network/gossip.rs:1110-1122`), authenticated by Strict-mode signed
gossipsub, and `check_dkls_sender_against_propagation_source` compares the
claimed `sender` to `runtime.peer_id_for_party(epoch, sender)`
(`runtime.rs:1242`). A spoofing peer is dropped at `actor.rs:1378`. The
buffered path bypasses exactly this guard.

## Secondary observation (permissive fallthrough)

Even on the live path, `check_dkls_sender_against_propagation_source`
returns `true` (accept) when `peer_id_for_party` returns `None` — i.e. when
the committee member has not yet published a ContactInfo / has no entry in
`compute_active_peer_ids(epoch)` (`actor.rs:2472-2479`). During registry
warm-up this re-opens the same spoofing window on the live path. The
codec's own doc-comment (`dkls_wire_codec.rs:276-283`) still describes the
registry as "not yet wired" and the residual risk as "liveness-only" — the
narrative is stale (the registry IS wired now) but the buffered-path gap
and the permissive fallthrough mean the residual risk it describes is real
and broader than liveness-only (blame mis-assignment).

## Suggested remediation

- Buffer the authenticated originator alongside `encoded` in
  `pending_dkls_inbound` (store `(encoded, propagation_source)`), and run
  `check_dkls_sender_against_propagation_source` in the drain loop before
  `driver.submit(m)` — mirroring `actor.rs:1373`.
- Consider making the registry-unknown fallthrough fail-closed for
  committee members of an active/forming ceremony (drop rather than
  accept), at least once the epoch's committee peer-id set is expected to
  be populated.
- Defence-in-depth: have `DklsCeremonyCoordinator::submit` reject a second
  broadcast that would overwrite an already-populated `sender` slot, so
  late spoof frames cannot clobber a genuine commitment.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.84
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F024 validation — buffered pre-StartDkls DKG drain skips the F018 sender/peer-id check

Validator: validator (deliberate-disagreement). Commit pinned `cab225f`.
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` (no drift, clean tree).

Finding under test: the F023(a) buffer drain on `StartDkls` (`actor.rs:1430-1462`) hands each
buffered round message straight to `driver.submit(m)` WITHOUT
`check_dkls_sender_against_propagation_source`, unlike the live DKG path (`actor.rs:1373`) and
the sign path (`actor.rs:1521`). Net: broadcast-sender spoofing into a target node's DKG
accumulator if the frame arrives before the node starts its ceremony.

## Code claims re-verified (file:line)

- Buffer fill stores ONLY `encoded`, discards `propagation_source`: `actor.rs:1334-1345` (push at 1337).
  CONFIRMED verbatim. The captured `propagation_source` on the `InboundDkls` event is dropped.
- Live DKG path DOES call the F018 check before submit: `actor.rs:1373-1379`. CONFIRMED.
- Drain loop calls `driver.submit(m)` with NO sender check: `actor.rs:1430-1462` (submit at 1444).
  CONFIRMED — no `check_dkls_sender_against_propagation_source` anywhere in the drain block;
  the originator is not even in scope (only `encoded` was buffered).
- `check_dkls_sender_against_propagation_source` body: `actor.rs:2462-2493`. CONFIRMED. It is the
  ONLY application-level sender-binding control.
- `driver.submit` is a thin pass-through to `coordinator.submit` with no auth: `dkls_driver.rs:59-61`.
  CONFIRMED — no second sender check downstream of the actor.
- Coordinator `submit`: broadcast variants insert by attacker-chosen `sender` with NO inner-vs-outer
  cross-check: `dkls_ceremony.rs:345-356` (`proof_commitments.insert(sender,...)` 349,
  `bip_broadcasts_2to4.insert` 355), `383-384` (`bip_broadcasts_3to4.insert` 384). The F114 guard
  (`zero_init.parties.sender != sender` etc.) covers ONLY `Phase*ZeroShareSend`/`Phase3MulSend`
  (lines 375, 395, 409) — broadcasts have no inner `parties` field to cross-check. CONFIRMED.
- `Phase2ProofCommitment` insert has no state guard — always inserted regardless of `state`,
  persists last-write-wins until phase4 reads it: `dkls_ceremony.rs:345-350`. CONFIRMED.
- phase4 abort names `abort.index` (the party whose data failed) as blame: `dkls_ceremony.rs:558-573`.
  CONFIRMED — a forged commitment in the victim's slot makes phase4 blame the spoofed `sender`.
- `try_advance` short-circuits once `error`/`output` set (no in-place resume): `dkls_ceremony.rs:421`.
  CONFIRMED.
- Gossip ingress: only a size cap, no committee-membership filter; produces `InboundDkls` with
  `propagation_source = Some(originator)`: `gossip.rs:1099-1135` (originator at 1119,
  `wire_to_event_with_source` at 1120). `gossip_adapter.rs:65-92` threads it into `InboundDkls`.
  CONFIRMED.
- Plaintext broadcast decode, no AEAD/transport key: `dkls_wire_codec.rs:294-298`. CONFIRMED.
- Gossipsub Strict + Signed: `gossip.rs:314,324` (per F021 note, re-confirmed by reference). The
  originator is cryptographically authenticated, but the buffered path never compares against it.

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a committee-membership / sender gate UPSTREAM of the drain that the specialist missed?
NO. Gossip ingress (`gossip.rs:1099-1135`) applies only a size cap and forwards any Strict-signed
frame. Buffer fill (`actor.rs:1334-1345`) applies no auth at all — it just pushes `encoded`. The
ONLY application sender-binding control is `check_dkls_sender_against_propagation_source`, and the
drain path provably never calls it (it can't — it threw away the source at 1337). The bug is the
absence of the gate, not a gate hidden upstream. Stands.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (impact bounded to liveness/blame, not key compromise)
What consumes the spoofed `submit`? `coordinator.submit` → broadcast map insert → `phase4` at
`try_advance_phase23_to_complete` (`dkls_ceremony.rs:558`). phase4 verifies the proof/bip broadcasts;
a forged/garbage commitment in the victim's slot returns `DklsError::Abort { party: abort.index }`
(570-573), NOT a poisoned group key. So this is liveness (ceremony abort/stall) + blame
mis-assignment (the abort names the spoofed honest party), exactly as the finding states. It is NOT
silent threshold-key corruption. The finding already rates this "integrity/liveness, not silent key
corruption" and severity high on the DoS+false-blame basis — consistent with the same `sign_id`/abort
ceiling F021's validator found. So this PARTIALLY bounds impact but does NOT overstate it: the
finding's own impact section is already correctly ceiling'd. The "if blame drives slashing" escalation
is conditional (NEEDS_MORE_DATA below). Partial only against any reader who infers key compromise.

### H3 Downstream enforcement — STANDS (bounds severity, does not catch the spoof)
Does a layer below the actor re-verify the sender? `driver.submit` (`dkls_driver.rs:59-61`) is a pure
pass-through; `coordinator.submit` only cross-checks inner-vs-outer for P2P variants (F114), and
broadcasts have no such field. So no layer re-authenticates the broadcast sender. phase4's
verification is downstream enforcement of *cryptographic consistency* — it converts the forgery into
an abort rather than rejecting it at auth time. The authentication-bypass claim genuinely stands;
phase4 only bounds blast radius to liveness/blame (see H2). Stands.

### H4 PR HEAD currency — STANDS
HEAD == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, matches pin. Clean tree. No drift. Stands.

### H5 Spec carve-out — PARTIALLY INVALIDATED (a doc carve-out exists but is stale/narrower than the bug)
`dkls_wire_codec.rs:276-283` says the peer-id registry "is not yet wired" and frames residual risk as
"liveness-only." Two problems: (a) the doc is STALE — the registry IS wired now at `actor.rs:2462`
and consulted on the live path, so "not yet wired" no longer holds; (b) the carve-out covers the
*plaintext broadcast on the live path* class, but the F024 gap is specifically that the DRAIN path
omits the now-wired check entirely, and the consequence includes blame mis-assignment (an innocent
party named in the abort), which is broader than the "liveness-only" the doc claims. So there is a
documented-as-transitional flavor, but the doc neither anticipates the drain-path omission nor the
blame vector. Reframes public narrative slightly ("the wired check is bypassed on one path + the
sibling doc is stale") rather than "silent undocumented hole." Core gap unchanged. Partial.

### H6 Reachability of harm — STANDS
Can the spoof land via untrusted gossip? Requires: (i) a frame for `target_epoch` arriving while
`active_dkls` is not yet that epoch → buffered (`actor.rs:1334`) — this is the F023(a) happy path
(round-1 messages routinely precede local `StartDkls`, per the fix's own comment 1424-1429); (ii)
attacker controls one Strict-signed mesh peer publishing a `DISCRIMINATOR_PLAINTEXT` broadcast with
`sender()==Q` (`dkls_wire_codec.rs:294-298`) — no AEAD, no committee membership, no peer-id needed;
(iii) `StartDkls` later drains the buffer and submits unchecked (1444). All preconditions are normal
operating conditions / attacker-attainable. Ordering through the buffer is attacker-influenceable
(attacker can send early). Reachable. Stands.

### H7 Test wiring — STANDS
Is the drain path live in production? `StartDkls` is the production ceremony-start handler; the drain
block (1430-1467) runs on every `StartDkls` that finds a non-empty `pending_dkls_inbound` for the
epoch, and that map is filled from real gossip ingress (`gossip.rs:1099-1135` →
`wire_to_event_with_source` → `InboundDkls` → buffer fill 1334-1345). Not test-only. Stands.

### H8 PoC mechanics — NEEDS_MORE_DATA
No executable PoC attached; the claim rests on static reasoning. Each link is line-confirmed above.
A live PoC would need to show that a buffered+drained broadcast attributed to Q (a) reaches `submit`
(it does: `OpenedDklsMessage::Broadcast(m) => driver.submit(m)` at 1442-1444) and (b) actually lands
in `proof_commitments[Q]` and survives to phase4 to produce the blamed abort. The static path is
sound: broadcast insert has no state/dedup guard (349) and `try_advance` reads the map at 549. The
last-write-wins race (attacker frame vs Q's genuine commitment) is plausible but the precise ordering
window is not executed. This does not undercut the authentication-bypass core (the bypass is the
missing check at the actor, upstream of any driver behavior) but leaves the abort-vs-other downstream
outcome unproven by PoC. Impact ceiling stays as written (high, liveness+blame). NEEDS_MORE_DATA.

## Distinctness from F016 / F021 (root-cause separation — requested)

- F016 (mailbox-ordering-assumption, WATERPROOF): unbounded growth of `pending_dkls_inbound` keyed by
  attacker `target_epoch` with no global cap / no stale-epoch eviction → memory-exhaustion DoS. Root
  cause = buffer *sizing/keying*. DISTINCT.
- F021 (sender-spoofing-inside-payload, HAS_CAVEATS): on the LIVE path the F018 check fails OPEN when
  `peer_id_for_party` returns `None` (committee party with empty registered peer-id). Root cause =
  *fail-open inside the check*. DISTINCT.
- F024 (this): on the DRAIN path the F018 check is NEVER CALLED, because the buffer discarded
  `propagation_source` (1337). Root cause = *check omitted on one path*. This works even for parties
  WITH a registered peer-id (F021 needs the empty-peer-id case; F024 does not). DISTINCT root cause.
  All three are facets of the same F023(a) buffer but with non-overlapping fixes — F024's fix (buffer
  the source + run the check on drain) does not fix F016 or F021 and vice versa.

## Overall verdict

WATERPROOF on the core claim: the buffered pre-StartDkls drain (`actor.rs:1430-1462`) submits round
messages to the ceremony state machine without `check_dkls_sender_against_propagation_source`, while
the live path (1373) and sign path (1521) apply it; the buffer (1337) discards the authenticated
`propagation_source`, so the check is structurally impossible on this path. Broadcast variants
(`Phase2ProofCommitment`/`Phase2BipBroadcast`/`Phase3BipBroadcast`) then insert by attacker-chosen
`sender` with no inner cross-check (`dkls_ceremony.rs:349,355,384`), and phase4 blames the spoofed
party on abort (570-573). Every link line-confirmed.

HAS_CAVEATS on framing/impact: (a) impact is liveness (DKG abort/stall) + blame mis-assignment,
bounded by phase4's verification — NOT silent key compromise (H2/H3); (b) the "blame drives slashing"
escalation is conditional and not traced to a slashing consumer here (NEEDS_MORE_DATA); (c) the
"liveness-only" codec doc is stale and narrower than the actual gap, so public framing should note
the blame vector explicitly; (d) no executable PoC for the last-write-wins ordering window (H8).

Verdict: HAS_CAVEATS. Confidence: 0.84.

## Open follow-ups (NOT new findings — for specialist/lead triage)
- Whether abort blame (`DklsError::Abort { party }`) is consumed by any
  exclusion/scoring/slashing path is the key escalation question and was not exhaustively traced
  here; if it is, F024's blame-mis-assignment rises above pure liveness. Worth a downstream trace.
- The "defence-in-depth: reject overwriting an already-populated `sender` slot" suggestion in the
  finding would also mitigate the F021 live-path spoof — shared mitigation surface across F021/F024.

---

## F025 — Committee membership is grindable via attacker-chosen validator_key because party indices are assigned by lexicographic key order against a fully predictable per-epoch committee seed

## Summary

The DKLS23 signing committee for any future epoch is selectable in advance
by an attacker who grinds the bytes of their `validator_key` (a 32-byte
Ed25519 public key freely chosen at registration). The F036 fix made the
committee *seed* non-grindable, but committee selection runs over **party
indices** `1..=share_count`, and the index→validator mapping is simply the
lexicographic (BTreeMap) sort order of the active validator keys. Because
the per-epoch committee seed is deterministic and known far in advance, an
attacker can pre-compute which indices win for a target epoch, then grind
an Ed25519 keypair whose public key sorts into a winning index slot —
biasing committee membership toward their own (sybil) validators.

## Root cause: two independently-deterministic layers compose into a grind

Committee selection (`dkls_committee.rs:53` `select_signing_committee`)
ranks **indices**, not keys:

```rust
rank(i) = keccak256("hypersnap-dkls-committee-v1\0" || epoch || digest || i)
```

The `threshold` indices with lowest rank win. The inputs are `epoch` and
the seed `digest` only — there is no dependence on validator identity. The
seed itself is built to be non-grindable (F036):

- `committee_seed_for_epoch(epoch, message_tag)` (`dkls_committee.rs:110`)
  depends only on `epoch` and a static per-ceremony tag.
- `committee_seed_for_block(epoch, height, parent_hash)`
  (`dkls_committee.rs:119`) depends only on consensus-pinned values.

Consequence: the *set of winning indices* for a target epoch/ceremony is a
pure function of public, predictable values. An attacker knows months ahead
(epoch length is 432,000 anchor blocks, `epoch.rs:14`) exactly which
`party_index` values will be on the committee.

The second layer — the index→validator assignment — lives in the
supervisor (`dkls_supervisor.rs:194-200`):

```rust
let mut own_idx: Option<u8> = None;
for (i, vk) in active.keys().enumerate() {
    if vk == &inputs.local_validator_key {
        own_idx = Some((i + 1) as u8);
        break;
    }
}
```

`active` is a `BTreeMap<Vec<u8>, _>` keyed on `validator_key`, so
`party_index = 1-based position of the key in lexicographic order`. There
is no epoch-randomized shuffle, no VRF, no commit-reveal — the position is
a direct function of the raw key bytes the attacker chose at registration.

## Why this is grindable

`validator_key` is a 32-byte Ed25519 public key (`validator_registry.rs:375`
enforces only the 32-byte length). The registrant generates the keypair
off-chain and is free to grind candidate keypairs cheaply (one Ed25519
keygen per attempt). Nothing binds the key bytes to anything unpredictable:

- The Ed25519 signature (`verify_event_signature`) only proves the
  registrant holds the private key — any ground key still verifies.
- The EIP-712 custody cross-sign (`verify_custody_signature`) commits to
  whatever `validator_key` the attacker supplies; the attacker controls the
  custody key for their own sybil FIDs and re-signs each candidate.
- The trust-floor gate (`validate_register_with_trust`) gates on the FID's
  *trust score*, not on key bytes.
- The per-FID cap is `MAX_VALIDATORS_PER_FID = 3`
  (`validator_registry.rs:24`), but a sybil attacker controls many FIDs, so
  the cap does not constrain the attack.

### Attack procedure

1. Target a future epoch `E` (and a ceremony tag, e.g. `b"reward-issuance"`,
   or the block path's `(E, height, parent_hash)` once the parent is known).
2. Compute the winning index set
   `W = select_signing_committee(E, committee_seed_for_epoch(E, tag),
   share_count, threshold)`. `share_count` for epoch `E` is the size of the
   active set, which is itself derivable from the public registry one epoch
   ahead (`EPOCH_BUFFER = 1`).
3. For each sybil validator, grind Ed25519 keypairs until the key sorts into
   a lexicographic position that lands on a winning index `w ∈ W`. Because
   the position is `rank within the full sorted key list`, the attacker
   targets a byte-prefix bucket; with knowledge of the other (already
   registered) keys this is a direct sort-position computation, not even a
   brute force in many cases.
4. Register the ground keys before epoch `E − EPOCH_BUFFER − 1` so they are
   in the active set at `E`.

The result: the attacker disproportionately (or, with enough sybils,
entirely) populates the `threshold`-sized signing committee for epoch `E`.

## Impact

DKLS23 requires *exactly* `threshold` parties to sign. If an attacker lands
`threshold` of the committee slots, they unilaterally control the group
signature for that epoch's ceremonies: hyperblock production, reward
issuance, trust-snapshot, lock-merkle-root, inbound-burn, and DA-PoW seed
(all the `committee_seed_for_epoch` call sites in `actor.rs:3054-3357` plus
the block path at `actor.rs:2657`). Concretely:

- **Forge/withhold threshold signatures** for any of the above ceremonies in
  the captured epoch (e.g. sign an attacker-favorable lock-merkle-root or
  inbound-burn, or deny service by refusing to sign).
- **Targeted exclusion / DoS**: grind to *avoid* committee membership for
  honest-heavy epochs, or to exclude a specific honest validator from
  pivotal ceremonies, since the attacker can shift the whole index map by
  inserting ground keys at chosen sort positions.

Because the committee for an epoch is fixed and predictable, the attacker
can also pre-position across many future epochs in one registration wave.

This is exactly the committee-selection-grinding class: F036 closed the
proposer-grinds-the-seed door; this finding shows the
attacker-grinds-their-own-position-in-the-index-map door is still open.

## Severity: High

A sybil-capable adversary gains deterministic control over future signing
committees, defeating the threshold trust assumption of every DKLS23
ceremony. Requires registering `threshold`-many sybil validators (subject to
trust floor and per-FID caps), so it is not free, but the grind itself is
cheap and the payoff is full control of an epoch's threshold signer set.

## Suggested direction (non-binding)

Mix an unpredictable, per-epoch beacon into the index assignment so a
validator cannot pre-compute its `party_index` at registration time.
Options: derive the index ordering from
`keccak256(committee_seed(epoch) || validator_key)` (sort by that hash
instead of by raw key bytes) so the position depends on a value the
attacker cannot grind a key against without also fixing the epoch seed —
or, better, key the per-index `rank_for` on the validator_key directly
(rank validators, not abstract indices) under the non-grindable seed, so
the selection ranks identities rather than sort positions. Any fix must
keep the mapping deterministic and identical across all honest nodes for a
given epoch.

## Notes / residual uncertainty

- The block path additionally binds `parent_hash` into the seed, which is
  only known one block ahead; that narrows the pre-computation window for
  the block ceremony but the epoch-tag ceremonies
  (`reward-issuance`, `trust-snapshot`, `lock-merkle-root`,
  `inbound-burn`, `da-epoch-seed`) depend only on `epoch` and a static
  tag and are fully predictable arbitrarily far ahead.
- `select_signing_committee` is called with `epoch` as the first arg and
  the seed as `digest`; the seed already incorporates the epoch, so the
  selection is well-domain-separated — the grind is on the *index map*, not
  on the seed.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.78
- Hypotheses walked: 8
- Validated at: 2026-06-08 12:30:00+00:00

### Validator notes

# F025 validation — committee-index grinding via attacker-chosen validator_key

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f`. HEAD verified == workspace pin (read-only, no git repo to fetch; PR-HEAD currency assessed below).

Finding under test: F036 made the committee *seed* non-grindable, but `select_signing_committee` ranks abstract **party indices** `1..=share_count`, and the index→validator binding is the 1-based lexicographic (BTreeMap) sort position of the active validators' raw 32-byte Ed25519 `validator_key`s. Since the per-epoch seed is fully predictable far ahead, an attacker grinds key bytes so their sybil validators land on the winning index slot(s) for a target epoch.

## Code claims re-verified (file:line)

- Index-ranking selection (no identity input): `dkls_committee.rs:53-89`. `rank(i)=keccak256("hypersnap-dkls-committee-v1\0"||epoch||digest||i)`; inputs are epoch + seed only. CONFIRMED verbatim.
- Non-grindable epoch seed: `committee_seed_for_epoch(epoch, message_tag)` depends only on `epoch` + static tag (`dkls_committee.rs:110-117`). Block seed adds `(height,parent_hash)` (`:119-127`). CONFIRMED.
- Index→validator = lexicographic key order: `dkls_supervisor.rs:194-201` — `for (i, vk) in active.keys().enumerate() { if vk==local … own_idx=Some((i+1)) }`. `active` is `BTreeMap<Vec<u8>,_>` keyed on `validator_key` (`actor.rs:819`, `runtime.rs:3993`). CONFIRMED — party_index is a pure function of raw key bytes; no shuffle/VRF/commit-reveal.
- Winning index ⇒ that validator signs, bound into payload: block path `actor.rs:2657-2705` (`committee.contains(&local_party_index)` gate + `signing_payload(epoch,&committee_indices)` F153 bind). Same shape for all epoch-tag ceremonies: `actor.rs:3055-3087`, `:3216`, `:3284`, `:3357`. CONFIRMED — only the selected index's signature recomputes to the same digest, so committee membership IS the authorization.
- `validator_key` freely chosen, only 32-byte length enforced: `validator_registry.rs:375`. CONFIRMED.
- Registration binding does NOT constrain key bytes: ed25519 self-sig only proves possession (`verify_event_signature`, `validate_event` :403-405); EIP-712 custody sig commits to whatever key the attacker supplies (`:406-409`); trust floor gates the FID score not key bytes (`validate_register_with_trust` :466-489). CONFIRMED.
- Per-FID cap = 3 (`MAX_VALIDATORS_PER_FID`, `validator_registry.rs:24`), but sybil controls many FIDs. CONFIRMED — cap is per-FID, not global.
- Timing window: `EPOCH_LENGTH=432_000`, `EPOCH_BUFFER=1` (`epoch.rs:14,19`); active set at epoch N reflects events ≤ N−2 (`compute_active_set` cutoff `:686`). CONFIRMED — epoch-tag ceremonies predictable arbitrarily far ahead.

## CRITICAL CONTEXT discovered: production threshold is hardcoded to 1 (F028 overlap)

`main.rs:1603` — `let dkls_threshold = 1u8;` is the only production wiring of `DklsSupervisorInputs.threshold` (`main.rs:1647-1658`). So in production **every committee is size 1**: `select_signing_committee` returns exactly one winning index per ceremony. This materially reshapes the impact framing (see H2/overlap).

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a gate upstream that prevents an attacker from registering a key with attacker-chosen bytes, or that re-randomizes the index? No. Registration (`validate_register_with_trust`) enforces signature possession, custody cross-sign, trust floor and per-FID cap — none constrains the 32 key bytes. The index assignment in `build_driver` is a raw `BTreeMap` enumerate with no beacon mixed in. The finding's mechanism is not masked by any upstream control. STANDS.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (marginal value over F028 is conditional)
What does winning the index actually buy, *given the rest of the system*? Two regimes:
- **Production today (threshold=1):** the threshold-security assumption is already void — whichever single validator wins each ceremony has unilateral signing power (this is the separate F028 problem). F025's *marginal* contribution here is that grinding lets the attacker **deterministically be that winner** for a target epoch/ceremony, rather than holding a 1/N chance. That is a real, distinct capability (selection control), but the catastrophic "threshold broken" outcome is already delivered by t=1 regardless of grinding. So in the *current* config, F025 is best described as "deterministic-targeting amplifier on top of an already-broken t=1 committee," not an independent root cause of signature capture.
- **Intended t>1 config:** grinding lets a sybil land on *multiple* winning slots and assemble a full `threshold`-of-N quorum it controls — this is the strong, independent impact the finding claims. The finding's High rating is sound for this regime.
The finding's prose asserts the strong impact generally; it does not flag that the *shipped* threshold is 1, which makes part of the claimed novelty redundant with F028 today. Impact is real but **overstated for the current production config** and **understated-context** (doesn't note t=1). Hence PARTIALLY INVALIDATED on impact-framing, not on mechanism.

### H3 Downstream enforcement — STANDS
Does a layer below re-verify the signer's identity in a way that defeats grinding? No. The verifier recomputes the *same* deterministic committee from the same public seed and accepts the bound signature (`signing_payload(epoch,&committee_indices)`, F153). The whole point of determinism is that all nodes agree on which index signs — so an attacker who legitimately holds the winning index produces a fully valid signature. There is no separate stake-weight or identity re-check downstream that would reject a grinder-occupied index. STANDS.

### H4 PR HEAD currency — NEEDS_MORE_DATA (no drift detectable in workspace)
Workspace is a read-only snapshot at `cab225f` with no `.git`. I cannot `git fetch` to confirm the branch hasn't moved. The structural facts (BTreeMap key-order index, hardcoded t=1) are unlikely to have changed silently, but I flag this as the one hypothesis I cannot fully close. NEEDS_MORE_DATA.

### H5 Spec carve-out — STANDS (no carve-out found)
`dkls_committee.rs` module docs tout uniformity/determinism but say nothing about index assignment being randomized against the key — and explicitly note "output is sorted by index" and "correctness relies on every party seeing the same canonical ordering." No README/doc-comment says "index→key mapping is intentionally raw-sort / grindability deferred." The F036 fix comment (`:91-109`) addresses *seed* grindability only and does not acknowledge the index-map vector. No carve-out. STANDS.

### H6 Reachability of harm — STANDS (with cost caveat)
Can the grind be realized end-to-end? Yes: (a) seed is public/predictable (epoch-tag path, far ahead); (b) winning index set computable offline; (c) attacker computes the target sort position knowing other registered keys (or targets a byte-prefix bucket) and grinds Ed25519 keypairs cheaply (one keygen/attempt); (d) registers before `epoch−2`. The cost gates are real but surmountable for a sybil adversary: trust floor per FID + 3-cap per FID, so the attacker needs enough sufficiently-trusted FIDs. Reachable. STANDS (the attack is not free, which the finding already states).

### H7 Test wiring — STANDS
Is the code actually in production? Yes. `dkls_supervisor::run` is spawned in `main.rs:1647` for any node with operator identity; `build_driver` (the index-assignment site) runs each epoch; `select_signing_committee` is called on every real ceremony path (`actor.rs:2659,3055,3080,3216,3284,3357`) plus block production (`:2657`). Not test-only. STANDS.

### H8 PoC mechanics — NEEDS_MORE_DATA
The finding ships no executable PoC, only an attack procedure. The procedure is internally consistent and the load-bearing primitives are verified above, but there is no assertion artifact to scrutinize for "passes for the wrong reason." The one mechanical nuance worth stating: the attacker must grind a *sort position*, and inserting a new key shifts the positions of all keys that sort after it — so to land sybils on multiple specific indices simultaneously the attacker must solve the joint placement (register in sorted order, accounting for self-shifts). This is tractable (the attacker controls all sybil keys and knows the honest set) but is more involved than "grind each key independently." Does not invalidate; flagged for accuracy. NEEDS_MORE_DATA (no PoC to test).

## Overall verdict: HAS_CAVEATS (confidence 0.78)

The mechanism is real and verified at every step: committee selection ranks indices, the index→validator map is raw lexicographic key order, validator_key is attacker-chosen with no beacon/PoP binding the bytes, and the winning index is the authoritative signer. The grindability claim is correct.

Caveats that prevent WATERPROOF:
1. **F028 overlap / threshold=1 (H2).** Production ships `dkls_threshold = 1u8` (`main.rs:1603`). In the shipped config the threshold assumption is already broken by F028, so F025's incremental value today is "deterministic targeting of the single winner," not "first break of threshold security." The finding's High severity is fully justified only in the intended t>1 regime; for the current config it should be read as composing with / amplifying F028. The finding does not note the hardcoded t=1, which is a material framing gap.
2. **Joint sort-position placement (H8).** Landing multiple sybils on multiple specific winning indices requires solving the joint placement (self-shifts), slightly harder than the prose's per-key framing — tractable, not invalidating.
3. **PR-HEAD currency (H4) and absence of executable PoC (H8)** could not be closed from the workspace.

None of these invalidate the core finding; they bound and contextualize its severity. Recommend the originating specialist add a one-line note on the shipped `threshold=1` and the F028 relationship, and (for the joint-placement nuance) tighten the "direct sort-position computation, not even a brute force" wording.

## Open follow-ups (NOT new findings — for specialist triage)
- The hardcoded `dkls_threshold = 1u8` at `main.rs:1603` is the substance of F028; F025 and F028 should be cross-linked at dedupe (related, not duplicate — different root cause: F028 = no threshold security; F025 = grindable selection map). Validator cannot create findings; flagging for dedupe-curator.

---

## F028 — DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set size), so any single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations

## Summary

The DKLS23 reconstruction threshold used to run the per-epoch DKG is taken
verbatim from a single static config field (`DklsSupervisorInputs.threshold`)
and is **never validated against the active-validator-set size** and **never
floored to a BFT-safe value**. In the production node-bootstrap path that
field is hard-coded:

`code/hypersnap/src/main.rs:1603`
```rust
let dkls_threshold = 1u8;
```

`build_driver` (`dkls_supervisor.rs:175`) then derives `share_count` from the
*real* active set (`share_count = active.len()`) but plugs the static
`inputs.threshold` straight into the DKG parameters with no relationship check:

`code/hypersnap/src/hyper/dkls_supervisor.rs:203`
```rust
let parameters = Parameters {
    threshold: inputs.threshold,   // = 1, regardless of share_count
    share_count,                   // = active.len(), e.g. 5, 10, 32
};
```

The result is a `1-of-N` group key for any validator set of size N. Because
DKLS23 signs with *exactly* `threshold` parties, the signing committee for
every ceremony is a **single** validator, and that one validator's share
alone produces a valid `(r, s, v)` group signature recovering to the group
address. One validator therefore unilaterally controls every threshold-signed
authority in the system.

## Where the mismatch lives

The lower layers are individually "correct" but enforce no floor, so the
config value flows through unchecked:

- `dkls_threshold.rs:115` (`run_honest_dkg`) rejects only `threshold == 0 ||
  threshold > share_count`. `threshold = 1, share_count = N` passes.
- `dkls_committee.rs:59` (`select_signing_committee`) rejects only the same
  two cases; `threshold = 1` is explicitly supported and even pinned by the
  `pinned_vector_one_of_three` test (`dkls_committee.rs:240`), which asserts a
  committee of size 1 for a 3-party group.
- At sign time the threshold is read back from the installed share
  (`actor.rs:2645` `share.party.parameters.threshold`) and fed to
  `select_signing_committee` (`actor.rs:2659`). With `threshold = 1`,
  `select_signing_committee` returns exactly one index — the lowest-rank
  party — and only that party (the `committee.contains(&local_party_index)`
  gate at `actor.rs:2666`) runs the single-party DKLS sign and broadcasts the
  finished signature.

There is no code path anywhere between config and DKG that requires
`threshold ≥ 2`, `threshold > share_count / 2`, or `threshold ≥ 2f+1`. The
`threshold == share_count == 1` checks scattered through `runtime.rs`
(e.g. lines 1079-1081, 1428) and `actor.rs:1289` are *local-sign shortcut*
detectors (for single-validator devnets that skip the gossip ceremony); they
do not constrain the multi-party threshold and in fact normalize the idea
that a `1`-threshold group is a legitimate operating mode.

## Impact

The DKLS23 group signature is the sole authority over (per `00-OVERVIEW.md`):
hyperblock production, reward/emission issuance, trust snapshots, **bridge
merkle-root (lock-leaf) updates, bridge owner rotations, and pause/upgrade
authorizations**. A `1-of-N` group means:

- Any single validator that wins the deterministic committee draw for a given
  `(epoch, digest)` signs alone, with no cosigners and no quorum. Equivocation
  detection (which assumes a fixed committee per `(epoch, digest)`) does not
  help, because the lone signer is the legitimately-selected committee.
- Compromise or malice of *one* validator forges bridge lock-root updates and
  owner rotations, i.e. mints arbitrary wrapped `SNAP` on the EVM side and/or
  seizes the bridge owner — a fund-loss / total-bridge-takeover primitive,
  with no t-of-n safety whatsoever.
- The system's entire threshold-security premise is void in production; the
  group key is effectively held by whichever single validator the committee
  selector elects each epoch.

Severity: critical. The threshold-signing scheme provides no security beyond a
single-key signer despite running an N-party DKG and presenting itself as a
threshold system.

## Reproduction / evidence

- Boot a multi-validator network through the production path in
  `main.rs` (operator identity configured). `dkls_threshold = 1u8` is fixed at
  `main.rs:1603` and passed to `dkls_supervisor::run`.
- For target epoch with active set of size N, `build_driver` constructs
  `Parameters { threshold: 1, share_count: N }` and runs the DKG; every
  validator receives a share of a 1-of-N key.
- At any ceremony, `select_signing_committee(epoch, seed, N, 1)` returns a
  single index; that party's `run_honest_sign`-equivalent single-party DKLS
  sign yields a full group signature. (The `dkls_committee` unit tests
  `selection_size_equals_threshold` and `pinned_vector_one_of_three` confirm
  committee size == threshold == 1.)

## Recommended fix

- Derive the threshold from the active-set size with a BFT-safe floor at
  `build_driver` time, e.g. `threshold = floor(2 * share_count / 3) + 1`
  (or the project's intended quorum), and reject construction when the
  resulting `threshold < 2` for non-devnet (`share_count > 1`) sets.
- Remove the static `dkls_threshold = 1u8` and treat `threshold == 1` with
  `share_count > 1` as a hard error in `run_honest_dkg` /
  `select_signing_committee` / the supervisor, distinct from the legitimate
  `threshold == share_count == 1` local-sign devnet mode.
- Add a regression test asserting that a ≥2-validator active set never yields
  a committee of size 1.

## Notes / scope

This is an integration-layer defect, not a flaw in the vendored `dkls23`
primitive (out of scope per `00-OVERVIEW.md`). The primitive faithfully
supports `t < n`; the bug is that Hypersnap selects `t = 1` for arbitrary `n`.

### Validation

- Verdict: **WATERPROOF**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F028 validation — DKLS threshold hard-pinned to 1

Validator: validator (deliberate-disagreement). Commit `cab225f` (workspace HEAD).
Finding claims: `main.rs:1603 let dkls_threshold = 1u8;` flows unchecked into the
per-epoch DKG, yielding a 1-of-N group key, so any single committee-elected
validator unilaterally produces the group threshold signature over hyperblocks,
rewards, trust snapshots, and bridge authorizations. Severity: Critical.

## Evidence chain re-verified (read-only)

- `src/main.rs:1603` — `let dkls_threshold = 1u8;` — no nearby comment marking it
  phased/testnet/placeholder. Grep for `testnet|phase|placeholder|TODO` near line
  1603 found nothing on that line.
- `src/main.rs:1650` — `threshold: dkls_threshold` passed into
  `DklsSupervisorInputs`. Spawned only on signing validators (operator identity
  configured) — i.e. the production validator path, not a test stub.
- `src/hyper/dkls_supervisor.rs:192,203-205` — `share_count = active.len()` (real
  active set), `parameters = Parameters { threshold: inputs.threshold, share_count }`.
  No floor, no `threshold vs share_count` relationship check. Confirmed.
- `src/hyper/dkls_committee.rs:59` — `select_signing_committee` rejects only
  `threshold == 0 || threshold > share_count`; `take(threshold)` ⇒ returns exactly
  1 index for threshold=1. Confirmed.
- `crates/hypersnap-crypto/src/dkls_threshold.rs:115` — `run_honest_dkg` rejects
  only the same two cases. Confirmed.
- `src/hyper/actor.rs:2645-2666` — at sign time threshold is read back from the
  installed share and fed to `select_signing_committee`; only committee members
  sign. With threshold=1 a single lowest-rank party signs and broadcasts.
- `src/hyper/actor.rs:2711` — `signing_committee().len() == 1` is an explicitly
  supported fast path ("1-of-1 case completes within a single tick"). Confirms a
  size-1 committee is a first-class operating mode, not an error.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS
Is there a check upstream of `build_driver` that forces threshold ≥ 2? No. The
only field is the static `dkls_threshold = 1u8` in `main.rs`; it is the sole
producer of `inputs.threshold`. There is no config validation, env override, or
runtime clamp between `main.rs:1603` and `Parameters` construction. The supervisor
guards EmptyActiveSet / ActiveSetTooLarge / LocalNotActive only — none constrain
threshold. No upstream gate exists.

### 2. Consumer-side impact — STANDS (impact real, with one scoping nuance)
What consumes the group signature? `src/hyper/sig_verify.rs` verifies hyperblock,
reward-issuance, trust-snapshot, and DA-epoch-seed signatures. In every path the
verifier recovers ONE 65-byte ECDSA signature against the per-epoch group address
(`dispatch`, lines 74-77) and fails closed only on address mismatch. There is NO
check that `signer_indices.len() >= quorum` — grep for `signer_indices.len`,
`quorum`, `2f+1`, `two-thirds` across `src/` returned no DKLS-side quorum gate.
Therefore a signature produced by a 1-member committee recovers to the legitimate
group address and verifies. The corrupted "state" (a 1-of-N key) is directly
consumed by the authority verifier with no compensating count check. The bridge /
reward / hyperblock authority is genuinely exercised by a single party.
Nuance: the *on-chain L1 bridge* enforcement (EVM side) is outside this repo; the
finding's "mints arbitrary wrapped SNAP / seizes bridge owner" claim depends on the
L1 contract trusting the group address signature, which per `docs/00-OVERVIEW.md`
lines 28,47-48 it does ("threshold-signs root updates / owner rotations"). That is
the documented trust model, so the consumer is real. Impact not overstated.

### 3. Downstream enforcement — STANDS
Does a lower layer re-check for a real quorum? The only `quorum.is_met` in the
codebase is `src/core/util.rs:132`, which validates the **legacy Snapchain Ed25519
block certificate** (`certificate.aggregated_signature.signatures` against the shard
`validator_set.validators`). That is a different pipeline (two-pipeline-confusion
guard applied) — it does not touch the DKLS hyper threshold signature and provides
no floor on the DKLS committee size. No downstream layer re-enforces a t-of-n quorum
for the group signature. Confirmed not caught downstream.

### 4. PR HEAD currency — STANDS
`git rev-parse HEAD` = `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, identical to the
finding's pinned `commit`. Workspace is a detached checkout at the pinned SHA; the
cited lines are current. No drift.

### 5. Spec carve-out — STANDS (special-scrutiny target)
Hard search for documentation declaring threshold=1 intentional/phased/testnet:
- No comment at or near `main.rs:1603` says phased/placeholder; the adjacent
  comments describe block_time / supervisor_lead_blocks, not the threshold.
- `docs/00-OVERVIEW.md` describes the system as "**threshold ECDSA (DKLS23)**"
  (line 18) and lists the group signature as authority over hyperblocks, rewards,
  and "bridge merkle-root updates / owner rotations / pause / upgrade" (lines 28,
  42-48). It presents threshold signing as the *security model*, with no carve-out
  that t=1 is an accepted current-phase configuration.
- `crates/hypersnap-crypto/src/dkls_threshold.rs:104-106` mentions a "single-operator
  dummy ceremony" only for the bridge-ceremony *tool*, not the production node.
- No README / SECURITY.md / docs/hyper.md (no `threshold`/`dkls` matches) flags
  t=1 as known-incomplete.
Conclusion: this is NOT a documented phased config. The code presents a full N-party
DKG while silently fixing reconstruction at 1, and the docs assert real threshold
security. The carve-out hypothesis fails — finding stands.
Caveat noted: `dkls_threshold = 1u8` with the comment "Conservative defaults;
operators can re-tune via config fields if/when those land" (main.rs:1597-1598)
*could* be read as a not-yet-wired-config placeholder. But (a) no config plumbing
exists to override it, (b) the docs claim threshold security regardless, and (c) the
spawn is gated on production operator identity — so the live default is t=1 with no
operator escape hatch. This lowers neither reachability nor severity; it is at most
an "operator docs don't warn it's incomplete" framing on top of a real exposure.

### 6. Reachability of harm — STANDS
Can a single validator actually extract value? Path: a validator in the active set
wins the deterministic committee draw for some `(epoch, height, parent_hash)` →
`select_signing_committee` returns its index alone → it runs single-party DKLS sign
→ broadcasts a full `(r,s,v)` recovering to the group address → `sig_verify`
accepts it (no cosigner / count requirement). The committee selector is keyed on
non-grindable consensus-pinned fields (F036 fix), so the validator cannot freely
target a digest, BUT with threshold=1 *every* ceremony has a size-1 committee, so
across epochs a given validator is selected for many `(epoch,digest)` tuples and
needs only the ones it is selected for to forge authority for that payload. Bridge
owner-rotation / lock-root payloads are among the signed authorities
(docs/00-OVERVIEW.md:47-48). Harm is reachable for any payload the lone signer is
elected to sign. Not gated.

### 7. Test wiring — STANDS
Is the buggy path production or test-only? `main.rs:1603` is in the node bootstrap
(`HyperHttpHandler` construction), spawned under the real
`operator_validator_pubkey_hex` + `local_dkls_share_path` gate (lines 1572-1591) —
the production signing-validator path, not `#[cfg(test)]`. The supervisor, driver,
committee selector, and `sig_verify` are all production modules. Tests
(`pinned_vector_one_of_three`, `selection_size_equals_threshold`,
`dkls_integration_test.rs:150`) merely *confirm* size==threshold behavior. The bug
is in production wiring.

### 8. PoC mechanics — STANDS
The finding has no executable PoC, but cites unit tests as corroboration:
`pinned_vector_one_of_three` (committee of size 1 for a 3-party group) and
`selection_size_equals_threshold` prove `committee.len() == threshold`, and
`actor.rs:2711` proves a size-1 committee finalizes a full signature. These
assertions prove exactly the prose claim: threshold=1 ⇒ one signer produces a
valid group signature. The assertion cannot pass for an unrelated reason (it is a
direct size/threshold equality on the selection function actually used in prod via
actor.rs:2659). Mechanics sound.

## Overall verdict

WATERPROOF — confidence 0.9.

Every hypothesis STANDS. The two adversarial targets called out in the brief:
- Spec carve-out (#5): no doc/comment declares t=1 phased/testnet; the overview
  asserts real threshold security. The only mitigating reading ("config not yet
  wired") does not reduce the live exposure because no override path exists and the
  default ships t=1 on the production validator path.
- Consumer/reachability (#2/#6): the downstream verifier enforces only
  address-recovery, with NO `signer_indices`/quorum floor; the legacy Ed25519
  certificate quorum (util.rs:132) is a separate pipeline and does not apply. A
  single elected validator's signature verifies as the group authority.

Confidence held at 0.9 (not 1.0) for two honest residuals: (a) the EVM-side L1
bridge contract is out of this repo, so the literal "mint wrapped SNAP / seize
owner" L1 consequence is asserted from the docs' trust model rather than verified in
contract code here; (b) the "config may be intended to be operator-tunable later"
comment introduces a small framing ambiguity. Neither changes the core defect: in
the production node path the group threshold is fixed at 1 with no floor or operator
override, defeating the t-of-n premise. Critical severity is appropriate.

## Open follow-ups (NOT new findings)
- The on-chain L1 bridge contract (EVM, outside this repo) should be checked to
  confirm it trusts only the group address signature with no independent multisig;
  if it does, the bridge-takeover impact is fully concrete. Validator cannot create
  findings — flagging for hunt specialists.
- `main.rs:1597-1598` "operators can re-tune via config fields if/when those land"
  suggests intended-but-unwired threshold config; worth a hunt pass on whether any
  partial config plumbing exists elsewhere.

---

## F035 — HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed verkle state root with no balance closure, range proof, or signature verification

## Summary

The `HyperLockEvent` bridge-lock pipeline writes a caller-supplied plaintext
`amount` directly into a verkle-tree leaf with **no source-side balance
enforcement of any kind**: no Pedersen balance closure, no range proof, and no
verification of the proto `lock_signature` field. The verkle root containing
that leaf is then threshold-signed and posted as the cross-chain
`hyper_state_root`, and `lock_event.rs`'s own module doc + end-to-end test
assert the L1 bridge proves inclusion of this leaf "before minting wrapped
tokens."

A second, secure lock pipeline exists in the same scope —
`confidential_lock::validate_against_store` performs full Pedersen balance
closure (`commit_in - (amount+fee)·B == r_diff·B_blinding`) against a
caller-supplied `blinding_diff_scalar`, plus Schnorr spend verification and
nullifier double-spend checks. This is the classic two-pipeline confusion: the
strong validator is fully implemented and wired into `apply_confidential_lock`,
while the **production block-application path still applies the weak
`HyperLockEvent` path unconditionally**. A malicious proposer can include
arbitrary-amount `HyperLockEvent`s in a block; every importer applies them with
structural validation only.

## Affected code (file:line)

- `src/hyper/lock_event.rs:141` `validate_lock_event` — the only validation
  ever run on a `HyperLockEvent`. Checks `amount != 0`, `lock_id.len()==32`,
  non-empty dest/spend fields, and EVM length conventions. **Never checks
  `lock_signature`, never enforces any balance relation.** Module doc
  (lines 11-14) explicitly states: "the handler accepts the lock event but
  does not enforce source-side balance constraints. This is documented as a
  known gap."
- `src/hyper/lock_event.rs:27` `encode_lock_leaf` — serializes the plaintext
  `amount` (8B BE) straight into the verkle leaf the L1 bridge decodes
  (lines 4-9, 18-26).
- `src/hyper/builder.rs:113-118` `apply_message(PendingMessage::Lock)` →
  `insert_lock_into_tree` → `validate_lock_event` only, then inserts the leaf
  into the verkle tree. No commitment, no range proof.
- `src/hyper/importer.rs:238-305` `import_hyper_block` — the production
  block-application path. Verifies ONLY (a) the block threshold ECDSA
  signature and (b) that the recomputed verkle root equals the signed
  `hyper_state_root`. It then loops every `lock` in `locks_in_block`
  (decoded from the proposer's `HyperWireBlock.locks` payload, NOT from local
  mempool) into `PendingMessage::Lock` and applies it (lines 263-265, 270-283).
- `src/hyper/runtime.rs:4461-4534` `HyperRuntime::import_block` — the live
  runtime entry. For **transfers** it re-runs strong off-mempool validation
  (`validate_against_store` + `verify_balance_with_blinding_diff`, lines
  4482-4524) explicitly "to defend against a malicious proposer who included a
  transfer off-mempool." **No equivalent re-validation exists for
  `locks_in_block`** — they go straight into `import_hyper_block_with_index`.
- `src/hyper/mempool.rs:119-129` `submit_lock` — structural-only admission
  (`validate_lock_event`), retained.

Contrast — the secure path that is NOT on the verkle/L1 lock path:
- `src/hyper/confidential_lock.rs:156-186` `validate_against_store` enforces
  balance closure at line 182 (`residual != expected`), Schnorr verify
  (line 171), nullifier-not-spent (line 166).
- `src/hyper/runtime.rs:860-913` `apply_confidential_lock` is the only
  non-test writer of `TokenLockState` into `reward_store`; those states feed
  `build_lock_merkle_tree` (runtime.rs:921) / `lock_tree.rs`, the merkle root
  the L1 `claim` consumes.

## Attack scenario

1. A malicious (or compromised) block proposer constructs a `HyperLockEvent`
   with `amount = 1_000_000_000`, a valid 32-byte `lock_id`, an attacker EVM
   `dest_address`, `spend_pubkey` of valid length, and `lock_signature` left
   zero-filled (it is never checked). `validate_lock_event` passes.
2. The proposer places this lock directly into the block's
   `HyperWireBlock.locks` payload (it need not pass through any node's mempool
   router, which would reject transparent locks). It builds the block; the
   verkle root deterministically incorporates the lock leaf.
3. The proposer obtains the normal block threshold signature over the metadata
   (the verkle `hyper_state_root`). This is the only signature the protocol
   requires.
4. Every importer runs `import_hyper_block`: the threshold sig verifies, the
   recomputed verkle root matches (the lock leaf is deterministic), and the
   lock is applied with structural-only validation. The forged lock is now
   committed under the signed cross-chain state root on every node.
5. Per `lock_event.rs` lines 4-9 and the `bridge_proof_pipeline_end_to_end`
   test (lines 318-371), the L1 bridge proves verkle inclusion of this leaf and
   mints `amount` wrapped tokens to the attacker's `dest_address` — wrapped
   value backed by nothing on the source side.

No honest counter-party balance was ever debited; `sum(inputs)=sum(outputs)+fee`
is never evaluated for this lock, and no range proof bounds `amount`.

## Impact

Unbacked mint of arbitrary wrapped-token value, fully drainable on L1 — a direct
theft / protocol-insolvency vector, gated only by the honesty of the block
proposer (and the threshold-signing set's willingness to sign whatever verkle
root the proposer produces, since locks carry no independently-verifiable
authenticity).

Relation to prior F002 (per-lock authenticity rests on an honest proposer):
This **confirms F002 is, for the balance/authenticity dimension, still
vulnerable (at best partially-fixed)**. PR #34's hardening was applied to
*transfers* (the off-mempool re-validation block in `import_block`,
runtime.rs:4482-4524) and to *confidential locks*
(`apply_confidential_lock`/`validate_against_store`), but the transparent
`HyperLockEvent` → verkle path retained its weak, structural-only application
in `import_hyper_block`. The `lock_signature` proto field (hyper.proto:304) is
verified nowhere in production — every occurrence is a zero-fill or refers to
the unrelated block-level `verify_hyperblock_signature`. Lock authenticity and
balance still rest entirely on an honest proposer, exactly the F002 condition.

Note on exploit live-ness: the L1 `claim` entry point present in this repo
consumes the *merkle* lock-tree root (`lock_tree.rs` / `bridge_state.rs`,
built only from balance-validated `TokenLockState`s), so an attacker cannot
reach L1 through *that* specific root. The verkle-inclusion mint path is the one
`lock_event.rs` documents and tests; whether the deployed L1 bridge currently
honors verkle-inclusion claims is not determinable from this repo (the L1
contract is out of scope). Regardless, the in-scope code commits attacker-chosen,
unbacked lock leaves into the threshold-signed cross-chain state root with zero
balance enforcement — a latent mint primitive that becomes immediately
exploitable the moment the verkle-inclusion claim path is enabled on L1, and a
clear violation of the balance-closure invariant for the lock primitive.

## Root cause

Two parallel lock pipelines with asymmetric enforcement. The balance-closure
validator was implemented and wired only into the confidential pipeline; the
transparent `HyperLockEvent` pipeline that writes the verkle/cross-chain state
root kept its placeholder "source-side balance constraints are a known gap /
Phase B-3" handler and was never decommissioned from the block-application path.
The proto carries a `lock_signature` field but no code reads it, and no
`r_diff`/commitment/range-proof is carried for transparent locks, so balance
closure is structurally impossible on this path even if a check were added.

## Fix

Remove the transparent-lock state-change path entirely (the router already
rejects ingress at router.rs:133), OR require every `HyperLockEvent` applied in
`import_hyper_block` / `builder::apply_message` to carry and pass the same
enforcement as confidential locks:

1. In `HyperRuntime::import_block`, add a per-lock re-validation loop mirroring
   the transfer loop (runtime.rs:4482-4524): reject any block whose locks lack a
   verifiable source-side commitment + range proof + balance closure against the
   note store.
2. Extend the lock wire format to carry the input commitment, `blinding_diff`
   scalar, and a range proof on `amount`; verify
   `commit_in - (amount+fee)·B == r_diff·B_blinding` and the bullet-proof range
   bound before inserting the leaf.
3. Either verify `lock_signature` (Schnorr/ecrecover over a domain-separated
   payload binding amount + dest + nullifier) or delete the unused field and
   the mod.rs:14 "Includes Schnorr-signed authorization" claim, which is false.

Preferred: route all production bridge locks exclusively through
`apply_confidential_lock` (already balance-closed) and delete
`lock_event.rs` application from `builder`/`importer`, eliminating the
verkle-leaf mint primitive.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.7
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F035 validation — HyperLockEvent mints into the verkle root with no balance closure

Validator: validator (deliberate-disagreement). Commit `cab225f` (workspace HEAD, clean tree).
Finding claims: the transparent `HyperLockEvent` lock pipeline writes a caller-supplied
plaintext `amount` into a verkle leaf with no Pedersen balance closure, no range proof, and
no `lock_signature` check; the verkle root is threshold-signed and posted as the cross-chain
`hyper_state_root`. A malicious proposer can include arbitrary-amount locks in a wire block;
every importer applies them with structural-only validation. Confirms prior **F002** is, on
the balance/authenticity dimension, still vulnerable. Severity initial: High.

This is the **prior-F002 revalidation** and the central red-team concern is the
two-pipeline-confusion lesson (and the prior C3 invalidation): the L1 bridge consumes a
DIFFERENT, balance-validated pipeline than the one the finding traces. That tension is the
crux of the verdict below.

## Evidence chain re-verified (read-only)

WEAK path (the one the finding traces):
- `src/hyper/lock_event.rs:141` `validate_lock_event` — only checks `amount != 0`,
  `lock_id.len()==32`, non-empty dest/spend, EVM length conventions. Never reads
  `lock_signature`, enforces no balance relation. Confirmed.
- `src/hyper/lock_event.rs:1-14` module doc explicitly states source-side balance
  constraints are "a known gap" (Phase B-3). Confirmed.
- `src/hyper/builder.rs:113-118` `apply_message(PendingMessage::Lock)` → `insert_lock_into_tree`
  → `validate_lock_event` only, then `tree.insert(key, leaf)`. No commitment/range proof. Confirmed.
- `src/hyper/importer.rs:238-305` `import_hyper_block` — verifies block-level threshold ECDSA
  sig (252-258) and recomputed-root == stated root (285-292), then loops every `lock` in
  `locks_in_block` into `PendingMessage::Lock` (263-265). No per-lock authenticity/balance check. Confirmed.
- `src/hyper/runtime.rs:4461-4524` `import_block` — re-validates every TRANSFER off-mempool
  (`validate_against_store` + `verify_balance_with_blinding_diff`, 4482-4524) "to defend against
  a malicious proposer". **No equivalent loop for `locks_in_block`** — they pass straight to
  `import_hyper_block_with_index` (4526-4535). Confirmed asymmetry.
- `src/hyper/gossip_adapter.rs:70-77` `wire_to_event` — `InboundBlock { locks: b.locks, ... }`:
  locks are pulled VERBATIM from the proposer's `HyperWireBlock`, NOT cross-checked against the
  local mempool. → `actor.rs:1241-1248` `InboundBlock` → `runtime.import_block(&block, &locks, ...)`.
  Reachability of attacker-chosen leaves into the signed verkle root confirmed end-to-end.

STRONG path (the one the L1 bridge actually consumes):
- `src/hyper/confidential_lock.rs:156-186` `validate_against_store` — Pedersen closure
  (`residual != expected`, 182), Schnorr verify (171), nullifier-not-spent (166). Confirmed.
- `src/hyper/runtime.rs:860-913` `apply_confidential_lock` — the ONLY non-test writer of
  `TokenLockState` into `reward_store` (890-902), gated on `validate_against_store`. Confirmed.
- `src/hyper/runtime.rs:921-932` `build_lock_merkle_tree` — sources `reward_store.iter_all_locks()`
  (i.e. only `TokenLockState`s from the confidential path), builds the keccak256 merkle tree.
- `src/hyper/lock_tree.rs:1-46` — module doc + `encode_token_lock_leaf`: this merkle root is the
  one threshold-signed and posted to `HypersnapBridge.claim` as `latestRoot`; the claimant proves
  inclusion against THIS tree. The verkle root is a separate `hyper_state_root`. Confirmed.

Ingress sealing (F058):
- `src/hyper/router.rs:133-142` — gossip/RPC `Body::Lock` is rejected ("transparent lock path
  removed; use ConfidentialLockBody").
- `src/hyper/http_handler.rs:1706-1743` — HTTP POST of a Lock is rejected; mempool stays empty.
- BUT neither seals the block-application path: `b.locks` from a remote `HyperWireBlock` bypasses
  the router entirely (gossip_adapter → InboundBlock → import_block). The proposer-inserted weak
  lock path is genuinely live.

`lock_signature` usage: grep across `src/` — every occurrence is `vec![0u8; 64]` (test fixtures
in builder/actor/gossip_adapter/http_handler/mempool/router/runtime/lock_event/network_sim) or
the unrelated block-level `verify_hyperblock_signature`. The field is read NOWHERE in production. Confirmed.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS
Is there a check upstream of `apply_message(Lock)` that re-validates proposer-supplied locks?
The transfer path has one (`runtime.rs:4482-4524`); the lock path does not. The router seals
*gossip/HTTP* ingress (router.rs:133, http_handler.rs:1706) but the wire-block path
(`gossip_adapter.rs:75` → `InboundBlock.locks` → `import_block`) carries locks directly from the
proposer's frame with no mempool cross-check and no balance/auth gate. No upstream gate on the
exploited path. STANDS.

### 2. Consumer-side impact — PARTIALLY INVALIDATED (this is the key caveat)
What consumes the corrupted verkle leaf? The in-scope L1-facing consumer is
`HypersnapBridge.claim`, which recomputes the **keccak256 merkle** lock-tree root
(`lock_tree.rs:1-46`, `runtime.rs:921-932`), built ONLY from `TokenLockState`s written by the
balance-validated `apply_confidential_lock` (`runtime.rs:890-902`). The `HyperLockEvent` verkle
leaf is NOT in that merkle tree. So the attacker's forged leaf is committed under the
threshold-signed `hyper_state_root` (verkle) but is NOT claimable through the merkle root the
deployed bridge consumes. This is precisely the two-pipeline-confusion / prior-C3 scenario.
The finding's own "Note on exploit live-ness" (body lines 122-132) already concedes this and
explicitly downgrades to "latent in-protocol primitive". The corrupted state is real and
threshold-signed, but no IN-SCOPE consumer turns it into L1 fund-loss today. Impact is therefore
an in-protocol invariant break, not a live drain. PARTIALLY INVALIDATED (impact, not existence).

### 3. Downstream enforcement — STANDS
Does any layer below `apply_message(Lock)` re-verify balance/authenticity before the leaf is
sealed? No. `import_hyper_block` only checks (a) block threshold sig and (b) verkle-root equality
(importer.rs:252-292). The root-equality check is satisfied because the leaf is deterministic, so
it cannot catch a balanced-vs-unbalanced distinction. No downstream balance enforcement on the
verkle lock path. STANDS.

### 4. PR HEAD currency — STANDS
Workspace HEAD is `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` (git log), clean working tree,
matching the pinned commit. No drift; all cited lines are current. STANDS.

### 5. Spec carve-out — PARTIALLY INVALIDATED (mitigates severity framing)
`lock_event.rs:11-14` explicitly documents the missing source-side balance enforcement as "a
known gap" pending Phase B-3 UTXO+Pedersen+range-proof primitives. The confidential pipeline
(`confidential_lock.rs`, `apply_confidential_lock`) IS that Phase-B replacement and is wired as
the production bridge path; the router/HTTP seals (F058) show the team is actively retiring the
transparent path. So the transparent verkle-lock primitive reads as a documented, partially-decommissioned
placeholder rather than a silently-broken production money path. This does not erase the
invariant break (the application path is still live for proposer-inserted locks) but it weakens
the "production block-application path still applies the weak path unconditionally" framing toward
"a not-fully-removed legacy primitive". PARTIALLY INVALIDATED (framing/severity).

### 6. Reachability of the harm — PARTIALLY INVALIDATED
Verkle-leaf insertion IS reachable (hyp. 1: malicious proposer → `b.locks` → import_block →
verkle root, no gate). But reachability of *value extraction* requires an L1 contract that honors
verkle-inclusion claims. The in-scope L1 claim path consumes the merkle root (hyp. 2), and the
deployed verkle-inclusion bridge contract is out of scope / not in this repo, so it is not
determinable that a value-bearing consumer exists today. The `lock_event.rs` module doc and the
`bridge_proof_pipeline_end_to_end` test (lines 318-371) assert a verkle-inclusion L1 mint flow,
but that is a hypersnap-side proof exercise, not proof a live L1 contract honors it. Harm to
in-protocol state STANDS; harm to L1 funds is NEEDS-MORE-DATA/out-of-scope. PARTIALLY INVALIDATED.

### 7. Test wiring — STANDS (production-reachable; no production producer)
`import_block` / `apply_message(Lock)` / `insert_lock_into_tree` are production functions on the
live import path (actor.rs:1248, 2775). The locks are supplied from the wire frame, so a remote
proposer reaches them in production regardless of whether any honest node ever *produces* a
transparent lock (all in-repo `locks` populations outside tests are `vec![]`). The exploit relies
on a malicious proposer hand-crafting `b.locks`, which `gossip_adapter` feeds unconditionally —
so the buggy code is genuinely invoked in production by adversarial input. STANDS.

### 8. PoC mechanics — NEEDS-MORE-DATA (no executable PoC in the finding)
The finding cites the existing `bridge_proof_pipeline_end_to_end` test (lock_event.rs:318-371) as
evidence the verkle-inclusion path is exercised. That test proves the hypersnap-side flow
(insert → root → inclusion proof → verify → decode round-trip) but asserts nothing about an L1
contract honoring it, nor about a *missing* balance check — it uses a well-formed sample event.
It does not itself demonstrate the unbacked-mint claim end-to-end. The structural-only behavior of
`validate_lock_event` is directly evidenced by reading lines 141-171 (no balance/signature logic),
which is solid. The "L1 mints `amount` to attacker" step rests on assertion, not a PoC. The
in-protocol-invariant-break portion is well-evidenced by code; the L1-fund-loss portion is not
demonstrated. NEEDS-MORE-DATA on the L1 leg.

## Overall verdict — HAS_CAVEATS (confidence 0.7)

The underlying CODE FACTS are correct and verified:
- The transparent `HyperLockEvent` path applies attacker-controllable, plaintext-amount leaves
  into the threshold-signed verkle root with structural-only validation (no Pedersen closure, no
  range proof, no `lock_signature` check).
- The asymmetry is real: transfers are re-validated off-mempool in `import_block`; locks are not.
- The path is genuinely reachable by a malicious proposer via the wire-block `locks` field, which
  bypasses the F058 router/HTTP seals.
- `lock_signature` is dead in production; `mod.rs`'s "Schnorr-signed authorization" claim is false.

This substantiates that F002's balance/authenticity dimension is **still vulnerable** as an
in-protocol invariant break on the verkle lock primitive.

The CAVEAT (and reason this is not WATERPROOF High fund-loss) is the consumer-side / reachability
walk: the in-scope L1 `claim` consumes the MERKLE root built from balance-validated
`TokenLockState`s, NOT the verkle root the forged leaf lands in. So the live, in-scope impact is a
threshold-signed-state-corruption / latent-mint primitive, not a demonstrated L1 drain. Whether it
becomes true fund-loss depends on an out-of-scope L1 contract honoring verkle inclusion. The
finding's body already states this honestly (lines 122-132) and frames severity accordingly, which
is why this is HAS_CAVEATS rather than INVALIDATED. The prior C3/two-pipeline lesson would
INVALIDATE a finding that claimed *live L1 fund-loss via HyperLockEvent*; F035 does not overclaim
that — it claims an in-protocol balance-closure violation + latent primitive, which holds.

f002_status: **still-vulnerable** (balance-closure invariant on the transparent lock path is
unenforced and the application path is live; impact is in-protocol / latent-L1 rather than
confirmed live L1 fund-loss).

## Open follow-ups (NOT new findings — validator cannot create findings)
- Severity calibration: under an Immunefi-style rubric the demonstrated in-scope impact is
  "threshold-signed cross-chain state-root corruption requiring a hardfork to unwind" (High by
  state-corruption, not Critical fund-loss). The finding's `severity_initial: high` is consistent
  with the caveated reading; no downgrade warranted, but a Critical upgrade would NOT be justified
  without the out-of-scope L1 verkle-claim contract in evidence.
- Documentation gap worth noting to the team: `mod.rs:14` / `lock_event.rs:6` advertise lock
  signature validation that does not exist — independent of fund-loss, this is a false safety claim.

---

## F036 — ConfidentialLockBody.range_proof is carried on the wire but verify_value_range is never wired into the lock-admission path

## Summary

The confidential bridge-lock primitive defines a wire field
`ConfidentialLockBody.range_proof` (proto field 6) whose documented purpose
is "Bulletproofs range proof for `amount`. Proves `amount` fits in the
protocol's range." A range-proof verifier (`verify_value_range`) exists and
is correct. But the function that admits confidential locks on the live
gossip path — `confidential_lock::validate_against_store` — never calls
`verify_value_range` (or reads `body.range_proof` at all). The field is
accepted and silently discarded; locks are admitted with no range-proof
verification.

Note: the *primary* cryptographic verifier for this primitive
(`validate_against_store`: Schnorr spend-signature verify + Pedersen balance
closure + nullifier-not-spent) IS correctly wired (see "Live path" below),
so the broad "the verifier is dead code" framing does NOT hold. The
defined-but-unwired component is specifically the **range-proof** check.

## Affected code

Verifier defined (range proof):
- `crates/hypersnap-crypto/src/tokens.rs:158` — `pub fn verify_value_range(...)`.
  Its only non-test caller is `TransferTx::validate` at
  `crates/hypersnap-crypto/src/tokens.rs:332` (the confidential *transfer*
  path). Grep for `verify_value_range` across `src/**` returns zero hits in
  the confidential-lock path.

Wire field defined:
- `proto/definitions/hyper.proto:228-230` — `ConfidentialLockBody.range_proof`,
  documented as a Bulletproofs range proof for `amount`.

Admission verifier that omits it:
- `src/hyper/confidential_lock.rs:156` — `validate_against_store(...)`. Calls
  `validate_structural` (lengths/parse), Schnorr verify
  (`confidential_lock.rs:170-173`), and Pedersen balance closure
  (`confidential_lock.rs:177-184`). It never references `body.range_proof`.
- `src/hyper/confidential_lock.rs:100` — `validate_structural(...)` likewise
  never inspects `body.range_proof`.

## Live path (where admission happens)

- `src/hyper/runtime.rs:3699-3703` — `submit_message` (the inbound-gossip
  admission gate) intercepts `Body::ConfidentialLock` and calls
  `apply_confidential_lock`.
- `src/hyper/runtime.rs:860-913` — `apply_confidential_lock` calls
  `confidential_lock::validate_against_store` (runtime.rs:864), and on success
  immediately records a `TokenLockState` and marks the nullifier spent — a
  direct state change with no separate block-import re-validation for this
  body type (the importer at `src/hyper/importer.rs` has no confidential-lock
  handling). So `validate_against_store` is the sole gate, and it skips the
  range proof.

## Attack scenario

A peer crafts a `ConfidentialLockBody` with `range_proof` set to empty/garbage
bytes. `validate_against_store` ignores the field entirely, so the lock is
admitted as long as the Schnorr signature and Pedersen balance closure pass.
The "proves amount fits in range" guarantee advertised by the wire format is
never enforced.

## Impact

Low. The would-be value-overflow impact is already foreclosed by two facts
independent of the missing range proof:
1. `amount` is a public `uint64` (proto field 2), so it is structurally bounded
   to `< 2^64` and cannot be a near-group-order value.
2. The Pedersen balance closure
   (`commit_in - (amount + fee)*B == blinding_diff * B_blinding`,
   `confidential_lock.rs:177-184`) binds the committed input value to the public
   `amount + fee` exactly, so a prover cannot commit a large value while
   declaring a small public `amount`.

The codebase's own design treats this range proof as unnecessary when the
amount is public: the shield primitive reuses the same `range_proof` field as
a blinding scalar with the comment "the bulletproofs range proof is
unnecessary — `amount` is public" (`src/hyper/shield.rs:80-84`). The risk that
remains is a latent wire-format integrity gap: the field exists, looks
load-bearing, and could be relied upon by future code or off-chain tooling
that assumes lock admission enforces a range bound when it does not.

## Root cause

Defined-but-unwired verifier: `verify_value_range` is wired only for transfer
outputs, never for the confidential-lock body, even though the lock proto
carries a `range_proof` field. The omission is silent (no error, field simply
not read), which is exactly the dead-code-security pattern — a proof artifact
is transmitted but never checked.

## Fix

Either (a) verify the field on the live path — in
`confidential_lock::validate_against_store`, after balance closure, call
`hypersnap_crypto::tokens::verify_value_range(&body.range_proof,
&input.commitment[..].try_into()?, DEFAULT_RANGE_BITS)` and reject on failure;
or (b) if the range proof is genuinely redundant given the public `amount` +
balance closure (consistent with the shield rationale), remove the
`range_proof` field from `ConfidentialLockBody` in the proto and document that
lock amounts are bounded by the public `uint64` + closure, so no caller or
off-chain tool mistakes the discarded field for an enforced guarantee.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 12:30:00+00:00

### Validator notes

# F036 Validation — ConfidentialLockBody.range_proof defined-but-unwired

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f` (verified `git log -1` == cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9, 2026-06-08).

Finding claim: `ConfidentialLockBody.range_proof` (proto field 6) is carried on
the wire but `verify_value_range` is never called on the confidential-lock
admission path; finder rated **LOW** because impact is foreclosed by (1) public
`uint64 amount` and (2) Pedersen balance closure binding committed value to
`amount+fee`. RED-TEAM mandate: confirm impact really IS foreclosed, OR find a
path where the missing proof matters, OR show the issue isn't real (INVALIDATED).

## Verification of the factual core (the bug is REAL)

- `verify_value_range` has ZERO callers under `src/` (grep `verify_value_range src/`
  → empty). Its only non-test caller is `TransferTx::validate`
  (`crates/hypersnap-crypto/src/tokens.rs:332`). Confirmed unwired for locks.
- `validate_against_store` (`src/hyper/confidential_lock.rs:156-186`) calls
  `validate_structural` + `lookup_owner` + `is_spent` + Schnorr verify
  (`:170-173`) + Pedersen closure (`:177-184`). It NEVER references
  `body.range_proof`. `validate_structural` (`:100-152`) also never inspects it.
- `range_proof` refs in the lock path are all test fixtures setting `vec![]`
  (`confidential_lock.rs:212,232,253,274`). The runtime.rs:5310-5391 hits are the
  unrelated transfer-output codepath.
So the "defined-but-unwired" fact is correct. Question is impact magnitude.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS (no rescue)
`submit_message` (`runtime.rs:3699-3703`) intercepts `Body::ConfidentialLock` and
calls `apply_confidential_lock` directly. No upstream layer verifies a range
proof. (libp2p gossip signing authenticates the *peer*, not the lock contents.)
Nothing upstream re-introduces the missing check. Bug stands as a fact.

### 2. Consumer-side impact — INVALIDATES the "value overflow" harm (impact LOW is correct)
`apply_confidential_lock` (`runtime.rs:890-896`) records
`TokenLockState{ amount: body.amount, ... }` — the L1 bridge leaf carries the
**public** `body.amount`, not the committed value. The consumer never trusts the
hidden commitment value over the public amount. Combined with the closure (H6),
there is no value the attacker can inflate. Consumer-side confirms LOW.

### 3. Downstream enforcement — INVALIDATES the high-impact reading
The Pedersen balance closure at `confidential_lock.rs:177-184` is a downstream
crypto gate that already binds the committed input value to exactly
`amount+fee`. A correct range proof on `amount` would prove `amount ∈ [0,2^64)`,
which a `uint64` already guarantees structurally — so the missing proof enforces
nothing the closure + the type don't already enforce. Downstream catches what
the missing proof would have caught. This is the crux: impact is foreclosed.

### 4. PR HEAD currency — STANDS
Workspace HEAD == pinned `cab225f`; no drift. The unwired code is current.

### 5. Spec carve-out — PARTIALLY INVALIDATES (lowers severity, not the fact)
The codebase's own design documents that the range proof is unnecessary when
amount is public: the shield primitive reuses the same `range_proof` field as a
blinding scalar with the comment "the bulletproofs range proof is unnecessary —
`amount` is public" (`src/hyper/shield.rs:80-84`). So for the lock (also public
amount) the omission is consistent with stated design intent — not an oversight
that breaks a guarantee. The residual issue is purely a wire-format/doc integrity
gap (the proto comment still advertises an enforced range bound). Confirms LOW.

### 6. Reachability of the harm — INVALIDATED (no exploitable overflow)
Could a prover commit a near-group-order / negative value to overflow on the L1
side? No:
- `amount` and `fee_atoms` are `uint64` (proto fields 2 and 7), structurally
  `< 2^64`.
- `total_value = Scalar::from(amount.saturating_add(fee_atoms))`
  (`confidential_lock.rs:178`): `saturating_add` caps at `u64::MAX`, so
  `total_value < 2^64`. The Decaf448 scalar order L ≈ 2^446 ≫ 2^64, so
  `Scalar::from(total_value)` cannot wrap/alias. No modular escape.
- Closure `commitment.0 − total_value·B == blinding_diff·B_blinding`
  (`:180-182`) is an exact point equation binding the committed value to exactly
  `amount+fee mod L = amount+fee`. A prover cannot commit a large value while
  declaring a small public amount, nor a negative value (no value < the bound is
  reachable that the closure would accept while amount stays small). Harm to
  value conservation is unreachable.

### 7. Test wiring — STANDS (production path confirmed live)
`validate_against_store` is the SOLE gate: `apply_confidential_lock` →
`validate_against_store` (`runtime.rs:864`) then directly writes `TokenLockState`
and marks the nullifier spent (`:900-911`). The importer (`src/hyper/importer.rs`)
has no confidential-lock handling (grep empty) — no separate block-import
re-validation. So the unwired code runs in production; this is not a test-only
artifact. The bug is real and live (it's the IMPACT that's low, not the wiring).

### 8. PoC mechanics — N/A (no PoC asserted) → STANDS
The finding ships no executable PoC; its claim is a code-structure assertion
("field accepted, never verified"), which is directly confirmed by the grep +
read evidence above. The attack scenario ("garbage range_proof is admitted")
is trivially true since the field is never read. No over-claim in the prose:
the finding explicitly states the value-overflow impact is foreclosed.

## Overall verdict

**HAS_CAVEATS**, confidence 0.9.

The structural fact (range_proof carried on the wire, `verify_value_range` never
wired into the lock-admission path) is TRUE and verified at file:line. The
finding does NOT overstate impact: it self-rates LOW and correctly attributes
the foreclosure to (1) public `uint64` amount and (2) the Pedersen balance
closure — both of which I independently confirmed bind the value with no
overflow/aliasing/negative-value escape (H6), and whose consumer uses the public
amount (H2). The residual issue is a genuine but minor latent wire-format /
documentation integrity gap (proto comment advertises an enforced range bound
that admission does not enforce), consistent with the shield design rationale
(H5). LOW is the correct severity — neither INVALIDATED (the gap is real) nor
higher (no exploitable harm). "HAS_CAVEATS" reflects that the headline ("proof
defined but unwired") is true but the security consequence is essentially nil
given the closure; this is a hygiene/clarity finding, not a vulnerability.

## Open follow-ups (NOT new findings — for specialist consideration)
- None of security consequence. If the team chooses fix (b) (remove the proto
  field), confirm no off-chain tooling currently parses field 6 as load-bearing
  before removal, to avoid a wire-compat break.

---

## F039 — Admin retry RPCs (retry_onchain_events / retry_fname_events) reachable without authenticate_request guard

## Summary

The gRPC `AdminService` is mounted on the public gRPC socket with **no
transport-level auth interceptor**. Per-method authentication is the only
gate. Two state-affecting admin RPCs —
`retry_onchain_events` and `retry_fname_events` — call **neither**
`authenticate_request(...)` **nor** the `allow_debug()` network restriction.
Any client able to reach the gRPC port can invoke them, triggering
unbounded external L1-RPC / fname-registry scanning work on the node.

## Where

`code/hypersnap/src/network/admin_server.rs`, `impl AdminService for
MyAdminService`. Per-method guard inventory:

| Method | `authenticate_request`? | `allow_debug()`? |
|---|---|---|
| `submit_on_chain_event` (L103) | no | yes (network-gated) |
| `submit_user_name_proof` (L152) | no | yes (network-gated) |
| `retry_onchain_events` (L205) | **no** | **no** |
| `retry_fname_events` (L237) | **no** | **no** |
| `upload_snapshot` (L263) | yes | n/a |
| `run_onchain_events_migration` (L298) | yes | n/a |

`retry_onchain_events` and `retry_fname_events` have **no guard of any
kind**. They `.send(...)` onto `onchain_events_request_tx` /
`fname_request_tx` immediately on the attacker's call.

## Reachability / mounting

`code/hypersnap/src/main.rs` L301-312:

```rust
let grpc_svc = tonic::codegen::InterceptedService::new(
    HubServiceServer::from_arc(grpc_service),
    rate_limit_interceptor,        // <-- wraps HubService only
);
let mut server = Server::builder()
    .concurrency_limit_per_connection(64)
    .add_service(grpc_svc);

if admin_service.enabled() {       // enabled() == !allowed_users.is_empty()
    let admin_service = AdminServiceServer::new(admin_service);
    server = server.add_service(admin_service);   // no interceptor
}
```

The rate-limit interceptor wraps only `HubServiceServer`. `AdminServiceServer`
is added raw on the **same** `grpc_socket_addr`. `enabled()` returns true
whenever `rpc_auth` is configured — i.e. precisely when the operator
believes admin is locked down. So once auth is configured (the normal
production posture), the AdminService is exposed and the only protection
is the per-method `authenticate_request` call, which these two routes omit.

## Impact

Downstream of the unguarded sends:

- `OnchainEventsRequest::RetryBlockRange { start_block_number,
  stop_block_number }` → `retry_block_range(start, stop)`
  (`connectors/onchain_events/mod.rs` L1181-1186). The block range is
  fully attacker-controlled with no bound. A single anonymous call with a
  huge range forces the node to scan/refetch that range against the L1
  RPC endpoint — CPU-grief plus exhaustion of the operator's upstream L1
  RPC quota/rate-limit.
- `OnchainEventsRequest::RetryFid(fid)` / `FnameRequest::RetryFid` /
  `RetryFname` → repeated external refetch work
  (`connectors/onchain_events/mod.rs` L1175, `connectors/fname/mod.rs`
  L405-413). Unauthenticated, unbounded repetition = CPU/network grief.

No on-disk corruption (events are re-validated before merge), so this is
a denial-of-service / resource-grief primitive rather than a state-forgery
one. Severity: medium.

## Secondary observations (same auth path)

`rpc_extensions.rs::authenticate_request` (L151-195) has two further
weaknesses, noted for completeness:

1. **Fail-open on empty config (L155-157):** `if allowed_users.is_empty()
   { return Ok(()); }`. For the AdminService this is moot (the service is
   only mounted when `allowed_users` is non-empty). But the same function
   guards `HubService::submit_message` / `submit_bulk_messages`
   (`network/server.rs` L1192, L1265); when `rpc_auth` is unset those
   mutating endpoints are fully open. That is an intentional "auth
   disabled" mode, but it means the *guarded* submit routes silently
   become unauthenticated under the empty-config that the retry routes
   also rely on.
2. **Non-constant-time secret comparison (L184):** `if password ==
   parts[1]` compares the configured password with `==` (early-exit byte
   compare), a timing side-channel on the admin password. Low severity,
   but trivial to fix with a constant-time compare.

## Note on the HTTP submit path (in scope, ruled clean)

`http_server.rs` POST routes were also enumerated. `/v1/submitMessage` and
`/v1/submitBulkMessages` forward the `authorization` header into the gRPC
metadata and dispatch to `HubService::submit_message` /
`submit_bulk_messages`, both of which call `authenticate_request` and
validate-before-broadcast (`simulate_message_for_shard_typed` runs before
the mempool enqueue, `network/server.rs` L453-472). Body size is capped at
4 MiB via `read_limited_body` / `Limited`. The HTTP layer is **not** the
finding; the gap is the two unguarded admin gRPC retry methods.

## Recommended fix

Add `authenticate_request(&request, &self.allowed_users)?;` as the first
statement of both `retry_onchain_events` and `retry_fname_events` (matching
`upload_snapshot` / `run_onchain_events_migration`). Optionally also bound
the `RetryBlockRange` span and gate the debug-submit/retry surface behind a
separate DebugService not mounted in production. Switch the password check
to a constant-time comparison.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.8
- Hypotheses walked: 8
- Validated at: 2026-06-08 12:45:00+00:00

### Validator notes

# F039 validation — Admin retry RPCs missing authenticate_request guard

Validator: validator (deliberate-disagreement). Commit pinned `cab225f`, HEAD confirmed identical.

Finding claim: gRPC `retry_onchain_events` / `retry_fname_events` on `MyAdminService`
have neither `authenticate_request` nor `allow_debug()`, are mounted on the shared
public gRPC socket (no interceptor), and let any reachable client trigger
unbounded external L1-RPC / fname-registry refetch work → DoS / resource-grief (medium).

## Core facts verified (file:line)

- `admin_server.rs:205-235` `retry_onchain_events` — NO guard. `.send(RetryFid|RetryBlockRange)` immediately.
- `admin_server.rs:237-261` `retry_fname_events` — NO guard. `.send(RetryFid|RetryFname)` immediately.
- `admin_server.rs:263-326` `upload_snapshot` / `run_onchain_events_migration` DO call `authenticate_request` first; `submit_on_chain_event` (109) / `submit_user_name_proof` (158) call `allow_debug()`. The two retry methods are the unique gap — guard inventory in the finding is exactly correct.
- `main.rs:301-312` mount: `HubServiceServer` wrapped in `InterceptedService(rate_limit_interceptor)`; `AdminServiceServer::new(admin_service)` added RAW (no interceptor) on the SAME `grpc_socket_addr`. Confirmed: rate-limit interceptor wraps Hub only.
- `main.rs:318` `server.serve(grpc_socket_addr)` — single socket; no separate admin bind/port.
- Downstream wired in production: `main.rs:1026/1042/1063` connector run-loops subscribe the receivers; loops at `onchain_events/mod.rs:1169-1192` and `fname/mod.rs:398-417` dispatch the requests. Not test-only.
- `retry_block_range` (`onchain_events/mod.rs:1266-1288`) builds one `Filter` with attacker-controlled `from_block`/`to_block` and calls `get_logs_with_retry` against L1 RPC.

## 8-hypothesis walk

### 1. Upstream auth / gate — INVALIDATED (impact-narrowing, not finding-killing)
The finding's own mounting argument has a mis-attribution: `enabled()` keys on
`admin_rpc_auth` (`main.rs:78`, `cfg.rs:102`), NOT `rpc_auth` as the finding body states
("enabled() returns true whenever rpc_auth is configured"). Substance is unaffected —
the AdminService is still mounted whenever `admin_rpc_auth` is non-empty, with these two
methods unguarded. But the bigger upstream gate the finder under-weighted is the
**bind address**. `cfg.rs:132-138` default `rpc_address = 127.0.0.1:<port>` with an
explicit comment that gRPC auth ships off-by-default so loopback is the default posture
and "operators exposing these ports publicly must opt in via config." So the
"publicly reachable" precondition is operator-configuration-dependent, not default.
Verdict on this hypothesis: the unauthenticated-reachability is real ONLY when the
operator binds `rpc_address` to a non-loopback interface (a common hub posture, but an
explicit opt-in the codebase warns about). This narrows the claim from "default-exposed"
to "exposed under the standard public-hub config."

### 2. Consumer-side impact — STANDS (with severity ceiling)
Consumers re-validate before merge (events flow through mempool/runtime validation),
so there is NO state-forgery / on-disk corruption — the finding correctly says so.
Impact is purely resource-grief: forces `eth_getLogs` / fname-registry refetch.
`retry_block_range` issues ONE un-batched giant filter (contrast `sync_historical_events`
at `mod.rs:974-989` which chunks 1000-block batches), so a huge range typically gets
rejected by the provider → up to 5 retries with `RETRY_TIMEOUT_SECONDS` sleeps
(`mod.rs:936-958`), then returns. Per-call cost is bounded; the primitive is repetition.

### 3. Downstream enforcement — STANDS
No lower layer re-checks auth for these sends. The send is unconditional once the method
is entered. Merge-time validation prevents forgery (already counted in #2) but does not
prevent the wasted external-RPC work, which is the claimed harm.

### 4. PR HEAD currency — STANDS
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, identical to pin. No drift.

### 5. Spec carve-out — PARTIALLY MITIGATES
`admin_server.rs:101` carries the author comment: "This should probably go in a separate
'DebugService' that's not mounted for production." This is an acknowledgement that the
admin surface is debug-flavored and ideally not production-mounted — but it is NOT a
documented "intentionally unauthenticated" carve-out, and the code DOES mount it in
production whenever `admin_rpc_auth` is set. The two retry methods being unauthenticated
while sibling methods are authenticated is clearly an oversight, not a documented design
choice. Finding stands; the comment slightly softens it to "known-rough surface."

### 6. Reachability of harm — STANDS (gated by #1 bind + rate limit)
When `rpc_address` is public and `admin_rpc_auth` is set, an anonymous client reaches
the unguarded methods and triggers real external-RPC work. Amplification is capped by
the gRPC per-IP rate limiter (120 req/min/IP, `main.rs:288`) which DOES apply to the
shared socket connection layer. So sustained but rate-limited grief. Medium is appropriate.

### 7. Test wiring — STANDS
Receivers are subscribed in production run-loops (`main.rs:1026/1042/1063`), gated only on
`!fnames.disable` and non-empty onchain RPC URLs (normal validator config). Buggy path is
production-reachable, not test-only. If a node runs without those connectors, `.send()`
returns Err → `Status::internal`, no work — a no-op, not a crash.

### 8. PoC mechanics — NEEDS_MORE_DATA
No executable PoC is attached. The prose is supported by static evidence (guard absence +
mount + downstream wiring), all independently confirmed above. A PoC would need to assert
that an unauthenticated gRPC call to `retry_onchain_events` returns `Ok(Empty)` AND that
`get_logs` fires — the latter requires a live L1 endpoint. Claim is evidentially sound
without a PoC; absence of PoC is a completeness gap, not a correctness defect.

## Overall

Verdict: HAS_CAVEATS. Confidence 0.8.

The technical core is correct and independently confirmed at every step: the two retry
methods genuinely lack any auth/network guard, they are mounted raw (no interceptor) on
the shared gRPC socket, and the downstream external-RPC work is production-wired. Two
caveats keep this from WATERPROOF:
1. Mis-attribution in the body: gating is `admin_rpc_auth`, not `rpc_auth` (cosmetic;
   substance holds).
2. Reachability requires the operator to bind `rpc_address` publicly — the default is
   loopback with an explicit security comment. So the precondition is "public hub
   posture," not "out-of-the-box." Medium severity is justified for that posture
   (DoS/resource-grief, no state forgery, rate-limited amplification); it would be Low
   if scoped to the default loopback bind.

## Open follow-ups (NOT new findings)
- `rpc_extensions.rs:184` `password == parts[1]` non-constant-time compare — already noted
  in the finding body as a secondary observation; confirmed present. Timing side-channel on
  admin password, low severity.
- `rpc_extensions.rs:155-157` fail-open on empty `allowed_users` — confirmed; also guards
  `HubService::submit_message` (`server.rs:1192`) / submit_bulk. Intentional "auth disabled"
  mode per the localhost-default comment; flagged for the specialist's awareness only.

---

## F045 — Universal control-plane signatures (propose/cancel-upgrade, pause, owner-rotate) replay onto lagging canonical deployments; the per-deployment watermark is not a sound cross-deployment replay defense

## Summary

`HypersnapBridge` deliberately makes six payloads **universal** (no chainId,
no contract-address binding): `MERKLE_ROOT_UPDATE`, `OWNER_UPDATE`,
`OWNER_ACCEPTANCE`, `UPGRADE`, `UPGRADE_CANCEL`, `PAUSE`. The same threshold
group key signs them, and the same signature is intended to be relayed to
**every** canonical deployment on every chain. The only stated defense against
cross-deployment / cross-chain replay is the "strictly-monotonic 64-bit
block-number watermark" (`latestBlock`).

The watermark is **per-deployment storage that advances independently and at an
attacker-influenceable rate**. It only rejects a signature whose `blockNumber`
is `<=` *that deployment's local* `latestBlock`. It does **not** prevent a
universal signature from being applied to any deployment that has not yet
locally advanced past its block number. Because relay is permissionless and
unsynchronized — and an attacker is also a relayer who can withhold newer
signatures from a chosen deployment — a low-traffic / lagging deployment can be
kept at a stale watermark and then fed an old, **already-superseded** universal
signature that it has never consumed. The watermark provides no protection in
this case: it cannot tell that a `proposeUpgrade(block=N)` was later
`cancelUpgrade`d on a different deployment; it only checks `N > localWatermark`.

The value/claim path is **not** affected (leaf embeds `destinationChainId`,
`claim` enforces it at L183, and `claimed[lockId]` is per-deployment), so
cross-chain double-claim of a value leaf is correctly blocked. The defect is
confined to — and is serious in — the **control plane**, where the worst case
is an attacker-driven UUPS implementation swap (total custody theft) on the
lagging deployment.

## Where

`contracts/src/HypersnapBridge.sol`:

- Domain constants L53-58 — all six universal domains.
- Watermark gate, repeated per universal entry point:
  - `claim` root-update: `if (blockNumber > latestBlock)` (L188), else exact
    `(blockNumber, merkleRoot)` match (L199).
  - `rotateOwner`: `if (blockNumber <= latestBlock) revert StaleBlock` (L235).
  - `proposeUpgrade`: L276.
  - `cancelUpgrade`: L321.
  - `pause`: L362.
- Universal digests bind only `(domain, bytes8(blockNumber), payloadFields)` —
  e.g. `proposeUpgrade` digest L281-285, `cancelUpgrade` digest L325-329.
  Neither `block.chainid` nor `address(this)` is in any universal preimage.
- Per-deployment state: `latestBlock` (L90), `pendingImplementation` /
  `pendingUpgradeEffectiveAt` (L96, L98) all live in this contract's storage,
  independent of every other deployment.

Rust side (`crates/hypersnap-crypto/src/bridge_payload.rs`) matches byte-for-byte
and is pinned to the Solidity vectors (`cross_side_pinned_vectors`, L382). The
module header (L8-18) states the universal-vs-chain-specific split explicitly;
`upgrade_digest` (L133) and `upgrade_cancel_digest` (L147) bind only
`(tag, u64_be(block), addr)`. So this is **not** an encoding-asymmetry bug — the
two sides agree. The flaw is in the replay-defense model itself.

## Attack walk (no key compromise required)

Two canonical deployments share owner key `O`:
- Deployment A (busy chain): `latestBlock = 5000`.
- Deployment B (low-traffic chain holding real custody): `latestBlock = 100`.

1. Validators legitimately sign `proposeUpgrade(block=4000, implX, sigO)`,
   intending it for all chains. A relayer applies it on A.
2. A defect in `implX` is found. Validators sign
   `cancelUpgrade(block=4001, implX, sigO)`; a relayer applies it on A. A is
   clean — no pending upgrade.
3. The attacker (also a relayer) has the still-valid
   `proposeUpgrade(block=4000, implX, sigO)` bytes and **never relayed steps
   1-2 to B**, keeping B's watermark at 100.
4. Attacker submits `proposeUpgrade(4000, implX, sigO)` to **B**. B's gate
   `4000 > latestBlock(100)` passes (L276). `implX` becomes pending on B with a
   48h timer; B's watermark advances to 4000.
5. The `cancelUpgrade(4001)` exists, but the attacker withholds it from B; even
   if a defender relays it, the attacker only has to win the
   `executeUpgrade()` race after 48h. After execute, the cancelled-on-A
   implementation is live on B.

The monotonic watermark gives **zero** protection in step 4: cancellation does
not propagate across deployments, and `latestBlock` cannot encode "this propose
was superseded." Any superseded universal action stays live on every deployment
that has not locally advanced past its block number, and the attacker controls
B's advancement by selectively relaying.

## Higher-impact variant (compromised / rotated-out key)

The contract documents a key-compromise recovery (L266-270): rotate to `O2`
(immediate), then `O2` signs `cancelUpgrade`, so "the malicious upgrade's 48h
timer never fires." The lockout arithmetic in L64-71 (PAUSE 72h > UPGRADE 48h,
"24h guaranteed lockout") is **only valid on a deployment whose watermark is
current**. On a lagging deployment B, the holder of the old `O1` key can replay
any `O1`-signed universal payload whose block number lies in
`(B.latestBlock, rotationBlock)` — including a malicious
`proposeUpgrade(block, evilImpl, O1sig)` — because B never consumed those block
numbers and the rotation to `O2` (higher block) has not yet landed on B. The
attacker thus gets a head start that the contract's same-block-timestamp
analysis assumes away. The pause backstop helps only if defenders detect and
pause B in time; the watermark itself does not stop the replay.

## Watermark-coupling aggravator: `recoverERC20`

`recoverERC20` is the one chain-bound payload (digest binds `block.chainid`,
L402-409) yet it consumes the **same** global watermark (`latestBlock =
blockNumber`, L411). A recover applied on one chain burns a watermark slot that
universal payloads on *other* chains may also want, and vice-versa. Because the
signer must allocate one shared monotonic 64-bit counter across both
chain-bound and universal actions, the per-deployment watermarks legitimately
diverge over time — which is exactly what widens every universal payload's
cross-deployment replay window. This coupling makes "keep all deployments at the
same watermark" operationally impossible, so lagging deployments are the
expected state, not an edge case.

## Why this is not closed by existing mitigations

- **Watermark monotonicity:** rejects only sigs older than the *local*
  watermark. Superseded-but-newer-than-local sigs pass. Attacker controls local
  advancement by withholding relays.
- **`OWNER_ACCEPTANCE` has no watermark at all** (digest binds only `newOwner`,
  L247-250 / `owner_acceptance_digest` L127). It is replayable forever and
  everywhere; not directly exploitable alone (rotation still needs a fresh `O1`
  authorization sig), but it is a strict watermark-coverage gap worth recording.
- **Pause backstop:** mitigates but does not prevent; requires defenders to
  detect the targeted lagging deployment and land a higher-block pause before
  `executeUpgrade`.

## Impact

Cross-deployment replay of control-plane signatures on any deployment the
attacker can keep watermark-stale. Worst case: a superseded or
old-key-signed `proposeUpgrade` is replayed and executed, swapping the UUPS
implementation on a deployment holding live custody → total loss of that
deployment's funds. Lower-bound case: cancelled/superseded upgrades and pauses
remain live across the deployment set, defeating the documented incident-
response guarantees. Severity: high.

## Recommended fix

Bind every universal control-plane digest to the deployment identity so a
signature is no longer replayable across deployments:

- Include `block.chainid` AND `address(this)` (or a per-deployment
  `bytes32 deploymentId` set at `initialize`) in the preimage of
  `UPGRADE`, `UPGRADE_CANCEL`, `OWNER_UPDATE`, `OWNER_ACCEPTANCE`, and `PAUSE`
  on both the Solidity and `bridge_payload.rs` sides, and re-pin the cross-side
  vectors. The root-update path can remain universal because the leaf's embedded
  `destinationChainId` already isolates value per chain.
- Alternatively keep universal payloads but add a per-deployment, signed,
  monotonic *cancellation epoch* so a cancel on one chain cannot be out-run by a
  stale propose on another — but per-deployment digest binding is simpler and
  removes the entire class.
- Add a watermark (or full deployment binding) to `OWNER_ACCEPTANCE`.
- Decouple `recoverERC20` from the universal watermark namespace (e.g. a
  separate per-chain recover nonce) so chain-bound actions stop perturbing the
  universal watermark.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.85
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

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

---

## F047 — Owner rotation has no priority over other watermark-consuming actions; a compromised old owner front-runs the recovery `rotateOwner` to retain power or seize permanent ownership, defeating the documented "immediate rotation" key-compromise recovery

## Summary

`rotateOwner` is an atomic one-shot rotation gated solely by the shared
strictly-monotonic 64-bit watermark (`blockNumber > latestBlock`). It shares
that single watermark namespace with every other owner-signed universal action
(`pause`, `proposeUpgrade`, `cancelUpgrade`, the `claim` root-advancement) and
with `recoverERC20`. Rotation has **no priority** over those actions and the
on-chain digests are public the instant a rotation transaction enters the
mempool.

The contract's documented key-compromise recovery (L266-270) rests on the
premise that `rotateOwner(... O2 ...)` is "immediate, no delay" and therefore
out-runs the 48h upgrade timer. That premise is false in the exact scenario it
is written for. Because the **compromised old key `O1` is still the owner until
the rotation actually lands**, the attacker holding `O1` can watch the mempool
for the defenders' `rotateOwner(block=N, O2, …)` and front-run it with any
`O1`-signed, watermark-consuming action whose `blockNumber >= N`. That bumps
`latestBlock >= N`, so the legitimate rotation reverts with `StaleBlock` and
never lands. Repeated each round, the attacker indefinitely starves the
rotation — the compromised owner retains power.

The decisive escalation: the attacker can front-run with their **own**
`rotateOwner(block=N, O_attacker, authSig_O1, acceptSig_O_attacker)`. The
attacker holds `O1` (signs the authorization) and controls `O_attacker` (signs
the acceptance), so both gates pass and `ownerAddress` becomes `O_attacker`
**permanently** — the attacker wins the rotation race outright and the
legitimate `O2` rotation is now stale forever. This directly realizes the
hunt's "attacker becomes owner / old owner retains power after rotation."

## Where

`contracts/src/HypersnapBridge.sol`:

- `rotateOwner` (L229-258). Gate `if (blockNumber <= latestBlock) revert
  StaleBlock` (L235); on success `latestBlock = blockNumber; ownerAddress =
  newOwner` (L255-256). No priority, no commit/reveal, no per-action nonce.
- Authorization digest binds only `(DOMAIN_OWNER_UPDATE, bytes8(blockNumber),
  bytes20(newOwner))` (L238-242). Acceptance digest binds only
  `(DOMAIN_OWNER_ACCEPTANCE, bytes20(newOwner))` (L247-250) — no block, no
  chainId, so an `O_attacker` acceptance sig is trivially producible offline by
  the attacker and is reusable forever.
- Shared watermark consumers that an attacker holding `O1` can use to front-run
  / bump `latestBlock`: `proposeUpgrade` L276/L306, `cancelUpgrade` L321/L331,
  `pause` L362/L368, `recoverERC20` L399/L411, and the `claim` root-advancement
  L188/L195. All set `latestBlock = blockNumber` after an `O1` ecrecover, so any
  of them at `block >= N` invalidates a pending `rotateOwner(block=N)`.
- The recovery narrative that this breaks: L266-270 ("rotate … immediate, no
  delay") and the lockout arithmetic L64-71.

Rust side encodes the identical preimages and is pinned to the Solidity vectors
(`crates/hypersnap-crypto/src/bridge_payload.rs::owner_update_signing_payload`
L97, `owner_acceptance_signing_payload` L115, `cross_side_pinned_vectors`
L382). `src/hyper/runtime.rs::produce_signed_owner_rotation_local` (L1066) /
`apply_owner_rotation` (L1130) drive the same `(block_number, new_owner)`
authorization + `new_owner`-only acceptance, confirming the off-chain pipeline
matches and offers no extra anti-front-run binding. This is **not** an encoding
asymmetry; the defect is the on-chain race model.

## Attack walk (key-compromise recovery, single deployment, no cross-deployment lag required)

Preconditions: validator group key `O1` is compromised (the only scenario the
contract's recovery flow is designed for). Validators run a fresh DKG and obtain
`O2`; they sign `rotateOwner(block=N, O2, authSig_O1, acceptSig_O2)` and relay
it. `latestBlock` is currently `< N`.

1. The rotation tx sits in the public mempool. The attacker observes block `N`
   and `newOwner=O2`.
2. The attacker, still holding `O1`, signs and submits with higher priority fee
   **either**:
   - a grief: `pause(block=N, O1)` or `proposeUpgrade(block=N, evilImpl, O1)` —
     bumps `latestBlock = N`; the defenders' `rotateOwner(block=N)` now reverts
     `StaleBlock`; **or**
   - a seizure: `rotateOwner(block=N, O_attacker, authSig_O1,
     acceptSig_O_attacker)` — both signatures verify, `ownerAddress =
     O_attacker`, `latestBlock = N`. The defenders' rotation to `O2` is now
     permanently stale.
3. Defenders re-sign the rotation at `N+1` (another DKG-coordinated signing
   ceremony). The attacker repeats step 2 against `N+1`. The attacker only needs
   to win one mempool race per round and can keep `latestBlock` perpetually at
   or above the defenders' freshest rotation block. The compromised owner never
   relinquishes control; with the seizure variant the attacker is already the
   sole owner after a single won race.

No 48h timer, no lagging secondary deployment, and no withheld-relay setup is
required — the race is decided in the mempool of the very deployment under
recovery.

## Why existing mitigations do not close it

- **Watermark monotonicity**: it is precisely the weapon here. The attacker uses
  the shared counter to invalidate the rotation; monotonicity gives the
  *first-landed* `block>=N` action the win, and the attacker can always be first
  by fee.
- **Acceptance "proof of key possession"**: only proves the named `newOwner`
  controls a key. The attacker names `O_attacker` and supplies its own
  acceptance, so the gate is satisfied by the attacker, not bypassed.
- **Pause backstop**: pause is itself an `O1`-signed, watermark-consuming action
  — using it as a defense consumes the same counter and is equally front-runnable
  by the attacker; it cannot be landed "for free" ahead of the attacker.
- **Two-step nature**: there is no on-chain pending-owner state, so there is no
  accept-window to protect; the entire rotation is one tx and the race is on
  *landing* that tx, not on a separate accept.

## Dedup note

Related to **F047 (this finding)** is **F045** (claim-signature-replay):
F045 concerns *cross-deployment* replay of already-superseded universal
signatures onto a deliberately lagging deployment B, and notes the
`OWNER_ACCEPTANCE` watermark gap in passing. This finding is a distinct
*owner-rotate-race* on a *single* deployment: a same-mempool front-run that
defeats the documented immediate-rotation recovery and lets the attacker seize
or retain ownership without any second deployment or withheld relay. Shared root
cause family (universal/shared-watermark control plane) but different exploit
primitive and different broken guarantee; should be linked, not merged.

## Impact

In the one scenario the recovery flow exists to handle — a stolen group key —
the recovery is defeatable: the attacker either livelocks every rotation attempt
(old compromised owner retains full bridge control: mint via `claim`
root-advancement, `proposeUpgrade` to a custody-draining implementation, etc.)
or, in the stronger variant, becomes the permanent sole owner in a single won
mempool race. This is total, persistent loss of bridge control during incident
response. Severity: high.

## Recommended fix

Give rotation a path that cannot be starved by other watermark consumers, and
remove the front-run primitive:

- Decouple `rotateOwner` from the shared monotonic watermark: gate it on a
  **dedicated, rotation-only** monotonic counter (`ownerRotationBlock`) so that
  `pause` / `proposeUpgrade` / `cancelUpgrade` / `recoverERC20` / root-update can
  never invalidate a pending rotation, and vice versa.
- Bind the authorization digest to the **current** `ownerAddress` (the key being
  rotated out) and to deployment identity (`block.chainid` + `address(this)`),
  so an attacker cannot reuse a captured `O1` authorization to install a
  *different* `newOwner` of their choosing — the captured sig is valid only for
  the exact `(currentOwner -> O2)` transition the defenders signed. (Combine with
  F045's deployment-binding recommendation.)
- Bind the acceptance digest to `blockNumber` (and deployment identity) so an
  acceptance cannot be pre-fabricated/relayed independently of the specific
  rotation it belongs to.
- Consider a short commit/reveal or a "highest-block-wins within the tx"
  selection that lets a freshly signed legitimate rotation supersede an
  attacker's same-block action deterministically, rather than first-to-land.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.85
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

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

---

## F048 — Pause does not gate proposeUpgrade, so an attacker who defers the malicious propose to land effectiveAt at/after pauseExpiry erases the documented 24h "guaranteed lockout" cushion

## Summary

`HypersnapBridge` documents a pause-vs-upgrade timing guarantee (L64-71 and
L341-345): because `PAUSE_DURATION` (72h) is strictly longer than
`UPGRADE_DELAY` (48h), a defensive `pause` is claimed to give validators a
"24h guaranteed lockout window" to land `cancelUpgrade` against a malicious
`proposeUpgrade`, and `pause` is claimed to "block all execute attempts for 48h,
giving cancel ample time to land."

That guarantee holds **only** for the specific scenario analyzed in the comment:
the malicious `proposeUpgrade` landing in the *same* `block.timestamp` as (or
earlier than) the defensive `pause`. It does **not** hold for the genuine worst
case, because **`proposeUpgrade` is not gated by `whenNotPaused`** (L271-311).
Only `claim`, `burn`, and `executeUpgrade` carry the modifier. An attacker can
therefore call `proposeUpgrade` *during* an active pause and freely choose the
propose timestamp so that the upgrade's `effectiveAt` coincides with — or
exceeds — `pauseExpiry`, collapsing the defender's cushion to zero. A single
pre-signed pause does not durably outlast a late-proposed upgrade.

## Where

`contracts/src/HypersnapBridge.sol`:

- `whenNotPaused` modifier (L165-168): reverts when `block.timestamp <
  pauseExpiry` (strict `<`; pause is inactive at `block.timestamp ==
  pauseExpiry`).
- `pause` (L361-372): sets `pauseExpiry = uint64(block.timestamp) +
  PAUSE_DURATION` (L369). One-shot, auto-expiring, no unpause.
- `proposeUpgrade` (L271-311): **no `whenNotPaused`**. Sets `effectiveAt =
  uint64(block.timestamp) + UPGRADE_DELAY` (L307). Callable while paused; the
  only structural gate is the watermark (L276) and the single-pending-slot
  guard `pendingImplementation == address(0)` (L278).
- `executeUpgrade` (L346-355): `whenNotPaused` (L346) + `block.timestamp <
  effectiveAt` (L350).
- The asserted guarantee lives in the L64-71 storage-comment block and the
  L341-345 `executeUpgrade` doc-comment.

## Why the documented arithmetic is incomplete

The comment models the worst case as `T_prop == T_pause == T`:

- `pause`  → effective on `[T, T + 72h)`
- `propose`→ execute-ready on `[T + 48h, inf)`
- execute blocked by pause until `T + 72h`; defender cushion =
  `[T + 48h, T + 72h)` = 24h. (Correct, for this ordering.)

But `T_prop` is attacker-controlled and unconstrained by the pause. Let the
defender pause at `T_pause = 0`, so `pauseExpiry = 72h`. The attacker waits
inside the pause window and proposes late:

- Attacker calls `proposeUpgrade(evilImpl)` at `T_prop = 24h` (pause still
  active; propose is not pause-gated). Then `effectiveAt = 24h + 48h = 72h`.
- `executeUpgrade` is blocked while `block.timestamp < pauseExpiry (= 72h)` and
  while `block.timestamp < effectiveAt (= 72h)`. **Both gates clear at exactly
  `block.timestamp == 72h`**, so the attacker executes the upgrade in the same
  block the pause lapses. Defender cushion = **0h**.
- If the attacker proposes at `T_prop = 24h + epsilon`, then `effectiveAt =
  72h + epsilon > pauseExpiry`; execute fires immediately once the pause
  expires, again with no protective overlap.

Generalizing: a single pause beginning at `T_pause` only blocks execute of an
upgrade whose `effectiveAt` falls before `pauseExpiry`. The attacker sets
`effectiveAt = T_prop + 48h >= pauseExpiry` by choosing
`T_prop >= pauseExpiry - 48h` (i.e. any time in the final 24h before the pause
expires, all of which is inside the pause window). The "24h guaranteed lockout"
and the "block all execute attempts for 48h" claims are both violated for this
ordering.

## Impact

The pause backstop the code relies on for upgrade incident response is not the
fire-and-forget guarantee it is documented to be. A single threshold-signed
pause does not durably hold off a malicious upgrade; the attacker, who can
relay `proposeUpgrade` permissionlessly even while paused, drives the
defender's guaranteed cancel-landing window to zero by deferring the propose
to the tail of the pause window.

The primary remedy — `cancelUpgrade`, signed by the (possibly freshly rotated)
owner — remains available and, on a current-watermark deployment, an attacker
cannot bump `latestBlock` past the defender's fresh cancel signature, so the
incident is still recoverable *if* validators produce and land a fresh cancel
in time. This is therefore a degradation of a documented defense-in-depth
guarantee (shrinking, to zero, the window the protocol promises defenders) and
a contradiction between the security comments and the implementation, rather
than unconditional standalone fund loss. It compounds with F045: on a lagging
deployment where the cancel guarantee is already void, the pause backstop being
defeatable removes the last line of defense before a UUPS implementation swap
and total custody loss. Severity: medium.

## Recommended fix

Make the pause actually halt the upgrade *pipeline*, not just the final
`executeUpgrade` step, so the documented arithmetic becomes sound:

1. Gate `proposeUpgrade` with `whenNotPaused` (and/or reset any in-flight
   pending-upgrade timer when a pause lands). If propose cannot occur during a
   pause, the same-timestamp worst case in the comment becomes the actual worst
   case and the 72h > 48h cushion holds.
2. Alternatively, on `pause`, push any existing `pendingUpgradeEffectiveAt`
   out to at least `pauseExpiry` (and forbid `effectiveAt < pauseExpiry` at
   propose time while paused), so no upgrade can become executable before the
   pause it raced is guaranteed to have expired plus the cancel margin.
3. Correct the L64-71 / L341-345 comments: a single pause only blocks upgrades
   whose `effectiveAt < pauseExpiry`; without (1)/(2), validators must be told
   they may need to re-pause (fresh signature, higher watermark) rather than
   rely on one pre-signed pause.

### Validation

- Verdict: **WATERPROOF**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F048 validation — pause does not gate proposeUpgrade (late-propose erases lockout window)

Validator: validator (deliberate-disagreement). Code @ cab225f (read-only).
Finding severity_initial: medium.

## Core claim verification (file:line)

- `whenNotPaused` modifier — `HypersnapBridge.sol:165-168`: `if (block.timestamp < pauseExpiry) revert BridgePaused(pauseExpiry);` — STRICT `<`. Pause is INACTIVE at `block.timestamp == pauseExpiry`. Confirmed.
- `proposeUpgrade` — `:271-311`: signature `external` with NO `whenNotPaused`. Confirmed missing. Only gates: watermark `blockNumber <= latestBlock` (:276), zero-addr (:277), single-pending-slot `pendingImplementation != address(0)` (:278), owner sig (:286), UUPS-compat staticcall (:298). Sets `effectiveAt = uint64(block.timestamp) + UPGRADE_DELAY` (:307). Confirmed callable while paused.
- `executeUpgrade` — `:346`: `external whenNotPaused`; `:350` `block.timestamp < effectiveAt` strict `<`. Confirmed.
- `pause` — `:361-372`: `pauseExpiry = block.timestamp + PAUSE_DURATION` (:369). One-shot, auto-expiring. Confirmed.
- Documented guarantee — `:64-71` storage comment ("24h guaranteed lockout window … even in the adversarial same-block-timestamp scenario") and `:341-345` executeUpgrade doc ("block all execute attempts for 48h, giving cancel ample time to land"). Both present verbatim. Confirmed.
- `PAUSE_DURATION = 72h` (:70), `UPGRADE_DELAY = 48h` (:71). Confirmed.

## Arithmetic re-derivation (independent)

Defender pause at T=0 ⇒ pauseExpiry=72h. Attacker proposes at T_prop=24h (pause still active, propose not gated) ⇒ effectiveAt=24h+48h=72h.
At block.timestamp == 72h:
- whenNotPaused: `72 < 72` == false ⇒ passes (strict `<`, pause inactive exactly at expiry).
- executeUpgrade timer: `72 < 72` == false ⇒ passes.
Both gates clear in the SAME block ⇒ defender cushion collapses from documented 24h to 0h. Arithmetic SOUND. The comment's "same-timestamp" worst case is NOT the genuine worst case because T_prop is attacker-controlled and unconstrained by pause.

## 8-hypothesis walk

1. **Upstream auth / gate** — STANDS. No upstream pause check on proposeUpgrade exists. proposeUpgrade requires owner sig — but in the threat model the owner key is compromised (this is the key-compromise recovery scenario the comments address), so the attacker holds a valid owner sig. The watermark gate (:276) only enforces monotonic blockNumber, not pause state. Nothing upstream halts propose during pause.

2. **Consumer-side impact** — PARTIALLY INVALIDATED (impact bounded, as finding already states). The "corrupted state" is the pending upgrade landing executable with zero pause-overlap. The consumer is `executeUpgrade` → `ERC1967Utils.upgradeToAndCall` (:354) = real implementation swap = total custody loss IF it lands. BUT the finding itself caps impact: `cancelUpgrade` (:316-335) remains available with no pause gate, so a freshly-rotated owner can still clear the pending impl. Net: this is degradation of a documented defense-in-depth window, not standalone unconditional theft. The Medium rating already reflects this. No overstatement beyond what the body concedes.

3. **Downstream enforcement** — STANDS. Does any layer below re-block execute? executeUpgrade's only two gates are whenNotPaused and the effectiveAt timer; both are shown to clear simultaneously. cancelUpgrade is a *parallel* remedy (race), not a downstream enforcement that automatically catches the bug. No automatic backstop.

4. **PR HEAD currency** — STANDS. Workspace pinned at cab225f; `git log -1` HEAD == cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (2026-06-08). Lines cited match current file. No drift.

5. **Spec carve-out** — STANDS / strengthens finding. The doc-comments at :64-71 and :341-345 do NOT say "deferred/known-incomplete"; they affirmatively CLAIM the 24h guarantee and "block all execute attempts for 48h." So this is a code-vs-documented-guarantee contradiction (the worst kind for a security comment), not an acknowledged limitation. No carve-out exists.

6. **Reachability of harm** — STANDS (conditional, as bodied). Attacker needs a valid owner sig for proposeUpgrade — i.e. this only bites in the key-compromise scenario, which is precisely the scenario the pause guarantee was written for. Reachable within that model. The harm (execute landing with 0h cushion) is reachable; the *remedy* (cancel) is also reachable, so harm = "guaranteed defensive window reduced to a tight race," reachable and real, bounded as the finding states.

7. **Test wiring** — STANDS. proposeUpgrade/executeUpgrade/pause are production external functions on the deployed bridge contract (UUPS proxy target), not test-only. They are the live upgrade pipeline.

8. **PoC mechanics** — NEEDS_MORE_DATA (no executable PoC supplied), but the analytical proof is self-contained and the arithmetic is independently re-derived above and checks out. The two strict-`<` comparisons clearing in the same block is verifiable by inspection; no PoC needed to establish the timing collapse. The prose claim ("cushion = 0") is exactly what the arithmetic proves — no assertion-vs-claim mismatch.

## Severity judgment

Medium is appropriate. Standalone, this is a defense-in-depth degradation: the pause backstop is not the fire-and-forget guarantee documented, but cancelUpgrade still offers recovery on a current-watermark deployment. It is NOT standalone fund loss. Agree with finder's Medium.

## Shared-root-cause / dedupe note

- F048 root cause: missing `whenNotPaused` on proposeUpgrade + strict-`<` boundary alignment defeating the documented 72h>48h timing cushion. This is a PAUSE-vs-UPGRADE-TIMING bug.
- F045 (high): universal sig cross-deployment replay — different root cause (signature scoping / watermark not deployment-bound). F048 explicitly notes it *compounds* with F045 (on a lagging deployment the cancel remedy is void). Related-by-compounding, NOT same root cause.
- F047 (high): rotateOwner has no priority over other watermark consumers (front-run race). Different root cause (watermark ordering / no rotate priority).
- F049 (high): single max-block sig saturates shared watermark, bricking rotate/cancel while watermark-independent executeUpgrade survives. Different root cause (watermark saturation), though it ALSO concerns the cancel-vs-execute race from a different angle.
- Recommend: link F048 as RELATED to F045/F047/F049 (shared upgrade/pause/watermark control-plane theme + compounding interactions) but DO NOT merge — each has a distinct mechanism and fix. F048's fix (gate proposeUpgrade with whenNotPaused, or push effectiveAt past pauseExpiry on pause) is independent of the watermark fixes.

## Open follow-ups (not new findings)

- Even WITH the recommended fix (1) [gate proposeUpgrade], an upgrade proposed just before a pause (effectiveAt already set) is unaffected by a later pause unless fix (2) [push effectiveAt to >= pauseExpiry on pause] is also applied. The finder lists both; worth ensuring any patch adopts (2) or the timer-reset, not just (1). Noted for the specialist, not a separate finding.

## Overall

Verdict: WATERPROOF (core mechanism + arithmetic confirmed at file:line; impact correctly self-bounded to Medium; comment-vs-code contradiction is real and not carved out).
Confidence: 0.9 (deduction: no executable PoC, but analytical proof is complete and re-derived).

---

## F049 — A single max-block universal signature saturates the shared watermark, permanently disabling rotateOwner/cancelUpgrade while the watermark-independent executeUpgrade still fires the pending (malicious) implementation

## Summary

`HypersnapBridge` gates every *universal* control-plane ceremony
(`claim` root-update, `rotateOwner`, `proposeUpgrade`, `cancelUpgrade`, `pause`)
on a single shared 64-bit watermark `latestBlock` with the rule
"`blockNumber > latestBlock`, then `latestBlock = blockNumber`". There is **no
upper bound / sanity cap** on the signed `blockNumber` anywhere — not in the
contract, not in the Rust digest builders (`bridge_payload.rs`).

The contract's documented incident-response (L266-270) is: rotate the owner to a
fresh key `O2` (immediate, no delay), then have `O2` sign `cancelUpgrade` so "the
malicious upgrade's 48h timer never fires." That recovery path depends on
`rotateOwner` and `cancelUpgrade` still being callable. Both require
`blockNumber > latestBlock`.

A signer who can produce one universal signature with `blockNumber =
type(uint64).max` (2^64-1) sets `latestBlock = 2^64-1`. After that, **every**
universal ceremony reverts `StaleBlock` forever, because no `uint64` can be
strictly greater than `2^64-1`. `rotateOwner` is dead, `cancelUpgrade` is dead,
`claim` root advancement is dead, and re-`pause` is dead — **permanently, even
after a fresh DKG produces a clean key**.

Meanwhile `executeUpgrade()` (L346-355) reads **only** `pendingImplementation`,
`pendingUpgradeEffectiveAt`, and `pauseExpiry` — it has **no watermark
dependency, no signature, and is permissionless**. So if a pending malicious
upgrade exists, the attacker:

1. lands `proposeUpgrade(N, evilImpl, sig)` (starts 48h timer), and
2. lands `pause(2^64-1, sig)` and/or any universal payload at `2^64-1` to
   saturate the watermark — this simultaneously blocks `executeUpgrade` for the
   pause window AND **permanently disables the rotate-then-cancel recovery the
   contract relies on**, then
3. after the 72h pause auto-expires, calls the permissionless `executeUpgrade()`
   — which still fires because it never consults `latestBlock`.

The defenders can never cancel (watermark saturated) and can never rotate to a
key that could cancel (watermark saturated). The pending implementation
executes. This is a direct, total custody-loss path and a permanent brick of the
control plane.

## Where

`contracts/src/HypersnapBridge.sol`:

- Watermark is a raw `uint64 latestBlock` (L90) with no max guard.
- Saturation-capable gates (each is `blockNumber <= latestBlock` revert, then
  `latestBlock = blockNumber`, with no cap on the supplied value):
  - `rotateOwner` L235 / L255
  - `proposeUpgrade` L276 / L306
  - `cancelUpgrade` L321 / L331
  - `pause` L362 / L368
  - `claim` root-update L188 / L195
  - `recoverERC20` L399 / L411
- `executeUpgrade` L346-355: gated only by `whenNotPaused` and
  `block.timestamp >= pendingUpgradeEffectiveAt`. **No `latestBlock` read, no
  signature, `external` and permissionless.**
- `rotateOwner` does NOT clear `pendingImplementation` / `pendingUpgradeEffectiveAt`
  (L255-257), so a pending upgrade survives any rotation by construction — the
  only way to remove it is `cancelUpgrade`, which the saturation has disabled.

Rust side (`crates/hypersnap-crypto/src/bridge_payload.rs`): every digest builder
(`pause_digest` L158, `upgrade_digest` L133, `owner_update_digest` L108, etc.)
takes a raw `block_number: u64` and serializes `block_number.to_be_bytes()` with
no range check. The off-chain side imposes no ceiling either; the contract is the
sole gate and it has none.

## Attack walk (key-compromise scenario — the contract's own threat model)

The upgrade-flow doc (L266-270) explicitly scopes "a key-compromise scenario."
In that model the attacker holds the threshold key and can sign any universal
payload at any block number.

Pre-conditions: attacker holds owner key `O1`; a fresh DKG yields clean key `O2`
that defenders will rotate to.

1. Attacker signs and lands `proposeUpgrade(blockNumber = 10, evilImpl, O1sig)`.
   `pendingImplementation = evilImpl`, `effectiveAt = now + 48h`,
   `latestBlock = 10`.
2. Attacker signs and lands `pause(blockNumber = 2^64-1, O1sig)`.
   `pauseExpiry = now + 72h`, **`latestBlock = 2^64-1`**.
3. Defenders run DKG → `O2` and try the documented recovery:
   - `rotateOwner(blockNumber = X, O2, ...)` — for any `X <= 2^64-1` this reverts
     `StaleBlock(2^64-1, X)`. There is no valid `X`. **Rotation impossible.**
   - `cancelUpgrade(blockNumber = X, evilImpl, ...)` — same `StaleBlock` revert
     regardless of who signs. **Cancel impossible.**
   - re-`pause` — same. Defenders cannot even extend the pause.
4. 72h later `pauseExpiry` is in the past. Anyone (the attacker) calls
   `executeUpgrade()`. It passes `whenNotPaused` (pause expired) and
   `block.timestamp >= effectiveAt` (48h < 72h elapsed), and swaps the proxy to
   `evilImpl` via `ERC1967Utils.upgradeToAndCall`. **Total custody theft.**

The contract's L64-71 "24h guaranteed lockout window" arithmetic
(PAUSE 72h > UPGRADE 48h) is the analysis the attacker inverts: the pause is used
*by the attacker* not to protect but to (a) run out the clock cheaply and (b)
saturate the watermark in the same step. Even ignoring the pause, step 2's
saturation alone permanently kills the rotate/cancel recovery; the pending
upgrade then executes on its own 48h timer.

## Lower-bound variant (no pending upgrade)

Even with no malicious upgrade, a single `pause(2^64-1)` (or root-update at
`2^64-1` via the `claim` path) permanently bricks the entire control plane:
the owner can never be rotated, the root can never be advanced again (freezing
all future inbound claims), and the bridge can never be re-paused or recovered.
This is an unrecoverable denial-of-service of the bridge with one signature.

## Why existing mitigations do not close it

- **Monotonic watermark:** the very mechanism abused. Monotonicity guarantees the
  counter can only go up; the absence of a cap lets it go up to the type max in a
  single step, after which monotonicity guarantees it can never move again.
- **Two-step owner rotation / acceptance:** irrelevant — `rotateOwner` itself is
  gated by the saturated watermark and never reaches the acceptance check.
- **Pause backstop / 72h > 48h timing:** does not help, because the recovery
  actions the timing is meant to enable (rotate + cancel) are exactly what the
  saturation disables; and `executeUpgrade` ignores the watermark entirely.
- **F045** documents *cross-deployment* replay of universal sigs (a different
  failure mode: superseded sigs surviving on lagging deployments). This finding
  is **single-deployment**: the permanent saturation/brick of the watermark
  namespace and the resulting inability to cancel a surviving pending upgrade,
  combined with `executeUpgrade`'s watermark-independence. The two are
  complementary, not duplicates.

## Impact

- Permanent, unrecoverable disablement of `rotateOwner`, `cancelUpgrade`,
  `pause`, and `claim` root-advancement via one max-block universal signature.
- When chained with a pending `proposeUpgrade`, the documented key-compromise
  recovery becomes impossible while the permissionless `executeUpgrade` still
  fires the attacker's implementation → total loss of the deployment's custody.
- Severity: high (direct custody-theft path under the contract's own stated
  threat model, plus an unconditional permanent-DoS variant).

## Recommended fix

- Bound the accepted `blockNumber` on every universal entry point to a sane
  forward window relative to a trusted reference (e.g. require
  `blockNumber <= latestBlock + MAX_BLOCK_ADVANCE`, or bind/clamp to the real
  L1 `block.number`/an oracle of the hyperchain height) so a single signature
  cannot jump the watermark to `type(uint64).max`. Apply the same bound in
  `bridge_payload.rs` so honest signers never produce out-of-range block numbers.
- Decouple the upgrade-recovery actions from the saturable namespace: gate
  `cancelUpgrade` (and ideally `rotateOwner`) on a *separate* monotonic counter,
  or allow `cancelUpgrade` by the current owner without consuming/advancing the
  shared watermark, so cancel can never be locked out by an unrelated payload.
- Consider giving `executeUpgrade` a defensive check that the current owner has
  not changed since `proposeUpgrade` (snapshot `ownerAddress` at propose time and
  require it unchanged, or require a fresh owner co-sign at execute), so a
  surviving pending upgrade cannot outlive the key that authorized it.

### Validation

- Verdict: **WATERPROOF**, confidence 0.88
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

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

---

## F068 — Empty-text CastAdds (embed/mention/reply-only) permanently evade the per-message fee

# Summary

A `CastAdd` whose `text` is empty but which carries an embed, a mention,
or a parent (i.e. an embed-only post, a reply, or a mention-only post) is
a fully valid, fee-bearing message, yet it is **always charged a fee of
zero** — no matter how many identical or spammy ones the sender posts.
The fee mechanism (FIP-proof-of-quality §4) is supposed to make spam
costly for low-trust users; this lets a low-trust/zero-trust attacker
emit unbounded embed-only and reply casts at zero cost, defeating the
anti-spam fee for that entire message subtype.

The debit==burn+proposer conservation invariant itself is **intact**
(verified below); the defect is a systematic *charged-zero* path, which
is one of the explicit H068 hunt questions ("Can fee be skipped (charged
0) for some message types?").

# Root cause

The effective fee is `base × max(0, 1 − max(trust, uniqueness))`
(`crates/proof-of-quality/src/fees.rs:58`). For a zero-trust sender the
fee is fully determined by `uniqueness`: `uniqueness == 1.0` ⇒ fee 0.

For CastAdd, `FeeCharger::stage_fee` derives uniqueness from the cast's
`text` only (`src/hyper/fee_charger.rs:107-121`):

```rust
let uniqueness = if class == FeeClass::CastAdd {
    let text = data.body.as_ref().and_then(|b| match b {
        proto::message_data::Body::CastAddBody(c) => Some(c.text.as_str()),
        _ => None,
    }).unwrap_or("");
    self.fingerprint_store.uniqueness_score(text, data.timestamp as u64, batch)?
} else { 1.0 };
```

`uniqueness_score` measures near-duplication against the rolling
fingerprint window. The window is populated by
`record_fingerprint_if_cast`, which is called after a successful merge —
but it **early-returns for empty text** (`src/hyper/fee_charger.rs:167`):

```rust
if text.is_empty() {
    return Ok(());
}
self.fingerprint_store.stage_insert(data.fid, text, ...);
```

So the two halves of the cast-uniqueness machinery disagree on empty
text:

1. `stage_fee` *scores* empty text (`uniqueness_score("")`), but
2. `record_fingerprint_if_cast` *never inserts* a fingerprint for empty
   text.

Because no empty-text fingerprint is ever written, the empty-text
SimHash bucket stays permanently empty. Every empty-text cast therefore
sees `near_dup_count == 0` ⇒ `uniqueness_score == 1.0`
(`src/hyper/fingerprint_store.rs:176`, via
`uniqueness_score_from_neighbor_count(0)`), and with any trust value
`compute_effective_fee_micro` returns 0 (`fees.rs:67-70`,
`(1.0 - 1.0).max(0.0) == 0.0`). `stage_fee` then hits the `fee == 0`
short-circuit (`fee_charger.rs:124`) and stages no charge.

Cast validation explicitly permits empty text as long as embeds,
embeds_deprecated, or mentions are present
(`src/core/validations/cast.rs:65-71` — `CastIsEmpty` only fires when
text AND embeds AND embeds_deprecated AND mentions are all empty). So
the zero-fee class is large and useful to a spammer:

- embed-only casts (link/image spam, each with a distinct embed URL),
- reply casts that carry only a parent + empty text,
- mention-only casts (tagging/notification spam).

A secondary contributor: uniqueness is scored over `text` alone and
ignores `embeds`, `embeds_deprecated`, `mentions`, and `parent`. Even
for non-empty text, two casts that differ only in their embed/parent are
treated as identical content; but the empty-text case is the clean,
unconditional bypass.

# Exploit

Sender FID with `trust == 0` (a brand-new/Sybil FID) wants to flood the
network:

1. Submit `CastAdd { text: "", embeds: [<unique URL>], type: Cast }`.
   Validation passes (has an embed). Merge succeeds.
2. `stage_fee`: `text == ""`, `uniqueness_score("") == 1.0` (bucket never
   populated), `effective_fee = 1_000_000 × max(0, 1 − 1.0) = 0` ⇒ no
   charge.
3. `record_fingerprint_if_cast`: `text.is_empty()` ⇒ no fingerprint
   written, so step 2 stays true forever.

Repeat unbounded. None of these casts ever require a fee deposit
(`apply_fee_deposit`) and none deplete `HyperFeeBalance`, so the
`HyperFeeInsufficient` gate in
`src/storage/store/engine.rs:1311-1331` never fires.

# Conservation invariant (verified sound)

For completeness, the in-scope debit/split arithmetic is correct:

- `split_burn_proposer(total)` returns `burn = total*6000/10000`,
  `proposer = total − burn`, so `burn + proposer == total` exactly for
  all `total` (`fees.rs:82-86`) — no minted or lost atoms.
- `stage_charge_message_fee` debits exactly `total` from the fee balance
  and increments the burn accumulator by `burn` and the proposer pot by
  `proposer` on the same batch (`rewards.rs:637-679`); the
  read-through-batch helpers (F132 fix) make this hold across multiple
  same-FID charges in one shard chunk.
- Underflow is guarded: `cur < total` ⇒ `InsufficientBalance` before any
  subtraction (`rewards.rs:646-653`).
- `compute_effective_fee_micro` floors and clamps the multiplier to
  `[0,1]`, so the fee can never exceed `base` (no overcharge).

The integrity defect is purely the charged-zero path above, not the
split math.

# Impact

- Anti-spam fee (§4) is fully bypassable for embed-only, reply-only, and
  mention-only casts by any account regardless of trust.
- Because the fee is the economic throttle on low-trust message volume,
  this reopens the spam/Sybil-amplification surface the fee was designed
  to close.
- No fund loss and no break of burn/proposer conservation, hence Medium
  rather than High.

# Suggested fix

- Make `stage_fee` and `record_fingerprint_if_cast` agree on what gets
  fingerprinted: either fingerprint empty-text casts too (so duplicates
  drive uniqueness down), or fold a canonicalized digest of
  `embeds`/`embeds_deprecated`/`mentions`/`parent` into the SimHash input
  so empty-text-but-non-empty-body casts are scored on their actual
  content.
- Alternatively, treat empty text as `uniqueness = 0.0` for fee purposes
  (no novel textual content ⇒ no uniqueness discount), forcing
  embed/reply spam through the trust-only discount.

### Validation

- Verdict: **HAS_CAVEATS**, confidence 0.82
- Hypotheses walked: 8
- Validated at: 2026-06-08 00:00:00+00:00

### Validator notes

# F068 validation — empty-text CastAdd permanently evades the per-message fee

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f` (verified HEAD == pin).

## Mechanic re-derived from source (independent of finding body)

- `compute_effective_fee_micro` = `base × max(0, 1 − max(trust, uniqueness))`,
  no minimum-fee floor; `fee==0` short-circuits with zero charge
  (`crates/proof-of-quality/src/fees.rs:58-71`; `src/hyper/fee_charger.rs:124-126`).
- `stage_fee` derives CastAdd uniqueness from `text` only and defaults to `""`
  when the body is missing/non-cast (`fee_charger.rs:107-121`).
- `record_fingerprint_if_cast` early-returns on `text.is_empty()`
  (`fee_charger.rs:167-169`) so NO empty-text fingerprint is ever inserted.
- `uniqueness_score` of empty text → bucket for `fingerprint("")==0`
  (`uniqueness.rs:24-26`, test `empty_text_zero_fingerprint` line 134) is never
  populated → `near_dup_count==0` → `uniqueness_score_from_neighbor_count(0)==1.0`
  (`uniqueness.rs:75-78`; `fingerprint_store.rs:176`).
- Fresh Sybil FID: `trust_store.get` → `None` → `unwrap_or(0.0)` (`fee_charger.rs:95-99`).
  So `max(0.0, 1.0)=1.0` → multiplier 0 → fee 0. Confirmed.
- Cast validation permits empty text when embeds/embeds_deprecated/mentions present
  (`src/core/validations/cast.rs:65-71`). Reachable.
- Production wiring: `stage_fee` at `engine.rs:1311`, `record_fingerprint_if_cast`
  at `engine.rs:1336`, both on the live merge batch. NOT test-only.

## 8-hypothesis walk

1. **Upstream auth / gate — PARTIALLY INVALIDATED (impact only).**
   No upstream gate negates the zero-fee path. BUT a parallel anti-spam bound
   exists: per-FID message pruning to `max_count` storage units
   (`store.rs:1019-1068`, `get_prune_size_limit`). This caps *stored* casts per
   FID, so "unbounded accumulation" is bounded for stored state. It does NOT bound
   network/gossip throughput, and Sybils spread across FIDs; the fee is a distinct
   per-message throughput throttle. Bug stands; "unbounded" framing slightly
   overstated for storage but accurate for throughput.

2. **Consumer-side impact — STANDS.** `uniqueness` is consumed ONLY by the fee
   path (grep: appears in fee_charger + fingerprint_store; reward calc uses
   `trust`, not uniqueness). uniqueness=1.0 is therefore NOT inert — it directly
   waives the full 1.0-token CastAdd base fee. Real economic benefit.

3. **Downstream enforcement — STANDS.** No lower layer re-charges. `apply_fee_deposit`
   / `HyperFeeBalance` / `HyperFeeInsufficient` (engine.rs:1311-1331) only fire
   when a non-zero fee is staged; a zero fee never touches the balance gate.

4. **PR HEAD currency — STANDS.** `git rev-parse HEAD == cab225f1...` matches the
   pinned commit exactly. No drift.

5. **Spec carve-out — STANDS.** fees.rs doc says "new users posting novel content
   pay nothing" (intentional), but NOTHING documents empty-text-with-embed casts
   being scored as novel. No FIP/comment/TODO marks this gap as deferred or known.
   The fee_charger doc explains uniqueness=1.0 for *other Add types* (identity dedup)
   but is silent on empty-text CastAdds. Undocumented gap, not an accepted deviation.

6. **Reachability of harm — STANDS.** CastAdd base=1_000_000 (non-zero), real FID
   (≠0), validation accepts empty-text+embed/mention/reply. Every guard the fee
   path could hit is cleared; fee deterministically resolves to 0.

7. **Test wiring — STANDS.** Buggy code is invoked from the production merge path
   (engine.rs:1311/1336), not just tests. fee_charger.rs has no test module, so the
   empty-text branch is unverified by tests — reinforcing rather than weakening the bug.

8. **PoC mechanics — STANDS (prose-level; no executable PoC supplied).** The finding's
   step-by-step exploit matches the code exactly: each transition (validation pass →
   uniqueness 1.0 → fee 0 → no fingerprint insert → repeat) is line-confirmed above.
   No assertion-passes-for-wrong-reason risk because there is no test asserting it;
   the claim rests on direct code reading, which checks out.

## Overall

Verdict: HAS_CAVEATS. Confidence: 0.82.
The zero-fee path is real, reachable, and undocumented; uniqueness=1.0 yields a
genuine fee waiver (not inert); conservation/split math is correctly excluded from
the defect. The single caveat: per-FID pruning (`store.rs:1019`) bounds *stored*
cast count, so the "unbounded / permanently accumulate" framing overstates the
storage dimension — the surviving harm is unbounded *zero-cost throughput* of
embed/reply/mention spam, especially under Sybil FIDs. Severity Medium
(spam/grief, no fund loss, burn/proposer conservation intact) is appropriate and
not overstated.

## Open follow-ups (NOT new findings — for specialist consideration)
- Secondary observation in the body (uniqueness ignores embeds/parent even for
  non-empty text) is a related but distinct weakness; left to the originating
  specialist.
- A short non-empty text (`chars.len() < n`) falls back to `xxhash_128`
  (`uniqueness.rs:28-30`); fingerprints ARE inserted there, so that sub-case is
  scored — does not affect the empty-text claim.

---

## F070 — Validator-registration custody-signature gate is never wired into the production ingestion path — the router is built without a CustodyResolver, so the lenient validate_event branch runs and the EIP-712 custody cross-sign is never checked, letting an attacker register arbitrary validator keys under any FID

## Summary

`validator_registry.rs` implements a correct, well-tested EIP-712 custody
cross-signature gate (`verify_custody_signature`, required by
`validate_and_check_quota` / `validate_register_with_trust`) intended to
ensure a validator slot can only be registered/rotated with the
authorization of the FID's on-chain custody key. **That gate is never
reached in production.** Every inbound validator event flows through
`HyperRuntime::submit_message`, which constructs the `HyperRouter`
**without** calling `with_custody_resolver(...)`. With `custody_resolver ==
None`, `HyperRouter::route_inbound` takes the lenient branch
`ValidatorRegistry::validate_event(&event, epoch, None)`, which skips
custody-signature verification entirely (it only verifies a custody sig when
a custody address is supplied). The strict `validate_and_check_quota` path —
the only one that resolves a custody address and enforces the cross-sign and
the per-FID 3-cap — is dead code in production.

Net effect: an attacker can register an arbitrary, self-generated
validator key bound to **any FID they choose** (including a victim's FID, or
many sybil FIDs) using only a self-signed Ed25519 signature and **no valid
custody signature at all**. The only remaining barrier is an optional trust
floor that is disabled (`0.0`) by default.

## Where the gate is, and why it never runs

### The gate exists and is correct

`validate_and_check_quota` (`validator_registry.rs:421`) resolves the FID's
custody address via the `CustodyResolver`, requires a custody signature on
Register (`MissingCustodySignature`, line 436-438), and verifies it through
`validate_event(event, epoch, Some(&custody))` → `verify_custody_signature`
(line 268). All the tests (`cross_signed_register_passes_strict_validation`,
`register_with_wrong_custody_address_rejected`,
`register_without_custody_signature_strict_rejected`, …) exercise this
strict path directly and pass.

### The lenient path skips the custody check

`validate_event` (`validator_registry.rs:367`) takes
`custody_address: Option<&[u8;20]>`. With `None`:

```rust
let has_ed25519 = !event.signature.is_empty();
let has_custody = !event.custody_signature.is_empty();
if !has_ed25519 && !has_custody { return Err(MissingSignature); }
if has_ed25519 { verify_event_signature(event)?; }
if has_custody {
    let addr = custody_address.ok_or(CustodyAddressUnknown{...})?;  // only if Some
    verify_custody_signature(event, addr)?;
}
```

When `custody_address` is `None`, the custody signature is only checked if
the attacker *chooses to include one* — and they simply omit it. A register
event with a valid self-signed Ed25519 sig and an empty `custody_signature`
passes `validate_event(.., None)` unconditionally. `fid` is an
attacker-controlled field on the event; no proof of control over that FID's
custody key is required.

### Production never supplies a resolver

`router.rs:165-168`:

```rust
match self.custody_resolver.as_deref() {
    Some(r) => registry.validate_and_check_quota(&event, self.current_epoch, r)?,
    None    => ValidatorRegistry::validate_event(&event, self.current_epoch, None)?,
}
registry.record_event(&event)?;
```

`with_custody_resolver` (`router.rs:115`) is **never called anywhere** in
the codebase (only defined). The single production router construction site,
`runtime.rs:3882`:

```rust
let mut router = HyperRouter::new(
    std::mem::take(&mut self.mempool),
    Some(self.validator_registry.clone()),
    self.epoch_resolver.current_epoch(),
);   // no .with_custody_resolver(...)
```

So `custody_resolver` is `None` → lenient branch → custody sig skipped →
`record_event` persists the registration and its
`HyperValidatorFidLookup[vk] → fid` binding.

### Both ingestion points are affected

- Gossip + local submit: `actor.rs:1218` / `actor.rs:1230`
  (`HyperActorEvent::InboundMessage` / `LocalSubmitMessage`) both call
  `self.runtime.submit_message(msg)` → the unwired router above.
- The alternative `importer::apply_validator_events` (`importer.rs:65`),
  which *also* supports a strict resolver, is **never called** anywhere in
  the tree (dead code), so it provides no compensating enforcement.

The only pre-router gate in `submit_message` (`runtime.rs:3855-3878`) is the
**trust-score floor**, and it is `if self.min_validator_trust_score > 0.0`.
The default is `0.0` (`config.rs:526`, and every non-test runtime config),
so by default even that gate is off; when enabled it only checks the claimed
FID's trust score, never custody authorization.

The metric label set in `observe_routing_rejection`
(`actor.rs:1953-1955`: `invalid_custody_sig`, `missing_custody_sig`,
`custody_address_unknown`) shows the design *intended* custody enforcement
on this path; those counters can never increment from registration because
the strict branch is never taken.

## Impact

Authorization for the entire validator set collapses to "holds a freshly
generated Ed25519 key + names an FID":

- **Validator-slot hijacking / impersonation.** Register a validator key
  under a *victim's* FID with no custody signature. The
  `HyperValidatorFidLookup[vk] → fid` binding (written by
  `record_event`) now attributes attacker-controlled validator activity to
  the victim's FID. Downstream consumers trust this binding as ground truth
  — e.g. DA-PoW response admission (`runtime.rs:3292-3307`) checks
  `fid_for_validator_key(validator_pubkey) == body.fid`, which the attacker
  forged.
- **Active-set dilution / capture.** `compute_active_set`
  (`validator_registry.rs:674`) replays every persisted Register/Deregister
  event regardless of how it was validated. An attacker registers unbounded
  cheap validator keys (the per-FID 3-cap lives only in the dead strict
  path, and the attacker can name arbitrary FIDs anyway) to flood the active
  set. This directly feeds DKLS committee selection, hyperblock proposer
  selection, and quorum math — the attacker can dilute or majority the
  active set.
- **Amplifies F025.** F025 (committee-index grinding) explicitly assumed the
  EIP-712 custody cross-sign was enforced and that sybils needed to control
  their own FIDs' custody keys. With this gap, no custody key is needed at
  all and the per-FID cap does not bind, making the grind strictly cheaper
  and registration under arbitrary FIDs unrestricted. This is nonetheless a
  distinct root cause (missing wiring vs. grindable index map).

## Severity: High

Registration authorization is the trust anchor for the whole validator
subsystem (committee selection, proposer set, DA-PoW attribution, quorum).
The custody gate that is supposed to enforce it is implemented but
unreachable on every production ingestion path, and the only fallback gate
is disabled by default. Exploitation requires only crafting a normal
validator-event gossip message with a self-signed Ed25519 sig and an empty
custody signature. Not direct fund-loss, but it is silent, total bypass of
validator-registration authorization — consistent with the high-severity
incentive/authorization-distortion class for this domain.

## Suggested direction (non-binding)

Wire a `StoreBackedCustodyResolver` into the production router at
`runtime.rs:3882` via `.with_custody_resolver(...)` (mirroring how
`apply_miniapp_register` already builds one at `runtime.rs:2597`), so
`route_inbound` takes the `validate_and_check_quota` /
`validate_register_with_trust` branch. Alternatively make the lenient
`None`-resolver branch unreachable in production by requiring a resolver at
router construction for any non-test runtime. Consider also asserting that
Register events with an empty `custody_signature` are rejected
unconditionally outside explicitly-flagged migration/test contexts.

## Notes / residual uncertainty

- `with_custody_resolver` and `importer::apply_validator_events` both exist
  and are correct; the defect is purely that neither is invoked on a live
  path. Confirmed by full-tree grep: the only callers of
  `with_custody_resolver` and `apply_validator_events` are their own
  definitions/tests.
- If a deployment sets `min_validator_trust_score > 0.0`, the trust floor
  raises the bar (attacker must name an FID whose trust ≥ floor) but still
  does not establish custody authorization — slot hijacking of any
  sufficiently-trusted FID, and sybil registration under any such FID,
  remain possible.
- `compute_active_set` / `record_event` themselves are sound; they faithfully
  apply whatever passed validation. The defect is upstream at the validation
  wiring.

### Validation

- Verdict: **WATERPROOF**, confidence 0.9
- Hypotheses walked: 8
- Validated at: 2026-06-08 13:37:04+00:00

### Validator notes

# F070 validation — custody-sig gate unwired in production router

Validator: validator (deliberate-disagreement). Commit `cab225f`. Date 2026-06-08.

Finding claim: the EIP-712 custody cross-sign gate for validator registration is
implemented (`validate_and_check_quota`/`validate_register_with_trust`) but never
wired into the live ingestion path. The production router is built without a
`CustodyResolver`, so `route_inbound` takes the lenient `validate_event(.., None)`
branch, which skips the custody check. An attacker can register an arbitrary
self-generated validator key bound to any FID.

## Pipeline traced (entry → mutate)

- `actor.rs:1218` (gossip `InboundMessage`) and `actor.rs:1230` (`LocalSubmitMessage`)
  → `runtime.submit_message(msg)`.
- `runtime.submit_message` (`runtime.rs:3664`): ValidatorEvent is NOT intercepted
  earlier (unlike RewardIssuance/TokenTransfer/Miniapp* which return early). The only
  pre-router gate is the trust floor (`runtime.rs:3855`, `if min_validator_trust_score > 0.0`).
- Router constructed at `runtime.rs:3882` via `HyperRouter::new(...)` with NO
  `.with_custody_resolver(...)` → `custody_resolver = None` (`router.rs:111`).
- `route_inbound` ValidatorEvent branch `router.rs:165-169`: `None` → lenient
  `ValidatorRegistry::validate_event(&event, epoch, None)` then `registry.record_event`.
- `validate_event` (`validator_registry.rs:367-412`): with `custody_address == None`,
  custody sig is only checked `if has_custody` (non-empty) AND `Some(addr)`. Attacker
  omits `custody_signature` → empty → custody check skipped entirely. Only the
  attacker-controlled, self-signed Ed25519 over `validator_key` is verified
  (`verify_event_signature` `validator_registry.rs:172-187`), which proves nothing
  about FID ownership.
- `record_event` (`validator_registry.rs:541-581`) writes directly to `self.db`
  (RocksDB) — persists `[HyperValidatorEvent]`, `[HyperValidatorByFid][fid][vk]`,
  and `[HyperValidatorFidLookup][vk]→fid` immediately at ingestion. No separate
  consensus-admission re-validation.

## 8-hypothesis walk

1. Upstream auth/gate — STANDS. The only upstream gate in `submit_message` is the
   trust floor (`runtime.rs:3855`), gated on `min_validator_trust_score > 0.0`. Every
   non-test config sets it to `0.0` (config.rs:526, genesis.rs:121, devnet.rs:41,
   dkls_driver.rs:136, scheduler.rs:596). So by default no upstream gate runs at all,
   and even when set (>0) it only checks the *claimed* FID's trust score — never
   custody authorization. ValidatorEvent is not early-intercepted, so the router is
   genuinely the live handler.

2. Consumer-side impact — STANDS. The `[HyperValidatorFidLookup][vk]→fid` binding is
   consumed by DA-PoW response admission (`runtime.rs:3292-3307`,
   `fid_for_validator_key == body.fid`) and the per-FID active index drives
   `count_active_validators_for_fid` / `compute_active_set`. Persisted state is read
   by real authorization logic, not just "writes garbage to disk."

3. Downstream enforcement — STANDS. No lower layer re-validates. `record_event` mutates
   the DB at ingestion. The block importer does NOT re-apply validator events:
   `apply_validator_events` (`importer.rs:65`) has zero production callers (grep
   confirms only its own definition + doc references; `import_hyper_block*` never call
   it), and the builder never references validator events. So there is no
   block-import/consensus re-check that supplies a resolver.

4. PR HEAD currency — STANDS. Pinned commit `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
   matches finding frontmatter; working tree clean; HEAD detached at the pinned SHA.
   No drift.

5. Spec carve-out — PARTIALLY. The lenient branch is documented as
   "tests + migration" (`router.rs:163`) and the importer doc says "Production callers
   should always pass a resolver" (`importer.rs:64`). This is the inverse of a
   carve-out: the code comments assert production SHOULD wire a resolver, and it does
   not — strengthening, not excusing, the finding. No doc says the gate is intentionally
   deferred in production. STANDS as a defect; impact framing unchanged.

6. Reachability of harm — STANDS. Exploit is a single crafted gossip ValidatorEvent
   (Register) with a valid self-signed Ed25519 sig over the attacker's own
   `validator_key` and an empty `custody_signature`, naming any `fid`. It passes
   `validate_event(.., None)` unconditionally and is persisted. No additional gate on
   the path (trust floor off by default).

7. Test wiring — STANDS (this is the crux, and it confirms the finding). The strict
   functions are exercised ONLY in tests: `validate_and_check_quota` and
   `validate_register_with_trust` callers are all in `validator_registry.rs` tests
   (lines 1280-1469). `with_custody_resolver` (`router.rs:115`) is never called outside
   its definition/doc. `apply_validator_events` (`importer.rs:65`) is never called at
   all. So the implemented gate is dead code in production; the lenient path is the one
   actually wired.

8. PoC mechanics — N/A / STANDS. No PoC artifact attached; the claim rests on static
   dispatch tracing, which I reproduced end-to-end above. The prose's mechanism
   (None-resolver → lenient → empty custody sig skipped) matches the code exactly.
   `verify_event_signature` binds only `validator_key`, not `fid`, confirming the FID
   is attacker-chosen.

## Severity judgement

High is appropriate. Registration authorization is the trust anchor for committee
selection (DKLS), proposer set, quorum math, and DA-PoW FID attribution. The gate is
unreachable on every live path and the fallback (trust floor) is disabled by default.
Not direct fund loss, but a silent, total bypass of validator-registration
authorization — consistent with high-severity authorization/incentive-distortion for
this domain. Interaction with F028 (threshold=1) and F025 (committee grinding) is real
but those are distinct root causes; F070 makes them strictly cheaper (no custody key
needed, per-FID 3-cap does not bind since it lives only in the dead strict path).

## Overall verdict

WATERPROOF. Confidence 0.9. Every hypothesis either STANDS or strengthens the finding.
The only residual is that a deployment could set `min_validator_trust_score > 0.0`,
which raises (but does not establish custody authorization for) the bar — the finding
already states this caveat accurately, so it is not an invalidation. Cross-checks with
H075's router-gap observation: consistent (ValidatorEvent dispatch is the live gap).

## Open follow-ups (NOT new findings)

- The trust floor (`runtime.rs:3855`) being disabled by default in genesis/config could
  warrant operator-doc hardening; out of scope for this finding's body.

---

## Methodology

- Pipeline: audit-suite (multi-agent audit harness)
- Brain library SHA: `b2c8f8bade0bf4b91d254eb4d5774b7fd3e3c1ea`
- Recon → Hunt → Validate → Gapfill → Dedupe → Report
- Each finding was independently validated via an 8-hypothesis red-team walk by an agent distinct from the originating specialist.
