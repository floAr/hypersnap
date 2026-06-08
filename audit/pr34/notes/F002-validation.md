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
