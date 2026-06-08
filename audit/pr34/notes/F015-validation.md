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
