---
id: H014
specialist: node-lifecycle-actor
attack_class: signing-payload-field-coverage-gap
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/importer.rs
  - code/hypersnap/src/hyper/mod.rs
  - code/hypersnap/src/hyper/chain.rs
  - code/hypersnap/proto/definitions/hyper.proto
---

# H014 — signing-payload field-coverage gap — RULED OUT

## Scope
`import_hyper_block` (`importer.rs:238-305`) and
`HyperBlockMetadata::signing_payload` (`mod.rs:403-452`).

## Method
1. Enumerated every field of `HyperBlockMetadata` (`mod.rs:291-329`).
2. For each field, located its byte contribution inside `signing_payload`.
3. Cross-checked the canonical block-hash fields
   (`chain.rs:hyper_block_hash`, 25-44) against the payload.
4. Traced downstream consumers (block application, scoring, epoch
   resolver, L1/scheduler anchor snapshot) to confirm every consumed
   field is one of the signed fields.
5. Verified the proto<->native round-trip carries all fields so the
   verifier reconstructs identical payload bytes.

## Field-by-field coverage (all SIGNED)

Native struct field — signing_payload site — consumer:

- `canonical_block_id` — `mod.rs:408` — chain continuity / block hash (`chain.rs:28`).
- `parent_hash` — `mod.rs:409-410` — chain continuity / block hash (`chain.rs:29-30`).
- `hyper_state_root` — `mod.rs:411-412` — state-root match (`importer.rs:288-292`); block hash (`chain.rs:31-32`).
- `extra_rules_version` — `mod.rs:417` — block hash (`chain.rs:33`). (F028 v1 gap, now closed.)
- `retained_message_count` — `mod.rs:418` — block hash (`chain.rs:34`). (F028 v1 gap, now closed.)
- `missed_proposals` — `mod.rs:421-426` — `update_scores_for_missed_proposals` → `record_missed_proposal` (`importer.rs:102-111`).
- `snapchain_anchor_block` — `mod.rs:428` — `epoch_resolver.observe_anchor` (`runtime.rs:4581-4582`); scoring/DA triggers + seed (`actor.rs:1246-1254`); scheduler `LatestAnchor` (`main.rs:1711-1715`).
- `snapchain_anchor_hash` — `mod.rs:429-430` — proposer-selection seed; `LatestAnchor.hash` (`main.rs:1713`).
- `snapchain_range_start_block` — `mod.rs:433` — range commitment for snapchain-fork detection / settlement.
- `snapchain_range_root` — `mod.rs:434-435` — SHA-256 Merkle root over covered snapchain blocks (settlement / divergence surfacing).
- `snapchain_anchor_timestamp` — `mod.rs:438` — deterministic `now_unix` for `evaluate_epoch` scoring (`actor.rs:1247,1250`, `maybe_trigger_scoring`).

Additional bound input (not a struct field): `epoch` (`mod.rs:407`) and
`signer_indices` (sorted, `mod.rs:445-450`, F153 fix) — the latter prevents
committee malleation of captured conflicting-block evidence.

## Verifier path is consistent
`import_hyper_block` rebuilds the payload from `block.signature.epoch` and
`block.signature.signer_indices` (`importer.rs:246-249`) and verifies the
ECDSA group signature over it (`importer.rs:250-258`). Any variation of any
listed field changes the payload bytes → signature recovery fails.

## Wire completeness
proto `HyperBlockMetadata` fields 1-11 (`hyper.proto:3-56`) map 1:1 to the
native struct; both `From` impls (`mod.rs:527-573`) round-trip every field, so
a gossiped block deserializes with all signed fields populated before
verification. No proto-only field exists that escapes the payload.

## Conclusion
No consumed-but-unsigned metadata field. The v2 `signing_payload` (DST
`hypersnap-hyperblock-v2:`) covers every field that feeds block application,
state transition, scoring, epoch resolution, and the snapchain/L1 anchor
snapshot. The historical gaps (F028: `extra_rules_version`,
`retained_message_count`; F153: `signer_indices`) are closed at this commit.
Revalidation confirms the fix holds. No finding.
