---
id: F015
specialist: node-lifecycle-actor
attack_class: signing-payload-field-coverage-gap
file_paths:
  - src/hyper/slashing_store.rs
  - src/hyper/mod.rs
  - src/hyper/slashing.rs
  - src/hyper/chain.rs
  - src/hyper/gossip_adapter.rs
  - src/hyper/runtime.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: medium
title: slashing_store encode_block zeroes signing_payload-committed fields, so persisted equivocation evidence is no longer self-verifying
related_findings:
  - F002
  - F009
relationship: related-but-distinct
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

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
