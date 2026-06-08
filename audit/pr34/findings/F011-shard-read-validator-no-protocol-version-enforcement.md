---
id: F011
specialist: consensus-malachite-tendermint
attack_class: read-validator-protocol-version
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: medium
title: Shard read-validators have no protocol-version enforcement; stale read-node silently applies post-upgrade chunks under wrong rules and diverges
file_paths:
  - src/consensus/read_validator.rs
  - src/storage/store/engine.rs
  - proto/definitions/blocks.proto
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.8
  hypotheses_walked: 8
  validated_at: 2026-06-08T12:30:00+00:00
---

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
