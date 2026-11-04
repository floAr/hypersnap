---
finding_id: F001
title: '`HypersnapBlockHeader` fields 14/15 (`epoch_record_hash`, `bridge_action_hash`) diverge from FIP §17.7; no Rust-side pinned header vector'
severity: info
status: pending-validation
---
# F001 — `HypersnapBlockHeader` fields 14/15 (`epoch_record_hash`, `bridge_action_hash`) diverge from FIP §17.7; no Rust-side pinned header vector

- **Severity:** Informational (spec/code divergence; no fund or liveness impact in the code as written)
- **Specialist:** solidity-bridge · attack class: cross-side-encoding-asymmetry · task H001
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Summary

The bridge V2 trust model depends on two header fields that the spec does not define.
FIP §17.7 ends `HypersnapBlockHeader` at `pivot_record_hash = 13`
(`docs/spec/FIP-proof-of-work-tokenization.md:2247-2261`). The code adds
`epoch_record_hash = 14` and `bridge_action_hash = 15`
(`proto/definitions/hypersnap.proto:29-30`). They are the only link between a certified
header and (a) the `EpochBoundaryRecord` used for the validator-set handoff
(`HypersnapBridgeV2.sol:256`) and (b) a governance action
(`HypersnapBridgeV2.sol:492-495`). The library documents the gap
(`contracts/src/libraries/HypersnapProto.sol:22-25`: "Fields 14 and 15 are NOT in §17.7 yet").

The spec only says that `advanceEpoch` verifies a CERT-STARK "over the header that contains the
record" (§13.4, line 1180) and that an upgrade needs "a shard-0 header that contains the upgrade
action" (§13.7, line 1260). It never defines how a header commits to either one. Someone who
implements only the spec (another client, an auditor of the spec, or the future CERT-STARK work)
gets a header that cannot be used to drive `advanceEpoch`, `proposeUpgrade`, `cancelUpgrade` or
`pause`. The spec also defines no domain separation for `bridge_action_hash`
(`"hypersnap-bridge-action-v1" || u8 kind || u32_be chain_id || target`: Rust
`src/chain/shard0/bridge_actions.rs:27-34`, Solidity `HypersnapBridgeV2.sol:436-442`).

A second, related gap: the cross-side vectors for the header and record in
`contracts/test/HypersnapProto.t.sol:28-55` are `protoc --encode` output. The proposed-header
vector was produced "with those two fields added to a scratch copy of the schema". No Rust test
asserts that `chain::block::block_hash()` (`src/chain/block.rs:53-55`, prost re-encode +
keccak) or the `epoch_record_hash` computation (`src/chain/shard0/engine.rs:891-893`) gives these
bytes or digests. `grep` finds no `.rs` file that references the Solidity vectors. Today the
encoders agree (see "Why it is not worse"), but nothing in CI stops them from drifting apart.

## Attacker model / impact

None directly. Every party that can change the header schema is the protocol developer. The
risks are:

1. **Spec-level ambiguity.** Under the spec alone, the bridge's handoff and governance paths
   cannot be implemented. A spec-conformant node (fields 1–13 only) produces headers whose
   `epochRecordHash`/`bridgeActionHash` decode as zero. The bridge then rejects every
   `advanceEpoch` (`RecordNotInHeader`) and every governance action (`ActionNotInHeader`). The
   validator-set handoff stalls at epoch 1. `advanceRoot` keeps working only while
   `setRoot[h.epoch]` is known, so after epoch 1 ends, outbound claims are stuck on the last
   epoch-1 root.
2. **Silent drift.** A future change to the Rust header (a renumbered field, a non-32-byte
   `bridge_lock_root`, a field that becomes `optional` and therefore encodes an explicit
   default) makes certified headers fail the strict decoder. This is a bridge liveness failure,
   and no Rust-side test would catch it.

## Why it is not worse (checked, holds at 7eb981b)

- prost 0.13.5 encodes fields in tag order (`prost-derive-0.13.5/src/lib.rs:90`
  `fields.sort_by_key(... tags().min())`), writes repeated `shard_links` together, and leaves out
  proto3 defaults. This matches the decoder's ordering and no-default rules.
- Every validator signs `keccak256(prost re-encoding of the decoded header)`
  (`block.rs:53-55`, checked against `block.hash` at `block.rs:167`, used by
  `shard0/engine.rs:1038` and `shard_blocks.rs:478`). prost drops unknown fields and
  canonicalises duplicates. So only the canonical encoding is ever certified, and keccak
  preimage resistance stops a relayer from presenting other bytes. The bridge's forward-compat
  skipping of unknown fields (`HypersnapProto.sol:155-157`) is not reachable with certified
  input today.
- The shard-0 executor always writes `bridge_lock_root` as 32 bytes (`[0;32]` when the lock set
  is empty, `ledger.rs:705-712`). It writes `epoch_record_hash`/`bridge_action_hash` as 32 bytes
  or leaves them empty (`engine.rs:877-893`). Validators require exact equality on re-execution
  (`engine.rs:1085-1093`). All of these shapes decode.
- The `EpochBoundaryRecord` built at `boundary.rs:34-40` always has non-zero `epoch`,
  `block_height`, a 32-byte `state_root`, a 32-byte `next_set_root` and non-zero
  `next_total_weight` (the last could be zero only for an empty validator set, and then the chain
  halts anyway). `epoch == header.epoch` and `block_height == header.height` hold by
  construction, which matches `HypersnapBridgeV2.sol:261`.
- The commit digest is the same on both sides:
  `keccak("hypersnap-commit-v1" || u32_be shard || u64_be height || u32_be round || block_hash)`
  in `consensus_keys.rs:30-52` and in `HypersnapBridgeV2.sol:425-431`. The bridge hard-codes
  shard 0 in the digest (`:464`) and also requires `shard_id == 0` in the header bytes (`:454`),
  so a shard-1/2 certificate cannot be replayed.

## Fix

1. Add fields 14 and 15 to FIP §17.7 and define their semantics (§13.4 "a header contains the
   record" means `epoch_record_hash == keccak256(encode(record))`, and §13.7 defines the
   `bridge_action_hash` preimage and domain). Alternatively, change the code to whatever the spec
   adopts.
2. Add a Rust test that builds the exact `HypersnapBlockHeader`/`EpochBoundaryRecord` from
   `HypersnapProto.t.sol` and asserts `encode_to_vec()` equals the pinned hex and that
   `block_hash()` equals the pinned `blockHash` values. Do the same for
   `action_hash(kind, chain, target)` against `bridgeActionHash` (the pattern in
   `CrossSideDigests.t.sol` for the v1 payloads).
3. Optional: in `validate_header` for shard 0, assert that
   `bridge_lock_root.len() == 32` and that `epoch_record_hash`/`bridge_action_hash` are empty or
   32 bytes. This makes the bridge decoder's assumptions a node-side invariant and does not rely
   only on executor equality.
