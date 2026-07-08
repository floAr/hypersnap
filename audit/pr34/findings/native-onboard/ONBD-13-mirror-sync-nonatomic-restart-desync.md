# ONBD-13 — RocksDB query-mirror sync is non-atomic with block persistence and is not rebuilt on restart → crash-window query-index desync

- **Severity:** Low (non-consensus; self-healing)
- **Status:** OPEN (new at `f4fc4af`; **not** a merge blocker)
- **Component:** `src/hyper/runtime.rs`, `src/hyper/importer.rs`, `src/hyper/native_onboard.rs`
- **Introduced by:** partly pre-existing (the onboarding mirror sync was already a separate commit at `ab73681`); the `f4fc4af` rotation fix adds a fourth separate commit (`sync_rotation_mirror_from_tree`), widening the same window.
- **Corroboration:** independently surfaced by BOTH the storage-consistency lane and the lifecycle-determinism lane.

## Summary

At import, a hyperblock's authoritative state (the verkle tree, folded into the threshold-signed
root) and its RocksDB **query mirror** (`HyperNativeCustodyToFid` / `HyperNativeFidSequence` /
`HyperNativeRotationNonce`) are committed in **four separate `db.commit` calls with no spanning
write-batch**: `index.record` + `index.record_messages` (`importer.rs:174-183`), then
`sync_onboarding_mirror_from_tree` (`runtime.rs:4970`), then `sync_rotation_mirror_from_tree`
(`runtime.rs:4986`). A crash (power loss / OOM-kill / panic) after the block is durably stored but
before the mirror syncs commit leaves the block on disk while the mirror misses that block's effects.

Compounding it, the **cold-restart replay** (`runtime.rs:386-436`) rebuilds the **tree only** — it
replays stored onboards/rotations/transfers via `builder::apply_message` and never calls either
mirror sync. So a mirror that fell behind before the crash is never reconciled at startup; it stays
behind until the affected custody/FID is next touched by a live import (which re-reads the tree and
self-heals that key).

## Impact / why Low

The mirror is a **non-consensus query/dedup index**. Its only live-production reader is
`lookup_custody_fid` at `runtime.rs:4097`, used for the **optimistic duplicate-onboard rejection**
when an onboard enters the mempool (`next_hyper_fid` and `read_rotation_nonce` are test-only; the
rotation submit-path optimistic check reads the **tree**, not the mirror). Consequences of a stale
mirror:

- **Stale-missing binding:** a duplicate onboard slips past the optimistic mempool reject, but is a
  deterministic no-op at import (the in-tree `ever` marker is authoritative) — **no double-mint**.
- **Stale-extra binding (tombstone not mirrored):** an HTTP/query custody→FID lookup returns a
  revoked binding, but a rotation is still correctly gated because its authoritative check reads the
  tree (`runtime.rs:4124`), not the mirror.
- Verkle roots on all honest nodes remain identical → **no fork, no halt.** The divergence is a
  local query-index artifact and self-heals on the next sync of that custody/FID.

## Fix direction

Either (a) fold the two mirror syncs into the **same write-batch** as `index.record_messages` so
block-persist and mirror-update are atomic, or (b) **rebuild the mirror from the tree** at the end of
the restart-replay loop (`runtime.rs:435`) so any pre-crash lag is reconciled at startup. (a) is
preferred — it closes the window rather than papering over it at restart.

## Key locations

`importer.rs:174-183` (block persist) · `runtime.rs:4969-4997` (two separate mirror-sync commits) ·
`runtime.rs:386-436` (restart replay rebuilds tree only) · `runtime.rs:4097` (sole live mirror reader) ·
`native_onboard.rs:469-499` (onboarding sync) · `native_onboard.rs:843-879` (rotation sync).
