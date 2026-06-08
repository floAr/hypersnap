---
id: H072
specialist: solidity-bridge
attack_class: untrusted-recover-event-ingest
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/recovery_watcher.rs
  - code/hypersnap/src/hyper/recovery_store.rs
  - code/hypersnap/src/hyper/bridge_burn_watcher.rs
  - code/hypersnap/src/hyper/bridge_burn_store.rs
  - code/hypersnap/proto/definitions/hyper.proto
title: Recover-event watcher enforces source-contract + signature + finality + dedup; no spoof/replay/reorg path to retro distribution
---

# H072 — untrusted-recover-event-ingest — ruled out

## Scope

`recovery_watcher.rs` ingests untrusted IdRegistry `Recover(address indexed
from, address indexed to, uint256 indexed id)` events from the OP-mainnet
IdRegistry and persists them via `RecoveryEventStore` for later use by the
deterministic retro distribution. Per `hyper.proto` (lines 1240-1258), a
recovery event is matched against `Transfer` events by `(fid, block_number)`
so that forced-recovery transfers preserve the original `effective_ts` rather
than being scored as a fresh ownership change. So a forged / replayed / reorged
recovery event could in principle alter retro reward attribution if it reached
the store. The hunt asked whether finality + dedup + source-contract
verification are enforced like the burn watcher.

## Findings: all three controls present, equal to the burn watcher

1. **Source-contract verification (anti-spoof).** `scan_range` builds the log
   filter with `.address(ID_REGISTRY_ADDRESS_OP)` (recovery_watcher.rs:173) and
   `.event_signature(Recover::SIGNATURE_HASH)` (line 176). Only logs emitted by
   the canonical IdRegistry address `0x00000000Fc6c5F01Fc30151999387Bb99A9f489b`
   with the exact `Recover` topic0 are returned. A log from any other contract,
   or a different event with a colliding shape, is never fetched. This mirrors
   the burn watcher (bridge_burn_watcher.rs:212-215). A forged event would
   require an emit from the real IdRegistry, which the attacker does not
   control. No spoof path.

2. **Finality (anti-reorg).** The loop computes
   `finalized_head = head.saturating_sub(cfg.finality_confirmations)` (default
   64) and only scans `next_block..=min(stop, finalized_head)`
   (recovery_watcher.rs:143-150). An event is therefore persisted only once it
   is >= 64 OP blocks deep, identical to the burn watcher's
   `DEFAULT_FINALITY_CONFIRMATIONS = 64` (bridge_burn_watcher.rs:174). A reorg
   shallower than the confirmation depth can never reach the store; a reorg
   deeper than 64 blocks is the same explicitly-accepted source-chain-consensus-
   failure assumption documented for the burn watcher. No new reorg exposure.

3. **Dedup / replay.** `RecoveryEventStore::record` keys on the composite
   `[prefix][block_number BE u64][log_index BE u32][fid BE u64]`
   (recovery_store.rs:43-50). On Ethereum/OP `log_index` is block-scoped and
   unique across all logs in a block, so `(block_number, log_index)` already
   uniquely identifies a log; re-recording the identical event is an idempotent
   overwrite with byte-identical value (tested at recovery_store.rs:194-200).
   Two distinct legitimate events cannot collide on the key, and there is no
   forged-event path (control 1) that could overwrite a real entry. Replay /
   duplicate ingestion is a no-op.

## Resume logic is safe (no missed-block gap)

The recovery watcher resumes from `highest_recorded_block() + 1`
(recovery_watcher.rs:116-120), i.e. the block of the last *recorded* event, not
the last *scanned* block. Because the store never deletes entries (unlike the
burn store, whose `remove` drained the queue and motivated the F094 watermark),
`highest_recorded_block` is a stable lower bound: on restart the watcher
re-scans from the last event forward, which can only re-observe already-recorded
events (idempotent) and never skips a range. There is no resume gap that drops a
real `Recover` event. The watcher therefore does not need the burn watcher's
persisted watermark + `REORG_GUARD` machinery.

## Minor defensive divergences (not findings — unreachable)

- `fid = U256::from_be_slice(topic3).to::<u64>()` (recovery_watcher.rs:230)
  uses the panicking `to::<u64>()`, whereas the burn watcher guards the amount
  with a checked `try_into()` (bridge_burn_watcher.rs:275). A `Recover` `id`
  above `u64::MAX` would panic the scan task. IdRegistry FIDs are sequential
  small integers and the real contract never emits an id near `u64::MAX`, so
  this is unreachable with on-contract data; at most a hardening nit for
  consistency with the burn watcher.
- `log_index = log.log_index.unwrap_or(0)` (recovery_watcher.rs:212) defaults a
  `None` index to 0. `None` only occurs for pending/unmined logs; the watcher
  only ever queries finalized historical ranges, where every log carries
  `Some(log_index)`. Not reachable.

Neither divergence is exploitable with data from the real IdRegistry contract
past finality, so neither rises to a finding.

## Conclusion

The recovery watcher enforces source-contract verification, event-signature
filtering, finality confirmations, and idempotent composite-key dedup — the same
controls as the inbound-burn watcher. No forged, replayed, or reorged `Recover`
event can influence retro reward distribution or reassign an FID. Ruled out.
