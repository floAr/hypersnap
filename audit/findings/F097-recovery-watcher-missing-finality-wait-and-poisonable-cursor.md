---
id: F097
task: H097
specialist: solidity-bridge
attack_class: inbound-burn-finality-or-replay
file_paths:
  - code/hypersnap/src/hyper/recovery_watcher.rs
  - code/hypersnap/src/hyper/recovery_store.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: low
status: draft
related_findings:
  - id: F094
    relationship: related-but-distinct
  - id: F095
    relationship: related-but-distinct
  - id: F096
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.93
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F097 — `recovery_watcher` has no finality wait and inherits the cursor-poisoning + sparse-event-rescan bugs from F094/F095

- **Attack class:** `inbound-burn-finality-or-replay` (parallel pipeline for
  IdRegistry `Recover` events; same family of bugs as F094/F095 but in a
  separate code path)
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\recovery_watcher.rs`
- **Severity (provisional):** **Low** (today: store has no production
  consumer, so write-only — latent. Becomes **Medium** the moment the
  deterministic retro distribution starts reading
  `HyperIdRecoveryEvent` to disambiguate forced-recovery transfers from
  ownership changes, per the proto docstring at
  `hyper.proto:1212-1230`.)
- **Direct fund-loss to attacker?** No today (no read consumer). On
  consumer wire-up: a poisoned recovery record can cause the retro
  distribution to misclassify a real Transfer event as a recovery
  (preserving `effective_ts` for the wrong wallet), but credit flow is
  one-FID-at-a-time and bounded by the retro vesting schedule, so the
  worst case is "wrong FID's vesting clock keeps running."
- **Direct grief / liveness for victim?** Yes. A single poisoned
  observation permanently freezes the watcher (resume cursor pinned past
  head). On the consumer side, a near-head reorg silently produces a
  Recover record that doesn't exist on the canonical chain.

## Summary

The new hyper-side `recovery_watcher` is a near-clone of
`bridge_burn_watcher` but with three regressions relative to that sibling:

1. **No finality wait.** Unlike `bridge_burn_watcher` which scans up to
   `head - cfg.finality_confirmations` (default 64 on OP), the
   recovery watcher scans up to `head` directly. This contradicts the
   module's own determinism claim ("every validator synced to the same
   OP finality depth has the same Recover event set",
   `recovery_watcher.rs:23-26`) — the depth is not enforced anywhere.
2. **Poisonable resume cursor (F095 variant, worse).** The cursor is
   derived from `RecoveryEventStore::highest_recorded_block()`, which
   reads `block_number` straight off RocksDB key bytes that were
   themselves taken straight from the JSON-RPC reply. A single log with
   a fabricated `block_number` (e.g., `u64::MAX - 100`) pins the
   watermark forever and every legitimate Recover after that is
   silently dropped. Without the `head - finality_confirmations` clamp,
   the loop's "are we caught up?" check (`next_block > head`,
   line 131) just sleeps in perpetuity.
3. **Sparse-event rescan-from-start_block (F094 variant, "issue B").**
   Until the first Recover is observed, every restart re-scans from
   `cfg.start_block` (default IdRegistry deployment block ~108_864_739)
   to head. There is no separate scan-watermark — the resume cursor
   IS the highest-recorded-event-block. On OP this is millions of
   blocks of `eth_getLogs` per restart.

Plus a smaller cluster of code-hygiene defects discussed at the bottom
(panic on overflowing FID, key layout that mixes block numbers across
future chain extensions, no reorg-guard window even though the doc
claims determinism).

## What the code does

### Resume cursor (lines 107-114)

```rust
let resume_from = store
    .highest_recorded_block()
    .map_err(RecoveryWatcherError::Store)?
    .map(|b| b.saturating_add(1))
    .unwrap_or(cfg.start_block);
```

`highest_recorded_block` (`recovery_store.rs:127-147`) reverse-walks
prefix 47 and reads the first 8 bytes after the prefix byte:

```rust
self.db.for_each_iterator_by_prefix(Some(prefix), Some(stop), &page_options, |key, _value| {
    if key.len() >= 1 + 8 {
        let mut be = [0u8; 8];
        be.copy_from_slice(&key[1..1 + 8]);
        highest = Some(u64::from_be_bytes(be));
    }
    Ok(true)
})?;
```

Since the key layout is `[47][block_number BE u64][log_index BE u32][fid BE u64]`
(line 43-50), the highest key in the prefix gives the highest
`block_number` ever recorded.

### Scan loop (lines 117-147)

```rust
let head = match provider.get_block_number().await { ... };
if next_block > head {
    time::sleep(cfg.poll_interval).await;
    continue;
}
let stop = (next_block + cfg.block_batch - 1).min(head);
if let Err(e) = scan_range(&provider, &store, next_block, stop).await { ... }
next_block = stop.saturating_add(1);
```

Compare to `bridge_burn_watcher.rs:173-178`:

```rust
let finalized_head = head.saturating_sub(cfg.finality_confirmations);
if next_block > finalized_head {
    time::sleep(cfg.poll_interval).await;
    continue;
}
let stop = (next_block + cfg.block_batch - 1).min(finalized_head);
```

The recovery watcher dropped the `.saturating_sub(cfg.finality_confirmations)`
clamp. There is also no `REORG_GUARD` rewind on restart (cf.
`bridge_burn_watcher.rs:152` — `b.saturating_sub(REORG_GUARD)`).

### Block-number is RPC-trusting (line 191-198, 225)

```rust
let block_number = match log.block_number {
    Some(b) => b,
    None => continue,
};
// ...
let ev = proto::HyperRecoveryEvent {
    fid,
    from_address: from_addr,
    to_address: to_addr,
    block_number,        // <-- whatever the RPC returned, no plausibility
    block_timestamp,
    transaction_hash: tx_hash,
    log_index,
    chain_id: OP_MAINNET_CHAIN_ID,
};
store.record(&ev)?;
```

No clamp against `from..=to` (the scan range the watcher asked for) and
no clamp against any independently-known finalized head. Whatever
`block_number` the JSON-RPC reply carries is written verbatim into the
RocksDB key.

## How the bugs compose

### B1 — Finality-wait gap (Recover-event rollback)

OP mainnet is not reorg-free (recent OP-stack history shows depth-1 to
depth-5 reorgs are routine; deeper reorgs are rarer but documented).
With `next_block > head` as the only guard, the watcher records Recover
events from blocks that the canonical chain may drop minutes later. The
record stays in the hyper store. When the retro-distribution consumer
is wired (per `hyper.proto:1212-1230`):

> "a Transfer event whose (fid, block_number) matches a
> HyperRecoveryEvent preserves the original effective_ts"

a Transfer in a reorged-away block will still match the now-orphaned
HyperRecoveryEvent and the retro distribution will treat it as a
recovery, preserving `effective_ts` on the wrong wallet for vesting
purposes.

Worse, validators that observe the reorg at different timings will
disagree on whether the Recover happened — the docstring at line 23-26
claims byte-identical reads "for any validator synced to the same OP
finality depth", but the code does not pin a finality depth. Two
validators with slightly-different `poll_interval` cadence can have
divergent local stores at the same canonical head until the older one
gets re-recorded on a later poll (and even then only if their RPC
re-served the orphaned block, which it shouldn't but compromised RPCs
might). Determinism for `iter_up_to_block` reads is therefore not
guaranteed in the reorg-zone.

### B2 — Watermark-poisoning DoS (F095 variant in this watcher)

Same mechanism as F095 (`bridge_burn_watcher`). A compromised or buggy
JSON-RPC injects one Recover log with `block_number = u64::MAX - 100`.
`record()` (line 55-61) writes it to RocksDB unconditionally. On the
next restart:

- `highest_recorded_block()` returns `Some(u64::MAX - 100)`.
- `resume_from = u64::MAX - 99`.
- `next_block > head` is permanently true (head is ~1.3 × 10^8).
- The watcher sleeps `poll_interval` forever; no legitimate Recover is
  ever recorded.

Worse than F095 in `bridge_burn_watcher` for two reasons:

1. There is no `head - finality_confirmations` clamp to keep
   the poisoned value still less than head; the F095 variant in
   bridge_burn_watcher could in principle clear itself if head ever
   caught up. The recovery_watcher's loop genuinely never escapes
   without operator intervention.
2. There is no `RecoveryEventStore::remove` method at all, so the only
   way out is a manual RocksDB surgery to delete the poisoned key.

### B3 — Sparse-event rescan-from-start_block (F094 variant in this watcher)

`highest_recorded_block` returns `None` when the store has zero
Recover events. So:

- First-ever startup with `cfg.start_block = 108_864_739`: watcher
  scans from `108_864_739` to head, ~24M blocks at 8K/batch = ~3000
  `eth_getLogs` calls. Acceptable for one-time bootstrap.
- Subsequent restarts BEFORE the first Recover is observed: the
  scan-from-start-block is repeated entirely on every restart. Recover
  events on OP IdRegistry are rare (one per FID-recovery action, very
  long-tail), so the watcher can run for weeks before recording its
  first event. Every crash-restart-loop during that window hammers the
  RPC.

Unlike F094 in `bridge_burn_watcher` (where `remove()` exists and would
drain the cursor on consumer wire-up), `recovery_store.rs` has no
`remove`. So the "queue-drained restart" subvariant of F094 is not
present — but the **sparse-event rescan** subvariant (F094 issue B) is,
and it bites harder because Recover events are rarer than Burn events.

### B4 — Same-batch crash window (mild)

If `scan_range` succeeds for a 8000-block range that contained zero
Recover events, the in-memory `next_block` advances 8000. On crash
before any Recover is ever recorded, the restart's `resume_from` goes
back to `cfg.start_block` (since `highest_recorded_block` is still
`None`). The 8000 blocks of "we already scanned this, no events here"
work is repeated. Cumulatively, a watcher that has scanned 100M blocks
without ever seeing an event and then crashes-restarts re-does all 100M
on every restart — until an event eventually lands and the watermark
sticks.

Fix is the same as for F094: a persisted scan watermark separate from
the event store.

## Smaller defects observed in the same file

### S1 — FID overflow panics the task

Line 217:

```rust
let fid = match topics.get(3) {
    Some(t) => U256::from_be_slice(t.as_slice()).to::<u64>(),
    None => continue,
};
```

`U256::to::<u64>()` (alloy / ruint) **panics** on out-of-u64-range —
it is the unwrapping conversion, not the wrapping one (`wrapping_to`).
The real IdRegistry never emits an id > ~10M, but a compromised RPC
could fabricate a Recover log with id = 2^65, panicking the watcher
task. The snapchain-side ingester avoids this with `id.try_into()?`
which propagates as `Err` (`connectors/onchain_events/mod.rs:762, 778, 795`).
Use the same here.

### S2 — Key layout omits `chain_id`, even though `chain_id` is stored in the value

The docstring at line 47-49 says "the watcher is ever extended to
other chains, consumers can disambiguate via the recorded `chain_id`".
But the RocksDB key is `[47][block_number][log_index][fid]` with no
`chain_id` — `highest_recorded_block` will return the cross-chain max
block, not the per-chain max. If the watcher is ever pointed at two
chains in parallel (or sequentially in test/dev), the cursor for one
chain pins the cursor for the other. Same shape as the bridge_burn
store but worse because there `highest_observed_block` is filtered by
`source_chain_id` after the iter (`bridge_burn_store.rs:131-137`); here
the highest-block reader is unfiltered (`recovery_store.rs:127-147`).

### S3 — `block_batch = 0` underflows the scan-range arithmetic

Line 137: `(next_block + cfg.block_batch - 1).min(head)`. If an
operator config writes `block_batch = 0`, the subtraction underflows
to `u64::MAX`. With default 8000 this is moot, but the field is
public on `RecoveryWatcherConfig` and validated nowhere. A non-zero
floor in `config.rs` would close this.

### S4 — Address-spoofing claim

`Filter::new().address(ID_REGISTRY_ADDRESS_OP)` filters at the RPC, but
the watcher does not re-check `log.address == ID_REGISTRY_ADDRESS_OP`
on returned logs (line 159-168, 190-232). A byzantine RPC can return
logs for any address while still serving the watcher's filter. Same
per-validator-trust caveat as R4 in H094 — not a cross-validator
exploit, but defense-in-depth.

## Why severity is **Low** today (and **Medium** on consumer wire-up)

Grep across the repo for production consumers of `RecoveryEventStore`:

```
$ grep -rn 'recovery_store\.\(for_fid\|iter_up_to_block\|iter_all\)' code/hypersnap/src
(only test sites)
```

So the store is currently write-only. Bugs B1-B4 affect the watcher's
own liveness and the freshness of the store, but no downstream
protocol decision is made off the recorded events yet. The same
applies to S1-S4.

The moment the deterministic retro distribution starts reading
`recovery_store` (per `hyper.proto:1212-1230` which describes exactly
this consumer), severity rises:

- B1 → diverging local recovery records across validators in the
  reorg-zone → consumer reads diverge → retro distribution becomes
  non-deterministic, breaking the in-protocol consensus claim at
  `recovery_watcher.rs:23-26`.
- B2 → a poisoned validator silently stops observing real
  Recover events; its retro-distribution consumer eventually fires
  with an incomplete set, mis-classifying real Transfers as "not a
  recovery" and overwriting `effective_ts`.
- B3 + B4 → RPC-cost regression, not safety.

## Suggested fixes

1. **Mirror `bridge_burn_watcher`'s finality wait.** Add
   `finality_confirmations: u64` to `RecoveryWatcherConfig`,
   default to 64 (matching FIP §13.8 for the bridge — IdRegistry's
   finality posture should be at least as conservative).
2. **Add a separate scan-watermark column-family** for the watcher,
   keyed by `chain_id`, written after each successful `scan_range`.
   Reads from this watermark on restart instead of
   `highest_recorded_block`. This fixes B2, B3, B4 in one shot.
3. **`record()` plausibility check** — validate
   `expected_min_block <= ev.block_number <= expected_max_block` (the
   watcher passes the scan range; the store returns Err if outside).
   Caller-side validate `log.block_number ∈ [from, to]` before
   constructing the `HyperRecoveryEvent`.
4. **FID overflow safety** — replace `.to::<u64>()` with `.try_into()`
   and `continue` on Err.
5. **`log.address` re-check** as defense-in-depth.
6. **Optional: REORG_GUARD rewind** on restart, even with the
   finality wait, since the docstring claims byte-identical reads
   and that requires a small overlap window for the rare case of a
   reorg right at the finality horizon.

## Affected source

- `code/hypersnap/src/hyper/recovery_watcher.rs` — lines 107-114
  (resume cursor), 117-147 (scan loop, missing finality wait), 159-168
  (filter, no address re-check), 190-231 (decode, no block-number
  clamp, FID overflow panic at line 217).
- `code/hypersnap/src/hyper/recovery_store.rs` — lines 43-50 (key
  layout omits chain_id), 55-61 (no record-time plausibility check),
  127-147 (`highest_recorded_block` unfiltered by chain_id).
- `code/hypersnap/src/storage/constants.rs` — lines 92-100 (prefix 47
  layout documentation).
- `code/hypersnap/proto/definitions/hyper.proto` — lines 1212-1230
  (consumer contract docstring).

## Relationship to F094 / F095

- This file is the parallel watcher to `bridge_burn_watcher.rs`. F094
  filed the cursor-derived-from-queue regression in that file; F095
  filed the watermark-poisonability + unbounded-queue regression in
  the matching store. F097 is the same family of bugs in the
  recovery pipeline, with one regression added (no finality wait at
  all) and one removed (no `remove()` to drain the queue, so the
  queue-drain subvariant of F094 doesn't fire here).
- Pinning the comparison: the bridge_burn pipeline carries a 64-block
  finality wait (`bridge_burn_watcher.rs:172-178`), a REORG_GUARD
  rewind on restart (line 152), and a per-chain `highest_observed_block`
  filter (`bridge_burn_store.rs:131-137`). The recovery pipeline
  carries none of these. The two files were written together, and one
  is materially less defensive than the other.
