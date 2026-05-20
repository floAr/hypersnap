---
id: F094
attack_class: inbound-burn-finality-or-replay
file_paths:
  - code/hypersnap/src/hyper/bridge_burn_watcher.rs
  - code/hypersnap/src/hyper/bridge_burn_store.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: low
status: draft
---

# F094 — Bridge-burn watcher resume cursor is derived from the (drainable) `BridgeBurnStore` queue, not from a persisted high-watermark

- **Attack class:** `inbound-burn-finality-or-replay`
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\bridge_burn_watcher.rs`
- **Severity (provisional):** Low (operational fragility / DoS-on-restart; replay-protection at the apply site prevents double-credit, so this is NOT a direct fund-loss vector)
- **Direct fund-loss?** No. The processed-marker at `RootPrefix::HyperInboundBurnProcessed` (id 63) keyed by `(source_chain_id, burn_id)` blocks re-credit, and `apply_inbound_burn` (`runtime.rs:1087-1098`) short-circuits on re-observe.
- **Direct grief / freeze?** Partial. After certain operator actions (or once `BridgeBurnStore::remove` starts being called per its docstring intent), the watcher silently resets its resume cursor to `cfg.start_block` and re-scans the entire bridge history from L1 deployment block on every subsequent restart — RPC-rate-limited operators may be unable to catch up to head, blocking new burns from being observed in a timely manner. Liveness, not safety.

## What the code does

`bridge_burn_watcher::run` reconstructs its resume point from the
**observation queue** (which is intended to be ephemeral) rather than from
a dedicated watermark:

```rust
// bridge_burn_watcher.rs:148-154
let resume_from = match store
    .highest_observed_block(cfg.source_chain_id)
    .map_err(BridgeBurnWatcherError::Store)?
{
    Some(b) => b.saturating_sub(REORG_GUARD).max(cfg.start_block),
    None => cfg.start_block,
};
```

`highest_observed_block` (`bridge_burn_store.rs:127-137`) walks the
`HyperBridgeObservedBurn`-prefix iterator (id 64 — the
**unprocessed-queue** prefix, NOT the
`HyperInboundBurnProcessed`-prefix audit record):

```rust
pub fn highest_observed_block(
    &self,
    source_chain_id: u32,
) -> Result<Option<u64>, BridgeBurnStoreError> {
    let burns = self.iter_all()?;
    Ok(burns
        .iter()
        .filter(|b| b.source_chain_id == source_chain_id)
        .map(|b| b.source_block_number)
        .max())
}
```

The `BridgeBurnStore::remove(...)` method exists and is documented as:

```rust
// bridge_burn_store.rs:86-88
/// Remove a burn from the queue. Called once it's been
/// successfully threshold-signed + applied.
pub fn remove(&self, source_chain_id: u32, burn_id: &[u8]) -> Result<(), ...>
```

and the module-level docstring confirms intent:

```rust
// bridge_burn_store.rs:5-9
//! The watcher (`bridge_burn_watcher`) writes here; the threshold-
//! signing flow consumes from here. Once a burn is threshold-signed
//! and applied via `apply_inbound_burn`, the corresponding entry
//! here can be removed — the canonical record lives at
//! `RootPrefix::HyperInboundBurnProcessed`.
```

## Two-pipeline confusion (this is the bug)

The watcher conflates two semantically distinct cursors:

1. **Resume cursor**: the L1 block beyond which the watcher need not re-scan.
   This MUST monotonically advance and MUST persist across restarts and
   queue draining.
2. **Pending-work queue**: the set of observed burns awaiting threshold
   signing. This is intentionally drainable (per the `remove` docstring).

Today both live behind one `iter_all` walk over the
`HyperBridgeObservedBurn` prefix. Failure modes that follow from this
coupling:

### A. Queue-drained restart (latent)

`grep -r 'bridge_burn_store.remove\|burn_store.remove' src/` shows that
`remove` is currently called from **no production site** (only from a
unit test, `bridge_burn_store.rs:222`). So today the queue grows
unbounded — `highest_observed_block` always returns the max block ever
observed, so the cursor never regresses. Liveness preserved by accident.

The bug is **latent**: as soon as a follow-up adds the queue-drain step
that the docstring promises (likely, since `iter_all` is called every
epoch in `start_dkls_inbound_burns_multi_party` and `refresh_inbound_burns`
and growing it unboundedly is itself a separate problem), the resume
cursor collapses. Concretely:

- Validator processes all queued burns in epoch E, then `remove`s them.
- Validator restarts.
- `highest_observed_block` returns `None` (empty queue) → `resume_from = cfg.start_block`.
- Watcher re-scans from the bridge deployment block — potentially millions
  of L1 blocks — on every restart, hammering its `eth_getLogs` provider.

The same regression also fires the first time the watcher is restarted
after an operator manually prunes the queue (e.g., to recover from a
malformed-record DB write).

### B. Sparse-event re-scan (always-on)

Even without `remove`, the cursor reflects the **last observed burn's
block**, not the last **scanned** block. So if the watcher scans blocks
M..N (where M is the last burn block and N >> M, no burns in between),
crashes after writing the in-memory `next_block = N+1`, then restarts —
resume goes back to `M - 32`, re-scanning M..N. For a bridge with rare
burns on a high-throughput chain, this is O(burn-sparsity) extra RPC
load per restart.

### C. Re-scan re-overwrites the queue

`record` is idempotent on key (`bridge_burn_store.rs:52-54` docstring
plus `record_is_idempotent_on_same_key` test) — re-recording an already-
applied burn writes the queue entry back. If the burn was previously
`remove`d, it now sits in the queue forever as a re-observed phantom.
`refresh_inbound_burns` / `start_dkls_inbound_burns_multi_party` then
call `is_inbound_burn_processed` to skip it. So it's a quiet
inefficiency, not a double-credit, but it defeats the purpose of `remove`
and inflates the multi-party sign-tasks list every epoch.

## Why this is not a direct-credit / replay bug

The replay protection is at `apply_inbound_burn`
(`runtime.rs:1087-1098`):

```rust
let key = Self::inbound_burn_key(burn.source_chain_id, &burn.burn_id);
if self.db.get(&key)?.is_some() {
    return Ok(false);   // already-processed short-circuit
}
```

keyed by `(source_chain_id, burn_id)`, with the canonical processed-
marker written atomically alongside the balance credit
(`runtime.rs:1124-1141`, `batch.put(bal_key, ...)` + `batch.put(key, ...)`
+ `self.db.commit(batch)`). So a re-observed burn cannot double-credit,
no matter how many times the watcher re-records it. Safety is preserved;
only liveness / RPC-budget is at stake.

## Suggested fix

Add a separate per-chain watermark column-family that the watcher
explicitly bumps after each successful scan range:

```rust
// bridge_burn_watcher.rs around line 188
next_block = stop.saturating_add(1);
store.set_scan_watermark(cfg.source_chain_id, next_block)?;  // new
```

and:

```rust
// bridge_burn_watcher.rs around line 148-154
let resume_from = store
    .scan_watermark(cfg.source_chain_id)?
    .unwrap_or(cfg.start_block)
    .saturating_sub(REORG_GUARD)
    .max(cfg.start_block);
```

Backed by a new `RootPrefix::HyperBridgeScanWatermark` keyed by
`source_chain_id`. The watermark is independent of queue contents, so
removing applied burns from the queue does not move the cursor backward.

Equivalent alternative: have `highest_observed_block` walk
**`HyperInboundBurnProcessed`** instead of `HyperBridgeObservedBurn`
(since the processed marker is forever-persistent and stores the same
`source_block_number` field). That keeps the storage shape unchanged and
just retargets the iterator at the right prefix.

## What this finding does NOT claim

- **Finality**: the 64-confirmation wait at line 174
  (`head.saturating_sub(cfg.finality_confirmations)`) is in place and
  matches FIP §13.8. Reorgs deeper than the configured depth are
  documented as out-of-scope ("the operator's problem", lines 14-18).
- **Replay**: as noted above, `apply_inbound_burn` has a per-
  `(source_chain_id, burn_id)` nullifier that prevents double-credit.
- **Emitter binding**: `Filter::new().address(cfg.bridge_contract_address)`
  at line 203 constrains `eth_getLogs` to the configured bridge address.
  This is RPC-side enforced (the watcher trusts its own RPC), which is
  the standard threat model for `eth_getLogs` consumers.
- **Cross-chain spoofing via RPC misconfig**: not claimed here; see the
  ruled-out note for the chain-id verification gap (defense-in-depth
  only, no exploit path).
