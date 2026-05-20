---
id: F095
task: H095
specialist: solidity-bridge
attack_class: inbound-burn-finality-or-replay
file_paths:
  - code/hypersnap/src/hyper/bridge_burn_store.rs
  - code/hypersnap/src/hyper/bridge_burn_watcher.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/runtime.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: low
status: draft
---

# F095 — `BridgeBurnStore` watermark is poisonable and queue is never pruned, degrading the inbound-bridge over time

- **Attack class:** `inbound-burn-finality-or-replay` (defense-in-depth gap in the per-validator observed-burn DB)
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\bridge_burn_store.rs`
- **Severity (provisional):** **Low** (per-validator liveness degradation; no direct fund-loss or double-credit — the `HyperInboundBurnProcessed` replay marker in `runtime.rs::apply_inbound_burn` correctly gates final credit)
- **Direct fund loss to attacker?** No.
- **Direct fund loss / freeze for victim?** No directly, but the per-validator inbound-bridge pipeline can be made permanently stuck for that validator (and, if all validators share the same compromised RPC vendor, for the whole network) with a single bad observation.

## Summary

`BridgeBurnStore` (the per-validator queue that the threshold-signing flow drains each epoch) has two related defense-in-depth gaps:

1. **`highest_observed_block` is RPC-trusting.** The watcher (`bridge_burn_watcher.rs::scan_range`, line 222-286) writes `burn.source_block_number = log.block_number` directly from the JSON-RPC reply with **no plausibility check against the range it actually requested**. On restart, `bridge_burn_watcher.rs::run` (line 148-154) resumes from `highest_observed_block(source_chain_id).saturating_sub(REORG_GUARD)`. A single observation with a far-future `source_block_number` (e.g. `u64::MAX - 100`, easily produced by a malicious or buggy RPC) permanently pins the resume watermark past the finalized head; the watcher's main loop will then `continue` forever on `next_block > finalized_head` (line 175-178) and every subsequent legitimate burn on that chain is skipped until manual intervention.

2. **The queue is never pruned in production.** The module docstring (`bridge_burn_store.rs` lines 6-9) promises:

   > "Once a burn is threshold-signed and applied via `apply_inbound_burn`, the corresponding entry here can be removed".

   `BridgeBurnStore::remove` exists (line 88-96) but Grep across the whole repo confirms it is only called from in-module tests:

   ```text
   $ grep -nr 'bridge_burn_store.remove\|burn_store.remove' code/hypersnap/src
   (no matches)
   ```

   The actor's two drain paths (`refresh_inbound_burns` line 2721-2767 and `start_dkls_inbound_burns_multi_party` line 2775+) just iterate `iter_all()` and skip already-processed entries via the L2-side `is_inbound_burn_processed` marker. The `ObservedBurns` HTTP query docstring (`actor.rs:321-325`) confirms the design choice explicitly:

   > "the queue isn't auto-pruned in Phase 3c, only the processed-marker is checked at sign time".

   Combined with `iter_all`'s **unpaged** RocksDB scan (`bridge_burn_store.rs:101-118` calls `for_each_iterator_by_prefix`, which `storage/db/rocksdb.rs:553-555` documents as the "does not limit by page size" variant), this means every epoch boundary reloads the entire historical burn set into a `Vec<HyperObservedBurn>` in memory, and re-runs `is_inbound_burn_processed` (one extra RocksDB `get` per already-applied burn) for every record ever observed. At ~200 bytes per encoded proto record, after N burns the RAM cost per epoch is ~200N bytes and the per-epoch DB hits are ~N. This is sub-linear-OK at thousands but increasingly disruptive past hundreds of thousands.

The two bugs compose: an attacker who can land **one** poisoned observation also benefits from never being able to delete it via the protocol path — only direct RocksDB surgery clears it.

## Description

### The watermark-poison path (issue 1)

The watcher's resume logic is:

```rust
// bridge_burn_watcher.rs:148-154
let resume_from = match store.highest_observed_block(cfg.source_chain_id)? {
    Some(b) => b.saturating_sub(REORG_GUARD).max(cfg.start_block),
    None => cfg.start_block,
};
```

And `highest_observed_block` is just `max(source_block_number)` over the entire queue:

```rust
// bridge_burn_store.rs:127-137
pub fn highest_observed_block(&self, source_chain_id: u32) -> Result<Option<u64>, ...> {
    let burns = self.iter_all()?;
    Ok(burns.iter()
        .filter(|b| b.source_chain_id == source_chain_id)
        .map(|b| b.source_block_number)
        .max())
}
```

The watcher's main loop guards against scanning past the finalized head:

```rust
// bridge_burn_watcher.rs:173-178
let finalized_head = head.saturating_sub(cfg.finality_confirmations);
if next_block > finalized_head {
    time::sleep(cfg.poll_interval).await;
    continue;
}
```

So if the stored watermark `b` is past `finalized_head + REORG_GUARD`, the watcher loops on `sleep → fetch_head → continue` forever and never advances. New burns are silently dropped on the floor until an operator manually edits the RocksDB.

**How a single bad observation gets in.** Per `bridge_burn_watcher.rs:200-211`, the watcher requests logs with `Filter::from_block(from).to_block(to)` — but the JSON-RPC server is the source of truth for the `block_number` attached to each log in the reply. A malicious or buggy RPC can attach any `block_number` it likes. Then at line 277-286:

```rust
let burn = proto::HyperObservedBurn {
    source_chain_id: cfg.source_chain_id,
    burn_id,
    recipient_fid,
    amount,
    source_block_number: block_number,   // <-- pulled straight from log.block_number, no clamp
    source_tx_hash: tx_hash,
    observed_at_unix: now_unix,
};
store.record(&burn)?;
```

`store.record()` (line 55-66) validates only `burn_id.len() == 32`; it does not check that `source_block_number <= finalized_head + slop` or that it falls within the `(from, to)` window the watcher requested. So one crafted log returned by a compromised RPC permanently anchors that validator's watermark.

Once the L2 finishes successfully signing/applying the poisoned burn — which it will, because `apply_inbound_burn` just verifies the DKLS group signature, not source-block-number sanity — the credited L2 balance is also permanent. (That's an honest reflection of the "we trust the RPC up to BRIDGE_FINALITY_CONFIRMATIONS" assumption in the watcher docstring, lines 10-18, so isn't a new theft path — but the **DoS on subsequent burns** is the new bit, and it's an asymmetric outcome: one poisoned event freezes every honest event after it.)

### The unbounded-queue path (issue 2)

Three observations in code:

- `BridgeBurnStore::remove` (line 88-96) is dead code outside `mod tests`.
- `BridgeBurnStore::iter_all` (line 101-118) is the unpaged RocksDB scan.
- The two drain sites (`actor.rs:2726` and `actor.rs:2786`) both call `iter_all().unwrap_or(Vec::new())` every epoch boundary and then re-`is_inbound_burn_processed` each entry.

Each `HyperObservedBurn` proto carries `source_chain_id(u32) + burn_id(32B) + recipient_fid(u64) + amount(u64) + source_block_number(u64) + source_tx_hash(32B) + observed_at_unix(u64)` ≈ 100 bytes raw plus protobuf framing → ~120-180 bytes encoded. At a steady-state of a few hundred legitimate burns per day across all source chains, the per-epoch cost is fine. But:

- The queue never shrinks — the only way an entry can be removed today is by a validator operator manually deleting the rocksdb key.
- `is_inbound_burn_processed` is called once per queued entry per epoch — so the cost per epoch grows as `O(historical burns) × O(get latency)`.
- `highest_observed_block` (line 127-137) also walks the whole queue every restart and every other call site.

Over the multi-year lifetime envisaged for `RootPrefix::HyperBridgeObservedBurn = 64`, the queue is a monotonically growing on-disk structure that the hot-path drain function loads into memory in full each epoch. Combined with issue 1, an attacker who lands a single poisoned watermark also makes that DB row impossible to evict via the protocol.

### Why this is "low" rather than "med/high"

- The L2 credit is still gated by `runtime.rs::apply_inbound_burn`, which (a) checks the processed-marker before crediting (line 1089-1098), and (b) verifies the DKLS group signature over the canonical payload (line 1100-1111). So no path through `BridgeBurnStore` can produce a double-credit or a spoofed credit.
- The multi-party DKLS sign requires `t` validators to independently observe the same `(burn_id, amount, recipient_fid, source_block_number, source_tx_hash)` (digest match). A poisoned single-validator observation will not get countersigned; only the 1-of-1 mode is at risk of crediting a poisoned burn, and 1-of-1 already accepts full single-validator trust by design.
- The unbounded-queue cost is sub-linear-OK for the first months of operation; the docstring acknowledges that "Phase 3c" doesn't prune.

So the realistic bad outcome is: **a validator with a compromised RPC vendor permanently stops processing inbound burns until an operator runs `rocksdb_dump | grep -v 0x40 | rocksdb_restore`**. Important to fix before mainnet but not a stealth fund-drain.

### Suggested fixes

1. In `bridge_burn_store.rs::record`, reject `source_block_number` that the caller can prove is post-finalized-head — e.g. add an optional `expected_max_block: Option<u64>` parameter the watcher passes as `finalized_head + watcher_batch_size`, and return `Err` if violated. Or sanity-cap at `u64::MAX / 2`.
2. In `bridge_burn_watcher.rs::scan_range`, validate `log.block_number ∈ [from, to]` before constructing the `HyperObservedBurn`.
3. Implement the pruning behaviour the module docstring already promises: in `actor.rs::refresh_inbound_burns` and `start_dkls_inbound_burns_multi_party`, call `self.runtime.bridge_burn_store.remove(obs.source_chain_id, &obs.burn_id)` once `is_inbound_burn_processed` returns true. Doing this **after** the L2 marker is set is replay-safe (the marker is the trust anchor; the store entry is just a queue).
4. Switch `highest_observed_block` to a maintained-on-write watermark stored under its own key, rather than scanning the whole queue. Bonus: a separate watermark survives `remove()` calls in (3).

## Reproduction sketch

1. Stand up a validator with the watcher pointed at a controlled JSON-RPC mock.
2. Mock returns one `Burned` log with `block_number = 10_000_000_000` (well past any real source-chain head) and a valid `burn_id`.
3. Watcher calls `record()`, stores the poisoned observation.
4. (Optional) Wait for the actor to threshold-sign and apply; L2 balance updates for whatever FID was in the recipient field. Replay is still blocked thereafter.
5. Real `Burned` events emitted by the genuine contract are ignored: `next_block > finalized_head` for every poll until the operator manually intervenes.

No tests in `bridge_burn_store.rs::tests` cover the post-`remove()` drain flow or block-number plausibility — both gaps are easy to wedge into the existing `record_*` test cluster.

## Affected source

- `code/hypersnap/src/hyper/bridge_burn_store.rs` (lines 55-66, 88-96, 101-137 — `record`, `remove`, `iter_all`, `highest_observed_block`)
- `code/hypersnap/src/hyper/bridge_burn_watcher.rs` (lines 148-154 resume logic, 222-286 log decode without block-number clamp)
- `code/hypersnap/src/hyper/actor.rs` (lines 2721-2767, 2775+ — drain functions that never call `remove`)
- `code/hypersnap/src/hyper/runtime.rs` (lines 1055-1143 — `apply_inbound_burn`, the gate that mitigates the worst-case)
