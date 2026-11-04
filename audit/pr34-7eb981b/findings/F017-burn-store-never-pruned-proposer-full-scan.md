---
finding_id: F017
title: The observed-burn store is never pruned
severity: low
status: pending-validation
related_findings:
- F009
- F013
---
# F017 — The observed-burn store is never pruned. Every proposal attempt and every `bridge/observed-burns` request scans every burn ever seen, and burns to unregistered FIDs are retried in every block forever.

- **Severity:** Low (proposer latency and public-endpoint availability that grow over time. V1's lack of a minimum makes the growth cheap to force.)
- **Category:** dos / resource-exhaustion
- **Specialist:** shard0-ledger-state · attack class: inbound-burn-double-credit-or-loss · task H011
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Finding

1. **No pruning.** The store doc says a burn "can be removed" once applied
   (`bridge_burn_store.rs:7-10`). `BridgeBurnStore::remove` has no non-test caller, so the store
   holds every burn ever observed.
2. **The proposer scans everything on each attempt.** `BurnView::pending` calls `iter_all()`,
   which uses `for_each_iterator_by_prefix` with `page_size: None` and so has no bound. It
   protobuf-decodes every entry and does one shard-0 `db.get` per entry for `processed()`
   (`watchers.rs:265-302`). The proposer runs this inside its propose loop
   (`proposer.rs:181-188`) and repeats it on every 200 ms retry within a round. The cost is
   O(all burns ever) on the consensus-critical path, before the proposal timeout.
3. **Unregistered-FID burns never leave.** They stay "pending" by design (FIP §13.6, and the
   comment at `watchers.rs:280-282`). On each proposal attempt every one of them is put through
   `apply_system` → `is_registered`, which does up to 3 DB reads, and is then dropped
   (`engine.rs:788-797`). This repeats every height forever. The burner may pick an FID that will
   never be registered.
4. **Public endpoint.** `GET /hyper/v1/bridge/observed-burns` (`hyper_v1.rs:313-330`) returns
   `iter_all()` in full as JSON on every request, synchronously on the async runtime. This is the
   F013 pattern again: about 60 requests/min per IP and no pagination.
5. **Dust is cheap on V1.** V2 enforces `MIN_BRIDGE_AMOUNT` (1 token). V1 `burn` has no minimum
   (`HypersnapBridge.sol:378-386`), and the node's `ledger::inbound_burn` only rejects
   `amount == 0` (`ledger.rs:754`). This diverges from FIP §13.8, where `MIN_BRIDGE_AMOUNT`
   "prevents dust attacks", on the inbound side. While V1 is live, each store entry costs an
   attacker one micro-unit plus Optimism gas. After V2, each entry costs 1 token, and the token
   comes back if the FID is registered.

**Sizing (estimate).** At 10^5–10^6 entries, each proposal attempt does 10^5–10^6 decodes and
gets, which is hundreds of ms to seconds. That is in the same range as the round timeout, so
proposers hit timeouts. The endpoint response is tens to hundreds of MB.

## Red-team walk

- *Organic growth only?* No: points 3 and 5 let an attacker grow the always-retried set
  cheaply, and point 1 makes even honest volume accumulate.
- *Does it affect validators?* `is_final` is a single point `get`, so validation stays O(1) per
  burn. The cost falls on proposers and on HTTP readers.
- *Consensus safety?* Not affected. Hence Low.

## Recommendation

Call `remove` once a burn is committed: on block commit, for each `InboundBurn` in the block.
Keep unregistered-FID burns in a separate index keyed by FID and re-check them only when that
FID's registration event is applied. Enforce `min_bridge_amount` in `ledger::inbound_burn` (or
in the watcher) and add the minimum to V1 `burn`. Paginate `bridge/observed-burns` and move it
to `spawn_blocking`.

## Evidence

`src/chain/bridge_burn_store.rs:7-10, 88-121`; `src/storage/db/rocksdb.rs:636-643`;
`src/chain/watchers.rs:265-302`; `src/chain/shard0/proposer.rs:181-188`;
`src/chain/shard0/engine.rs:759-797`; `src/chain/shard0/ledger.rs:749-773`;
`src/node/hyper_v1.rs:313-330`; `contracts/src/HypersnapBridge.sol:378-386`.
