---
id: F160
task: H200
attack_class: dos
severity: high
status: draft
commit: 4a6bca5
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.97
  hypotheses_walked: 8
  validated_at: 2026-05-29T00:00:00Z
  poc: "audit/poc/F160-live-at-shard-panic/ (RUNNABLE — panics at mempool.rs:212:59; log f160-poc-4a6bca5.log)"
  note: "Runnable PoC confirms remote/default-reachable node crash via gossip LIVE_AT for a FID on a non-hosted shard. Upstream-inherited (snapchain v0.12.0). High not Critical: single-shard deployments immune. See audit/notes/F160-validation.md and audit/poc/F160-live-at-shard-panic/."
---

# F160 — LIVE_AT rate limiter panics (node crash) on a FID routed to a shard the node does not host

## Summary

The new FIP-268 `LiveAtRateLimits::consume_for_fid` (added by PR #32) re-routes the
message FID to a shard via its own `ShardRouter` and then does:

```rust
let shard_id = self.message_router.route_fid(fid, self.num_shards);
let stores = self.shard_stores.get(&shard_id).unwrap();          // <-- panics if shard not hosted
let storage_limits = stores.get_storage_limits(fid).unwrap();    // <-- panics on a RocksDB read error
```

`num_shards` is the *network-wide* shard count (`consensus.num_shards`), but
`shard_stores` only contains the shards this node actually hosts
(`consensus.shard_ids`, populated in `snapchain_node.rs:83-123`). These are two
independent config fields (`consensus.rs:49-50`). On the standard multi-shard
topology where a validator hosts a *subset* of shards (e.g. `num_shards = 2`,
`shard_ids = [1]`), `route_fid` returns `(sha256(fid) % num_shards) + 1`, which for
roughly half of all FIDs resolves to a shard NOT present in `shard_stores`. The
`HashMap::get(&shard_id)` then returns `None` and `.unwrap()` panics, taking down
the mempool task (and, since `Mempool::run` is the node's mempool loop, the node).

Unlike the pre-existing general `RateLimits` (which carries the identical
`get(&shard_id).unwrap()` / `get_storage_limits().unwrap()` pattern but is gated
behind `Config::enable_rate_limits`, default `false`), `LiveAtRateLimits` is
**always constructed and always consulted** for any LIVE_AT message
(`mempool.rs:712-719`, `message_exceeds_rate_limits`). So this panic surface, which
was previously dormant in default configurations, becomes **reachable by default**
on any V17-capable node that hosts a subset of shards.

The crash does not require an attacker: any honestly-signed LIVE_AT whose FID hashes
to a non-hosted shard triggers it during normal operation. It is also reachable
without RPC validation via the **gossip ingress** — gossip-forwarded mempool
messages enter as `MempoolSource::Gossip` (`gossip.rs:952-954`) and flow straight
into `insert -> insert_into_shard -> message_is_valid(.., true) ->
message_exceeds_rate_limits -> consume_for_fid`, bypassing the RPC-side
`simulate_message_for_shard_typed` shard check. A single crafted/forwarded LIVE_AT
for a non-hosted-shard FID crashes every subset-hosting peer that ingests it.

## Affected files (file:line)

- `code/hypersnap/src/mempool/mempool.rs:209-234` — `LiveAtRateLimits::consume_for_fid`
  (the two `.unwrap()` calls at L212-213).
- `code/hypersnap/src/mempool/mempool.rs:712-719` — always-on LIVE_AT limiter call site.
- `code/hypersnap/src/mempool/mempool.rs:674-678` — `LiveAtRateLimits::new` constructed
  unconditionally (no `enable_rate_limits` gate).
- `code/hypersnap/src/mempool/routing.rs:12-19` — `route_fid` returns `1..=num_shards`
  regardless of which shards the node hosts.
- `code/hypersnap/src/node/snapchain_node.rs:83-123` — `shard_stores` populated only
  from `config.shard_ids` (hosted subset).
- `code/hypersnap/src/consensus/consensus.rs:49-50` — `num_shards` and `shard_ids`
  are independent config fields.

## Trigger / Reachability

Preconditions:
- Node is V17-capable (LIVE_AT feature live — testnet already past activation as of
  2026-05-29; mainnet 2026-06-04).
- Node hosts a strict subset of the network's shards
  (`shard_ids ⊊ {1..=num_shards}`), i.e. the normal sharded production topology.

Trigger (no special privilege required):
1. Any LIVE_AT `UserDataAdd` (`UserDataType::LiveAt`) for a FID whose
   `(sha256(fid) % num_shards) + 1` is not in `shard_stores`.
2. Delivered via gossip (`MempoolSource::Gossip`) — bypasses RPC simulation — or via
   RPC if the routed shard happens to be locally simulable.
3. `message_exceeds_rate_limits -> consume_for_fid` runs
   `shard_stores.get(&non_hosted_shard).unwrap()` -> panic -> mempool/node crash.

Reachability is before signature/engine validation as far as the mempool admission
limiter is concerned (the rate-limit check runs inside `message_is_valid` at
admission, and gossip ingress is not RPC-simulated). An attacker can flood gossip
with LIVE_AT messages spanning many FIDs to guarantee non-hosted-shard hits on every
subset-hosting peer simultaneously — a network-wide remote crash.

Secondary sub-hypotheses checked:
- `units == 0` (FID with no storage registration, or a lender who lent out all
  units): `get_storage_limits` returns `Ok` with `units == 0` (not `Err`), so
  `consume_for_fid` returns `None -> false` (message rejected, "rate limit
  exceeded"). No panic. Confirmed by the ported test
  `test_live_at_mempool_rejects_fid_without_storage`. NOT a separate finding.
- Storage lend/borrow: `units` is the *net* slot (purchased + borrowed - lent) from
  `get_storage_limits`. Borrowers get a quota, full lenders get `units == 0`
  (rejected). Behavioral, no panic.
- `NonZeroU32::new(quota).unwrap()`: `quota = units.saturating_mul(5000)` and this is
  only reached on the `units != 0` branch, so `quota >= 5000 > 0`. Safe.
- `get_storage_limits(fid).unwrap()`: returns `Err` only on an underlying RocksDB /
  onchain-event-store error, which is an internal-fault panic rather than an
  attacker-chosen one. Lower priority than the `shard_stores.get().unwrap()` path but
  shares the same fix.

## Snapchain-parity note

Inherited verbatim from upstream snapchain v0.12.0. The
`LiveAtRateLimits::consume_for_fid` body (incl. both `.unwrap()` calls), the
always-on construction, `RateLimits` gating, `route_fid`, and the
`num_shards`/`shard_ids` config split are byte-for-byte identical to
`C:\Projects\snapchain\src\mempool\mempool.rs:215-240` and the surrounding node/config
code. Only the TODO author name differs elsewhere in the module
(`topocount` vs `aditi`). This is therefore an **upstream-inherited** defect, not a
hypersnap drift — but it is newly *introduced into the audited surface* by the PR #32
LIVE_AT port and newly *reachable by default* (the general limiter that shares the
pattern is off by default; the LIVE_AT limiter is always on). Per the delta-audit
charter (newly-reachable inherited issues are in scope), it is reported here. Worth
routing upstream as well.

## Severity rationale

High. Remote, unauthenticated, low-effort node crash (panic) reachable via gossip on
the standard sharded validator/full-node topology, affecting potentially every
subset-hosting peer that ingests one crafted LIVE_AT. No fund loss and no consensus
state corruption, and a single-shard (`shard_ids == {1..=num_shards}`) deployment
is not affected — which is why this is High rather than Critical. On testnet the
feature is already live; on mainnet it arms at V17 activation (2026-06-04).

## Suggested remediation

In `LiveAtRateLimits::consume_for_fid` (and, for parity, the pre-existing
`RateLimits::get_rate_limiter_for_fid`):
- Replace `self.shard_stores.get(&shard_id).unwrap()` with a graceful path: if the
  routed shard is not hosted locally, do not panic. Either fall through to a
  permissive/neutral decision for non-hosted shards (the node cannot authoritatively
  rate-limit a FID whose state it does not hold) or reject without crashing, matching
  how `message_already_exists` already tolerates a missing store
  (`mempool.rs:444-448` logs and returns `false`).
- Replace `stores.get_storage_limits(fid).unwrap()` with error handling that
  logs/metrics and returns a non-panicking decision on a store read error.

Add a regression test for the subset-hosting topology (`num_shards = 2`,
`shard_ids = [1]`) feeding a LIVE_AT whose FID routes to shard 2, asserting no panic.

## Dedupe links

- F151 (`snapchain-codec-decode-panics...`) — same *class* (attacker/peer-reachable
  `.unwrap()` panic DoS) but different subsystem (consensus codec vs mempool LIVE_AT
  limiter) and different root cause. Link as related, not duplicate.
- Existing mempool-cluster findings — link as same-subsystem.
