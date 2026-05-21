---
id: F133
task: H133
attack_class: fee-trust-uniqueness-flow
severity: critical
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.75
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F133 — `FingerprintStore` writes/deletes bypass the engine's `txn_batch` and execute on every gRPC `submitMessage` simulate; produces per-validator `uniqueness_score` divergence (consensus fork) and lets any attacker plant or evict fingerprints at zero fee cost

- **Task:** H133
- **Attack class:** `fee-trust-uniqueness-flow` (uniqueness-score input store written outside consensus state-transition, by attacker-callable RPC)
- **Severity (provisional):** Critical. The fingerprint store is read by every validator during `replay_proposal` to compute `uniqueness_score → effective_fee → fee_balance` delta. Because the store is mutated by gRPC `submit_message` simulate-path side-effects that bypass the engine's `txn_batch`, validators that receive different simulate traffic see different fingerprint state and compute different per-CastAdd fees, producing different account_roots and thus `EngineError::HashMismatch` / consensus fork. The same defect also allows fee-free fingerprint poisoning and forced eviction of >=30-day fingerprints via authenticated-but-unbilled RPC.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/fingerprint_store.rs:81-88` — `FingerprintStore::insert`; `self.db.put(&key, &val)` writes directly to RocksDB, NOT to a `RocksDbTransactionBatch`. No batch parameter exists on the function.
- `code/hypersnap/src/hyper/fingerprint_store.rs:93-144` — `FingerprintStore::uniqueness_score`; reads via `self.db.for_each_iterator_by_prefix(...)` (bypasses any pending batch), and **on every call** issues `self.db.commit(batch)` (line 140) to DELETE every fingerprint in the inspected bucket whose `ts < now_secs - FINGERPRINT_WINDOW_SECS`. The eviction commit is independent of any engine txn_batch.
- `code/hypersnap/src/hyper/fee_charger.rs:107-121` — `FeeCharger::stage_fee` calls `self.fingerprint_store.uniqueness_score(text, data.timestamp as u64)` for every CastAdd. So **every** CastAdd merge — whether via consensus replay or gRPC simulate — invokes the eviction.
- `code/hypersnap/src/hyper/fee_charger.rs:135-162` — `FeeCharger::record_fingerprint_if_cast` calls `self.fingerprint_store.insert(data.fid, text, data.timestamp as u64)`; runs unconditionally after a successful `merge_message` regardless of `ProposalSource`.
- `code/hypersnap/src/storage/store/engine.rs:1217-1340` — `merge_message`; line 1240 invokes `stage_fee` (triggers `uniqueness_score` → DB-eviction commit); line 1336 invokes `record_fingerprint_if_cast` (direct `db.put`). Both side-effects bypass the engine's `txn_batch` and persist independently of whether the merge commits.
- `code/hypersnap/src/storage/store/engine.rs:2108-2151` — `simulate_message`; constructs a throwaway `RocksDbTransactionBatch`, calls `replay_snapchain_txn` (→ `merge_message`), then `self.stores.trie.reload(&self.db)` — explicit comment: "we are not committing state here." But the fingerprint store has already written through `self.db` directly.
- `code/hypersnap/src/storage/store/engine.rs:2153-2234` — `simulate_bulk_messages`; same shape, multi-message version. Explicit "discard all in-memory changes" comment on line 2222-2223 is contradicted by the fingerprint store's direct disk writes.
- `code/hypersnap/src/network/server.rs:441-472` — `submit_message_internal`; the gRPC `submitMessage` handler. Calls `simulate_message_for_shard_typed` BEFORE enqueueing to mempool. Any client able to reach the gRPC ingress (authenticated or anonymous, depending on operator config; the codebase ships with no auth) can drive this code path.
- `code/hypersnap/src/network/server.rs:719-787` — `simulate_message_for_shard_typed`; constructs a `ShardEngine::new(stores.db.clone(), ...)` (the comment calls it "readonly_engine" — that label is wrong; the `Arc<RocksDB>` is shared with the live consensus shard engine) and calls `simulate_message`.
- `code/hypersnap/src/storage/db/rocksdb.rs:355-388` — `RocksDB::put` and `RocksDB::commit`; both go to the underlying `DBProvider::Transaction`. There is no "scratch" or "snapshot" mode for simulate-driven engines.

## Summary

The "rolling content-fingerprint store" is read by `stage_fee` on every
CastAdd merge to compute `uniqueness_score`, which feeds
`compute_effective_fee_micro(base, trust, uniqueness)` →
`stage_charge_message_fee`. The resulting fee debit lands in the
account state that contributes to the shard's `account_root` and thus
to consensus.

But the fingerprint store is written through TWO code paths that
**bypass the engine's `RocksDbTransactionBatch` entirely** and instead
issue raw `self.db.put` / `self.db.commit(batch)` calls:

1. `FingerprintStore::insert` (called by `record_fingerprint_if_cast`
   after every successful CastAdd merge in `merge_message`).
2. `FingerprintStore::uniqueness_score`'s eviction tail
   (`fingerprint_store.rs:135-141`), which DELETES every fingerprint
   in the queried bucket whose `ts < now_secs - 30_days`.

Because `merge_message` is reached from the gRPC `submit_message`
simulate path (`network/server.rs:441-472` →
`simulate_message_for_shard_typed` → `simulate_message` →
`replay_snapchain_txn` → `merge_message`), and because the simulate
path discards its `txn_batch` ("we are not committing state here",
`engine.rs:2222-2223`), the simulate path RECORDS the fingerprint to
disk AND EVICTS old fingerprints from disk while NOT recording any
of the consensus state (cast added, fee debited, etc.).

The fingerprint store is per-validator local state. Each validator
has its own RocksDB. The gRPC `submit_message` ingress is per-node;
different validators receive different RPC traffic (load balancers,
mempool gossip semantics, attacker chooses targets). As a result:

- Validator A receives an attacker's `submit_message` for CastAdd
  with text T at timestamp t. The simulate path persists fingerprint
  (T, t, fid) to A's DB.
- Validator B does not receive the message (or it failed simulate on
  B for a different reason).
- A block proposer later includes a CastAdd with text T' similar to
  T. During `replay_proposal`, both validators compute
  `uniqueness_score(T', t')`:
  - A's bucket-scan finds the persisted fingerprint for T → returns
    `uniqueness_score < 1.0` → `effective_fee` lower → less debit.
  - B's bucket-scan finds nothing → returns `uniqueness_score = 1.0`
    → `effective_fee` higher → more debit.
- A and B compute different `fee_balance(proposer_fid)`, different
  `total_fee_burned`, different `proposer_fee_pot`. Their account
  roots diverge. Whichever validator(s) match the proposer's root
  pass `replay_proposal`; others return `EngineError::HashMismatch`
  (`engine.rs:587, 604`) and the network forks.

Comment at `fingerprint_store.rs:79-80` claims "`ts_secs` is the block
timestamp — using the block clock (not wall-clock) keeps the store
deterministic across validators." This is true at the protocol intent
level, but the determinism guarantee is broken by the simulate path
because `data.timestamp` on a simulate is whatever the attacker put
in the `MessageData`, and simulate runs on whichever validators
receive the RPC. The clock argument is irrelevant: the store
diverges because it's WRITTEN by gRPC traffic, not because the
clock chosen is non-deterministic.

A secondary consequence (smaller but real): an attacker with any
non-zero fee balance ≥ `effective_fee` can plant unlimited
fingerprints WITHOUT actually paying any fee, because `stage_fee`'s
debit goes only to the simulate-path txn_batch that is discarded —
but `record_fingerprint_if_cast` writes directly to disk. The
attacker pays nothing yet gets to author the uniqueness
"history" that all subsequent CastAdds will be scored against on
this validator's node.

A tertiary consequence: an attacker can permanently EVICT
fingerprints older than 30 days by submitting a CastAdd whose
SimHash falls in the same top-64-bit bucket; eviction is per-bucket
on every read.

## Description

### Where the fingerprint store feeds consensus

`FeeCharger::stage_fee` (`fee_charger.rs:76-130`) is invoked from
`ShardEngine::merge_message` (`engine.rs:1240`) on every user-message
merge. For CastAdd messages (line 107-121), it calls
`self.fingerprint_store.uniqueness_score(text, data.timestamp as
u64)`. The returned `uniqueness` is plugged into
`compute_effective_fee_micro(base, trust, uniqueness)`
(`fees.rs:58-71`), which is `(base * (1 - max(trust_discount,
uniqueness_discount))).floor()`. The result `fee` is passed to
`reward_store.stage_charge_message_fee(sender_fid, fee, batch)`
(`fee_charger.rs:127-128`), which stages writes to `fee_balance_key(fid)`,
`total_burned_key()`, and `proposer_pot_key()` on the engine's
`txn_batch`. These keys participate in the shard's account state and
are covered by `account_root` (per `replay_snapchain_txn`'s trie
updates).

So a divergence in `uniqueness_score` between validators causes a
divergence in `fee` for that CastAdd, which causes a divergence in
the post-merge value of `fee_balance(fid)` (and global counters,
which are global singletons that ALL validators must agree on).

### Why the fingerprint store diverges between validators

`FingerprintStore::insert` (`fingerprint_store.rs:81-88`):

```rust
pub fn insert(&self, fid: u64, text: &str, ts_secs: u64) -> Result<u128, FingerprintError> {
    let fp = fingerprint(text);
    let high = (fp >> 64) as u64;
    let key = Self::full_key(high, ts_secs, fid);
    let val = fp.to_le_bytes();
    self.db.put(&key, &val).map_err(HubError::from)?;   // <-- DIRECT DB PUT
    Ok(fp)
}
```

Note: no `&mut RocksDbTransactionBatch` parameter. The write goes
directly to RocksDB via `self.db.put`. `RocksDB::put`
(`rocksdb.rs:355-362`) writes synchronously into the live DB
transaction provider with no relationship to whatever
`RocksDbTransactionBatch` the caller may be holding.

`FingerprintStore::uniqueness_score` (`fingerprint_store.rs:93-144`):

```rust
pub fn uniqueness_score(&self, text: &str, now_secs: u64) -> Result<f64, FingerprintError> {
    ...
    self.db
        .for_each_iterator_by_prefix(...)   // direct DB read, not batch-aware
        .map_err(...)?;

    if !to_evict.is_empty() {
        let mut batch = self.db.txn();
        for k in to_evict {
            batch.delete(k);
        }
        self.db.commit(batch).map_err(HubError::from)?;  // <-- INDEPENDENT COMMIT
    }
    ...
}
```

The eviction commit (`self.db.commit(batch)`) is its own,
independent `RocksDbTransactionBatch` constructed locally and
committed inside `uniqueness_score`. It is not the caller's batch,
not the engine's batch — it lands in RocksDB immediately and
permanently regardless of whether the surrounding merge eventually
commits.

`FeeCharger::record_fingerprint_if_cast`
(`fee_charger.rs:135-162`) calls the bare `insert`; the
`record_fingerprint_if_cast` site in `merge_message`
(`engine.rs:1336`) calls it AFTER the inner-store merge succeeds but
BEFORE the engine's outer `db.commit(txn)` is run. The fingerprint
write therefore happens on the live DB even if the engine later
returns `EngineError::HashMismatch` or rolls back, or — more
importantly — even if the caller is `simulate_message` (which
explicitly discards `txn_batch`).

The author of `merge_message` was aware of this (`engine.rs:1331-1335`):

```text
// Now that the merge succeeded, record the CastAdd fingerprint
// so subsequent casts in the 30-day window see this content as
// a near-dup. This write goes directly to the DB (not the txn
// batch) because the fingerprint store is best-effort scoring
// data — losing one on a crash before commit is acceptable.
```

The justification is correct for `Commit`-source proposals (where
the engine immediately commits the txn_batch after merge, and the
fingerprint is "good enough" even if the very last step crashes),
but it's silently false for `Validate`-source proposals (which can
return `Err(HashMismatch)` and discard the txn_batch — yet the
fingerprint persists, and gives this validator's uniqueness
machinery a fingerprint that no other validator has) and outright
broken for `Simulate`-source proposals, which are explicitly
intended to commit nothing.

### Why every gRPC `submit_message` reaches `merge_message`

`Server::submit_message_internal` (`network/server.rs:441-472`):

```rust
async fn submit_message_internal(
    &self,
    message: proto::Message,
) -> Result<proto::Message, HubError> {
    let fid = message.fid();
    if fid == 0 {
        return Err(HubError::invalid_parameter("fid cannot be 0"));
    }
    let dst_shard = routing::route_message(&self.message_router, &message, self.num_shards);
    match self
        .simulate_message_for_shard_typed(&message, dst_shard)
        .await
    {
        Ok(()) => {}
        Err(engine::MessageValidationError::MissingFname) => { /* fname recovery */ }
        Err(err) => return Err(simulate_error_to_hub_error(err)),
    }
    self.submit_message_to_mempool(message).await
}
```

The simulate happens UNCONDITIONALLY on every gRPC submitMessage
RPC. The result of simulate gates mempool admission, but the
side-effects on the fingerprint store happen regardless of whether
the simulate result is Ok or Err.

`simulate_message_for_shard_typed` (`network/server.rs:732-787`)
constructs a `ShardEngine::new(stores.db.clone(), ...)` and calls
`simulate_message`. The `stores.db` is the live consensus shard's
RocksDB, shared via `Arc<RocksDB>`. The comment-named "readonly"
designation is purely a code-level convention; nothing prevents
writes.

`ShardEngine::simulate_message` (`engine.rs:2108-2151`) calls
`replay_snapchain_txn` (line 2121), which calls `merge_message`
(line 1001), which calls `fee_charger.stage_fee` (line 1240) and
`fee_charger.record_fingerprint_if_cast` (line 1336). The fingerprint
DB write happens. Then `simulate_message` returns and the
`txn_batch` is dropped (its `RocksDbTransactionBatch` is a local
variable). `self.stores.trie.reload(&self.db)` discards trie
mutations. But the fingerprint and the eviction commits have ALREADY
landed in `self.db`.

### Concrete divergence scenario (consensus fork)

Setup: three validators V_A, V_B, V_C, each running the same code,
each with an independent RocksDB. Network-level: V_A is reachable
from the public Internet on its gRPC port; V_B is behind a private
load balancer; V_C is behind a different private load balancer.

Step 1. Attacker (any FID with `fee_balance >= 1`) opens a gRPC
connection to V_A and calls `submit_message` with a CastAdd:

```
fid = X
timestamp = 1_700_000_000
text = "literally any spam phrase that another user will quote later"
```

V_A's `simulate_message_for_shard_typed` is invoked. Inside, on
V_A's RocksDB only:

- `stage_fee` calls `uniqueness_score("literally any...", 1_700_000_000)`.
  No matching fingerprint exists → returns 1.0. Eviction commit may
  occur for any fingerprints in the bucket with `ts < 1_700_000_000
  - 30d`; this also lands only on V_A.
- `stage_fee` stages a fee debit to txn_batch (discarded later).
- The cast-store `merge` writes to txn_batch (discarded later).
- `record_fingerprint_if_cast` calls
  `FingerprintStore::insert(X, "literally any...", 1_700_000_000)`
  → `self.db.put(...)` lands on V_A's RocksDB permanently.

V_A returns Ok or Err to the attacker; either way, the mempool may
or may not propagate the message. The attacker doesn't care; they
got V_A to plant a fingerprint.

Step 2. Some time later, a legitimate user U on V_B submits a
CastAdd quoting (or otherwise overlapping the SimHash of) the
attacker's planted text:

```
fid = U
timestamp = 1_700_500_000
text = "+1, literally any spam phrase that another user will quote later"
```

This goes through the mempool and reaches a block proposer P; P
includes U's CastAdd in shard S of block N.

Step 3. Each validator runs `validate_state_change` (`engine.rs:1749`)
→ `replay_proposal` → `replay_snapchain_txn` → `merge_message` →
`stage_fee` → `uniqueness_score(U's text, U's timestamp)`. The
SimHash of U's text falls in the same top-64-bit bucket as the
attacker's planted text (the goal of the attacker's text choice).

- V_A scans its bucket: finds the attacker-planted fingerprint;
  hamming distance to U's text ≤ 6 → `near_dup_count = 1` →
  `uniqueness_score = 1 - 1/8 = 0.875`. `effective_fee = base *
  (1 - max(trust_discount, 0.875 * MAX_UNIQUENESS_DISCOUNT))`.
- V_B / V_C scan their buckets: empty → `near_dup_count = 0` →
  `uniqueness_score = 1.0` → `effective_fee = base * (1 -
  max(trust_discount, MAX_UNIQUENESS_DISCOUNT))`.

V_A's `effective_fee` is strictly larger than V_B's (because
V_A applies less uniqueness discount). The difference may be
hundreds of micros; the magnitude doesn't matter, only that it's
nonzero.

`stage_charge_message_fee(U, V_A_fee, batch)` and
`stage_charge_message_fee(U, V_B_fee, batch)` stage DIFFERENT
deltas to `fee_balance_key(U)`, `total_burned_key()`, and
`proposer_pot_key()`. After the trie update, V_A's account_root and
V_B's account_root differ. P's published `shard_root` matches
either V_A or V_B (whichever fingerprint state P had locally — the
proposer themselves is just one validator), and the other(s) return
`Err(EngineError::HashMismatch)` from `replay_proposal`
(`engine.rs:587, 604`).

Result: validators fork on a block produced by honest behaviour.
The attacker's only action was an unauthenticated (or
trivially-authenticated, depending on operator config) gRPC
`submit_message` call to one of the validator nodes.

### Variant: any CastAdd at all triggers eviction

The `uniqueness_score` eviction tail (`fingerprint_store.rs:135-141`)
runs on every call. So even a single attacker `submit_message`
whose simulate succeeds (or fails after `stage_fee`) on V_A but
not on V_B causes V_A to delete fingerprints in the inspected
bucket that are older than 30 days but that V_B still has. The
next consensus replay over a CastAdd hitting the same bucket
diverges in the opposite direction (V_A under-counts duplicates,
V_B over-counts) — same fork mechanism.

### Variant: fee-free fingerprint poisoning

Separately from consensus fork — even before any honest user
quotes the attacker's text — the simulate path lets the attacker
plant arbitrarily many fingerprints without paying ANY fee:

- `stage_fee` reads `fee_balance(X)` from disk (per F132, directly,
  not via batch), checks `cur >= fee`, stages `cur - fee` to
  txn_batch.
- Txn_batch is discarded by simulate.
- `fee_balance(X)` on disk is unchanged.
- BUT `record_fingerprint_if_cast`'s `self.db.put` already landed.

So if the attacker has `fee_balance(X) = 1`, they can repeatedly
call `submit_message` with `effective_fee = 1` CastAdds (e.g., a
high-trust account with `trust ≈ 1.0` so `effective_fee` is the
floor 0 — wait, even better: if `effective_fee == 0` the early
return at `fee_charger.rs:124-125` skips `stage_charge_message_fee`
entirely, but `record_fingerprint_if_cast` is in `merge_message`
AFTER the inner-store merge, which still runs).

Actually the simpler case: a freshly-funded account with `fee_balance
= 1_000_000` can submit a million CastAdds via gRPC. Each one
plants a fingerprint on the receiving validator's disk. NONE of
them pay any fee (txn_batch is discarded). The fingerprint store
grows without bound; the attacker's fee balance stays intact.

If the operator runs without authentication (the default in the
shipping codebase), the cost is the bandwidth of the gRPC connection
and nothing else.

### Variant: forced eviction of >=30-day-old fingerprints

The eviction tail will DELETE every fingerprint in the queried
bucket whose `ts < now_secs - FINGERPRINT_WINDOW_SECS`. `now_secs`
comes from `data.timestamp` (the message-data timestamp, which the
attacker controls). So the attacker can submit a CastAdd with
`data.timestamp = far_future` to evict fingerprints whose
`ts < far_future - 30d`, which can be ALL fingerprints in the
bucket. This is a one-call permanent wipe of the bucket's
historical fingerprints, on the receiving validator's disk.

Combined with the poisoning variant: an attacker can wipe an
established near-dup history (e.g., for popular meme content) on
one validator, allowing whoever next reposts that content to enjoy
a full uniqueness discount that other validators don't grant —
again, fork. Or the attacker can simply degrade the fingerprint
store on a validator while leaving others intact, degrading that
validator's anti-spam protections while keeping the others
"correct" — yielding a measurable fee divergence across the
validator set even without immediate fork (because the lower-fee
calculation on the degraded validator simply means it disagrees
with the proposer's high-fee account_root on every spam CastAdd).

### Why this is structurally a fork, not just a fee-accounting bug

The fingerprint store directly drives `effective_fee`. The
`effective_fee` is debited from `fee_balance(fid)` in the engine's
`txn_batch`, written to `fee_balance_key(fid)` (under
`RootPrefix::Hyper...`). `update_trie` (`engine.rs:1009`) updates
the merkle trie with the merge events (CastAdd hashes etc.), and
the trie root + the account state under HyperFeeBalance keys both
contribute to the account_root that `replay_proposal` compares
against `shard_root`.

`account_root` is computed across the engine's pending state at
chunk-commit time. If `fee_balance(fid)` differs by even one micro
between two validators, the `account_root` differs (it's a merkle
hash of the encoded value), and the comparison at `engine.rs:604`
(`if root != shard_root.as_ref() ...`) fires.

Note: even though `total_fee_burned` and `proposer_fee_pot` are
GLOBAL singleton keys, they are still in the merkle-trie-covered
account state and any divergence propagates the same way.

### Difference from F015, F033, F132

- F015 (`credit_if_unissued`): two separate WAL groups inside a
  retroactive-credit path. Out of scope here; same-batch issue.
- F033 (Stage-A / Stage-B split): cross-batch composition across
  hyperblock import. Different mechanism.
- F132 (`stage_charge_message_fee` read-after-write collapse): the
  WRITES correctly go to the engine's txn_batch but the READS bypass
  the batch. F132 is invisible to other validators (everyone runs
  the same broken arithmetic, deterministic shortfall, no fork).
- F133 (this finding): the fingerprint store is the OPPOSITE — its
  writes bypass the engine's txn_batch entirely, and worse, they
  happen on gRPC `submit_message` simulate (which is supposed to
  be side-effect-free). F133 produces DIVERGENT writes across
  validators, hence the fork. F132 and F133 are independent
  pathologies that happen to share an "adjacent observation" note
  in F132.

## Reproduction / proof-of-witness sketch

### Unit-level (deterministic, no networking)

Construct two `FingerprintStore` instances backed by separate
`TempDir`s — call them `store_A` and `store_B`. Insert one
fingerprint into A only (simulating "V_A received an RPC, V_B
didn't"):

```rust
store_A.insert(99, "literally any spam phrase that another user will quote later", 1_700_000_000).unwrap();
```

Now compute `uniqueness_score` on both for a near-duplicate text:

```rust
let s_a = store_A.uniqueness_score("+1, literally any spam phrase that another user will quote later", 1_700_500_000).unwrap();
let s_b = store_B.uniqueness_score("+1, literally any spam phrase that another user will quote later", 1_700_500_000).unwrap();
assert_ne!(s_a, s_b);  // s_a == 0.875, s_b == 1.0
```

`compute_effective_fee_micro(base, trust=0.0, s_a)` and
`compute_effective_fee_micro(base, trust=0.0, s_b)` produce
different values; this is the fee divergence that drives the
account_root divergence.

### Integration-level (single-process, no networking)

A test that:
1. Spins up two `ShardEngine`s pointed at separate RocksDBs,
   `engine_A` and `engine_B`, with the same network/shard config.
2. Calls `engine_A.simulate_message(&attacker_castadd)`.
3. Does NOT call simulate on engine_B.
4. Submits a benign `victim_castadd` (whose text near-duplicates
   `attacker_castadd.text`) to BOTH engines via `validate` (the
   consensus-replay path), with the same proposer-published
   `shard_root` computed from one of them.
5. Asserts that `engine_A.validate_state_change(...)` and
   `engine_B.validate_state_change(...)` produce different account
   states — concretely, `RewardStore::fee_balance_of(victim_fid)`
   differs by `(s_b - s_a) * MAX_UNIQUENESS_DISCOUNT * base` micros.
6. Asserts that whichever engine matched the proposer's `shard_root`
   returns `true` from `validate_state_change`, and the other
   returns `false` with `EngineError::HashMismatch` in logs.

### Network-level (mainnet-realistic)

Standing up two hypersnap nodes from this commit
(`6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae`) with a shared validator
set in a devnet:

1. Bring up node_A and node_B; both join consensus, both replay genesis.
2. From an external client, dial `node_A`'s gRPC and call
   `submitMessage` with the attacker's CastAdd. Do NOT dial node_B.
3. Wait for any block proposer to include a near-duplicate CastAdd
   from any FID.
4. Observe `node_A`'s log: "State change validation failed:
   HashMismatch" (or the opposite, depending on which side the
   proposer was on). The two nodes' shard chunks diverge starting at
   that block.

## Remediation

Three viable fixes; (A) is the structurally correct one.

### Option A — make `FingerprintStore` batch-aware; thread `txn_batch` through

Change `insert` and the eviction tail of `uniqueness_score` to take
`&mut RocksDbTransactionBatch` and stage writes/deletes via
`batch.put` / `batch.delete`. Change `uniqueness_score`'s read loop
to consult `batch.batch.get(...)` first when iterating (or — simpler
— compose a snapshot view of "DB rows merged with pending-batch
puts/deletes" for the bucket scan, modelled on the pattern at
`storage/store/account/message.rs:234`).

Propagate the `batch` argument through `FeeCharger::stage_fee` and
`record_fingerprint_if_cast`. Both already receive the batch from
`merge_message`; threading it through `FingerprintStore` is purely
mechanical.

After this change:

- The fingerprint write composes atomically with the engine's
  txn_batch. On a `Commit`-source merge, it commits. On a
  `Validate`-source merge that returns `HashMismatch`, the batch is
  dropped and the fingerprint is not persisted. On a `Simulate`,
  the batch is explicitly dropped, so the fingerprint is not
  persisted.
- The eviction commits become deletions on the same batch — they
  compose with the commit / abort decision.
- Validators see identical fingerprint state at consensus replay
  time; `uniqueness_score` returns the same value on every
  validator; no fork.

### Option B — gate fingerprint writes by `ProposalSource`

Less invasive but less robust: pass `ProposalSource` (or a
`is_dry_run: bool`) into `FeeCharger::stage_fee` /
`record_fingerprint_if_cast`. Skip the `insert` call and skip the
eviction commit on `ProposalSource::Simulate`. Continue to commit
on `ProposalSource::Commit`. On `ProposalSource::Validate`,
DO NOT commit — defer to the engine's outer commit by buffering
the fingerprint write into the engine's `txn_batch` (which requires
Option A's batch threading anyway).

Option B alone (skip on Simulate) closes the fee-free poisoning and
the forced-eviction attack surface, but does not close the
`Validate`-source variant: a validator that ran `Validate` and
returned HashMismatch still has the fingerprint written to disk.
The fork mechanism survives any case where one validator's
`Validate` runs further than another's before short-circuiting.

### Option C — make the fingerprint store ephemeral / non-consensus-visible

Move the fingerprint store off RocksDB and into an in-memory LRU
cache that is not consulted during `replay_proposal`. Pre-compute
the uniqueness score offline (e.g., as part of `submit_message` and
attach to the message envelope; have the proposer commit the
attested uniqueness score) so consensus replay reads a value bound
to the message instead of recomputing from local state.

This is the heaviest change but it eliminates the structural
problem that local-mutable-DB state participates in consensus fee
computation.

### Required tests after fix

1. Two-engine divergence test (the integration-level reproduction
   above) — must demonstrate identical account_root after
   simulate-only-on-A traffic.
2. Simulate-no-side-effect test: `simulate_message(&castadd); let
   fp_count_before = ...; simulate_message(&castadd); let
   fp_count_after = ...;` assert `fp_count_before == fp_count_after
   == 0`.
3. Commit-side-effect test: a real `replay_proposal` →
   `commit_and_emit_events` flow inserts the fingerprint exactly
   once.
4. Eviction-atomicity test: a `Validate`-source replay that returns
   `HashMismatch` must NOT delete any fingerprints from disk.

### Note on the existing F132 "adjacent observation"

F132's "Adjacent observation" (`F132-stage-charge-message-fee-read-after-write-collapse.md:345-360`)
flags the `FingerprintStore::uniqueness_score` eviction commit and
the `FingerprintStore::insert` direct-write as
"determinism-adjacent" and "out of scope for the H132 fee-flow
finding." F133 is that scope: the full impact is consensus fork
via gRPC, plus fee-free poisoning, plus forced eviction. The
remediation in F132 Option A (read-through-batch) is necessary but
not sufficient; F133 Option A (write-through-batch) is the
complementary fix.

## Severity rationale

- **Impact (consensus fork):** A single anonymous gRPC
  `submit_message` call to one validator suffices to plant
  divergent fingerprint state. Any subsequent CastAdd whose
  SimHash bucket overlaps with the planted fingerprint produces a
  divergent `effective_fee`, divergent `fee_balance(fid)`,
  divergent account_root, and `EngineError::HashMismatch` on the
  validators that don't match the proposer's local fingerprint
  state. This is a network-halt or chain-split vector triggered by
  trivial unauthenticated input.
- **Impact (fee-free fingerprint poisoning):** An attacker with any
  non-zero fee balance can plant arbitrarily many fingerprints on
  any validator's RocksDB at zero recurring cost. The fingerprint
  store grows without bound. Uniqueness scoring becomes
  attacker-attested for any text the attacker pre-plants.
- **Impact (forced eviction):** An attacker with attacker-controlled
  `data.timestamp` can wipe entire SimHash buckets on a target
  validator, degrading anti-spam protections on that validator while
  leaving others intact.
- **Pre-conditions:** gRPC ingress reachability + at least one of
  (any non-zero `fee_balance`, or any CastAdd that passes
  `validate_user_message` — note that the eviction tail runs
  regardless of `stage_fee` outcome, because the read happens
  before the InsufficientBalance check).
- **Detection difficulty:** Hard at consensus-replay time (the
  validator just sees `HashMismatch` and assumes the proposer
  cheated; the offending RPC traffic happened on a different
  validator). Detectable in retrospect by cross-validator audit of
  RocksDB fingerprint key counts (each validator has different
  totals).
- **Crash-safety / determinism:** The fingerprint store comment at
  `fingerprint_store.rs:79-80` SPECIFICALLY claims determinism
  (block-clock argument). The claim is false in the presence of the
  simulate path.
- **Comparison to validated iter-1 / iter-2 findings:** Most similar
  in mechanism to F033 (Stage-A/Stage-B split across separate
  batches), but structurally worse because the second "batch" is
  the bare DB. Comparable in attacker-input shape to F036
  (proposer-grindable committee-selection digest), but the trigger
  here is unauthenticated gRPC, not a privileged proposer. Bumping
  to **Critical** on the consensus-fork severity; if the operator
  team objects on grounds that "gRPC is usually authenticated in
  production," downgrade to High — but the shipping default has no
  auth and the fee-free poisoning + forced eviction variants
  survive even with auth (since any FID-holder is an authenticated
  attacker).
