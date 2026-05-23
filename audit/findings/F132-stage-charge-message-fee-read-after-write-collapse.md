---
id: F132
task: H132
attack_class: fee-trust-uniqueness-flow
severity: high
status: draft
related_findings:
  - id: F133
    relationship: related-but-distinct
  - id: F135
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.96
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F132 — `RewardStore::stage_charge_message_fee` reads `fee_balance` / `total_fee_burned` / `proposer_fee_pot` directly from disk, so multiple fee-bearing messages from the same FID in one shard transaction collapse to a single charge and silently lose burn + proposer-pot accounting

- **Task:** H132
- **Attack class:** `fee-trust-uniqueness-flow` (read-after-write in a caller-supplied `&mut RocksDbTransactionBatch`)
- **Severity (provisional):** High. Silent fee evasion by any FID with `>= 2` fee-bearing messages in a single snapchain `Transaction` (which by `blocks.proto:179-184` groups ALL of an FID's user_messages in one chunk), plus silent loss of the corresponding burn and proposer-pot deltas — every fee-bearing message after the FIRST in a snapchain transaction is effectively FREE and contributes nothing to the burn counter or proposer pot. Conservation invariant "debited = burned + proposer_share" breaks per-batch.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/rewards.rs:576-618` — `stage_charge_message_fee`; the three `self.db.get(...)`-backed reads (`fee_balance_of`, `total_fee_burned`, `proposer_fee_pot`) feed three `batch.put(...)` writes whose keys are identical across same-FID calls (`fee_balance_key(fid)`) or globally singleton (`total_burned_key()`, `proposer_pot_key()`), so successive calls in the same batch overwrite each other.
- `code/hypersnap/src/hyper/rewards.rs:422-437` — `fee_balance_of`; direct `self.db.get(&Self::fee_balance_key(fid))`, no batch parameter.
- `code/hypersnap/src/hyper/rewards.rs:537-566` — `total_fee_burned` / `proposer_fee_pot`; both direct `self.db.get(...)`, no batch parameter.
- `code/hypersnap/src/hyper/fee_charger.rs:76-130` — `stage_fee` is the sole production caller, invoked per-message from `merge_message`.
- `code/hypersnap/src/storage/store/engine.rs:1217-1340` — `merge_message`; instantiates a fresh `FeeCharger` per message and calls `stage_fee(msg, txn_batch)` against a `txn_batch` shared across the WHOLE shard chunk (all `snapchain_txn`s, all `user_messages` per `snapchain_txn`).
- `code/hypersnap/src/storage/store/engine.rs:960-1041` — sorted-user_messages loop; iterates every message of an FID against the same `txn_batch`.
- `code/hypersnap/src/storage/db/rocksdb.rs:32-55` — `RocksDbTransactionBatch` is a plain `HashMap<Vec<u8>, Option<Vec<u8>>>` with `put` / `delete` / `merge` but **no `get`**; reads must come from `RocksDB::get` which goes to the underlying CF and does NOT see pending batch entries.
- `code/hypersnap/proto/definitions/blocks.proto:179-184` — `message Transaction { uint64 fid = 1; repeated Message user_messages = 2; ... }` — by protocol design, every snapchain transaction is per-FID and holds an unbounded list of user_messages.

## Summary

Per-message fees are charged inside `merge_message`
(`src/storage/store/engine.rs:1234-1260`) via
`FeeCharger::stage_fee → RewardStore::stage_charge_message_fee`. The
write-side correctly goes through the caller-supplied
`&mut RocksDbTransactionBatch` (this is what H035's per-store sweep
ruled OK at the WRITE level). However, the READ side of
`stage_charge_message_fee` (`rewards.rs:585-603`) reads three values
from RocksDB **directly**, not from the pending batch:

1. `cur = self.fee_balance_of(sender_fid)?` → `self.db.get(&Self::fee_balance_key(fid))` (`rewards.rs:424-437`).
2. `self.total_fee_burned()?` → `self.db.get(&Self::total_burned_key())` (`rewards.rs:537-550`).
3. `self.proposer_fee_pot()?` → `self.db.get(&Self::proposer_pot_key())` (`rewards.rs:553-566`).

Because `RocksDbTransactionBatch` is a plain `HashMap` with no `get`
method (`rocksdb.rs:32-55`), and other parts of the engine that need
read-after-write semantics explicitly consult
`txn_batch.batch.get(&key)` first
(e.g. `storage/trie/merkle_trie.rs:383`,
`storage/store/account/message.rs:234`,
`api/channels.rs:163,182`,
`api/social_graph.rs:601`,
`api/metrics.rs:244`,
`storage/store/node_local_state.rs:244`), the fee-charging path is
unique in the codebase in NOT doing this lookup. The result is that
multiple `stage_charge_message_fee(fid, ...)` calls in the same batch
overwrite each other's batch entries with stale-base deltas:

- All N calls observe the same pre-batch `fee_balance(fid)` and stage the same `(pre_balance - total_N)` to `fee_balance_key(fid)`. The HashMap deduplicates by key, so only the LAST staged value commits. The user pays for exactly ONE message, not N.
- All N calls observe `total_fee_burned == X` and stage `X + burn_N` to `total_burned_key()`. Only the last value commits. The cumulative burn counter is incremented by ONE message's burn share, not N's.
- All N calls observe `proposer_fee_pot == Y` and stage `Y + proposer_share_N` to `proposer_pot_key()`. Only the last value commits. The proposer's collected fee pot is incremented by ONE message's share, not N's.

Net per shard chunk: for any FID submitting K >= 2 fee-bearing messages,
only one fee is actually debited; the burn counter and proposer pot
each receive ONE message's share, and the conservation invariant
"sum of fee_balance debits == sum of burn + sum of proposer_share"
silently breaks (in fact the on-disk delta satisfies `debited = burn +
proposer_share` for the LAST message only, but the value that was
"supposed" to be charged across all K messages is silently dropped).

## Description

### The merge-path commit boundary is the entire shard chunk

`replay_proposal` (`engine.rs:525-611`) iterates every `snapchain_txn`
in the chunk and calls `replay_snapchain_txn(..., txn_batch, ...)`. The
same `&mut RocksDbTransactionBatch` is threaded through every
`replay_snapchain_txn` call. Inside `replay_snapchain_txn`
(`engine.rs:715-958`), the user-messages loop at lines 997-1041
processes each sorted message via `merge_message(msg, txn_batch)` using
the **same** batch. `merge_message` (`engine.rs:1217-1340`) is the sole
caller of `FeeCharger::stage_fee`, which is the sole caller of
`RewardStore::stage_charge_message_fee`. The shard chunk's atomic
commit happens later, at `engine.rs:1838`
(`self.db.commit(txn).unwrap();`). Between every call to
`stage_charge_message_fee` and the final commit, the batch is
in-memory only.

Per `blocks.proto:179-184`, a `Transaction` is per-FID with a
`repeated Message user_messages`. So multiple fee-bearing messages
from the same FID can appear in one Transaction, and `replay_proposal`
processes them all against the same `txn_batch`. Even across distinct
`snapchain_txn`s — if two Transactions belong to the same FID (or to
two FIDs where one or both submits multiple messages of their own),
the batch is shared. The collapse semantics apply per (fid, key)
across the entire chunk.

### The exact read-after-write inconsistency

`stage_charge_message_fee` (`rewards.rs:576-618`):

```rust
pub fn stage_charge_message_fee(
    &self,
    sender_fid: u64,
    total: u64,
    batch: &mut crate::storage::db::RocksDbTransactionBatch,
) -> Result<(), RewardError> {
    if total == 0 { return Ok(()); }
    let cur = self.fee_balance_of(sender_fid)?;          // (1) DB read
    if cur < total { return Err(... InsufficientBalance ...); }
    let new_fee_balance = cur - total;
    let (burn, proposer_share) = proof_of_quality::fees::split_burn_proposer(total);
    let new_burned   = self.total_fee_burned()?.checked_add(burn as u128)...; // (2) DB read
    let new_pot      = self.proposer_fee_pot()?.checked_add(proposer_share)...; // (3) DB read

    batch.put(Self::fee_balance_key(sender_fid).to_vec(), new_fee_balance.to_be_bytes().to_vec()); // (A) HashMap put
    batch.put(Self::total_burned_key().to_vec(),         new_burned.to_be_bytes().to_vec());      // (B) HashMap put
    batch.put(Self::proposer_pot_key().to_vec(),         new_pot.to_be_bytes().to_vec());         // (C) HashMap put
    Ok(())
}
```

Every read at (1), (2), (3) calls `RocksDB::get(...)` via
`self.db.get(...)` (`rewards.rs:424-437, 537-550, 553-566`). The
`RocksDB::get` implementation at `rocksdb.rs:329-336` goes to the
underlying RocksDB column family — it cannot see pending writes
staged in the in-memory `RocksDbTransactionBatch` HashMap, because
that HashMap is owned by the caller and has no relationship to the
RocksDB read transaction.

Compare to the contract pattern used elsewhere in the codebase for
exactly this case
(`storage/store/account/message.rs:234`):

```rust
if let Some(value) = txn.batch.get(key) {
    // honour pending batch entry
}
```

`stage_charge_message_fee` does not do this lookup.

The three batch.put calls at (A), (B), (C) write into the HashMap
keyed by `fee_balance_key(fid)`, `total_burned_key()`,
`proposer_pot_key()`. The first two keys are FID-scoped; (B) and (C)
are GLOBAL singleton keys. Subsequent calls within the same batch
write the same three keys, and `HashMap::insert` returns the previous
value while replacing it (`rocksdb.rs:44-46` —
`self.batch.insert(key, Some(value))`). So per (fid, key) the LAST
staged value is what commits, and earlier staged values are silently
dropped.

### Concrete witness — three CastAdds from one FID

Pre-state: `fee_balance(fid=7) = 1000`, `total_fee_burned = 0`,
`proposer_pot = 0`. Three CastAdds, each computing `effective_fee =
100` (base 100, trust=0, uniqueness=1, so no discount), with
60/40 burn/proposer split.

Call 1 (`stage_charge_message_fee(7, 100, batch)`):
- DB reads: cur=1000, burned=0, pot=0.
- Stages: `fee_balance_key(7) -> 900`, `total_burned_key -> 60`, `proposer_pot_key -> 40`.

Call 2 (`stage_charge_message_fee(7, 100, batch)`):
- DB reads: cur=1000 (still — batch not committed), burned=0 (still), pot=0 (still).
- Stages (overwrites batch entries): `fee_balance_key(7) -> 900`, `total_burned_key -> 60`, `proposer_pot_key -> 40`.

Call 3 (same): again overwrites with `900 / 60 / 40`.

On `db.commit(batch)` at `engine.rs:1838`:
- `fee_balance(7) = 900` — debited 100, not 300.
- `total_fee_burned = 60` — incremented by one cast's burn, not three's.
- `proposer_fee_pot = 40` — credited one cast's proposer share, not three's.

Two of the three casts were entirely free. The "burn 60% / proposer
40%" accounting recorded the equivalent of ONE message. The other 200
atoms that "should" have been debited from fid=7 were never debited;
they remain in fid=7's fee balance. The system simultaneously
under-burned by 120 atoms and under-credited the proposer pot by 80
atoms.

The conservation invariant (`Σ debits == Σ burns + Σ proposer_shares`)
is preserved per-commit (60 + 40 == 100 == observed debit) — but the
expected invariant (`Σ effective_fees over all merged messages == Σ
debits`) breaks: 3 * 100 = 300 effective fees were charged, but only
100 was actually debited. The 200-atom shortfall accrues as silent
under-burn + silent under-payout to the proposer.

### Exploit path — fee evasion by batching

A user wishing to spam K fee-bearing messages cheaply needs only to
submit them via the same shard's snapchain transaction. Sequencer
behavior under load typically aggregates a single FID's mempool
messages into one Transaction (this is `merge_messages_in`'s natural
shape; the user can also influence this by sending in burst), and the
result is that K messages cost the user the fee for ONE.

A user with fee_balance = `base_fee` (the minimum to pass the
`InsufficientBalance` check) can sustain unbounded K message bursts
per shard chunk indefinitely — because after each shard commit the
fee balance is only debited by ONE message's worth, the same balance
funds the next K-burst, and so on. The only practical limit is the
mempool / shard-throughput rate, not the fee balance.

The asymmetric trust×uniqueness discount makes this worse for spam:
duplicate casts have uniqueness near 0 (low effective fee) and
high-trust accounts have effective_fee near 0 anyway, so the
attacker's marginal cost per spammed cast is already small; the
batching bug compounds the loss because the protocol believes it is
charging K * effective_fee but really only charges 1 * effective_fee.

### Damage to burn + proposer pot accounting

Even if no user attempted to exploit the bug — which is unlikely
because batching is the default sequencing behaviour — the routine
per-chunk operation silently under-burns and under-pays proposers
whenever any FID has `>= 2` fee-bearing messages in the chunk:

- The `HyperTotalFeeBurned` global counter no longer represents the
  cumulative atoms "removed from supply." It's a strict undercount,
  monotonically widening as throughput grows.
- The `HyperProposerFeePot` (`drain_proposer_fee_pot` at
  `rewards.rs:623-643`) pays the proposer at chunk finalization. Each
  chunk where any FID submitted multiple fee-bearing messages pays
  the proposer strictly less than the protocol "intends" — the
  difference is unaccounted-for (it stays in the user's fee balance,
  so it'll eventually be re-debited when that user sends a later
  isolated message, but the proposer for THIS chunk receives the
  short share; the chunk's proposer never recovers the missing
  payout, because the missing burns/credits were attributed in-batch
  but overwritten and the proposer who eventually drains the pot will
  be the proposer of the LATER chunk that finally debits).

This redistributes proposer fees from chunk-N proposers to chunk-(N+k)
proposers in a fashion that is not protocol-specified and that
high-throughput proposers cannot predict or compensate for.

### Comparable sites in the codebase that DO get this right

For reference, the pattern of "stage a write that depends on a
batch-pending value" is solved in
`storage/store/account/message.rs:234` and `storage/trie/merkle_trie.rs:383`
by consulting `txn.batch.get(key)` first and falling back to
`db.get(key)`. The `stage_charge_message_fee` path is the only
arithmetic-accumulator-update path in `src/hyper/` that does NOT use
this idiom; it is the only place where same-key writes from
sequential same-batch callers must compose additively rather than
last-write-wins.

Note: this is structurally distinct from F015 (which is about a crash
between two SEPARATE WAL groups in `credit_if_unissued`) and F033
(which is about Stage-A / Stage-B split across separate batches in
hyperblock import). H035's per-store sweep called out
`stage_charge_message_fee` as "correctly composes with the engine's
commit" — that statement is true for crash-safety (the writes ARE
batched into the engine's atomic commit) but false for
within-batch read-after-write composition (the reads bypass the batch
entirely).

## Reproduction / proof-of-witness sketch

A unit test against `RewardStore::stage_charge_message_fee` (no
mocks; the test harness in `rewards.rs:703-1058` already opens a real
RocksDB via `TempDir`) demonstrates the collapse in <30 lines:

```rust
#[test]
fn stage_charge_message_fee_collapses_within_a_single_batch() {
    let (store, _dir) = make_store();
    // top up fid 7 with 1_000 atoms of fee balance
    store.credit_if_unissued(0, 7, proto::WorkMarket::Growth as i32, 10_000).unwrap();
    store.apply_fee_deposit(7, 1_000, 1).unwrap();

    // charge 100 atoms three times into the SAME batch
    let mut batch = store.db.txn();
    store.stage_charge_message_fee(7, 100, &mut batch).unwrap();
    store.stage_charge_message_fee(7, 100, &mut batch).unwrap();
    store.stage_charge_message_fee(7, 100, &mut batch).unwrap();
    store.db.commit(batch).unwrap();

    // expected: 1_000 - 300 = 700; actual: 1_000 - 100 = 900
    assert_eq!(store.fee_balance_of(7).unwrap(), 700);
    // expected: 3 * 60 = 180; actual: 60
    assert_eq!(store.total_fee_burned().unwrap(), 180);
    // expected: 3 * 40 = 120; actual: 40
    assert_eq!(store.proposer_fee_pot().unwrap(), 120);
}
```

All three asserts will fail under the current implementation; the
actual values committed are `fee_balance=900`, `total_burned=60`,
`proposer_pot=40` — the LAST-STAGED values, because each subsequent
call read the same pre-batch DB state and overwrote the prior batch
entries.

A second test asserts the conservation invariant
(`pre_fee_balance - post_fee_balance == post_burn + post_pot - pre_burn -
pre_pot`) — it passes (100 == 60 + 40) but the absolute values are
1/3 of what they should be.

## Remediation

Two viable fixes; either is sufficient.

### Option A — read through the batch in `stage_charge_message_fee`

Change the three reads to consult `batch.batch.get(...)` before
falling back to `self.db.get(...)`. Pattern (modeled on
`message.rs:234`):

```rust
fn read_u64_through_batch(db: &Arc<RocksDB>, batch: &RocksDbTransactionBatch, key: &[u8]) -> Result<u64, RewardError> {
    if let Some(maybe) = batch.batch.get(key) {
        return Ok(maybe.as_deref().map(decode_u64_be).unwrap_or(0));
    }
    Ok(db.get(key).map_err(...)?.map(decode_u64_be).unwrap_or(0))
}
```

Apply the same shape for `total_fee_burned` (16-byte u128) and for
`proposer_fee_pot` (8-byte u64) and for `fee_balance_of` (8-byte
u64). After this change, sequential `stage_charge_message_fee`
calls in the same batch correctly observe each other's pending
writes and compose additively.

### Option B — accumulate fee deltas in `merge_message` (or one level up) and emit a single `stage_charge_message_fee` per (chunk, fid)

Move the call out of the per-message merge path. Have
`replay_snapchain_txn` (or `replay_proposal`) accumulate per-FID and
global fee deltas across the chunk and emit ONE
`stage_charge_message_fee(fid, total)` (plus one global
total_burned / proposer_pot update) at the end. This is more
invasive but eliminates the read-after-write hazard structurally.

Either fix should be accompanied by:

1. The unit test above (with corrected assertion: expected values
   should match the protocol math).
2. A second test that asserts `record_fingerprint_if_cast`'s
   out-of-batch behavior is intended (it currently writes directly
   to DB via `fingerprint_store.insert` at `fingerprint_store.rs:81-88`,
   bypassing the merge txn_batch; see "Adjacent observation" below).
3. A regression test in `merge_message` that posts K=10 CastAdds
   from one FID in one Transaction and asserts cumulative fee
   debit == K * effective_fee.

## Adjacent observation (NOT a separate finding under H132's scope)

`FingerprintStore::uniqueness_score` (`fingerprint_store.rs:135-140`)
does `self.db.commit(batch)` for eviction of >30-day fingerprints
during the merge txn — this commit is OUTSIDE the engine's
`txn_batch` and therefore lands in DB even if the merge txn
subsequently aborts (e.g., `EngineError::HashMismatch` in
`replay_proposal`). Similarly `FingerprintStore::insert` and
`record_fingerprint_if_cast` write directly via `self.db.put`.
fee_charger.rs:1333-1336 explicitly comments this as best-effort
("losing one on a crash before commit is acceptable"), but eviction
is more aggressive — evicted fingerprints are PERMANENTLY removed
even on rollback. This is a determinism-adjacent concern for
fingerprint-based uniqueness scoring at chain restart / reorg, but
out of scope for the H132 fee-flow finding; flagging here for
operator awareness.

## Severity rationale

- **Impact:** Silent fee evasion (every fee-bearing message after the
  first per (fid, shard chunk) is FREE), silent under-burn (the
  `HyperTotalFeeBurned` counter strictly undercounts), silent
  under-credit of the proposer fee pot (proposer of a fee-heavy
  chunk gets short-changed; the missing share never reaches any
  proposer, it stays as un-debited fee_balance and gets paid out
  later to a different chunk's proposer).
- **Pre-conditions:** A FID with `>=2` fee-bearing messages in one
  shard chunk. The default mempool sequencing produces this on any
  active account; no exotic trigger needed. No special permissions,
  no special timing — just normal throughput.
- **Detection difficulty:** Hard. The bug is invisible from any
  single-message log line; it only shows up as a divergence between
  "sum of `merge_message` fee log lines" and "delta on
  `fee_balance(fid)` and global counters" across an interval. No
  consensus check fires because the divergence is consistent across
  validators (they all execute the same broken arithmetic
  deterministically — the bug is a determinism-safe accounting
  shortfall, not a fork).
- **Crash-safety:** Orthogonal. The batch IS committed atomically;
  the issue is what gets committed (last-write-wins on
  HashMap-keyed batch entries), not whether it commits at all.
- **Comparison to validated iter-1 findings:** Most economically
  comparable to F015 (medium) and F011 (medium); the fee-evasion
  multiplier here scales linearly with chunk fee-message
  concurrency per FID, which is a strictly larger impact surface
  than F015's one-shot crash-conditional double-credit. Bumping to
  **High** on that basis.
