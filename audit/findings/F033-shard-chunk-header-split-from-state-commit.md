---
id: F033
task: H033
specialist: http-api-rocksdb
attack_class: column-family-atomicity-around-fork
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Block / shard-chunk header is persisted in a separate RocksDB commit from the engine state-mutation batch; a crash between the two leaves the trie + message stores advanced past the highest persisted header, breaking the on-restart "current height" invariant and the cross-CF atomicity contract that consensus restart-replay assumes

## Summary

`SnapchainEngine::commit_and_emit_events`
(`code/hypersnap/src/storage/store/engine.rs:1802-1856`) and
`BlockEngine::commit_block`
(`code/hypersnap/src/storage/store/block_engine.rs:916-981`) are the two
shard-finalize paths that land a confirmed block into RocksDB. Each
follows the same two-stage pattern:

1. **Stage A — state mutations.** All message-merge events, account-root
   updates, hub-event log entries, block-event-store updates, and
   merkle-trie node writes are accumulated into one
   `RocksDbTransactionBatch`. The batch is committed atomically via
   `self.db.commit(txn)`
   (`engine.rs:1838`, `block_engine.rs:955`).
2. **Stage B — header persistence.** `shard_store.put_shard_chunk(...)`
   (`engine.rs:1845-1850`) or `block_store.put_block(...)`
   (`block_engine.rs:956-959`) is called. **Each of those functions
   opens its own `db.txn()` and runs its own `db.commit(...)`**
   (`storage/store/shard.rs:156-175`, `storage/store/block.rs:163-182`).

The two commits are independent. There is no enclosing transaction, no
ordering barrier, no fsync coordination. RocksDB's WAL groups writes by
commit, so the two commits produce two separate WAL groups. A
power-fail / SIGKILL / OOM / kernel panic between them — equivalently, a
mid-finalize crash at any restart boundary, snapshot-restore boundary,
or pod eviction — leaves the persistent database in a state where:

- The merkle trie at `RootPrefix::MerkleTrieNode` (`= 8`) has the **new**
  root for block height `H`.
- Per-FID account stores under `RootPrefix::User` (`= 3`), the cast /
  link / reaction / verification / username-proof secondary indexes
  (`RootPrefix::CastsByParent` etc., `= 4..7`), the hub-event log under
  `RootPrefix::HubEvents` (`= 9`), the on-chain-event store under
  `RootPrefix::OnChainEvent` (`= 12`), and the block-event store under
  `RootPrefix::BlockEvent` (`= 19`) all reflect the **post-`H`** state.
- **But** `RootPrefix::Shard` (`= 2`) for `SnapchainEngine` or
  `RootPrefix::Block` (`= 1`) for `BlockEngine` carries only entries up
  to height `H-1` — the row for height `H` was never written, because
  Stage B did not commit.

On restart, `BlockStore::max_block_number()` / `ShardStore::get_last_shard_chunk()`
returns `H-1`. Malachite's consensus loop wakes up, asks for the
current height, gets `H-1`, and proposes a block for height `H` over a
**post-`H`** state.  The state root the proposer signs is the trie root
**after** the lost block's transactions are already applied — a value
that no other validator will reproduce from `H-1` + the proposer's
proposal. The proposer either signs garbage (visible to the network and
slashed if the network is configured for slashing on bad state roots),
or — if the proposer panics on the mismatch and is restarted again — it
loops forever, never able to produce a valid proposal because its own
state is ahead of its own header pointer.

This is the textbook `column-family-atomicity-around-fork` shape, applied
to the snapchain / hypersnap key-prefix-as-CF storage model: writes
across logically-distinct column families
(`RootPrefix::MerkleTrieNode` + `RootPrefix::User`-derived stores on one
side, `RootPrefix::Shard` / `RootPrefix::Block` on the other) need to be
either all visible or all absent across a restart. The current engine
finalize path does not enforce that, and the lost header cannot be
recovered without consensus-level intervention (replay from a peer,
operator-driven snapshot restore, or manually trimming the trie back to
`H-1`).

The same anti-pattern recurs elsewhere in the hyper-layer storage
modules — most acutely in `HyperBlockIndex::record` /
`HyperBlockIndex::record_messages`
(`src/hyper/block_index.rs:91-126`), which performs **three** separate
bare `db.put` calls (height index, hash index, messages payload) per
imported hyperblock with no batch wrapping any of them. The same family
of mismatch is observable across `trust_store::set_many`
(`src/hyper/trust_store.rs:59-64`), `validator_registry::record_event`
(`src/hyper/validator_registry.rs:533-572`), `note_store` recorders
(`src/hyper/note_store.rs:86-96`), `slashing_store::record_evidence`,
`recovery_store`, `dkls_address_store`, and `fingerprint_store` — every
hyper-side store except `RewardStore` (and even there only
`apply_lock` / `apply_transfer` / `apply_fee_deposit` use batches; see
sibling F015 for `credit_if_unissued`'s analogous two-puts gap).

The choice of shard-chunk / block-header persistence as the highlighted
witness is deliberate: it is the cross-CF write whose half-applied state
manifests as a *consensus-correctness* failure (proposed state root
diverges from the rest of the network), not merely an
economic-overpay or audit-trail bug. F015 documents the rewards-store
witness; this finding documents the engine.rs / block_engine.rs witness;
H033's ruled-out note enumerates the other cross-CF write sites for
completeness.

## Description

### The two-commit pattern in `commit_and_emit_events`

`engine.rs:1802-1856` (annotated):

```rust
pub async fn commit_and_emit_events(
    &mut self,
    shard_chunk: &ShardChunk,
    mut events: Vec<HubEvent>,
    max_block_event_seqnum: u64,
    mut txn: RocksDbTransactionBatch,
) {
    // ... [1810-1834] event composition, BLOCK_CONFIRMED synthesis ...

    let _block_confirmed_id = self
        .stores
        .event_handler
        .commit_transaction(&mut txn, &mut block_confirmed)   // adds to txn
        .unwrap();
    events.insert(0, block_confirmed);

    self.metrics.gauge("block_event_seqnum", max_block_event_seqnum);
    _ = self.emit_commit_metrics(&shard_chunk, &events);

    let now = std::time::Instant::now();
    self.db.commit(txn).unwrap();                              // === Stage A commit ===

    for mut event in events {
        event.timestamp = header.timestamp;
        let _ = self.senders.events_tx.send(event);
    }
    self.stores.trie.reload(&self.db).unwrap();

    match self.stores.shard_store.put_shard_chunk(shard_chunk) {   // === Stage B ===
        Err(err) => {
            error!("Unable to write shard chunk to store {}", err)
        }
        Ok(()) => {}
    }
    // ... [1851-1855] post_commit hook, timing metrics ...
}
```

`put_shard_chunk` (`storage/store/shard.rs:155-176`) is a fresh
mini-transaction:

```rust
pub fn put_shard_chunk(db: &RocksDB, shard_chunk: &ShardChunk) -> Result<(), ShardStorageError> {
    let mut txn = db.txn();                                       // <-- new batch
    let header = shard_chunk.header.as_ref().ok_or(...)?;
    let height = header.height.as_ref().ok_or(...)?;
    let primary_key = make_shard_key(height.block_number);
    txn.put(primary_key.clone(), shard_chunk.encode_to_vec());

    let timestamp_index_key = make_block_timestamp_index(...);
    if db.get(&timestamp_index_key)? == None {
        txn.put(timestamp_index_key, primary_key);
    }

    db.commit(txn)?;                                              // <-- separate commit
    Ok(())
}
```

The `BlockEngine` path mirrors this exactly
(`block_engine.rs:939-980` → `block.rs:162-183`):
state-mutating batch is committed at `block_engine.rs:955`, then the
`block_store.put_block(block)` at `:956` opens a fresh batch in
`block.rs:163` and commits at `block.rs:181`.

### Why the gap matters: the on-restart "current height" derivation

`SnapchainEngine::get_confirmed_height`
(`engine.rs:2263-2268`) reads from `shard_store.max_block_number()`,
which itself returns the highest `Height` for which a `ShardHeader` row
exists under `RootPrefix::Shard`
(`storage/store/shard.rs:117-145, 232-248`). The Malachite consensus
glue (`src/consensus/consensus.rs`, `src/consensus/proposer.rs`) uses
this height to drive proposal generation and validation. The
post-restart consensus thread cannot distinguish between:

- "We finalized H-1 cleanly; H is the next height to produce."  
- "We applied state for H but never persisted the H header; H is also
  the next height to produce, but the trie/store already reflect H."

The second case is what a crash between Stage A and Stage B produces.

### What gets serialized into Stage A — the column families that move forward

The `RocksDbTransactionBatch` handed to `commit_and_emit_events` carries
writes that cross **every** logical column family below, in any given
block:

- `RootPrefix::MerkleTrieNode` (`= 8`) — every modified trie node along
  the path of every changed key.
- `RootPrefix::User` (`= 3`) — per-FID message-store records: cast adds,
  reaction adds, link adds, verification adds, user_data, username_proof,
  storage-lend, etc.
- `RootPrefix::CastsByParent` (`= 4`), `CastsByMention` (`= 5`),
  `LinksByTarget` (`= 6`), `ReactionsByTarget` (`= 7`) — secondary
  indexes maintained per merge.
- `RootPrefix::HubEvents` (`= 9`) — every event emitted (MergeMessage,
  RevokeMessage, PruneMessage, MergeOnChainEvent, MergeUsernameProof,
  MergeFailure, BlockConfirmed, etc.).
- `RootPrefix::FNameUserNameProof` (`= 11`),
  `FNameUserNameProofByFid` (`= 15`), `UserNameProofByName` (`= 16`) —
  fname proof state.
- `RootPrefix::OnChainEvent` (`= 12`),
  `VerificationByAddress` (`= 14`) — on-chain event consumption.
- `RootPrefix::BlockEvent` (`= 19`) — block-event log.
- `RootPrefix::LendStorageByRecipient` (`= 22`) — storage lend
  recipient index.
- `RootPrefix::GaslessKey` (`= 23`) — gasless-key state.

All of these advance atomically to height-`H` state when Stage A
commits.

### What gets written in Stage B — the column families that lag

- `RootPrefix::Shard` (`= 2`) — `make_shard_key(height) = [Shard,
  height BE u64]`. The encoded `ShardChunk` (header + transactions +
  commits) is the value. Plus
- `RootPrefix::BlockIndex` (`= 18`) inside
  `make_block_timestamp_index` (used by `shard.rs:168-172` /
  `block.rs:175-179`) — only when no row exists yet for the timestamp.

For `BlockEngine`:

- `RootPrefix::Block` (`= 1`) — `make_block_key(height) = [Block,
  height BE u64]`. The encoded `Block` is the value. Plus the same
  timestamp index conditional write.

### The crash window — what a power-fail produces

The relevant RocksDB durability primitive: `db.commit(txn)` translates
to `TransactionDB::transaction()` + `txn.commit()`
(`storage/db/rocksdb.rs:377-395`), which writes a WAL group with all
the per-key puts and flushes WAL (default `wal_recovery_mode =
PointInTimeRecovery`, no explicit `set_use_fsync` in `open()` at
`rocksdb.rs:199-247` — Stage A's commit is **not** sync'd through to
disk on default settings).

A crash between Stage A's `self.db.commit(txn)`
(`engine.rs:1838`) and `put_shard_chunk`'s `db.commit(txn)`
(`shard.rs:174`) creates one of three outcomes:

1. **Stage A's WAL group is fsync'd, Stage B's never written.** Disk
   state on recovery: trie + message stores at `H`; shard header at
   `H-1`. *This is the broken case.*
2. **Stage A's WAL group is in OS page cache but not on disk; crash
   loses both.** Disk state on recovery: everything at `H-1`. Clean.
3. **Both Stage A and Stage B's WAL groups are fsync'd before the
   crash.** Disk state on recovery: everything at `H`. Clean.

Outcomes (2) and (3) are recoverable. Outcome (1) is not. The window
for outcome (1) is small in absolute time — between `engine.rs:1838`
and the matching `shard.rs:174` is roughly a `put_shard_chunk` call's
worth of code: one encode, one `db.get` (timestamp index check), two
`txn.put`, one `db.commit`. On commodity hardware this is on the order
of 100 microseconds to a few milliseconds. But the engine runs on every
block, blocks finalize every few seconds, so the window is encountered
billions of times across a deployment. RocksDB documentation explicitly
warns that "two separate commits" is **not** an atomicity-preserving
construction even when the WAL is fsync'd, because the second WAL
group's record may or may not reach disk depending on flush timing and
the OS's page-cache eviction order.

The window is also visibly larger in operator-induced restarts: a
SIGKILL fired between the two commits has no power-fail uncertainty;
the second commit simply never happens.

### Why this is a fork-relevant write — even without "rewind" semantics

The task framing is `column-family-atomicity-around-fork`. Hypersnap /
Snapchain use Malachite BFT, which has **instant finality** (decided
blocks never roll back), so there's no traditional chain-fork rollback
to enumerate. The "fork point" relevant here is the *restart-recovery
point* — the moment the node opens RocksDB after any non-clean
shutdown. RocksDB's `wal_recovery_mode = PointInTimeRecovery` (the
default for `TransactionDB::open` per `rocksdb.rs:230-234`) treats the
WAL as an authoritative log up to the last consistent point. The
"fork" between "what got into the WAL" and "what didn't" is precisely
the cross-CF atomicity boundary the attack class names.

Independent of Malachite's instant finality, three production scenarios
**do** create the rewind:

1. **Replication bootstrap restore.** `src/network/replication/`
   ships RocksDB snapshots to bootstrapping peers (`RootPrefix::ReplicationBootstrapStatus` `= 21`).
   If a peer restores a snapshot taken between Stage A and Stage B by
   the source peer, the new peer inherits the inconsistent state
   directly.
2. **S3 snapshot upload + restore.** `src/jobs/snapshot_upload.rs` and
   `src/storage/db/snapshot.rs` upload SST snapshots to S3 for cold
   bootstrap. A snapshot taken in the Stage-A-flushed / Stage-B-pending
   window has the same defect frozen into it; any node that restores
   from that snapshot starts up with the broken state.
3. **Engine version migration cutover.** `EngineVersion::version_for`
   (`src/version/version.rs`) gates protocol features at a timestamp
   boundary. The block at the cutover boundary is the highest-stakes
   block of the entire deployment lifetime; a crash there is the
   highest-value moment for an attacker who can induce one (e.g., by
   exhausting memory at a known time-zone moment).

### Witness: the same anti-pattern across the hyper-layer storage modules

The task explicitly notes the cross-CF atomicity check should "pay
particular attention to: chain trie vs. evidence store vs. validator-
registry vs. trust store at a cutover." Each of those stores
independently violates batch atomicity at its write site:

- **HyperBlockIndex** (`src/hyper/block_index.rs:91-105`) does *three*
  bare `db.put` calls per recorded block: height index, hash index,
  and (via `record_messages` at `:109-126`) the message payload. None
  share a batch. A crash between the height-index put and the hash-
  index put leaves the chain queryable by height but not by hash —
  observable as a `get_by_hash` returning `None` for a block that
  `get_by_height` returns. A crash before `record_messages` leaves the
  block recorded but its messages missing, so the verkle tree cannot
  be replayed from disk on restart.
- **TrustScoreStore::set_many**
  (`src/hyper/trust_store.rs:59-64`) iterates `set(fid, score)`, and
  each `set` does an independent `db.put`
  (`trust_store.rs:38-42`). At the trust-snapshot rotation
  (FIP-hyper-validator-selection §2.2), `apply_trust_snapshot_update`
  (`src/hyper/runtime.rs:581-616`) calls
  `self.trust_store.set(entry.fid, score)` in a loop over hundreds to
  thousands of FIDs. A mid-loop crash leaves the trust store at a
  half-rotated state: some FIDs at the new epoch's scores, others at
  the previous epoch's scores. The watermark
  `last_trust_snapshot_epoch` is in-memory only
  (`runtime.rs:267, 414, 614`) — it is **not** persisted at all. On
  restart it's `None`, and a maliciously-replayed older threshold-
  signed snapshot can be applied to clobber the half-rotated state
  without the epoch-monotonicity gate firing. The validator-
  registration trust gate then admits or rejects validators based on a
  mixture of stale and fresh scores.
- **ValidatorRegistry::record_event**
  (`src/hyper/validator_registry.rs:533-572`) does up to three bare
  `db.put` / `db.del` on a Register (event, by-fid marker, fid lookup)
  or Deregister. A crash between the event put and the by-fid marker
  put leaves the event log carrying the registration but the per-FID
  active index missing the marker. The next validator-registration
  call queries the marker to enforce the 3-validators-per-FID quota
  (`validator_registry.rs` quota check) — without the marker, the
  FID is treated as having zero active validators and can register a
  4th, 5th, etc.
- **SlashingEvidenceStore::record_evidence** does a single bare
  `db.put` (`src/hyper/slashing_store.rs:65`). On its own, single-key
  atomicity holds. The cross-CF gap shows up when slashing evidence
  ingest triggers a validator deregister or trust-score penalty in
  the same actor dispatch tick — the slashing record persists but the
  consequential state transition (a follow-up `validator_registry`
  call, a follow-up `trust_store.set`, etc.) may not.
- **DklsAddressStore::set** (`src/hyper/dkls_address_store.rs:36-40`)
  is a single put. The gap is the *handshake* with
  `HyperRuntime::dkls_group_addresses` in-memory map
  (`runtime.rs:278-296`) — the in-memory cache is updated in
  `install_local_dkls_share` then the disk store is written. A crash
  between cache update and disk write loses the DKLS address for the
  epoch on restart, breaking signature verification for any block
  signed under that epoch's key.
- **NoteStore** (`src/hyper/note_store.rs:86-96`) discards the
  `Result` from `db.put` entirely (line 90: `let _:
  Result<(), RocksdbError> = self.db.put(...)`). On any I/O error
  the note isn't recorded but the import path proceeds as if it had
  been. The transfer is in the verkle tree, but its commitment isn't
  in the disk-backed note store — subsequent transfers spending that
  output can't resolve the owner pubkey.
- **HyperBlockIndex + everything above** runs inside
  `HyperRuntime::import_block`
  (`src/hyper/runtime.rs:4120-4217`) → `import_hyper_block_with_index`
  (`src/hyper/importer.rs:145-173`). The call sequence is:
  1. `chain.validate(block)` — in-memory.
  2. `import_hyper_block` — verifies threshold sig, applies messages
     to in-memory `VerkleTree`
     (`crates/hypersnap-crypto/src/verkle.rs:94-110` — purely in-RAM
     tree, no DB), drains mempool.
  3. `chain.advance(block)` — in-memory tracker bump.
  4. `index.record(block)` — *two unbatched puts* (block_index.rs:98-103).
  5. `index.record_messages(...)` — *one unbatched put*
     (block_index.rs:124).
  6. Outside this function, the dispatch continues:
     `maybe_trigger_scoring`, `maybe_sign_da_epoch_seed`,
     `maybe_trigger_da_responses` (`actor.rs:1164-1170`). These can
     themselves invoke `apply_reward_issuance` →
     `credit_if_unissued` (F015) or `apply_trust_snapshot_update` →
     `set_many` (witness above), each producing further unbatched
     puts.

  At any crash point in steps 4-6, the persistent state is
  inconsistent: the block may be queryable by height but not by hash,
  or the messages may be missing, or the rewards / trust state may be
  half-applied, while the verkle tree (in-memory) is lost entirely
  and must be replayed from `HyperBlockMessages` — *which were
  themselves only partially persisted*. A restart in any of these
  windows leaves the runtime unable to reconstruct a consistent
  hyper-state root, and the next produced hyperblock signs over a
  state root the rest of the network will not reproduce.

### Why this isn't a duplicate of F015

F015 covers `RewardStore::credit_if_unissued` — a function whose own
two writes lack a batch. The atomicity break is intra-function: one
function makes two puts. The witness in this finding is **cross-
function**: `engine.commit_and_emit_events` does one big batched commit,
then *invokes* a separate persistence function that does its own commit.
The atomicity contract is not promised by the inner function (which
does atomically commit its two writes), but by the *caller* chain that
treats the two persistence steps as a logical unit.

Fixing F015 (wrap the two `credit_if_unissued` puts in a batch) does
not fix this finding. Conversely, fixing this finding (have the engine
pass its `txn_batch` to `put_shard_chunk` / `put_block` so the two
stages share one commit) does not fix F015, because the rewards path
has its own internal two-put gap that doesn't pass through the engine
batch.

The two findings are co-located in the same anti-pattern family, and
both point at the underlying root cause: there's no
`#[must_use]`-style enforcement that cross-prefix writes within a single
"finalize a block" operation share a single RocksDB commit. They
nonetheless map to distinct code sites, distinct severities, and
distinct fix surfaces.

### Why the `MerkleTrie::reload(&self.db)` after Stage A doesn't help

`engine.rs:1843` (and `block_engine.rs:960`) call
`self.stores.trie.reload(&self.db)` after Stage A. This re-loads the
trie's root node from disk (`merkle_trie.rs:279-291`) — a defensive
move to keep the in-memory cache aligned with the just-flushed Stage A
writes. It does **not** durability-coordinate Stage A and Stage B; it
reads, not writes, and is a no-op for the cross-CF atomicity question.

### Why the snapchain-shard variant is more dangerous than the hyper variant

On the snapchain side, the data layer is **wire-compatible with
upstream snapchain peers**. A snapchain node with the engine-side
partial-finalize is producing proposals whose state root will diverge
from every other validator. Malachite votes will fail to reach a
`+2/3` quorum, the network stalls, and the operator has to manually
recover by truncating their local state back to `H-1` or restoring
from a known-good snapshot.

On the hyper side, the partial state breaks reward and validator
state — economic correctness but not network liveness — and the network
can tolerate one peer being out of sync because hyperblocks are
threshold-signed by a subset of the validator set.

## Impact

* **Consensus liveness halt on snapchain shards.** A power-fail or
  SIGKILL between `engine.rs:1838` and `shard.rs:174` produces a
  validator whose trie root for height `H` is locked in by disk state
  but whose advertised confirmed height is `H-1`. On restart, the
  validator either signs a proposal whose state root no other peer can
  reproduce from `H-1`'s state (producing a slashable / undetected-but-
  fork-creating bad proposal) or panics on the first `process_proposal`
  and refuses to participate. If a quorum of validators were running
  under the same kernel-panic / common-mode failure (e.g., the same
  hosting provider, same cloud region, same hypervisor update), the
  network as a whole halts.
* **Cross-side state-root divergence.** Because the snapchain wire
  contract has no built-in detection for "this peer's trie is one
  block ahead of its shard-chunk index," a node in this state produces
  state proofs (`/v1/state-proofs/*` style endpoints, if surfaced) that
  are valid against its own trie but reference shard headers that don't
  exist on other peers. This is a silent integrity gap visible only to
  observers comparing cross-peer state.
* **Half-rotated validator registry / trust store / DKLS address store
  at hyper-layer epoch boundaries.** The cross-witness sites above
  (`validator_registry::record_event`, `trust_store::set_many`,
  `dkls_address_store::set`) each enable a different exploitation
  shape:
  - validator quota bypass (half-applied Register lets the same FID
    register a 4th validator past the `MAX_VALIDATORS_PER_FID = 3`
    cap),
  - mixed-epoch trust scores affecting registration eligibility
    (some FIDs gated by stale low scores, others ungated by stale
    high scores),
  - lost DKLS group address for the epoch (block signature
    verification fails closed; honest hyperblocks rejected).
* **Snapshot bootstrap pollutes new peers.** The S3 snapshot upload
  path and the replication shipping path both treat the RocksDB state
  as a coherent file. A snapshot taken during the Stage-A-flushed /
  Stage-B-pending window is structurally well-formed (RocksDB SSTs
  open and read cleanly) but semantically inconsistent. New peers
  bootstrapping from that snapshot inherit the inconsistency without
  any restart of their own.
* **No on-restart detection.** There is no startup-time check that
  reads `trie.root_hash()` and cross-references it against the
  `ShardHeader::shard_root` at `shard_store.max_block_number()` to
  detect the off-by-one. A startup integrity check would be cheap
  (one trie root read, one shard header decode, one byte compare) but
  is absent.

Severity: **medium**. The crash window is narrow per block (≈ a few
ms), the trigger is restart-correlated (not adversary-controlled in
the simple case), and the consequence on the snapchain shard variant
is consensus stall rather than economic loss. **High** if the threat
model includes (a) coordinated SIGKILL by a hosting provider during a
deployment rollout, (b) a malicious operator who can time process
kills to maximize their odds of producing a bad-state-root proposal
that other validators sign through quorum mistake, or (c) the S3-
snapshot pollution path that propagates a single bad snapshot to
every bootstrapping peer simultaneously. The "validator-quota bypass"
witness on the hyper-layer is also `high` if exercised maliciously,
because the quota is the only guard against an attacker registering
many validator slots under one FID.

## Evidence

* `code/hypersnap/src/storage/store/engine.rs:1802-1856` —
  `commit_and_emit_events`. Stage A commit at `:1838`; Stage B call
  at `:1845`.
* `code/hypersnap/src/storage/store/engine.rs:2036-2106` —
  `commit_shard_chunk` shows the cached-vs-uncached branches both
  funnel through `commit_and_emit_events`; the two-commit pattern is
  the only finalization path for snapchain shards.
* `code/hypersnap/src/storage/store/shard.rs:155-176` —
  `put_shard_chunk` opens its own `db.txn()` and commits at `:174`.
* `code/hypersnap/src/storage/store/block_engine.rs:916-981` —
  `BlockEngine::commit_block`. Stage A commit at `:955`; Stage B call
  at `:956`.
* `code/hypersnap/src/storage/store/block.rs:162-183` — `put_block`
  opens its own `db.txn()` and commits at `:181`.
* `code/hypersnap/src/storage/db/rocksdb.rs:355-362` — `RocksDB::put`
  is a direct unbatched put. The two-commit pattern relies on this
  to be a no-op-if-WAL-already-fsync'd; it is not.
* `code/hypersnap/src/storage/db/rocksdb.rs:199-247` — `open()`. No
  `set_use_fsync(true)`, no manual WAL flush coordination. The
  default `wal_recovery_mode` is RocksDB's `PointInTimeRecovery`,
  which is exactly the recovery mode that can leave Stage A's WAL
  group durably committed while Stage B's is lost.
* `code/hypersnap/src/storage/db/rocksdb.rs:377-395` — `commit(batch)`
  body: builds a `db.transaction()`, applies the batch, commits.
  Per-commit atomicity holds; cross-commit atomicity does not.
* `code/hypersnap/src/storage/constants.rs:1-200` — `RootPrefix` enum
  with the column-family-equivalent prefix layout. Confirms
  `Shard = 2`, `Block = 1`, `MerkleTrieNode = 8`, `User = 3` etc.,
  validating the cross-prefix argument above.
* `code/hypersnap/src/hyper/block_index.rs:91-126` — `HyperBlockIndex::record`
  + `record_messages`. Three bare `db.put` calls, no batch.
* `code/hypersnap/src/hyper/trust_store.rs:38-64` — `set` / `set_many`.
  Per-entry bare puts.
* `code/hypersnap/src/hyper/runtime.rs:267, 414, 614, 581-616` —
  `last_trust_snapshot_epoch` is in-memory only; not persisted; reset
  to `None` on every runtime construction.
* `code/hypersnap/src/hyper/validator_registry.rs:533-572` —
  `record_event` does up to three bare puts/dels on Register/Deregister.
* `code/hypersnap/src/hyper/note_store.rs:86-96` — `record_note`,
  `mark_spent`. Bare puts, returned `Result` discarded.
* `code/hypersnap/src/hyper/slashing_store.rs:65` — bare put.
* `code/hypersnap/src/hyper/dkls_address_store.rs:36-40` — bare put;
  paired with in-memory `dkls_group_addresses` BTreeMap in
  `runtime.rs:278-296`, write-through ordering not enforced.
* `code/hypersnap/src/hyper/recovery_store.rs:59`,
  `code/hypersnap/src/hyper/fingerprint_store.rs:86`,
  `code/hypersnap/src/hyper/retro_store.rs:198` — additional bare-put
  / bare-del sites.
* `code/hypersnap/src/hyper/runtime.rs:4120-4217` — `import_block`
  showing the full hyper-layer import flow that strings together
  all the above stores' writes with no enclosing batch boundary.
* `code/hypersnap/src/hyper/importer.rs:145-173` —
  `import_hyper_block_with_index` showing the
  `index.record(block)` + `index.record_messages(...)` sequence with
  no batch.
* `code/hypersnap/crates/hypersnap-crypto/src/verkle.rs:94-110` —
  `VerkleTree::new` / `VerkleTree::insert`. The tree is purely
  in-memory; on restart, state is reconstructed by replaying every
  block's `HyperBlockMessages` payload through the builder. A
  partially-persisted `HyperBlockMessages` row means the replay
  fails or produces a wrong root.
* `code/hypersnap/src/hyper/actor.rs:1157-1172` — `InboundBlock`
  handler runs `import_block` then synchronously fires
  `maybe_trigger_scoring`, `maybe_sign_da_epoch_seed`,
  `maybe_trigger_da_responses`. These can issue rewards (F015) or
  rotate trust snapshots, all without sharing a commit boundary with
  the block-index puts.
* `code/hypersnap/findings/drafts/F015-credit-if-unissued-two-puts-replay.md`
  — sibling finding on a different witness of the same anti-pattern.
* `.claude/agents/specialists/http-api-rocksdb.md` —
  `column-family-atomicity-around-fork` attack class:
  "RocksDB writes across multiple column families need a write-batch
  for atomicity. A partial write that survives a chain-fork can
  corrupt state." Here the "chain-fork" is the restart-recovery
  point; "multiple column families" is the multi-`RootPrefix` cross-
  write.

## Suggested remediation

1. **Pass `RocksDbTransactionBatch` into `put_shard_chunk` /
   `put_block` instead of letting them open their own transactions.**
   Add an internal helper:

   ```rust
   // shard.rs
   pub fn put_shard_chunk_into(
       txn: &mut RocksDbTransactionBatch,
       db: &RocksDB,
       shard_chunk: &ShardChunk,
   ) -> Result<(), ShardStorageError> {
       let header = shard_chunk.header.as_ref().ok_or(...)?;
       let height = header.height.as_ref().ok_or(...)?;
       let primary_key = make_shard_key(height.block_number);
       txn.put(primary_key.clone(), shard_chunk.encode_to_vec());
       let timestamp_index_key = make_block_timestamp_index(...);
       if db.get(&timestamp_index_key)? == None {
           txn.put(timestamp_index_key, primary_key);
       }
       Ok(())
   }
   ```

   Then `engine.commit_and_emit_events` becomes:

   ```rust
   // engine.rs
   shard::put_shard_chunk_into(&mut txn, &self.db, shard_chunk)?;
   // ... event_handler.commit_transaction adds events too ...
   self.db.commit(txn).unwrap();           // <-- single commit
   self.stores.trie.reload(&self.db).unwrap();
   ```

   The same refactor applies to `block_store.put_block` →
   `BlockEngine::commit_block`. Now Stage A + Stage B share one commit.
   A power-fail anywhere in the path either preserves both or loses
   both.

2. **Persist `last_trust_snapshot_epoch`.** Move it to a new
   `RootPrefix::HyperTrustEpochWatermark` (or reuse a single
   well-known key under an existing prefix). Update inside the same
   batch as the trust entries:

   ```rust
   // runtime.rs apply_trust_snapshot_update
   let mut batch = self.db.txn();
   for entry in &update.entries {
       batch.put(make_trust_key(entry.fid).to_vec(),
                 f64::from_bits(entry.score_bits).to_be_bytes().to_vec());
   }
   batch.put(TRUST_WATERMARK_KEY.to_vec(), update.epoch.to_be_bytes().to_vec());
   self.db.commit(batch)?;
   self.last_trust_snapshot_epoch = Some(update.epoch);
   ```

   On runtime construction, read the watermark from disk into
   `last_trust_snapshot_epoch` (`runtime.rs:414`). This closes the
   replay-an-older-snapshot-after-restart window and lets the
   epoch-monotonicity gate fire correctly.

3. **Batch `HyperBlockIndex::record` + `record_messages` together.**
   Change the function shape so a caller passes in a
   `&mut RocksDbTransactionBatch`:

   ```rust
   pub fn record_with_messages(
       txn: &mut RocksDbTransactionBatch,
       block: &HyperBlock,
       locks: Vec<proto::HyperLockEvent>,
       transfers: Vec<proto::HyperTransferTx>,
   ) -> Result<(), IndexError> { /* three batched puts */ }
   ```

   Then `import_hyper_block_with_index` opens one batch, calls
   `record_with_messages` plus whatever further per-message state
   mutations the dispatch needs, and commits at the end. This is the
   correct atomicity unit: one block → one batch.

4. **Audit `validator_registry::record_event` for the same
   refactor.** Same shape — accept a `txn_batch`, the caller (which
   is `HyperRuntime::apply_validator_event` or the import path) owns
   the commit boundary.

5. **Replace `note_store`'s discarded `Result`s with proper error
   propagation,** and route `record_note` / `mark_spent` through a
   `txn_batch` parameter rather than a bare `self.db.put`. The
   present behavior — silently swallow I/O errors — is independently
   a defect even before the atomicity question.

6. **Add a startup integrity probe.** On engine construction, compare
   `self.stores.trie.root_hash()` against
   `shard_store.get_last_shard_chunk()?.header.shard_root`. If they
   differ, the engine is in the post-Stage-A, pre-Stage-B state.
   Refuse to accept proposals until an operator resolves the gap
   (truncate trie to `H-1` or restore from a known-good snapshot).
   This is the canonical "fail fast on corrupted state" pattern.

7. **Enforce the atomicity contract with a lint.** A `clippy::custom`
   rule (or a `cargo deny`-style check) that flags any `self.db.put`
   or `self.db.del` outside of a `txn / commit` pattern, with an
   allowlist for storeless single-key admin writes (e.g.,
   `node_local_state` which is genuinely fork-irrelevant). This
   matches the recommendation in F015 and would prevent regression
   on every site this finding enumerates.

8. **For the S3 / replication snapshot upload paths, take the
   snapshot from a checkpoint, not the live DB.** RocksDB's
   `Checkpoint::create_checkpoint` produces a point-in-time snapshot
   guaranteed to be consistent at the moment of capture — taking SSTs
   from the live DB without a checkpoint can capture inconsistent
   mid-flush state. Move `src/jobs/snapshot_upload.rs` and
   `src/storage/db/snapshot.rs` to checkpoint-based capture
   (verify whether this is already done; if so, this
   recommendation is a no-op).

9. **Document the atomicity contract on every store type.** Add a
   module-header note on each of `block_index.rs`, `trust_store.rs`,
   `validator_registry.rs`, `note_store.rs`, `slashing_store.rs`,
   `dkls_address_store.rs`, `recovery_store.rs`, `fingerprint_store.rs`,
   `retro_store.rs` stating "All puts/dels go through a caller-
   supplied `RocksDbTransactionBatch`; the store does NOT open its
   own commit. The block-import / cutover path is responsible for
   bundling all per-block state writes into a single commit so
   power-fail recovery is atomic." This surfaces the contract to
   future readers and to subsequent specialist agents auditing new
   store types.
