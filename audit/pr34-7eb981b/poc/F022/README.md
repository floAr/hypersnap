# F022 PoC: undecided value overwritten by an unauthenticated copy

Target: farcasterorg/hypersnap @ `7eb981b`. Malachite sibling at `<malachite>` (path deps `../malachite/code/crates/*`). The same tree previously built hs-f4fc4af. It is not a git checkout, so its rev could not be re-checked with git. No other sibling deps are needed: `eth-signature-verifier` is not a path dep at this commit.

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0 (59807616e 2026-04-14)`, `RUSTFLAGS="--cap-lints allow"` (malachite-wal lint ICE workaround).
- Source copy: `git archive 7eb981b | tar -x -C <build-tree>`. The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/f022_poc_test.rs`, wired as `#[cfg(test)] mod f022_poc_test;` in `src/chain/mod.rs`. A copy is here as `f022_poc_test.rs`.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f022 -- --nocapture`
- First build plus test run took about 8 minutes (14:13 to 14:21) with the in-workspace `target/`.
- Output: `F022-test-output.txt`.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `value_id_is_not_bound_to_the_body_shard1` | A copy that keeps the honest header and hash bytes but adds a transaction has the same `shard_hash()` (value id). `validate_body(honest) == Ok` and `validate_body(copy) == Err(BadMessagesRoot)`. | **RED** (pass, claim reproduced) |
| `value_id_is_not_bound_to_the_body_shard0` | Same check on a shard-0 block with one junk `messages` entry. | **RED** |
| `unauthenticated_copy_overwrites_the_stored_honest_value` | `UndecidedValues::add(honest)` then `add(copy)` (round 1000). `get(honest id)` returns the copy, and the stored body fails `validate_body` with `BadMessagesRoot`. | **RED** |
| `decide_commits_the_overwritten_body_and_stores_a_corrupt_block` | Real `HypersnapShardProposer` for shard 1 (ShardEngine, ShardBlockProducer, fixture Falcon set built as in `consensus_net_test.rs`). Steps: `propose_value`, then `add_proposed_value(honest) == Valid`. The copy has the same header and hash, a junk `messages` entry, unchanged (empty) transactions and round 1000; `add_proposed_value(copy) == Invalid`. Then `get_proposed_value(id) == copy`. `decide` runs with a 3-of-4 quorum `Commits` for the honest id and does not panic. `store().get(1)` returns the attacker body with `validate_body == Err(BadMessagesRoot)`. | **RED**: the full decide/commit path stores a corrupt, unsyncable block |
| `decide_panics_when_the_copy_changes_the_transactions` (`#[should_panic]`) | Same flow, but the copy adds `Transaction{fid:1}` with no messages, so the cached-execution events hash misses and the body is replayed. | **GREEN, not reproduced**: "test did not panic as expected". |

## Notes for the finding's caveats

- The panic test did not reproduce the halt. An empty-message `Transaction` likely changes no state, so the replayed roots match and the commit succeeds. Reproducing the shard 1/2 halt would need an honest block that has transactions, or a copy whose transactions change state. The mempool in this harness is empty, so `propose_value` yields empty blocks. The halt sub-claim is therefore still **source-only**. This unit harness also cannot tell whether this variant stores the attacker body; that was not asserted.
- The corrupt-store outcome is now build-backed on the real shard-1 `decide` path. It is the field-3 variant from the validation note. The shard-0 twin is shown at the value-id, store and `validate_body` level only; `Shard0Proposer::decide` was not run because shard-0 engine and genesis setup is much heavier.
- Timing and the race are not exercised: a unit test calls things in order. The restart/WAL sub-claim is not exercised either. Gossip ingress is not exercised; it rests on the source trace.

## Coordinator note (2026-11-03)
- Malachite provenance verified: `diff -rq --exclude=target --exclude=.git <malachite>/code <pinned clone>/code` is empty, and the pinned clone is at `13bca14c` — the WSL tree used for this build is content-identical to the rev Hypersnap pins.
- Result summary: 4 RED / 1 not reproduced. Build-backed: value id not bound to body (shard 0 + 1), store overwrite by an unauthenticated copy, and shard-1 `decide` committing the attacker's body as an unsyncable block (`BadMessagesRoot`). NOT reproduced: shard 1/2 commit panic (copy's extra transaction changed no state; harness produces empty honest blocks). The halt claim remains source-only.

## Halt reproduction (run 2) — 2026-11-03

The shard 1/2 commit halt now reproduces on the real `HypersnapShardProposer::decide` path. Output: `F022-test-output-2.txt`. Same build (`<build-tree>`, rustc 1.95.0, `--cap-lints allow`); incremental rebuild ~40 s. **All 7 tests pass.**

### Why run 1 did not halt, and what the halt actually requires
The commit-time cache key is `compute_block_events_hash(transactions)` (`engine.rs:3563`), and it hashes **only** `system_messages[].block_event` — it ignores user messages and any transaction that carries no block event. So:
- An attacker body that differs only in **user messages**, or that adds a bogus empty `Transaction{fid:1}` (run 1's 5th test), produces the **same** events hash as the honest body. The cache **hits**, the honest execution commits, and nothing diverges — no halt. Run 1's `#[should_panic]` test was asserting a halt that cannot occur on that input; run 2 renames it to `no_halt_when_the_differing_txn_carries_no_block_event` and asserts the negative directly (now green). This is not a weaker claim: it pins the precise condition the halt needs.
- To halt, the differing body must change the **block-events hash** (so the cache misses) **and** change the **trie** (so the replayed root diverges from the cached `shard_root`). In Hypersnap mode on-chain events are rejected by the propose filter (`hypersnap_onchain_check` always `Err`), and the only mergeable `MergeOnChainEvent` block event (ChannelRegister) is trie-neutral. A **`MergeMessage` block event** carrying a signed cast is trie-backed (`engine.rs:1575-1590`) and is the realistic state-changing unit for a data shard.

### Fixture
`shard1_proposer_with_cast` registers `FID_FOR_TEST` (storage + id + signer) in snapchain mode via `register_user`, then `enter_hypersnap_mode(Some(fork_height))` (= shard-blocks-test's own setup). The engine is built with a mempool channel; a spawned responder serves one pull: a `MempoolMessage::BlockEvent { for_shard: 1, message: create_merge_message_event(cast, 1) }`. `propose_value` therefore yields an honest block with one state-changing transaction. The honest block is height `fork_height + 1` (= 4 in the run); `decide` is caught with `futures::catch_unwind` so the store can be inspected after the panic.

### Results
| Test | Copy body (same header+hash) | Result |
|---|---|---|
| `decide_halts_when_copy_drops_the_honest_transaction` (A) | transactions **emptied** | **GREEN** |
| `decide_halts_when_copy_alters_the_honest_transaction` (B) | block event's payload swapped for a different cast (same seqnum) | **GREEN** |
| `no_halt_when_the_differing_txn_carries_no_block_event` (neg. control) | empty honest block + junk `Transaction{fid:1}` | **GREEN** (asserts **no** panic) |

For A and B the rejected copy (`add_proposed_value` → `Invalid`, via `validate_body` `BadMessagesRoot`) overwrites the honest entry under the same value id; `decide` then commits the stored copy. The cache misses on the events hash, the stored body is replayed against the cached blake3 `shard_root`, and `commit_shard_chunk` panics:

```
panicked at src/storage/store/engine.rs:3703:21:
State change commit failed: merkle trie root hash mismatch
```

**State written before the panic:** none. `producer().store().get(4)` is `None` both before and after. `LocalStateStore::read_shard_halt(db, 1)` returns `Some(ShardHalt { shard_id: 1, height: 4, reason: "merkle trie root hash mismatch" })` — the record `commit_shard_chunk` writes immediately before `panic!` (`engine.rs:3697-3703`). This is the exact halt the finding describes (inner `replay_proposal` `HashMismatch`, shard-halt record, no committed block), not the outer Keccak-root path.

### Effect on the finding's caveats
- The shard 1/2 halt sub-claim is now **build-backed**, not source-only. Update the finding's PoC note and the validation note's caveat 3 accordingly.
- **Sharper scope than the finding states:** the halt fires only when the attacker's body differs in a way that changes `compute_block_events_hash` **and** the trie — i.e. the swap must touch a **block event** (shards 1/2 carry shard-0-fanned block events: MergeMessage / verification / channel). A body that differs only in **user messages** does **not** halt and does **not** corrupt the store: the cache hits and the honest execution commits (negative control). The finding's phrasing "empty `transactions`, or one bogus transaction" is therefore too broad for the halt — that input is the *corrupt-store* / cache-hit case, not the halt. The halt and the corrupt-store outcomes partition on whether the differing body carries a block event. The attack is still unauthenticated and repeatable; this only narrows which crafted bodies produce the halt vs. the unsyncable-block outcome.
- Not exercised (unchanged from run 1): the gossip race, the restart/WAL divergence, and shard 0's `decide`.
