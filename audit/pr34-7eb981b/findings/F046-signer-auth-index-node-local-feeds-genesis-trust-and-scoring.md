---
finding_id: F046
title: A node-local signer index (prefix 83, outside every state root) feeds the genesis trust snapshot and every ScoringResult, so honest nodes
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.75
poc:
  path: poc/F046
  kind: build-backed
  result: 5/5
related_findings:
- F027
- F045
- F015
- F021
---
# F046 — The PoQ app filter (F0) reads `HyperSignerAuthByRequester` (prefix 83). That index is node-local: it is not in the state trie, and its contents depend on which release merged which events on this node. It feeds the epoch-1 trust snapshot at genesis (so `trust_snapshot_root` and `genesis_state_roots[0]`) and every later `ScoringResult`, which validators compare byte for byte. Nodes whose snapchain shard-0 DB came from the default upstream snapshot, from an older release, or from the manual `f0_backfill` tool compute different genesis records and scoring results.

> **Status (2026-11-04):** Severity **High** (validated 0.75, HAS_CAVEATS). PoC: [poc/F046](../poc/F046/) (build-backed, 5/5). State: validated.

> **Status 2026-11-04 (post-validation):** Severity High (validated 0.75): it fails closed at the pivot vote, but a latent split appears at scoring heights. PoC: [poc/F046](../poc/F046/) (5/5).


- **Severity:** High, source-only. This is liveness at the pivot and at every scoring height, with no fund loss.
  - At the pivot, the bootstrap validators must agree on one `PivotRecord` (`engine.rs:679-681`). If their prefix-83 contents differ in any way that flips one FID's F0 bit, they don't agree and the chain does not start.
  - A follower whose prefix 83 differs cannot boot at all: `prepare` rejects its own record against the certified one (`pivot_boot.rs:324-331`).
  - After the pivot, validators with a different index reject every block at each scoring height. At ≥ 1/3 of the weight, that halts shard 0 every epoch.

  Confidence 0.6. The exposure depends on how the bootstrap operators populate their shard-0 DBs. If every one of them synced shard 0 from snapchain genesis with a release that already had this code, no divergence occurs.
- **Category:** checkpoint-input-nondeterminism / consensus-vs-local-prefix-misclassification / genesis-input-nondeterminism (G3, X3)
- **Specialist:** pivot-genesis-epoch · tasks H025 + H035 (G3)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** Prefix 83, `signer_auth_index.rs`, `f0_backfill.rs`, `scoring.rs` and `pivot.rs` are all absent from the fork base bdef7b7 (snapchain v0.15 content).

## Code facts

1. **The index is not consensus state.** `is_shard0_consensus_prefix` lists the snapchain prefixes and the Hyper* state, but not `HyperSignerAuthByRequester` (83) (`src/chain/shard0/keys.rs:443-515`). `build_state_trie` skips it (`src/chain/pivot.rs:325-354`).
2. **Scoring reads it.** `HypersnapReader::signer_authorizations` scans prefix 83 in the shard-0 DB (`src/chain/scoring.rs:207-210` → `src/chain/poq_reader.rs:608-640`). `signer_authorizations_clustered` uses the trait default, which is the same number (`crates/proof-of-quality/src/reader.rs:121-123`). F0 trips when `max(signer_authorizations, clustered, miniapp_author_count) ≥ app_threshold` (`crates/proof-of-quality/src/eligibility.rs:118-124`). The eligibility bit goes into `ScoredFid.eligibility` and therefore into the trust snapshot, the rewards and the vouch evaluations.
3. **Genesis reads the node's own snapchain shard-0 DB.** `build_in` checkpoints `snapchain_db_path(rocksdb_dir, 0)` as the shard-0 build DB (`src/node/pivot_boot.rs:350-363`). `build_genesis` → `write_trust_snapshot` runs PoQ over it with `HypersnapReader` (`pivot.rs:290-320, 383`). The result is written as `trust_score` and `eligibility` keys, which are consensus prefixes, and hashed into `trust_snapshot_root` (`pivot.rs:464`). The genesis-snapshot path covers only shards 1 and 2 (`src/node/genesis_snapshot.rs:1-21, 359-406`), so every node, snapshot or not, builds shard 0 from its own DB.
4. **The contents depend on the node's history.**
   - Incremental writers exist only in this release: `merge_onchain_event` signer Add/Remove (`src/storage/store/account/onchain_event_store.rs:555-571`, which ignores errors with `let _ =`), gasless `merge_key_add`/`remove` (`gasless_key_merge.rs:260, 392`), and `registry::remove_gasless_key` (`registry.rs:516`).
   - The default bootstrap of a read node downloads the upstream snapchain snapshot for shards 0, 1 and 2 (`src/storage/db/snapshot.rs:61-75`, `load_db_from_snapshot: true`, `BootstrapMethod::Snapshot`; `src/main.rs:351-410`). Upstream never writes prefix 83, so for all history before the node's start the index is empty.
   - The `f0_backfill` binary exists to fill these gaps "for any pair the merge paths didn't already record" (`src/bin/f0_backfill.rs:1-15`). It uses a different rule from the merge path: net `Add − Remove` per pair over every stored event, clamped at 0, and only for pairs it finds (`f0_backfill.rs:96-150, 213-240`). The merge path is sequential `inc`/`dec` with saturation, skips superseded events, and leaves AdminReset alone. Nothing in `pivot_boot` runs or checks it, and no doc in the repo mentions it.
   - The state walk derives prefix 83 for data shards (`state_walk.rs:47-62, 240-280`), which shows the authors know it is derived. Shard 0 has no such step.
5. **Validity compares the local result.** Validate requires the block's `ScoringResult` to equal this node's (`engine.rs:731-738`). The pivot block requires the `PivotRecord` to equal this node's (`engine.rs:679-681`).

## Attack / failure path

No attacker is needed. Validators A and B both run this release:
- A bootstrapped snapchain from the upstream snapshot in 2026-09.
- B synced shard 0 from snapchain genesis.

For any app FID whose distinct-user count crosses `app_threshold` in B's index but not in A's, F0 differs. Then the eligibility bits differ, then `trust_snapshot_root` differs, then the `PivotRecord` differs. At the pivot vote each rejects the other's block. Every later scoring height repeats the split, because the index is never reconciled.

An attacker can also widen the gap on purpose. An app FID that registers signers for many users (cheap with gasless KEY_ADD) moves its count across the threshold right before the fork. That maximises the effect of any bootstrap difference.

## Red-team

1. *All bootstrap validators may sync from genesis with one release.* That is possible, and then they agree. But the data shards already need the full chunk history for the content replay, and shard 0 doesn't. The default config takes the upstream snapshot, and the existence of `f0_backfill` shows that partial indexes were expected. Followers have no such coordination.
2. *Is F0 actually in the genesis scoring?* Yes. `write_trust_snapshot` uses `ScoringParams::default()` with empty market budgets only (`pivot.rs:302-305`). The eligibility filters run unchanged.
3. *Is prefix 84 also involved?* `HyperCustodyToFid` is also node-local, but `HypersnapReader` does not use the clustered `PoqReader` path, so it doesn't reach consensus at 7eb981b. If someone wires it in later, it has the same bug.
4. *After the pivot, writes are deterministic.* True. Divergence carries forward from the genesis base and is never repaired.
5. *Fail-closed?* Yes: no forged state is accepted, and nodes refuse to agree. Severity is about the pivot not starting and recurring halts.

## Recommendations

- Make prefix 83 consensus state: add it to `is_shard0_consensus_prefix` (it is then in the root and checked at the pivot vote). Or derive it deterministically inside `build_genesis` by a full re-derivation from the on-chain signer events and gasless records, with the same rule as the merge path, before `write_trust_snapshot`.
- Remove `f0_backfill`, or make it the same function the builder calls.
- Add a pivot test: same events, different prefix-83 history, so the build must give the same `PivotRecord`.
