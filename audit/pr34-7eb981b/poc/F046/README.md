# F046 PoC: node-local prefix 83 (`HyperSignerAuthByRequester`) splits the genesis `PivotRecord`

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`, `CARGO_TARGET_DIR=<build-tree>/target`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/f046_poc_test.rs`, wired as `#[cfg(test)] mod f046_poc_test;` in `src/chain/mod.rs`. A copy is here as `f046_poc_test.rs`.
- Run script: a local helper (not included) that copies the test in, wires the module and runs cargo.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f046_poc_test -- --nocapture --test-threads=1`
- Incremental build ~37 s, test run ~8 s.
- Output: `F046-test-output.txt`.

## Fixture

A copy of `pivot_test::two_nodes_build_the_same_genesis_and_accept_the_pivot_block` (its helpers are private, so `id_event`, `validator`, `open` and `epoch0` are copied verbatim): the same eths, four genesis validators, genesis file, `params()` with `pivot_height_0 = 100`, the exempt recovery for FID 1000, the shard forks and the `PivotInputs`. Each node is a fresh RocksDB shard-0 DB that runs `epoch0` (FIDs 1-4, 1000 and 1001 through `merge_onchain_event`), then a node-local preparation step, then the production `pivot::build_genesis`.

- **Node A** stands for an upstream-snapshot or older-release node: prefix 83 is empty.
- **Node B** additionally gets `signer_auth_index::inc(&shard0, txn, 1000, 10_000 + u)` for `u in 1..=100` (`app_threshold` defaults to 100). That is exactly what the merge path writes for 100 distinct users authorised by app FID 1000.
- Before every build the test dumps every key under every `keys::is_shard0_consensus_prefix` prefix on both DBs and asserts the dumps are **equal**, so the only difference between the nodes is prefix 83.
- The pivot vote uses `Shard0Engine::propose` on one node and `Shard0Engine::validate` on the other, each with `TestInputs { pivot: Some(<own record>) }`.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `f046_prefix83_divergence_splits_genesis_and_rejects_pivot_block` (headline) | Consensus prefixes equal before the build; prefix 83 A=0, B=100. After `build_genesis`: `trust_snapshot_root` and `genesis_state_roots[0]` differ, `record_differences(B, A) = ["genesis_state_roots", "trust_snapshot_root"]`, the consensus key `eligibility(1000)` is `[121]` on A and `[120]` on B (F0 bit). B's `validate` of A's pivot block returns `Invalid("PivotRecord differs from this node's")`, and A rejects B's block the same way. | **RED** (pass, claim reproduced) |
| `f046_trust_snapshot_f0_bit_flips` (direct) | `pivot::write_trust_snapshot` on fresh copies: FID 1000's `ScoredFid.eligibility` is 121 on A (F0 passes) and 120 on B (F0 trips). The `trust_snapshot_root`s differ (`e9cdba01…` vs `0cbf198f…`). | **RED** (pass, claim reproduced) |
| `f046_control_no_increments_records_equal` (control 1) | No `inc` on either node: the records are equal, `record_differences` is empty, and B accepts A's pivot block. | pass (control) |
| `f046_control_99_users_equal_record_then_latent_scoring_split` (control 2) | 99 users on B (below the threshold): prefix 83 differs (0 vs 99), but the `PivotRecord`s are **equal** and B accepts A's pivot block. Post-genesis, `scoring::compute` (epoch 1) gives equal `ScoringResult`s. After a 100th user is added to **B's index only**, the `ScoringResult`s differ (FID 1000 mask 121 vs 120). This is the latent post-pivot split: passing the pivot vote does not show the indexes agree. | pass (control, plus latent split reproduced) |
| `f046_step7_real_signer_events_snapshot_vs_merged` (recipe step 7) | 100 real KeyRegistry `SignerEventBody{Add, metadata_type 1, metadata = abi(SignedKeyRequestMetadata{requestFid: 1000, ..})}` events per node. B merges them through `OnchainEventStore::merge_onchain_event` (this release). A merges the same events and then has prefix 83 removed (what an upstream snapshot or an older release holds). Consensus state is equal (214 `OnChainEvent` rows each); prefix 83 A=0, B=100; `record_differences` names `trust_snapshot_root` and `genesis_state_roots`; B rejects A's pivot block with "PivotRecord differs". The metadata is an unsigned dummy ABI blob, which confirms `get_request_fid_from_signer_event` does not check the signature. | **RED** (pass, claim reproduced) |

**All 5 tests pass.** The core claim reproduces: two nodes with byte-identical consensus state but different prefix-83 contents build different genesis `PivotRecord`s, and each prevotes nil on the other's pivot block. Below the threshold the records agree, and the divergence surfaces later as different `ScoringResult`s.

## What was and was not exercised

- Exercised with real code: `signer_auth_index::inc`, `OnchainEventStore::merge_onchain_event` → `build_secondary_indices_for_signer` → `get_request_fid_from_signer_event` (step 7), `pivot::build_genesis` (`write_fid_clocks`, `write_trust_snapshot` → `HypersnapReader` → `PoqReader::signer_authorizations` → PoQ `evaluate_epoch` / F0, `build_state_trie`), `pivot::trust_snapshot_root`, `pivot_boot::record_differences`, `Shard0Engine::propose` / `validate` on the pivot block, and `scoring::compute` on the post-genesis DBs.
- Source-only:
  - The follower `pivot_boot::prepare` path (`pivot_boot.rs:324-331`) was not driven. The test calls the same `record_differences` that `prepare` uses on its own record against the certified one.
  - The scoring-height halt itself: the test shows `scoring::compute` diverges on the two DBs, but it does not drive a `Shard0Engine` to a scoring boundary and observe the `ScoringResult` byte comparison in validate (`shard0/engine.rs:731-738`) reject the block.
  - How a real node's prefix 83 ends up different (default upstream snapshot bootstrap, in-place upgrade from hypersnap `origin/main`, `f0_backfill` versus the merge path). The test models these states directly: an empty index on A, and, in step 7, the same `OnChainEvent` rows with prefix 83 removed.
  - The size of the gap on mainnet data, and whether the operators plan to run `f0_backfill` on the frozen DB on every node (the mitigation in the validation note).

## Caveats

- This is fail-closed liveness. No wrong state is certified: the pivot vote catches the divergence with a clear error. The impact is that the network does not start, or that a follower cannot join, unless every bootstrap node's prefix 83 agrees on every FID's F0 bit.
- The 100-user threshold is the default `ScoringParams` `app_threshold`, which `write_trust_snapshot` uses. Real app FIDs (Warpcast-class) are many orders of magnitude above it, so an empty versus a full index flips F0 for every real app FID, not only near the threshold.
