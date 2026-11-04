---
finding_id: F027
title: The genesis-snapshot install checks the Keccak root and walks the stores, but it never checks the BLAKE3 sync trie
severity: medium
status: pending-validation
related_findings:
- F028
- F033
---
# F027 — The genesis-snapshot install checks the Keccak root and walks the stores, but it never checks the BLAKE3 sync trie (`RootPrefix::MerkleTrieNode`). After the pivot, data-shard blocks still carry a per-FID BLAKE3 `account_root` in each transaction, and validators compare it. A snapshot provider can therefore poison every node that bootstraps from its snapshot: the node installs it, then halts at the first data-shard block

- **Severity:** Medium (availability of every snapshot-bootstrapped node; a validity input that the spec does not list). No forged state is accepted network-wide, and the victim fails loudly. Downgrade to Low if the operators confirm that the genesis snapshot path is only for followers and never for validators, and that a second snapshot source is always configured.
- **Category:** genesis-state-forgery (state-walk completeness) + spec-divergence (two-pipeline: Keccak is "the commitment", but BLAKE3 is still checked)
- **Specialist:** pivot-genesis-epoch · attack class: genesis-state-forgery · task H017
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **Trust assumption:** the attacker controls the genesis-snapshot download (`hypersnap.genesis_snapshot_url`, i.e. the bootstrap bucket or whoever can write to it, or one exporting bootstrap validator). The code treats that source as untrusted: `state_walk.rs:3-8` says "A forged snapshot can keep that root and add records that no trie key names … The store walk closes this gap." The certified `PivotRecord` path (`fetch_certified_record`) is sound and is not needed for the attack.
- **PoC:** None (reasoned from source; the node crate was not built).

## Code facts

1. **What install verifies.** `genesis_snapshot::check_staged` (`src/node/genesis_snapshot.rs:359-406`) runs four steps. (a) `check_fork_chunk` checks the last chunk against the local marker. (b) `rebuild_shard_root` clears **only** `KeccakTrieNode` (`shadow_backfill.rs:60-87`) and rebuilds the Keccak trie. (c) It compares the result with `certified.genesis_state_roots[s]`. (d) It runs `walk_stores`, then `drop_history` (which deletes HubEvents and chunks `< H_s`).
2. **The walk leaves the sync trie alone.** `state_walk.rs:67-79` puts `RootPrefix::MerkleTrieNode` (8) in `NOT_DERIVED`: "the history, the tries and local data". Nothing in the walk, the rebuild or `drop_history` reads, rebuilds, compares or deletes prefix 8. The installed DB becomes the Hypersnap shard DB as it is (`pivot_boot.rs:376-381`, a checkpoint of the replay DB; `genesis_points` opens it).
3. **The Keccak rebuild uses the sync trie only to list keys, and it tolerates junk.** `build_from_snapshot` (`shadow_backfill.rs:91-…`) gets its keys from `snapshot.trie.get_paged_values_of_subtree` and resolves each key against the stores. Unresolved keys are logged, and `rebuild_shard_root` only `warn!`s about them (`pivot_boot.rs:527-533`). A key that the sync trie *lacks* drops its object from the Keccak trie, so the root check or the walk ("not in the Keccak trie") fails. Extra keys and wrong node hashes, however, are accepted.
4. **Trie hashes are read from storage and never recomputed.** `MerkleTrie::get_hash` / `root_hash` return the stored `node.hash()` (`merkle_trie.rs:417-447`).
5. **After the pivot, `account_root` is a validity condition.**
   - The proposer writes it: `hypersnap_propose` → `propose_state_change` sets `snapchain_txn.account_root = trie.get_hash(TrieKey::for_fid(fid))` (`engine.rs:1104-1116`, `2461-2467`), and those transactions are the block body (`shard_blocks.rs:424-428`).
   - The validator checks it: `ShardBlockStore::validate` → `hypersnap_validate` → `replay_proposal(…, ProposalSource::Validate)`, which does `if !self.content_replay && account_root != snapchain_txn.account_root { return Err(HashMismatch) }` (`engine.rs:1308-1331`). `content_replay` is only set by `enter_content_replay` (`engine.rs:481-500`), not in Hypersnap mode. Only the *whole-trie* root check is skipped in Hypersnap mode (`engine.rs:1337-1339`).
   - Commit/sync does the same: `hypersnap_commit` without a cached execution goes through `commit_shard_chunk`, which calls `replay_proposal(…, Commit)`. On error it records `ShardHalt` and panics (`engine.rs:3680-3700`).
6. **Nothing anchors the BLAKE3 trie of a replay DB.** The `PivotRecord` has only Keccak roots (FIP §17.4). The fork chunk's `shard_root` is the *snapchain* root, and the replay DB differs from it because it does no pruning. So there is nothing to compare the snapshot's sync trie with.
7. **The spec does not mention it.** FIP §17.7 says the header `state_root` is the Keccak root, and "New nodes … compare the roots of the snapshot with the `PivotRecord`. The certificate … makes the `PivotRecord` trusted." The FIP does not mention a BLAKE3 `account_root` as a post-pivot validity condition (§16.13 keeps BLAKE3 only for message identifiers, "not commitments").

## Attack

1. The attacker publishes (or modifies) `genesis-<P>/<s>` in the bucket. The DB is an honest replay DB with one change: in the `MerkleTrieNode` records, every FID-level node gets a wrong stored hash (or an extra leaf key under each FID subtree). The key set stays a superset of the canonical one.
2. A new node runs the snapshot path (`hypersnap_main.rs:822-857`). The certified record verifies. The rebuilt Keccak root equals `genesis_state_roots[s]`, because the objects are canonical and the extra keys are unresolved and only produce a warning. The walk passes. `install` renames the DB into place, and `prepare` builds the record, compares it with the certified one (it is equal) and commits the data directory.
3. At the first post-pivot data-shard block that touches any FID, the victim's recomputed `account_root` differs from the body → `HashMismatch`.
   - As a validator, it rejects every honest proposal (prevote nil). Its own proposals carry wrong `account_root`s, so honest validators reject them too.
   - As a follower or syncing node, `commit_shard_chunk` panics and records `ShardHalt`, and the shard stays dead.
   - Recovery means wiping the Hypersnap data directory and the replay DBs and installing from another source. The error ("Account root mismatch") points the operator at block data, not at the snapshot.
4. Scale: every node that uses the genesis-snapshot path from that source. These are the nodes that synced snapchain from a snapshot (`shards_without_history`). That is most new nodes, and after the pivot it is probably every new joiner, because a new node needs the genesis state at `H_s`. If they are validators of an epoch, they cannot vote on shards 1/2. Shards 1/2 halt if their weight reaches 1/3 (compare F024 for how seats are obtained).

## Red-team (invalidation hypotheses)

1. *Is the sync trie checked somewhere else?* No. Checked: `check_staged`, `rebuild_shard_root`, `walk_stores`/`state_walk::check`, `drop_history`, `prepare`/`build_in`/`shard_root` (status `Live{H_s}` → it uses the rebuilt Keccak trie), and `enter_hypersnap_mode`. None of them touches prefix 8.
2. *Is `account_root` really checked after the pivot?* Yes: `!self.content_replay` is the only guard, and it is false in Hypersnap mode. The proposer fills the field, and the validate and commit paths compare it (fact 5).
3. *Does the walk's "each object is in the Keccak trie" check catch a missing sync key?* Yes, but only for *missing* keys. Junk keys and corrupted stored hashes do not change the object set, so they pass (fact 3).
4. *Do honest replay nodes agree on the BLAKE3 trie, so that the snapshot is the only divergence?* Yes, the content replay is deterministic. Exporters and local-path nodes hold the same trie, and only an edited snapshot differs.
5. *Is this just "don't use a malicious snapshot"?* No. The module explicitly sets out to make the snapshot untrusted (store walk, certified root). It covers the Keccak pipeline and misses the second pipeline, which consensus still reads (the two-pipeline-confusion lesson).
6. *Can the attacker do more than DoS, e.g. make the victim accept or propose bad state?* No. The Keccak `state_root` check and the walk still hold, so the victim cannot be steered into accepting forged Keccak state. The impact is availability only.
7. *Is a regular (non-genesis) snapchain snapshot equally trusted, making this moot?* Before the pivot, snapchain snapshots are trusted wholesale, but that is the snapchain trust model. This PR adds a *verified* genesis path and documents it as safe against forged snapshots. Post-pivot Hypersnap state snapshots are out of H017 scope.
8. *Severity check.* No funds and no network-wide integrity break. Many nodes can lose availability from one bucket write, and the cost is low. Medium, with a Low floor (see header).

## Recommendations

- Rebuild the BLAKE3 sync trie on install: in `check_staged`, delete prefix `MerkleTrieNode` and re-insert the trie keys of the walked objects (the same keys `TrieKey::for_message`/`for_onchain_event`/`for_fname` derive). Alternatively, rebuild it with the existing snapchain trie reconstruction from the stores. Also make `unresolved_keys > 0` a hard error on the snapshot path.
- Better, resolve the spec divergence. Either (a) stop checking `account_root` in Hypersnap mode (the Keccak `state_root` is the commitment; the field can be set to empty and ignored), or (b) specify it in the FIP and commit the BLAKE3 roots of shards 1/2 in the `PivotRecord`.
- More generally, have `install` delete or rebuild every `NOT_DERIVED` prefix that the node reads after the pivot (`MerkleTrieNode`, `BlockEvent`, `NodeLocalState`, `KeccakTrieMeta` history, `DBSchemaVersion`), instead of keeping the provider's copy.
