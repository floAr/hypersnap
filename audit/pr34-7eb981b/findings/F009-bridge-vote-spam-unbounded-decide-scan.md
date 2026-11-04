---
finding_id: F009
title: One validator can create unlimited distinct bridge actions for free, and every shard-0 block's `decide` loads all of them into memory, so a
severity: medium
status: pending-validation
related_findings:
- F008
- F017
---
# F009 — One validator can create unlimited distinct bridge actions for free, and every shard-0 block's `decide` loads all of them into memory, so a single member of the set can slow or stall shard-0 execution for the rest of the epoch

- **Severity:** Medium (liveness). It needs one registered validator, a single Byzantine member, which is well below the 1/3 the BFT model tolerates. It cannot move funds, forge an action, or reach the bridge threshold. The impact is a degraded or halted shard 0 until the boundary block. That block then also has to delete all of the data in one batch. The attacker can repeat this every epoch. Downgrade to Low if the operators treat the validator set as permissioned and trusted not to grief.
- **Category:** bridge-action-vote-miscount (resource accounting of the vote path) / proposer-validator DoS.
- **Specialist:** shard0-ledger-state · task H008
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** None. The finding is reasoned from source only. The operator asked us not to build the node crate. A test in the existing `engine_test.rs` harness (`bridge_*` tests near `:2185-2290`) can show it: a single member submits N votes with N distinct `target`s, and then the time of one empty block grows with N.
- **Related:** F008 covers action ordering and relaying on the EVM side, and the effect of the boundary on decided actions. It is not refiled.

## Summary

`bridge_actions::vote` (`src/chain/shard0/bridge_actions.rs:38-93`) admits any action that:
- has a valid `kind` (1..3),
- has a 20-byte `target` (zero for a pause), and
- has any `chain_id` (u32, not checked against a list of deployments).

Each voter is limited to **one vote per action**, but **not to a number of actions**. The action identity is `keccak(domain‖kind‖chain_id‖target)` (`:29-35`). A member can therefore make about 3·2^32·2^160 distinct actions. Each first vote writes three keys: `BRIDGE_VOTE`, `BRIDGE_VOTE_COUNT` and `BRIDGE_ACTION` (`:77-91`). Nothing is charged: `vote` debits no balance and checks no fee or stake, and there is no per-voter or per-epoch cap.

`decide` (`:98-143`) runs in **every** shard-0 block, in `execute` step 6 (`engine.rs:877`). This covers propose, validate and commit. Each time it calls

```rust
let prefix = keys::bridge_votes_of_epoch(keys::BRIDGE_VOTE_COUNT, ctx.epoch);
for (k, v) in txn.scan(&prefix)? { ... }
```

`MsgTxn::scan` → `BlockState::scan` (`state.rs:54-91, 175-192`) builds a full in-memory `BTreeMap` of **every** key under the prefix, from RocksDB plus the batch overlay, before iterating. The loop exits early only when an action passes 2/3. In the attack, no action passes, so every block reads and allocates all K vote-count entries of the epoch.

The entries stay until the boundary of the **next** epoch. `on_boundary` (`:154-168`, `boundary.rs:32`) deletes epochs `e-2..e-1`. It first scans all four sub-prefixes into memory again and deletes about 3K keys in the single boundary block.

## Attack

1. The attacker is a validator: a migrated FID with the account key, an attested node key, the age and trust gates, a member of `set(e)`. That is the only precondition.
2. In every block it proposes, it fills the block with `BRIDGE_ACTION_VOTE`s signed by its node key. Each has `kind = UPGRADE`, a fresh random `target`, and any `chain_id`. A Falcon-signed vote is roughly 0.8 KB. The block cap is `max_messages_per_block = 12_000` (`engine.rs:163`), within `MAX_BLOCK_BYTES = 16 MiB` (`block.rs:11`). So each attacker proposal adds up to 12,000 new actions. Validators accept them: each vote is valid on its own (`engine.rs:547`, `bridge_actions.rs:38-93`). The proposer does not need the mempool, so mempool rate limits do not apply. It can also feed honest proposers through the mempool, within its per-FID limits.
3. With N validators, the attacker proposes about 36,000/N blocks per epoch (`EPOCH_LENGTH = 36_000`, `epoch.rs:6`). With N = 20, that is about 1,800 blocks, so K reaches about 21.6M action entries, with about 65M keys in total. Even after 100 attacker blocks (K ≈ 1.2M), every following block on every node does a 1.2M-entry RocksDB prefix iteration and builds a BTreeMap of about 100 MB in `decide`. The cost grows linearly with each further attacker block. The total work over the epoch is quadratic in the number of attacker blocks.
4. When block execution time goes past the consensus timeouts, shard-0 liveness degrades or halts. Shards 1 and 2 depend on shard-0 heights (replica / fee settlement), and so do the bridge headers. The boundary block then has to scan and delete everything, which may be the worst block of all.
5. Repeat in the next epoch.

The state also grows by about 3K keys (several GB at the larger K) for up to two epochs. The trie and state root cover these keys, so the shard-0 commitment work grows too.

## Red-team walk

1. *Reachable at `7eb981b`?* Yes. `vote` is a normal shard-0 user message (`engine.rs:547`). The checks are only the node-key role (`auth.rs:337,345-362`), the epoch, the kind/target shape, set membership and the per-(action, node key) dedupe. No cap exists anywhere on the path.
2. *Who controls the input?* Any single member of `set(e)`. Its votes are individually valid, so honest validators must accept its blocks. Otherwise they reject valid blocks, which is proposer/validator divergence.
3. *Existing mitigations?* The mempool rate limits (`mempool/l1_gate.rs`) are local policy and do not bind the attacker's own proposals. The block size and message cap only bound the growth per block, not the total. Shard 0 has no fee for this message type.
4. *Is it just generic block stuffing?* No. Generic stuffing costs each block once. Here, each stuffed vote adds a cost that **every later block of the epoch pays again** (and the boundary block pays once more), so a small number of attacker blocks amplifies.
5. *Can the attacker make an action pass?* No. With weight 1 per member, it has one vote per action. This finding is about liveness, not authority.
6. *Is the BTreeMap materialisation a real cost, or lazy?* It is real. `BlockState::scan` iterates `for_each_iterator_by_prefix` into `out: BTreeMap` with cloned keys and values (`state.rs:54-67`). `MsgTxn::scan` then clones again when it merges the overlay.
7. *Slashing or accountability?* Nothing in `validators.rs` penalises vote spam. The attacker stays in the set while it keeps proposing, because auto-deregistration only counts missed proposals.
8. *Severity check.* It needs a validator. The impact is liveness only and can be recovered after the boundary. It can be repeated. That gives Medium for a permissionless validator set. If the set is curated, Low.

## Recommendation

Do one or more of the following:
- Bound the work per voter. For example, allow at most `MAX_OPEN_ACTIONS_PER_VOTER` (a small number, such as 4) open actions per node key per epoch, counted in a key such as `[BRIDGE_VOTER_OPEN][epoch][node_key_hash]`, and reject further votes.
- Make `decide` incremental. When `vote` raises a count past `2/3·total_weight`, have it append the action hash to a small `BRIDGE_PASSED` queue, and let `decide` pop from that queue (keeping the hash order within a block if wanted). Then `decide` costs O(passed) instead of O(all voted actions).
- Optionally, restrict `chain_id` to the configured bridge deployments and `target` for `CANCEL` to an upgrade proposed earlier. That removes most of the free action space.
- Consider deleting old-epoch bridge keys across several blocks, or limiting them so that the boundary block is bounded.

## Other H008 questions (checked, no finding)

- **Q1 Weight vs. count.** Every set-member constructor sets `weight: 1`: `validators.rs:126-137` (`members_at`, used by `write_set_record` at boundaries and in `pivot.rs:427`), `genesis_file.rs:234-239` (epoch-1 set) and `build_record` (`validator_sets.rs:36-50`, which dedups by consensus key and sums weights). So `votes*3 > total_weight*2` is exactly a 2/3 member count at this commit. **Latent** risk: if weights are ever non-1, `vote`'s `add_u64(count, 1)` must become `add_u64(count, member.weight)`. That would be a minority decide (weights < 1 impossible) or a blocked supermajority. EVM side: `HypersnapBridgeV2` does not count bridge votes. It trusts the certified header's `bridge_action_hash` (`:436-442` hash preimage matches `action_hash` byte for byte: domain, u8 kind, u32 BE chain id, 20-byte target). Every validator recomputes `decide` and rejects a header whose `bridge_action_hash` differs (`engine.rs:1091`). The certificate quorum (`3*w > 2*total`, `validator_sets.rs:130`, `certificate.rs:160`) uses the same per-member weights. Consistent.
- **Q2 Eligibility / duplicates / replay.** A vote must be signed by a Falcon node key whose attestation names `env.fid()` (`auth.rs:345-362`). The (node_key_hash, fid) pair must be a member of `set(ctx.epoch)` (`bridge_actions.rs:60-68`), and `body.epoch == ctx.epoch`. Dedupe is per `(epoch, action, node_key_hash)`, so a replayed or duplicated vote is rejected. Another epoch's vote fails the epoch check. Network binding comes from `auth::open`. One FID can run several validators (distinct consensus and node keys, bounded by `max_nodes_per_fid`), but each of them is also a separate consensus seat with weight 1, so bridge voting power equals consensus power. This is not a bridge-specific amplification. Edge case: the register-cancel path (`validators.rs:214-223`) re-activates a validator without the node-key-uniqueness check at `:204-208`. So two active members of the same FID can share a node key. Such a pair gets **one** bridge vote (dedupe by node key) but weight 2. This makes the threshold harder, which is self-harm equal to abstaining, so there is no finding.
- **Q3 Grinding / starvation.** `decide` picks the lowest-hash passing action, one per block. Only actions with more than 2/3 votes are candidates, so a Byzantine minority cannot insert a competitor. A decided action is skipped next block, so a passing cancel is delayed by at most (number of simultaneously passing actions − 1) blocks. The ordering consequences are covered by F008. The only node-side scheduling issue is the cost described above.
- **Q4 Boundary.** Votes are scoped by epoch, and `decide` only scans `ctx.epoch`. An action that passes in the last block of an epoch, but is not the one picked (only possible when ≥2 actions pass in that same last block), is wiped at the next boundary and must be voted again. Votes never carry over to a different set. This is documented behaviour ("An action that an epoch does not decide needs new votes", `:152-153`), and F008 discusses it. `BRIDGE_PAUSE` is not cleared, which is correct.
- **Q5 Determinism.** All scans return `BTreeMap` (byte order). The key layout `[prefix][sub][epoch BE][action]` gives action-hash order within an epoch, and `try_from` skips any key of the wrong length. There is no `HashMap` iteration in `vote`, `decide` or `on_boundary`. `pause` uses `max(existing, ts + PAUSE_DURATION)`, which is deterministic and only extends the pause.
