---
finding_id: F022
title: Any gossip peer can replace the stored body of a proposal that consensus is about to decide
severity: critical
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F022
  kind: build-backed
  result: 7/7
related_findings:
- F023
- F033
---
# F022 — Any gossip peer can replace the stored body of a proposal that consensus is about to decide. The undecided-value store is keyed only by the block's self-declared `hash`, a copy is written before it is validated, and `decide` commits whatever body is stored. On shards 1 and 2 every validator panics at commit (shard halt); on shard 0 every validator stores a corrupt block that no node can later sync.

> **Status (2026-11-04):** Severity **Critical** (validated 0.85, HAS_CAVEATS). PoC: poc/F022 (build-backed, 7/7). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity Critical (validated). PoC: poc/F022 (7/7).


- **Severity:** Critical (shards 1/2: network-wide halt of the shard, repeatable at every height; shard 0: permanent sync failure at the attacked height, plus a panic on any node that takes the re-execution path). The attacker needs no key and no stake: only a libp2p connection to the `consensus` gossip topic, which the code does not restrict (see "Trust assumptions"). **Downgrade to High** if deployment puts validators behind a gossip allowlist so that only validators can publish on `consensus`; a single Byzantine validator can still do it then.
- **Category:** propose-value-misuse / consensus-safety-of-stored-value (value id not bound to the stored body)
- **Specialist:** consensus-malachite-tendermint · attack class: propose-value-misuse · task H013
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Code facts

1. **The value id is the declared hash.** `FullProposal::shard_hash()` decodes only `HypersnapBlockView { header, hash }` and returns `hash` as it appears in the bytes. It does not recompute `keccak(header)` and does not look at the body (`proto/src/lib.rs:192-215`). The body (fields 3, 4, 8) is bound to the header only through `messages_root`, and that is checked only in `validate_body` (`src/chain/block.rs:155-176`).
2. **Store before validation, last write wins.** `check_value` calls `self.proposed.add(full_proposal.clone())` before `validate`/`check_structure` (`src/chain/proposer.rs:111`, `src/chain/shard0/proposer.rs:56`). `UndecidedValues::add` overwrites both the in-memory `BTreeMap<ShardHash, FullProposal>` entry (`src/consensus/proposer.rs:75-78`) and the RocksDB row at `[height][hash]` (`src/chain/undecided.rs:31-36, 58-64`). Round and proposer are not part of either key. An `Invalid` result does not undo the write.
3. **No sender check.** FullProposals reach the host unsigned: gossip → `map_gossip_message` (size, height, round ≥ 0, shard only; `src/network/gossip.rs:1792-1846`) → `network_connector` → Malachite `NetworkEvent::ProposalPart` → `HostMsg::ReceivedProposalPart` → `ShardValidator::add_proposed_value` (`src/consensus/malachite/host.rs:174-190`, `src/consensus/validator.rs:313-365`). Nothing compares `full_proposal.proposer` with `current_proposer` (stored in `start_round`, never read), and `verify_signed_proposal_part` (`src/core/types.rs:228`) has no caller here or in Malachite 13bca14c's engine.
4. **Malachite keeps the first validity.** Malachite's `FullProposalKeeper::store_value_at_value_round` ignores a second value with the same id at the same `(height, round)` ("Same value received before, nothing to do"; `malachite/code/crates/core-consensus/src/full_proposal.rs:300-310`). So the honest copy's `Valid` stays in force and the decision on `V` goes ahead, while Hypersnap's store now holds the attacker's body. If the attacker sends its copy with a round number above the current one, Malachite files it under a round with no signed proposal and it has no effect on voting at all.
5. **`decide` commits the stored body without re-checking it.** `decide` takes `self.proposed.get(&value)`, decodes it, attaches the certificate and calls `commit` (`src/chain/proposer.rs:290-332`, `src/chain/shard0/proposer.rs:232-258`). No `validate_body`, no comparison with the copy that was validated.

## What happens at commit

**Shards 1 and 2** (`ShardBlockProducer::commit` → `ShardEngine::hypersnap_commit` → `commit_shard_chunk`, `src/chain/shard_blocks.rs:524-548`, `src/storage/store/engine.rs:807-843, 3581-3708`):
- The cached execution from `validate` is used only if `compute_block_events_hash(transactions)` matches. The attacker's body (no transactions, or one bogus transaction) does not match, so the commit replays the attacker's transactions against the cached blake3 `shard_root`. The replay returns `HashMismatch` (or an account-root mismatch), and `commit_shard_chunk` records a shard halt and `panic!`s (`engine.rs:3689-3702`). The comment there says the panic stops the host actor and leaves the shard dead.
- Every validator that received the copy before the decision does this at the same height, so the shard halts.
- **After a restart** (expected, given the design note in `undecided.rs:1-7`): memory is empty, so `get` reads the attacker's body back from RocksDB. There is no cached execution, so `blake3_root` is empty and `replay_proposal` skips its root check (`engine.rs:1339-1340`). `commit_and_emit_events` then **writes the wrong state and the attacker's block to the DB** (`engine.rs:3431`) before `ShardBlockProducer::commit` sees the Keccak root mismatch and `decide` panics. On the next start the node is past height `h` with a diverged state. This last step depends on Malachite reaching `Decided` from the WAL without a fresh value; I did not confirm that by running it.

**Shard 0** (`Shard0Engine::commit`, `src/chain/shard0/engine.rs:1098-1140`):
- If `pending.hash == block.hash` (the usual case: the node validated or proposed the honest block), commit uses the honest execution's state, so the state root is correct. But `self.store.stage(block, …)` stores the **attacker's** block. That block is what `get_decided_value` serves to sync (`shard0/proposer.rs:268-279`), and every syncing node rejects it with `BadMessagesRoot` (`check_value(synced=true)` → `check_structure` → `validate_body`). If the attacker reached every validator, no node in the network has a valid copy of height `h`, and no new or lagging node can get past it. It is the same end state as F020, reached at will and at any height.
- If `pending` does not match (the node validated a later round's proposal, restarted, or an attacker evicted it with F023's forged-but-valid block), commit re-executes the attacker's body in `Mode::Commit`; `check_executed` fails and `decide` panics (`shard0/proposer.rs:256-258`).
- The attacker's block also goes out on `decided_tx` (consumer not traced; out of scope).
- `RestreamValue` re-publishes `get_proposed_value(V)`, so an honest proposer that is asked to restream sends out the attacker's body (`host.rs:133-166`).

## Attack

1. Join the Hypersnap libp2p network and subscribe to `consensus` (any peer can; validators accept and forward gossipsub messages from any connected peer, `ValidationMode::Strict` only checks the publisher's own peer signature).
2. When the honest `FullProposal` for `(shard, h, r)` arrives, copy its header and `hash` bytes and replace the body: empty `transactions` on shards 1/2, empty `messages` on shard 0. Set `round` to e.g. `r + 1000`.
3. Publish the copy, and publish it again every ~50 ms until the precommits for `h` appear. The honest copy is delivered once (gossipsub dedupes it by message id), so the attacker's copy is the last write at each node.
4. Repeat at every height.

The cost is a few small gossip messages per height. The timing window is the prevote and precommit phase, hundreds of ms at the minimum and up to `PREVOTE_TIME + PRECOMMIT_TIME` (6 s), which is easy to hit with repeated sends.

## A Byzantine proposer (question 1 of the task)

Two different bodies cannot have the same value id unless they differ only in fields outside `messages_root` and the header: `certificate` (5; `decide` overwrites it) and `aggregate_certificates` (6). Field 6 is never read or verified anywhere in `src/` (FIP §16.5 step 12 says each node verifies the aggregate certificate; field 6 is outside the block hash, so consensus does not cover it either). A Byzantine proposer, or any peer using the attack above, can therefore make nodes store different, `Valid` blocks for one decided hash, differing in field 6. Today this only bloats the stored block (padding toward F020's size failure). Once R2 compaction reads field 6, it will be a consensus-uncovered input. Equivocation with two different hashes is ordinary Tendermint equivocation, and Malachite's signed proposals and votes handle it.

## Trust assumptions

- Attacker: any libp2p peer that can publish on the `consensus` topic. I found no peer allowlist for that topic (`validator_peers` gates only the diagnostics RPC, `gossip.rs:840-845, 1405-1412`). Spec §4.10 describes an open Hypersnap libp2p network.
- No validator key, no FID, no stake.

## Red-team walk

1. *Does Malachite verify proposal parts?* No. `ProposalAndParts` mode (`spawn.rs:102`); the engine forwards parts to the host with no signature check (`engine/src/consensus.rs:510-528`).
2. *Does validation failure undo the store?* No. `add` happens first and nothing removes it.
3. *Does `decide` use Malachite's value or the validated copy?* It uses only `self.proposed.get`, which is last write wins.
4. *Does the shard-0 commit check the body?* Not on the `pending` path, and that path stores `block` as passed.
5. *Does the data-shard cache hide the swap?* No. `is_cached_txn_valid` checks the events hash of the passed transactions, misses, and replays.
6. *Can the attacker's copy make Malachite reject the honest value instead?* Only if it arrives first at the same round. Using a higher round avoids that, and the attack does not need it.
7. *Is the header hard to copy?* No. It comes in the honest proposal.
8. *Is this snapchain's existing behaviour?* The pattern of keying by declared hash is inherited, but `UndecidedValues`, the persisted copy, the Hypersnap `check_value`, and the commit paths are new in this PR (`A src/chain/undecided.rs`, `src/chain/proposer.rs`, `src/chain/shard0/proposer.rs`).

## Fix

- Key undecided values by a hash the node computes itself: `block_hash(header)` **and** a body commitment (or the hash of the whole encoded value). Better: store a proposal only after it validates, and never let a later copy replace an entry whose validation succeeded.
- In `decide`, check `block_hash(header) == value.hash` and `validate_body(block)` before committing, and prefer the body whose execution is in `pending`.
- Drop `FullProposal`s whose `proposer` is not `select_proposer(h, r)`. The field is unauthenticated, so this alone is not enough; sign proposal parts (`sign_proposal_part` exists) or bind the full value to the signed `Proposal`.
- Put `aggregate_certificates` under a commitment (header field) or leave it out of the stored block until R2 defines its verification.
