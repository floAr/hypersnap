---
finding_id: F023
title: Every `FullProposal` for heights `next` and `next+1` from any peer is kept in memory and in RocksDB, with no count or byte limit
severity: medium
status: pending-validation
related_findings:
- F022
---
# F023 — Every `FullProposal` for heights `next` and `next+1` from any peer is kept in memory and in RocksDB, with no count or byte limit. Each one for height `next` that passes the structural checks is also fully executed and replaces the node's cached execution.

- **Severity:** Medium (resource DoS: RAM and disk on every node, bounded by the attacker's bandwidth multiplied by gossip fan-out; CPU through forced full executions). The attacker is any gossip peer, with no key. It is not High because the retention is bounded in time while the chain progresses (≈ 2 block times) and the attacker pays bandwidth. It gets worse while a shard is stalled (see "Retention").
- **Category:** propose-value-misuse / resource exhaustion (unauthenticated proposal ingestion)
- **Specialist:** consensus-malachite-tendermint · attack class: propose-value-misuse · task H013
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** None. This is reasoned from source.

## Code facts

1. **Ingress.** Gossip accepts a `FullProposal` of up to `HYPERSNAP_MAX_VALUE_BYTES` = 17 MiB (`src/network/gossip.rs:80-82, 1792-1805`) from any peer, checks height presence, `round ≥ 0` and shard, and forwards it to consensus. Gossipsub forwards it to its mesh before the application looks at it (no `validate_messages`), and the default message id (source + seqno) means each publish is new. No proposer or signature check exists (F022, fact 3).
2. **Store.** `check_value` only requires `header.height == FullProposal.height ∈ {next, next+1}` and then calls `UndecidedValues::add` (`src/chain/proposer.rs:99-111`, `src/chain/shard0/proposer.rs:47-56`). The key is `[height][declared hash]`, and the attacker picks the hash freely, so every message is a new row and a new in-memory `FullProposal` clone (`src/chain/undecided.rs:58-64`; `ProposedValues::add_proposed_value` also appends to a per-height `Vec` without dedupe, `src/consensus/proposer.rs:75-87`).
3. **Pruning.** Only `UndecidedValues::decide(h)` deletes rows with height ≤ h (`undecided.rs:101-125`). There is no cap and no eviction by count or size.
4. **Execution.** For height `next`, a proposal that passes `check_structure` is executed in full (`Shard0Engine::validate`, `engine.rs:993-1026`; `ShardBlockProducer::validate` → `hypersnap_validate`, `shard_blocks.rs:436-466`). The header carries no proposer, so anyone running a node can build a structurally valid, executable block for height `next` (copy the public parent certificate, fill messages, compute the roots). A valid one also replaces `pending` / `pending_txn`, so the honest decided block misses the cache and is executed a second time at commit (shard 0 `Mode::Commit`, data shards replay).

## Sizing

- Per message: ≤ 17 MiB kept twice (RAM clone plus RocksDB value) on **every** node that the gossip mesh reaches, for one attacker publish.
- Retention: rows for `next` live until that height is decided (~12 s); rows for `next+1` live about one block longer. At an attacker upload of 100 MB/s, that is about 2.4 GB of RAM and disk per node, held until the next decision. RocksDB reclaims space only after compaction of the tombstones.
- **Retention while stalled.** If a shard does not decide (F019 ScoringResult stall, F022 halt, a lost quorum), nothing is pruned, and the attacker's rows grow without limit for as long as the stall lasts. After a restart, `UndecidedValues::get` falls back to a full prefix scan comparing every key suffix (`undecided.rs:68-98`), and a decision that needs the DB has to walk all of the junk.
- CPU: each crafted, structurally valid block for `next` costs one full execution per node, and the attacker can send them without limit.

## Red-team walk

1. *Does Malachite bound values per round?* It keeps its own `FullProposalKeeper` entries, but Hypersnap's store is separate and written before Malachite sees the value.
2. *Does gossipsub rate-limit?* No peer scoring is configured in the builder (`gossip.rs:632-660`).
3. *Is the `next+1` window needed?* No. `next` alone allows the attack; `next+1` only extends retention.
4. *Is this generic gossip spam?* The flood itself is generic. What is specific here is that the node keeps each message (RAM plus disk, keyed by an attacker-chosen hash) and executes it, instead of dropping it when the sender is not the round's proposer.

## Fix

- Before storing or validating, drop a proposal whose `(height, round)` proposer, as given by `select_proposer`, is not the sender. Bind this with a signature on the proposal part, because `FullProposal.proposer` is not authenticated.
- Keep at most one value per `(height, round, proposer)`. Store it only after it validates (for `next+1`, buffer at most one per round in memory).
- Add a byte cap on `UndecidedValues`, and prune by round as well as by height.
