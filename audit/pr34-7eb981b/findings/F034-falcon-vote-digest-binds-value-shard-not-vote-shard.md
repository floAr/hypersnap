---
finding_id: F034
title: A Falcon-512 vote signs `vote_digest(type, value.shard_index, height.block_number, round, hash)`
severity: medium
status: pending-validation
related_findings:
- F002
---
# F034 — A Falcon-512 vote signs `vote_digest(type, value.shard_index, height.block_number, round, hash)`. The shard in the digest comes from the *value* (`ShardHash.shard_index`), not from the vote's `height.shard_index`, and nothing checks that the two are equal. All three shards are signed by the same epoch set with the same keys. So any peer can take a validator's prevote or precommit for a value on shard A at `(h, r)` and re-publish it as a vote of the same validator on shard B at `(h, r)` for value `ShardHash{A, X}`. It verifies there. Malachite keeps the first vote per validator, round and type, and drops a later conflicting vote as equivocation. Replayed votes delivered first therefore discard the honest round-r votes on shard B, and the round cannot reach a quorum on B's real proposal.

- **Severity:** Medium. Liveness only, and safety holds (see red-team 5). Any network peer can do it with no keys. It works wherever two shards' height ranges overlap after the pivot: the shard behind in height can be replayed from the shard ahead, at every height and permanently. Each attacked height loses round 0 (prevote and precommit timeouts, `FIP` table: 3 s + 3 s) before round 1 decides, so block time on that shard grows several-fold. On shard 0 this slows the bridge, governance and epoch processing as well. Confidence about 0.7. How far heights overlap, and how much the epoch set changes over the lag, depend on the live snapchain heights at the pivot.
- **Category:** missing domain separation / signature replay (cross-shard)
- **Specialist:** consensus-malachite-tendermint · attack class: read-validator-protocol-version (Ed25519→Falcon switch) · task H020
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). New in this PR. Ed25519 votes sign `vote.to_sign_bytes()`, the protobuf that includes `height.shard_index`, so this did not happen before the pivot.
- **Trigger:** gossip `consensus/<shard>` topic. Routing is by the vote's own `height.shard_index` (`gossip.rs:1850-1873`).
- **PoC:** None (source-only). Unit-test sketch: with `falcon_validator`, sign `Vote::new_precommit(Height::new(1, 42), Round(0), Val(ShardHash{1, H}), addr)`. Then call `provider.verify_signed_vote(&Vote::new_precommit(Height::new(2, 42), Round(0), Val(ShardHash{1, H}), addr), &sig, &pk)`. It returns `true`.

## Code facts

1. **The digest takes the shard from the value.** In `vote_sign_bytes` (`core/types.rs:137-155`), the Falcon branch reads `(shard, hash) = match vote.shard_hash { Val(v) => (v.shard_index, Some(v.hash)), Nil => (vote.height.shard_index, None) }` and then calls `vote_digest(precommit, shard, vote.height.block_number, round, hash)` (`consensus_keys.rs:30-52`). `vote.height.shard_index` is not in the signed bytes for a value vote.
2. **Verification uses the same function.** `verify_signed_vote` (`types.rs:169-187`) and `verify_commit_signature` (`types.rs:268-299`, which rebuilds the vote from `certificate.value_id`) both go through `vote_sign_bytes`. Neither checks `shard_hash.shard_index == height.shard_index`. A repo-wide grep finds no such check (`grep shard_index … ==|!=`). The only shard checks are on proposals (`validator.rs` `add_proposed_value`) and on read nodes.
3. **One key set for all shards.** `EpochSet::validator_set(shard_id)` builds every shard's set from the same `keys` (`chain/validator_sets.rs:91-106`). Addresses (`keccak(pk)`) and keys are the same on shards 0, 1 and 2.
4. **First vote wins in Malachite.** `PerRound::add` returns `ConflictingVote` when a vote from that address and type already exists with a different value. `VoteKeeper::apply_vote` then records evidence and returns `None`, so the later vote is never counted (`malachite core-votekeeper/src/keeper.rs:84-96, 219-228`). Votes for a higher height are verified and queued (`core-consensus/src/handle/vote.rs:37-73`), so a replayed vote can be in place before shard B even starts height h.
5. **Hypersnap evidence is unused.** No code reads the Malachite evidence (`grep -i evidence|equivoc` in `src/` → none in consensus). The honest validators are not punished, but nothing detects the attack either.

## Attack

1. Shards A and B are both post-pivot, and A is ahead in height (snapchain's three shards have independent height counters that grow at similar rates). The attacker records A's gossip votes: prevotes and precommits at `(A, h, 0)` for `ShardHash{A, X_h}`.
2. As B nears height h, the attacker publishes each recorded vote re-wrapped as `Vote{height: (B, h), round: 0, value: Val(ShardHash{A, X_h}), voter, type}` with the original signature, on `consensus/B`. Each verifies (fact 1) against B's set for h. That set is identical to A's set at h if the lag stays inside one epoch (36,000 shard-0 heights), and largely overlapping if it does not.
3. On every B node, the replayed votes are counted first. The real prevotes and precommits of those validators for B's proposal Y are dropped as conflicting (fact 4). That includes the node's own vote when it is applied locally. If the replayed weight is greater than 1/3, Y cannot reach 2/3 in round 0. If it is at least 2/3, B even sees a polka and precommit quorum for an unknown value `{A, X_h}`. That cannot decide (see red-team 5), so round 0 ends on timeouts.
4. Round 1 at h is replayable only if A also used round 1 at h, which is rare. B decides in round 1, and the attacker repeats this at every height.

## Red-team (invalidation hypotheses walked)

1. *Does gossip or Malachite drop a vote whose value shard differs from its height shard?* No. Gossip routes by `height.shard_index`. Malachite treats `ValueId` as opaque, and the host never inspects votes.
2. *Do shard heights ever overlap after the pivot?* Shards keep their snapchain heights (shard 0 from `PIVOT_HEIGHT_0`, shards 1/2 from `H_s`) and all advance at about one block per round. Any lagging shard passes heights that a leading shard has already signed after the pivot. The size of the lag only affects set churn (the replay needs > 1/3 weight of members common to both sets).
3. *Are the Nil votes affected?* No. Nil votes use `height.shard_index` (fact 1). Only value votes are replayable, and those are the votes that matter.
4. *Are proposals replayable?* No. Proposals sign `proposal.to_sign_bytes()`, whose protobuf includes `height` with the shard. So the attacker cannot supply a proposal for `{A, X}` on B.
5. *Safety?* B cannot commit A's block. Deciding needs the value. Sync-supplied values go through `check_structure`/`validate_header`, which rejects `header.shard_id != B` (`block.rs:183-190`). The certificate path for synced blocks also binds `cert.shard_id` (`shard_blocks.rs:505-508`, `shard0/engine.rs:1052-1056`). The bridge digest `d` is computed from `cert.shard_id` and the header, which is consistent. So the impact is liveness only.
6. *Is this the same as F002 (no network binding in `d`)?* No. F002 is cross-network replay that needs key reuse. This is cross-shard replay inside one network with no precondition on operators.
7. *Is it covered by the F029 proposer-order issue?* No. This is unrelated to proposer selection.
8. *Spec?* FIP §16.5 defines `d` with "u32 shard" but does not say which shard. Taking the vote's shard is the only reading that gives domain separation. Not filed as spec-divergence.

## Recommendations

- In `vote_sign_bytes`, use `vote.height.shard_index` for the digest's shard in both arms. In `verify_signed_vote` and `verify_commit_signature`, also reject any vote or certificate whose `shard_hash.shard_index != height.shard_index`, so that the precommit digest still equals the certificate digest `d` (`certificate::precommit_sign_bytes` uses `cert.shard_id`).
- Optionally include `epoch` in the vote digest, so that a replay across an epoch with the same members fails too. This needs a matching change to the bridge `d`.
- Add a test: a vote signed for shard 1 must fail verification when presented as a vote on shard 2 at the same height and round.
