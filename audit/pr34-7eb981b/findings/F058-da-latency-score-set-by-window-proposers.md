---
finding_id: F058
title: A validator's DA latency score is the height of the block that includes its response, which the shard-0 proposers choose, not the time the
severity: low
status: pending-validation
related_findings:
- F021
- F049
- F056
- F057
---
# F058 — A validator's DA latency score is the height of the block that includes its response, which the shard-0 proposers choose, not the time the validator answered. The proposer of each of the first blocks of the 25-block window can leave other validators' responses out, at no cost and with no trace, while including its own. Each block of delay costs every victim 4 percentage points of `latency_factor`, and the code applies it at full weight to the DA pool. A coalition placed at the start of the window (by chance, or by F057 seed bias) shifts DA reward from honest validators to itself in every epoch.

- **Severity:** Low, source-only. The shift is bounded: 4% of each victim's DA score per attacker-held opening block, with at most 25 blocks. It needs attacker proposers at the window start. It is inert while F049 keeps the DA pool at 0. Raise it to Medium if F049 is fixed and the validator set is small or the attacker holds a large share.
- **Confidence:** 0.7. Scoring and proposer discretion come straight from source. The mempool ordering in honest proposals (own responses first) was not checked.
- **Category:** Economic / reward manipulation by proposer censorship
- **Specialist:** chain-economics · task H029
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **Mostly PR-introduced.** FIP §5.4 has a latency factor, but at `DA_LATENCY_WEIGHT = 0.3` alongside an uptime factor. The code multiplies the full latency factor into the score (`da_pow.rs`, new in this PR; see F049 "Related" / F056). That makes the proposer's choice weigh about 3× more than the spec intends.
- **PoC:** None, reasoned from source. Test sketch in `engine_test`: in the window of epoch `e`, have the proposer of `boundary(e)+1` and `+2` filter out validator V's `DaChallengeResponse` messages. Score epoch `e` and compare V's `da_score_fp` with the no-filter run: `avg_offset` goes up by 2, so the score falls by 0.08 × `answered_ratio`.

## Code facts

1. **The scored height is the inclusion height.** `da_response` stores `da_answered(epoch, key, index) = ctx.height`, the height of the block that carries the response (`src/chain/shard0/work.rs:138`). Scoring sums those heights (`src/chain/scoring.rs:262-275`). `da_score = answered_ratio × (1 − avg_offset / 25)`, where `avg_offset` is the mean of `height − boundary` (`crates/proof-of-quality/src/da_pow.rs:37-53`). Rewards are shared out in proportion (`da_pow.rs:60-80`).
2. **The earliest any response can land is `boundary + 1`.** The responder needs `epoch_seed(e)`, which is written by the boundary block, and the validator's checkpoint, which comes from the boundary state or later (`src/chain/da_responder.rs:62-101`, `src/chain/shard0/boundary.rs:30-31`). So every validator starts at offset ≥ 1. The opening blocks decide everything after that.
3. **The proposer chooses what goes in.** In `Mode::Propose` the engine packs mempool messages in order, up to `room` / `max_messages_per_block` (`src/chain/shard0/engine.rs:745-760`, `:829-850`). Nothing requires a proposer to include a valid pending DA response, and validators do not check for omissions.
4. **The honest retry is slow compared with the window.** `RESEND_AFTER = 5` blocks (`da_responder.rs:26`, `:88-91`). A response that the gossiping mempools still hold can be picked up by the next honest proposer. A dropped one waits 5 blocks, which is 20% of the window.
5. **Load makes it worse.** Each validator sends 100 responses (`shard0/mod.rs:147`), and each carries a trie proof, the leaf value and a Falcon signature. With `n` validators that is `100n` messages, within a 16 MiB / 12,000-message block (`src/chain/block.rs:11`, `engine.rs:163-164`). For n ≳ 100 the opening blocks cannot carry everyone, so the proposers' ordering decides who gets offset 1 and who gets 3 or 4, even with no malice.

## Attack path

1. The attacker's validators hold the proposer slots for `boundary(e)+1 … +j`. This happens by rotation (probability about `(k/n)^j`), or deliberately through F057 by choosing `epoch_seed(e)` among `2^k` candidates.
2. Each of those blocks includes the attacker's own 100 responses per validator and leaves out every other validator's responses. The blocks are still valid.
3. Honest responses land at offset ≥ `j + 1`, or later if they were dropped and resent. Each victim loses `0.04·j` of latency factor. The attacker keeps offset 1 to `j`.
4. With proportional allocation, the attacker's share of the 50% DA pool rises in each epoch where it holds the opening slots.

Example: `n = 50`, an attacker holding the first 3 window slots. Honest latency goes from 0.96 to 0.84 at best. The attacker's 3 validators score 0.96 and gain about 12-14% relative share, every such epoch.

## Red-team

1. *Is proposer censorship in scope at all?* Yes. The FIP intends latency to measure validators, not proposers. Here a valid-but-selective block quietly moves reward, and nobody can prove it happened.
2. *Do honest proposers fix it?* They include responses from the next honest block on. The loss is the attacker-held prefix, plus resend delays when a response was dropped.
3. *Can the victim respond faster?* No. The victim already sends right after the boundary commits. Inclusion is out of its hands.
4. *Is it moot because of F049?* Today, yes, because the DA pool is 0. The finding holds once F049 is fixed, and that fix is expected.
5. *Is it the same as F021?* No. F021 is about validity depending on the local checkpoint, which rejects the whole block. This is about valid omission.
6. *Is this spec-mandated?* The spec has the latency term but weights it at 0.3. The code's weight of 1.0 and its 100 challenges (vs 10 in FIP §15) are code choices (F049/F056 roll-up).

## Fix

- Measure latency from data the proposer cannot shape. For example, credit any response included by `boundary + W` as on time (pass/fail), or score the response's signed `timestamp` within bounds. Or apply the FIP's 0.3 weight.
- Or require the proposers of window blocks to include every valid pending DA response that fits, and let validators check that the response mempool was drained (hard). A softer option is to cap the extra credit for offset 1 vs offset `j` at a negligible amount.
- Reduce `da_challenges_per_epoch` to the FIP's 10 so the window's load fits in one block.

## Files

- `src/chain/shard0/work.rs:94-138`
- `src/chain/da_responder.rs:26`, `:62-101`
- `crates/proof-of-quality/src/da_pow.rs:1-80`
- `src/chain/scoring.rs:252-275`
- `src/chain/shard0/engine.rs:745-760`, `:829-850`
