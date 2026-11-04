---
finding_id: F057
title: The commit-reveal seed beacon lets every committed validator choose, after seeing all honest reveals, whether to reveal
severity: low
status: pending-validation
related_findings:
- F029
- F049
- F024
- F058
---
# F057 — The commit-reveal seed beacon lets every committed validator choose, after seeing all honest reveals, whether to reveal. The only cost of withholding is the forfeit of that validator's DA reward for one epoch. That is zero for a validator that does not earn DA rewards, and zero for everyone while F049 stands. A coalition of `k` validators picks `epoch_seed(t)` from up to `2^k` candidates about 35,700 blocks before the window closes. The seed fixes the epoch's proposer order and every DA challenge. FIP §18 item 6 presents the beacon as the fix that "can remove" seed grinding. In fact the beacon swaps one grinder (the last-block proposer in v1) for a cheap `k`-bit bias held by any committed coalition.

- **Severity:** Low, source-only. What the seed controls is limited: the proposer rotation (each member still proposes about 1/n of heights) and the DA challenge targets. The main concrete use is placing attacker validators on chosen heights, such as the first DA-window blocks (F058). That turns a small rotation advantage into a repeatable one. It is not a direct theft.
- **Confidence:** 0.8 for the mechanism (straight from source). The value of the bias is estimated, not measured.
- **Category:** Randomness / seed grinding (commit-reveal last-revealer bias)
- **Specialist:** pivot-genesis-epoch · task H051
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** The beacon (`src/chain/shard0/seed.rs`, `src/chain/seed_responder.rs`) is new code and is not in the in-repo FIP. FIP §4.9 defines only the v1 seed, and §18 item 6 lists the beacon as future work.
- **PoC:** None, reasoned from source. Test sketch on `engine_test` (the beacon test at `shard0/engine_test.rs:~2368` already drives commits and reveals). Use two validators A and B that commit for epoch 3. A reveals early. Compute `seed_with = keccak("…-v2"||3||sA||sB)` and `seed_without = keccak("…-v2"||3||sA)` before `boundary(3) − margin`. Show that B's choice picks the stored seed and that the only state difference is `SEED_FORFEIT(2, B)`.

## Code facts

1. **The seed is a hash of the reveals that are present.** At the boundary of `e ≥ 3`, `seed = keccak256("hypersnap-epoch-seed-v2" || e || reveals…)`. The reveals are those in state, in node-key-hash order. Withholding just drops one term (`src/chain/shard0/seed.rs:127-137`).
2. **Honest reveals are public very early.** `SeedResponder::after_block` sends the reveal for `t = epoch + 1` from the first block of epoch `t − 1`, as soon as `next + margin < boundary(t)` and the commit exists (`src/chain/seed_responder.rs:103-137`). The window stays open until `boundary(t) − SEED_REVEAL_MARGIN` (`seed.rs:98`), which is 36,000 − 300 = 35,700 blocks on mainnet (`src/chain/shard0/mod.rs:165`, `src/chain/epoch.rs:6`). An attacker who waits to the last allowed height knows every honest secret, so it can compute the seed for each subset of its own reveals.
3. **Withholding costs one epoch's DA reward and nothing else.** On a commit without a reveal, `on_boundary` writes `SEED_FORFEIT(e − 1, member)` (`seed.rs:141-149`). The only reader is `HypersnapReader::da_fid`. It drops that validator's DA answers of epoch `e − 1` from scoring (`src/chain/scoring.rs:93-103`, `:252-275`). The forfeit does not touch set membership, `consecutive_missed`, growth or app rewards, or any stake. Nothing else in the tree reads `SEED_FORFEIT` (grep).
4. **The forfeit is often worth zero.**
   - (a) F049: on mainnet every DA score is 0, so there is no DA reward to forfeit.
   - (b) Even with F049 fixed, a validator that does not answer DA challenges, or answers them badly, loses nothing.
   - (c) The attacker pays only when it actually withholds, after it has seen the outcome.
5. **What the seed decides.**
   - `order(e)`, the members sorted by `keccak256(seed || consensus_key_hash)`, with proposer `order[(h + r + shard) mod n]` (`src/chain/validator_sets.rs:107-125`, `src/core/types.rs:419-435`, `:672-680`).
   - `da_seed(e)`, and through it every validator's 100 challenge targets (`src/chain/shard0/work.rs:19-55`).
6. **`k` is not bounded by anything small.** Each member of `set(t − 1)` holding a commit is one free bit. F024 records that validator inflow is unbounded, gated only by age ≥ 90 days and trust ≥ 0.05.

## Attack path

1. The attacker controls `k` members of `set(t − 1)` and commits for each in epoch `t − 2`, like an honest node would.
2. In epoch `t − 1` the honest validators reveal in the first blocks. The attacker waits.
3. At height `boundary(t) − SEED_REVEAL_MARGIN − 1`, the attacker evaluates up to `2^k` seeds, one per subset of its reveals. It picks the one that best serves its goal, for example:
   - its validators propose `boundary(t) + 1 … + j`, the opening blocks of the DA window (F058);
   - its validator proposes `H_last(t)` or other heights of interest;
   - the challenge targets of its own validators land on data it stores.
4. It submits only the chosen subset. The withheld members lose their epoch `t − 1` DA reward, which is 0 under F049.

Rough value: the chance that one attacker validator gets a given slot is `1 − (1 − k/n)^(2^k)`. For `n = 50`, `k = 10` that is about 1. Getting the first `j` window slots all attacker-held needs about `(n/k)^j` draws, so `j ≈ 4` with 1,024 draws.

## Red-team

1. *Is this just the known RANDAO weakness?* Yes, and that is the point. The beacon's design note claims the seed is "fixed before the last block" (`seed.rs:6-7`), and FIP §18 says a beacon "can remove" grinding. The bias remains, and the deterrent the code chose (a DA forfeit) can be worth zero.
2. *Is v2 worse than v1?* No. v1 lets one proposer grind block contents with unbounded tries. v2 caps the bias at `k` bits once one honest reveal exists. Hence Low and not higher.
3. *Can the attacker dodge even the forfeit?* It does not need to. The forfeit is already worth nothing in cases (a) and (b) above.
4. *Can honest reveals be censored to raise the attacker's control?* Not realistically: there are about 35,700 rotating proposers and a resend every 5 blocks (`seed_responder.rs:155-160`).
5. *Does controlling the order matter if every member still proposes 1/n of heights?* Only for position-sensitive heights. F058 shows the DA window is one, and it pays.
6. *Already filed?* F029 is about which seed (v1 or v2) is used for proposer selection, not about bias. F049 is the DA pool bug that zeroes the forfeit. The roots are distinct, so link them.

## Fix

- Make withholding costly and independent of DA earnings. For example, a non-reveal marks the validator for removal from `set(t + 1)`, or counts like `auto_deregister_threshold` misses, or forfeits all rewards of the epoch.
- Or remove the last-revealer choice: use a threshold or VRF beacon, or mix in a value that becomes known only after the reveal window closes (with its own grinding point documented).
- Document the residual `k`-bit bias in FIP §4.9 / §18 next to the beacon spec.

## Files

- `src/chain/shard0/seed.rs:85-164`
- `src/chain/seed_responder.rs:24-30`, `:103-137`
- `src/chain/scoring.rs:93-103`, `:252-275`
- `src/chain/validator_sets.rs:107-125`, `src/core/types.rs:419-435`, `src/chain/shard0/work.rs:19-55`
- `src/chain/shard0/mod.rs:147-165`
