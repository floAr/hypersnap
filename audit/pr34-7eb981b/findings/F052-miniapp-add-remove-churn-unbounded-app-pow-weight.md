---
finding_id: F052
title: The per-epoch miniapp-add counter goes up on every `MINIAPP_ADD` and never goes down on `MINIAPP_REMOVE`, and nothing caps it per epoch
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F052
  kind: build-backed
  result: 5/5
related_findings:
- F053
- F054
---
# F052 — The per-epoch miniapp-add counter goes up on every `MINIAPP_ADD` and never goes down on `MINIAPP_REMOVE`, and nothing caps it per epoch. One FID can alternate add and remove of the same miniapp, all free, and each add counts 5.0 × its credibility toward the miniapp owner's App-PoW work. One account (or a small set of them) can capture almost all of the AppUsage pool, which is 30% of each epoch's emission.

> **Status (2026-11-04):** Severity **High** (validated 0.85, HAS_CAVEATS). PoC: poc/F052 (build-backed, 5/5). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity High (validated 0.85). PoC: poc/F052 (5/5; 200 churned adds take 64.5% of the AppUsage pool; control d shows byte-identical replays are accepted, see F076).


- **Severity:** High, source-only. This is direct mis-allocation of minted tokens, about 2M tokens per epoch at launch (30% of `E0 ≈ 6.85M`), every epoch. No consensus split: every node computes the same, wrong, result. It is not Critical because the pool is bounded and nothing outside it can be drained.
- **Confidence:** 0.85. The path is short and complete in source. Not built. The only open question is how many such messages a hostile sender can get into shard-0 blocks per epoch, and even a small share is enough (see the arithmetic below).
- **Category:** eligibility-bypass / reward-claim inflation (App PoW)
- **Specialist:** chain-economics · task H027
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard0/miniapp.rs`, `src/chain/scoring.rs` and `crates/proof-of-quality/**` do not exist at merge-base `bdef7b7`.

## Code facts

1. **`add` increments the per-epoch counter on every add.** `src/chain/shard0/miniapp.rs:195-223`:
   ```rust
   let key = add_key(fid, &id);
   if txn.exists(&key)? { return Err(invalid("the FID already added the miniapp")); }
   if txn.scan(&adds_of(fid))?.len() >= MAX_ADDS_PER_FID { ... }
   txn.put_proto(key, &MiniappAddState { .. });
   state.add_count += 1;
   ...
   txn.add_u64(adds_by_epoch_key(ctx.epoch, state.author_fid, fid), 1)?;
   ```
   The only per-user guards are "not currently added" and "≤ 100 apps currently added" (`MAX_ADDS_PER_FID`, `miniapp.rs:21`). Neither one is per epoch.
2. **`remove` clears the add marker but leaves the epoch counter alone.** `miniapp.rs:226-244` deletes `add_key(fid, id)` and decrements `state.add_count`. It never touches `adds_by_epoch_key`. After a remove, the "already added" guard passes again.
3. **The scoring reader takes the counter as is.** `miniapp_add_events_for_epoch` reads `[79][epoch][owner][user] → count` and returns `count` (`src/chain/scoring.rs:218-233`).
4. **App work is linear in that count and has no cap.** `accumulate_app_work` adds `fp_mul(count · weight_fp, cred(user))` per `(app, user)` (`crates/proof-of-quality/src/app_pow.rs:44-73`). Adds use `app_pow_add_weight_fp = 5_000_000` (5.0, `lib.rs:350`). `compute_app_pow_rewards` sums receipts and adds, then splits the budget pro rata (`app_pow.rs:136-152`). `MAX_APP_REWARD_PER_EPOCH` defaults to 0, so there is no limit (`lib.rs:351`).
5. **The messages are free and nothing limits them by FID.** `MINIAPP_ADD` and `MINIAPP_REMOVE` are shard-0 Hypersnap types (`src/chain/shard0/engine.rs:568-573`). The fee gate `charge_fee` runs only on data-shard merges (`src/storage/store/engine.rs:2707-2716`). In any case, `base_fee` is 0 for every type other than the five snapchain add types (`src/chain/replica.rs:192-198`). The only shard-0 throughput limit is `max_messages_per_block = 12_000` per block (`shard0/engine.rs:163, 831`). Signer roles allowed: `AppSigner | AccountKey` (`miniapp.rs:78-80`).
6. **There is no self-dealing filter.** `add` doesn't compare `fid` with `state.author_fid`, so the owner can add its own app. Neither the user nor the owner is gated by the §8.3 eligibility flags in App PoW (`app_pow.rs` reads only `credibility_weight_fp`).

## Attack path

1. The attacker owns FID `O` and registers miniapp `D` (needs an EIP-712 account association for a domain the attacker controls, `miniapp.rs:110-124`).
2. From one FID `U` with credibility `c` (`U = O` is allowed; any FID has `c ≥ 0.10`, see F053), the attacker sends `MINIAPP_ADD(D)`, `MINIAPP_REMOVE(D)` repeatedly during epoch `e`, with a new timestamp each time so every message has its own hash.
3. After `k` cycles, `adds_by_epoch_key(e, O, U) = k`, and `app_work(O) ≥ 5 · k · c`.
4. For comparison, the most an honest `(app, user)` pair can contribute is one add (5.0) plus 100 receipts at 0.5 (50.0), times `c ≤ 1.0`, so at most 55. At only one add/remove pair per shard-0 block, `k = 36_000` per epoch. With `c = 1.0` that is 180,000, the work of about 3,300 honest users at the maximum. With `c = 0.10` it is still about 330 honest users at the maximum. Shard-0 blocks hold up to 12,000 messages, so `k` can be much larger. `U` can also use several apps, and the attacker can use several `U`s.
5. At `boundary(e+1) + SCORING_DELAY`, the `ScoringResult` pays `O` almost all of `pools(e).app`. Every validator computes the same numbers, so the block is valid.

## Red-team

1. *Does `remove` maybe decrement the epoch counter elsewhere?* No. The only writers of `adds_by_epoch_key` are `add` (`miniapp.rs:222`) and the key function (`miniapp.rs:51`). A grep finds no other.
2. *Does the reader dedupe per `(owner, user)` to 0/1?* No. It returns the raw count (fact 3), and `accumulate_app_work` multiplies by it.
3. *Is there a per-epoch add rate limit like `MAX_RECEIPTS_PER_APP_PER_EPOCH`?* Not for adds. The receipt cap is in `work.rs:174-186` and covers receipts only.
4. *Do fees or storage stop the churn?* No. Shard-0 Hypersnap messages pay no fee (fact 5). The `enable_rate_limits` mempool path is off by default. Block space is the only limit.
5. *Is the spec OK with counting re-adds?* No. FIP §7.2 weights "Miniapp add (Miniapp Index FIP)" at 5.0 as a verifiable record of real usage, and §7.5 adds a per-user rate limit to stop click farms. A re-add of the same app by the same user in the same epoch is not new usage.
6. *Does credibility weighting save it?* Partly. A zero-trust sender gets 0.10 (F053), not 0. Any established account (`c ≈ 0.6–1.0`) gets full effect.
7. *Could a later epoch undo it?* No. `apply_scoring_result` mints and credits once (`src/chain/shard0/boundary.rs`). There is no clawback.
8. *Already filed?* No. F047 is the data-shard fee gate order, F049 is DA. No finding covers App PoW.

## Fix

- Count at most one add per `(epoch, owner, user, miniapp)`. For example, set `adds_by_epoch_key` to 1 with `put` instead of `add_u64`, keyed by miniapp id. Or count only an add whose `MiniappAddState` didn't exist at the epoch boundary.
- Better: derive the add signal at scoring time from the boundary state (active `add_key` records whose `added_at_timestamp` falls in the epoch) instead of from an event counter.
- Add a per-epoch cap for adds like the receipt cap. Consider excluding `user == owner` from App PoW.
- Regression test: add/remove/add in one epoch gives a count of 1.

## Files

- `src/chain/shard0/miniapp.rs:21, 51-64, 78-80, 195-244`
- `src/chain/scoring.rs:218-233`
- `crates/proof-of-quality/src/app_pow.rs:44-73, 136-152`
- `crates/proof-of-quality/src/lib.rs:349-351`
- `src/chain/shard0/engine.rs:163, 568-573, 831`
- `src/chain/replica.rs:192-198`, `src/storage/store/engine.rs:2707-2716`
