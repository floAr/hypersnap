---
finding_id: F053
title: App PoW weighs each user by the full §8.4 credibility scalar, not by the FIP §7.1 `w_user = trust × age_factor`
severity: medium
status: pending-validation
related_findings:
- F052
- F056
---
# F053 — App PoW weighs each user by the full §8.4 credibility scalar, not by the FIP §7.1 `w_user = trust × age_factor`. That scalar includes a `client_diversity` term hard-coded to 1.0 for every FID. A just-created FID with zero trust and zero age therefore has weight 0.10, not ≈ 0. With free reactions it can reach 0.30. Cheap sybils (a 30-bit hashcash native onboarding, no fees on receipts) earn App-PoW work for a colluding app at 10-30% of a perfect real user's rate.

- **Severity:** Medium, source-only. Systematic leakage of the AppUsage pool (30% of emission) to sybil-driven apps. The FIP §7.6 risk table calls "self-usage" sybils High and gives "credibility weights give minimal work to sybil accounts with low trust" as the mitigation. In the code that mitigation is a 3-10× discount, not a gate. It is not High on its own, because it needs many sybils (F052 needs none).
- **Confidence:** 0.8. The source facts are certain. The cost per sybil (hashcash time, signer setup) is estimated, not measured.
- **Category:** sybil-amplification / eligibility-bypass (App PoW weight)
- **Specialist:** chain-economics · task H027
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (all files new since `bdef7b7`).
- **PoC:** None, reasoned from source and not built. Unit sketch: `compute_credibility_weight_fp(0, 0, 0, 0) == 100_000` is already asserted by the crate's own test (`metrics.rs:398`). Then `accumulate_app_work` with `counts = {(app, sybil): 100}` and `metrics[sybil].credibility_weight_fp = 100_000` gives a work of 5.0 (100 receipts × 0.5 × 0.10). That is 10% of a real user with credibility 1.0.

## Code facts

1. **`client_diversity` is a constant 1.0.** `CLIENT_DIVERSITY_FP: u64 = FP_ONE` "the constant 1.0 for each FID" (`crates/proof-of-quality/src/metrics.rs:141-142`), added with weight 0.10 in `compute_credibility_weight_fp` (`metrics.rs:175-190`). The crate's test asserts the floor: `compute_credibility_weight_fp(0, 0, 0, 0) == 100_000` (`metrics.rs:398`). FIP §8.4 defines `client_diversity = min(1.0, log2(distinct app-FIDs))`, which is 0 for an FID with 0 or 1 app.
2. **App PoW uses that credibility.** `accumulate_app_work` takes `metrics[user].credibility_weight_fp`, and skips a user only when it is 0 (`app_pow.rs:57-63`). It never reads `trust_fp`, the age factor or the eligibility flags. FIP §7.1: "`w_user` is the credibility of the user (Proof of Quality trust score × FID age factor)".
3. **Two more terms are cheap for a sybil.** `interaction_entropy` is the normalized entropy of the FID's outbound engagement (`metrics.rs:283-292`). Two reactions to two different FIDs give `H = 1.0`, so +0.20. Reactions are free after the pivot (F054), and stores no longer prune (`src/storage/store/engine.rs:472`). `stake_factor` counts vouch stake *received* (`metrics.rs:250-280`). A vouch of 7.4 tokens (`STAKE_MATURITY_AMOUNT`) gives +0.10, and the tokens are only locked, not spent.
4. **Every registered FID is in the universe, native ones included.** `registered_fids` includes every `HyperFidCustody` record (`src/chain/scoring.rs:124-155`). Native onboarding writes one (`src/chain/shard0/onboarding.rs:337-360`). Its gate is a hashcash of `min_difficulty_bits = 30` (`shard0/mod.rs:154`), about 10^9 SHA-256 calls, seconds on a GPU. A stake gate also exists.
5. **Receipts are free and capped per user, not per sybil set.** `app_receipt` needs only `Role::AppSigner`, the current epoch and an active miniapp. It allows 100 receipts per `(epoch, owner, user)` (`src/chain/shard0/work.rs:152-189`). Receipts carry no fee (F052 fact 5).

## Attack path

1. The attacker registers miniapp `D` as owner `O`.
2. They onboard `N` native FIDs (30-bit hashcash each), add a Falcon app signer to each, and send two reactions from each to different FIDs (for `interaction_entropy = 1`).
3. Each epoch, each sybil signs 100 `APP_USAGE_RECEIPT`s for `D` (and one `MINIAPP_ADD`; see F052 for unbounded adds).
4. Per sybil, app work is `100 · 0.5 · 0.30 + 5 · 0.30 = 16.5`. A perfect honest user scores 55. So `N = 1,000` sybils equal about 300 maximal real users, or a lot more ordinary ones (typical honest users don't send 100 receipts per app per epoch).
5. The App pool is split pro rata, and `O` takes a share that grows linearly with `N`.

## Red-team

1. *Is the 0.10 floor intended?* The crate documents it as a constant (fact 1), but it contradicts both §8.4 (`log2` of distinct apps) and §7.1 (`trust × age`). The Growth market is protected by `CREDITER_TRUST_FLOOR`. App PoW has no such floor.
2. *Do sybils fail some other gate first?* App PoW doesn't read eligibility (fact 2), and the owner isn't gated either.
3. *Is a sybil really this cheap?* Native onboarding needs no on-chain fee (fact 4). Legacy Optimism FIDs cost a registration fee, so they are more costly. The signer add and the receipts are shard-0 messages with no fee.
4. *Does the receipt cap help?* It caps each sybil at 100 per app, so the attacker scales with `N` instead. FIP §7.6 says the cap "prevents click farms" only for one user.
5. *Doesn't the age factor eventually catch this?* Age adds weight; it never removes it. A sybil at age 0 already has 0.10-0.30.
6. *Severity inflation?* No funds outside the pool move, and the FIP itself admits collusion with high-trust accounts is undetectable. The finding is that *zero-trust* accounts are not near zero. That is why it is Medium.
7. *Already filed?* No. F046 is about the node-local signer index (an F0 input). This finding is about the App-PoW weight.
8. *Is `client_diversity = 1.0` a defensible substitute?* It could be a placeholder, because the protocol has no app-FID signal for native signers. But the effect on App PoW is not documented.

## Fix

- Use the §7.1 weight `trust_fp × age_factor` in `accumulate_app_work`. Or keep credibility and require `trust_fp ≥ CREDITER_TRUST_FLOOR_FP`, like Growth does.
- Implement `client_diversity` as specified, or set its weight to 0 until a signal exists, so that a zero-signal FID has credibility 0.
- Consider requiring `eligibility.passes_all()` (or at least F1/F2) for receipt users, and excluding `user == owner`.

## Files

- `crates/proof-of-quality/src/metrics.rs:135-190, 250-292, 398`
- `crates/proof-of-quality/src/app_pow.rs:44-73`
- `src/chain/shard0/work.rs:152-189`
- `src/chain/scoring.rs:124-155`
- `src/chain/shard0/onboarding.rs:337-360`, `src/chain/shard0/mod.rs:154`
