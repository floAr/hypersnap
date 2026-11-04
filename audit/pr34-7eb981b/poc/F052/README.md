# F052 PoC: miniapp add/remove churn gives unbounded App-PoW weight

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`). Recipe: the internal validation notes, "Exact minimal build-backed PoC recipe".

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`, `CARGO_TARGET_DIR=<build-tree>/target`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/shard0/f052_poc_test.rs`, wired as `#[cfg(test)] mod f052_poc_test;` at the end of `src/chain/shard0/mod.rs`. A copy is here as `f052_poc_test.rs`.
- Run script: a local helper (not included) that copies the test in, wires the module and runs cargo.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f052_poc_test -- --nocapture --test-threads=1`
- Incremental build 1 min 59 s, test run 16 s.
- Output: `F052-test-output.txt`.

## Fixture

- The real shard-0 `Net` harness from `src/chain/shard0/test_support.rs` via `funded_net()`: 3 nodes on one genesis, FID 1000 migrated to Falcon custody, FID 2000 registered. Every block is proposed on node 0, validated on nodes 1-2 and committed on all three, and the state roots must agree.
- The registration block of `engine_test::miniapp_register_add_and_receipt`, copied verbatim: FID 1000 registers `example.com` with its custody Falcon key and the JFS account-association proof signed by its custody address.
- The churn: for `i in 0..k`, a `MiniappAdd { domain: "example.com" }` at `block_time - 1000 + 2i` and a `MiniappRemove` at `block_time - 1000 + 2i + 1`, all signed by FID 1000's custody Falcon key (`Role::AccountKey`). FID 1000 adds its own app. The timestamps are distinct and backdated, so every message has a distinct hash.
- Scoring: the production `HypersnapReader::new(node 0 db, {}, params(), default set)` for the reader input, and the PoQ `app_pow::compute_app_pow_rewards` with `ScoringParams::default()` for the share, using `FidMetrics` built as in the `app_pow.rs` tests (`make_metrics`).

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `f052_churn_200_pairs_one_block_counter_200` (headline) | 200 add/remove pairs (400 messages) in one block at height 104 (epoch 1): all 400 are included and validated on nodes 1-2. `adds_by_epoch_key(1, 1000, 1000) = 200`, while `MiniappState.add_count = 0` (the registry shows no change). `HypersnapReader::miniapp_add_events_for_epoch(1) = {(1000, 1000): 200}`. | **RED** (pass, claim reproduced) |
| `f052_scoring_share_vs_max_honest_pair` (scoring) | Attacker: owner 1000, user 1000 at the 0.10 credibility floor. Honest: owner 2000, user 2001 at credibility 1.0 with 1 add and 100 receipts (the per-pair maximum, work 55). Budget 1,000,000. `k = 200` gives owner 1000 **645,162 (64.5%)**. `k = 2,000` gives **947,868 (94.8%)**. Control: with the honest count `k = 1` (the most the registry state can show), owner 1000 gets 9,009 (0.9%). | **RED** (pass) |
| `f052_control_double_add_rejected` (control a) | Two adds without a remove in one block: 1 of 2 included. A further add is rejected with `Invalid("the FID already added the miniapp")`. The counter is 1. The only guard is "not currently added", which a remove resets. | pass (control) |
| `f052_control_receipts_capped_at_100` (control b) | FID 2000 gets an on-chain Ed25519 signer (the `signature_acceptance_matrix` setup), so it signs as `Role::AppSigner`. 101 `AppUsageReceipt`s for `example.com` in one epoch-1 block: 100 accepted (`MAX_RECEIPTS_PER_APP_PER_EPOCH`). Receipts have a per-epoch cap and adds do not. | pass (control, asymmetry shown) |
| `f052_control_replay_and_epoch_isolation` (controls c, d) | After the 200-pair block, the **byte-identical** `add_0` and `remove_0` (hash `5ded32ef…`) are re-submitted in a later epoch-1 block: both are accepted and the counter goes to 201. Then the chain runs past `boundary(2)` and one add lands in `adds_by_epoch_key(2, …) = 1`, while epoch 1 stays at 201. | pass (control c); **RED** for the replay follow-up (d) |

**All 5 tests pass.** The core claim reproduces: one FID with one registered miniapp inflates its own App-PoW add counter by 1 per add/remove pair, honest validators include and validate the churn, the registry state does not show it, and the counter feeds App-PoW linearly. The share control shows the same user with an honest count earns under 1%.

## What was and was not exercised

- Exercised with real code: `Shard0Engine` propose / validate / commit of `MiniappRegister`, `MiniappAdd`, `MiniappRemove` and `AppUsageReceipt` (`miniapp::add` / `remove`, `work::app_usage_receipt` cap, `auth::open` / `resolve` for `AccountKey` and Ed25519 `AppSigner`), the `[79]` counter, `HypersnapReader::miniapp_add_events_for_epoch`, `simulate_messages`, and PoQ `compute_app_pow_rewards` (`accumulate_app_work`, `allocate_app_pow_budget`).
- Source-only:
  - The full `scoring::compute` -> `evaluate_epoch` path over the harness DB was not driven, because the harness FIDs have no social data and hence no real credibility. The share uses `compute_app_pow_rewards` directly with synthetic credibility (0.10 floor, 1.0 honest), as the recipe specifies. The reader output that `evaluate_epoch` feeds into it is asserted from the real DB.
  - The honest-mempool layer (the `mempool_key` dedupe, `enable_rate_limits: false` by default, the mempool ordering) was not exercised. The test builds the proposal directly, so it shows what consensus accepts, not how many messages an honest mempool forwards per FID. The realistic per-epoch `k` (about 6,000 with rate limits on, far more by default) is from source.
  - The 12,000-messages-per-block cap and the 16 MiB block limit were not hit (400 messages per block here).
  - The honest App-PoW baseline on mainnet is unknown. The 64.5% / 94.8% figures are against one maximum-intensity honest pair.

## Caveats

- Magnitude depends on inclusion. Consensus allows any number of pairs up to block space. The test shows 200 pairs in one block and byte-identical replay, so neither a per-epoch nor a per-hash bound exists.
- The replay result (control d) confirms the validation note's follow-up: shard-0 user messages have no replay protection, so a third party could re-submit a victim's signed add/remove pair. That is a separate follow-up, not part of this finding's severity.
- No split: all three nodes agree on every block. The harm is the App-PoW pool share, minted and not clawed back.
