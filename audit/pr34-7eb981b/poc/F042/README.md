# F042 PoC: data-less messages panic the data-shard replay sort

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/storage/store/f042_poc_test.rs`, wired as `#[cfg(test)] mod f042_poc_test;` in `src/storage/store/mod.rs`. A copy is here as `f042_poc_test.rs`.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f042_poc_test -- --nocapture --test-threads=1`
- Incremental build plus test run ~45 s.
- Output: `F042-test-output.txt`.

## The bug

`replay_snapchain_txn` sorts a transaction's user messages before any per-message validation. On equal priority the comparator is
`then_with(|| a.data.as_ref().unwrap().timestamp.cmp(&b.data.as_ref().unwrap().timestamp))` (`engine.rs:2347-2353`), which unwraps `data`. Two messages with `data = None` at equal priority (priority 5) panic with `called `Option::unwrap()` on a `None` value`. The `NoMessageData` rejection is only in `validate_user_message`, which runs **after** the sort.

## Fixtures

- Test A: `test_helper::new_engine()` (snapchain-mode `ShardEngine`). The panic is caught with `std::panic::catch_unwind` (default panic hook temporarily silenced) around `validate_state_change`.
- Test B: a minimal shard-1 Hypersnap proposer, identical in shape to `poc/F022`'s `shard1_proposer` (`HypersnapShardProposer` over a real `ShardEngine` in Hypersnap mode, fixture Falcon validator set via `test_validators(4, 1)`, genesis parent). An honest empty block for the next height is produced with `propose_value`; `craft_data_less` swaps its transactions for one holding two `Message::default()` and reseals.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `validate_state_change_panics_on_two_data_less_messages` (Test A) | `validate_state_change` on a transaction with two `Message::default()` panics; the payload is `called `Option::unwrap()` on a `None` value`. | **RED** (pass, panic reproduced) |
| `control_single_data_less_message_does_not_panic` (control i) | One data-less message: no panic; `validate_state_change` returns `false` (rejected). | pass (control) |
| `control_two_messages_with_data_do_not_panic` (control ii) | Two `CastAdd`s (both `data = Some`) at equal priority: no panic (the comparator unwraps two `Some`s). | pass (control) |
| `control_priority_split_does_not_panic` (control iii) | One `UserDataAdd(Username)` (priority 3) + one data-less message (priority 5): no panic (the timestamp `then_with` is never evaluated). Pins the trigger to an equal-priority pair. | pass (control) |
| `entry_point::check_value_panics_on_data_less_transaction` (Test B) | A crafted `HypersnapBlock` that passes `validate_body` is executed by the production `HypersnapShardProposer::check_value(&fp, false)` and **panics** with the unwrap message. The proposal is stored in the undecided set **before** the panic (`get_proposed_value` returns it). | **RED** (pass, reproduced on the production entry point) |
| `entry_point::check_value_synced_returns_valid_without_executing` (Test B control) | The same crafted block with `synced = true` (structure checks only, no execution) returns `Validity::Valid`. Shows every pre-execution gate passes and only the execution path panics. | pass (control) |

**All 6 tests pass.** The panic reproduces both at the engine entry point (`validate_state_change`) and at the production proposer entry point (`check_value`), after only structural checks and before any per-message, proposer or root check.

## What was and was not exercised

- Exercised with real code: `validate_state_change` → `replay_proposal` → `replay_snapchain_txn` (the sort), and the full `HypersnapShardProposer::check_value` → `producer.validate` → `hypersnap_validate` → `replay_proposal` path. Test B also confirms the crafted proposal is stored before the panic and that the structure-only (`synced = true`) path is clean.
- Not exercised (Test C, optional, **source-only**): that the panic stops the shard's Malachite Host actor (ractor 0.14.7 `catch_unwind` → `ActorErr::Failed`, unsupervised `Host` actor stops, node process survives). This needs the actor harness (`MalachiteConsensusActors::create_and_start`) and only settles the panic-containment caveat; the validation note traces it in source. The network-wide reach (gossip forwarding of the crafted `FullProposal`, F022/F023) is likewise source-only.

## Caveats

- Test B uses the empty-mempool `shard1_proposer` (genesis parent, no parent certificate needed), which is sufficient because the panic happens during execution of the crafted body, before any root comparison. `state_root` is left at the honest block's value and is never reached.
- The sort is inherited from snapchain v0.15 and is **fixed upstream** at `f66b47c` (`engine.rs:1589-1594`, panic-free comparator). Hypersnap's copy predates the fix. The severity above Medium rests on the PR's open proposer set and unauthenticated proposal execution (F022/F023/F024), which are separate findings.
