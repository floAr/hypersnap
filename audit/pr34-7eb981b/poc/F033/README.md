# F033 PoC: read-node `Commits` not bound to the decided value

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/consensus/f033_poc_test.rs`, wired as `#[cfg(test)] mod f033_poc_test;` at the end of `src/consensus/mod.rs`. A copy is here as `f033_poc_test.rs`.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f033_poc_test -- --nocapture --test-threads=1`
- The incremental build plus test run took about 40 s.
- Output: `F033-test-output.txt`.

## Fixture

- Reuses the exact harness shape of `src/consensus/read_validator_test.rs`: a real `ReadValidator` wrapping a real `ShardEngine` (RocksDB temp dirs), a single genuine proposer validator in the set (quorum = 1), `last_height = 0`, `pivot_guard = None`, Devnet.
- A genuine decided value is produced the production way: `commit_event(default_storage_event)` on a proposer engine, then `sign_chunk(proposer_keypair, chunk)` — a real Ed25519 precommit over `ShardHash { hash: chunk.hash }` at the chunk height. So `commits.value.hash == chunk.hash == blake3(header)`.
- The PoC drives the **real** `ReadValidator::process_decided_value` end to end (signature check -> `validate_block_hash_matches_header` (the F012 fix) -> `validate_protocol_version` -> engine commit), not a narrowed helper.

## The forgery

`forge_different_value` takes a genuine chunk and changes a header field that is **not** part of the state replay (`parent_hash`), then re-derives `hash = blake3(header)`. The genuine `commits` are left untouched, so:

- `verify_signatures` passes — the quorum genuinely signed `commits.value.hash` (the OLD hash) at that height.
- `validate_block_hash_matches_header` passes — `forged.hash == blake3(forged.header)` (attacker controls the header).
- Nothing compares `commits.value.hash` with `forged.hash`. They differ. The replay reproduces the unchanged `shard_root`, so the engine commits the forged value.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `f033_forged_value_with_genuine_foreign_commits_is_committed` | A chunk whose own `hash` differs from the hash the quorum signed, but which carries that genuine quorum certificate, is **committed** (`process_decided_value` returns 1, `last_height` advances to 1). Also asserts `forged.hash != signed_hash`. | **RED** (pass, claim reproduced) |
| `f033_control_genuine_value_accepted` | A correctly bound genuine value (`hash == commits.value.hash == blake3(header)`) is committed (returns 1). | pass (control) |
| `f033_control_below_quorum_rejected` | The same forged value but with `signatures` stripped (0 of 1, below quorum) is rejected (returns 0, no commit). | pass (control) |
| `f033_version_exit_is_reachable_on_forged_block` | The real `validate_protocol_version` on a forged `Block` with a bad `header.version` returns false and emits `SystemMessage::ExitWithError`. | pass (secondary) |

**All 4 tests pass, and the core claim reproduces:** one decided value whose `Commits` is a genuine quorum certificate for a *different* value hash is accepted and committed by the read path.

## What was and was not exercised

- Exercised with real code: the full `process_decided_value` path on a real `ShardEngine`, including the in-diff F012 `validate_block_hash_matches_header`. The forged value is committed, confirming the missing `commits.value.hash <-> value.hash` (and `commits.height <-> header.height`) binding.
- Secondary / partial: the "one gossip message exits every pre-pivot node" kill switch (impact (a)) is demonstrated only at its real exit function, `validate_protocol_version` (bad version -> `ExitWithError`). Reaching that through the full `process_decided_value` needs a **shard-0 `BlockEngine`** fixture, because a `Block` sent to this `ShardEngine` is dropped by `matches_engine` before the version check. The end-to-end gossip wiring (`gossip.rs` -> `main.rs` -> `dispatch_decided_value` -> `ReadHost`) is source-only.
- Not exercised: the sync (`read_sync` `ValueResponse`) ingress channel, and the genesis-poisoning / pivot-guard consequences (source-reasoned in the finding and validation note).

## Caveats

- Equal-weight, count-based quorum (quorum = 1 here) matches the current `verify_signatures`, which ignores voting power.
- The forged value in the PoC differs from the signed value only in `parent_hash` so the body still replays cleanly and commits (demonstrating self-consistent forgery, finding fact 4). A forgery that also changes trie state would instead panic at the next genuine chunk (validation note, hypothesis 2) — a per-node DoS rather than a silent divergence.
