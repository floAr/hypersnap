# F018 PoC: oversized message admitted, then rejected by `validate_body`

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/f018_poc_test.rs`, wired as `#[cfg(test)] mod f018_poc_test;` in `src/chain/mod.rs`. A copy is here as `f018_poc_test.rs`.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f018_poc_test -- --nocapture --test-threads=1`
- The incremental build plus test run took about 35 s.
- Output: `F018-test-output.txt`.

## What is exercised

The PoC runs two **real** functions against the same message:

- Admission: `crate::chain::shard0::auth::open` (the stateless check the gRPC / HTTP submit path and the mempool simulate path go through). It bounds only `data_bytes.len() <= MAX_MESSAGE_BYTES` and places **no** bound on the encoded `Message` or on `message.signature`.
- Validation: `crate::chain::block::validate_body`, which rejects any block containing a message whose `encoded_len() > MAX_MESSAGE_BYTES` (`MessageTooLarge`). Blocks are built with the real `block::seal` (correct `hash` and `messages_root`).

The proposer's own size gate is `PULL_BYTES` (~15 MiB) with no per-message 1 MiB cap; the PoC asserts each oversized message sits in the gap `MAX_MESSAGE_BYTES < encoded_len <= PULL_BYTES`, i.e. the proposer would include it while the validator rejects the block. Driving the full `Shard0Engine::propose` is **not** done (it needs a populated shard-0 state: custody records, signer, fee balance); that hop is source-backed by the finding.

## Recipe note

The finding's original "2 x 550 KiB unknown-field padding" construction does **not** work: `message_bytes_decode` sets `data` from the prost decode of `data_bytes`, and prost drops unknown fields, so the duplicate never materializes. The PoC uses the two working routes the validator identified.

## Tests and results

| Test | Route | What it asserts | Result |
|---|---|---|---|
| `f018_route_a_data_bytes_padding` | (a) `data_bytes` padded with a well-formed unknown field to 1048560 B (just under the 1 MiB limit) | `auth::open` **accepts** it; `encoded_len` = 1048761 > `MAX_MESSAGE_BYTES` and <= `PULL_BYTES`; `validate_body` returns `MessageTooLarge(1048761)`. | **RED** (pass) |
| `f018_route_b_signature_extension_padding` | (b) `Ed25519Falcon512` signature whose `HyperSignatureExtension.falcon_signature` is ~1.2 MiB (genuine Ed25519 sig over the hash) | `auth::open` **accepts** it (data_bytes = 9 B); `encoded_len` = 1200179 > `MAX_MESSAGE_BYTES` and <= `PULL_BYTES`; `validate_body` returns `MessageTooLarge(1200179)`. | **RED** (pass) |
| `f018_control_normal_message_validates` | normal | A 208-byte dual-signed message is accepted by `auth::open`, and a sealed block carrying it **passes** `validate_body` (`Ok`). | pass (control) |

**All 3 tests pass.** Both admission routes produce a message that `auth::open` accepts and `validate_body` then rejects for size — the two size checks disagree.

## What was and was not exercised

- Exercised with real code: `auth::open` admission and `validate_body` rejection of the same message, by both routes; the proposer/validator size-rule gap against the real `MAX_MESSAGE_BYTES` and `PULL_BYTES` constants; and that a normal message produces a block that validates.
- Not exercised (source-backed): the end-to-end submit ingress (`HubService::submit_message` / HTTP `/v1/submitMessage`), the mempool `insert`/`pull_messages`, and `Shard0Engine::propose` / `execute(Mode::Propose)` building the block. These need a populated shard-0 engine state; the finding establishes that none of them applies a per-message `encoded_len` cap.
- Not exercised: the liveness consequence (one copy per proposer round stalls shard 0). That is a deployment/timing claim, covered in the finding and validation note.

## Caveats

- `admitted()` means `auth::open` returns `Ok` (stateless checks). It does not include the stateful role/key resolution and Falcon verification that run later; those are irrelevant to the size divergence, which is fully decided by `data_bytes.len()` vs `encoded_len()`.
- Reachability depends on the validator exposing its submit endpoint. The code default binds gRPC to `127.0.0.1` with `submit_address` disabled, but `docker-compose.mainnet.yml` binds `0.0.0.0:3383` (validation note).
