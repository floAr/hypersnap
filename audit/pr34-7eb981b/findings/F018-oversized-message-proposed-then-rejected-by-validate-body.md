---
finding_id: F018
title: The shard-0 proposer has no per-message size limit, but `validate_body` rejects any message over `MAX_MESSAGE_BYTES`
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.8
poc:
  path: poc/F018
  kind: build-backed
  result: 3/3
related_findings:
- F019
- F020
- F030
---
# F018 — The shard-0 proposer has no per-message size limit, but `validate_body` rejects any message over `MAX_MESSAGE_BYTES`. One oversized message, submitted for free to a validator's submit endpoint, makes that validator's next proposal invalid on every other node.

> **Status (2026-11-04):** Severity **High** (validated 0.8, HAS_CAVEATS). PoC: [poc/F018](../poc/F018/) (build-backed, 3/3). State: validated.

> **Status 2026-11-04 (post-validation):** Severity High (validated). **The 2 × 550 KiB unknown-field recipe in the steps below is wrong** (prost drops unknown fields). Working routes, both build-backed in [poc/F018](../poc/F018/) (3/3): (a) `data_bytes` padded with a well-formed unknown field to 1,048,560 B, encoded 1,048,761 B, giving `MessageTooLarge`; (b) an `Ed25519Falcon512` signature extension padded to about 1.2 MiB (`auth::open` never bounds `message.signature`).


- **Severity:** High (shard-0 liveness). An unprivileged user with any FID that can sign one valid shard-0 message can do it. It costs nothing, because the message is never committed and so never pays a fee or uses a nonce, and the same message can be submitted again. One message kills one proposal round of the targeted validator. Keeping one message in every validator's mempool fails every round, which halts shard 0 for as long as the attack runs. **Downgrade to Medium** if validators do not expose the gRPC `SubmitMessage` or the `submit_address` endpoint to untrusted clients. Gossip alone cannot deliver such a message (see "Trust assumptions").
- **Category:** proposer-validator-divergence / consensus-liveness (resource limit enforced on one side only)
- **Specialist:** shard0-ledger-state · attack class: proposer-validator-divergence · task H016
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## The two limits

| Check | Where | What it bounds |
|---|---|---|
| `auth::open` | `src/chain/shard0/auth.rs:32-41, 128-130` | `data_bytes.len() <= MAX_MESSAGE_BYTES` (1 MiB) for Hypersnap types. It does not bound the encoded `Message`. If `data_bytes` is present, `message.data` is ignored (`:111-125`). |
| `Shard0Engine::execute`, `Mode::Propose` | `src/chain/shard0/engine.rs:827-850` | Only `field_len(m.encoded_len()) <= room`, where `room` is about 16 MiB minus system messages. **No per-message limit.** |
| `validate_body` (from `check_structure`, which runs first in `validate` and on synced values) | `src/chain/block.rs:155-165`, `engine.rs:1000, 1038` | `m.encoded_len() <= MAX_MESSAGE_BYTES` for **every** message in the block. The whole block is rejected otherwise. |

So the proposer includes any message that executes, at any size up to the block room. A validator rejects the whole block if one message's encoding is over 1 MiB. The two limits measure different things: `data_bytes` against the encoded `Message`.

## Building a message that passes `auth::open` and fails `validate_body`

1. Take any shard-0 message the attacker can validly sign, for example a 1-micro-unit `TokenTransfer` from an FID it controls. Append one unknown protobuf field of about 550 KiB to `data_bytes`. prost ignores unknown fields on decode, so `auth::open`, the hash (over `data_bytes`) and the signature all pass, and the handler sees the normal body.
2. Submit it through gRPC `SubmitMessage`, which has no auth by default (`rpc_extensions.rs:161-163`, `allowed_users` empty) and tonic's default 4 MiB decode limit (no `max_decoding_message_size` is set in `servers.rs:433-441`). Or submit it through the Hypersnap `POST /v1/submitMessage` endpoint (`hypersnap_main.rs:594-605`), which reads the body with no size limit at all.
3. `message_bytes_decode` (`storage/store/account/message.rs:378-386`) sets `data` = decoded `data_bytes` without the unknown field. In the mempool, `compact_message` (`block.rs:18-30`, called at `mempool.rs:1074-1077`) keeps both fields, because the re-encoding differs from `data_bytes`. The stored message is now about 2 × 550 KiB, which is over 1 MiB. The canonical route also works: `data_bytes` within ~130 bytes of 1 MiB passes `auth::open`, and the signature, hash and signer push the encoded message over the limit.
4. `simulate_shard0` → `Shard0Engine::simulate_messages` accepts it, because it runs only `apply_message`. The message enters the validator's shard-0 mempool.
5. At that validator's next proposer turn, `pull_messages` pops it (`mempool.rs:845-880`). `execute(Mode::Propose)` applies it successfully and puts it in the block.
6. Every other validator runs `check_value` → `validate` → `check_structure` → `validate_body` → `MessageTooLarge` → `Validity::Invalid` (`shard0/proposer.rs:72-88`). The round gets no polka and times out.

The message was popped at pull time and is not re-inserted when the round fails. The honest messages pulled into the same proposal are lost from that node's mempool too, although they are still in other nodes' mempools through gossip. The attacker simply submits again. The message was never committed, so its nonce, balance and fee are unchanged, and `message_is_valid` checks only merged state for duplicates.

## Trust assumptions

- **The validator's submit path is reachable.** Gossip cannot deliver the message: `mempool_add` drops any `MempoolMessage` over `MAX_MEMPOOL_MESSAGE_BYTES` = 256 KiB (`network/gossip.rs:58, 1722-1730`). Peers drop the RPC node's re-gossip of the message for the same reason. So the attacker has to reach each targeted validator's own gRPC or submit endpoint. Both are open by default.
- The attacker controls an FID with a key that can sign one shard-0 message that executes. `NATIVE_ONBOARD` would also work: its PoW is paid once, because the onboarding is never committed.

## Red-team walk

1. *Does the proposer check `validate_body` on its own block?* No. `propose` calls `seal` only (`engine.rs:983`). `propose_value` does not self-check (`shard0/proposer.rs:189-211`).
2. *Does the mempool or the RPC bound the message size?* The RPC and submit paths do not. The snapchain `validate_message` size checks are skipped on Hypersnap nodes (`mempool.rs:1066-1073`, `server.rs:1138-1143` use `simulate_hypersnap`). Only gossip has a 256 KiB cap.
3. *Is `data_bytes` ≤ 1 MiB the same as the message ≤ 1 MiB?* No. See the table. The extra bytes are the `data` duplicate (non-canonical form) or the signature, hash and signer (canonical form).
4. *Would Malachite re-propose the bad value in later rounds?* Only with a POL, which it cannot get. The next proposer builds its own block.
5. *Can the validators that reject it be wrong?* No. Rejection is the same on every honest node. This is a liveness issue only, with no fork.
6. *Cost to attacker?* None per round beyond bandwidth. Nothing commits.
7. *Is this F015 again?* No. F015 is about the views of the inbound-burn watcher. Here the cause is a size rule enforced only on the validating side.
8. *Rate limits?* The gRPC interceptor rate-limits per peer, and one message per proposer turn per validator (~12 s) is far below any plausible limit.

## Recommendation

- In `execute(Mode::Propose)`, skip a message with `m.encoded_len() > MAX_MESSAGE_BYTES`, and treat it as invalid in `simulate_messages`, so that propose and validate use one rule. Better: define a single `message_fits(m)` predicate used by `auth::open`, `simulate_messages`, `execute` and `validate_body`.
- In `auth::open`, bound the encoded `Message`, not only `data_bytes`. Reject a message that has both `data` and `data_bytes` unless they are the same bytes, or always strip `data` when `data_bytes` is present, before the size check and before the message goes into the mempool.
- Put a body limit on the `submit_address` HTTP endpoint and an explicit `max_decoding_message_size` on the gRPC server (≤ `MAX_MESSAGE_BYTES` plus envelope).

## Evidence

- `src/chain/shard0/engine.rs:827-850` (no per-message cap in propose), `:1000, 1038` (check_structure → validate_body)
- `src/chain/block.rs:11-12, 18-30, 155-165`
- `src/chain/shard0/auth.rs:32-41, 106-130`
- `src/mempool/mempool.rs:845-880, 1066-1077`
- `src/network/gossip.rs:58, 1722-1730`; `src/network/server.rs:1582-1600, 826-860`; `src/network/rpc_extensions.rs:157-163`; `src/node/servers.rs:433-441`; `src/node/hypersnap_main.rs:548-625`
- `src/storage/store/account/message.rs:378-386`
