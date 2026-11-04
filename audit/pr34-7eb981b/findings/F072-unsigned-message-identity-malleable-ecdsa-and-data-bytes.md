---
finding_id: F072
title: FID-0 (`SIGNATURE_SCHEME_NONE`) messages are malleable by third parties
severity: info
status: pending-validation
related_findings:
- F070
---
# F072 — FID-0 (`SIGNATURE_SCHEME_NONE`) messages are malleable by third parties. Their body ECDSA signature is accepted with a high `s` and with any `v` byte except 0 and 27 meaning parity 1. OpenZeppelin accepts only low `s` with `v` ∈ {27, 28}. The authorisation is also checked over a canonical re-encoding of `data`, while the message hash is over the raw `data_bytes`. So anyone can produce many byte-different, valid copies of an escrow claim, escrow bridge or onboarding, each with a different message hash. No double execution follows, because state nonces and indices dedupe. What breaks is the message hash as a stable identifier.

- **Severity:** Info/Low, source-only. Replay is blocked by state: escrow nonce (`ledger.rs:484-491`), custody index (`onboarding.rs:333-335`) and rotation nonce (`:394-398`). The mempool dedupes by a semantic key while a message is pending (`precheck.rs:20-74`). The impact is that a client tracking its submitted escrow claim or onboarding by hash may never see that hash merged. Event and API consumers see a hash the user never produced. A mutated copy with a different hash also wins the mempool slot (the F070 race mechanism, with no change in effect).
- **Confidence:** 0.85. The ECDSA behaviour was checked against `alloy-primitives-1.7.3` (`Signature::recover_from_prehash_k256` calls `normalized_s()`, `sig.rs:376-387`). The `data_bytes` behaviour is from source. Not built.
- **Category:** low-s-ecdsa-divergence / signature malleability / non-canonical encoding
- **Specialist:** rust-crypto-primitives · task H053
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `crates/hypersnap-messages`, `src/chain/shard0/{auth,onboarding,ledger,precheck}.rs` are new since `bdef7b7`.
- **PoC:** None. Unit-test sketch in `crates/hypersnap-messages/src/eip712.rs` tests: take `sig = eip712_sign(..)`. Set `s' = n − s` and flip `v` (27↔28). Also try `v = 0x02` on a parity-1 signature. `recover_eip712` returns the same address for all three. For `data_bytes`, append the unknown field `0xF8 0x3F 0x00` (field 1023, varint 0) to an escrow claim's `data_bytes` and recompute `hash`. `auth::open` and `fid0_dedupe_key` accept it with the same dedupe key.

## Code facts

1. **The `v` byte is mapped loosely.** `recover_eip712`: `parity = v != 0x1b && v != 0x00` (`crates/hypersnap-messages/src/eip712.rs:94-95`). `onboarding::recover` does the same (`src/chain/shard0/onboarding.rs:205-206`). Bytes 2..=26 and 29..=255 all mean parity 1. `account_association.rs:194-199` is strict ({0,1,27,28}).
2. **High-s is accepted.** `Signature::recover_address_from_prehash` normalises `s` and flips parity before recovery (alloy-primitives 1.7.3 `sig.rs:376-387`). So `(r, n−s, ¬v)` recovers the same address. No caller checks `s ≤ n/2`.
3. **Hash vs payload.** `auth::open` hashes the raw `data_bytes` (`auth.rs:138-142`). Second signatures are over `second_signature_payload` = `data.clone()` with the signature fields cleared, re-encoded canonically (`crates/hypersnap-messages/src/second.rs:18-24`). prost drops unknown fields and accepts non-canonical encodings, so many `data_bytes` decode to the same `data`. For `SIGNATURE_SCHEME_NONE` nothing signs the raw bytes (`auth.rs:162-168`).
4. **Who is affected.** Every FID-0 type: `TOKEN_ESCROW_CLAIM`, `TOKEN_ESCROW_BRIDGE`, `NATIVE_ONBOARD`, and `NATIVE_CUSTODY_ROTATION` (unreachable via the mempool per F065). Ed25519-signed messages are not malleable this way, because Ed25519 (`verify_strict`, `auth.rs:224`) signs `hash` = BLAKE3(raw `data_bytes`).
5. **Cross-side.** The node never forwards these ECDSA signatures to the bridge contract. `HypersnapBridge.sol` (V1) uses OZ `ECDSA.recover`, which rejects high-s and `v ∉ {27,28}`. The ceremony signer (`crates/hypersnap-bridge-ceremony/src/main.rs:464-467`) emits k256 low-s with `v_byte()` = 27/28, which OZ accepts. Its `recover` sub-command (`:518-521`) normalises `s`, so it would report "ok" for a high-s MPC signature that OZ then rejects. That is an operator-tooling nit with no on-chain consequence.

## Red-team

1. *Can a malleated copy execute twice?* No. Every FID-0 effect bumps a nonce or writes an index (see Severity).
2. *Can it make the honest copy fail permanently?* No. Both copies have the same effect and only one executes. The honest user's intent is fulfilled under a different hash.
3. *Does the shard-0 chain keep a hash-keyed index?* No hash-based dedupe was found under `src/chain/` (grep `message.hash`). `message_already_exists` returns false for shard-0 types (`mempool.rs:449-480`).
4. *Is this the upstream snapchain behaviour?* Snapchain's `KEY_ADD` custody EIP-712 path (`src/core/validations/key.rs:186-230`) is inherited and was not re-audited here.

## Fix

- Reject `s > n/2` and `v ∉ {27, 28}` (optionally {0, 1}) in `recover_eip712` and `onboarding::recover`, the same rule as OZ. Use a single shared helper.
- For FID-0 messages, require `data_bytes == data.encode_to_vec()` (canonical encoding) in `auth::open`, or define the message id as the hash of the canonical re-encoding.
- In the ceremony `recover` command, reject high-s, so it matches the contract.

## Files

- `crates/hypersnap-messages/src/eip712.rs:84-98`; `src/chain/shard0/onboarding.rs:201-209`
- `src/chain/shard0/auth.rs:106-168`; `crates/hypersnap-messages/src/second.rs:18-24`
- `src/chain/shard0/precheck.rs:20-74`; `src/chain/shard0/ledger.rs:438-491`
- `crates/hypersnap-bridge-ceremony/src/main.rs:464-467, 507-531`; `contracts/src/HypersnapBridge.sol:7, 194`
