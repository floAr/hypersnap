---
id: F104
task: H104
attack_class: signing-payload-or-dst-collision
severity: low
status: draft
---

# F104 — `FeeDepositBody` Ed25519 signing payload omits `chain_id`, replayable across hypersnap deployments / shards (F101-class variant)

- **Task:** H104
- **Attack class:** `signing-payload-or-dst-collision` (chain_id-binding variant — F101 antipattern in a sibling user-signed payload)
- **Severity (provisional):** Low. Not exploitable to steal balance — the cross-chain replay only moves the victim's atoms from their **primary** balance into their own **fee-balance ledger** on the same FID, on a non-targeted chain. Realised damage is grief / nuisance: a captured `FeeDepositBody` on chain A re-applies on any other hypersnap deployment / shard B where the victim FID has (a) a positive primary balance and (b) the per-FID `HyperTokenNonce` happens to equal `body.nonce - 1`. The user did not authorize topping up fees on chain B; the runtime applies it anyway. The same gap exists in `token_transfer.rs::DST` (`-v1`) and `token_lock.rs::DST` (`-v1`), but H104's scope is `fee_deposit.rs`; the broader v1-DST family is the same defect class.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/fee_deposit.rs:42-52` — `fee_deposit_signing_payload`; canonical bytes omit `chain_id`.
- `code/hypersnap/src/hyper/mod.rs:106-111` — documented protocol-wide invariant **"Embedded in every Ed25519-signed canonical payload (v2 DSTs) so a message signed for chain A cannot replay on chain B"**. fee_deposit uses a `-v1` DST and is the sibling case that did NOT receive the v2 chain_id upgrade.
- `code/hypersnap/src/hyper/runtime.rs:681-707` — `apply_fee_deposit` does NOT pass `protocol_chain_id` to the validator (contrast with `validate_token_stake(body, self.protocol_chain_id)` at `runtime.rs:1618`).
- `code/hypersnap/proto/definitions/hyper.proto:1089-1097` — `FeeDepositBody` has no `chain_id` field.

## Summary

`fee_deposit_signing_payload` (`fee_deposit.rs:42-52`) concatenates:

```
DST  "hypersnap-fee-deposit-v1\x00\x00\x00\x00"   28 B
sender_fid       (BE u64)                          8 B
amount           (BE u64)                          8 B
nonce            (BE u64)                          8 B
signer_pubkey_len (BE u16) + signer_pubkey        2 + 32 B
                                                  ──────
                                                  86 B
```

There is no `chain_id` byte. The protocol-wide invariant at `hyper/mod.rs:106-111` (verbatim: "Embedded in every Ed25519-signed canonical payload (v2 DSTs)…") is satisfied by the v2-DST family — `token_stake.rs::STAKE_DST`/`UNSTAKE_DST`, `miniapp.rs::{ADD,UPDATE,REMOVE,UNREGISTER}_DST`, `node_attestation.rs::{ATTEST,REVOKE}_DST`, `app_usage_receipt.rs::RECEIPT_DST`, `da_pow.rs::DA_RESPONSE_DST`. All v2-DST validators take `chain_id: u64` as a parameter and prepend it to the signed bytes (e.g. `token_stake.rs:64,68 -> chain_id.to_be_bytes()`; cross-checked via `runtime.rs` call sites that pass `self.protocol_chain_id`).

`fee_deposit` is `-v1`. `validate_fee_deposit` takes no `chain_id` argument (`fee_deposit.rs:54`). `apply_fee_deposit` does not plumb `self.protocol_chain_id` to it (`runtime.rs:685`). The same gap is present in the other `-v1` user-signed payloads (`token_transfer.rs`, `token_lock.rs`) and is the direct sibling of the F101 antipattern in `account_association.rs`.

## What this signing payload DOES bind (other H104 checks closed)

| Lever | Bound? | Where |
|---|---|---|
| DST collision (stake / transfer / lock / miniapp / etc.) | yes — distinct DSTs, no prefix overlap | grep over `hypersnap-*` DST literals; fee_deposit diverges from every sibling at byte 10 (`f`) |
| Per-FID nonce binding | yes | `nonce` is part of the signed payload; apply path requires `nonce == current_nonce + 1` (`rewards.rs:448-456`) |
| Amount binding | yes | `amount` is in the payload; tampering trips `SignatureVerifyFailed` (test `tampering_with_amount_breaks_signature`) |
| Signer-key binding (anti rotated-signer replay) | yes | `signer_pubkey_len + signer_pubkey` are in the payload; rotated keys can't inherit signatures |
| Active-key gate at apply | yes | `get_active_key(&onchain, &self.db, &txn, body.sender_fid, &body.signer_pubkey)` at `runtime.rs:691-703`; returns `SignerNotAuthorized` on `None` |
| Cross-DST replay as token_transfer / token_stake / token_lock | closed by distinct DSTs | a fee_deposit sig is over an 86-byte payload starting `hypersnap-fee-deposit-v1\x00…`; cannot satisfy the token_transfer / stake / lock DST prefix |
| Same-chain replay (capture + re-gossip) | closed by nonce | `apply_fee_deposit` rejects `nonce ≠ expected` with `NonceMismatch` |
| **Cross-chain / cross-shard replay** | **OPEN** | no `chain_id` byte in the payload, AND the FID's Ed25519 active-key set is L1-global so the same pubkey authorizes on every hypersnap deployment that mirrors the same OnchainEventStore |

## Why the cross-chain gap matters here (and not for v2 DSTs)

Hypersnap supports configurable `protocol_chain_id` (`hyper/config.rs:447`; default `10` at `hyper/mod.rs:111`). F101's analysis applies verbatim: "Testnet / staging / future shards run distinct chain ids." The FID active-key set comes from the snapchain `OnchainEventStore` (L1 IdRegistry / KeyRegistry events) which is the same on every hypersnap deployment that indexes the same L1 chain. So a signer key authorized for FID 42 on mainnet is ALSO authorized for FID 42 on any other production / testnet / shard hypersnap whose `OnchainEventStore` mirrors the same L1.

This is what `mod.rs:106-111` flags as the invariant that the v2-DST migration was supposed to enforce. fee_deposit was left at `-v1` and never received the chain_id upgrade.

The same argument extends to `token_transfer.rs` (also `-v1`, also no chain_id) — the broader v1-DST family shares this defect. The H103 sibling ruled-out note (`findings/notes/H103-ruled-out.md`) explicitly notes that v2-DST stake closes this gap; it does NOT claim the v1-DST family closes it.

## Concrete attack scenario

**Setup.** Alice (FID 42) operates on mainnet hypersnap (chain_id=10). Her authorized Ed25519 signer is `pk_A`. She has primary balance > 0 on mainnet and intends to top up her fee balance via `FeeDepositBody{sender_fid=42, amount=100, nonce=5, signer_pubkey=pk_A, signature=sig}`. The same `pk_A` is authorized on the testnet hypersnap (chain_id=11161) and on any future hypersnap shard because the FID 42 KeyRegistry event is on L1 and every hypersnap deployment that mirrors the same L1 sees the same active-key set.

**Replay path.** Anyone who observes the gossip layer (the message is broadcast on the open p2p topic) captures the `HyperMessage::FeeDeposit` blob and re-publishes it on a different hypersnap deployment's gossip topic.

1. Mainnet apply: `validate_fee_deposit` passes (sig over the canonical 86-byte payload verifies under `pk_A`). `get_active_key` returns `Some`. `apply_fee_deposit(42, 100, 5)` requires mainnet nonce = 4; succeeds; nonce → 5; 100 atoms move from primary → fee balance.
2. Testnet apply: the **same** payload bytes verify under `pk_A` (which is also authorized on testnet because both deployments see the same L1 KeyRegistry events). `validate_fee_deposit` passes. `get_active_key` on testnet returns `Some`. `apply_fee_deposit(42, 100, 5)` on testnet only succeeds if Alice's testnet `HyperTokenNonce` for FID 42 happens to equal 4 — i.e., she has made exactly 4 prior transfer/lock/fee-deposit messages on testnet. When that aligns, testnet runtime moves 100 atoms of Alice's testnet primary balance into her testnet fee balance — without Alice authorizing a deposit on testnet.

**Impact.**

- **Multi-shard production.** When hypersnap adds a second production shard (the FIP roadmap is explicit about parallel shards), every captured `FeeDepositBody` on shard A becomes a force-deposit transaction on shard B for whichever FIDs are nonce-aligned at the moment of replay. Users lose the ability to refuse fee-balance top-ups on shards they did not intend to interact with; their primary balance on shard B drops by the captured amount even though they explicitly signed a chain-A intent.
- **Adversarial nonce-alignment grinding.** An attacker who controls the order in which they release captured FeeDeposits can pick the moment a victim's nonce on shard B coincides with the captured nonce on shard A. Bob captures `nonce=5..15` of Alice's mainnet FeeDeposits. On a low-activity shard B Alice slowly accumulates nonces (1, 2, 3, …). When her shard-B nonce hits 4, Bob releases the captured nonce-5 deposit. When it hits 5, Bob releases nonce-6. Bob has a 10-deposit campaign of unauthorized shard-B fee-balance top-ups against Alice.
- **Cross-DST replay** (fee_deposit-sig replayed as token_transfer or stake) is closed: the payload prefix is the fee_deposit DST and verifies only against a payload that starts with those exact 28 bytes. Distinct DSTs mean the byte image is necessarily incompatible.

**Why "low" severity.** The replay always credits the victim's own fee-balance ledger on the destination chain (the apply path is `balance[fid] -= amount; fee_balance[fid] += amount`), not an attacker-controlled account. So the attacker gains nothing financially. But:

- The victim loses control over WHICH chains their primary balance is drained into fee balance on, which violates the user's explicit signing intent (they signed "deposit 100 to my fee balance on chain 10" — they did not sign "deposit 100 on every shard that exists").
- Fee balance is debited at merge-time for snapchain messages — atoms in fee balance are committed to message fees and can only be reclaimed via on-chain mechanics. The forced fee-balance reservation on a shard the user never wanted to operate on is sunk cost.
- The pattern undermines the documented protocol invariant at `mod.rs:106-111` and is the same defect class as F101.

## Why other H104 checks are satisfied (also documented in `findings/notes/H104-ruled-out.md`)

- **Distinct DST from stake / unstake / transfer / lock / inbound_burn / miniapp.** Grepped every `hypersnap-*` DST in `code/hypersnap/src/hyper/*.rs`. fee_deposit DST is `hypersnap-fee-deposit-v1\x00\x00\x00\x00` (28 B). Diverges from every sibling at byte 10 (`f`). No DST is a prefix of another. Cross-DST payload-byte-for-byte collision infeasible.
- **Per-FID nonce binding.** `nonce` is bound in the signing payload and enforced as `current + 1` by `RewardStore::apply_fee_deposit` (`rewards.rs:448-456`). Same-chain replay closed.
- **Amount binding.** `amount` is in the payload (tested at `tampering_with_amount_breaks_signature` line 137-144).
- **Signer-auth.** `get_active_key` gate at `runtime.rs:691-703` enforces that the in-payload `signer_pubkey` is in the FID's authorized active-key set.
- **Cross-pipeline reuse** (fee_deposit-sig replayed as stake / transfer / lock). Closed by distinct DSTs and by the per-FID monotonic nonce that all four (transfer, lock, fee_deposit, stake) share — a replay attempt would hit `NonceMismatch` even before the DST mismatch is detected.

## Compounding factors

### Lax `pk.verify` (codebase-wide pattern, observed by H103)

`fee_deposit.rs:77` uses `pk.verify` rather than `verify_strict`. This admits cofactor-form malleability (mixed-order points / SBS). Not independently exploitable here for the same reasons H103 documented for token_stake: the per-FID monotonic nonce check rejects any malleated replay of the same `(fid, nonce)`. Flagging only because the cross-chain replay window WOULD let a single captured signature be applied on multiple deployments, and verify_strict would close one layer of latent risk if the underlying primitive ever changes. Strict mode is the better default; not a load-bearing finding.

### Apply-path `txn` is unused

`apply_fee_deposit` at `runtime.rs:690` creates an empty `RocksDbTransactionBatch` and passes it to `get_active_key` as the pending-write overlay. The txn is never committed and contains no writes — it's effectively a no-op argument to satisfy `get_active_key`'s signature. The active-key read therefore sees latest committed state, which is the intended behavior. Not a finding; flagging only because the same pattern is used elsewhere (`apply_token_transfer`, `apply_token_lock`).

## Why the existing checks do not close the gap

| Check | What it gates | Replay window it leaves open |
|---|---|---|
| Distinct DST | Cross-purpose replay (fee_deposit → stake, etc.) | none here — closed |
| `signer_pubkey` in payload | Signer rotation invalidates older sigs | n/a — chain-A and chain-B share the active-key set, rotation timing differs only by L1 finality |
| Per-FID monotonic nonce | Same-chain capture-and-replay | Cross-chain replay against any deployment whose `HyperTokenNonce[FID]` is nonce-aligned |
| `get_active_key` | Unauthorized signer | n/a — the same pubkey is authorized on every deployment mirroring the same L1 |
| `validate_fee_deposit` | Structural + Ed25519 sig | n/a — the validator is chain-agnostic |

There is no chain_id binding at any layer in the fee_deposit path.

## Recommended fix

Promote the signing payload to `-v2` and bind `protocol_chain_id`:

1. Rename the DST to `b"hypersnap-fee-deposit-v2"` (with appropriate NUL padding to retain canonical length; or drop the padding since v2 has no compatibility constraint with the v1 layout).
2. Extend `fee_deposit_signing_payload` to take `chain_id: u64` and prepend `chain_id.to_be_bytes()` to the body (after the DST, before `sender_fid`). Mirror the layout of `token_stake_signing_payload(body, chain_id)` exactly.
3. Update `validate_fee_deposit` to take `chain_id: u64` and pass `self.protocol_chain_id` from `runtime.rs::apply_fee_deposit`.
4. Add a test mirroring `stake_signature_does_not_replay_across_chains` (chain A sig → chain B verify → assert `SignatureVerifyFailed`).

The wallet / signer UX would change in a back-compatible way (v2 payloads commit to the chain_id the user is signing for; v1 is rejected).

**Co-fix:** apply the same upgrade to `token_transfer.rs::DST` and `token_lock.rs::DST` — they have the same gap.

**Defense-in-depth (not load-bearing):** switch `pk.verify` to `pk.verify_strict` to close cofactor-malleability latently. Same recommendation extends to all Ed25519 verifies in `code/hypersnap/src/hyper/*`.

## Affected attack-class checklist items (rust-crypto-primitives persona)

- `signing-payload-or-dst-collision` — chain_id binding is the F101-antipattern lever; present here in a sibling user-signed payload.
- `cross-side-encoding-asymmetry` — n/a (no Rust↔Solidity boundary for this payload; pure Rust signer/verifier).

## Tests to add

- **Cross-chain replay rejected.** Sign a `FeeDepositBody` for `protocol_chain_id = 10`; apply on a fresh runtime with `protocol_chain_id = 11161`; assert `SignatureVerifyFailed` (currently passes — the test would fail under v1).
- **Chain-id tampering rejected.** Build a v2 payload with `chain_id = 10`, flip to `chain_id = 11`, expect `SignatureVerifyFailed`.
- **Tampering with nonce rejected.** Already exists (`tampering_with_nonce_breaks_signature`).
- **`verify_strict` malleability rejected.** Build a malleated point that `verify` accepts; assert the new strict verifier rejects.
