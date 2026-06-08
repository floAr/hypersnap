---
id: H067
specialist: chain-economics
attack_class: fee-deposit-replay
outcome: ruled-out
file_paths:
  - src/hyper/fee_deposit.rs
  - src/hyper/rewards.rs
  - src/hyper/runtime.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H067 fee-deposit-replay — ruled out

## Scope
`src/hyper/fee_deposit.rs` Ed25519-signed atom move into the per-FID fee
ledger. Hunted: replay / dedup, amount binding, signer authorization.

## Why no issue

The validation function `validate_fee_deposit` (fee_deposit.rs:60) is a
pure structural + signature check; replay/dedup is enforced at the apply
path, which is correctly wired.

1. **Replay / single-use signature.** `nonce` is bound into the signed
   payload (`fee_deposit_signing_payload`, fee_deposit.rs:54). At apply,
   `RewardStore::apply_fee_deposit` (rewards.rs:443) requires
   `nonce == nonce_of(sender_fid) + 1` and persists the new nonce in the
   same atomic RocksDB batch as the balance/fee-balance writes
   (rewards.rs:449-482). Re-applying the same body fails
   `NonceMismatch` — the per-FID nonce has already advanced. The nonce is
   *shared* across `apply_transfer` / `apply_lock` / `apply_shield` /
   `apply_fee_deposit` (single `HyperTokenNonce` keyspace,
   rewards.rs:338), so a fee-deposit cannot reuse a nonce already burnt by
   another atom-moving path, nor vice-versa.

2. **Amount bound to signature.** `amount` is in the signed payload
   (fee_deposit.rs:53); mutating it breaks verification (test
   `tampering_with_amount_breaks_signature`). Apply does a balance
   pre-check (`sender_bal < amount`) and `checked_add` overflow guard on
   the fee balance (rewards.rs:467-470).

3. **Signer authorized.** `runtime::apply_fee_deposit` (runtime.rs:744)
   calls `get_active_key(sender_fid, signer_pubkey)` and rejects with
   `SignerNotAuthorized` when the key is not an active L1 key for the FID
   (runtime.rs:754-766). The signature was verified under that same
   `signer_pubkey` and `sender_fid` is bound into the payload, so the
   authorized-signer → committed-fid → credited-fid chain is tight.

4. **Cross-context replay.** `chain_id` is bound into the payload
   (fee_deposit.rs:51; test `cross_chain_replay_rejected`), and the DST
   `b"hypersnap-fee-deposit-v1"` is distinct from token-transfer's
   `b"hypersnap-token-transfer-v1"`, preventing cross-deployment and
   cross-message-type signature reuse.

The single dispatch site (runtime.rs:3692 in `submit_message`) routes
`FeeDeposit` bodies exclusively through `apply_fee_deposit`; no alternate
ingestion path bypasses the nonce/signer gates.

## Conclusion
Deposit signatures are single-use via the persisted monotonic per-FID
nonce; amount and signer are cryptographically bound; replay (same-body,
cross-type, cross-chain) is blocked. No finding.
