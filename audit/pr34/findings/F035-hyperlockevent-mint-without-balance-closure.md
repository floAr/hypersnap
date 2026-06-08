---
id: F035
specialist: rust-bulletproofs-pedersen
attack_class: balance-closure-not-enforced
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed verkle state root with no balance closure, range proof, or signature verification
file_paths:
  - src/hyper/lock_event.rs
  - src/hyper/builder.rs
  - src/hyper/importer.rs
  - src/hyper/runtime.rs
  - src/hyper/mempool.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.7
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The `HyperLockEvent` bridge-lock pipeline writes a caller-supplied plaintext
`amount` directly into a verkle-tree leaf with **no source-side balance
enforcement of any kind**: no Pedersen balance closure, no range proof, and no
verification of the proto `lock_signature` field. The verkle root containing
that leaf is then threshold-signed and posted as the cross-chain
`hyper_state_root`, and `lock_event.rs`'s own module doc + end-to-end test
assert the L1 bridge proves inclusion of this leaf "before minting wrapped
tokens."

A second, secure lock pipeline exists in the same scope —
`confidential_lock::validate_against_store` performs full Pedersen balance
closure (`commit_in - (amount+fee)·B == r_diff·B_blinding`) against a
caller-supplied `blinding_diff_scalar`, plus Schnorr spend verification and
nullifier double-spend checks. This is the classic two-pipeline confusion: the
strong validator is fully implemented and wired into `apply_confidential_lock`,
while the **production block-application path still applies the weak
`HyperLockEvent` path unconditionally**. A malicious proposer can include
arbitrary-amount `HyperLockEvent`s in a block; every importer applies them with
structural validation only.

## Affected code (file:line)

- `src/hyper/lock_event.rs:141` `validate_lock_event` — the only validation
  ever run on a `HyperLockEvent`. Checks `amount != 0`, `lock_id.len()==32`,
  non-empty dest/spend fields, and EVM length conventions. **Never checks
  `lock_signature`, never enforces any balance relation.** Module doc
  (lines 11-14) explicitly states: "the handler accepts the lock event but
  does not enforce source-side balance constraints. This is documented as a
  known gap."
- `src/hyper/lock_event.rs:27` `encode_lock_leaf` — serializes the plaintext
  `amount` (8B BE) straight into the verkle leaf the L1 bridge decodes
  (lines 4-9, 18-26).
- `src/hyper/builder.rs:113-118` `apply_message(PendingMessage::Lock)` →
  `insert_lock_into_tree` → `validate_lock_event` only, then inserts the leaf
  into the verkle tree. No commitment, no range proof.
- `src/hyper/importer.rs:238-305` `import_hyper_block` — the production
  block-application path. Verifies ONLY (a) the block threshold ECDSA
  signature and (b) that the recomputed verkle root equals the signed
  `hyper_state_root`. It then loops every `lock` in `locks_in_block`
  (decoded from the proposer's `HyperWireBlock.locks` payload, NOT from local
  mempool) into `PendingMessage::Lock` and applies it (lines 263-265, 270-283).
- `src/hyper/runtime.rs:4461-4534` `HyperRuntime::import_block` — the live
  runtime entry. For **transfers** it re-runs strong off-mempool validation
  (`validate_against_store` + `verify_balance_with_blinding_diff`, lines
  4482-4524) explicitly "to defend against a malicious proposer who included a
  transfer off-mempool." **No equivalent re-validation exists for
  `locks_in_block`** — they go straight into `import_hyper_block_with_index`.
- `src/hyper/mempool.rs:119-129` `submit_lock` — structural-only admission
  (`validate_lock_event`), retained.

Contrast — the secure path that is NOT on the verkle/L1 lock path:
- `src/hyper/confidential_lock.rs:156-186` `validate_against_store` enforces
  balance closure at line 182 (`residual != expected`), Schnorr verify
  (line 171), nullifier-not-spent (line 166).
- `src/hyper/runtime.rs:860-913` `apply_confidential_lock` is the only
  non-test writer of `TokenLockState` into `reward_store`; those states feed
  `build_lock_merkle_tree` (runtime.rs:921) / `lock_tree.rs`, the merkle root
  the L1 `claim` consumes.

## Attack scenario

1. A malicious (or compromised) block proposer constructs a `HyperLockEvent`
   with `amount = 1_000_000_000`, a valid 32-byte `lock_id`, an attacker EVM
   `dest_address`, `spend_pubkey` of valid length, and `lock_signature` left
   zero-filled (it is never checked). `validate_lock_event` passes.
2. The proposer places this lock directly into the block's
   `HyperWireBlock.locks` payload (it need not pass through any node's mempool
   router, which would reject transparent locks). It builds the block; the
   verkle root deterministically incorporates the lock leaf.
3. The proposer obtains the normal block threshold signature over the metadata
   (the verkle `hyper_state_root`). This is the only signature the protocol
   requires.
4. Every importer runs `import_hyper_block`: the threshold sig verifies, the
   recomputed verkle root matches (the lock leaf is deterministic), and the
   lock is applied with structural-only validation. The forged lock is now
   committed under the signed cross-chain state root on every node.
5. Per `lock_event.rs` lines 4-9 and the `bridge_proof_pipeline_end_to_end`
   test (lines 318-371), the L1 bridge proves verkle inclusion of this leaf and
   mints `amount` wrapped tokens to the attacker's `dest_address` — wrapped
   value backed by nothing on the source side.

No honest counter-party balance was ever debited; `sum(inputs)=sum(outputs)+fee`
is never evaluated for this lock, and no range proof bounds `amount`.

## Impact

Unbacked mint of arbitrary wrapped-token value, fully drainable on L1 — a direct
theft / protocol-insolvency vector, gated only by the honesty of the block
proposer (and the threshold-signing set's willingness to sign whatever verkle
root the proposer produces, since locks carry no independently-verifiable
authenticity).

Relation to prior F002 (per-lock authenticity rests on an honest proposer):
This **confirms F002 is, for the balance/authenticity dimension, still
vulnerable (at best partially-fixed)**. PR #34's hardening was applied to
*transfers* (the off-mempool re-validation block in `import_block`,
runtime.rs:4482-4524) and to *confidential locks*
(`apply_confidential_lock`/`validate_against_store`), but the transparent
`HyperLockEvent` → verkle path retained its weak, structural-only application
in `import_hyper_block`. The `lock_signature` proto field (hyper.proto:304) is
verified nowhere in production — every occurrence is a zero-fill or refers to
the unrelated block-level `verify_hyperblock_signature`. Lock authenticity and
balance still rest entirely on an honest proposer, exactly the F002 condition.

Note on exploit live-ness: the L1 `claim` entry point present in this repo
consumes the *merkle* lock-tree root (`lock_tree.rs` / `bridge_state.rs`,
built only from balance-validated `TokenLockState`s), so an attacker cannot
reach L1 through *that* specific root. The verkle-inclusion mint path is the one
`lock_event.rs` documents and tests; whether the deployed L1 bridge currently
honors verkle-inclusion claims is not determinable from this repo (the L1
contract is out of scope). Regardless, the in-scope code commits attacker-chosen,
unbacked lock leaves into the threshold-signed cross-chain state root with zero
balance enforcement — a latent mint primitive that becomes immediately
exploitable the moment the verkle-inclusion claim path is enabled on L1, and a
clear violation of the balance-closure invariant for the lock primitive.

## Root cause

Two parallel lock pipelines with asymmetric enforcement. The balance-closure
validator was implemented and wired only into the confidential pipeline; the
transparent `HyperLockEvent` pipeline that writes the verkle/cross-chain state
root kept its placeholder "source-side balance constraints are a known gap /
Phase B-3" handler and was never decommissioned from the block-application path.
The proto carries a `lock_signature` field but no code reads it, and no
`r_diff`/commitment/range-proof is carried for transparent locks, so balance
closure is structurally impossible on this path even if a check were added.

## Fix

Remove the transparent-lock state-change path entirely (the router already
rejects ingress at router.rs:133), OR require every `HyperLockEvent` applied in
`import_hyper_block` / `builder::apply_message` to carry and pass the same
enforcement as confidential locks:

1. In `HyperRuntime::import_block`, add a per-lock re-validation loop mirroring
   the transfer loop (runtime.rs:4482-4524): reject any block whose locks lack a
   verifiable source-side commitment + range proof + balance closure against the
   note store.
2. Extend the lock wire format to carry the input commitment, `blinding_diff`
   scalar, and a range proof on `amount`; verify
   `commit_in - (amount+fee)·B == r_diff·B_blinding` and the bullet-proof range
   bound before inserting the leaf.
3. Either verify `lock_signature` (Schnorr/ecrecover over a domain-separated
   payload binding amount + dest + nullifier) or delete the unused field and
   the mod.rs:14 "Includes Schnorr-signed authorization" claim, which is false.

Preferred: route all production bridge locks exclusively through
`apply_confidential_lock` (already balance-closed) and delete
`lock_event.rs` application from `builder`/`importer`, eliminating the
verkle-leaf mint primitive.
