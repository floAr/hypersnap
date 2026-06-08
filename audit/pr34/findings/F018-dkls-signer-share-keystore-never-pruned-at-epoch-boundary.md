---
id: F018
specialist: node-lifecycle-actor
attack_class: lifecycle-state-leak
file_paths:
  - src/hyper/runtime.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: medium
title: Per-epoch DKLS23 secret-share keystore (dkls_signers) is never pruned, zeroized, or retired across epoch transitions, so retired threshold shares stay live and signing-capable for the process lifetime
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

`HyperRuntime.dkls_signers: BTreeMap<u64, DklsEpochState>` is the
post-migration authoritative threshold-ECDSA keystore. Each
`DklsEpochState` holds the local DKLS23 `Party` — i.e. this node's
**secret share of the group key plus the pre-computed multiplication
shares used at signing time** (`runtime.rs:324-335`). The map is keyed by
epoch and is **insert-only**: it is mutated in exactly one place
(`install_local_dkls_share`, `runtime.rs:4722`) and read in two
(`dkls_share_for_epoch`, the production path). There is **no removal,
prune, eviction, retirement, or zeroization path anywhere in the
codebase** — a full grep of `src/hyper/**` shows `dkls_signers` is only
ever `insert`ed, `get`/`keys`-read, and `BTreeMap::new()`-initialized.

Consequently a node that participated as a signer in epoch `E` keeps the
epoch-`E` secret share live in process memory indefinitely, long after
epoch `E` has retired and the committee has rotated. The secret material
leaks across every subsequent lifecycle transition. This is a
lifecycle-state-leak: state that the protocol model treats as bound to a
single (now-dead) epoch persists and remains usable in later epochs.

## Where

- State def: `src/hyper/runtime.rs:288`
  `pub dkls_signers: std::collections::BTreeMap<u64, DklsEpochState>`
- Secret material: `src/hyper/runtime.rs:324-335` (`DklsEpochState.party`
  = secret share + mult shares; comment confirms "our share of the group
  secret").
- Sole insert: `src/hyper/runtime.rs:4715-4748` `install_local_dkls_share`
  (called from `genesis.rs`, `dkls_driver.rs`, `dkls_supervisor.rs` on
  every finalized ceremony).
- Sole reads: `src/hyper/runtime.rs:4772-4774` `dkls_share_for_epoch`;
  block-production path `runtime.rs:4832-4838`,
  `runtime.rs:4902-4905`.
- No prune: grep `dkls_signers` over `src/hyper/**` returns only the
  insert, the reads, `next_back()` (a query helper, `actor.rs:1729-1737`),
  and `BTreeMap::new()`. No `.remove(`, `.retain(`, `.clear(`, `.split_off(`.
- No zeroize: grep `Zeroize|zeroize|impl Drop for DklsEpochState` in
  `runtime.rs` returns nothing. `DklsEpochState` derives only `Clone`; the
  `Party` is dropped by the default allocator with no scrubbing.

## Why it is a leak (and the contrast that proves intent)

The struct doc-comment at `runtime.rs:282-287` explicitly states that once
the DKLS path is authoritative "the existing `signer` BLS state is
retired." There is corresponding retirement logic for the BLS signer, but
**no analogous retirement for `dkls_signers`** — the DKLS shares simply
accumulate. The keystore was designed with a notion of per-epoch lifetime
but the lifetime is never enforced.

Two concrete consequences of the stale share remaining *usable*:

1. **Bridge-side local sign helpers accept an arbitrary, retired epoch.**
   - `produce_signed_lock_merkle_root_local(epoch, block_number)`
     (`runtime.rs:940-987`) does `dkls_share_for_epoch(epoch)` with **no
     "epoch must be current" check** and will produce a fresh, valid ECDSA
     signature over a *current* merkle root using a *retired* epoch's
     secret share.
   - `produce_signed_owner_rotation_local(outgoing_epoch,
     incoming_epoch, ...)` (`runtime.rs:1066-1122`) likewise signs with
     whatever epoch shares are still resident.
   Both contrast with the block-production path
   (`produce_unsigned_block_dkls`, `runtime.rs:4824-4838`), which was
   deliberately hardened by a prior fix (F028/F026) to bind signing to
   `epoch_resolver.current_epoch()` precisely because
   "`dkls_signers.iter().next_back()` ... leaks pre-staged future-epoch
   material into current production." That same anti-pattern — using a
   non-current epoch's resident share — is still reachable through the
   bridge helpers because the underlying keystore is never pruned.

2. **Verify side resolves the group key from an attacker-chosen epoch
   against the never-pruned group-address registry.** All threshold-signed
   apply paths key off the caller-supplied `epoch` field via
   `dkls_group_address_for_epoch(...)` (issuance `runtime.rs:566`,
   trust-snapshot `:656`, merkle-root `:1026`, owner-rotation `:1146/:1149`,
   inbound-burn `:1333`). The trust-snapshot path defends against exactly
   this stale-key reuse with an explicit epoch-monotonicity watermark
   (`last_trust_snapshot_epoch`, `runtime.rs:646-653`, whose own comment
   warns "an attacker holding a valid older-epoch threshold signature could
   otherwise clobber a fresh snapshot"). The **lock-merkle-root**
   (`apply_lock_merkle_root_update`, `:995-1055`) and **owner-rotation**
   (`apply_owner_rotation`, `:1130-`) paths enforce only `block_number`
   monotonicity, **not** epoch monotonicity, so the protocol-side store will
   accept a fresh payload signed by a retired epoch's group key.

## Impact / severity rationale

This is a confirmed cross-epoch secret-material leak (lifecycle-state-leak).
Direct fund-loss exploitability is partially blunted by two factors, which
is why this is rated medium rather than high:

- The canonical **block** signing path is pinned to `current_epoch`, so a
  stale share cannot forge a current hyperblock through the normal proposer
  flow.
- The **bridge contract** (`HypersnapBridge.sol`) is the authoritative
  enforcer of the current owner/root; a signature from a *retired* group
  address is rejected on-chain even though the protocol-side
  `apply_lock_merkle_root_update` / `apply_owner_rotation` relay-cache
  accepts it. The protocol-side acceptance is a local-state divergence /
  relay-cache poisoning, not an on-chain fund move on its own.

The real and unavoidable harm is **secret-material hygiene / blast-radius
expansion**:

- A rotated-out validator retains a fully usable secret share for every
  epoch it ever signed in. The protocol treats those epochs as dead; the
  node does not. This is exactly the "state that leaks across transitions"
  the lifecycle-state-leak class targets, and it converts a single-epoch
  committee membership into an indefinite signing capability for that
  epoch's group key.
- A node compromised at time T leaks **every** historical epoch's secret
  share at once (the whole `BTreeMap`), not just the current epoch's. With
  no zeroization on drop, the material also lingers in freed heap pages.
- The lock-merkle-root / owner-rotation verify paths lack the
  epoch-monotonicity guard that the trust-snapshot path has, so a leaked
  retired share can poison the protocol-side relay cache with stale-key
  signatures (local divergence from on-chain truth, a liveness/consistency
  hazard for relayers reading the cached "latest signed root/owner").

## Suggested remediation

- Prune `dkls_signers` at the epoch boundary: on epoch advance / once an
  epoch is finalized and past its signing window, remove the now-retired
  epoch's `DklsEpochState`, retaining only a small bounded window
  (e.g. `current_epoch` and `current_epoch - k` for in-flight rotations).
  Mirror this in the scheduler/actor epoch-transition handler that already
  drives `EvaluateEpochDkls`.
- Implement `Drop`/`Zeroize` for `DklsEpochState` (and ensure the vendored
  `Party` zeroizes its secret share) so retired shares are scrubbed, not
  just dropped.
- Add an epoch-currency check to the bridge-side local sign helpers
  (`produce_signed_lock_merkle_root_local`,
  `produce_signed_owner_rotation_local`): refuse to sign with a share whose
  epoch is not the current (or the explicitly-intended rotation) epoch,
  matching the `current_epoch` binding already enforced on the block path.
- Add epoch-monotonicity replay guards to `apply_lock_merkle_root_update`
  and `apply_owner_rotation` analogous to `last_trust_snapshot_epoch`, so
  the protocol-side relay cache cannot be advanced by a retired epoch's
  group key.

## Verification notes

- `dkls_signers` mutation sites (whole repo): insert at
  `runtime.rs:4722`; no remove/retain/clear/split_off anywhere.
- Block path current-epoch binding (the contrasting, hardened path):
  `runtime.rs:4824-4838`.
- Bridge local-sign helpers take caller-chosen epoch, no currency check:
  `runtime.rs:940-987`, `runtime.rs:1066-1122`.
- Trust-snapshot epoch-monotonicity guard (present) vs merkle-root /
  owner-rotation (absent): `runtime.rs:646-653` vs `:995-1055` / `:1130-`.
- No zeroize/Drop for `DklsEpochState`: `runtime.rs:323-335`.
- Persistence asymmetry confirming design intent: only the group-address
  registry is durable; shares are in-memory and empty after restart
  (test `runtime.rs:5702-5705`) — i.e. the only thing that *does* clear the
  shares is a process restart, never a lifecycle transition.
