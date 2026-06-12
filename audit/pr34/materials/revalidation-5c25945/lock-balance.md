# Revalidation — lock event / balance closure / range proof

- Audited commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- Fix commit: `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child)
- Scope: F035 (transparent HyperLockEvent unbacked mint), F036 (confidential-lock range proof unwired)

## Summary table

| ID   | Verdict | Confidence | One-line reason |
|------|---------|-----------|-----------------|
| F035 | FIXED   | 0.95      | Transparent-lock state-change path disabled at both ingress (router) and the block-import chokepoint (`import_hyper_block` rejects any block carrying locks); no production caller can populate the lock mempool. |
| F036 | FIXED   | 0.95      | `validate_against_store` (the sole live confidential-lock gate) now mandates + verifies the Bulletproofs range proof against the input commitment, and rejects missing/empty/bad proofs; `checked_add` also closes the related amount+fee overflow. |

---

## F035 — HyperLockEvent mints into signed verkle root without balance closure

Verdict: FIXED — confidence 0.95

### What the fix does
The fix removes the transparent `HyperLockEvent` state-change path rather than
adding balance enforcement to it (the "Preferred" remediation in the finding).
Three layered gates:

1. Ingress rejected. `src/hyper/router.rs:133-142` — `route_inbound` now hard-rejects
   `Body::Lock`:
   ```rust
   proto::hyper_message::Body::Lock(_) => {
       Err(RoutingError::Lock(
           "transparent lock path removed; use ConfidentialLockBody".to_string(),
       ))
   }
   ```
   No production caller of `mempool.submit_lock` remains (grep over `src/**`
   excluding tests returns only `forget_lock` cleanup and test assertions), so the
   `HyperMempool.locks` map cannot be populated in production and
   `mempool.drain()` returns empty locks at the producer path
   (`src/hyper/runtime.rs:4737`).

2. Block-import rejected — the real applied path. `src/hyper/importer.rs:269-273`:
   ```rust
   if !locks_in_block.is_empty() {
       return Err(ImportError::Lock(
           crate::hyper::lock_event::LockError::TransparentLocksDisabled,
       ));
   }
   ```
   This is inside `import_hyper_block`, the single chokepoint that every import
   wrapper funnels through: `import_hyper_block_chain_aware`
   (`importer.rs:128`), `import_hyper_block_with_index` (`importer.rs:155`),
   and `import_hyper_block_with_scoring` (`importer.rs:195`) all call it. The live
   runtime entry `HyperRuntime::import_block` (`src/hyper/runtime.rs:4520`) calls
   `import_hyper_block_with_index` (`runtime.rs:4585`), so a malicious proposer who
   injects locks directly into `HyperWireBlock.locks` (the exact F035 attack vector)
   gets the whole block rejected on every importing node — the gate runs after the
   threshold-sig check but before any state mutation.

3. Replay rejected. `src/hyper/runtime.rs:368-378` — verkle rehydration on restart
   now skips (warns on) any stored locks from pre-fix blocks instead of re-applying
   them, so historical leaves cannot be re-minted into the root.

New error variant: `src/hyper/lock_event.rs:143` `LockError::TransparentLocksDisabled`.

### Adversarial check
The proposer-insert path (`locks_in_block` decoded from the proposer's payload, not
local mempool) was the residual gap the finding emphasized. It is closed: the
rejection is in `import_hyper_block` itself, which the proposer-insert path cannot
bypass. The builder's `insert_lock_into_tree` (`src/hyper/builder.rs:116`) is now
unreachable in production because no `PendingMessage::Lock` is ever pushed in the
import path and the only producer-side push (`runtime.rs:4737`) drains an always-empty
lock set. `apply_message(PendingMessage::Lock)` and `insert_lock_into_tree` remain in
the code but have no reachable production caller.

### Residual notes (non-blocking)
- `insert_lock_into_tree`, `encode_lock_leaf`, and `apply_message(Lock)` are now dead
  code retained for tests; harmless but could be deleted to remove the latent
  primitive entirely. Does not affect the verdict — there is no path to invoke them.
- The unused proto `lock_signature` field and the mod.rs "Schnorr-signed
  authorization" doc claim were not removed, but with the path disabled they are inert.

---

## F036 — Confidential-lock range proof defined but unwired

Verdict: FIXED — confidence 0.95

### What the fix does
`src/hyper/confidential_lock.rs:213-237` — `validate_against_store` now verifies the
range proof on the input commitment after balance closure:
```rust
if body.range_proof.is_empty() {
    return Err(ConfidentialLockError::MissingRangeProof);
}
let mut commitment_bytes = [0u8; 56];
commitment_bytes.copy_from_slice(
    &body.input.as_ref().expect("validate_structural ensured input is present").commitment,
);
let ok = verify_value_range(&body.range_proof, &commitment_bytes, DEFAULT_RANGE_BITS)
    .map_err(|_| ConfidentialLockError::BadRangeProof)?;
if !ok {
    return Err(ConfidentialLockError::BadRangeProof);
}
```
New error variants `MissingRangeProof` / `BadRangeProof` at
`src/hyper/confidential_lock.rs:56-60`.

This matches the finding's recommended fix (a): the range proof is now read and
verified on the live admission path with `verify_value_range(..., DEFAULT_RANGE_BITS)`
(`crates/hypersnap-crypto/src/tokens.rs:158`, `DEFAULT_RANGE_BITS = 64`,
`tokens.rs:36`). The commitment passed is the same input commitment used for the
Pedersen balance closure, and the signature/length contract matches
(`[u8; 56]`).

### Liveness / no-bypass
`validate_against_store` is the sole gate for confidential locks. Live path:
`HyperRuntime::submit_message` → `apply_confidential_lock` (`runtime.rs:3729`) →
`validate_against_store` (`runtime.rs:872`). There is no separate block-import
re-validation for `ConfidentialLockBody` (the importer has no confidential-lock arm),
so this single gate is authoritative and now enforces the range proof. No alternate
caller of `apply_confidential_lock` bypasses it (only `runtime.rs:3729` in production).

### Safety of the new code
`validate_against_store` calls `validate_structural` first
(`confidential_lock.rs:172`), which guarantees `body.input` is `Some` and
`input.commitment.len() == 56` (`confidential_lock.rs:126-132`). Therefore the later
`.expect(...)` and `copy_from_slice(...)` in the range-proof block cannot panic in
production. A malformed/short commitment is rejected structurally before the range
check is reached.

### Bonus hardening (related to finding's impact discussion)
The balance-closure arithmetic was changed from `saturating_add` to `checked_add`
(`confidential_lock.rs:195-198`, new `AmountFeeOverflow` error), closing the
unit-mismatch primitive where a prover could declare `amount + fee = u64::MAX` to bind
the input to a saturated value while L1 mints only `body.amount`.

### Residual notes (non-blocking)
- The fix takes option (a) and keeps the `range_proof` wire field, so no proto change /
  off-chain-tooling concern remains; the field is now genuinely load-bearing.
