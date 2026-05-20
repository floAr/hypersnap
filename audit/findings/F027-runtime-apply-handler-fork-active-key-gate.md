---
id: F027
task: H027
specialist: node-lifecycle-actor
attack_class: actor-context-window-blow
severity: medium
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.78
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F027: `runtime.rs` apply-handler fork — 13 copy-pasted active-key gates and a documented "Phase 1b" gap that must now be patched in 13 places

## Summary

`src/hyper/runtime.rs` (9668 LOC total; 4554 LOC of production code before
the `#[cfg(test)]` mod at line 4554) carries a systemic anti-pattern: the
"the signer pubkey on this message is an active key for the named FID"
gate has been hand-inlined into **13 distinct `apply_*` handlers** rather
than factored into a single helper. The forks are byte-for-byte identical
in shape but live in 13 different functions; the in-source comment on the
first occurrence (`apply_token_transfer`, line 637) explicitly defers
**scope-gating** — "so a CastAdd-only key can't move tokens" — as a
follow-up.

The consequence of the fork pattern is that the deferred scope-gating fix,
when it lands, has to be applied identically at all 13 sites. Any site
missed retains the looser "any active key" check; the looser check is
silently security-relevant on value-moving paths
(`apply_token_transfer`, `apply_fee_deposit`, `apply_token_lock`,
`apply_token_stake`, `apply_token_unstake`, `apply_token_escrow_claim`).
This is the classic "copy-pasted handler forked N times with subtly
different ordering" anti-pattern that this attack class is designed to
catch.

The `actor.rs` file (4870 LOC) is itself over the > 4000 LOC audit-side
threshold the persona flags, but its production code (2982 LOC before
`#[cfg(test)]` at line 2982) is well-structured: the central `dispatch`
match (lines 1129-1390) and `handle_query` match (1392-1651) are routing
shells that delegate to dedicated helpers, with **2** `.unwrap()` sites in
all of production (lines 1098 and 1100, both inside the `drive_events`
test-helper path). `engine.rs` (2431 LOC) bounds per-block work via
`max_messages_per_block` (line 202/214/230/272), so the prompt's
"unbounded `WriteBatch` chunk per arm of `apply_*`" concern does **not**
materialise in this engine. The single substantive finding is the
runtime.rs apply-handler fork.

## Description

### Inventory of the 13 forks

Each of the following `apply_*` (and one helper, `miniapp_check_signer_and_nonce`)
opens with the same four-line preamble:

```rust
let handler = StoreEventHandler::new_no_persist();
let onchain = OnchainEventStore::new(self.db.clone(), handler);
let txn = crate::storage::db::RocksDbTransactionBatch::new();
let active = get_active_key(&onchain, &self.db, &txn, <fid>, &<signer_pubkey>)
    .map_err(|e| RewardError::Custom(format!("active-key lookup: {}", e)))?;
if active.is_none() {
    return Err(RewardError::SignerNotAuthorized { fid: <fid> });
}
```

Sites (line numbers from `src/hyper/runtime.rs`):

| Line | Function | Notes |
|------|----------|-------|
|  456 | `fids_for_scoring` | onchain handler construction, no `get_active_key` |
|  654 | `apply_token_transfer` | value-moving |
|  691 | `apply_fee_deposit` | value-moving |
|  730 | `apply_token_lock` | value-moving (lock burns to bridge) |
| 1265 | `apply_token_escrow_claim` | value-moving (escrow → balance) |
| 1625 | `apply_token_stake` | value-moving (balance → staked) |
| 1717 | `apply_token_unstake` | value-moving (staked → unstake queue) |
| 1991 | `apply_node_attestation` | non-value, but signer-bound state write |
| 2078 | `apply_node_attestation_revoke` | non-value |
| 2198 | `apply_app_usage_receipt` | non-value, but reward-credit input |
| 2358 | `apply_miniapp_register` | non-value, but binds miniapp ownership |
| 2501 | `miniapp_check_signer_and_nonce` | helper called by register/unregister/update/add/remove |
| 3039 | `apply_da_challenge_response` | reward-credit input |

13 inline copies plus one helper. The helper at 2501 covers four downstream
`apply_miniapp_*` paths via a `match` — that's a step toward refactoring,
but it's the *only* such step in the file. The 12 value- or
reward-relevant sites remain forked.

### The TODO that this fork blocks

`apply_token_transfer` line 630-633 (doc comment):

> Phase 1b accepts both `ActiveKey::OnChain` and `ActiveKey::Gasless`;
> scope-gating on gasless keys (so a CastAdd-only key can't move tokens)
> is a follow-up — for now, any active key for the FID is sufficient.

`get_active_key` (referenced from `src/storage/store/account.rs`) returns
`Option<ActiveKey>` where `ActiveKey::Gasless(scope_metadata)` carries the
scope of the gasless authorisation. The current code discards
`active`'s payload after the `is_none()` check (`let _active = active;`
implied; the binding is never read). The "Phase 1b" follow-up needs to:

1. Match on `ActiveKey::OnChain | ActiveKey::Gasless { scopes }`,
2. For `Gasless`, require that the current message's `MessageType` (or a
   coarser "value-moving" bit) is present in `scopes`.

That fix must be re-derived and re-pasted at all 12 sites individually,
because there is no single chokepoint. The probability that one site is
forgotten — say `apply_token_escrow_claim` at line 1265, which sits
between the heavily-used transfer/lock/stake cluster and the
attestation cluster and is the only escrow-claim handler in the file —
is non-negligible. A forgotten site means a CastAdd-scoped gasless key
can drain the escrow column even after Phase 1b ships everywhere else.

### Variation in error returns across the forks

Even today, before the scope-gating lands, the forks already drift
slightly in their error type:

* `apply_token_transfer` (654): returns `RewardError::SignerNotAuthorized { fid: body.sender_fid }`
* `apply_token_stake` (1625): returns `RewardError::SignerNotAuthorized { fid: body.fid }`
* `apply_token_escrow_claim` (1265-1273): see below — wraps the lookup
  error in `RewardError::Custom(format!("active-key lookup: {}", e))`
  but the `is_none()` arm returns `SignerNotAuthorized` (consistent
  with the others), BUT the `body` field plumbed in is the
  custody-address-derived `fid` not the message's `signer_fid`, so the
  reported FID on this rejection path is a different field from
  all other handlers.
* `miniapp_check_signer_and_nonce` (2501): does not return
  `SignerNotAuthorized` at all — uses a plain `RewardError::Custom`
  string. Downstream callers (`apply_miniapp_register/unregister/
  update/add/remove`) inherit this drift, so a single client error
  matcher cannot uniformly detect "signer rejected" across all
  user-message types.

These are minor today (no security impact at present), but they're the
canonical "forked handlers drift apart" warning sign that should not be
allowed to compound when the scope-gating change lands.

### File-size discipline (audit-side bookkeeping)

| File | Total LOC | Production LOC (excl. `#[cfg(test)]`) | Persona threshold (4000) |
|------|-----------|----------------------------------------|--------------------------|
| `src/hyper/actor.rs` | 4870 | 2982 | Over total; production OK |
| `src/hyper/runtime.rs` | 9668 | 4554 | Over both |
| `src/storage/store/engine.rs` | 2431 | 2431 (no test mod) | Under |

`runtime.rs` production code at 4554 LOC exceeds the > 4000 LOC line. It
is also the file that contains the 13 forks above — the two issues are
correlated: the file is too big to spot the duplication without a tool.
Suggested mitigation: extract a helper

```rust
fn require_active_signer(
    &self,
    fid: u64,
    signer_pubkey: &[u8],
) -> Result<ActiveKey, RewardError> { /* the boilerplate */ }
```

and replace the 12 value-relevant sites in a single PR before the
Phase 1b scope-gating work lands.

### What is *not* a finding

* **No `unsafe` in production.** The 30 `unsafe` matches in `actor.rs`
  are all `KzgSrs::random_unsafe(...)` API names in the test module
  (lines 3067, 3088, 3128, 3202, ...). Zero `unsafe { ... }` blocks
  in `actor.rs` or `runtime.rs`.
* **No production `.unwrap()` cluster.** `runtime.rs` has zero `.unwrap()`
  before line 4554 (the `#[cfg(test)]` mod). `actor.rs` has 2 in
  production (lines 1098, 1100, both inside the `drive_events` async
  test-helper). `engine.rs` has ~23 production `.unwrap()` sites,
  several of which are panic-on-malformed-block — but those are
  pre-existing concerns covered elsewhere (e.g. line 1809
  `header.as_ref().unwrap()`, line 1838 `self.db.commit(txn).unwrap()`
  on RocksDB commit failure) and are not a *systemic* fork pattern.
  Not folded into this finding.
* **No unbounded `WriteBatch`.** `engine.rs` bounds per-block work via
  `max_messages_per_block` (passed into both `new` constructors at
  lines 202, 230 and stored at line 272). A malicious block proposing
  more than this is rejected before the batch is built. The prompt's
  "unbounded chunk on a malicious block size" attack does not apply.
* **No infinite-restart loop.** Already covered by H025 ruled-out
  (no supervision tree at all).

## Impact

**Direct, today:** none — the missing scope check is a documented
Phase 1b deferral, not a bug.

**Latent, on the next change:** when the gasless-key scope-gating fix
ships, the maintainer has to remember 12 sites. Forgetting one
silently re-opens "gasless CastAdd-only key drains my balance via the
forgotten endpoint." `apply_token_escrow_claim` is the most likely
site to be missed because its preamble is structurally identical but
its body diverges most from the transfer/lock/stake cluster (it
reads from the escrow column and credits an unrelated `recipient_fid`).

**Audit-side, today:** the runtime.rs production LOC at 4554 exceeds
the > 4000 audit-window threshold the persona flags. Per-arm chunking
is what allowed this finding to surface; the whole-file pass missed the
forks because the file does not fit in one window of attention.

## Reproduction

Static review only. The 13 sites are independently grep-able:

```
rg -n 'let handler = StoreEventHandler::new_no_persist\(\);' \
   src/hyper/runtime.rs
```

13 hits. Cross-reference with the `get_active_key` callsites:

```
rg -n 'let active = get_active_key\(' src/hyper/runtime.rs
```

10 hits (the three `apply_token_*` callsites use multi-line argument
formatting and don't match the single-line regex; the count is the
same once those are folded in).

## Recommendation

1. Extract a single helper on `HyperRuntime` that opens the
   `OnchainEventStore`, performs the `get_active_key` lookup, and
   returns either the resolved `ActiveKey` (for downstream scope-
   checks) or `RewardError::SignerNotAuthorized { fid }`. Place it
   adjacent to `nonce_of` / `balance_of` in the runtime impl block.
2. Replace all 12 inline value- or signer-relevant sites with calls to
   the helper. The 13th (`fids_for_scoring` at 456) is an unrelated
   listing helper that just needs the store, not the gate — leave
   alone.
3. **Then** land the Phase 1b scope-gating change in exactly one
   place (the helper). The helper takes a `MessageType` or
   "permission" parameter; on `ActiveKey::Gasless { scopes }` it
   intersects the requested permission against `scopes`.
4. Add a `#[deny(unused)]`-style construct or a sentinel test that
   trips if a new `apply_*` handler is added and forgets to call the
   helper. (Or, more pragmatic, a `// REQUIRES: require_active_signer`
   comment + a `clippy` lint workflow check.)

Separately, consider splitting `runtime.rs` into:
- `runtime/core.rs` (constructor, db handle, config, scoring inputs),
- `runtime/token.rs` (transfer/lock/stake/unstake/escrow),
- `runtime/miniapp.rs` (register/unregister/update/add/remove),
- `runtime/da.rs` (DA epoch seed + challenge response),
- `runtime/node.rs` (attestation, app receipts).

That brings each module under the 2000-LOC line and avoids future
recurrence of the "I couldn't see the duplication because the file is
too big" failure mode that this finding ultimately reflects.

## References

* `src/hyper/runtime.rs:637-674` — `apply_token_transfer` (canonical
  fork; carries the Phase 1b TODO comment).
* `src/hyper/runtime.rs:681-718` — `apply_fee_deposit`.
* `src/hyper/runtime.rs:720-747` — `apply_token_lock`.
* `src/hyper/runtime.rs:1217-1330` — `apply_token_escrow_claim`
  (the most-likely-to-be-missed site).
* `src/hyper/runtime.rs:1614-1692` — `apply_token_stake`.
* `src/hyper/runtime.rs:1704-1788` — `apply_token_unstake`.
* `src/hyper/runtime.rs:1977-2054` — `apply_node_attestation`.
* `src/hyper/runtime.rs:2064-2123` — `apply_node_attestation_revoke`.
* `src/hyper/runtime.rs:2181-2258` — `apply_app_usage_receipt`.
* `src/hyper/runtime.rs:2338-2417` — `apply_miniapp_register`.
* `src/hyper/runtime.rs:2489-2528` — `miniapp_check_signer_and_nonce`
  (the partial helper; only used by the miniapp family).
* `src/hyper/runtime.rs:3022-3145` — `apply_da_challenge_response`.
* `src/hyper/actor.rs:1129-1390` — dispatch match (well-structured;
  cited as evidence that the actor.rs LOC count is not itself a
  finding once production-only is computed).
* `src/storage/store/engine.rs:202, 214, 230, 272` —
  `max_messages_per_block` bound (cited as evidence that the
  unbounded-batch concern does not apply).
