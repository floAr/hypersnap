---
id: F012
task: H012
specialist: chain-economics
attack_class: emission-budget-cap-missing
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# `apply_retro_vesting_tranche` mints to balances without consulting `max_reward_per_epoch` / `max_reward_per_epoch_per_market`, defeating the `BudgetExceeded` defense-in-depth cap

## Summary

`HyperRuntime::apply_reward_issuance` enforces a per-market and a global
per-epoch cap (`max_reward_per_epoch_per_market`, `max_reward_per_epoch`)
that raise `RewardError::BudgetExceeded` if `Σ entries.amount +
already_issued > cap`. The retroactive-vesting path
(`HyperRuntime::apply_retro_vesting_tranche`, FIP §10.5) reaches
`RewardStore::credit_if_unissued` directly without consulting **either**
cap. The retro market (`WorkMarket::Retroactive`) does inherit the same
issued-key namespace, so its credits count *against* the global cap when
the cap is later consulted by `apply_reward_issuance` — but the retro
path itself never reads the cap before minting. The net effect: an
operator who calibrates a `max_reward_per_epoch` defense-in-depth limit
gets no protection on the retro tranche, and a buggy/corrupted retro
CSV (or a future epoch where `remaining_atoms / remaining_tranches`
unexpectedly explodes) can mint past the cap and then *additionally*
starve the live `Growth` issuance for the rest of that epoch (because
the global cap reader sums all markets).

This is the textbook `emission-budget-cap-missing` shape from the
chain-economics checklist: the budget cap exists, raises a typed error,
and is enforced on *one* branch of the credit emitter but not on the
parallel branch.

## Description

There are exactly two production code paths that increment a FID's
primary `HyperRewardBalance` via the issued-key replay store:

1. **Threshold-signed live issuance.** `HyperRuntime::apply_reward_issuance`
   (`src/hyper/runtime.rs:504`) verifies the DKLS23 group-key signature
   over the issuance payload, then sums new (`!was_issued`) entries into
   `new_amount`, checks
   `already_in_market.saturating_add(new_amount) > market_cap`
   (`src/hyper/runtime.rs:528-544`) and the global
   `already_global.saturating_add(new_amount) > global_cap`
   (`src/hyper/runtime.rs:547-557`), and only then calls
   `credit_if_unissued`. **Both caps are consulted before any state
   mutation; rejection is wholesale.**

2. **Retroactive vesting tranche.** `HyperRuntime::apply_retro_vesting_tranche`
   (`src/hyper/runtime.rs:4062-4111`) iterates every persisted
   `HyperRetroactiveRecord`, computes
   `tranche = rec.remaining_atoms / remaining_tranches` (or the full
   residual on the final epoch), and calls
   `self.reward_store.credit_if_unissued(epoch, rec.fid,
   WorkMarket::Retroactive as i32, tranche)` directly
   (`src/hyper/runtime.rs:4101-4103`). The function **does not read**
   `self.max_reward_per_epoch_per_market`, **does not read**
   `self.max_reward_per_epoch`, and **does not sum new_amount** before
   minting. There is no `BudgetExceeded` branch on this path. The
   schedule helper that the rest of the codebase uses for emission
   accounting (`src/emission/schedule.rs::market_budget`) explicitly
   returns 0 for `WorkMarket::Retroactive` (`src/emission/schedule.rs:114`),
   so any cap configuration keyed by market budget gives the operator a
   false sense that *something* is rate-limiting retro — nothing is.

### Where credits land in the issued-key namespace

Both paths use the same key layout
(`RewardStore::issued_key(epoch, fid, market)`,
`src/hyper/rewards.rs:83-90`) and the same balance key
(`RewardStore::balance_key`, `src/hyper/rewards.rs:69-74`). The
distinction is *only* the `market` discriminant in the 4-byte suffix.
That means:

* `RewardStore::issued_total_for_epoch_market(epoch, Growth)`
  (`src/hyper/rewards.rs:122-154`) filters by market suffix and does
  **not** see retro credits, so the per-market cap behaves as documented
  — but only because retro is in a different market bucket.
* `RewardStore::issued_total_for_epoch(epoch)`
  (`src/hyper/rewards.rs:158-181`) sums **every** key under that
  epoch prefix regardless of market. Retro credits applied earlier in
  the same epoch therefore count against the **global** cap. Because
  retro fires from `EvaluateEpochDkls` in `src/hyper/actor.rs:1197`
  *before* `run_scoring` and the resulting growth issuance
  (`src/hyper/actor.rs:1209-1210`), the ordering is:

  ```
  EvaluateEpochDkls(epoch)
    └─ apply_retro_vesting_tranche(epoch)              # no cap check, mints
    └─ run_scoring + apply_and_broadcast_scoring_output # cap-checked
  ```

  So a too-large retro tranche silently inflates `issued_total_for_epoch`
  *before* the live growth issuance arrives, and the live growth issuance
  is **then** rejected with `BudgetExceeded`. The growth committee has
  no way to recover within that epoch — the retro path has already
  committed the over-spend.

### Sources of "too large" retro

The retro CSV is operator-loaded at cutover (`src/hyper/retro_store.rs:9-13`)
and persisted; there is no on-chain validation that
`Σ remaining_atoms ≤ retro_supply_share`. The vesting math
(`tranche = rec.remaining_atoms / remaining_tranches` with a
final-epoch sweep `tranche = rec.remaining_atoms`,
`src/hyper/runtime.rs:4093-4097`) means:

1. **Final-epoch sweep.** On the epoch where `remaining_tranches == 1`,
   *every* retro FID pays out their entire remaining balance in one
   block. Even if average per-epoch retro fits within
   `max_reward_per_epoch`, the final tranche multiplies it by the number
   of remaining tranches' worth of stranded atoms. This is the most
   likely real-world breach.
2. **Operator-supplied amounts.** A corrupted, mis-pasted, or malicious
   retro CSV (no signature, no on-chain quorum on the values themselves)
   propagates straight into `credit_if_unissued` with no budget check.
   The only check is per-FID balance overflow
   (`src/hyper/rewards.rs:198-199`).
3. **Re-seeding semantics.** `RetroStore::seed_records` is documented as
   idempotent on identical input (`src/hyper/retro_store.rs:18-19`), but
   re-seeding with *different* values overwrites and there is no rule
   preventing post-cutover bumps of `remaining_atoms` if the operator
   has DB access — at which point the next tranche silently mints the
   bumped amount.

### Why this is the `emission-budget-cap-missing` attack class

The class checklist (`.claude/agents/specialists/chain-economics.md:63-67`)
flags exactly this shape:

> Per-market or per-epoch reward budgets prevent runaway emission. A
> single-party DKLS / 1-of-1 signing path without `Σ entries.amount ≤
> market_budget(epoch, market)` check lets the operator issue unbounded
> rewards.

The retro tranche distribution has no DKLS signature at all — it runs
on every node as a deterministic state transition from
`EvaluateEpochDkls` — but the *operator* gets to dictate the per-FID
amounts at genesis seeding and re-seeding time, and there is no in-band
quorum on the total. The cap predicate that should bound this
(`Σ tranche ≤ market_budget(epoch, Retroactive)`) is wired through a
function that returns 0 by design (`src/emission/schedule.rs:114`) and
is not consulted from the credit path anyway. Concretely, the
checklist's "single-party … without `Σ entries.amount ≤ market_budget`
check" is *literally* this code:

```rust
// src/hyper/runtime.rs:4101-4103 (no surrounding cap check)
self.reward_store
    .credit_if_unissued(epoch, rec.fid, market, tranche)
    .map_err(|e| RuntimeRetroVestError::Reward(e.to_string()))?;
```

## Impact

* **Defense-in-depth bypass.** An operator-configurable safety net
  (`max_reward_per_epoch`) is silently inert on what is, by atom count,
  one of the largest credit paths in the chain's first 29 post-cutover
  epochs (§10.5 vesting schedule). Operators who set
  `max_reward_per_epoch` reasonably expect "no emission past this
  amount this epoch"; the retro path violates that contract.
* **Cross-path starvation.** Because the global cap reader
  (`issued_total_for_epoch`) sums *all* markets in the epoch, an
  unexpectedly-large retro tranche pre-emptively consumes the global
  budget and causes the legitimate threshold-signed Growth issuance for
  that epoch to be rejected with `BudgetExceeded`
  (`src/hyper/runtime.rs:550-555`). Growth participants miss an entire
  epoch's emission with no on-chain recourse — the committee cannot
  resubmit a smaller batch in time because the retro mint is already
  committed in the same `EvaluateEpochDkls` event.
* **Final-tranche cliff.** The final retro epoch
  (`remaining_tranches == 1`) sweeps every FID's residual atoms
  (`src/hyper/runtime.rs:4093-4097`). For 29 epochs ≈ 145 days at 5
  days/epoch, that's a single block on day 145 where the total minted
  in one transition equals the sum of all stranded retro residuals.
  Without a cap check this can be arbitrarily larger than
  `emission_per_epoch(final_epoch)` from the schedule curve.
* **No mempool-side or DKLS-side filter.** Unlike live issuance, retro
  has no threshold signature whose verification step could be made to
  enforce a cap — the only logical place to enforce it is in
  `apply_retro_vesting_tranche` itself, which currently does not.

Severity: **medium**. The defense-in-depth budget is currently `None`
in every production config we inspected (`src/hyper/config.rs:443`,
`src/hyper/genesis.rs:118`, `src/hyper/actor.rs:3004,3806,3859`,
`src/hyper/scheduler.rs:561`, `src/hyper/dkls_driver.rs:133`,
`src/hyper/http_handler.rs:1409`, `src/hyper/scoring_driver.rs:215`),
so today the bypass has no live impact — the cap is `None` for both
paths uniformly. The bug becomes a real exploit the moment an operator
turns on `max_reward_per_epoch` for safety (e.g., after an incident
postmortem). At that point the operator believes "no path mints past
this number" and the retro path will silently breach it. Calling it
**high** is reasonable if the assumption is that anyone bothering to
build a `BudgetExceeded` enum and a global-cap field intends to wire it
on before mainnet.

## Evidence

* `src/hyper/runtime.rs:504-571` — `apply_reward_issuance`, the only
  cap-enforcing credit emitter. Both market cap (lines 528-544) and
  global cap (lines 547-557) are summed against `new_amount` and raise
  `RewardError::BudgetExceeded` *before* any `credit_if_unissued` call.
* `src/hyper/runtime.rs:4062-4111` — `apply_retro_vesting_tranche`. No
  reference to `self.max_reward_per_epoch_per_market` or
  `self.max_reward_per_epoch` anywhere in the function body. The credit
  call at lines 4101-4103 is the production retro-mint path.
* `src/hyper/rewards.rs:43-50` — `RewardError::BudgetExceeded` enum
  variant. Only raised from `apply_reward_issuance`
  (`src/hyper/runtime.rs:538`, `:551`); never raised from any other
  call site (`Grep BudgetExceeded` returns exactly those two
  references).
* `src/hyper/rewards.rs:186-207` — `credit_if_unissued`. Has no
  awareness of any cap; the only failure mode is `BalanceOverflow`. It
  is the join point for both paths.
* `src/hyper/rewards.rs:158-181` — `issued_total_for_epoch` sums every
  market under the epoch prefix; this is the global-cap reader used by
  `apply_reward_issuance`. Retro credits land in the same prefix so
  they are seen here even though no cap reads it on the retro path.
* `src/hyper/rewards.rs:122-154` — `issued_total_for_epoch_market`
  filters by market suffix; retro credits do *not* spill into the
  Growth bucket, so the per-market Growth cap is consistent — only the
  global cap and any per-market Retroactive cap (if ever configured)
  are bypassed.
* `src/emission/schedule.rs:105-119` — `market_budget` returns 0 for
  `WorkMarket::Retroactive`. The module-level comment
  (`src/emission/schedule.rs:22-24`) states "Vesting tranches for the
  retroactive distribution (§10.5) flow through a separate path keyed
  on `WorkMarket::Retroactive` and do not consume from this curve."
  This is the architectural decision that *requires* the retro path to
  carry its own cap — and that cap is not present.
* `src/hyper/actor.rs:1192-1210` — `EvaluateEpochDkls` handler invokes
  `apply_retro_vesting_tranche(epoch)` *before* `run_scoring`, so retro
  credits land in the epoch's `issued_total` window before the live
  growth issuance is even computed. Any global-cap breach by retro
  therefore manifests as a rejection of the *legitimate* growth
  issuance.
* `src/hyper/runtime.rs:4093-4097` — final-tranche sweep
  (`if remaining_tranches == 1 { rec.remaining_atoms } else { ... }`).
  This is the largest single-block retro mint by design.
* `src/hyper/retro_store.rs:1-19` — retro records are operator-seeded
  at cutover from CSV with no on-chain signature, threshold, or
  quorum on the per-FID amounts.
* `src/hyper/runtime.rs:130-138, 233-235, 405-406` — definitions of
  `max_reward_per_epoch` / `max_reward_per_epoch_per_market` on both
  `HyperRuntime` and `HyperRuntimeConfig`. Wired into the runtime; not
  consulted by the retro path.
* `.claude/agents/specialists/chain-economics.md:63-67` — the attack
  class definition this finding maps to.

## Suggested remediation

1. **Enforce both caps inside `apply_retro_vesting_tranche` before any
   `credit_if_unissued` call.** Mirror the two-step pattern from
   `apply_reward_issuance`:

   ```rust
   // 1. Sum the not-yet-issued tranches for this epoch.
   let mut new_amount: u128 = 0;
   for rec in &records {
       if self.reward_store.was_issued(epoch, rec.fid, market)? { continue; }
       if rec.remaining_atoms == 0 { continue; }
       let tranche = if remaining_tranches == 1 { rec.remaining_atoms }
                     else { rec.remaining_atoms / remaining_tranches };
       new_amount = new_amount.saturating_add(tranche as u128);
   }
   // 2. Per-market Retroactive cap (if configured).
   if let Some(market_cap) =
       self.max_reward_per_epoch_per_market.get(&market).copied()
   {
       let already = self.reward_store
           .issued_total_for_epoch_market(epoch, market)?;
       if already.saturating_add(new_amount) > market_cap {
           return Err(/* BudgetExceeded */);
       }
   }
   // 3. Global cap (defense-in-depth).
   if let Some(global_cap) = self.max_reward_per_epoch {
       let already = self.reward_store.issued_total_for_epoch(epoch)?;
       if already.saturating_add(new_amount) > global_cap {
           return Err(/* BudgetExceeded */);
       }
   }
   // 4. Apply.
   ```

   Wholesale rejection (matches the `apply_reward_issuance` contract)
   is safer than partial credit: the next epoch's tranche will
   recompute correctly because `remaining_atoms` only decrements on
   successful credit.

2. **Add a retro-specific schedule cap** to `src/emission/schedule.rs`.
   The current 0 return for `WorkMarket::Retroactive` is documented as
   "Retroactive vesting flows through a separate path" — make that
   separate path actually have a `retro_market_budget(epoch)` function
   that bounds the per-epoch retro emission analytically (e.g.,
   `TOTAL_RETRO_ATOMS / RETRO_VESTING_ON_PROTOCOL_EPOCHS + slack`), and
   consult it from `apply_retro_vesting_tranche`. This catches the
   final-tranche cliff even when no operator cap is configured.

3. **Cross-path budget consistency.** Decide whether retro credits
   should count against the global `max_reward_per_epoch` or not. If
   yes (current accounting), retro must respect the cap. If no,
   `issued_total_for_epoch` should grow a market-filter variant and the
   global-cap reader at `src/hyper/runtime.rs:548` should call it with
   `markets = [Growth, DataAvailability, AppUsage]`. Either resolution
   is fine as long as the two paths agree.

4. **Reorder `EvaluateEpochDkls`** to compute the growth issuance
   *before* applying the retro tranche, or run them under a single
   transactional batch with a combined cap check. Today the
   retro-then-growth ordering means a retro overshoot starves growth
   participants of their own emission with no operator recourse.

5. **Add a regression test** in `src/hyper/runtime.rs` tests module
   that seeds a `RetroStore` whose final-epoch sweep would exceed a
   configured `max_reward_per_epoch`, calls
   `apply_retro_vesting_tranche(final_epoch)`, and asserts
   `BudgetExceeded`. Today no such test exists; the existing retro
   tests (`src/hyper/runtime.rs:5414, 5448-5590`) all run with
   `max_reward_per_epoch: None`.
