# Remaining after PR #28 round 5 (`4a7d9c6`)

R5 ("resolve blocking test failures + audit feedback") compiles clean (nightly, exit 0) and
clears the entire [REMAINING-AFTER-R4](REMAINING-AFTER-R4.md) punch list **except one** — and
the exception is a regression in the same area it set out to fix:

- ✅ **F026 party-helper twins — FIXED.** `transport_pubkey_for_party` (`runtime.rs:1206`) and
  `peer_id_for_party` (`~1228`) now resolve against `get_active_validators_enforced` instead of
  the raw `compute_active_set` — the substitution R4's callout requested. Verified the ordering
  is the same enforced, key-sorted `BTreeMap` DKLS committee party indices are assigned over
  (`active_validators(epoch, true)` → `actor.rs:1700` → `active_validators_enforced`).
- ✅ **F024 — both narrow residuals FIXED.** The watchdog is now `BTreeMap<epoch, ticks>`
  (every dispatched epoch in a burst is tracked + retried, not just the last); cold start seeds
  `first_undispatched = (highest_installed + 1).min(current_epoch + 1)` via a new
  `HighestInstalledDklsEpoch` query, so a mid-epoch cold start no longer skips the current epoch.
- ✅ **F004 `build_driver` double-read — FIXED.** `build_driver` now takes an `anchor_snapshot`
  argument; the loop snapshots the anchor once per tick and threads it through. The second
  in-`build_driver` lock acquisition is gone.

One critical item remains — **introduced by R5's attempt at the F004 cutover offset** — plus the
two carried F004 deferrals.

---

## 1. F004 — cutover-offset fix is a BROKEN-FIX (PoC-confirmed launch-day chain halt) — TOP PRIORITY

R5 built exactly the primitives the R4 callout asked for — `epoch_for_with_offset`,
`epoch_start_block_with_offset`, `EpochManager::with_cutover`, `EpochManager::from_anchor_with_cutover`
(`src/hyper/epoch.rs`) — and threaded the cutover offset into the **peripheral** timing loops:
`actor.rs` (`maybe_trigger_scoring` / `maybe_sign_da_epoch_seed` / `maybe_trigger_da_responses`),
`dkls_supervisor.rs` (run loop), and `scheduler.rs` (refresh loop, wired from `main.rs`).

**It never wired the offset into the runtime's authoritative `epoch_resolver`.** `HyperRuntime::new`
still builds `EpochManager::new()` (cutover = 0) at **`src/hyper/runtime.rs:339`**. That resolver is
the single source of `current_epoch()` for the consensus-critical paths — block signing
(`runtime.rs:4824`), scoring attestation (`:2262`), unstake maturation, DA-PoW acceptance, router
current-epoch.

**Mechanism (verified in code):**
1. At cutover the genesis DKLS material is keyed at **epoch 0** — `apply_cutover` →
   `install_dkls_group_address(0, …)` (`runtime.rs:4277`); genesis committee shares →
   `install_local_dkls_share(0, …)` (`genesis.rs:88`). The comment at `runtime.rs:4275` even states
   the intent: *"Anchored at the cutover snapchain block so the epoch resolver knows where epoch 0
   begins."*
2. The resolver does not know — it lacks the offset. `apply_cutover` calls
   `epoch_resolver.observe_anchor(cutover_block)` (`:4278`); with the manager's `cutover_block = 0`
   this yields `current_epoch() = cutover_block / EPOCH_LENGTH`, **not 0**.
3. The signing path (`produce_signed_block_dkls_local`, `runtime.rs:4824-4829`) does
   `dkls_signers.get(&epoch_resolver.current_epoch())` → looks up the raw epoch → **misses** the
   genesis share at epoch 0 → `RuntimeProduceError::NoDklsShare`.
4. No self-heal: the supervisor dispatches/installs DKG keyed on **offset** epoch numbers while the
   signer looks up **raw** numbers — they never converge for any nonzero cutover.

**Runnable PoC** (real `apply_cutover` + `produce_signed_block_dkls_local`, nightly lib test) —
source + run instructions in [`poc/F004-cutover/`](poc/F004-cutover/README.md):
```
cutover=5000000 EPOCH_LENGTH=432000
epoch_for_with_offset(cutover, cutover) = 0   <- genesis keyed here
rt.epoch_resolver.current_epoch()       = 11  <- signer looks up here
produce_signed_block_dkls_local => Err(NoDklsShare)
```

**Trigger / impact.** Fires whenever `cutover_snapchain_block ≥ EPOCH_LENGTH` (432,000) — i.e. any
real mainnet cutover (`apply_cutover` itself errors when cutover == 0, so production *must* set a
nonzero cutover). The chain cannot produce its first post-cutover block → **launch-day liveness
halt**. Invisible to CI: every test fixture uses cutover = 0, devnet uses cutover = 1 (< EPOCH_LENGTH,
maps to epoch 0), and `apply_cutover` has **zero** direct test coverage anywhere in the tree — which
is why the R4 callout's "add a regression test at a mainnet-shaped cutover height" was the load-bearing
half of that fix request.

**Fix (one line):**
```rust
// src/hyper/runtime.rs:339
let manager = EpochManager::with_cutover(config.cutover_snapchain_block);
```
This calls the constructor R5 already added for exactly this purpose but never used in
`HyperRuntime::new`. Confirm the restart / `from_anchor` recovery path likewise carries the cutover
(`from_anchor_with_cutover`). **Add the cutover regression test** (a mainnet-shaped cutover height
asserting `current_epoch() == 0` immediately post-cutover and that the genesis proposer can produce)
— the PoC above is a ready template.

---

## 2. F004 — two desynchronized anchor sources (carried, still OPEN)

Unchanged from the R4 callout: the supervisor keeps a separate anchor mutex (`Arc<Mutex<u64>>`) from
the scheduler's `LatestAnchor`; the two are written non-atomically and each derives its epoch from its
own anchor, so the two epoch views can diverge by a full epoch. R5 snapshots within each loop (closing
the intra-loop double-read) but does not collapse the two sources. Fix: a single shared anchor source.

---

## 3. F031 — gRPC auth off-by-default (carried residual, not a defect R5 targeted)

The R4-landed gRPC IP limiter is correct and gates all four methods, but gRPC auth remains
off-by-default (`server.rs:409`), so the IP limiter is the sole default ingress gate. Flagged for
completeness; enabling auth in the default config closes it.

---

## Carried caveats (informational, no code change required to be "correct")

- **F135** — frozen-count fixed R4; **DA-PoW reward hit-rate magnitude still NEEDS-RUNTIME**. The
  devnet (`run_testnet.sh`) added in R3 makes this measurable; not yet executed.
- **F009** — three-layer sybil defense; executed sim (R3) confirms the ring is starved by the **L0
  trust floor**. The L2 sqrt-damping is distribution-blind/inert (the `max_growth_fraction_per_crediter`
  param is literally unused), so the defense rests entirely on L0 — acceptable but single-layered.
- **F023** — cross-digest sign routing closed; the phase-3 plaintext-broadcast arm (`receiver = None`)
  remains digest-unbound → contained liveness-grief, no forgery.
