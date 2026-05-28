# Revalidation — commit `4a7d9c6` ("resolve blocking test failures + audit feedback")

**Round 5 of fix-revalidation on PR #28** (farcasterorg/hypersnap, branch `pow`).
**Commit:** `4a7d9c6cb00260fa362645d743ce3c51a4d9299a` — Cassandra Heart.
**Parent:** `f2b062c8` (our R4 base). Direct single child.
**Working tree:** checked out at `4a7d9c6`. (`git checkout 6cff47c` for pristine base.)
**Scope:** 12 files, +411/−244. Split between *audit feedback* (epoch/supervisor/runtime) and *blocking test failures* (mostly F058 stale-test cleanup). Diffs: `.audit/pr28-4a7d9c6-delta.diff`, `.audit/pr28-4a7d9c6-full.diff`.

```
crates/proof-of-quality/src/eligibility.rs |   8   (prod: < -> <=, tiny-cohort calibration)
crates/proof-of-quality/src/fees.rs        |  11   (test-only: f64 tolerance)
crates/proof-of-quality/src/uniqueness.rs  |  17   (test-only: longer near-dup strings)
src/hyper/actor.rs                         | 100   (HighestInstalledDklsEpoch query; epoch offset; F058 tests)
src/hyper/dkls_supervisor.rs               | 140   (F024 BTreeMap watchdog + cold-start; F004 anchor snapshot)
src/hyper/epoch.rs                         |  97   (epoch_for_with_offset / with_cutover primitives + tests)
src/hyper/http_handler.rs                  |  16   (test-only: F058 POST seal)
src/hyper/poq_integration_test.rs          |  10   (test-only: loosen synthetic-cohort gates)
src/hyper/router.rs                        |  40   (test-only: F058 router seal assertions)
src/hyper/runtime.rs                       | 209   (F026 party-helpers; F058 tests; F135 fixtures)
src/hyper/scheduler.rs                     |   4   (epoch offset)
src/main.rs                                |   3   (wire cutover into scheduler + supervisor)
```

---

## HEADLINE: ❌ the F004 cutover-offset fix is a BROKEN-FIX — latent chain-liveness bug at mainnet cutover

R5 **builds clean** (`cargo +nightly check --bin hypersnap` → EXIT_CODE=0, zero errors, 14m13s; `.audit/build-wsl-4a7d9c6-nightly.log`) — second round in a row. But a green build is exactly what masks this finding: every test fixture uses `cutover_snapchain_block = 0`, so the bug is invisible to CI.

R5 introduced the correct primitives — `epoch_for_with_offset`, `epoch_start_block_with_offset`, `EpochManager::with_cutover`, `EpochManager::from_anchor_with_cutover` (epoch.rs) — and threaded the cutover offset into the **peripheral** timing loops:
- `actor.rs` `maybe_trigger_scoring` / `maybe_sign_da_epoch_seed` / `maybe_trigger_da_responses` (→ `epoch_for_with_offset(anchor, cutover)`),
- `dkls_supervisor.rs` run loop (`epoch_for_with_offset` + `epoch_start_block_with_offset`),
- `scheduler.rs` refresh loop, wired from `main.rs`.

**It never wired the offset into the runtime's authoritative `epoch_resolver`.** At `runtime.rs:339`, `HyperRuntime::new` still builds `EpochManager::new()` (cutover = 0). That resolver is the single source of `current_epoch()` for the consensus-critical paths: block signing (`runtime.rs:4824`), scoring attestation (`2262`), unstake maturation, DA-PoW response acceptance, router current_epoch.

### Mechanism (all verified in code)
1. At cutover, genesis DKLS material is keyed at **epoch 0**: `apply_cutover` → `install_dkls_group_address(0, genesis_group_address)` (`runtime.rs:4277`); genesis committee shares → `install_local_dkls_share(0, …)` (`genesis.rs:88`). The code comment at 4275 even states the intent: *"Anchored at the cutover snapchain block so the epoch resolver knows where epoch 0 begins."*
2. The resolver does **not** know — it lacks the offset. `apply_cutover` calls `epoch_resolver.observe_anchor(cutover_block)` (`4278`); with `cutover_block = 0` inside the `EpochManager`, that computes `epoch_for_with_offset(cutover, 0) = cutover / EPOCH_LENGTH`.
3. The signing path (`produce_signed_block_dkls_local`, `runtime.rs:4824-4829`) does `dkls_signers.get(&epoch_resolver.current_epoch())` → looks up the *raw* epoch → **misses** the genesis share at epoch 0 → `RuntimeProduceError::NoDklsShare`.
4. No self-heal: the supervisor dispatches/installs DKG keyed on **offset** epoch numbers, while the signer looks up **raw** numbers — they never converge for `cutover ≠ 0`.

### ✅ Runnable PoC (behavioral witness — not just a trace)
Inserted a focused test into `runtime.rs` mod tests, ran it on nightly WSL against the **real** `apply_cutover` + `produce_signed_block_dkls_local`, then restored the tree.
Source: `.audit/f004_cutover_poc.rs` · Log: `.audit/f004-poc-4a7d9c6.log`.

```
cutover=5000000 EPOCH_LENGTH=432000
epoch_for_with_offset(cutover, cutover) = 0   <- genesis keyed here
rt.epoch_resolver.current_epoch()       = 11  <- signer looks up here
produce_signed_block_dkls_local => Err(NoDklsShare)
test ... ok   (1 passed)
```

### Trigger / blast radius
- Fires whenever `cutover_snapchain_block ≥ EPOCH_LENGTH` (432,000) — i.e. **any real mainnet cutover** (snapchain mainnet is far past 432k blocks). `apply_cutover` itself errors out when cutover == 0 (`runtime.rs:4261`), so production *must* configure a nonzero cutover.
- Invisible to the suite: all fixtures use cutover=0; devnet uses cutover=1 (< EPOCH_LENGTH → maps to epoch 0, so devnet looks fine). `apply_cutover` has **zero** direct test coverage anywhere in the tree.
- Severity: chain cannot produce its first post-cutover block → **launch-day liveness halt**. Latent until the real cutover height is configured.

### One-line fix
```rust
// runtime.rs:339
let manager = EpochManager::with_cutover(config.cutover_snapchain_block);
```
i.e. call the constructor R5 already added for exactly this purpose but never used in `HyperRuntime::new`. (Confirm restart/`from_anchor` paths likewise carry the cutover.)

---

## ✅ Fixed by R5 (verified)

### F026 party-helper twins — FIXED (R4's only concrete wheelhouse miss → closed)
`transport_pubkey_for_party` (`runtime.rs:1206`) and `peer_id_for_party` (`~1228`) now resolve against `get_active_validators_enforced(epoch, …)` instead of the raw `compute_active_set`. The stale "same ordering" comment was removed and replaced with one correctly citing the enforced set.
- **Verified ordering equivalence.** Committee party indices are assigned over `client.active_validators(epoch, true)` (`dkls_supervisor.rs` build_driver, `active.keys().enumerate()`) → `HyperActorQuery::ActiveValidators{enforced:true}` → `actor.rs:1700-1702` `active_validators_enforced` → `get_active_validators_enforced` — the **identical** key-sorted `BTreeMap` the helpers now `nth()` into. Party-index → validator-key mapping is now consistent across signing, read-path slash resolution (R4), and the transport/peer helpers.

### F024 — both sub-residuals FIXED
- **Watchdog "last epoch of a burst only".** `dispatched: Option<Dispatched>` → `dispatched: BTreeMap<u64, u32>` (epoch → ticks). The watchdog now iterates **every** dispatched epoch and re-dispatches each that times out (`DKLS_RETRY_AFTER_TICKS`). A burst of catch-up DKGs is fully tracked.
- **Current-epoch skip on cold start.** New actor query `HighestInstalledDklsEpoch` (returns `dkls_signers.keys().next_back()`); `first_undispatched = (highest_installed + 1).min(current_epoch + 1)` on cold start. A mid-epoch cold start now dispatches from the current epoch rather than skipping it. Anchor-jump catch-up (R2 fix) preserved — past targets have `blocks_until_target = 0 ≤ lead`, so they dispatch rather than break.

### F004 build_driver double-read race — FIXED
`build_driver` now takes an `anchor_snapshot: u64` argument; the run loop snapshots `anchor` **once per tick** and threads it through. The inner second read (`let anchor_at_install = *inputs.latest_anchor.lock().await`) is deleted — comment: *"eliminating the double-read race (F004)."*

### F058 — intact + now test-covered (the "blocking test failures")
Production seal confirmed at `router.rs:133`: `route_inbound` rejects `Body::Lock(_)` with `RoutingError::Lock`. R5 corrects ~15 stale tests across `actor.rs` / `http_handler.rs` / `router.rs` / `runtime.rs` that still asserted transparent locks reach the mempool; they now assert the sealed behavior (mempool empty, `EventError`, `pending = 0`). These were the "blocking test failures." No production-logic change — hardening only.

### F135 — test fixtures hardened (verdict unchanged)
`build_valid_da_response` now threads a real `fid_count` (`build_valid_da_response_with_fid_count` + `seed_id_register` to register FIDs so `count_registered_fids()` matches), replacing R3's `u32::MAX` placeholder. The R4 verdict stands: frozen-count fixed; **magnitude still NEEDS-RUNTIME** (devnet measurement not yet executed).

---

## Carried residuals (untouched by R5)
- **F004 dual-anchor desync** — supervisor `latest_anchor: Arc<Mutex<u64>>` vs scheduler `LatestAnchor` remain two separate sources. Untouched.
- **gRPC auth off-by-default** (`server.rs:409`) — the IP limiter remains the sole default gate. Untouched.
- **F009 single-layer defense** — L2 sqrt-damping still distribution-blind/inert (defense rests entirely on the L0 trust floor). The eligibility `<` → `<=` change (`eligibility.rs:131`) is a benign tiny-cohort calibration fix (lets a zero-new-user-share FID pass a zero threshold), **not** sybil-related and not a weakening of the spam gate (high-share farms still strictly exceed any nonzero threshold).
- **F023 phase-3 plaintext-broadcast caveat** — untouched.

## Regressions
**None.** F058 seal, F026 read-path (R4), F031 interceptor wiring (R4), F135 frozen-count (R4) all intact. The poq `fees.rs`/`uniqueness.rs`/`poq_integration_test.rs` edits are test-only.

---

## Re-report set after R5 (for R6)
1. **F004 cutover-offset BROKEN-FIX — blocker** (one-liner: `EpochManager::with_cutover` at runtime.rs:339). PoC-confirmed launch-day liveness halt. *Top priority.*
2. F004 dual-anchor desync (carried).
3. gRPC auth off-by-default (carried).
4. F135 runtime magnitude measurement (devnet now available).
5. F009 single-layer-defense caveat (carried).
6. F023 phase-3 broadcast caveat (carried).

**Bottom line:** R5 cleanly closes the audit-feedback items it set out to fix (F026 twins, F024 ×2, F004 double-read) and is the second compiling round — but the F004 cutover-offset fix is **incomplete in the one place that matters most**, turning a known residual into a PoC-confirmed, latent chain-halt at mainnet cutover. This is **not** the last commit.
