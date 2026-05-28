# Revalidation — commit `a1e866ab` ("latest audit pass")

**Round 6 of fix-revalidation on PR #28** (farcasterorg/hypersnap, branch `pow`).
**Commit:** `a1e866ab31d121bf846a5e81adfb71b22c40d631` — Cassandra Heart, 2026-05-28 06:31 CDT.
**Parent:** `4a7d9c6` (our R5 base). Direct single child.
**Working tree:** checked out at `a1e866ab`. (`git checkout 6cff47c` for pristine base.)
**Scope:** 9 files, +458/−49 — surgical, every change maps to an R5 residual. Diffs: `.audit/pr28-a1e866ab-delta.diff`, `.audit/pr28-a1e866ab-full.diff`.

```
crates/proof-of-quality/src/lib.rs     |  35   (F009 L2: growth_distribution_skew_exponent param + default 2.0)
crates/proof-of-quality/src/metrics.rs |  38   (F009 L2: normalized_entropy_of_values)
crates/proof-of-quality/src/scoring.rs | 176   (F009 L2: entropy damping in compute_growth_harmonic + tests)
src/cfg.rs                             |   9   (gRPC/HTTP default bind 0.0.0.0 -> 127.0.0.1)
src/hyper/dkls_supervisor.rs           |  14   (F004: shared LatestAnchor, read .block)
src/hyper/dkls_wire_codec.rs           | 115   (F023 phase-3: DISCRIMINATOR_SIGN_BROADCAST digest binding + tests)
src/hyper/poq_integration_test.rs      |   8   (test fixture: skew_exp = 0.0 for synthetic cohort)
src/hyper/runtime.rs                   |  81   (F004: EpochManager::with_cutover + regression test)
src/main.rs                            |  31   (F004: collapse dual-anchor into one shared LatestAnchor)
```

---

## HEADLINE: ✅ the R5 F004 cutover BROKEN-FIX is now correctly fixed — runtime-verified

R5's headline blocker was that `HyperRuntime::new` built the authoritative `epoch_resolver` with `EpochManager::new()` (cutover = 0) while genesis DKLS material is keyed at epoch 0, so at any mainnet cutover (`≥ EPOCH_LENGTH = 432_000`) the signer looked up the *raw* post-cutover epoch, missed the genesis share, and the chain halted with `NoDklsShare` on the first block. I PoC-confirmed that halt against R5.

**R6 applies exactly the one-line fix I recommended** at `runtime.rs:339`:

```rust
// R5:  let manager = EpochManager::new();
// R6:
let manager = EpochManager::with_cutover(config.cutover_snapchain_block);
let epoch_resolver = EpochResolver::new(manager);
```

`EpochManager::with_cutover` stores the cutover and `observe_anchor` offsets through `epoch_for_with_offset(anchor, cutover_block)` (epoch.rs:67, 101). So post-cutover `epoch_resolver.current_epoch()` returns 0 — matching where the genesis share lives — and advances cutover-relative thereafter. The signing path (`runtime.rs:4832`) reads that same resolver, so `dkls_signers.get(&0)` now hits.

### Runtime verification (not just a source trace)

R6 ships a regression test that encodes my R5 PoC scenario, and **it passes**:

```
test hyper::runtime::tests::cutover_aware_resolver_reports_epoch_zero_post_cutover ... ok
test result: ok. 1 passed; 0 failed; ... finished in 1.57s
```

The test uses `cutover = 5_000_000` (≥ EPOCH_LENGTH), calls real `apply_cutover`, asserts `epoch_resolver.current_epoch() == 0`, installs the genesis share, and asserts `produce_signed_block_dkls_local(...)` returns **Ok** — the exact inverse of my R5 PoC, which asserted `Err(NoDklsShare)` against the broken code. This test would have **failed** on R5 (current_epoch would be 11), so it is a genuine regression guard, not a vacuous fixture. The `apply_cutover` path — previously zero test coverage — is now exercised at a mainnet-shaped cutover. Source: `runtime.rs:4969`.

### Build status: ✅ COMPILES (3rd round running)

`cargo +nightly check --bin hypersnap` → **Finished in 13m19s, 0 errors** (warnings only). `.audit/build-wsl-a1e866ab-nightly.log`. The R5→R6 signature ripple (F009 6th arg, main.rs anchor refactor) type-checks cleanly. Setup unchanged: WSL, malachite sibling 13bca14c, `target-wsl` in-tree, nightly (stable 1.95 still ICEs ed448).

---

## Per-residual verdicts

### ✅ F004 dual-anchor desync — FIXED
R5 left two anchor sources that could disagree by a full epoch between the poller's two non-atomic writes: the scheduler's `Arc<Mutex<LatestAnchor>>` and the supervisor's separate `Arc<Mutex<u64>>`. R6 collapses them into **one shared `Arc<Mutex<LatestAnchor>>`** (main.rs `build_hyper_handler` + `spawn_anchor_poller`; `DklsSupervisorInputs.latest_anchor` retyped). The supervisor reads `inputs.latest_anchor.lock().await.block` (dkls_supervisor.rs:74). Semantics preserved: `LatestAnchor.block` (scheduler.rs:41) ← `meta.snapchain_anchor_block` (main.rs:1655), identical to the value the old `u64` mutex held, and the value `epoch_for_with_offset` consumes. The single-mutex poller write (main.rs:1659) is now atomic across both readers. No use-after-move (`shared_anchor` is `.clone()`d into poller + scheduler, moved into supervisor last). Confirmed by the clean bin compile.

### ✅ F009 single-layer-defense caveat — ADDRESSED (with a new, narrower residual)
R5's "Layer 2" (`sqrt(n)/n` count damping) was distribution-blind — it gave a popular legit user with 99 real crediters the *identical* penalty as a 99-member ring, and the `max_growth_fraction_per_crediter` knob was inert (unused-variable warning). The actual sybil defense rested entirely on **L0** (the `crediter_trust_threshold = 0.05` floor; my R5 sim measured the ring at trust 0.0057, already killed there).

R6 replaces L2 with a **distribution-aware entropy damping**: it computes the normalized Shannon entropy `H_norm` of the per-crediter contribution vector and multiplies growth by `(1 − H_norm)^growth_distribution_skew_exponent` (default 2.0), composed with the existing `sqrt(n)/n` (scoring.rs:216–256; new `normalized_entropy_of_values` in metrics.rs). A uniform-contribution ring (`H_norm ≈ 1`) is damped toward zero; a skewed real-user distribution keeps most of its mass. The old knob is now `_max_growth_fraction_per_crediter`. The two shipped unit tests pass.

**Verified by run + independent probe** (executed, then tree restored):
| recipient shape | growth (L2 on, skew=2.0) |
|---|---|
| uniform sybil ring (50 equal crediters) | **0.0** |
| uniform *legitimate* user (50 equal real crediters) | **0.0** |
| skewed legitimate user (1 whale + tail) | 0.0066 (survives) |
| uniform legit, L2 **off** | 16.96 |

**New residual (fairness / false-positive, LOW severity):** the discrimination axis is contribution *uniformity*, not sybil-ness. A legitimate popular account whose many crediters engage at similar magnitudes (a creator/celebrity with equal-weight fans) is structurally **indistinguishable from a uniform ring** and is damped to exactly the same 0.0 (probe: uniform-legit vs uniform-ring growth diff = 0). This is not a security hole — L0 remains the real sybil gate and the affected user only loses the *growth* component, not all reward — but R6 has traded R5's "no discrimination" caveat for a behavioral assumption ("legit engagement is skewed") whose failure mode penalizes a class of genuine users. Worth a config note for operators; `skew_exponent = 0` recovers count-only behavior. Probe lives at `.audit/f009-r6-probe.log` (reproduced below).

### ✅ F023 phase-3 broadcast caveat — FIXED (structural, narrow residual)
R5 fixed the encrypted sign rounds (digest in AEAD AAD) but the phase-3 *plaintext broadcast* arm (`receiver == None`) was still digest-unbound, so a phase-3 frame from co-running ceremony D_A could be injected into a driver signing D_B (same epoch) → liveness grief. R6 adds `DISCRIMINATOR_SIGN_BROADCAST = 2` with the wire layout `[disc][digest_32B][raw]` (dkls_wire_codec.rs). The receiver rejects frames whose prefix digest ≠ active driver digest (`SignBroadcastDigestMismatch`) or that are truncated (`SignBroadcastTruncated`) **before** deserialization. Both seal (actor.rs:2587, `driver.coordinator.digest()`) and open (actor.rs:1504, `active_sign.coordinator.digest()`) thread the active digest. The two codec tests pass:
```
test hyper::dkls_wire_codec::tests::sign_broadcast_cross_digest_rejected ... ok
test hyper::dkls_wire_codec::tests::sign_broadcast_truncated_rejected ... ok
```
**Residual (acknowledged in-code):** the binding is structural, not cryptographic — the digest is public, so an attacker who knows D_B can still craft a correctly-prefixed frame. But that only reaches the same liveness abort the protocol already tolerates; forgery remains blocked by the dkls23 `mul_sid` abort + F018 sender binding. Adequate for the stated cross-routing/liveness vector.

### ◑ gRPC auth off-by-default — MITIGATED (not eliminated)
R6 changes the default bind in cfg.rs from `0.0.0.0` to `127.0.0.1` for both the gRPC (`rpc_address`) and HTTP (`http_address`) RPC ports. gRPC auth still ships off (`server.rs` `rpc_auth = ""`), but the out-of-the-box posture is now loopback-only, so an operator must consciously expose the port (ideally behind a reverse proxy / mTLS, as the new comment states). Defense-in-depth improvement; the underlying "auth opt-in" design is unchanged.

### ◑ F135 reward-magnitude — UNTOUCHED, still NEEDS-RUNTIME
No `da_*` / fid-count changes in this delta. R4's `fid_count_fn` live-recompute fix stands; the magnitude question (does the producer/verifier prefix derivation diverge under real registry growth?) remains a runtime measurement, now possible via the R3 devnet tooling. Not run this round.

---

## Regressions: 0
R6's 9-file delta does not touch `router.rs` (F058 `Body::Lock` reject), and the only non-test change in `runtime.rs` is the 1-line `EpochManager::with_cutover` swap. So the R1–R5 fixes for **F058, F133, F138, F026 (read-path + party-helper twins), F036, F108, F024** are structurally untouched. The clean bin compile confirms no signature/type regressions from the F009 and anchor-refactor ripples.

---

## Re-report set after R6 (for any R7)

R6 closes every concrete code bug from the R5 re-report set. What remains is caveats and one untested magnitude:

1. **F009 L2 false-positive (LOW, fairness):** uniform-engagement legit users damped identically to rings. Behavioral-assumption risk, not a security hole. Consider documenting / tuning `growth_distribution_skew_exponent`.
2. **F135 magnitude (NEEDS-RUNTIME):** measure producer/verifier prefix agreement under registry growth on devnet.
3. **gRPC auth off-by-default:** loopback bind mitigates exposure; auth is still opt-in.
4. **F023 structural-binding residual:** knowledgeable-attacker liveness grief (attributable, bounded).

No blocker-class finding remains. The launch-day chain-halt (the R5 headline) is closed and runtime-verified.

---

## Verification artifacts
- `.audit/build-wsl-a1e866ab-nightly.log` — `cargo +nightly check --bin hypersnap` (13m19s, 0 errors) + F004 regression test pass.
- `.audit/pr28-a1e866ab-delta.diff`, `.audit/pr28-a1e866ab-full.diff` — R5→R6 and base→R6 diffs.
- F009 probe + F023 codec tests run on the cached `target-wsl` lib-test binary (nightly) and `target-wsl-f009` (stable, proof-of-quality).
</content>
</invoke>
