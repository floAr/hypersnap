# Remaining after PR #28 round 6 (`a1e866ab`)

R6 ("latest audit pass") compiles clean (nightly, `cargo +nightly check --bin hypersnap` → exit 0,
13m19s) and clears the entire [REMAINING-AFTER-R5](REMAINING-AFTER-R5.md) punch list — including the
launch-day chain-halt blocker R5 introduced. **No blocker-class finding remains.**

- ✅ **F004 cutover-offset broken-fix — FIXED + runtime-verified.** `HyperRuntime::new` now builds
  `EpochManager::with_cutover(config.cutover_snapchain_block)` at `src/hyper/runtime.rs:339` (the
  one-liner the R5 callout requested). The maintainer added the load-bearing regression test
  `cutover_aware_resolver_reports_epoch_zero_post_cutover` (`runtime.rs:4969`): it runs the **real**
  `apply_cutover` + `produce_signed_block_dkls_local` at a mainnet-shaped `cutover = 5,000,000`,
  asserts `epoch_resolver.current_epoch() == 0` immediately post-cutover, installs the genesis share,
  and asserts production succeeds. It **passes** — the inverse of our R5 PoC, and it would have gone
  red against R5 (resolver epoch 11). `apply_cutover` now has direct test coverage at a real cutover
  height for the first time.
- ✅ **F004 dual-anchor desync — FIXED.** The supervisor's separate `Arc<Mutex<u64>>` is collapsed
  into the scheduler's `Arc<Mutex<LatestAnchor>>`; `spawn_anchor_poller` writes one mutex, both
  readers share it. `LatestAnchor.block` (`scheduler.rs:41`) carries `meta.snapchain_anchor_block`,
  the same value the old `u64` mutex held — semantics preserved, the cross-source epoch drift is gone.
- ✅ **F009 L2 distribution-blindness — FIXED (with a new low-severity fairness caveat).** L2 is now
  distribution-aware: `(1 − H_norm)^growth_distribution_skew_exponent` (default 2.0) over the
  per-crediter contribution entropy. See §1 below for the residual.
- ✅ **F023 phase-3 broadcast arm — FIXED.** Digest-bound via the new `DISCRIMINATOR_SIGN_BROADCAST`
  frame; receiver rejects cross-digest/truncated frames before deserialization. Two codec tests pass.
- ◑ **F031 gRPC auth off-by-default — MITIGATED.** Default RPC/HTTP bind changed `0.0.0.0` → `127.0.0.1`.

What remains is one new low-severity fairness caveat plus the carried informational items — none
require a code change to be "correct", and none are exploitable on a default deploy.

---

## 1. F009 — L2 entropy damping penalizes uniformity, not sybil-ness (NEW, low severity / fairness)

R6's distribution-aware L2 correctly damps the modeled uniform sybil ring to zero, closing the R5
"distribution-blind" caveat. But the discrimination axis is **contribution uniformity**, not
sybil-ness. We probed this directly (probe injected into `proof-of-quality` unit tests, executed on
stable, tree restored):

```
skew_exponent = 2.0 (production default)
uniform sybil ring (50 equal crediters)         growth = 0.0
uniform LEGIT user  (50 equal real crediters)   growth = 0.0     <- identical
skewed  legit user  (1 whale + tail)            growth = 0.0066  <- survives
uniform legit user with L2 OFF                  growth = 16.96
uniform-legit vs uniform-ring growth diff       = 0.0  (L2 cannot tell them apart)
```

A legitimate popular account whose many crediters engage at similar magnitudes — a creator/celebrity
with equal-weight fans — has near-uniform contributions (`H_norm ≈ 1`) and is damped to the **same**
0.0 as a ring. This is a fairness/false-positive concern, **not a security hole**:

- The real sybil defense is **L0** (the `crediter_trust_threshold = 0.05` floor); an executed sim
  (R3) measured the ring at trust 0.0057, already starved there regardless of L2.
- The affected legit user loses only the **growth** component of their score, not all reward.

Suggested handling: document the assumption for operators, and/or tune
`growth_distribution_skew_exponent` (setting it to `0` recovers the count-only behavior). No urgent
code change.

---

## 2. F135 — DA-PoW reward hit-rate magnitude (carried, NEEDS-RUNTIME)

Unchanged from R4/R5: the frozen-count bug was fixed R4 (`fid_count_fn` live closure); the remaining
question — whether the producer/verifier challenge-prefix derivation agrees under real registry growth
— is a runtime measurement. The devnet (`run_testnet.sh`, added R3) makes it measurable; it has not
yet been executed.

---

## 3. F023 — structural (non-cryptographic) broadcast binding (carried, informational)

The phase-3 digest binding is structural: the digest is public, so an attacker who knows the active
driver's digest can still craft a correctly-prefixed frame. That only reaches the same liveness abort
the protocol already tolerates; forgery remains blocked by the dkls23 `mul_sid` abort and F018 sender
binding. Acknowledged in-code; adequate for the stated cross-routing/liveness vector.

---

## 4. F031 — gRPC auth still opt-in (carried, mitigated)

R6's loopback default bind removes the out-of-the-box public exposure, but gRPC auth itself remains
off by default (`server.rs`, `rpc_auth = ""`). An operator who binds the port publicly should enable
auth (or front it with a reverse proxy / mTLS). Posture improvement, not a defect.
</content>
