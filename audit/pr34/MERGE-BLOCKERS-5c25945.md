# PR #34 — Merge Blockers after fix commit `5c25945`

**Fix commit:** [`5c2594563df84c374fdce7cdeae06d3444da3b72`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72) ("audit fixes", 2026-06-12)
**Audited base:** `cab225f` · **Scoping assumption (operator-confirmed):** a **single canonical bridge deployment** (no multi-deployment / universal cross-chain relay). This retires the cross-deployment replay finding **F045** (→ Informational; see §4).
**Method:** static call-site tracing against `5c25945` + **runnable PoCs** (Foundry for the bridge cluster, a stack-overflow model for F002). Full revalidation: [REVALIDATION-5c25945.md](REVALIDATION-5c25945.md).

---

## Verdict

| # | Finding | Sev | Gate type | PoC status |
|---|---------|-----|-----------|------------|
| **B1** | F002 — slashing-evidence self-recursion → chain halt | High | **Hard blocker** | ✅ reproduced (stack-overflow model); in-crate test authored, not built here |
| **B2** | F049 — watermark saturation bricks recovery; `executeUpgrade` survives | High | **Conditional** ¹ | ✅ reproduced (`forge`, passing) |
| **B3** | F047 — owner-rotation front-run / seizure defeats recovery | High | **Conditional** ¹ | ✅ reproduced (`forge`, passing) |
| **B4** | F048 — `pause` does not gate `proposeUpgrade`; 24h lockout erased | Medium | **Conditional** ¹ | ✅ reproduced (`forge`, passing) |

¹ **B2–B4 gate the merge *only if* "owner/threshold-key-compromise is recoverable" is a security guarantee you are shipping.** They all live under the contract's own documented key-compromise recovery model (`HypersnapBridge.sol:266-270`) and all require control of the owner threshold signature. If instead you accept "a Byzantine/compromised threshold key means that deployment is lost, full stop," they drop to documented known-risk. **B1 gates regardless** — it needs only a single epoch's committee captured, not the global key.

**Recommendation:** block on **B1** unconditionally; block on **B2–B4** unless the team explicitly de-scopes key-compromise recovery. None of B2–B4 was touched by the fix commit (the contract is byte-identical to `cab225f`).

---

## B1 — F002 slashing-evidence self-recursion → permanent chain halt  *(HARD BLOCKER)*

**Where (unchanged in `5c25945`):** `src/hyper/runtime.rs`
- `get_active_validators_enforced(E)` → `slashed_validators_for_epoch(E-1)` — `runtime.rs:4122`.
- `slashed_validators_for_epoch`'s `resolve_signers` closure reads each block's own `sig.epoch` and re-enters `get_active_validators_enforced(block_epoch)` — `runtime.rs:4262-4264`.
- Evidence persisted under `min(epoch_a, epoch_b)` — `slashing_store.rs:163`.
- The `_active_set_at_epoch` parameter that could break the cycle is **passed and ignored** — `runtime.rs:4241`.

**The cycle:** a stored cross-epoch evidence row `(epoch_a = E-1, epoch_b = E)` (block_b validly signed for epoch E) is keyed under `E-1`. Then `get_active_validators_enforced(E) → slashed_validators_for_epoch(E-1) → resolve_signers(block_b @ E) → get_active_validators_enforced(E) → …` recurses unbounded → stack overflow. No depth guard, no memoization. The F002 *intersection* fix (`runtime.rs:4283`) changed **who** is slashed; it did not touch this traversal.

**Precondition:** a Byzantine quorum of **one** epoch's committee (enough to threshold-sign one junk `block_b` sharing a `canonical_block_id` with an adjacent-epoch block — the latter can be the real canonical block). This is a *per-epoch committee subset*, not the global 2/3, and may be far cheaper to capture for a single epoch.

**Impact — the reason it's a hard blocker:** the evidence is **persisted**, so every honest node crashes when it recomputes that epoch boundary, and keeps crashing. A **transient** single-epoch capture becomes a **permanent, network-wide liveness kill**. That asymmetry exceeds what a transient Byzantine quorum can normally do.

**PoC:** [`poc/residual-5c25945-F002-chainhalt/`](poc/residual-5c25945-F002-chainhalt/)
- `f002_model_standalone.rs` — a faithful model of the exact call graph + `min()` keying. **Observed:** benign same-epoch evidence returns `Ok`; the malicious cross-epoch row drives the worker thread to `STATUS_STACK_OVERFLOW` (`0xC00000FD`). Difference is the cross-epoch cycle, not setup.
- `F002_chainhalt_test.rs` — a paste-ready in-crate `#[test]` (mirrors the existing `active_set_excludes_validator_with_trust_below_floor` harness, drives the real `record_evidence` store API). **Caveat — honest:** this was **not compiled here**; the hypersnap crate fails to build in this environment because the transitive native dep `tikv-jemalloc-sys` cannot run its autotools `configure` against the local MSVC toolchain. That is a toolchain blocker, unrelated to the F002 logic (pure safe-Rust recursion). **Run it in CI** (where the crate builds) to convert this to a fully-built green→red regression test.

**Fix (cheap, local):** in `resolve_signers`, resolve block signers against an already-computed/cached active set instead of re-entering `get_active_validators_enforced`; or add an equal-epoch / depth / visited-set guard; or actually use the ignored `_active_set_at_epoch`. The function was already being edited for F002 — finish it.

---

## B2 — F049 watermark saturation bricks recovery; `executeUpgrade` survives  *(conditional)*

**Where:** `HypersnapBridge.sol` — gates `blockNumber <= latestBlock → revert StaleBlock` at `:235` (rotate) / `:321` (cancel) / `:362` (pause), with **no upper bound** on `blockNumber`; `executeUpgrade()` (`:346-355`) is permissionless and never reads `latestBlock`. The fix commit added only a Rust-side honest-signer cap (`MAX_SANE_BRIDGE_BLOCK_NUMBER`) — it does **not** bind the contract, and does not constrain a Byzantine signer.

**Attack:** an owner-signed action with `blockNumber = type(uint64).max` saturates `latestBlock`; thereafter `rotateOwner`/`cancelUpgrade`/`pause` all revert `StaleBlock` (recovery permanently bricked), while a previously-pending implementation still executes via permissionless `executeUpgrade()` after the 48h delay → permanent brick + custody theft.

**PoC:** [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) → `test_F049_…` **PASS**. After `pause(MAX)`, rotate/cancel/pause all revert `StaleBlock(MAX, MAX)`; after the 72h pause auto-expires, `executeUpgrade()` succeeds and the ERC-1967 impl slot (`vm.load`) holds the attacker implementation; `pendingImplementation == 0`.

**Fix:** bound accepted `blockNumber` to a sane forward window (`<= latestBlock + MAX_ADVANCE`, or bind to real L1 height) on every universal entry point **in the contract**, and gate `executeUpgrade` consistently. (Landing only the Rust cap — the half that does not stop the attacker — is worse optics than doing neither.)

---

## B3 — F047 owner-rotation front-run / seizure defeats recovery  *(conditional)*

**Where:** `HypersnapBridge.sol` — `rotateOwner` shares the single monotonic watermark namespace with no priority; the auth digest binds only `(DOMAIN, block, newOwner)` (`:238-242`), acceptance only `newOwner` (`:247-250`); digests are public in the mempool.

**Attack (seizure variant demonstrated):** a holder of the compromised old `O1` key lands `rotateOwner(N, O_attacker, sigByO1, …)`, permanently setting `ownerAddress` to an attacker EOA (`:256`); the victim's legitimate recovery `rotateOwner(N, O2, …)` then reverts `StaleBlock`, and O1's own signature is afterward rejected — the documented "immediate rotation" recovery is defeated.

**PoC:** [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) → `test_F047_…` **PASS** (`ownerAddress == attackerEOA`; victim rotation reverts `StaleBlock(N, N)`).

**Fix:** give rotation a watermark namespace/priority other consumers cannot starve, and remove the public front-run primitive (commit-reveal or a dedicated rotation counter).

---

## B4 — F048 `pause` does not gate `proposeUpgrade`; 24h lockout erased  *(conditional)*

**Where:** `HypersnapBridge.sol` — `proposeUpgrade` (`:271-311`) lacks `whenNotPaused`. The "24h guaranteed lockout" reasoning (`:64-71`, PAUSE 72h > UPGRADE 48h) assumes a malicious propose cannot be (re)issued during a pause.

**Attack:** propose/refresh the malicious upgrade **during** the pause window so its 48h `effectiveAt` lands at/after `pauseExpiry`; the guaranteed lockout collapses to zero and `executeUpgrade` fires the instant pause lapses.

**PoC:** [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) → `test_F048_…` **PASS** (proposing at `pauseStart + 24h` gives `effectiveAt == pauseExpiry`; `executeUpgrade` reverts `BridgePaused` one second before and succeeds at the lapse instant).

**Fix:** add `whenNotPaused` to `proposeUpgrade` (and re-check pause/effectiveAt invariants so a propose cannot be timed to expire the lockout).

---

## §4 — Not blocking (record & defer)

- **F045** (cross-deployment universal-sig replay) → **Informational** under the single-deployment assumption. **Action:** write the assumption down — a `HypersnapBridge.sol` invariant comment + a deployment checklist note — because the day a second instance is stood up under the same key, F045 silently reactivates. Binding `chainid`+`address(this)` into the five universal digests anyway is near-free future-proofing.
- **F011** (read-node protocol-version staleness; multi-week silent-divergence window) and **F018** (retired DKLS shares freed un-zeroized; missing epoch-currency guards on some apply paths) — operational / defense-in-depth partials. Track as issues; not merge gates.

---

## PoC index

| PoC | Path | Tooling | Result |
|-----|------|---------|--------|
| Bridge cluster (F047/F048/F049) | [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) (`Residual5c25945.t.sol`, `README.md`, `forge-output.txt`) | Foundry 1.2.3, solc 0.8.24 | **3 passed / 0 failed**; baseline suite 112/112 |
| F002 chain-halt | [`poc/residual-5c25945-F002-chainhalt/`](poc/residual-5c25945-F002-chainhalt/) (`f002_model_standalone.rs`, `F002_chainhalt_test.rs`, `README.md`, logs) | Rust (model run); in-crate test for CICD | model: **STATUS_STACK_OVERFLOW** reproduced; in-crate test **UNVERIFIED-BY-BUILD** (jemalloc toolchain) |

*Static analysis + PoCs; no full node build was possible locally for B1 (jemalloc native dep). The bridge PoCs are fully built and passing. Run the F002 in-crate test in CI to close that one gap.*
