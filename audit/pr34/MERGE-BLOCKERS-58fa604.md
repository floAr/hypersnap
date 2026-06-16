# PR #34 — Merge Blockers after fix commit `58fa604`

**Fix commit:** [`58fa604bb5874d20a58e6fb10b4c9fad903d4b3d`](https://github.com/farcasterorg/hypersnap/commit/58fa604bb5874d20a58e6fb10b4c9fad903d4b3d) ("audit update", 2026-06-14) — **direct child of** [`5c25945`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72).
**Audited base:** `cab225f` · **Scoping assumption (operator-confirmed):** a **single canonical bridge deployment** (retires F045 → Informational).
**Method:** static call-site tracing against `58fa604` + **a WSL/Linux build that compiles and runs the relevant tests** (rustc 1.95, `RUSTFLAGS="--cap-lints allow"` to dodge an unrelated `ed448-bulletproofs` compiler ICE). Full revalidation: [REVALIDATION-58fa604.md](REVALIDATION-58fa604.md). Prior round: [MERGE-BLOCKERS-5c25945.md](MERGE-BLOCKERS-5c25945.md).

---

## What changed since `5c25945`

`58fa604` is pure Rust (7 files, +252/−18); **`HypersnapBridge.sol` is byte-identical to `cab225f`.** It closes the one unconditional blocker from last round and the F018 partial — but a **new High-severity, fix-induced regression** was found and build-confirmed this round.

## Verdict

| # | Finding | Sev | Gate type | Status after `58fa604` |
|---|---------|-----|-----------|------------------------|
| **B1** | F002 — slashing-evidence self-recursion → chain halt | High | Hard | ✅ **CLEARED** — recursion removed; shipped test `f002_…does_not_recurse` **built & passing** (WSL) |
| **B5** | **NEW** — slashing resolves `signer_indices` in lexicographic order, signing assigns them keccak-permuted → wrong validator slashed | High | **Hard blocker** | ❌ **OPEN** — regression test **built & passing** (pins the bug) |
| **B2** | F049 — watermark saturation bricks recovery; `executeUpgrade` survives | High | Conditional ¹ | ❌ OPEN — contract untouched |
| **B3** | F047 — owner-rotation front-run / seizure defeats recovery | High | Conditional ¹ | ❌ OPEN — contract untouched |
| **B4** | F048 — `pause` does not gate `proposeUpgrade`; lockout erased | Medium | Conditional ¹ | ❌ OPEN — contract untouched |

¹ **B2–B4 gate the merge *only if* "owner/threshold-key-compromise is recoverable" is a guarantee you are shipping** (`HypersnapBridge.sol:266-270`). De-scope that and they drop to documented known-risk. **B1 was, and B5 is, hard — they gate regardless.**

**Recommendation:** B1 is cleared. Block on **B5** unconditionally (cheap one-line fix). Block on **B2–B4** unless the team explicitly de-scopes key-compromise recovery. None of B2–B4 was touched by either fix commit.

---

## B1 — F002 slashing-evidence self-recursion → chain halt  *(CLEARED)*

**Fixed in `58fa604`.** `slashed_validators_for_epoch` no longer calls `get_active_validators_enforced` (verified: no call remains in the function body, only comments). It resolves signer indices only for blocks whose `sig.epoch == epoch`, against the caller-supplied `active_set_at_epoch` (`= compute_active_set(prev)`), and skips cross-epoch blocks. The fatal cycle `enforced(E) → slashed(E-1) → resolve_signers(block@E) → enforced(E) → …` no longer exists.

**Build-verified.** Shipped test `f002_cross_epoch_evidence_does_not_recurse_on_epoch_boundary` runs the boundary call on a 256 KiB stack; both the benign same-epoch row and the malicious cross-epoch row return `Ok`. **Built and passing under WSL** — the prior round's "in-crate test authored but unbuilt (jemalloc toolchain)" caveat is closed.

**Residual (non-blocking, acknowledged by authors):** cross-epoch equivocators are now *under-slashed* (unresolved side → empty intersection → no slash). A deliberate trade against a permanent liveness kill; record it as reduced slashing soundness, not an oversight.

---

## B5 — slashing resolves signer indices in the wrong order  *(NEW — HARD BLOCKER)*

> Not one of the original 23 findings. **Introduced by the F025 remediation in `5c25945`**, undetected last round, carried through `58fa604` (which edited the exact function but preserved the defect). Surfaced during deep-dive revalidation of the F002 fix.

**Where:** `src/hyper/runtime.rs::slashed_validators_for_epoch` (the function `58fa604` edited).

**The mismatch.** `signer_indices` in a `HyperBlock` are DKLS **party indices**. The signing and slashing paths disagree on the index→key mapping:

| Path | Mapping | Source |
|---|---|---|
| **Signing** | party index `i` → `committee_party_order(epoch, active.keys())[i-1]` — keccak-rank permutation | `actor.rs` (`select_signing_committee` → `attach_dkls_signature`); supervisor `build_driver`; `transport_pubkey_for_party` |
| **Slashing** | signer index `i` → `active_set.keys()[i-1]` — lexicographic BTreeMap order | `slashed_validators_for_epoch::resolve_signers` |

`committee_party_order` is explicitly a permutation (its own doc: *"Sorting is purely for the hash; it does NOT determine the output order"*). When the keccak order diverges from lexicographic order — which it does by design — slashing resolves each signer index to the **wrong** validator key.

**Impact — why it's a hard blocker.** When evidence is processed, the slash lands on the validator at the *lexicographic* slot (an innocent party), who is then excluded from the active set via `get_active_validators_enforced`; the actual equivocator at the *party-order* slot escapes. This is incorrect slashing of honest validators in a safety-critical path, triggered by a single recorded equivocation — it does **not** depend on the optional key-compromise-recovery guarantee, so it gates regardless. It also ironically re-introduces F002's original spirit ("innocent validators slashed") through a new mechanism, and degrades F009 (double-sign) attribution the same way.

**Provenance.** At baseline `cab225f` both sides used lexicographic order (pre-F025 `build_driver` used `active.keys().enumerate()`), so they matched. `5c25945` changed only the signing side to the permutation; the slashing side was missed.

**PoC:** [`poc/residual-58fa604-slashing-index/`](poc/residual-58fa604-slashing-index/) (WSL build). Two opposite-polarity tests over a 5-key set with a known divergent index: the security-property test `slashing_must_slash_true_party_order_signer` (asserts the real signer is slashed) **FAILS on `58fa604`** — the primary proof of the violation — while the characterization test `slashing_resolves_signer_index_in_lexicographic_not_party_order` passes, pinning the buggy lexicographic resolution. Both flip when the resolver is corrected.

**Fix (cheap, local).** Resolve indices in `slashed_validators_for_epoch` through `committee_party_order(epoch, active_set.keys())` — the same permuted ordering the indices were assigned in — instead of raw `.keys()`. Apply the same correction to the `importer.rs` scoring path (`active_validator_keys_by_index`) if/when it goes live.

---

## B2 — F049 watermark saturation bricks recovery; `executeUpgrade` survives  *(conditional, unchanged)*

`HypersnapBridge.sol` untouched. The Rust-side `MAX_SANE_BRIDGE_BLOCK_NUMBER` cap from `5c25945` does not bind the contract and does not constrain a Byzantine signer. Attack and fix unchanged from [MERGE-BLOCKERS-5c25945.md §B2](MERGE-BLOCKERS-5c25945.md). PoC: [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) (`test_F049_…` **PASS**).

## B3 — F047 owner-rotation front-run / seizure defeats recovery  *(conditional, unchanged)*

`HypersnapBridge.sol` untouched. `rotateOwner` still shares the single monotonic watermark namespace; digests public in the mempool. Unchanged from [§B3](MERGE-BLOCKERS-5c25945.md). PoC: `test_F047_…` **PASS**.

## B4 — F048 `pause` does not gate `proposeUpgrade`  *(conditional, unchanged)*

`HypersnapBridge.sol` untouched. `proposeUpgrade` still lacks `whenNotPaused`. Unchanged from [§B4](MERGE-BLOCKERS-5c25945.md). PoC: `test_F048_…` **PASS**.

---

## Not blocking (record & defer)

- **F018** (retired DKLS shares freed un-scrubbed) — **CLOSED this round.** `impl Drop for Party` zeroizes `poly_point`/`session_id`; `DklsCurve: Scalar: Zeroize` wired. Build-verified: `party_poly_point_zeroizes_on_drop_path` passes and the trait bound compiles clean. Residual (defense-in-depth): OT-precompute fields not explicitly zeroized (authors argue not signing-capable without `poly_point`); epoch-currency guards on some apply paths still absent.
- **F045** (cross-deployment universal-sig replay) → **Informational** under the single-deployment assumption. Write the assumption down (contract invariant comment + deployment checklist); binding `chainid`+`address(this)` into the universal digests is near-free future-proofing.
- **F011** (read-node protocol-version staleness; multi-week silent-divergence window) — `read_validator.rs` untouched. Track as an issue; not a merge gate.

---

## PoC index

| PoC | Path | Tooling | Result |
|-----|------|---------|--------|
| Slashing signer-index mis-attribution (B5) | [`poc/residual-58fa604-slashing-index/`](poc/residual-58fa604-slashing-index/) | Rust in-crate tests, WSL build (rustc 1.95) | property test **FAILS** (proof); characterization test passes |
| F002 chain-halt regression (B1, now cleared) | shipped `f002_…does_not_recurse` in `runtime.rs` | Rust in-crate test, WSL build | **PASS** (both rows `Ok`) |
| F018 zeroize wiring | shipped `party_poly_point_zeroizes_on_drop_path` | Rust in-crate test, WSL build | **PASS** |
| Bridge cluster (F047/F048/F049) | [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/) | Foundry 1.2.3, solc 0.8.24 | **3 passed** (from prior round; contract unchanged) |

*This round's Rust tests are fully built and passing under WSL/Linux (the Windows/MSVC jemalloc blocker does not apply on Linux). `--cap-lints allow` was used to avoid an unrelated rustc 1.95 ICE in the vendored `ed448-bulletproofs` crate.*
