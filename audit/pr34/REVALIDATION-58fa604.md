# Hypersnap PR #34 — Fix Revalidation of commit `58fa604` ("audit update")

**Fix commit:** [`58fa604bb5874d20a58e6fb10b4c9fad903d4b3d`](https://github.com/farcasterorg/hypersnap/commit/58fa604bb5874d20a58e6fb10b4c9fad903d4b3d) — *"audit update"*, Cassandra Heart, 2026-06-14, on PR [#34](https://github.com/farcasterorg/hypersnap/pull/34) (branch `pow`).
**Parent (prior fix):** [`5c25945`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72) — the previously-revalidated "audit fixes" commit. `58fa604` is its **direct child**, so this diff *is* the follow-up fix set layered on top of the first round.
**Audited base (pre-fix):** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).
**Diff size:** 7 files, +252 / −18. **Pure Rust — the bridge contract was not touched.**
**Method:** static call-site tracing against the patched source at `58fa604`, **plus a WSL/Linux build that compiled and ran the relevant tests** (rustc 1.95, `RUSTFLAGS="--cap-lints allow"` to dodge an unrelated `ed448-bulletproofs` compiler ICE in the `check_unused_traits` lint pass). The crate does not build under the local Windows/MSVC toolchain (`tikv-jemalloc-sys` autotools `configure`); jemalloc builds fine on Linux, so WSL closes the prior "unbuilt" gap. **Build-verified results below.**

### Build verification (WSL, `58fa604` + one added regression test)

| Test | Finding | Result |
|---|---|---|
| crypto crate full build incl. `DklsCurve: Scalar: Zeroize` trait bound | F018 | ✅ compiles clean; 25 DKLS tests pass |
| `party_poly_point_zeroizes_on_drop_path` | F018 | ✅ **pass** |
| `f002_cross_epoch_evidence_does_not_recurse_on_epoch_boundary` (shipped) | F002 | ✅ **pass** (no stack overflow on 256 KiB stack) |
| `slashing_must_slash_true_party_order_signer` (added; asserts correct behavior) | regression below | ❌ **fails** — security property violated (primary proof) |
| `slashing_resolves_signer_index_in_lexicographic_not_party_order` (added; pins buggy behavior) | regression below | ✅ pass — characterization (flips to red when fixed) |

PoC: [`poc/residual-58fa604-slashing-index/`](poc/residual-58fa604-slashing-index/).
**Prior round:** [REVALIDATION-5c25945.md](REVALIDATION-5c25945.md) · merge-gate analysis [MERGE-BLOCKERS-5c25945.md](MERGE-BLOCKERS-5c25945.md).

---

## What this commit is

A second, narrowly-scoped response targeting the two open items from the first round that are fixable in Rust: the **F002 chain-halt** (the sole *unconditional* merge blocker, B1) and the **F018 keystore-scrub** partial. It does **not** touch `HypersnapBridge.sol`, so the entire bridge-watermark cluster (F045/F047/F048/F049) is unchanged from the prior round.

| Change | File (Δ) | Finding |
|---|---|---|
| `slashed_validators_for_epoch` no longer re-enters `get_active_validators_enforced`; resolves signer indices only for same-epoch (`sig.epoch == epoch`) blocks against the caller-passed `active_set_at_epoch`, skips cross-epoch blocks. Ships a 256 KiB-stack recursion regression test. | `runtime.rs` (+~140 incl. test) | **F002** (B1) |
| `impl Drop for Party<C>` zeroizes `poly_point` (the secret share), `session_id`, `eth_address`; `DklsCurve` trait now bounds `Scalar: Zeroize`; `zeroize` dep added; zeroize-wiring regression test. Doc on `prune_retired_dkls_shares` corrected (Party now really scrubs on drop). | `protocols.rs` (+30), `lib.rs`, `dkls_threshold.rs` (+20), `Cargo.toml` ×2, `Cargo.lock` | **F018** |

---

## Scoreboard delta vs `5c25945`

| Finding | Sev | After `5c25945` | After `58fa604` |
|---|---|---|---|
| **F002** | High | PARTIAL — chain-halt live | **FIXED** (chain-halt closed; narrow under-slashing trade accepted) |
| **F018** | Med | PARTIAL — shares freed un-scrubbed | **FIXED (core)** — `poly_point`/`session_id` zeroized on drop; minor residual |
| F045 | High→Info | Informational (single-deployment) | unchanged |
| F047 (B3) | High | NOT FIXED | unchanged — contract untouched |
| F048 (B4) | Med | NOT FIXED | unchanged — contract untouched |
| F049 (B2) | High | PARTIAL (Rust cap only) | unchanged — contract untouched |
| F011 | Med | PARTIAL | unchanged — `read_validator.rs` untouched |

**Net:** the one *unconditional* merge blocker (B1/F002) is cleared and the F018 partial is closed. The merge is now gated **solely** on the bridge-contract cluster B2–B4.

---

## F002 — slashing-evidence self-recursion → chain halt · **FIXED** (0.9)

**The cycle is cut at the source.** In the patched tree, `slashed_validators_for_epoch` contains **no call** to `get_active_validators_enforced` — only references in comments (verified by grep of the function body, `runtime.rs:4238`+). The closure now:

```rust
if sig.epoch != epoch {
    // Cross-epoch block — skip rather than recurse
    return out;
}
let keys: Vec<&Vec<u8>> = active_set_at_epoch.keys().collect();
```

The caller `get_active_validators_enforced(E)` computes `prev_active = compute_active_set(E-1)` (a registry call, **not** recursive) and passes it as `active_set_at_epoch` to `slashed_validators_for_epoch(E-1, &prev_active)`. The previously-fatal path `enforced(E) → slashed(E-1) → resolve_signers(block@E) → enforced(E) → …` no longer exists: a cross-epoch block is skipped, a same-epoch block is resolved against the already-materialized set. **One attacker-submitted cross-epoch evidence row can no longer overflow the stack.** This is exactly the "use the ignored `_active_set_at_epoch`" fix recommended in the prior merge-blocker writeup; the parameter is now bound (`active_set_at_epoch`) and consumed.

**Regression test:** `f002_cross_epoch_evidence_does_not_recurse_on_epoch_boundary` drives the real `record_evidence` store API and runs the boundary call on a 256 KiB stack so any latent recursion overflows fast; asserts both the benign same-epoch row and the malicious cross-epoch row return `Ok`. **Built and passing under WSL** (rustc 1.95) — the prior round's "unbuilt" caveat is closed.

### Caveats (neither blocking)

1. **Acknowledged under-slashing of cross-epoch equivocators.** With cross-epoch blocks skipped, an unresolved side yields an empty intersection → no slash for that evidence row. A genuine *cross-epoch* equivocator escapes attribution at the lower epoch's boundary. The authors document this explicitly and accept it as the correct trade against a transient single-epoch capture becoming a permanent network-wide liveness kill. Concur on the liveness priority; record it as a deliberate reduction in slashing soundness, not an oversight. Same-epoch equivocation is still caught.
2. **Resolution-set change.** Same-epoch attribution now resolves `signer_indices` against the *unenforced* `compute_active_set(prev)` rather than the *enforced* set the pre-fix code used. Subsumed by the confirmed regression below (the index *ordering* mismatch is the dominant defect, not the enforced/unenforced distinction).

---

## ★ NEW (fix-induced regression) — slashing resolves signer indices in the wrong order · **CONFIRMED — build-verified** (0.95)

> Not one of the original 23 findings. Introduced by the **F025 remediation in `5c25945`**, undetected last round, and carried through `58fa604` (which edited the exact function but preserved the defect). Surfaced during deep-dive revalidation of the F002 fix.

**The mismatch.** `signer_indices` in a `HyperBlock` are the DKLS **party indices** of the signing committee. At signing time (`actor.rs` → `select_signing_committee` → `attach_dkls_signature`), party index `i` maps to a validator key via `dkls_committee::committee_party_order(epoch, active.keys())` — a **keccak-rank permutation** of the active set (its own doc: *"Sorting is purely for the hash; it does NOT determine the output order"*). The supervisor (`build_driver`) and `transport_pubkey_for_party` both use this permuted mapping, so signing is internally consistent.

But `slashed_validators_for_epoch::resolve_signers` (the function this commit edited) maps signer index `i` → `active_set_at_epoch.keys()[i-1]` — plain **lexicographic** BTreeMap key order. The two orderings are different permutations of the same key set, by design.

**Impact.** Slashing attributes equivocation to the **wrong validators**: index `i` resolves to the validator at *lexicographic* position `i`, while the actual signer sits at *keccak-permuted* position `i`. Honest validators (whoever occupies the lexicographic slot) are slashed and then excluded from the active set via `get_active_validators_enforced`; the real equivocators escape. This degrades both F002 (intersection) and F009 (double-sign) attribution — and ironically re-introduces F002's original spirit ("innocent validators slashed") through a new mechanism. High severity (incorrect slashing of honest validators + active-set eviction).

**Provenance.** At baseline `cab225f` both sides used lexicographic order (`active.keys().enumerate()` in the pre-F025 `build_driver`), so they matched. `5c25945` changed only the signing side to the permutation; the slashing side was missed. `58fa604` edited the slashing function for F002 but kept `.keys()`.

**Fix.** Resolve indices in `slashed_validators_for_epoch` (and the `importer.rs` scoring path `active_validator_keys_by_index`, if/when it goes live) through `committee_party_order(epoch, active_set.keys())` — the same permuted ordering the indices were assigned in — not raw `.keys()`.

**Verification status — build-verified (red proof).** Static trace through sign→store→resolve (adversarial check for a reconciling translation: none found), **plus two in-crate tests under WSL**: a **failing** security-property test (`slashing_must_slash_true_party_order_signer` — asserts the real party-order signer is slashed; **FAILS on `58fa604`** → property violated, the primary proof) and a passing characterization test (`slashing_resolves_signer_index_in_lexicographic_not_party_order` — asserts the buggy lexicographic resolution; pins the behavior, flips to red when fixed). Both build a 5-key set, find the first index where `committee_party_order` diverges from lexicographic order, and record a same-epoch equivocation by that index. PoC + verbatim red/green output: [`poc/residual-58fa604-slashing-index/`](poc/residual-58fa604-slashing-index/).

---

## F018 — retired DKLS shares freed un-scrubbed · **core FIXED** (0.85)

Last round this was PARTIAL: `prune_retired_dkls_shares` removed the map entry, but `Party` carried **no** `Drop`/`Zeroize` (the then-comment claimed otherwise — flagged false). This commit lands the real scrub:

- `impl<C: DklsCurve> Drop for Party<C>` zeroizes `poly_point` — the field documented `/// Behaves as the secret key share` (`protocols.rs:38`) — plus `session_id` (transcript binding) and `eth_address`.
- The `DklsCurve` trait now bounds `<Self as CurveArithmetic>::Scalar: zeroize::Zeroize`, so the generic scrub is type-checked; both supported curves (`Secp256k1`, `NistP256`) satisfy it via `DefaultIsZeroes`.
- `prune_retired_dkls_shares` doc corrected: `BTreeMap::remove` moves the value into a temporary that drops at end of statement → `Party::drop` → zeroize, before the allocator reclaims the page.
- Regression test `party_poly_point_zeroizes_on_drop_path` proves `Zeroize` is wired and zeroes the scalar. **Built and passing under WSL**; the `DklsCurve: Scalar: Zeroize` trait-bound addition compiles cleanly across all use sites (the main compile risk of this change).

**Residual (defense-in-depth, not blocking):**
- The OT-precompute fields (`zero_share`, `mul_senders`/`mul_receivers`, `derivation_data`) are **not** explicitly zeroized. The authors argue they are not independently signing-capable without `poly_point` and that their heap sub-fields drop canonically — defensible, since `poly_point` is the reconstructing secret. Note it as accepted scope, not a closed gap.
- `Clone` is retained on `Party`; long-lived clones each scrub on their own drop, but copies that outlive a prune still hold share bytes until their own drop. Inherent to `Clone` + secrets; out of scope for the keystore-prune fix.
- The epoch-currency guards on the bridge local-sign / lock-root / owner-rotation apply paths that the original F018 also called for are not present in this commit.

---

## Unchanged from `5c25945` — still open

**The bridge contract `HypersnapBridge.sol` is byte-identical to baseline `cab225f`** (confirmed: `git diff cab225f 58fa604 -- contracts/` is empty). Both fix commits leave it untouched. Therefore:

- **F049 (B2)** — watermark saturation bricks `rotateOwner`/`cancelUpgrade`/`pause` while permissionless `executeUpgrade` survives. The Rust-side `MAX_SANE_BRIDGE_BLOCK_NUMBER` cap from the first round does **not** bind the contract or constrain a Byzantine signer. **NOT FIXED.**
- **F047 (B3)** — owner-rotation front-run / seizure defeats key-compromise recovery; single shared monotonic watermark, public mempool digests. **NOT FIXED.**
- **F048 (B4)** — `proposeUpgrade` still lacks `whenNotPaused`; the 24h guaranteed lockout can be collapsed by re-proposing during a pause. **NOT FIXED.**
- **F045** — cross-deployment universal-sig replay; remains **Informational** under the operator-confirmed single-deployment assumption. Write the assumption down (contract invariant comment + deployment checklist); binding `chainid`+`address(this)` into the universal digests is near-free future-proofing for the day a second instance is stood up under the same key.
- **F011** — `read_validator.rs` not touched; multi-week silent-divergence window before the staleness heuristic halts. Still **PARTIAL** (operational hardening, not a merge gate).

---

## Merge-gate status after `58fa604`

| # | Finding | Gate type | After `5c25945` | After `58fa604` |
|---|---------|-----------|-----------------|-----------------|
| **B1** | F002 chain-halt | **Hard (unconditional)** | OPEN | **CLEARED** ✅ |
| **B2** | F049 watermark saturation | Conditional ¹ | OPEN | OPEN (contract untouched) |
| **B3** | F047 owner-rotation front-run | Conditional ¹ | OPEN | OPEN (contract untouched) |
| **B4** | F048 pause vs proposeUpgrade | Conditional ¹ | OPEN | OPEN (contract untouched) |

¹ B2–B4 gate the merge **only if** "owner/threshold-key-compromise is recoverable" is a guarantee you are shipping (per `HypersnapBridge.sol:266-270`). De-scope that and they drop to documented known-risk.

**Bottom line:** the single unconditional blocker is resolved and the F018 partial is closed. The merge now hinges entirely on the bridge-contract cluster B2–B4 — which still needs the Solidity changes that did not land in either fix commit. If the team de-scopes key-compromise recovery, `58fa604` clears the path; otherwise B2–B4 remain blocking and require edits to `HypersnapBridge.sol`.
