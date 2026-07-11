# PR #34 — Merge Readiness at tip `f4fc4af`

**Tip commit:** [`f4fc4af`](https://github.com/farcasterorg/hypersnap/commit/f4fc4af) ("Resolve last audit run", 2026-07-07, branch `pow`).
**Audited base:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).
**Lineage:** `cab225f` → `5c25945` → `58fa604` → `573d671` (+PR#35 v0.13.0 compat) → `ab73681` → `f4fc4af`.

Consolidated merge-gate reevaluation across the full fix lineage. Supersedes [MERGE-BLOCKERS-58fa604.md](MERGE-BLOCKERS-58fa604.md) for the current gate; the intervening native-onboarding rounds are in [REVALIDATION-573d671.md](REVALIDATION-573d671.md), [REVALIDATION-ab73681.md](REVALIDATION-ab73681.md), [REVALIDATION-f4fc4af.md](REVALIDATION-f4fc4af.md).

---

## Verdict

**6 of 9 merge blockers are CLOSED and build-verified. The 3 that remain are all in the Solidity bridge contract, are all CONDITIONAL, and none has been touched since the audited base.**

**There are no remaining hard/unconditional merge blockers.** Both blockers that gated the merge regardless of scope — **B1** (chain halt) and **B5** (validator mis-slashing) — are fixed. Every consensus-side and native-onboarding blocker is resolved.

> **Update 2026-07-11 (external review pass):** a second conditional blocker
> cluster — **B10/B11/B12** on the **confidential-transfer feature** (F071/F072/F073,
> all RED-PoC-backed) — was added from `felirami`'s PR review. See the
> [overlay below](#overlay--external-review-pass-felirami-2026-07-11) and
> [REVALIDATION-f4fc4af-review.md](REVALIDATION-f4fc4af-review.md). Merge
> readiness now depends on **two** scope decisions (key-compromise recovery →
> bridge B2–B4; confidential transfers shipped → B10–B12), not one.

Merge readiness reduces to a scope decision (originally the bridge cluster only):

- **If "recovery from owner / threshold-key compromise" is a guarantee this deployment ships** → **NOT merge-ready.** Fix **B2/B3/B4** in `HypersnapBridge.sol` first. These are the same three findings flagged in the very first round; the contract is byte-identical to `cab225f`.
- **If key-compromise recovery is explicitly de-scoped** (documented known-risk) → **merge-ready from the consensus/Rust side**, with the bridge cluster recorded as accepted risk and the non-blocking residuals tracked (below).

---

## Blocker roster

| # | Finding | Sev | Status | Closed at | Hard / conditional |
|---|---------|-----|--------|-----------|--------------------|
| **B1** | F002 — slashing-evidence self-recursion → chain halt | High | ✅ CLOSED | `58fa604` | hard |
| **B2** | F049 — watermark saturation bricks `rotateOwner`/`cancelUpgrade`/pause; `executeUpgrade` survives | High | ⛔ **OPEN** | — | conditional |
| **B3** | F047 — owner-rotation front-run / seizure defeats key-compromise recovery | High | ⛔ **OPEN** | — | conditional |
| **B4** | F048 — `pause` does not gate `proposeUpgrade` (late-propose erases lockout window) | Med | ⛔ **OPEN** | — | conditional |
| **B5** | slashing resolves `signer_indices` in wrong order → innocent validator slashed | High | ✅ CLOSED | `573d671` | hard |
| **B6** | ONBD-1 — onboarding FID assignment off the signed root → identity fork | Critical | ✅ CLOSED | `ab73681` | hard |
| **B7** | ONBD-2 — stake-release burns staked atoms (non-atomic) | High | ✅ CLOSED | `ab73681` | hard |
| **B8** | ONBD-9+10 — custody rotation off-root divergence + replay-resurrection revocation bypass | High | ✅ CLOSED | `f4fc4af` | hard |
| **B9** | ONBD-11 — speculative `produce` self-halt / identity fork | High | ✅ CLOSED | `f4fc4af` | hard |

**Closed: B1, B5, B6, B7, B8, B9 (6).  Open: B2, B3, B4 (3, all bridge, all conditional).**

---

## The three open blockers (B2–B4) — bridge, unchanged, conditional

`HypersnapBridge.sol` blob hash is **identical** at `cab225f` and `f4fc4af` (`8c291366feee58db87ddb64ed4a494633c9b6149`); the entire `contracts/` tree is byte-identical across the lineage. The findings therefore hold exactly as first characterized, and their Foundry PoCs ([`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/), 3 pass) remain valid.

- **B2 / F049** — a single monotonic watermark namespace saturates and bricks `rotateOwner`/`cancelUpgrade`/pause while `executeUpgrade` survives; the Rust-side `MAX_SANE_BRIDGE_BLOCK_NUMBER` cap does not bind the contract or a Byzantine signer. See [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md).
- **B3 / F047** — `rotateOwner` shares the watermark namespace and its digests are public in the mempool, so an attacker who has compromised signing can front-run the recovery rotation. See [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md).
- **B4 / F048** — `proposeUpgrade` lacks `whenNotPaused`, so `pause` does not gate it and a late proposal erases the lockout window. See [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md).

All three are the "recovery-from-compromise" cluster: they matter only under the guarantee that a compromised owner/threshold key can be safely rotated/paused/upgrade-locked out. `HypersnapBridge.sol:266-270` is the invariant that makes that a shipped promise.

---

## Not blocking — record & defer

- **ONBD-5** (soft 30-bit SHA-256 onboarding PoW) — partial-by-design; "governance-tunable" is doc-only. Track for the durable memory-hard / stake-gated replacement.
- **ONBD-7 residual** — `read_onboard_seq` / `read_onboard_rotation_nonce` / `read_onboarding_stake_lock` are fail-open, but only ever see 8-byte-or-absent authoritative values (absent = correct default) or sit behind the prod-disabled stake gate; not reachable to a wrong FID / stake bypass. Latent fragility only.
- **ONBD-13 / 14 / 15** (new at `f4fc4af`, all Low) — non-atomic query-mirror sync (self-healing), no-op-rotation reloop (PoW-FID-bounded waste), rotation ecrecover before block-sig check (CPU-only, pre-existing class). See [REVALIDATION-f4fc4af.md](REVALIDATION-f4fc4af.md) Part B. Best single fix: verify the block threshold signature + a message-count cap before any per-message re-validation in `import_block`.
- **F045** (cross-deployment universal-sig replay) → Informational under the single-deployment assumption; write the assumption down + bind `chainid`+`address(this)` into the universal digests.
- **F011** (read-node protocol-version staleness) and **F018 residual** (OT-precompute fields not zeroized) — track as issues, not gates.

---

## Evidence base

- **Rust/consensus side:** every closed blocker (B1, B5, B6, B7, B8, B9) is build-verified under WSL/Linux (rustc 1.95, `--cap-lints allow`). Current tip `f4fc4af`: full crate clean, `native_onboard` 19/19, broad suite 170/170, green four-way rotation-determinism PoC, ported ONBD-10 red→green PoC.
- **Bridge side:** B2/B3/B4 reproduced by passing Foundry tests (`solc 0.8.24`) in [`poc/residual-5c25945-bridge/`](poc/residual-5c25945-bridge/); still valid — contract unchanged.
- **Bridge byte-identity:** `git rev-parse cab225f:contracts/src/HypersnapBridge.sol == f4fc4af:contracts/src/HypersnapBridge.sol` → `8c291366…`; `git diff cab225f f4fc4af -- contracts/` empty.

---

## Overlay — external review pass (felirami, 2026-07-11)

Five `[P1]` inline review comments on the PR at head `f4fc4af` were run through
the validation process (full detail:
[REVALIDATION-f4fc4af-review.md](REVALIDATION-f4fc4af-review.md)). They surface a
**new blocker cluster on the confidential-transfer feature** — a code surface
not previously blocker-assessed (the prior lineage covered consensus, native
onboarding, and the bridge). 4 confirmed, 1 partial; none refuted.

### New conditional cluster — confidential transfers (parallels the bridge cluster)

| # | Finding | Sev | Status | Nature |
|---|---------|-----|--------|--------|
| **B10** | [F071](findings/F071-transfer-envelope-not-bound-output-pubkey-malleable.md) — admission+import verify bare `signing_payload()`; relay rewrites output `one_time_pubkey` | High | ⛔ OPEN | Security (denial-of-funds; theft foreclosed by Pedersen closure). Live on verifier side. |
| **B11** | [F072](findings/F072-confidential-note-recovery-data-absent-from-wire.md) — wire output omits `tx_pubkey`+encrypted payload; notes undiscoverable/unspendable | High (P1 liveness) | ⛔ OPEN | Feature-incomplete, not security. |
| **B12** | [F073](findings/F073-confidential-lock-wallet-builder-emits-non-validatable-messages.md) — wallet `confidential_lock` builder emits wrong `blinding_diff` + empty `range_proof` → always rejected | High (P1 broken-primitive) | ⛔ OPEN | Broken feature; runtime correctly rejects. |

All three are RED-PoC-backed and WSL build-verified (`poc/F071-*`, `poc/F072-*`,
`poc/F073-*`; crate compiled clean, each test fails asserting the property that
should hold).

**Scope decision (same shape as B2–B4):**
- If the **confidential-transfer / stealth / confidential-lock capability is
  in-scope and shipped** this release → **NOT merge-ready** for that feature:
  B10 (security) + B11/B12 (liveness) block. The feature is both incomplete
  (B11/B12 — it doesn't work end-to-end for honest users) and malleable (B10 —
  the validation that runs can be tampered).
- If that capability is **experimental / feature-gated / not enabled** → record
  as known-incomplete pre-ship work; does not gate the consensus/onboarding/bridge
  core.

### Not blocking

- **F074** ([deployer UI unbuildable](findings/F074-deployer-ui-unbuildable-missing-lib-modules-and-node-types.md)) — genuinely broken (build-verified: `npm ci` + `tsc -b`), but peripheral off-chain tooling, outside consensus/bridge scope. Fix before the UI is usable; not a core-scope gate.
- **F075** ([log-then-commit after `stage_block` failure](findings/F075-commit-after-stage-block-failure-log-then-commit.md)) — anti-pattern real, but the only reachable failure drops a secondary timestamp index (block+header+state still atomic); Low / defense-in-depth. Reviewer's "state/header divergence" severity not reachable at this commit. Propagate-before-commit fix advised; not a blocker.

### Bonus revalidation observation

- **F036 → CLOSED at `f4fc4af`.** The range-proof verifier is now wired into
  confidential-lock admission (`verify_value_range` at
  `src/hyper/confidential_lock.rs:230`, empty-proof reject at `:219`). That fix
  is what makes B12/F073's empty `range_proof` hard-fail.

### Updated roster count

Closed: B1, B5, B6, B7, B8, B9 (6). Open: B2, B3, B4 (bridge, conditional) +
**B10, B11, B12 (confidential-transfer, conditional on feature scope)**. Two
independent conditional clusters now gate the merge, each tied to whether a
specific capability (key-compromise recovery / confidential transfers) is a
shipped guarantee of this release.
