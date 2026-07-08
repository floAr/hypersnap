# PR #34 — Merge Readiness at tip `f4fc4af`

**Tip commit:** [`f4fc4af`](https://github.com/farcasterorg/hypersnap/commit/f4fc4af) ("Resolve last audit run", 2026-07-07, branch `pow`).
**Audited base:** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).
**Lineage:** `cab225f` → `5c25945` → `58fa604` → `573d671` (+PR#35 v0.13.0 compat) → `ab73681` → `f4fc4af`.

Consolidated merge-gate reevaluation across the full fix lineage. Supersedes [MERGE-BLOCKERS-58fa604.md](MERGE-BLOCKERS-58fa604.md) for the current gate; the intervening native-onboarding rounds are in [REVALIDATION-573d671.md](REVALIDATION-573d671.md), [REVALIDATION-ab73681.md](REVALIDATION-ab73681.md), [REVALIDATION-f4fc4af.md](REVALIDATION-f4fc4af.md).

---

## Verdict

**6 of 9 merge blockers are CLOSED and build-verified. The 3 that remain are all in the Solidity bridge contract, are all CONDITIONAL, and none has been touched since the audited base.**

**There are no remaining hard/unconditional merge blockers.** Both blockers that gated the merge regardless of scope — **B1** (chain halt) and **B5** (validator mis-slashing) — are fixed. Every consensus-side and native-onboarding blocker is resolved.

Merge readiness reduces to a single scope decision:

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
