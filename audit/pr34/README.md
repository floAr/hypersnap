# Hypersnap — PR #34 Audit (Revalidation)

**Audited commit:** [`cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) (branch `pow`)
**PR:** [farcasterorg/hypersnap#34](https://github.com/farcasterorg/hypersnap/pull/34) — "proof of work (restored)"
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline, brain library `b2c8f8bade0b`
**Methodology:** Recon → Hunt (2 rounds, 76 tasks) → 8-hypothesis red-team Validate → Gapfill (PR-scoped) → Dedupe → Trace.

> This is a **separate audit lineage** from the PR #32 / PR #28 findings in [`../`](../README.md); its F-numbers are an independent namespace and do **not** correspond to the same-numbered findings there.

## Revalidation verdict (audit base `cab225f`)
- **Prior F001 (Critical — unsigned slashing evidence): FIXED.** `verify_evidence_signatures` now gates ingestion; no bypass path.
- **Prior F002 (High — lock admission skips verification): NOT fully fixed** → re-surfaces as [F035](findings/F035-hyperlockevent-mint-without-balance-closure.md).

## Fix status — fix commit `5c25945` ("audit fixes")

The maintainer (Cassandra Heart) landed a single fix commit [`5c25945`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72) (2026-06-12, direct child of the audited base) addressing this report. Revalidated by the audit-suite pipeline (static call-site tracing, 7 domain specialists). Full report: [REVALIDATION-5c25945.md](REVALIDATION-5c25945.md); per-cluster detail: [materials/revalidation-5c25945/](materials/revalidation-5c25945/).

| Severity | Fixed | Partial | Not fixed | N/A |
|---|---|---|---|---|
| **Critical (1)** | F028 | — | — | — |
| **High (13)** | F009, F012, F013, F016, F024, F025, F035, F070 | F002, F049 | F045, F047 | F003 (invalidated) |
| **Medium (8)** | F015, F021, F022, F039, F068 | F011, F018 | F048 | — |
| **Low (1)** | F036 | — | — | — |

**Critical closed; 15 of 22 active findings fixed.** Residual risk concentrates in the **untouched Solidity bridge contract** (`HypersnapBridge.sol` is byte-identical at this commit → F045/F047/F048/F049 unaddressed; F049's lone Rust-side cap does not constrain a Byzantine signer) and one **still-live chain-halt** in the otherwise-fixed F002 (`slashed_validators_for_epoch`↔`get_active_validators_enforced` self-recursion). **Recommended re-report set:** F002, F045, F047, F048, F049 (+ partial hardening F011, F018). Per-finding bodies below are unchanged and reflect the **original OPEN state at `cab225f`**; this section is the overlay describing current state on the `pow` branch.

### Merge blockers (single-deployment assumption)

See **[MERGE-BLOCKERS-5c25945.md](MERGE-BLOCKERS-5c25945.md)** — tailored merge-gate report with **runnable PoCs**. Assuming a single canonical deployment (F045 → Informational): **1 hard blocker** — F002 chain-halt (one captured epoch committee → permanent network-wide halt; reproduced via stack-overflow model, in-crate test authored for CI) — plus the **conditional** bridge-recovery cluster F049/F047/F048 (gate the merge only if owner/threshold-key-compromise recovery is a shipped guarantee; all three **reproduced with a passing Foundry test**, [poc/residual-5c25945-bridge/](poc/residual-5c25945-bridge/)). None of the bridge cluster was touched by the fix commit.

## Fix status — follow-up commit `58fa604` ("audit update")

A second fix commit [`58fa604`](https://github.com/farcasterorg/hypersnap/commit/58fa604bb5874d20a58e6fb10b4c9fad903d4b3d) (2026-06-14, **direct child of `5c25945`**) addresses the two post-`5c25945` items fixable in Rust. **Pure Rust — `HypersnapBridge.sol` still byte-identical to `cab225f`.** Full report: [REVALIDATION-58fa604.md](REVALIDATION-58fa604.md).

- **F002 (High) — chain-halt self-recursion: FIXED.** `slashed_validators_for_epoch` no longer re-enters `get_active_validators_enforced`; cross-epoch blocks skipped, same-epoch indices resolved against the caller-passed active set. Clears the **sole unconditional merge blocker (B1)**. Ships a 256 KiB-stack regression test. (Trade: cross-epoch equivocators now under-slashed — authors accept this vs. permanent liveness kill.)
- **F018 (Med) — DKLS shares freed un-scrubbed: core FIXED.** `impl Drop for Party` zeroizes `poly_point`/`session_id`; `DklsCurve: Scalar: Zeroize` wired; regression test. Residual: OT-precompute fields not explicitly zeroized (accepted scope).
- **Bridge cluster unchanged:** F049/F047/F048 (B2–B4) and F045 remain exactly as after `5c25945` — the contract was not touched. F011 also untouched (still partial).
- **★ NEW fix-induced regression (High) — build-verified:** slashing resolves `signer_indices` in **lexicographic** order while signing assigns them in **keccak-permuted** order (`committee_party_order`), so slashing attributes equivocation to the wrong validator (innocent slashed, real equivocator escapes). Introduced by the F025 fix in `5c25945`, carried through `58fa604`. PoC + passing regression test: [poc/residual-58fa604-slashing-index/](poc/residual-58fa604-slashing-index/).

**Build verification (this round):** WSL/Linux build (rustc 1.95) — F002 small-stack test, F018 zeroize test, the `Scalar: Zeroize` trait-bound compile, and the new mis-attribution regression test all build and pass. Closes the prior rounds' "unbuilt" caveat.

**Merge gate after `58fa604`:** the one unconditional blocker (B1/F002) is **cleared**, but a **new High-severity slashing regression** was found and confirmed this round. The merge now hinges on (a) the conditional bridge-recovery cluster B2–B4 (Solidity, untouched) and (b) the signer-index ordering fix in `slashed_validators_for_epoch`. Tailored merge-gate report: **[MERGE-BLOCKERS-58fa604.md](MERGE-BLOCKERS-58fa604.md)**.

## Fix status — follow-up commit `573d671` ("last pass of audit feedback + integrate hyper fid")

Commit [`573d671`](https://github.com/farcasterorg/hypersnap/commit/573d671) (2026-06-29) has two halves. The **audit-feedback** half is clean; the **"integrate hyper fid"** half ships a large new subsystem (`src/hyper/native_onboard.rs`, +1585 lines) with its own new attack surface. Full report: [REVALIDATION-573d671.md](REVALIDATION-573d671.md); per-cluster detail: [materials/revalidation-573d671/](materials/revalidation-573d671/). (This round also merges in **PR #35** snapchain-v0.13.0 compat — parity-correct, no PR34 code impact.)

- **★ B5 (High) — slashing signer-index order: FIXED.** `slashed_validators_for_epoch::resolve_signers` now resolves `signer_indices` through the keccak-permuted `committee_party_order`, matching signing. Correct-polarity security-property regression test (`slashing_resolves_signer_index_via_committee_party_order`).
- **F070 (High) — custody-sig gate unwired: FIXED.** Production `submit_message` now builds the router `.with_custody_resolver(StoreBackedCustodyResolver::new(…))`, forcing the strict `validate_and_check_quota` custody cross-sign + per-FID quota path.
- **Bridge cluster unchanged:** F049/F047/F048 (B2–B4) and F045 remain exactly as after `5c25945`/`58fa604` — `HypersnapBridge.sol` is still **byte-identical to `cab225f`**.

### ★ NEW subsystem findings — hyper-native onboarding (`native_onboard.rs`)

Applies authoritative **identity** + **economic** state at per-node gossip-ingestion, **outside the consensus `hyper_state_root`**. Audited by a 4-lane parallel specialist pass + adversarial validation of the top finding. **1 Critical, 1 High, 4 Medium, 1 Low/Info.**

| ID | Sev | Verdict | Title |
|----|-----|---------|-------|
| [ONBD-1](findings/native-onboard/ONBD-1-offroot-per-node-fid-assignment-divergence.md) | critical | CONFIRMED (0.88, 6/6 refutations failed) | Onboarding assigns FIDs from a per-node global counter off the consensus root → honest nodes permanently disagree on custody→FID identity (also forks rotation + stake-binding); silent, unrecoverable |
| [ONBD-2](findings/native-onboard/ONBD-2-stake-release-burns-staked-atoms-non-atomic.md) | high | CONFIRMED (0.9, ×3 lanes) | Stake release deletes+commits the lock before the fallible nonce check → stale nonce (routine on the shared nonce stream) or crash burns the sponsor's staked atoms, no refund |
| [ONBD-3](findings/native-onboard/ONBD-3-stake-lock-free-mint-on-crash-non-atomic.md) | medium | CONFIRMED (0.78) | Stake lock commits before the balance debit → crash yields a free, releasable lock = net atom inflation |
| [ONBD-4](findings/native-onboard/ONBD-4-rotate-then-replay-mints-unbounded-fids-one-pow.md) | med-high | PLAUSIBLE (0.7) | Rotate-then-replay: one POW solve mints unbounded FIDs (replay guard is the rotation-mutable custody index; no consumed-POW marker) |
| [ONBD-5](findings/native-onboard/ONBD-5-weak-miscalibrated-22bit-sha256-pow.md) | medium | PLAUSIBLE (0.85) | 22-bit SHA-256 POW is ASIC/SHA-NI-trivial (~7 ms, not the "~30s" claimed) — weak sole sybil gate |
| [ONBD-6](findings/native-onboard/ONBD-6-stake-arm-ingestion-ecrecover-dos-live-gate.md) | medium | PLAUSIBLE (0.75) | Stake arm does a full ecrecover before cheap rejection; unauthenticated, no rate-limit/size-cap; stake gate live despite "Phase-2 disabled" comment → ingestion CPU DoS |
| [ONBD-7](findings/native-onboard/ONBD-7-failopen-decode-corrupt-fid-counter-reuse.md) | low | PLAUSIBLE (0.5) | Fail-open decode: corrupt FID counter silently resets issuance to base → FID reuse (corruption-only) |

**Verified SOUND (negatives):** EIP-712 encoding & onboarding↔rotation/cross-deployment replay separation, chainId binding, `recover_custody`, gate-commitment binding, POW bit-math, ed25519 DSTs, custody-rotation auth, RootPrefix uniqueness (110/111/112/113/115), intra-node TOCTOU (single-actor), no double-value / FID-collision, amount conservation, **validator-Sybil amplification blocked** (custody resolver reads only snapchain `IdRegister`, which hyper-native FIDs lack).

**Merge gate after `573d671`:** B5 and F070 **cleared**; F002/F018 intact. **New hard blockers B6 (ONBD-1, consensus divergence) and B7 (ONBD-2, deterministic fund loss)** — the onboarding subsystem should not ship until at least these two are fixed. Bridge cluster B2–B4 unchanged.

## Fix status — follow-up commit `ab73681` ("audit pass")

Commit [`ab73681`](https://github.com/farcasterorg/hypersnap/commit/ab73681) (2026-07-07, direct child of `573d671`) responds to ONBD-1..7. **11 files, +531 / −103; no Solidity touched.** Full report: [REVALIDATION-ab73681.md](REVALIDATION-ab73681.md); per-cluster detail: [materials/revalidation-ab73681/](materials/revalidation-ab73681/). **WSL build-verified** (full crate clean; commit's `native_onboard` suite 17/17); 3 authored PoCs (2 green, 1 red).

- **ONBD-1 (Critical) — FIXED (onboarding mechanism).** FID assignment moved off per-node gossip ingestion into deterministic block-import order, folded into the threshold-signed verkle root; import recomputes the root and rejects on `StateRootMismatch`. Old per-node assigner is dead in prod. **Clears B6.** *Incomplete for custody rotation* → see ONBD-9/10.
- **ONBD-2 (High) — FIXED.** Stake-release delete staged into a single batch, committed only after the nonce check. **Clears B7.** Green PoC ([poc/onbd/ONBD-2-stake-release-burn/](poc/onbd/ONBD-2-stake-release-burn/) flips red→green).
- **ONBD-3, ONBD-6 — FIXED; ONBD-7 — FIXED (core, 2 minor readers remain); ONBD-4 — FIXED (2nd-FID mint blocked, green PoC); ONBD-5 — PARTIAL (30-bit floor, still a soft gate; "governance-tunable" is doc-only).**
- **Bridge cluster unchanged:** F049/F047/F048 (B2–B4) + F045 still **byte-identical to `cab225f`**.

### ★ NEW fix-induced findings — hyper-native onboarding

The ONBD-1 fix folded *onboarding* identity on-root but left *custody rotation* off-root. That single omission (+ the speculative produce path) yields **3 High + 1 Medium**, one build-verified with a red PoC.

| ID | Sev | Title |
|----|-----|-------|
| [ONBD-9](findings/native-onboard/ONBD-9-rotation-off-root-divergence.md) | high | Custody rotation identity is off-root & applied at gossip ingestion → per-node divergence (ONBD-1 anti-pattern reintroduced for rotation; silent, no root-mismatch halt) |
| [ONBD-10](findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md) | high | Onboard replay resurrects a rotated-away custody→FID binding via the mirror sync → **rotation-based key revocation can be undone** (custody double-binding / FID re-capture). **Build-verified red PoC** ([poc/onbd/ONBD-10-mirror-resurrection/](poc/onbd/ONBD-10-mirror-resurrection/)) |
| [ONBD-11](findings/native-onboard/ONBD-11-speculative-produce-tree-pollution-selfhalt.md) | high | Speculative `produce` mutates `self.tree` with no rollback; ONBD-1's global `seq` + permanent `ever` marker turn a losing-proposer divergence into an unrecoverable identity fork + self-halt |
| [ONBD-12](findings/native-onboard/ONBD-12-aged-onboard-produce-import-asymmetry-stall.md) | med | Aged-onboard produce/import re-validation asymmetry + no mempool eviction → proposer stall |

**Refuted (sound negatives):** verkle key collision · `next_hyper_fid` split-brain · double-apply self-halt · import-time nondeterminism fork · restart-replay ordering divergence.

**Merge gate after `ab73681`:** **B6, B7 cleared.** **New hard blockers B8 (ONBD-9+10 — fold rotation into the signed root) and B9 (ONBD-11 — no rollback on speculative produce).** Bridge B2–B4 unchanged.

## Fix status — follow-up commit `f4fc4af` ("Resolve last audit run")

Commit [`f4fc4af`](https://github.com/farcasterorg/hypersnap/commit/f4fc4af) (2026-07-07, direct child of `ab73681`) responds to ONBD-9/10/11/12. **12 files, +540 / −130; no Solidity touched.** Full report: [REVALIDATION-f4fc4af.md](REVALIDATION-f4fc4af.md); per-cluster detail: [materials/revalidation-f4fc4af/](materials/revalidation-f4fc4af/). **WSL build-verified** (full crate clean; `native_onboard` 19/19; broad suite 170/170); green four-way-determinism PoC + ported red→green PoCs.

- **ONBD-9 (High) — FIXED.** Custody rotation is now an on-root, block-ordered transition — the **exact fix direction recommended in ONBD-9**. New `HyperWireBlock.rotations` list flows through mempool → block → import like onboards; `apply_rotation_to_tree` tombstones the old custody (committed empty leaf), binds the new, sets `ever`, and advances an in-tree rotation nonce (domain `0x08`), all under the signed root; import re-validates + rejects on `StateRootMismatch`. **Clears half of B8.**
- **ONBD-10 (High) — FIXED.** Tombstone-aware `read_onboard_custody_fid` + mirror-reflects-tree; the `ab73681` red PoC is now **green** (`onboard_replay_must_not_resurrect_rotated_away_custody_binding`). **Clears the other half of B8.**
- **ONBD-11 (High) — FIXED.** `VerkleTree: Clone`; production builds against `scratch_tree = self.tree.clone()` (genuine deep copy); the only authoritative `self.tree` mutation is `import_block`. **Clears B9.**
- **ONBD-12 (Med) — FIXED.** Produce-time re-validate-and-drop of aged onboards; `verify_anchor` is chain-state-derived (not wall-clock) so no produce/import asymmetry remains.
- **Bridge cluster unchanged:** F049/F047/F048 (B2–B4) + F045 still **byte-identical to `cab225f`**.

### ★ NEW fix-induced findings — all Low, non-blocking

| ID | Sev | Title |
|----|-----|-------|
| [ONBD-13](findings/native-onboard/ONBD-13-mirror-sync-nonatomic-restart-desync.md) | low | Query-mirror sync is non-atomic with block persistence and not rebuilt on restart → self-healing query-index desync on a precisely-timed crash (non-consensus) |
| [ONBD-14](findings/native-onboard/ONBD-14-noop-rotation-not-produce-filtered-reloop.md) | low | No-op rotations lack the ONBD-12 produce filter → re-loopable block-slot/ecrecover waste (deterministic no-op; PoW-FID-bounded) |
| [ONBD-15](findings/native-onboard/ONBD-15-rotation-ecrecover-before-block-sig-check.md) | low | Rotation ecrecover runs (PoW-free) before the block signature check → CPU-only DoS; a minor new instance of a pre-existing pre-sig re-validation class |

**Refuted (sound negatives):** same-block mirror inconsistency · tombstone/empty-value collision · rotation dedup censorship · submit-vs-import fork · `forget_rotation` stranding · rotation-amplified eviction · ONBD-7 readers driven to a wrong FID/stake bypass.

**Merge gate after `f4fc4af`:** **B8 and B9 cleared. No native-onboarding merge blockers remain.** The three new findings are all Low hardening residuals. The merge now hinges solely on the **untouched Solidity bridge cluster B2–B4** (F049/F047/F048).

**★ Consolidated merge readiness (current tip):** [MERGE-BLOCKERS-f4fc4af.md](MERGE-BLOCKERS-f4fc4af.md) — full B1–B9 roster. **6 of 9 blockers closed & build-verified; 3 open, all in the byte-identical bridge contract, all conditional.** No hard/unconditional blockers remain (B1 + B5 were the hard ones, both closed). Merge-ready from the consensus/Rust side; the sole gate is whether "recovery from owner/threshold-key compromise" is a shipped guarantee (if yes → fix B2–B4 first; if de-scoped → documented known-risk).

## External review pass — `felirami` PR comments at `f4fc4af` (2026-07-11)

Five `[P1]` inline review comments run through the validation process:
[REVALIDATION-f4fc4af-review.md](REVALIDATION-f4fc4af-review.md) · per-finding
detail [materials/revalidation-f4fc4af-review/](materials/revalidation-f4fc4af-review/).
**4 confirmed, 1 partial; none refuted.** New IDs **F071–F075**.

| ID | Sev | Title | PoC |
|----|-----|-------|-----|
| [F071](findings/F071-transfer-envelope-not-bound-output-pubkey-malleable.md) | High | Transfer admission+import verify bare `signing_payload()` → relay rewrites output `one_time_pubkey` (denial-of-funds) | RED [poc/F071-*](poc/F071-transfer-envelope-malleable/) |
| [F072](findings/F072-confidential-note-recovery-data-absent-from-wire.md) | High (liveness) | Wire output omits `tx_pubkey`+encrypted payload → notes undiscoverable/unspendable | RED [poc/F072-*](poc/F072-note-unrecoverable-from-wire/) |
| [F073](findings/F073-confidential-lock-wallet-builder-emits-non-validatable-messages.md) | High (broken-primitive) | Wallet `confidential_lock` builder emits wrong `blinding_diff`+empty `range_proof` → always rejected | RED [poc/F073-*](poc/F073-conf-lock-builder-rejected/) |
| [F074](findings/F074-deployer-ui-unbuildable-missing-lib-modules-and-node-types.md) | Med | Deployer UI unbuildable (missing `src/lib/*` + `@types/node`) — peripheral tooling | build-verified |
| [F075](findings/F075-commit-after-stage-block-failure-log-then-commit.md) | Low | Log-then-commit after `stage_block` failure — reachable impact = dropped 2ndary index only (PARTIAL) | spec only |

**Merge-gate impact:** F071/F072/F073 form a **new conditional blocker cluster
(B10–B12) on the confidential-transfer feature** — incomplete (F072/F073) *and*
malleable (F071). Gates the merge only if that feature is in-scope/shipped this
release (parallel to the bridge B2–B4 framing). All three RED-PoC-backed + WSL
build-verified. F074 peripheral (not core-scope); F075 Low (not a blocker). Also
**F036 → CLOSED at `f4fc4af`** (range-proof now wired). Full overlay in
[MERGE-BLOCKERS-f4fc4af.md](MERGE-BLOCKERS-f4fc4af.md#overlay--external-review-pass-felirami-2026-07-11).

## Reports
- [REPORT.md](REPORT.md) — full report, all 23 findings.
- [REPORT-critical-high.md](REPORT-critical-high.md) — condensed report: the 22 verified Critical/High findings.
- Supporting materials: [materials/](materials/) (recon docs, dedupe report, standups).

## Status
23 findings — by severity: **1 Critical, 13 High, 8 Medium, 1 Low**.
Validation verdicts: **8 WATERPROOF · 14 HAS_CAVEATS · 1 INVALIDATED**.
Reachability traces + regression-test PoCs are provided for the 13 verified Critical/High findings (see [poc/](poc/), [traces/](traces/)).

## Findings

| ID | Sev | Verdict | Reachability | PoC / Trace | Title |
|----|-----|---------|--------------|-------------|-------|
| [F028](findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md) | critical | WATERPROOF (0.9) | LOCAL-CONFIG ( | [poc](poc/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key/) [trace](traces/F028-trace.md) | DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set size), so any single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations |
| [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md) | high | HAS_CAVEATS (0.72) | REMOTE-AUTHED-PEER | [poc](poc/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers/) [trace](traces/F002-trace.md) | F026 cross-epoch evidence slashes innocent validators who signed only one of the two epochs |
| [F003](findings/F003-ring-vouch-sybil-amplification-no-vouch-caps.md) | high | INVALIDATED (0.9) | — | — — | Ring-vouch sybil clusters cross the crediter trust floor — EigenTrust has no vouch cap, mutual-vouch requirement, or min-vouchee-trust gate |
| [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md) | high | HAS_CAVEATS (0.6) | REMOTE-UNAUTH ( | [poc](poc/F009-slashing-predicate-flags-benign-resign-as-doublesign/) [trace](traces/F009-trace.md) | Slashing predicate keys 'conflict' on signature-inclusive block hash; two valid threshold signatures over identical block content (sign-ceremony restart / round retry) are mis-classified as double-sign evidence and slash honest signers |
| [F012](findings/F012-block-hash-never-rederived-from-header-decouples-signed-value-from-committed-content.md) | high | HAS_CAVEATS (0.6) | REACHABLE ( | [poc](poc/F012-block-hash-never-rederived-from-header-decouples-signed-value-from-committed-content/) [trace](traces/F012-trace.md) | Block/ShardChunk `hash` is the consensus-committed value but is never re-derived from blake3(header) on validate/commit/read-node paths, decoupling the signed value from the header and body that actually get committed |
| [F013](findings/F013-fullproposal-missing-height-unwrap-panic-on-gossip.md) | high | WATERPROOF (0.92) | REMOTE-AUTHED-PEER | [poc](poc/F013-fullproposal-missing-height-unwrap-panic-on-gossip/) [trace](traces/F013-trace.md) | FullProposal gossip arm calls height().unwrap() before the shard-id guard, so a peer can crash any node with a height-less FullProposal frame |
| [F016](findings/F016-pending-dkls-inbound-unbounded-epoch-keys.md) | high | WATERPROOF (0.9) | REMOTE-UNAUTH | [poc](poc/F016-pending-dkls-inbound-unbounded-epoch-keys/) [trace](traces/F016-trace.md) | F023a pre-StartDkls buffer keyed by attacker-controlled target_epoch with no global cap or stale-epoch eviction, enabling unbounded memory growth from unauthenticated gossip |
| [F024](findings/F024-buffered-dkls-dkg-drain-skips-sender-authentication.md) | high | HAS_CAVEATS (0.84) | REACHABLE | [poc](poc/F024-buffered-dkls-dkg-drain-skips-sender-authentication/) [trace](traces/F024-trace.md) | Pre-StartDkls buffered DKG drain feeds round messages to the ceremony state machine without the F018 sender/peer-id check, enabling broadcast-sender spoofing |
| [F025](findings/F025-committee-index-grinding-via-attacker-chosen-validator-key.md) | high | HAS_CAVEATS (0.78) | REMOTE-UNAUTH | [poc](poc/F025-committee-index-grinding-via-attacker-chosen-validator-key/) [trace](traces/F025-trace.md) | Committee membership is grindable via attacker-chosen validator_key because party indices are assigned by lexicographic key order against a fully predictable per-epoch committee seed |
| [F035](findings/F035-hyperlockevent-mint-without-balance-closure.md) | high | HAS_CAVEATS (0.7) | VALIDATOR(PROPOSER) | [poc](poc/F035-hyperlockevent-mint-without-balance-closure/) [trace](traces/F035-trace.md) | HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed verkle state root with no balance closure, range proof, or signature verification |
| [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md) | high | HAS_CAVEATS (0.85) | RELAYER-ANY | [poc](poc/F045-universal-control-sig-replay-on-lagging-deployments/) [trace](traces/F045-trace.md) | Universal control-plane signatures (propose/cancel-upgrade, pause, owner-rotate) replay onto lagging canonical deployments; the per-deployment watermark is not a sound cross-deployment replay defense |
| [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md) | high | HAS_CAVEATS (0.85) | REACHABLE ( | [poc](poc/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery/) [trace](traces/F047-trace.md) | Owner rotation has no priority over other watermark-consuming actions; a compromised old owner front-runs the recovery `rotateOwner` to retain power or seize permanent ownership, defeating the documented "immediate rotation" key-compromise recovery |
| [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) | high | WATERPROOF (0.88) | REACHABLE ( | [poc](poc/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives/) [trace](traces/F049-trace.md) | A single max-block universal signature saturates the shared watermark, permanently disabling rotateOwner/cancelUpgrade while the watermark-independent executeUpgrade still fires the pending (malicious) implementation |
| [F070](findings/F070-custody-sig-gate-unwired-in-production-router.md) | high | WATERPROOF (0.9) | REMOTE-UNAUTH | [poc](poc/F070-custody-sig-gate-unwired-in-production-router/) [trace](traces/F070-trace.md) | Validator-registration custody-signature gate is never wired into the production ingestion path — the router is built without a CustodyResolver, so the lenient validate_event branch runs and the EIP-712 custody cross-sign is never checked, letting an attacker register arbitrary validator keys under any FID |
| [F011](findings/F011-shard-read-validator-no-protocol-version-enforcement.md) | medium | HAS_CAVEATS (0.8) | — | — — | Shard read-validators have no protocol-version enforcement; stale read-node silently applies post-upgrade chunks under wrong rules and diverges |
| [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md) | medium | HAS_CAVEATS (0.85) | — | — — | slashing_store encode_block zeroes signing_payload-committed fields, so persisted equivocation evidence is no longer self-verifying |
| [F018](findings/F018-dkls-signer-share-keystore-never-pruned-at-epoch-boundary.md) | medium | WATERPROOF (0.9) | — | — — | Per-epoch DKLS23 secret-share keystore (dkls_signers) is never pruned, zeroized, or retired across epoch transitions, so retired threshold shares stay live and signing-capable for the process lifetime |
| [F021](findings/F021-dkls-sender-binding-fail-open-when-party-has-no-registered-peer-id.md) | medium | HAS_CAVEATS (0.82) | — | — — | DKLS inner-sender binding fails open per-party when a committee member registered no libp2p_peer_id, letting any peer spoof that party in a DKLS round |
| [F022](findings/F022-fullproposal-and-decidedvalue-gossip-paths-lack-per-variant-size-cap.md) | medium | WATERPROOF (0.82) | — | — — | FullProposal and DecidedValue gossip ingress paths lack F019 per-variant size caps; full-block payloads bounded only by the 10 MB transport ceiling (memory-amplification DoS) |
| [F039](findings/F039-admin-retry-rpcs-missing-authenticate-request-guard.md) | medium | HAS_CAVEATS (0.8) | — | — — | Admin retry RPCs (retry_onchain_events / retry_fname_events) reachable without authenticate_request guard |
| [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md) | medium | WATERPROOF (0.9) | — | — — | Pause does not gate proposeUpgrade, so an attacker who defers the malicious propose to land effectiveAt at/after pauseExpiry erases the documented 24h "guaranteed lockout" cushion |
| [F068](findings/F068-empty-text-cast-permanently-evades-fee.md) | medium | HAS_CAVEATS (0.82) | — | — — | Empty-text CastAdds (embed/mention/reply-only) permanently evade the per-message fee |
| [F036](findings/F036-confidential-lock-range-proof-defined-but-unwired.md) | low | HAS_CAVEATS (0.9) | — | — — | ConfidentialLockBody.range_proof is carried on the wire but verify_value_range is never wired into the lock-admission path |

## Linked clusters (related-but-distinct)
- **Bridge-watermark:** [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md) · [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md) · [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md) · [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md) — shared `latestBlock` control-plane.
- **Slashing false-positive:** [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md) · [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md) · [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md).

## Layout
- `findings/` — per-finding writeups · `notes/` — validation records (8-hypothesis) + ruled-out hunt notes · `traces/` — entry-point→sink reachability · `poc/<finding>/` — regression-test PoC + README · `materials/` — recon docs, dedupe report, standups.

*Test PoCs assert secure behavior (fail/panic pre-fix, pass post-fix) and are marked UNVERIFIED — authored from source, not compiled.*
