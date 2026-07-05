# Hypersnap PR #34 — Fix Revalidation of commit `573d671` ("last pass of audit feedback + integrate hyper fid")

**Fix/feature commit:** [`573d67112cf5702349767ce0f682250195830ce1`](https://github.com/farcasterorg/hypersnap/commit/573d67112cf5702349767ce0f682250195830ce1) — *"last pass of audit feedback + integrate hyper fid"*, Cassandra Heart, 2026-06-29, on PR [#34](https://github.com/farcasterorg/hypersnap/pull/34) (branch `pow`).

**New commits since the last revalidation (`58fa604`):**
- [`ae83993`](https://github.com/farcasterorg/hypersnap/commit/ae83993) "support testnet local run" (direct child of `58fa604`) — wallet/testnet tooling + minor `validator_registry`/`epoch` changes.
- `8d17b06` merge of `main` → pulls in `495d7ad`/[`a1add28`](https://github.com/farcasterorg/hypersnap/commit/a1add28) = **PR #35** (snapchain v0.13.0 compat; previously analyzed — V18 storage-expiry extension + mesh module; parity-correct; no PR34 code impact).
- [`573d671`](https://github.com/farcasterorg/hypersnap/commit/573d671) — the audit-feedback + hyper-fid feature commit (primary subject of this report). **25 files, +3546 / −250**, including the new 1585-line `src/hyper/native_onboard.rs`.

**Audited base (pre-fix):** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).

**Method:** static call-site tracing against a worktree at `573d671`; a **4-lane parallel specialist audit** of the new native-onboarding subsystem (consensus/determinism, crypto/signatures, economics/accounting, storage-atomicity/DoS) plus an **8-hypothesis adversarial validation** of the top finding. Several findings are independently corroborated across ≥2 lanes. Prior-finding status re-derived from the patched source.

**Prior rounds:** [REVALIDATION-5c25945.md](REVALIDATION-5c25945.md) · [REVALIDATION-58fa604.md](REVALIDATION-58fa604.md).

---

## TL;DR

- **Two prior audit items are now closed:** the ★ slashing signer-index regression (B5, found last round) and **F070** (custody-sig gate unwired) are both **FIXED**, with correct-polarity regression tests.
- **The bridge-contract merge blockers are untouched:** `HypersnapBridge.sol` is byte-identical to `cab225f`, so **F049 (B2), F047 (B3), F048 (B4)** remain **OPEN** exactly as before.
- **The new "integrate hyper fid" feature ships a large new attack surface** (`native_onboard.rs`) that applies authoritative identity + economic state **outside consensus**. The audit found **1 Critical, 1 High, and 4 Medium** issues in it — headlined by a confirmed **per-node state-divergence** (ONBD-1) and a **deterministic staked-fund burn** (ONBD-2).

---

## Part A — Prior findings, status at `573d671`

| # | Finding | Sev | After `58fa604` | After `573d671` |
|---|---------|-----|-----------------|-----------------|
| **B5** | slashing resolves signer index in wrong order (regression from the F025 fix) | High | OPEN (build-verified red) | ✅ **FIXED** |
| **F070** | validator-registration custody-sig gate unwired in production router | High | OPEN | ✅ **FIXED** |
| **B1/F002** | slashing-evidence self-recursion → chain halt | High | FIXED | still FIXED (guard intact) |
| **F018** | retired DKLS shares freed un-scrubbed | Med | FIXED (core) | unchanged |
| **B2/F049** | watermark saturation bricks rotate/cancel/pause | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B3/F047** | owner-rotation front-run defeats key-compromise recovery | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B4/F048** | pause does not gate `proposeUpgrade` | Med | OPEN | ⛔ **OPEN** (contract untouched) |
| F045 | universal control-sig cross-deployment replay | Info | Info | unchanged |
| F011 | shard-read validator no protocol-version enforcement | Med | PARTIAL | unchanged |

### B5 — slashing signer-index order · **FIXED** (0.95)

`slashed_validators_for_epoch::resolve_signers` (`runtime.rs:4510-4535`) now maps each 1-based `signer_index` through
`committee_party_order(epoch, active_set_at_epoch.keys())` — the same keccak-rank permutation signing assigns indices in — instead of raw lexicographic `active_set_at_epoch.keys()`. The B1 cross-epoch skip and the F002 intersection rule (`signers_a ∩ signers_b`) are both preserved. Comment at 4503-4509 explicitly cites *"B5 fix (audit-suite revalidation of 58fa604)"*.

**Regression test** (`runtime.rs:7456` `slashing_resolves_signer_index_via_committee_party_order`): builds a 5-key set, finds the first index where `committee_party_order` diverges from lexicographic order, records a same-epoch equivocation by that index, and asserts the **true party-order signer IS in the slashed set**. This is a *security-property* assertion — green on the fixed code, red on the pre-fix code (correct red→green polarity). It matches the fix recommended in REVALIDATION-58fa604.md exactly.

### F070 — custody-sig gate unwired · **FIXED** (0.9)

The production ingestion path `HyperRuntime::submit_message` (`runtime.rs:4145-4151`) now constructs the router with
`.with_custody_resolver(StoreBackedCustodyResolver::new(OnchainEventStore::new(self.db.clone(), …)))` (comment "F070 fix" at 4129-4137). With a resolver present, `HyperRouter::route_inbound` takes the **strict** branch `validate_and_check_quota` → EIP-712 custody cross-sign + per-FID 3-cap, instead of the lenient `validate_event(.., None)` that skipped custody verification. This is exactly the fix recommended in the F070 writeup. It is confirmed the real production path: the same `submit_message` that does `route_inbound(msg)` with the mempool take/restore the finding described.

Supporting change: `validator_registry.rs` adds `record_bootstrap_entry` and threads a per-validator FID through the bootstrap tuple so bootstrap validators count toward `MAX_VALIDATORS_PER_FID` (developer-labeled "B1" quota regression; new tests `bootstrap_entry_counts_toward_quota`, `bootstrap_entry_with_zero_fid_is_noop`).

### Bridge cluster B2/F049, B3/F047, B4/F048 — **still OPEN**

`HypersnapBridge.sol` and everything under `contracts/` is **byte-identical to baseline `cab225f`** at `573d671` (`git diff cab225f 573d671 -- '*.sol' contracts/` is empty). Neither this commit nor any since `5c25945` touched the Solidity. All three bridge-contract merge blockers remain exactly as described in [REVALIDATION-58fa604.md](REVALIDATION-58fa604.md) and [MERGE-BLOCKERS-58fa604.md](MERGE-BLOCKERS-58fa604.md).

---

## Part B — NEW subsystem: hyper-native onboarding (`native_onboard.rs`, +1585 lines)

**What it is.** FIP-hyper-native-onboarding: validator-assigned FID issuance (FIDs ≥ `HYPER_FID_BASE = 1<<63`) gated by hashcash POW (Phase 1) or a native-token stake lock (Phase 2), plus custody rotation and stake lock/release. Four new `HyperMessage` variants — `NativeOnboard`, `NativeCustodyRotation`, `OnboardingStakeLock`, `OnboardingStakeRelease` — applied directly to authoritative RocksDB state inside `HyperRuntime::submit_message`. New RootPrefixes 110–113,115.

### Meta-finding / framing

This entire subsystem writes authoritative **identity** state (`HyperNativeCustodyToFid`, `HyperNativeFidSequence`, rotation nonces) and **economic** state (stake locks, balance debits/credits) at *per-node gossip-ingestion time* via `submit_message`, and **none of it is covered by the consensus `hyper_state_root`** (`builder.rs:247` = verkle-tree `root_commitment()` only, a 48-byte KZG commitment; `import_block` re-applies only transfers+locks; `PendingMessage` has no onboarding variant, so onboarding physically cannot enter a block). Existing token messages survive this ingestion-time model *only* because per-FID **monotonic nonce gating** forces a deterministic per-sender order and makes replays idempotent. Onboarding breaks that discipline (no per-custody nonce; the signature doesn't bind the assigned FID), and the stake flows break **atomicity** (two independent DB commits with a fallible check straddling the destructive one). Most findings below are consequences of applying consensus-critical state outside consensus.

### Findings

| ID | Finding | Severity | Corroboration |
|----|---------|----------|---------------|
| **[ONBD-1](findings/native-onboard/ONBD-1-offroot-per-node-fid-assignment-divergence.md)** | Off-root, arrival-order FID assignment → honest nodes permanently disagree on custody→FID identity (also forks rotation + stake-binding); silent (no halt), unrecoverable | **Critical** ¹ | determinism lane + validator (6/6 refutations failed) + self-verified |
| **[ONBD-2](findings/native-onboard/ONBD-2-stake-release-burns-staked-atoms-non-atomic.md)** | Stake **release** deletes+commits the lock *before* the fallible nonce check → wrong/stale nonce (or crash) **burns the sponsor's staked atoms** with no refund | **High** | economics + storage + crypto (×3) |
| **[ONBD-3](findings/native-onboard/ONBD-3-stake-lock-free-mint-on-crash-non-atomic.md)** | Stake **lock** write commits *before* the balance debit (separate txns) → crash mints a free, releasable lock = net atom inflation | **Medium** ² | economics + storage |
| **[ONBD-4](findings/native-onboard/ONBD-4-rotate-then-replay-mints-unbounded-fids-one-pow.md)** | Rotate-then-replay: one POW solve mints unbounded FIDs (replay guard is the rotation-mutable `custody_to_fid`; no consumed-POW marker) within the 1024-block anchor window | **Medium–High** | crypto lane |
| **[ONBD-5](findings/native-onboard/ONBD-5-weak-miscalibrated-22bit-sha256-pow.md)** | 22-bit SHA-256 POW is ASIC/SHA-NI-trivial (~7 ms–0.8 s, not the "~30 s" the comment claims) — weak sole Phase-1 sybil gate | **Medium** | economics lane |
| **[ONBD-6](findings/native-onboard/ONBD-6-stake-arm-ingestion-ecrecover-dos-live-gate.md)** | Stake-arm onboarding does a full secp256k1 ecrecover before any cheap rejection; no rate-limit/size-cap (inherits F022); stake gate is **live** despite the "Phase-2 `StakeGateNotYetEnabled`" comment → ingestion CPU DoS | **Medium** | storage lane |
| **[ONBD-7](findings/native-onboard/ONBD-7-failopen-decode-corrupt-fid-counter-reuse.md)** | Fail-open decode: a present-but-wrong-length `HyperNativeFidSequence` silently resets issuance to `HYPER_FID_BASE` → FID reuse (corruption-only, not attacker-reachable) | **Low/Info** | storage lane |
| ONBD-8 | Anchor acceptance gated on each node's live tip → admits the same onboarding at different tips/orders (feeds ONBD-1) | Low (Medium as ONBD-1 input) | determinism lane |

¹ Validator CONFIRMED across all 6 refutation hypotheses. The blast radius is confined to the off-root onboarding/rotation/stake subsystem (no demonstrated main-ledger halt or fund-loss consumer), so a reviewer applying a strict "Critical = fund-loss/chain-halt of the main ledger" rubric could rate it **High**; under a consensus/state-divergence rubric (permanent honest-node disagreement, no recovery path) it is **Critical**.
² **High if crash-reachable** — the outcome is unbounded atom inflation; only the trigger window (crash / commit I/O failure between the two commits) keeps it at Medium.

### ONBD-1 — off-root per-node FID divergence · **Critical** *(validator CONFIRMED — 6/6 refutations failed)*

`submit_message` runs on every `InboundMessage` (gossip) at ingestion, off consensus (`actor.rs:1344`; never called from `import_block`, no `is_proposer`/`is_syncing` gate). `apply_onboarding` (`native_onboard.rs:575`) assigns `fid = next_hyper_fid(db)` from the **global** counter and writes `HyperNativeCustodyToFid[custody]=fid` (`582-583`); the EIP-712 body signs custody/anchor/gate_commitment but **not** the FID, and there is no per-custody nonce.

Two onboardings from distinct custodies `C_A`,`C_B`, current sequence `N` everywhere:
- Node 1 gossip order A→B: `C_A=N`, `C_B=N+1` (seq→N+2).
- Node 2 gossip order B→A: `C_B=N`, `C_A=N+1` (seq→N+2).

The counter *value* converges (both reach N+2), but `HyperNativeCustodyToFid` **permanently disagrees** — FID N is owned by different custodies on different nodes. Maps are off-root (`builder.rs:247`), so no state-root mismatch → import never fails → **no halt; silent identity fork.** Replays are `CustodyAlreadyOnboarded` (`native_onboard.rs:535`) → **unrecoverable** (a resynced node rebuilds the map only from live gossip going forward, never from consensus). Custody rotation (`723`, checks `lookup_custody_fid==fid`) and stake binding inherit the split.

**Self-verified:** `hyper_state_root` is the 48-byte verkle root only; `apply_onboarding` is reachable **only** from the `submit_message` intercept (`runtime.rs:4060`), never from the builder or import; `PendingMessage` (`builder.rs`) has only `Lock`/`Transfer` variants. **Fix (design-level):** sequence onboarding through consensus (route it, assign the FID deterministically at `import_block` from block-canonical order, like transfers); or derive the FID deterministically from custody/anchor instead of a mutable counter; or fold the onboarding maps into the verkle state root so divergence halts rather than silently forks.

### ONBD-2 — stake-release atom burn · **High** (triple-confirmed)

`apply_onboarding_stake_release` (`runtime.rs:891`) calls `admit_onboarding_stake_release`, which **commits** `batch.delete(lock)` (`native_onboard.rs:1064-1067`) and returns `(sponsor, amount)` — *before* the runtime's nonce check at `runtime.rs:922-931`, which can `return Err(NonceMismatch)` before the credit-back commit (`938-955`). `HyperTokenNonce` is **shared** across all token messages, so any other op from the sponsor that advances the nonce ahead of a pre-signed release turns it into a **deterministic burn**: lock deleted, refund never credited, and a correctly-nonced retry hits the `(0,0)` no-op path (`1033-1037`). The same loss occurs on a crash between the two commits. **Fix:** validate nonce/sponsor/maturity/unbound *before* any destructive write; fold `delete(lock)` + balance-credit + nonce-bump into **one** `RocksDbTransactionBatch` committed once (`admit_*` should return the record, not commit). See red PoC: [`poc/onbd/ONBD-2-stake-release-burn/`](poc/onbd/ONBD-2-stake-release-burn/).

### ONBD-3 — stake-lock free-mint on crash · **Medium** (High if crash-reachable)

Mirror ordering: `admit_onboarding_stake_lock` commits the lock record (`native_onboard.rs:1010-1016`) *before* the runtime debits balance in a separate commit (`runtime.rs:866-883`). A crash / commit-failure between them → durable lock with no debit; retry fails `LockAlreadyExists` so the debit never happens; at maturity `release` credits `amount_atoms` (≥ `MIN_STAKE_AMOUNT` = 1e9) the sponsor never spent → net minting. **Fix:** single atomic batch (lock-write + debit + nonce-bump). Shares root cause with ONBD-2.

### ONBD-4 — rotate-then-replay unbounded FID minting · **Medium–High**

Onboarding carries no per-onboarding nonce and no consumed-POW marker; anti-replay rests solely on `custody_to_fid[custody]`, which `apply_custody_rotation` deletes (`native_onboard.rs:777`). Sequence: onboard A (1 POW) → FID X; rotate X→B (frees `custody_to_fid[A]`); **replay the byte-identical onboarding body** (anchor still in the 1024-block window, POW re-verifies, uniqueness now passes) → FID Y; repeat → unbounded FIDs per anchor window from one POW. The shipped `double_onboard_same_custody_rejected` test only covers replay *while the custody still holds the FID*. **Fix:** write a permanent rotation-immune marker (`HyperNativeCustodyEverOnboarded[custody]` or `PowSpent[custody‖anchor‖nonce]`) inside the atomic batch and check it in `apply_onboarding`. Amplified by ONBD-5. See red PoC: [`poc/onbd/ONBD-4-rotate-replay/`](poc/onbd/ONBD-4-rotate-replay/).

### ONBD-5 — weak/mis-calibrated POW · **Medium**

`MIN_DIFFICULTY_BITS = 22` ⇒ ~4.2M SHA-256/FID. With SHA-NI (~300–600 MH/s): ~7–14 ms/FID; GPU/ASIC: microseconds — not the "~30 s single-core" the comment (`native_onboard.rs:46-51`) claims (off by ~35×–3600×). SHA-256 PoW is ASIC-dominated. **Fix:** raise difficulty substantially and/or switch to a memory-hard function (Argon2/scrypt); correct the misleading comment. Combined with ONBD-4, POW provides essentially no sybil resistance.

### ONBD-6 — stake-arm ingestion DoS + live "disabled" gate · **Medium**

`validate_onboarding` rejects a bad **POW** cheaply (1 SHA-256) before ecrecover, but the **stake** arm (`native_onboard.rs:461-492`) only does length/floor checks then falls through to a full `recover_custody` ecrecover (`504-505`); lock existence is checked later. `POST /messages` (`http_handler.rs:190-200`) and the gossip path both accept these unauthenticated with no rate-limit/size-cap (the F022 gap is inherited). An attacker floods cheap messages (public anchor + garbage 65-byte sig) forcing an ecrecover each. The header comment claims the stake gate is "Phase 2, currently `StakeGateNotYetEnabled`" but **no such gate exists** — the stake path is fully live (which also makes ONBD-2/ONBD-3 reachable now, not dormant). **Fix:** actually gate the stake arm until Phase 2 (or check a cheap precondition before ecrecover); add per-variant rate-limit + size cap.

### ONBD-7 — fail-open decode of corrupt counters · **Low/Info**

`next_hyper_fid` / `lookup_custody_fid` / `read_rotation_nonce` (`native_onboard.rs:171-183,186-202,644-658`) treat a present-but-wrong-length value as the default (`HYPER_FID_BASE` / `None` / `0`). Not attacker-reachable (writers always emit 8 bytes), but a corrupt sequence value silently resets issuance to the base → FID reuse. **Fix:** fail closed on wrong-length (match `OnboardingStakeLock::decode`'s strict check).

### Verified SOUND (negative results)

EIP-712 typed-data encoding (`uint64` valid, no prehash-collision), onboarding↔rotation and cross-deployment replay separation (distinct typeHash; chainId bound), `recover_custody` v-byte handling (malleability present but non-exploitable — recovery must equal declared custody), gate-commitment binding, POW hash/target bit-math (boundary-checked, no OOB), ed25519 stake DSTs (`-lock-v1`/`-release-v1` disjoint, chainId bound), custody-rotation authorization (binds fid/current/new/nonce/chainId + monotonic nonce), **RootPrefix discriminants unique** (110/111/112/113/115; 114 is an unused gap), **intra-node TOCTOU safe** (single `HyperActor` task + `&mut self` serializes all read-then-commit — caveat: this breaks if the runtime is ever sharded across threads sharing the DB), no double-value (release XOR onboard are mutually exclusive), no FID-space collision with real Farcaster FIDs, amount conservation, and — notably — **validator-Sybil amplification is blocked**: `StoreBackedCustodyResolver` reads only the snapchain `IdRegister` on-chain event, which hyper-native FIDs (≥2^63) lack, so validator registration under a hyper-native FID is rejected `CustodyAddressUnknown` (residual gating dependency: this protection lapses if a future resolver is made hyper-native-aware while the trust floor is 0.0).

---

## Merge-gate status after `573d671`

| # | Gate | Type | Status |
|---|------|------|--------|
| B1 | F002 chain-halt | Hard | CLEARED (58fa604) |
| B5 | slashing signer-index order | Hard (High) | **CLEARED** ✅ (573d671) |
| F070 | custody-sig gate wiring | Hard (High) | **CLEARED** ✅ (573d671) |
| B2 | F049 watermark saturation | Conditional ¹ | OPEN (contract untouched) |
| B3 | F047 owner-rotation front-run | Conditional ¹ | OPEN (contract untouched) |
| B4 | F048 pause vs proposeUpgrade | Conditional ¹ | OPEN (contract untouched) |
| **B6** | **ONBD-1 onboarding state divergence** | **Hard (new)** | **OPEN** — consensus-safety defect in the new feature |
| **B7** | **ONBD-2 stake-release atom burn** | **Hard (new)** | **OPEN** — deterministic fund loss |

¹ B2–B4 gate the merge only if owner/threshold-key-compromise recovery is a shipped guarantee (per `HypersnapBridge.sol:266-270`).

**Bottom line.** The audit-feedback half of `573d671` is clean: **B5 and F070 are properly fixed** with good regression tests, and the F002/F018 fixes are intact. But the *"integrate hyper fid"* half introduces a **new consensus-safety defect (ONBD-1, Critical)** and a **new deterministic fund-loss bug (ONBD-2, High)**, plus four Medium hardening items — all in code that applies authoritative state outside the consensus root. **The onboarding subsystem should not ship until at least ONBD-1 and ONBD-2 are fixed.** The pre-existing bridge cluster (B2–B4) is unchanged and still requires the Solidity edits that have not landed in any fix commit.
