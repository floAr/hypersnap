# Revalidation `573d671` — materials summary

Commit [`573d671`](https://github.com/farcasterorg/hypersnap/commit/573d671) — "last pass of audit feedback + integrate hyper fid" (2026-06-29, branch `pow`). Full report: [../../REVALIDATION-573d671.md](../../REVALIDATION-573d671.md).

## Scope of the diff (58fa604 → 573d671)
- `ae83993` testnet-local-run tooling (wallet + validator_registry/epoch).
- `8d17b06` merge of `main` (brings in **PR #35** snapchain v0.13.0 compat — V18 storage-expiry extension + mesh module; parity-correct; no PR34 code impact).
- `573d671` audit-feedback + hyper-fid feature (25 files, +3546/−250; new `native_onboard.rs` +1585).

## Part A — prior findings
- **B5** (slashing signer-index order, the fix-induced regression found in the `58fa604` round) → **FIXED**: `slashed_validators_for_epoch::resolve_signers` resolves indices through `committee_party_order`; correct-polarity property test (`slashing_resolves_signer_index_via_committee_party_order`, runtime.rs:7456).
- **F070** (custody-sig gate unwired) → **FIXED**: production `submit_message` wires `StoreBackedCustodyResolver` (runtime.rs:4145-4151), forcing the strict `validate_and_check_quota` path.
- **B1/F002**, **F018** → still FIXED (guards intact).
- **B2/F049, B3/F047, B4/F048** → still OPEN; `HypersnapBridge.sol` byte-identical to `cab225f`.

## Part B — new native-onboarding subsystem: 4-lane parallel audit

| Lane | Specialist | Headline result |
|------|-----------|-----------------|
| Consensus / determinism | node-lifecycle-actor | ONBD-1 (Critical): off-root per-node FID divergence; ONBD-8 (anchor-on-local-tip, feeds ONBD-1). Established the whole subsystem is applied at gossip-ingestion, off the verkle `hyper_state_root`. |
| Crypto / signatures | rust-crypto-primitives | ONBD-4 (Med–High): rotate-then-replay mints unbounded FIDs from one POW. Cross-flagged ONBD-2. Verified sound: EIP-712 encoding, cross-message/deployment replay separation, `recover_custody`, gate-commitment binding, POW math, ed25519 DSTs, custody-rotation auth. |
| Economics / accounting | chain-economics | ONBD-2 (High): stake-release atom burn; ONBD-3 (Med): stake-lock free-mint on crash; ONBD-5 (Med): weak/mis-calibrated 22-bit POW. Verified sound: validator-Sybil blocked, no double-value/FID-collision, amount conservation. |
| Storage / DoS | http-api-rocksdb | ONBD-6 (Med): stake-arm ecrecover DoS + stake gate live despite "disabled" comment; ONBD-7 (Low): fail-open decode. Verified sound: RootPrefix uniqueness (110/111/112/113/115), intra-node TOCTOU (single-actor), single-batch atomicity of the in-module flows. |

### Cross-lane corroboration
- **ONBD-2 (stake-release burn)** independently found/confirmed by **3 lanes** (economics F-ECON-1, storage F1, crypto F2) — same trace: `admit_onboarding_stake_release` commits the lock delete (native_onboard.rs:1064-1067) before the runtime nonce check (runtime.rs:922-931).
- **ONBD-3 (stake-lock free-mint)** confirmed by 2 lanes (economics F-ECON-2, storage F2).

### Adversarial validation
- **ONBD-1** put through an 8-hypothesis (6 walked) deliberate-disagreement red-team: **CONFIRMED**. Decisive: `submit_message` per-node with no proposer/sync gate (actor.rs:1344, runtime.rs:4057); `PendingMessage` has only `Lock`/`Transfer` so onboarding can't enter a block; `import_block` re-applies neither; maps written straight to RocksDB off `builder.rs:247` `root_commitment()`; replay-rejected so unrecoverable. Blast radius confined to the off-root onboarding/rotation/stake subsystem (High under a strict fund-loss/halt rubric; Critical under a consensus-divergence rubric).

## Merge gate after `573d671`
- Cleared: B1/F002, B5, F070 (+ F018 intact).
- **New hard blockers: B6 (ONBD-1), B7 (ONBD-2).**
- Still open (bridge, contract untouched): B2/F049, B3/F047, B4/F048.

## PoCs (WSL-built red property tests)
- `poc/onbd/ONBD-2-stake-release-burn/` — value-conservation property; red on 573d671.
- `poc/onbd/ONBD-4-rotate-replay/` — replay-rejection property; red on 573d671.
Build recipe: WSL/Linux, rustc 1.95, `RUSTFLAGS="--cap-lints allow"`, malachite sibling staged at `~/malachite`.
