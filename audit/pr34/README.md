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
