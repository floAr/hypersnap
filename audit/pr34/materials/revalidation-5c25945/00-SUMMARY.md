# PR #34 Revalidation — new commit `5c25945` ("audit fixes")

**Audited (findings) commit:** `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
**Fix commit verified:** `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child of the audited commit; diff = the fixes)
**Verified:** 2026-06-12 · static, adversarial, per-finding revalidation by audit-suite specialists
**Per-group detail:** `findings/revalidation/*.md`

## Scoreboard (23 findings)

| Outcome | Count | IDs |
|---|---|---|
| ✅ FIXED | 15 | F009, F012, F013, F015, F016, F021, F022, F024, F025, F028, F035, F036, F039, F068, F070 |
| ⚠️ PARTIALLY FIXED | 4 | F002, F011, F018, F049 |
| ❌ NOT FIXED | 3 | F045, F047, F048 |
| ➖ N/A (already invalidated) | 1 | F003 |

## Critical/High subset (the 13 that survived validation)

| ID | Sev | Prior verdict | Revalidation | Note |
|----|-----|---------------|--------------|------|
| F028 | Critical | WATERPROOF | ✅ FIXED | BFT-safe `floor(2n/3)+1` threshold derived in `build_driver`; static `=1` ignored for real sets |
| F070 | High | WATERPROOF | ✅ FIXED | Production router now `.with_custody_resolver(...)`; lenient `None` branch unreachable |
| F013 | High | WATERPROOF | ✅ FIXED | `height`/`round` None-guarded on gossip decode arm |
| F016 | High | WATERPROOF | ✅ FIXED | `PENDING_DKLS_INBOUND_EPOCH_CAP=16` + eldest-epoch eviction |
| F024 | High | HAS_CAVEATS | ✅ FIXED | `propagation_source` preserved + re-checked on drain (all 3 submit sites) |
| F025 | High | HAS_CAVEATS | ✅ FIXED | Keccak permutation over `(epoch,set_hash,key)` replaces lexicographic index map |
| F035 | High | HAS_CAVEATS | ✅ FIXED | Transparent-lock path rejected at ingress AND block-import chokepoint |
| F012 | High | HAS_CAVEATS | ✅ FIXED | `hash == blake3(header)` re-derived + enforced on proposer + read paths |
| F009 | High | HAS_CAVEATS | ✅ FIXED | Conflict now keyed on signature-free `hyper_block_content_hash` |
| **F049** | High | WATERPROOF | ⚠️ **PARTIAL** | Rust honest-signer cap only; **contract has no `blockNumber` bound** → Byzantine-signer brick + `executeUpgrade` theft still open |
| **F002** | High | HAS_CAVEATS | ⚠️ **PARTIAL** | INTERSECTION fix lands (false-slash closed), but **`slashed_validators_for_epoch`↔`get_active_validators_enforced` self-recursion chain-halt remains** — one evidence row → stack overflow |
| **F045** | High | HAS_CAVEATS | ❌ **NOT FIXED** | `HypersnapBridge.sol` untouched; no chainId/address binding on universal digests |
| **F047** | High | HAS_CAVEATS | ❌ **NOT FIXED** | `rotateOwner` still on shared watermark; front-run primitive intact |

## Headline

**The Solidity bridge contract `contracts/src/HypersnapBridge.sol` was not modified at all.** It is byte-identical at the new commit. All four bridge-watermark findings (F045, F047, F048, F049 — three High + one Medium) had **contract-side** recommended fixes; only the Rust digest builder (`bridge_payload.rs`) got a block-number sanity cap, which by its own doc-comment does not constrain a Byzantine signer — i.e. the actual threat model of F049. **The bridge cluster is effectively unaddressed.**

## Residual gaps in "fixed" areas (do not regress)

- **F002 (High) — still a chain-halt DoS.** The innocent-signer false-slash is fixed (intersection), but the cross-epoch evidence self-recursion was not touched. Adjacent-epoch evidence `(E-1, E)` → infinite re-entry at the epoch boundary → stack overflow. One attacker-submitted evidence row. No depth guard / memoization added; `_active_set_at_epoch` still ignored (`runtime.rs:4241`).
- **F018 (was WATERPROOF) — partial.** Per-epoch prune added (`prune_retired_dkls_shares`) closes the keystore leak, but `Party`/`DklsEpochState` still have **no Zeroize/Drop** (the new comment claims otherwise — false); secret shares freed un-scrubbed. Bridge local-sign + lock-root/owner-rotation apply paths still lack epoch-currency guards.
- **F011 — partial.** New 60-day staleness heuristic can halt, but it's best-effort off the stale binary's own schedule horizon; a stale node still silently diverges for a multi-week grace window. No signed `ShardHeader.version` added.

## Method note

Read-only static revalidation against the diff `cab225f..5c25945` plus full reads of the new-commit files; each finding routed to its original specialist (DKLS, p2p, bridge, consensus/slashing, balance-closure, economics, API). Dynamic execution was not performed — verdicts are code-level.
