# Hypersnap PR #34 — Fix Revalidation of commit `5c25945` ("audit fixes")

**Fix commit:** [`5c2594563df84c374fdce7cdeae06d3444da3b72`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72) — *"audit fixes"*, Cassandra Heart, 2026-06-12, on PR [#34](https://github.com/farcasterorg/hypersnap/pull/34) (branch `pow`).
**Audited base (pre-fix):** [`cab225f1f63aea…`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9) — the exact commit this PR #34 audit was pinned to. The fix commit is its **direct child**, so the diff *is* the fix set.
**Diff size:** 21 files, +1,032 / −89.
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline, brain library `b2c8f8bade0b`. Revalidation by 7 domain specialists (DKLS/threshold, p2p-gossip, solidity-bridge, consensus/slashing, balance-closure, validator/API, economics), one cluster each.
**Per-cluster detail:** [`materials/revalidation-5c25945/`](materials/revalidation-5c25945/).

---

## What this commit is

A direct response to this audit's 23-finding report. It touches **21 files** spanning every implicated subsystem except one: the Solidity bridge contract. The single most consequential fact of this revalidation is a **negative** — `contracts/src/HypersnapBridge.sol` is **not in the diff** and is byte-identical at the new commit. All four bridge-watermark findings (F045/F047/F048/F049) had contract-side remediations; only the Rust digest builder was touched.

**Structural changes:**

| Change | File (Δ) | Primary findings |
|---|---|---|
| BFT-safe threshold `floor(2n/3)+1` derived in `build_driver`; static `=1` ignored for real sets | `dkls_supervisor.rs` (+108), `main.rs` (+6), `dkls_committee.rs` (+54) | **F028**, F025 |
| Keccak permutation over `(epoch, set_hash, validator_key)` replaces lexicographic party-index map | `dkls_committee.rs`, `dkls_supervisor.rs` | F025 |
| `propagation_source` preserved per buffered frame + re-checked on drain (all 3 submit sites); `PENDING_DKLS_INBOUND_EPOCH_CAP=16` + eldest-epoch eviction | `actor.rs` (+108), `dkls_supervisor.rs` | F024, F016 |
| Per-epoch share prune (`prune_retired_dkls_shares`); registry-miss sender binding flipped fail-closed | `dkls_supervisor.rs`, `actor.rs` | F018, F021 |
| Production router now built `.with_custody_resolver(StoreBackedCustodyResolver)` → strict EIP-712 path | `runtime.rs` (+166) | **F070** |
| Transparent-lock state path rejected at ingress (`router.rs`) **and** block-import chokepoint (`importer.rs:269`) | `importer.rs` (+25), `runtime.rs`, `lock_event.rs` (+10) | **F035** |
| Bulletproofs range proof now mandated + verified against input commitment; `checked_add` | `confidential_lock.rs` (+54) | F036 |
| Slashing penalty set switched UNION→INTERSECTION; conflict keyed on new signature-free `hyper_block_content_hash`; `encode_block` preserves all signed fields | `runtime.rs`, `slashing.rs` (+47), `chain.rs` (+78), `slashing_store.rs` (+36) | F002, F009, F015 |
| `hash == blake3(header)` re-derived + enforced on proposer + read-validator decided paths | `proposer.rs` (+30), `read_validator.rs` (+123) | F012 |
| Gossip `FullProposal` `height`/`round` None-guarded; per-variant 2 MB size caps | `gossip.rs` (+57), `proto/src/lib.rs` (+7) | F013, F022 |
| `authenticate_request` added to `retry_onchain_events` / `retry_fname_events` | `admin_server.rs` (+11) | F039 |
| Canonical cast-content fingerprint feeds both scoring and insertion (empty-text casts now fee-charged) | `fee_charger.rs` (+98) | F068 |
| Honest-signer block-number sanity cap `MAX_SANE_BRIDGE_BLOCK_NUMBER = 2^48−1` (Rust digest only) | `bridge_payload.rs` (+80) | F049 (partial) |

---

## Scoreboard

Scope: all 23 findings (1 Critical, 13 High, 8 Medium, 1 Low). F003 was INVALIDATED at the base and is unchanged by this commit (N/A).

| Severity | Fixed | Partial | Not fixed | N/A |
|---|---|---|---|---|
| **Critical (1)** | F028 | — | — | — |
| **High (13)** | F009, F012, F013, F016, F024, F025, F035, F070 — **8** | F002, F049 — **2** | F045, F047 — **2** | F003 (already invalidated) |
| **Medium (8)** | F015, F021, F022, F039, F068 — **5** | F011, F018 — **2** | F048 — **1** | — |
| **Low (1)** | F036 | — | — | — |

**Critical closed. 15 of 22 active findings fixed.** The residual risk concentrates in **one untouched subsystem (the bridge contract: F045/F047/F048/F049)** plus **one still-live chain-halt in an otherwise-fixed finding (F002)**.

All verdicts were adjudicated by static call-site tracing against the patched source at `5c25945` (originals at `cab225f`). No build was run; several fixes ship their own regression tests (notably F009, F015), uncompiled here.

---

## Critical — confirmed closed

### F028 — DKLS threshold hard-pinned to 1 · **FIXED** (0.95)
`build_driver` now derives the reconstruction threshold as a BFT-safe `floor(2·n/3)+1` (`bft_safe_threshold`) from active-set size; the static `inputs.threshold` (the shipped `=1`) is ignored for `share_count > 1` and the derived value flows into `Parameters`, the `session_id`, and the installed share. A single committee-elected validator can no longer unilaterally produce the group threshold signature. *(No residual; note F025 below is the now-dominant committee-capture lever once threshold > 1.)*

---

## High — fixed (8)

Each verified wired at the real call-site, not merely defined.

- **F070** custody gate unwired · the production `HyperRuntime::submit_message` now builds its single `HyperRouter` with `.with_custody_resolver(StoreBackedCustodyResolver)` (`runtime.rs:3882`), forcing the strict `validate_and_check_quota` EIP-712 custody + per-FID-quota path. The lenient `validate_event(.., None)` branch is no longer reachable on any live ingestion path; all other router constructions are `#[cfg(test)]`. `validator_registry.rs` itself was already correct — the fix is pure wiring.
- **F035** HyperLockEvent mint without balance closure · the transparent-lock state-change path is disabled at two layers: ingress rejects `Body::Lock` (`router.rs:133`) and the block-import chokepoint `import_hyper_block` rejects any block carrying `locks_in_block` (`importer.rs:269`) — the exact proposer-insert vector the finding flagged. Every import wrapper funnels through that gate; no production caller can populate the lock mempool, so `insert_lock_into_tree` is now dead code.
- **F024** buffered DKG drain skips sender auth · each buffer entry now stores its `propagation_source`, and the drain re-runs `check_dkls_sender_against_propagation_source` before **every** `driver.submit` (all three submit sites covered) — broadcast-sender spoofing closed.
- **F025** committee index grinding · party indices are now assigned by a keccak permutation over `(epoch, active-set hash, validator_key)` instead of lexicographic key order, applied consistently in the supervisor, `peer_id_for_party`, and the transport lookup. This is the construction the finding recommended. *(Residual-by-design: the permutation is still a pure function of known inputs — no unpredictable beacon — so a keccak-preimage grind remains theoretically possible but is now computationally hard rather than free.)*
- **F012** block hash never re-derived · `hash == blake3(header)` is now re-derived and enforced before commit on both proposer validate paths (`proposer.rs:235-241, 631-641`) and the read-validator decided path (`read_validator.rs:177-201, 341-350`).
- **F013** FullProposal height unwrap panic · the gossip arm now uses a `None`-guarded `let-else` on `full_proposal.height` plus a negative-`round` guard (`gossip.rs:1058-1075`), and routes via the fallible `shard_id()`. Both unwraps the finding named (the `Option<Height>` and the `round` `try_into().unwrap()`) are unreachable from the decode path.
- **F016** unbounded pending_dkls_inbound · `PENDING_DKLS_INBOUND_EPOCH_CAP = 16` with eldest-epoch eviction bounds the BTreeMap to 16 × 256 frames.
- **F009** slashing predicate conflict on sig-inclusive hash · "conflict" is now keyed on a new signature-free `hyper_block_content_hash` (`chain.rs:62-119`, consumed at `slashing.rs:68-72`) rather than the signature-bearing `hyper_block_hash`; a benign re-sign of identical content no longer mis-slashes. Ships a regression test.

---

## High — partial / not fixed: residuals still live

### ★ F002 — cross-epoch evidence slashes innocent signers · **PARTIAL — chain-halt DoS still live** (0.85)
The primary defect is genuinely fixed: the penalized set now uses the **INTERSECTION** of the two blocks' resolved signers (`runtime.rs:4284-4290`), so a validator who signed only one epoch is no longer evicted for the other committee's block. **But the finding's named second sub-issue is untouched:** the `slashed_validators_for_epoch` ↔ `get_active_validators_enforced` self-recursion. `resolve_signers` calls `get_active_validators_enforced(block_epoch)` (`runtime.rs:4262-4267`), which calls `slashed_validators_for_epoch(E-1)` (`runtime.rs:4122`). Adjacent-epoch evidence `(E-1, E)` is stored under `min=E-1` and is reachable (`detect_conflicting_blocks` never requires equal epochs); at the epoch-E boundary this re-enters itself → stack overflow → chain halt, on **one** attacker-submitted evidence row. No depth guard / memoization added; the `_active_set_at_epoch` parameter that could break the cycle is still ignored (`runtime.rs:4241`).

### ★ F049 — watermark saturation bricks recovery; `executeUpgrade` survives · **PARTIAL — Byzantine-signer core intact** (0.85)
Only the **secondary** (Rust-side) recommendation landed: `MAX_SANE_BRIDGE_BLOCK_NUMBER = 2^48−1` in `bridge_payload.rs`, wired into the two honest producers (`runtime.rs:956, :1086`). This closes only the *accidental / misconfigured-honest-signer* tail — the cap's own doc-comment concedes it does not constrain a Byzantine signer, **who is exactly this finding's threat model.** The contract (`HypersnapBridge.sol`) still has **no `blockNumber` upper bound**, so a threshold-capable adversary can still saturate `latestBlock` to permanently brick `rotateOwner`/`cancelUpgrade`/`pause` while the permissionless, watermark-independent `executeUpgrade` still fires the pending implementation. The High-severity core is open.

### ★ F045 — universal control-plane sigs replay across deployments · **NOT FIXED** (0.95)
`HypersnapBridge.sol` untouched; no chainId / contract-address / deployment-nonce binding was added to any universal digest, and `bridge_payload.rs` did not add it either. `OWNER_ACCEPTANCE` remains watermark-less. Cross-deployment replay of a superseded universal signature is unmitigated.

### ★ F047 — owner-rotation front-run defeats key-compromise recovery · **NOT FIXED** (0.95)
`rotateOwner` still shares the single monotonic watermark namespace with `pause`/`proposeUpgrade`/`cancelUpgrade`/`claim`/`recoverERC20`, with no priority; digests are still public in the mempool. The front-run primitive is intact and the auth digest is not bound to the outgoing owner.

---

## Medium / Low

**Fixed (6):**
- **F015** (M) slashing_store drops signed fields · `encode_block` now copies all six previously-zeroed signing-payload fields plus the full signature struct (`slashing_store.rs:177-210`); stored evidence round-trips its `signing_payload`. Ships a regression test.
- **F021** (M) DKLS sender-binding fail-open · the registry-miss branch is flipped to `return false` (fail-closed); the only remaining permissive case is `propagation_source == None`, which the finding itself deemed acceptable.
- **F022** (M) gossip variants lack size cap · new `MAX_FULL_PROPOSAL_BYTES` / `MAX_DECIDED_VALUE_BYTES` (2 MB) gate both arms via `encoded_len()` before re-encode/dispatch.
- **F039** (M) admin retry RPCs unauthenticated · `authenticate_request(&request, &self.allowed_users)?` is now the first statement of both `retry_onchain_events` (`admin_server.rs:214`) and `retry_fname_events` (`:249`).
- **F068** (M) empty-text cast evades fee · a new `canonical_cast_content()` (text + embeds + mentions + parent, tag-prefixed) feeds **both** `stage_fee` and `record_fingerprint_if_cast`, so empty-text embed/reply/mention casts are now fingerprinted and duplicates pay the fee. The unconditional charged-zero path is gone.
- **F036** (L) confidential-lock range proof unwired · `validate_against_store` now mandates and verifies the Bulletproofs range proof against the input commitment (`confidential_lock.rs:213-237`, `DEFAULT_RANGE_BITS=64`), rejecting missing/empty/bad proofs; `saturating_add`→`checked_add` also closes the related `amount+fee` overflow.

**Partial (2):**
- **F011** (M) read-validator no protocol-version enforcement · **PARTIAL.** A new staleness heuristic in the shard arm of `validate_protocol_version` (`read_validator.rs:238-309`) can `ExitWithError`, but it is best-effort: keyed off the stale binary's *own* schedule horizon with a ~60-day grace window, and only when `derived == EngineVersion::latest()`. A stale node still silently diverges for multiple weeks before halting — the originally-reported failure mode. No signed `ShardHeader.version` was added.
- **F018** (M) DKLS keystore never pruned · **PARTIAL.** `prune_retired_dkls_shares` on the `EvaluateEpochDkls` path closes the core keystore leak, but `Party` / `DklsEpochState` still carry **no Zeroize/Drop** (the new comment claims otherwise — verified false at `crates/dkls23/src/protocols.rs:32`), so retired shares are freed un-scrubbed; the bridge local-sign helpers and lock-root/owner-rotation apply paths still lack the epoch-currency guards the finding called for.

**Not fixed (1):**
- **F048** (M) pause does not gate proposeUpgrade · **NOT FIXED.** `proposeUpgrade` still lacks `whenNotPaused`; this was a pure-Solidity fix and the contract was untouched. The Rust commit is irrelevant to it.

**N/A:**
- **F003** (H) ring-vouch sybil · already INVALIDATED at the base; the emission/reputation files (`eigentrust.rs`, `mutuality.rs`) are byte-identical in this commit. Unchanged.

---

## Notes & caveats

- **Methodology:** static call-site tracing against patched source at `5c25945` (originals at `cab225f`), one domain specialist per cluster. No build/run was performed — verdicts are code-level. Fixes shipping their own regression tests (F009, F015, …) were not compiled here.
- **The bridge contract was not touched at all.** F045 / F047 / F048 / F049 all have their true verification sink in `HypersnapBridge.sol`, which is byte-identical at this commit. The bridge-watermark cluster is effectively unaddressed; the lone Rust-side cap (F049) does not constrain the Byzantine signer that is the cluster's threat model.
- **Recommended re-report set** (still-exploitable after this commit): **F002** (chain-halt residual), **F045**, **F047**, **F049** (contract-side bridge cluster), **F048** (pause/propose gating), plus the two partial hardening gaps **F011** and **F018**. F045/F047/F048/F049 require changes to `HypersnapBridge.sol` that this commit does not contain.
