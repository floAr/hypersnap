# PR #32 Delta Audit — hypersnap `4a6bca5`

**Date:** 2026-05-29
**PR:** [farcasterorg/hypersnap#32](https://github.com/farcasterorg/hypersnap/pull/32) — "snapchain v17 compat + audit fix"
**Scope:** diff-to-main `ab945ec..4a6bca5` (3 commits, 20 files, ~1616 lines). PR #30 (hyper-api) and #12 (feed) are already on `main` and excluded.
**Method:** scoped recon → 5-specialist hunt (max-parallel 2) → F151 fix backcheck → snapchain v0.12.0 cross-verification → validate → dedupe.
**Build:** `4a6bca5` **COMPILES** on WSL nightly (0 errors, 17 warnings) — contrast with PR#28 R2/R3 which did not compile.

---

## Commits

| commit | purpose | verdict |
|---|---|---|
| `4879074` | snapchain v17 compat delta (FIP-268 LIVE_AT, gasless signers, gossip self-heal) | parity-confirmed vs upstream; 1 new high (F160, inherited) |
| `b464cfb` | "pulling in a fix from the audit" = **fix for finding F151** | primary claim fixed; **1 residual high (F185)** |
| `4a6bca5` | upstream-discrepancy cleanup + Dockerfile | no new findings |

---

## ★ PRIORITY VERDICT — introduced-by-PR issues & fork/divergence risk

**Operator priority = (1) issues *introduced* by this PR, (2) hypersnap↔snapchain mismatches that could fork.**

**Fork/consensus-divergence risk: NONE FOUND.** A systematic drift sweep (snapchain v0.12.0 as the v17 spec; full-function comparison, not hypothesis-spot-checks) confirmed parity across every consensus-deterministic surface:

| Surface | Result (hypersnap@4a6bca5 vs snapchain v0.12.0) |
|---|---|
| `Vote/Proposal::to_sign_bytes`, `to_proto` (SIGNED bytes) | byte-identical |
| codec `encode` (×6 impls) + `decode` | byte-identical; F151 `try_*` only diverge on *malformed* input (Err vs panic — both reject) |
| `CommitCertificate` signature-aggregation order | identical (no reorder) → no cross-impl cert-verify fork |
| consensus wire protos (Vote/Proposal/Commits/Sync*) | byte-identical; PR's proto edits are gRPC-surface only |
| `message.rs` validation predicates (full +36 delta) | identical thresholds/gates/errors (`>256`, LiveAt feature-gate) |
| V17 activation trigger | keyed on **block timestamp on the consensus path** (not wall-clock) → no activation-boundary fork; devnet jump doesn't touch F004 cutover |
| hypersnap-specific v17 glue | LIVE_AT not wired into PoW/DKLS/fees/verkle; hyper shadow-store dual-write is in its own keyspace, never feeds consensus `shard_root` |
| block application ordering | `get_message_priority` + stable sort byte-identical → deterministic across nodes |

→ The v17 port is a **faithful, consensus-deterministic** match to upstream. Parity artifacts: [F190](findings/F190-pr32-fork-drift-sweep-codec-types-parity.md), [F195](findings/F195-livet-validation-version-parity-confirmed.md).

**Issues introduced by this PR:** the only introduced defect is **F160** (a panic newly *reachable-by-default* in introduced LIVE_AT code) and **F185** (the PR's own F151 fix is incomplete). Both are DoS/liveness, **not** fork vectors. F165/F166 are verbatim-inherited (not introduced). None of the four findings below can fork the chain.

## Findings (4 — all DoS/liveness, none fork-causing; priority-secondary)

### F160 — HIGH — LIVE_AT rate limiter panics on a FID routed to a non-hosted shard
`LiveAtRateLimits::consume_for_fid` (`mempool.rs:209-234`) does `shard_stores.get(&route_fid(fid, num_shards)).unwrap()`. `num_shards` is network-wide but `shard_stores` holds only the locally-hosted subset (`shard_ids`). On the standard subset-hosting topology (`num_shards=2, shard_ids=[1]`) ~half of all FIDs route to a non-hosted shard → `None.unwrap()` → node crash. **Reachable by default** via unauthenticated gossip mempool ingress (the general `RateLimits` with the same pattern is gated behind `enable_rate_limits`, default off; the LIVE_AT limiter is always-on). Triggers on **honest traffic** too (stability bug), not only adversarial. Testnet live now; mainnet arms at V17 (2026-06-04). Single-shard deployments unaffected (→ High, not Critical). **Upstream-inherited** (verbatim from snapchain v0.12.0). PoC: [`poc/F160-live-at-shard-panic/`](poc/F160-live-at-shard-panic/) — **RUNNABLE, CONFIRMED**. Under WSL nightly (`cargo +nightly test --lib f160_poc_...`) the mempool task panicked at `mempool.rs:212:59: called `Option::unwrap()` on a `None` value` (log: [`f160-poc-4a6bca5.log`](poc/F160-live-at-shard-panic/f160-poc-4a6bca5.log)). Validation: WATERPROOF ([notes/F160-validation.md](notes/F160-validation.md)).

### F185 — HIGH — `verify_signatures` panics on peer-gossiped `Commits` before signature check (F151 residual)
The F151 fix migrated the malachite **codec** decode arms to `try_to_commit_certificate`, but the original panicking `Commits::to_commit_certificate()` (`types.rs:758`) is **still called by `verify_signatures()`** (`util.rs:103`) as its first statement — before any signature/quorum check. On the read-node path, the `proto::Commits` arrives via raw `proto::GossipMessage::decode` (`gossip.rs:862`) and **never crosses the fixed codec**. A single peer gossips a `DecidedValue` whose inner `Commits` has a `CommitSignature.signer` of length ≠ 32 → `Address::from_vec` `copy_from_slice` abort → every subscribed read-node crashes, unauthenticated, pre-verify. The value-sync path (`read_sync.rs:344-359`) is also exposed (re-decodes `value_bytes`; the codec only validated the sibling top-level `commits`). `block_receiver.rs:86` ruled out (locally-sourced). **The F151 fix is one rewire short of complete** on exactly the read-node-crash path it targeted. Fix: point `verify_signatures` at the existing `try_to_commit_certificate()` and drop the block on `Err`.

### F165 — LOW — `get_signers_by_fid` nonce-loop amplification (gRPC)
`server.rs:2699-2731` does one `get_app_nonce` RocksDB read per `requester_fids` element; no cap, unauthenticated, no rate limit. gRPC ~4 MiB ceiling → ~10⁵–10⁶ serial reads/request. Upstream-inherited (verbatim). Newly reachable because PR widened `FidRequest → SignersByFidRequest`.

### F166 — LOW — GET `/v1/signersByFid` query-string amplification (HTTP)
Same sink via `serde_qs` GET parse (`http_server.rs:4166-4179`); unbounded `requesterFids[]` in the URL. Upstream-inherited. (Recon's "bypasses 4 MiB POST cap" premise was **corrected**: hypersnap has no body cap on any method — bare `serve_connection`; the unbounded-POST-body surface is pre-existing/out-of-delta.) Snake/camel alias smuggling **ruled out** (deterministic precedence).

---

## Ruled out (with evidence)

- **H201** mempool insert/coalesce LWW desync — coalescing contract holds; failed-admission LIVE_AT does not evict prior pending; index is single-slot, self-healing, bounded.
- **H204** gossip self-heal force-bounce churn — hard-bounded ≤1 bounce/60s/peer (`last_force_bounce_at` never reset on reconnect); no cross-peer eviction; bounce set = operator-trusted `direct_peers` config only. hypersnap drifts **safer** than upstream.
- **H205** startup-ordering / channel resize — gossip ingress can't reach stores before init (messages buffer in `system_rx`, drained only after stores ready); `1000→16384` is parity-to-upstream, semantics unchanged. Does **not** widen F160.

---

## Snapchain v0.12.0 cross-verification

| Surface | Result |
|---|---|
| version schedule / `protocol_version()` / LIVE_AT gate / 256-byte limit | **PARITY CONFIRMED** byte-for-byte — no hypersnap↔snapchain consensus-fork risk |
| proto fields (message/request_response/rpc) | identical field numbers/types/optionality |
| mempool LiveAtRateLimits + coalesce | verbatim (F160 inherited) |
| server.rs nonce loop / http_server query parse | verbatim (F165/F166 inherited) |
| gossip self-heal | faithful; hypersnap drifts safer |
| **F151/F002 codec panics** | **upstream snapchain is STILL VULNERABLE** — has no `try_*` variants; hypersnap is ahead. **Recommend reporting the codec-panic class to farcasterxyz/snapchain.** |

---

## Dedupe (link-only)

- **F165 ↔ F166**: same-root-cause (two transports). **↔ F154** (high, batch endpoints): related-but-distinct, same class but far lower per-element cost (point-read vs unbounded loop). **↔ F031**: related (systemic ingress rate-limit gap).
- **F185 ↔ F151**: same panic site, different reach path — the residual of F151's fix. **↔ F005**: related-but-distinct (fires after F005's `value==None` guard).
- **F160**: stands alone; related-by-class to F151 only.

(Full detail: [PR32-materials/dedupe.md](PR32-materials/dedupe.md), [PR32-materials/F151-fix-backcheck.md](PR32-materials/F151-fix-backcheck.md), [PR32-materials/recon.md](PR32-materials/recon.md).)

---

## Bottom line for the PR (operator priority order)

1. **No fork / consensus-divergence risk introduced.** Full-function drift sweep vs snapchain v0.12.0 confirms byte-identical signed payloads, codec, certificate construction, validation predicates, activation trigger, and deterministic block application. The v17 port is faithful. (F190, F195.)
2. **Introduced defects (both DoS/liveness, NOT fork):**
   - **F160** (high) — always-on LIVE_AT limiter `shard_stores.get(shard).unwrap()` → default-reachable node crash on subset-hosting topology; runnable PoC confirms. Fix before mainnet V17 (2026-06-04).
   - **F185** (high) — the PR's own F151 fix is incomplete: `verify_signatures` still panics on peer `Commits` via the read-node gossip path that bypasses the fixed codec. One-line rewire to `try_to_commit_certificate` finishes it.
3. **Inherited / not-introduced (secondary):** F165/F166 (low) gasless-signer amplification — verbatim from upstream; the F160/F185 *logic* is also upstream-inherited (the PR newly *exposes* F160 and *partially fixes* F185).
4. **Upstream snapchain** still carries the F002/F005/F151 codec-panic class (no `try_*` variants) — worth an upstream report; hypersnap is ahead.
