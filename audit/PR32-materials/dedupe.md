# PR #32 delta — dedupe judgments (link-only, no merging)

New findings from this pass: **F160** (high), **F165** (low), **F166** (low), **F185** (high).
Judged against the 57 standing findings. Taxonomy: same-root-cause / related-but-distinct / unrelated.

| Pair | Verdict | Rationale |
|---|---|---|
| **F165 ↔ F166** | **same-root-cause** | One defect (unbounded `requester_fids` → per-FID nonce read), two transports: gRPC `GetSignersByFid` (F165) vs HTTP GET `/v1/signersByFid` query-string (F166). Same sink `server.rs:2716`. Keep both (distinct ingress surfaces) but link tightly. |
| **F165/F166 ↔ F154** (standing, high — batch endpoints unbounded fids + uncapped pagination) | **related-but-distinct** | Same *class* (unbounded-fid-list ingress amplification) but different endpoint and **much lower per-element cost**: F154 runs an unbounded `get_casts_by_fid` loop per FID (→ High); F165/F166 do a single nonce point-read per FID (→ Low). Same systemic gap, lesser instance. |
| **F165/F166 ↔ F031** (standing — no rate limit on http/grpc ingress) | **related-but-distinct** | F031 is the systemic root: an ingress rate-limit / request-size cap would blunt F154/F165/F166 together. F165/F166 are specific amplifiers that F031's absence leaves unmitigated. |
| **F160 ↔ F151** (standing — codec decode panics) | **related-but-distinct** | Same *class* (peer-reachable `.unwrap()` panic DoS) but different subsystem (mempool LIVE_AT limiter vs consensus codec) and root cause (shard-routing/`shard_stores` mismatch vs malformed-proto). |
| **F185 ↔ F151** (standing) | **same-root-cause, different reach path** | The panic site is literally the *same function* `Commits::to_commit_certificate()` on malformed peer `Commits`. F151's fix migrated the **codec** decode arms to `try_to_commit_certificate`; F185 is the **un-migrated** `verify_signatures` consumer of the identical panic, reached via the raw `GossipMessage::decode` read-node ingress that bypasses the codec. F185 is the residual of F151's fix — must be tracked as a distinct fix item (different file: `util.rs:103`), but it is the same defect the F151 fix set out to eliminate. |
| **F185 ↔ F005** (standing — read_validator DecidedValue oneof unwrap) | **related-but-distinct** | Same read-node gossip ingress, but F005 fires at the *front* (`value == None` unknown-oneof unwrap); F185 fires *after* F005's guard would pass (valid `Block`/`Shard` variant, malformed *inner* `Commits`). Fixing F005 does not fix F185. |

## Cluster summary
- **Codec/Commits panic cluster:** F002 → F151 (fixed by PR#32) → **F185 (residual, NOT fixed)** + F005 (adjacent). The PR closed the codec edge but left the `verify_signatures` consumer panicking.
- **Ingress-amplification cluster:** F031 (systemic) → F154 (high) → **F165/F166 (new, low, gasless-signer endpoint)**.
- **Mempool panic:** **F160** stands alone (new subsystem/root cause); related-by-class to F151 only.

No standing finding is a true duplicate of any new finding — all four new findings are retained.
