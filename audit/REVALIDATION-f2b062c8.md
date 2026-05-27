# Revalidation — commit `f2b062c8` ("latest audit pass")

**Round 4 of fix-revalidation on PR #28** (farcasterorg/hypersnap, branch `pow`).
**Commit:** `f2b062c87a777342b2c11575521dc31f8663b1bc` — Cassandra Heart, 2026-05-27 06:28 CDT.
**Parent:** `cf62383e` (our R3 base). Direct single child.
**Working tree:** checked out at `f2b062c8`. (`git checkout 6cff47c` for pristine base.)
**Scope:** 4 files, surgical. Targets exactly the R3 re-report set — no new tooling.

```
crates/proof-of-quality/src/scoring.rs       |  +2  -2
src/hyper/da_response_producer_prod.rs        |  +8 -14
src/hyper/runtime.rs                          |  +3  -1
src/main.rs                                   | +41 -21
```

---

## HEADLINE: IT COMPILES (first time since R1)

`cargo +nightly check --bin hypersnap` → **EXIT_CODE=0, zero errors** (warnings only), `Finished in 21m 26s`.
Log: `.audit/build-wsl-f2b062c8-nightly.log`. Build setup unchanged from R3 (WSL Ubuntu, malachite sibling `13bca14c`, `CARGO_TARGET_DIR` in-tree `target-wsl`, **nightly** — stable 1.95.0 still ICEs on `ed448-bulletproofs`).

- R2 (`b14378a2`) failed `E0061` (arity). R3 (`cf62383e`) failed `E0277`×3 (gRPC interceptor). **R4 clears both.**
- The F031 fix is **exactly the wiring R3 recommended**: `InterceptedService::new(HubServiceServer::from_arc(grpc_service), interceptor)`.

---

## Verdicts against the R3 re-report set

### ✅ F031 compile break — FIXED + design intact
`main.rs:294` now `tonic::codegen::InterceptedService::new(HubServiceServer::from_arc(grpc_service), rate_limit_interceptor)`.
- Compiles (`from_arc` takes the `Arc<MyHubService>` by value — no `Clone` needed, which was the R3 blocker).
- **No method-gating regression.** In tonic 0.12, `with_interceptor(inner, f)` *is* `InterceptedService::new(Self::new(inner), f)`; R4 only swapped `Self::new`→`Self::from_arc` and inlined the call. Identical tower layer → all 4 methods incl. streaming remain gated by the shared IP limiter. R3's design verdict carries over.
- **No use-after-move.** `grpc_service` (main.rs:270, a `.clone()` of `service`) is moved into `from_arc` and never read again; the original `service` Arc survives for other wiring.
- **Residual (carried, unchanged):** gRPC auth still off-by-default (`server.rs:409`) → the IP limiter is the sole default gate. Not a defect R4 set out to fix.

### ✅ F135 frozen-count magnitude — FIXED
`BlockEngineDaResponseProducer` field `pub fid_count: u64` → `fid_count_fn: Box<dyn Fn() -> u64 + Send + Sync>`; `produce()` now calls `(self.fid_count_fn)()` live. main.rs wires a closure that paginates `OnchainEventStore::get_fids` against the live DB on every call.
- **Counts match the verifier.** Verifier (`runtime.rs:3337`) uses `count_registered_fids()` → `fids_for_scoring()` → paginates `get_fids` into a **BTreeSet** `.len()`. `get_fids` (`onchain_event_store.rs:689`) filters to `IdRegister`/`Register` events — exactly one per FID — so the producer's raw `count += fids.len()` per page equals the deduped verifier count. The R3 "frozen at startup → permanent `PrefixMismatch` after first post-startup registration" divergence is structurally eliminated.
- **Minor residual (maintainability):** the fix hand-rolls a *second* enumeration in main.rs rather than reusing `count_registered_fids()` (the closure captures only `runtime.db`, not the runtime). Correct today; a lockstep hazard if `get_fids` dedup semantics ever change. A cleaner form binds the existing function.
- **Minor residual (perf):** full paginated DB scan per `produce()`. Symmetric with the verifier (which already scans per `check_served_key_prefix`), so acceptable; flag for high-FID-count load.
- **NEEDS-RUNTIME (now measurable):** devnet (`run_testnet.sh`, added in R3) can confirm producer-count == verifier-count across a live registration. Not yet executed.

### ✅ F026 raw-vs-enforced (read path) — FIXED
`slashed_validators_for_epoch` (`runtime.rs:4213`) now resolves each evidence block's `signer_indices` against `get_active_validators_enforced(block_epoch, …)` instead of the raw `compute_active_set`.
- **Symmetric with signing.** Signing assigns 1-based indices over `client.active_validators(epoch, true)` (`dkls_supervisor.rs:199`) → `HyperActorQuery::ActiveValidators` → `actor.rs:1691` `active_validators_enforced` → the same `get_active_validators_enforced`. Read and write now share one ordered set → mis-slash on enforced-excluded validators closed.
- **Note (perf/consistency, not a defect):** `get_active_validators_enforced(E)` calls `slashed_validators_for_epoch(E-1)`, which now calls `get_active_validators_enforced(block_epoch)` — a descending recursion bounded by epoch height (base case at epoch 0). Terminates; repeated DB scans on deep evidence chains. Worth a runtime glance, not a correctness break.

### ✅ proof-of-quality test break — FIXED
All `compute_growth_harmonic(...)` call sites now pass the 5-arg form (`scoring.rs` lines 710/711/766/838/1196/1239/1241/1273/1274 + prod call at 365). Lib + bin compile clean. One cosmetic `unused_variable` warning: `max_growth_fraction_per_crediter` (scoring.rs:164) is **literally unused** — direct confirmation of R3's finding that F009's L2 sqrt-damping is distribution-blind/inert.

---

## ❌ NOT fixed by R4 (was in the R3 re-report set)

### F026 LATENT — `transport_pubkey_for_party` / `peer_id_for_party` — STILL OPEN
`runtime.rs:1200` and `:1244` still do `active.iter().nth(party_index-1)` over `self.validator_registry.compute_active_set(epoch, …)` — the **RAW** set — while DKLS committee party indices are assigned over the **ENFORCED** set (`active_validators(epoch, true)`, `dkls_supervisor.rs:199`/`:211`). The in-code comment ("same ordering `compute_active_set` uses for committee enumeration") is **stale** — that is precisely the divergence.
- **Impact:** once *any* validator is enforced-excluded at an epoch (slash / auto-deregister / trust-floor), every party index at or after that slot resolves to the wrong validator →
  - `transport_pubkey_for_party`: gossip seals DKLS round messages to the wrong transport key → undecryptable → ceremony liveness failure.
  - `peer_id_for_party`: F018 sender cross-check resolves the wrong validator → false-rejects honest frames / misattributes.
- **Why notable:** R4 was already inside F026 and fixed the read-path sibling with the exact one-liner this needs. Same root cause; the twins were missed.
- **Remediation:** resolve both against `get_active_validators_enforced(epoch, &self.bootstrap_validators)` (drop the registry error to `None`/`unwrap_or_default` as the helpers already do).

### F004 / F024 — UNTOUCHED
No scheduler / epoch-cutover / dkls_supervisor-anchor changes in the R4 delta. Carried unchanged from R2/R3.

---

## Standing caveats (carried, not R4's remit)

- **F009** — sybil defense rests entirely on the L0 `crediter_trust_threshold=0.05` floor (R3 sim: ring trust 0.0057 → growth 0.0). L2 sqrt-damping is distribution-blind (unused-var warning above); offers no sybil-specific discrimination under costlier graph-corruption.
- **F023** — phase-3 plaintext-broadcast arm (`DISCRIMINATOR_PLAINTEXT`, receiver=None) still digest-unbound → contained liveness-grief, no forgery (F018 sender-bind + dkls23 abort).

---

## Regressions

**0 found.** gRPC method gating preserved (tonic semantics, above); no use-after-move; the only `BlockEngineDaResponseProducer::new` call site (main.rs:1457) is updated for the closure signature. `u32::MAX as u64` fid_count at `runtime.rs:9439` is inside `build_valid_da_response` — a **test fixture** (not a production DA path). Compile-clean confirms no other call site broke.

---

## Net after 4 rounds

| Item | R3 | R4 |
|---|---|---|
| Compiles | ❌ E0277 | **✅** |
| F031 (gRPC limiter) | broken-fix | ✅ fixed (auth-off-by-default residual stands) |
| F135 magnitude | frozen-count | ✅ live closure |
| F026 read-path | partial | ✅ enforced set |
| F026 party-helpers | (flagged) | ❌ still raw set |
| F004 / F024 | untouched | untouched |
| F009 / F023 | caveats | caveats |
| proof-of-quality test | broken | ✅ |

**Re-report set after R4:** (1) **F026 party-resolution helpers** — only concrete code bug remaining in R4's own wheelhouse; (2) F004/F024; (3) gRPC auth-off-by-default; (4) F135 runtime measurement (now possible via devnet); (5) F009 single-layer-defense caveat; (6) F023 phase-3 caveat.
