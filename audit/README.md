# Hypersnap — Audit Findings Index

**Audited commit:** [`6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae`](https://github.com/farcasterorg/hypersnap/commit/6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae) (branch `pow`)
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline, brain library `2921c8eb3756`
**Methodology:** Recon → Hunt → 8-hypothesis red-team Validate → Dedupe. Each finding here survived an independent validator agent's adversarial 8-hypothesis walk; findings the validator broke (1 — see footnote on F058) are excluded.

**Status:** Iter-1 complete (29 validated). Iter-2 complete (27 validated). All 56 findings below survived an 8-hypothesis red-team validation pass; 1 was invalidated (F058, footnoted). See the [iter-2 spotlight](audit-index-iter2.md) for the new findings and the revalidation wins that contradicted iter-1 rulings. Dedupe (24 candidate pairs walked): 1 same-root-cause linkage (F107 ↔ F110), 20 related-but-distinct cross-references, 3 false-positive heuristics.

## Fix status — PR #28 (5 revalidation rounds; latest R5 `4a7d9c6`)

The maintainer (Cassandra Heart) landed **5 fix commits** on PR #28 in response to this audit, each independently revalidated by the audit-suite pipeline (static call-site tracing, augmented with an executed F009 simulation in R3, a full build in R4–R5, and an executed runtime PoC in R5): [R1 (883c4a5b)](REVALIDATION-883c4a5b.md), [R2 (b14378a2)](REVALIDATION-b14378a2.md), [R3 (cf62383e)](REVALIDATION-cf62383e.md), [R4 (f2b062c8)](REVALIDATION-f2b062c8.md), [R5 (4a7d9c6)](REVALIDATION-4a7d9c6.md). The per-finding bodies below are unchanged and reflect the **original OPEN severity at the audited base** (`6cff47c…`); this section is the overlay describing current state on the `pow` branch.

**Build arc:** R1 was buildable. **R2 failed to compile** (`error[E0061]` — F135 DA-PoW producer arity mismatch at `main.rs:1404`). **R3 failed to compile** (`error[E0277]` ×3 — F031 gRPC `with_interceptor` wiring passing `&MyHubService` where `T: HubService` is required, `main.rs:294-300`). **R4 compiles clean (nightly)** — the first buildable fix commit since R1. **R5 compiles clean (nightly)** — `cargo +nightly check --bin hypersnap` → exit 0. (Stable rustc 1.95.0 ICEs on the unchanged `ed448-bulletproofs` dependency, so verification used nightly 1.98.0 — an environmental toolchain issue, not a property of the commit.)

**⚠ R5 introduced a broken-fix.** R5 closed the F026 party-helper twins, both F024 residuals, and the F004 `build_driver` double-read — but its F004 **cutover-offset** fix is incomplete in the one place that matters: the runtime's authoritative `epoch_resolver` is still cutover-unaware. A runnable PoC (real `apply_cutover` + `produce_signed_block_dkls_local`) confirms `produce_signed_block_dkls_local → Err(NoDklsShare)` at any mainnet cutover ≥ `EPOCH_LENGTH` → launch-day chain halt. See [R5 report](REVALIDATION-4a7d9c6.md) and [REMAINING-AFTER-R5](REMAINING-AFTER-R5.md).

Fix status ∈ {FIXED, PARTIAL, OPEN, UNTOUCHED, not revalidated}. **Round** = the round whose verdict the row reflects. Findings the reports do not adjudicate are marked **not revalidated** (no status invented). The roll-up is built from the five `REVALIDATION-*.md` reports in this directory, which are the source of truth.

| Finding | Severity | Fix status | Round | Note |
|---|---|---|---|---|
| F138 | Critical | FIXED | R1 | Locks/transfers + all six anchor/range/missed-proposals fields now carried bidirectionally on `BroadcastBlock`/wire; sim's manual re-injection removed. `decode_proto_block` zeroing is `#[cfg(test)]`-only. |
| F133 | Critical | FIXED | R1 | `FingerprintStore::insert` now `#[cfg(test)]`; production writes thread the engine batch; simulate path builds a dropped batch. No residual. |
| F005 | High | FIXED | R1 | Every read-validator/gossip panic site now a graceful drop. |
| F011 | High | FIXED | R1 | New cross-epoch `HyperValidatorConsecutiveMisses` (RootPrefix 90) keyed on validator_key; regression test added. |
| F013 | High | FIXED | R1 | `vouch_boost_min_vouchee_trust` 0.0→0.3 default. Residual overlaps F009 (a ring-inflated sybil still clears 0.3). |
| F028 | High | FIXED | R1 | `signing_payload` (v2 DST) binds `extra_rules_version` + `retained_message_count` (+ `signer_indices`, see F153); verify paths re-derive. |
| F040 | High | FIXED | R1 | Dispatch-time latch replaced with install-confirmation + TTL retry (`DKLS_RETRY_AFTER_TICKS=12`). |
| F048 | High | FIXED | R1 | `build_srs` errors (`MissingKzgSetup`) unless `allow_random_kzg_srs` (default false); all `random_unsafe` sites `#[cfg(test)]`. |
| F105 | High | FIXED | R1 | `AppUsageReceiptBody` gains signed `epoch`; apply path rejects `epoch != current_epoch()`. (Silently fixed, not cited by ID.) |
| F107 | High | FIXED | R1 | `step5` now verifies every `ProofCommitment` unconditionally; `index == party_index` self-skip removed. |
| F114 | High | FIXED | R1 | `dkls_ceremony.rs` cross-checks inner `parties.sender`/`receiver` vs wire on all three zero-share/mul branches. |
| F116 | High | FIXED | R1 | `build_srs` requires `kzg_basis` declared and rejects Lagrange (`LagrangeKzgSetupNotSupported`). Detect-and-refuse (no conversion). |
| F117 | High | FIXED | R1 | Lock verkle key now `0x01‖lock_id` (33-byte); all three verkle domains disjoint-prefix. Regression test asserts no panic on `[0x02;32]`. |
| F119 | High | FIXED | R1 | `InteractiveDLogProof::verify` guards `challenge.len() != T/8` → false before `U256::from_be_slice`; both network paths covered. |
| F132 | High | FIXED | R1 | `stage_charge_message_fee` reads via `*_through_batch` helpers (batch before disk); same-FID charges compose. Regression test added. |
| F151 | High | FIXED | R1 | Consensus + sync codec decode now `?`-propagate via fallible `try_from_proto`/`try_from_vec`; connector logs instead of crashing. |
| F153 | High | FIXED | R1 | `signing_payload` binds `signer_indices` (sorted, length-prefixed) + adjacent fields, DST `-v2:`; low-S enforced. Closes steered slashing. |
| F154 | High | FIXED | R1 | `MAX_BATCH_FIDS = 1024` + `MAX_PAGES_PER_FID = 20`; total work finite. |
| F002 | High | FIXED | R2 | R1 patched the validator/proposer unwraps but the codec `proposal.height.unwrap()` fired earlier; R2 makes it fallible (`ok_or_else(...)?`). |
| F018 | High | FIXED | R2 | Cross-check now drives off gossipsub originator (not forwarding peer); `peer_id_for_party` indexes full active set. Documented rollout fall-throughs remain by design. |
| F024 | High | FIXED | R5 | Scheduler split-read FIXED R1; supervisor anchor-jump catch-up loop FIXED R2; the two narrow residuals FIXED R5 — watchdog is now a `BTreeMap<epoch, ticks>` that tracks every dispatched epoch in a burst, and cold-start seeds `first_undispatched` from the highest *installed* share + 1 (new `HighestInstalledDklsEpoch` query), no longer skipping the current epoch. |
| F026 | High | FIXED | R5 | Future-epoch leak FIXED R1; `DifferentEpochs` slashing bypass FIXED R2; slashing read-path resolution FIXED R4; the `transport_pubkey_for_party`/`peer_id_for_party` twins FIXED R5 — both swapped from the RAW `compute_active_set` to `get_active_validators_enforced`, matching the enforced set DKLS committee party indices are assigned over. |
| F036 | High | FIXED | R2 | New `committee_seed_for_epoch(epoch, tag)`; all six `select_signing_committee` callers (incl. lock-merkle-root) use a non-grindable seed. |
| F108 | High | FIXED | R2 | `dkls_sign.rs::submit` now enforces `parties.sender == wire sender` + committee membership on all three arms; framing primitive gone. |
| F004 | High | PARTIAL (R5 broken-fix) | R5 | `refresh_proposer_context_loop` race closed R2; `build_driver` double-read closed R5 (one anchor snapshot threaded per tick). **Cutover-offset is a BROKEN-FIX**: R5 added `epoch_for_with_offset`/`EpochManager::with_cutover` and applied them to the actor/supervisor/scheduler loops but NOT to the runtime's `epoch_resolver` (`runtime.rs:339` still `EpochManager::new()`, cutover=0). PoC-confirmed — at any mainnet cutover ≥ `EPOCH_LENGTH` the genesis DKLS share (keyed at epoch 0) is unreachable, `produce_signed_block_dkls_local` → `NoDklsShare`, launch-day chain halt. One-line fix: `EpochManager::with_cutover(config.cutover_snapchain_block)`. Dual-anchor desync still OPEN. See [REMAINING-AFTER-R5](REMAINING-AFTER-R5.md). |
| F009 | High | FIXED | R3 | Three-layer defense; executed sim measured ring trust 0.0057 (≈9× below the 0.05 L0 floor) → ring growth 0.0. Caveat: defense rests entirely on the L0 trust floor; L2 sqrt-damping is distribution-blind. |
| F023 | High | FIXED | R3 | Cross-digest sign routing closed via `build_sign_aad(epoch,sender,receiver,digest)` on encrypted rounds + clobber guard (R2). Caveat: phase-3 plaintext-broadcast arm (`receiver=None`) still digest-unbound — contained liveness-grief, no forgery. |
| F031 | High | FIXED | R4 | HTTP per-request limiter R2; gRPC limiter design correct R3 but did not compile; R4 wiring (`InterceptedService::new(HubServiceServer::from_arc(...), interceptor)`) compiles and gates all 4 methods. Residual: gRPC auth off-by-default, so the IP limiter is the sole default ingress gate. |
| F135 | High | FIXED | R4 | Driver width fix R1-area; arity compile break fixed R3; R4 replaces frozen `fid_count` field with a live `fid_count_fn` closure → producer count matches verifier. NEEDS-RUNTIME devnet hit-rate measurement still pending (now possible). |
| F058 | High (excluded — invalidated) | FIXED | R1 | Forge-mint root cause gone: bridge root built solely from authenticated emitters (`apply_confidential_lock` Schnorr + Pedersen + nullifier; `apply_token_escrow_bridge` EIP-712). Dead `HyperLockEvent` verkle path (info residual) also closed R2 (router returns `Err`). |
| F010 | Medium | not revalidated | — | Not adjudicated in any report. |
| F014 | Medium | not revalidated | — | Not adjudicated in any report. |
| F015 | Medium | not revalidated | — | Not adjudicated in any report. |
| F017 | Medium | not revalidated | — | Not adjudicated in any report. |
| F019 | Medium | not revalidated | — | Not adjudicated in any report. |
| F021 | Medium | not revalidated | — | Not adjudicated in any report. |
| F027 | Medium | not revalidated | — | Not adjudicated in any report. |
| F033 | Medium | not revalidated | — | Not adjudicated in any report. |
| F052 | Medium | not revalidated | — | Only named in R1's structural-changes file map (`shield.rs`); no verdict adjudicated. |
| F101 | Medium | not revalidated | — | Named only as a future wallet-SDK pass surface (R3); no verdict adjudicated. |
| F121 | Medium | not revalidated | — | Not adjudicated in any report. |
| F149 | Medium | not revalidated | — | Only named in R1's structural-changes file map + R3 future-pass note; no verdict adjudicated. |
| F157 | Medium | not revalidated | — | Not adjudicated in any report. |
| F044 | Low | not revalidated | — | Not adjudicated in any report (low-S enforcement is noted incidentally under F153, but F044 itself has no verdict). |
| F045 | Low | not revalidated | — | Not adjudicated in any report. |
| F062 | Low | not revalidated | — | Only named in R1's structural-changes file map (`confidential_lock.rs`); no verdict adjudicated. |
| F091 | Low | not revalidated | — | Only named in R1's structural-changes file map (`confidential_lock.rs`); no verdict adjudicated. |
| F094 | Low | not revalidated | — | Not adjudicated in any report. |
| F095 | Low | not revalidated | — | Not adjudicated in any report. |
| F096 | Low | not revalidated | — | Not adjudicated in any report. |
| F097 | Low | not revalidated | — | Not adjudicated in any report. |
| F104 | Low | not revalidated | — | R1 prose notes it was addressed via new chain-id binding (`shield.rs`), but no verdict was adjudicated in any scoreboard. |
| F137 | Low | not revalidated | — | Not adjudicated in any report. |
| F110 | Info | FIXED | R1 | Same root-cause site as F107, closed by the unconditional `step5` verify; refresh stays unreachable from production (severity stays info). |

**Verdict shorthand:**
- **WP** — *WATERPROOF*: finding stands after the validator's red-team walk.
- **HC** — *HAS_CAVEATS*: finding stands, but the validator narrowed impact, swapped an example, or flagged a load-bearing assumption. Read the validator notes alongside the finding body.
- Confidence (0–1) is the validator's own.

**Tier sizes:** 2 Critical · 31 High · 13 Medium · 9 Low · 1 Info — 56 validated total (1 excluded — F058).

---

## Critical — 2 findings (both iter-2)

### [F138 — Proposer broadcast strips locks/transfers + zeros signed anchor metadata; chain halts on any honest multi-node deployment](findings/F138-proposer-pipeline-strips-locks-transfers-and-signed-anchor-fields-from-wire-broadcast.md)
**WP 0.97 · node-lifecycle-actor**
`gossip_adapter::outbound_to_wire` hard-codes `locks: vec![], transfers: vec![]` and both `encode_hyper_block` / `decode_hyper_block` zero out `snapchain_anchor_*`, `missed_proposals`, `snapchain_range_*`. Every peer recomputes `signing_payload` over zeroed bytes and fails signature verification; for the all-anchors-zero case the state-root replay also diverges. The chain mechanically halts on any honest multi-node deployment past genesis. Validator: ALL 8 hypotheses STAND; additional discovery — `block_index.rs:35-63` is a third production copy of the drop pattern (the finding had classified it as a test-only mirror). `network_simulation_test.rs:144-156` literally contains a manual `locks: vec![lock.clone()]` re-injection compensating for the production bug.

### [F133 — `FingerprintStore` writes bypass txn_batch on the gRPC simulate path; per-validator divergence → consensus fork via unauthenticated RPC](findings/F133-fingerprint-store-direct-db-writes-during-simulate-cause-fork-and-free-poisoning.md)
**HC 0.75 · chain-economics**
`FingerprintStore::insert` writes directly to `self.db.put` and `uniqueness_score`'s eviction issues its own `self.db.commit`, both bypassing the engine's `txn_batch`. Because `merge_message` runs on the gRPC `submit_message` *simulate* path (which discards the batch), any unauthenticated/cheap RPC plants or evicts fingerprints on one validator's local DB. Validator: bug is real and consensus-fork is reachable, but the finding's intermediate prose ("fee_balance differs → account_root differs") is mechanically wrong — the merkle trie holds message/onchain/fname keys, NOT `HyperFeeBalance`/`HyperTotalFeeBurned`. The actual fork mechanism is divergent accept/reject when a poisoned fee crosses the victim's `HyperFeeInsufficient` threshold, producing different trie inserts on different validators. Severity stands; prose needs correction.

---

## High — 31 findings (17 iter-1 + 14 iter-2)

### [F005 — Read-validator panics on unknown DecidedValue oneof](findings/F005-read-validator-protocol-version.md)
**WP 0.95 · consensus-malachite-tendermint**
A peer-crafted gossip `DecidedValue` proto with an unknown oneof tag (or omitted oneof) decodes to `value: None`; `dispatch_decided_value` then unwraps and panics. Any libp2p peer can crash every read-node in the fleet — gossipsub's libp2p-layer signing does not gate this and the `snapchain_version` filter only governs outbound dials.

### [F011 — Auto-deregister counter resets each epoch, eviction policy never trips](findings/F011-auto-deregister-counter-resets-each-epoch.md)
**WP 0.93 · chain-economics**
`consecutive_misses` lives inside a per-epoch `ValidatorScoreRecord` keyed by `[HyperValidatorScore][epoch][vk]`, so the counter silently restarts at every epoch boundary. The FIP §5.3 eviction predicate `should_auto_deregister(prev, vk)` therefore never trips for a validator missing up to 99 proposals per epoch indefinitely; no downstream surface (slashing, trust score, score-based selection) compensates.

### [F012 — Retroactive vesting bypasses the per-epoch emission budget cap](findings/F012-retro-vesting-bypasses-budget-cap.md)
**WP 0.92 · chain-economics**
`apply_retro_vesting_tranche` credits via `credit_if_unissued` with zero consultation of `max_reward_per_epoch_per_market` or `max_reward_per_epoch`; the `BudgetExceeded` defense-in-depth cap is only enforced on the threshold-signed `apply_reward_issuance` path. Retro credits still count against `issued_total_for_epoch`, so a retro overshoot additionally starves the legitimate Growth issuance in the same epoch.

### [F013 — Vouch-puppet pump enabled by default (gating param ships at 0.0)](findings/F013-vouch-puppet-pump-default-disabled.md)
**WP 0.92 · chain-economics**
The vouch-graph admission gate is unbounded (no per-voucher cap, no k-distinct-sponsors, no decay) and the only documented puppet-pump mitigation, `vouch_boost_min_vouchee_trust`, ships at `0.0` in `ScoringParams::default()`. The 2× sybil-growth boost is therefore unconditional for any positive-stake vouch; no production config layer exposes the knob.

### [F026 — Local DKLS share selection leaks future epoch, bypasses double-sign slashing](findings/F026-dkls-share-selection-leaks-future-epoch-and-bypasses-slashing.md)
**WP 0.92 · node-lifecycle-actor**
`produce_unsigned_block_dkls` picks the local DKLS share with `dkls_signers.iter().next_back()` (max-installed epoch) instead of consulting `epoch_resolver.current_epoch()`. Pre-installed future-epoch material leaks into current-epoch block production and lets a proposer equivocate at the same `canonical_block_id` with two different `signature.epoch` tags — bypassing `detect_conflicting_blocks`'s `DifferentEpochs` guard and silently evading slashing.

### [F028 — Signing payload misses two hash-fields covered by `hyper_block_hash`](findings/F028-signing-payload-misses-hash-fields.md)
**WP 0.95 · node-lifecycle-actor**
`signing_payload` omits `extra_rules_version` and `retained_message_count` which `hyper_block_hash` mixes in. One DKLS signature therefore authenticates many distinct block hashes, enabling parent-hash forks and forgeable conflicting-blocks slashing evidence against the signing committee. The importer never re-derives either field from authoritative state.

### [F030 — Unbounded HTTP body buffer (no transport-level cap on `collect`)](findings/F030-unbounded-body-buffer-pre-cap.md)
**WP 0.92 · http-api-rocksdb**
All ingress paths (`network/http_server.rs`, `hyper/http_handler.rs`, `api/webhooks/handler.rs`) buffer the body via `Incoming::collect().await` with no transport-level cap. The webhook path checks `MAX_BODY_BYTES` *after* buffering; `http1::Builder` is bare in `main.rs`. Anonymous public-internet POST of a 10 GB body OOM-kills the node before any application-level rejection runs.

### [F031 — No rate limit on HTTP/gRPC ingress](findings/F031-no-rate-limit-on-http-grpc-ingress.md)
**WP 0.90 · http-api-rocksdb**
No tower/governor/`RateLimit` layer on any HTTP or gRPC ingress in `src/network/**` or `src/api/**`. The only `governor` use is per-FID inside the mempool, downstream of full signature-verify + engine-simulate work, so anonymous CPU-grief on `/v1/validateMessage`, `/v1/submitMessage`, `/v1/submitBulkMessages`, `/hyper/v1/messages`, webhook POSTs, and streaming `GetBlocks` is unbounded.

### [F036 — Committee-selection digest is proposer-grindable](findings/F036-committee-selection-digest-is-proposer-grindable.md)
**WP 0.94 · rust-threshold-signing**
The block-production rank-hash digest mixes proposer-controlled levers (mempool ordering, `missed_proposals`, anchor block/hash/timestamp) and is reused as the seed for DKLS committee selection without a beacon, commit-reveal, or verifier-side committee recomputation. ~10⁷ trials/sec/core lets a proposer self-exclude (≈1–2 trials, free) or pack a colluding committee at 3-of-10 in ~1 ms.

### [F040 — DKLS supervisor never retries after a ceremony abort](findings/F040-dkls-supervisor-no-retry-after-ceremony-abort.md)
**WP 0.92 · rust-threshold-signing**
The supervisor sets `last_started_for_epoch` on *dispatch* (not install-confirmation) with no completion feedback channel. Any post-dispatch DKG abort (peer fault, partition, `try_advance` error) permanently denies that epoch's group key until process restart; no admin RPC or operator-triggered re-DKG path exists.

### [F091 — Cross-FID `lock_id` collision lets any attacker permanently strand a victim's bridge-locked balance](findings/F091-lock-id-collision-across-fids-permanently-strands-victim-balance.md)
**WP 0.97 · solidity-bridge**
L2 per-FID `lock_id` dedup + L1 `claimed[lockId]` global nullifier + zero recovery path on either side. Any attacker with one funded FID and gossip-mesh observation can race the victim's burn message with a duplicate `lock_id`, get their own message into a finalized block first, and permanently nullify the L1 `claimed[lockId]` slot — the victim's bridge-locked atoms become unreachable. A pinned test (`rewards.rs:1041-1058 same_lock_id_on_distinct_fids_is_allowed`) explicitly asserts the buggy behavior; the in-source docstring at `token_lock.rs:353-358` falsely claims storage enforces global uniqueness while `rewards.rs:1036-1039` concedes "enforcement is up to the user".

### [F105 — App-PoW receipts have no epoch / timestamp binding; one captured receipt replays every future epoch indefinitely](findings/F105-app-usage-receipt-no-epoch-binding-cross-epoch-replay.md)
**WP 0.93 · rust-crypto-primitives**
`AppUsageReceiptBody.timestamp` is signed but never compared against `current_epoch()` or any freshness window; the apply path keys storage by submitter-chosen `current_epoch()` and the receipt-count consumer (`compute_app_pow_rewards` → `accumulate_app_work`) credits the count blindly. One captured byte-identical receipt can be re-broadcast every epoch indefinitely, saturating to `MAX_RECEIPTS_PER_APP_PER_EPOCH = 10_000` per (user, app) pair as a *floor* on §7 App-PoW reward inflation. Same family as F101/F104 chain-id-binding gaps.

### [F108 — DKLS signing trusts inner `parties.sender` for routing + abort-blame; 1-packet panic-DoS + misattribution-blame against any reachable peer](findings/F108-dkls-signing-trusts-inner-sender-for-routing-and-blame.md)
**WP 0.95 · rust-threshold-signing**
`sign_phase2`/`sign_phase3` dispatch `kept[..]`, `mul_senders[..]`, `mul_receivers[..]` and abort-blame strings on `message.parties.sender` (a bare bincode `u8` attacker-controls). The upper layer `dkls_sign.rs::submit` never cross-checks `parties.sender == wire sender`, and the protocol's `.unwrap()`s panic on out-of-range inner-sender. A single inbound `Phase1Send` lets any reachable peer either (a) permanently crash a victim's signing actor via `kept.get(&attacker_byte).unwrap()` (no `catch_unwind`, no supervisor restart), or (b) frame an innocent committee member with `Abort::new(self.party_index, "...failed because of Party {framed_index}...")`. F107/F108/F110/F114 share the same root cause (inner-index trust pattern).

### [F132 — `RewardStore::stage_charge_message_fee` reads accumulators from disk, not from the in-progress batch; same-FID fee-bearing messages silently free](findings/F132-stage-charge-message-fee-read-after-write-collapse.md)
**WP 0.96 · chain-economics**
`stage_charge_message_fee` reads `fee_balance`/`total_fee_burned`/`proposer_fee_pot` directly from RocksDB (`self.db.get`) instead of from the caller-supplied `RocksDbTransactionBatch` HashMap. Successive same-FID fee-bearing messages in one shard chunk overwrite each other's batch entries with stale-base deltas — only the LAST message's debit + burn + proposer-share commits, silently making every other message free and breaking burn/proposer-pot accounting. Determinism-safe (every validator computes the same broken value, no fork), but consensus converges on a broken accounting state. Directly contradicts iter-1's H035 ruling, which had cleared this function on crash-atomicity grounds; H035's sweep methodology was not designed to detect within-batch read-after-write.

### [F107 — DKLS `step5` skips DLog verification for any `ProofCommitment` whose inner `index` equals the verifier's own `party_index`](findings/F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md)
**HC 0.85 · rust-threshold-signing**
The `step5` proof+commitment-verification loop has an `if party_j.index != party_index { verify; }` shape that lets an attacker who plants an inbound message carrying `proof_commitment.index = victim_party_index` insert an unverified "public-key fragment" into the victim's own slot without any DLog proof check. Downstream: `t<n` produces silent ceremony-DoS via Lagrange cross-window mismatch with no actionable blame; `t==n` produces silent group-public-key corruption across the committee. Validator caveats: titular "arbitrary-pk injection" overstated (attacker can't know DLog of the resulting key — Lagrange mixes attacker's `Q` with honest secrets); per-recipient divergent-pk scenario requires F023-class network capabilities (Phase2ProofCommitment is broadcast). F107/F108/F110/F114 family.

### [F114 — DKG zero-share init trusts inner `parties.sender`/`receiver` bytes; one-packet DoS / misattribution-blame / silent ZeroShare-vec corruption](findings/F114-dkls-zero-share-init-trusts-inner-parties-sender-receiver.md)
**HC 0.85 · rust-threshold-signing**
DKG `phase4` (`dkg.rs:731-773`) dispatches on the inner `TransmitInitZeroSharePhase{2,3}to4.parties.sender / .receiver` byte. The ceremony layer (`dkls_ceremony.rs:357-381`) keys accumulator BTreeMaps on the *wire* sender but never cross-checks inner-vs-wire. Three reachable primitives: (A) one-packet DoS via `parties.receiver != V.party_index` triggering the blame-the-victim abort at `dkg.rs:741`; (B) misattribution-blame at `dkg.rs:760-762` framing an innocent counterparty; (C) silent ZeroShare-vec corruption surfacing at signing time with a blame-less "Invalid ECDSA signature at end of protocol" abort. Validator: A and B are unconditional from a single spoofed packet; C is contingent on F018/F023/multi-attacker as the finding honestly states.

### [F116 — KZG trusted-setup loader silently treats Lagrange-basis G1 points as monomial powers of τ](findings/F116-kzg-loader-assumes-monomial-basis-no-lagrange-detection-or-conversion.md)
**HC 0.72 · rust-crypto-primitives** *(validator suggests reclass to Medium)*
`HyperRuntimeFileConfig::build_srs` calls `into_srs_monomial` unconditionally with no basis detection or Lagrange→monomial conversion — pointing `kzg_setup_path` at a Lagrange-encoded Ethereum KZG ceremony file (the canonical EIP-4844 format) silently re-interprets `g^L_i(τ)` as `g^(τ^i)`. Validator narrowed: the finding's "forgery space opens" and "cross-validator divergence" framings are cryptographically wrong — the wrong-basis map is linear and injective, KZG binding transfers unchanged, so the actual harm is permanent failure of `kzg::verify` on honest verkle-inclusion openings (a liveness/RPC bug). No on-chain consumer (`verify_inclusion` only `#[cfg(test)]`); L1 bridge byte-compares state roots. Severity should drop High → Medium.

### [F151 — `SnapchainCodec` decode panics on peer Vote/Proposal/Commits before signature verify](findings/F151-snapchain-codec-decode-panics-on-peer-vote-proposal-and-syncresponse.md)
**WP 0.92 · rust-crypto-primitives**
Decode paths trust peer-supplied proto fields and panic on malformed inputs *before* signature verification, on both `Channel::Consensus` and `Channel::Sync`. Sibling DoS surface to F002's `add_proposed_value` panics, covering distinct channels and helper functions (`Vote::from_proto`, `Proposal::from_proto`, `Commits::to_commit_certificate`, `Address::from_vec`). Validator: tears down the network-connector actor (Ractor, no `catch_unwind`, no `panic=abort`); persistent attacker triggers repeated restart cycles, sync-channel variant crashes read-nodes during initial sync.

### [F153 — Hyperblock threshold-ECDSA signing payload omits `signer_indices` → attacker-controlled slashing](findings/F153-hyperblock-threshold-sig-omits-signer-indices-extra-rules-payload-attacker-controlled-slashing.md)
**WP 0.92 · rust-threshold-signing**
The signing payload binds `signer_indices` via `extra_rules_version`/`retained_message_count`/`envelope.payload` but the apply path consumes a malleable `signer_indices` byte vector that's not covered by the signature. A captured conflicting-block evidence message can be malleated to slash attacker-chosen validators at the next epoch boundary, on F028's adjacent surface. Validator: end-to-end pipeline traced from `InboundEvidence` → `slashed_validators_for_epoch` → `get_active_validators_enforced` — malleated `signer_indices` exclude the attacker-chosen vks from the next epoch's active set; one-shot per conflict-pair due to `(epoch, hash_a, hash_b)` dedup but `MAX_DISTINCT_CONFLICTS_PER_HEIGHT = 8` is enough to slash a large fraction.

### [F117 — Verkle insertions for locks omit the 1-byte domain discriminator that nullifier/note-commitment inserts use](findings/F117-verkle-lock-key-missing-domain-byte-path-prefix-panic-dos.md)
**WP 0.95 · rust-crypto-primitives**
An attacker-chosen 32-byte `lock_id` starting with `0x02` (or `0x03`) can be made a strict path-prefix of any nullifier/note-commitment key, panicking the block builder during `apply_message` (lock-then-nullifier order) or silently overwriting an entire nullifier subtree under the verkle root (nullifier-then-lock order). No `catch_unwind` anywhere on the actor's apply-message path. Validator: NOT L1 mint (F058 invalidation respected — live bridge consumes keccak256 merkle root of `TokenLockBody`, not the verkle tree) but IS L2 consensus liveness DoS plus verkle state-root divergence; repo-wide grep for `catch_unwind` returns zero hits, single `tokio::spawn(actor.run())` dies on panic and restart re-hits the same panic via the replay loop.

### [F119 — `DLogProof::verify` panics on malformed challenge length → 1-packet remote-thread panic-DoS](findings/F119-dlogproof-verify-panic-on-malformed-challenge-length.md)
**WP 0.95 · rust-crypto-primitives**
`U256::from_be_slice` `assert!`-panics in release whenever a wire-supplied `InteractiveDLogProof::challenge: Vec<u8>` has length ≠ `T/8 = 4` bytes. Reachable from DKG `step5` decommit-verify, `ot/base.rs::run_phase2_step1`, and signing-init via multiplication after only ~256 trials of 8-bit Fischlin-hash grinding. Validator: confirmed vendored `crypto-bigint::UInt::from_be_slice` uses `assert!` not `debug_assert!` so it fires in `--release`; `canonical_session_id` is `keccak256` of *public* (epoch, threshold, share_count) so the FS-grind is offline before the ceremony begins; rustdoc on `dkg.rs::step5` explicitly promises `Err` not panic, so this is a *contract violation*.

### [F135 — DA-PoW driver pads `served_key` to 32 bytes; apply-path exact-byte trie lookup never matches → §5 DA-PoW reward signal = 0 across the fleet](findings/F135-da-pow-driver-zero-pads-served-key-breaking-apply-time-trie-existence-gate.md)
**WP 0.95 · chain-economics**
Driver-side bug: every honest DA challenge response is rejected by the production apply-path lookup, collapsing the §5 DA-PoW reward signal to zero. Driver-only — protocol/encoding side (H134) is sound. Validator: `validate_da_response` actively enforces `served_key.len() == 32` and the 32-byte width is canonically encoded into the Ed25519 signing payload — no upstream normaliser could strip trailing zeros. Both failure modes confirmed: lookup-wired → all honest responses rejected; lookup-unwired (any deployment with `hyper_block_engine.is_none()`) → served_key is trivially forgeable. Production wires the padding driver + the lookup; no test exercises real `BlockEngineDaTrieLookup` against real natural-length entries, so this went undetected.

### [F154 — Farcaster v2 batch endpoints accept unbounded `fids` array + uncapped per-FID pagination loop → multi-GB heap DoS via single unauth request](findings/F154-farcaster-batch-endpoints-unbounded-fid-list-and-uncapped-pagination-loop.md)
**WP 0.90 · p2p-gossip**
The six `POST /v2/farcaster/batch/*` endpoints (`handle_batch_cast_interactions_batch`, `handle_batch_cast_bodies_batch`, ...) don't cap the `fids` array length and run an unbounded `loop { ... RocksDB 500-item page }` accumulating into one in-memory `HashMap` before a monolithic JSON serialize. 1 MiB body (~100k FIDs) → Θ(K·N) iterator steps, multi-GB heap, multi-minute CPU. Orthogonal to F030/F031 — even with F030's body-size cap and F031's rate limiter applied, 100k FIDs still fit under any 1 MiB cap and a single accepted request is the unit of amplification.

### [F158 — JFS-signed notification webhook events have no app_id/nonce/timestamp/destination binding → cross-app replay (notification phishing under trusted-app identity)](findings/F158-jfs-webhook-no-app-id-or-nonce-binding-enables-cross-app-replay.md)
**WP 0.93 · p2p-gossip**
The notification webhook accepts JFS-signed events whose signed payload has no `app_id`, no destination/domain, no nonce, and no timestamp. Captured envelopes replay across mini-apps on the same hypersnap deployment — cross-app subscription spoofing, force-unsubscribe of any user from any app, stale-URL overwrite. F101-family chain-id/nonce-binding gap applied to the multi-tenant notification proxy. Validator: `miniapp_removed` envelope carries zero app context — one captured envelope (legitimately seen by any mini-app operator) plus a self-registered `app_id` (open per `mod.rs:11-13`) unlocks unlimited force-unsubscribes against any `(Alice, *)` pairing; the existing `jfs_verify_e2e_smoke` test actually exercises the exact property the finding flags.

### [F002 — Remote-triggerable panics in `add_proposed_value` from malformed peer proposals](findings/F002-nil-block-proposal.md)
**HC 0.85 · consensus-malachite-tendermint**
`ShardValidator`/`ShardProposer`/`BlockProposer::add_proposed_value` each `unwrap()` peer-controlled `Option` fields of a `FullProposal`; a malformed proto crashes the receiving shard actor. Validator narrowed: the first cited site is gated by an earlier codec panic at `snapchain_codec.rs:106` (same crash, different line), but the other four unwraps and the dead `Validity::Invalid` guard remain reachable end-to-end.

### [F004 — Cross-epoch desync between resolver and supervisor anchors](findings/F004-epoch-boundary-race.md)
**HC 0.85 · consensus-malachite-tendermint**
`EpochResolver` is only advanced in `apply_cutover`; the DKLS supervisor uses a divergent private anchor; the `InboundBlock` handler does not advance the resolver. Validator narrowed: real downstream impact is unstake maturation, DA-PoW response rejection, router epoch, and proposer-context refresh — the finding's auto-scoring claim is overstated. Restart-amnesia variant flagged as follow-up.

### [F009 — Sybil amplification via unbounded EigenTrust input](findings/F009-sybil-amplification-via-eigentrust.md)
**HC 0.70 · chain-economics**
`evaluate_epoch` inserts every `reader.all_active_fids()` into the EigenTrust graph with zero personhood/stake/uniqueness predicate; default `crediter_trust_threshold = 0.0` and `seed_max_fid = 50_000` make the top-N normalization vulnerable to dense sub-cluster saturation that drains Growth-budget allocation. Validator: structural argument sound, but a 50-line numerical PoC would lift confidence from 0.70 toward 0.95.

### [F018 — DKLS inner-sender field not bound to outer libp2p peer-id](findings/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md)
**HC 0.92 · p2p-gossip**
The DKLS gossip ingress discards the libp2p `propagation_source` peer-id and never binds it to the inner `sender: u8` byte; the AAD `(epoch || round_tag || sender || receiver)` is encryptor-supplied and the seal-to-recipient X25519 box authenticates no sender. Any connected peer can publish a DKG/sign round message claiming `sender=Q` for any honest party Q. Validator: critical-promotion clause invalidated (`Abort.index` is reporter, not accused; `dkls_supervisor` has no blame-eviction). High stands.

### [F023 — DKLS round messages dropped before ceremony start; cross-routing possible](findings/F023-dkls-round-messages-dropped-and-cross-routed.md)
**HC 0.85 · node-lifecycle-actor**
Three sub-claims: (a) `InboundDkls`/`InboundDklsSign` drop pre-`StartDkls` round messages with no buffer (WP 0.92); (b) sign AAD omits the digest, so a round-N message from ceremony-A can route into ceremony-B at the same epoch (HC 0.80 — DKLS23's internal `sign_id` binding catches cross-digest installs as aborts, demoting the integrity break to liveness-only); (c) `StartDkls`/`start_dkls_block_production` unconditionally overwrite the active coordinator (WP 0.93).

### [F024 — Scheduler proposer-context split-read + supervisor anchor-jump](findings/F024-scheduler-split-read-and-supervisor-anchor-jump.md)
**HC 0.75 · node-lifecycle-actor**
Two scheduler races not covered by F004: (1) `BlockProductionScheduler::run` reads `ProposerContext` in two separate `lock().await` acquisitions — a refresh tick between them produces a block whose `anchor_hash` differs from the gating one; (2) the DKLS supervisor's `last_started_for_epoch` silently skips an entire epoch's DKG when the anchor jumps past `start_lead_blocks` in a single tick. Validator: collision frequency on (1) is ~µs window per 5 s tick, not "every tick"; (2) yields silent stale-key signing rather than chain halt.

### [F048 — KZG SRS silently falls back to `random_unsafe` in production config](findings/F048-kzg-srs-silent-random-tau-fallback-in-production-config.md)
**HC 0.85 · rust-crypto-primitives**
`HyperRuntimeFileConfig::build_srs` (`config.rs:405-420`) silently falls back to `KzgSrs::random_unsafe` when `kzg_setup_path` is `None`; `random_unsafe` is `pub` (no `cfg(test)` / feature flag) and reachable in release builds. Validator narrowed: the L1 bridge consumes zero verkle/KZG (no `verify_inclusion`/`KzgCommitment` in `contracts/`); real reachable harm is (a) multi-validator misconfig → `StateRootMismatch` chain halt, and (b) single-operator forgery of HTTP-served verkle proofs to RPC clients — not network-wide fund loss.

---

## Medium — 13 findings (9 iter-1 + 4 iter-2)

### [F101 — Custody-key JFS account-association proof is a publicly-served, replayable bearer token (no chain-id, no nonce, no consumption)](findings/F101-account-association-jfs-proof-replayable-no-chain-or-nonce-binding.md)
**WP 0.92 · solidity-bridge**
`apply_miniapp_register` consumes a JFS proof at `runtime.rs:3557` with zero envelope authentication, zero chain-id binding (contrast: every sibling miniapp body binds `protocol_chain_id`+nonce), and zero nonce/nullifier consumption. Cross-chain front-run and Phase-B forward-dated replay both walk through every check in `account_association.rs:130-221` cleanly. Canonical parent of the F101/F104/F105/F158 chain-id/nonce-binding family.

### [F121 — IPA `from_bytes` uses `Scalar::from_bytes_mod_order` instead of `from_canonical_bytes` → confidential-transfer wire-byte malleability](findings/F121-ipa-from-bytes-uses-mod-order-not-canonical-prover-wire-malleability.md)
**HC 0.85 · rust-bulletproofs-pedersen**
`InnerProductProof::from_bytes` in the ed448-bulletproofs port decodes IPA witness scalars `a`/`b` non-canonically — a single-site divergence from upstream dalek and from this crate's own RangeProof / LinearProof / R1CS parsers. Gives the prover ≥ 9 distinct, individually-signed, validation-passing `TransferTx` byte payloads per logical confidential transfer. Validator narrowed: mempool dedup blunts the per-node cache-amplification path (`HyperMempool::submit_transfer` keys on nullifier), but gossip bandwidth amplification is concrete-today — `network/gossip.rs:257-280` uses `hash(message.data)` as the libp2p gossipsub `message_id` so byte-distinct variants are re-flooded at ≥ 3^(2m) per logical tx. Core algebra (non-canonical decode diverges from upstream + docstring) is waterproof; severity Medium stands.

### [F149 — Transfer codec `one_time_pubkey` + `blinding_diff_scalar` not signed → relay-attacker output-burn griefing](findings/F149-transfer-codec-one-time-pubkey-and-blinding-diff-not-signed-malleability-burns-recipient-output.md)
**HC 0.85 · rust-crypto-primitives**
A gossip-relay attacker rewrites the recipient's `one_time_pubkey` to attacker-controlled, wins the mempool dedup race (keyed by first-input nullifier), and has `import_block` durably record the attacker's pubkey for the recipient's stealth output. Pedersen balance closure prevents extraction (so no theft), but locks the legitimate recipient out of those atoms — targeted output-burn primitive. Validator: cryptographic chain confirmed (libp2p `MessageAuthenticity::Signed` binds publisher PeerId only, mempool message-id is `source||sequence_number` not content-hashed, no app-level envelope sig on `HyperMessage`); BUT `tx_to_proto_full` / `outbound_transfer` for confidential transfers have zero non-test callers on the `pow` branch today — primitive is latent, exploitable the moment a producer is wired in.

### [F157 — `following_fid` filter on mini-app send endpoint enumerates an attacker-chosen FID's entire follower set per request → shared-RocksDB DoS](findings/F157-following-fid-filter-unbounded-follower-enumeration.md)
**WP 0.88 · p2p-gossip**
Post-auth mirror of F154 — any custody-key + one `app.create` envelope gets `loop { social_graph.get_followers(fid, cursor, 1000) }` to materialize a multi-MB `HashSet<u64>` and pin the consensus-shared RocksDB per call, no upstream rate limit (F031). Validator: production path confirmed at `api/mod.rs:520-537` → `set_notification_sender` → `api/http.rs:653-664`; reachability gated on operator config (`[api.social_graph].enabled` — Rust default `false`, shipped `config/sample.toml` sets it `true`); credible argument to bump to High by analogy to F154 but F157 is post-auth where F154 is anonymous.

### [F010 — Mutuality formula divergence between emission and proof-of-quality pipelines](findings/F010-mutuality-asymmetry.md)
**WP 0.90 · chain-economics**
`emission/mutuality.rs` ships `MutualityMode::Sum` (no reciprocity gate) while `proof-of-quality/scoring.rs` uses a harmonic-mean formula that *requires* reciprocity. The two-pipeline divergence is gated in production (consensus path is rigid harmonic; the Sum path is only reachable via the `compute_emissions` CLI binary), so the bug is low-impact today but the in-source docstrings contradict each other on which is "FIP-default", strengthening the case for normalization.

### [F014 — Stale trust scores never cleared from TrustScoreStore](findings/F014-stale-trust-never-cleared-from-trust-store.md)
**WP 0.86 · chain-economics**
`TrustScoreStore` is PUT-only; `apply_trust_snapshot_update` and the cutover `set_many` overwrite present entries but never delete FIDs absent from the new snapshot. Bootstrap FIDs that never enter `IdRegisterEventType::Register` retain stale `f64` scores indefinitely, feeding the validator-set inclusion gate, soft-evict filter, fee-charger (`MAX_TRUST_DISCOUNT = 1.0` ⇒ 90 % perpetual fee discount), and below-floor enum.

### [F019 — No per-topic gossip message size cap (10 MB transport-only)](findings/F019-no-per-topic-gossip-size-cap.md)
**WP 0.87 · p2p-gossip**
The only size cap is libp2p's global `MAX_GOSSIP_MESSAGE_SIZE = 10 MB`; `wire_to_event` and `map_gossip_bytes_to_system_message` decode `HyperWireDkg`, `HyperWireBlock`, `HyperMessage`, and `HyperWireEvidence` with no per-topic or per-variant ceiling — 100×–10 000× looser than legitimate frame sizes. Combined with the absence of `validate_messages()` and peer scoring (F017), one peer sustains ~20 MB/s × `mesh_n` egress without eviction.

### [F021 — Autodiscovery contact-info not bound to libp2p peer-id (eclipse + panic)](findings/F021-autodiscovery-contact-info-not-bound-to-libp2p-peer-id.md)
**WP 0.88 · p2p-gossip**
`handle_contact_info` dials body-supplied `gossip_address` without binding `contact_info_body.peer_id` to the libp2p sender, so a single connected peer can flood-dial a read-node with attacker multiaddrs (eclipse before any honest peer connects). The same handler contains an unconditional `PeerId::from_bytes().unwrap()` panic on any peer's malformed contact-info bytes, hitting validators too. mDNS is dead code; Kademlia is absent.

### [F033 — Shard-chunk header committed separately from state batch](findings/F033-shard-chunk-header-split-from-state-commit.md)
**WP 0.85 · http-api-rocksdb**
`SnapchainEngine.commit_and_emit_events` and `BlockEngine.commit_block` commit the state-mutation batch first, then call `put_shard_chunk`/`put_block`, which open their own separate `db.commit`. A crash between the two leaves the trie/message stores at height H but the `ShardChunk`/`Block` header at H-1, producing on-restart consensus divergence — and that divergence is then propagated to every bootstrapping peer via S3 snapshot pollution. The same anti-pattern recurs across `HyperBlockIndex`, `trust_store.set_many`, `validator_registry.record_event`, `dkls_address_store`, and `note_store`.

### [F015 — `RewardStore::credit_if_unissued` issues two unbatched RocksDB puts](findings/F015-credit-if-unissued-two-puts-replay.md)
**HC 0.85 · chain-economics**
`credit_if_unissued` writes balance and issued-key as two unbatched RocksDB puts; every sibling method uses `db.txn()/commit`. A crash between the two lets the next pass double-credit, and on the retro path the third unbatched `retro_store.put` leaves `remaining_atoms` un-decremented, cascading overpayments through every subsequent §10.5 tranche. Validator: live path reachable today; the retro 2× cascade requires the not-yet-wired `EvaluateEpochDkls` emitter to land.

### [F017 — Gossipsub mesh has no peer scoring or message-validation hook](findings/F017-gossipsub-mesh-no-peer-scoring.md)
**HC 0.78 · p2p-gossip**
Gossipsub is configured with no peer scoring, no `validate_messages()`, default `mesh_n_low`/`outbound_min`, and `100`/`100` connection limits. A Sybil-poisoned mesh can eclipse a validator from `hyper/dkg/v1` or `hyper/evidence/v1` with no eviction path. Validator: censorship tier is partly conditional on the evidence-pipeline TODO landing (per `topics.rs:21-23`).

### [F027 — `runtime.rs` 4554-LOC apply-handler fork around active-key gate](findings/F027-runtime-apply-handler-fork-active-key-gate.md)
**HC 0.78 · node-lifecycle-actor**
`runtime.rs` production LOC = 4554 (over the 4000-line discipline threshold). Inside that file, the active-key gate is hand-inlined into 13 distinct `apply_*` handlers with a documented "Phase 1b" scope-gating TODO that must be re-pasted at every site. Validator: the finding's named example (`apply_token_escrow_claim`) actually auths via EIP-712 to `custody_address`, not against ActiveKey — the macro finding survives but the example should be swapped (validator suggests `apply_da_challenge_response`).

### [F052 — Privacy-note AEAD AAD omits commitment and stealth context](findings/F052-note-payload-aead-aad-omits-commitment-and-stealth-context.md)
**HC 0.78 · rust-crypto-primitives**
`encrypt_note_payload`/`decrypt_note_payload` pass the static label `b"hypersnap-note-payload-v1"` as AAD with no per-note context (no commitment, no `tx_pubkey`, no recipient view-pubkey). Caller-side `PedersenCommitment::opens_to` is the sole substitution guard. Validator: the privacy-token primitives have zero production callers and no wire field, so this is forward-looking primitive-level hardening — not an active vulnerability — until the proto adds `bytes encrypted_payload` without simultaneously adding it to `signing_payload`.

---

## Low — 9 findings (3 iter-1 + 6 iter-2)

### [F094 — Bridge-burn watcher resume cursor is derived from the drainable `BridgeBurnStore` queue, not from a persisted high-watermark](findings/F094-bridge-burn-watcher-cursor-derived-from-drainable-queue.md)
**WP 0.92 · solidity-bridge**
`BridgeBurnWatcher`'s restart cursor is `max(source_block_number)` over the validator's own RocksDB prefix; if the queue is drained, the cursor regresses to the start block on next restart and replays the full L1 scan. Latent today (`BridgeBurnStore::remove` has no production caller — only test-callable), and `apply_inbound_burn`'s `(source_chain_id, burn_id)` replay-marker prevents double-credit. Self-limited to liveness/RPC-budget; correctly scoped Low.

### [F096 — `apply_inbound_burn` short-circuits on `(source_chain_id, burn_id)` nullifier BEFORE signature verification — accepts & one-hop-broadcasts forged unsigned messages](findings/F096-inbound-burn-nullifier-short-circuit-bypasses-signature-verification.md)
**WP 0.93 · solidity-bridge**
The runtime's apply-path checks the replay-nullifier first and the threshold-signature second. Against any `(source_chain_id, burn_id)` that has previously been credited, `apply_inbound_burn` returns `Ok(false)` on an *unsigned* forgery, which short-circuits before sig-verify; the gossip layer still emits a one-hop broadcast. No state mutation (Low), but pollutes metrics + one-hop gossip noise and the implementation order reverses the function's own docstring (which lists sig-verify FIRST). Reachable via unauth POST `/hyper/v1/messages`.

### [F097 — `recovery_watcher` omits finality wait, has poisonable cursor, and uses panicking U256-to-u64 narrowing](findings/F097-recovery-watcher-missing-finality-wait-and-poisonable-cursor.md)
**WP 0.93 · solidity-bridge**
Recovery-watcher pipeline omits all three defensive primitives `bridge_burn` carries (finality clamp, REORG_GUARD, dedicated per-chain scan watermark) and FID-decode uses panicking `U256::to::<u64>()` instead of snapchain's `try_into()`. Latent / Low today because the store has no production read-consumer, but mechanically poisonable and Medium-on-consumer-wire-up per the `hyper.proto:1212-1230` retro-distribution contract.

### [F104 — `FeeDepositBody` Ed25519 signing payload omits `chain_id` → replayable across hypersnap deployments / shards (F101-class variant)](findings/F104-fee-deposit-no-chain-id-binding-replayable-across-hypersnap-shards.md)
**WP 0.90 · solidity-bridge**
Sibling of F101 in a `-v1` DST. Cross-shard replay moves the victim's primary→fee balance on the victim's own FID — no value extraction, only forced reservation, hence Low. Production exposure gated on a second `protocol_chain_id` being provisioned (config field exists; today only chain 10 runs) plus victim nonce-alignment and chain-B primary balance. Same defect class extends to `token_transfer.rs::DST` and `token_lock.rs::DST` (v1-DST family).

### [F095 — `BridgeBurnStore` watermark is poisonable and queue is never pruned, degrading the inbound-bridge over time](findings/F095-watermark-poisoning-and-unbounded-queue-in-bridge-burn-store.md)
**HC 0.85 · solidity-bridge**
Two sub-issues: (a) cursor-poison DoS via attacker-injected high-`source_block_number` (the opposite-direction twin of F094); (b) `ObservedBurns` queue grows unboundedly. Validator: (b) is Phase-3c-acknowledged in `actor.rs:321-325` ("queue isn't auto-pruned in Phase 3c, only the processed-marker is checked at sign time"); (a) has no carve-out and stands. `apply_inbound_burn`'s replay marker prevents double-credit, so both issues correctly self-scope to Low.

### [F137 — Importer's per-transfer re-validation in `runtime::import_block` omits the `extract_output_pubkeys` gate that proposer-side admission enforces](findings/F137-importer-re-validation-omits-extract_output_pubkeys-gate-and-silently-strands-outputs.md)
**WP 0.90 · node-lifecycle-actor**
A malicious threshold signer can include a transfer with a malformed `one_time_pubkey` that passes import yet silently fails the post-apply note-store sync, leaving the verkle-tree commitment present but the output permanently unspendable (verkle/note-store divergence). Compounded by `apply_message_with_notes` being defined as the documented "production import path" yet never called, while the inline duplicate at `runtime.rs:4186-4205` encodes the OPPOSITE decision (silent skip). Validator: grep confirms `apply_message_with_notes` has ZERO production callers — the documented "production import variant" is dead code; the inline silent-skip at `runtime.rs:4185-4205` is the only path that runs, and its author-comment "Errors decoding wire fields here would have been caught above" cites an upstream gate the importer's re-validation loop *does not include* (mempool admission has it; import does not).

### [F045 — DKLS `recovery_id ∈ {2,3}` bricks signing with no retry](findings/F045-dkls-recovery-id-2-or-3-bricks-signing-no-retry.md)
**WP 0.90 · rust-crypto-primitives**
DKLS correctly rejects `recovery_id ∈ {2,3}` (no silent `v = 29/30` emission), but the protocol-prescribed MPC re-run is not wired. Probability per signature is ~2⁻¹²⁸ (≈10²⁹ years at 10⁹ sigs/year), making the trigger adversarially unreachable. Combined with F040, however, the once-per-universe event becomes a permanent in-epoch outage instead of a transient one-ceremony retry — flagged as defensive completeness.

### [F062 — Empty Merkle root accepted as valid bridge-root update](findings/F062-empty-merkle-root-accepted-as-valid-update.md)
**WP 0.90 · solidity-bridge**
`HypersnapBridge.sol::claim` advances `latestRoot` to any owner-signed value with no zero-root rejection; the Rust `build_lock_tree(vec![])` test pins that an empty input produces `B256::ZERO`. Every chain crossing an epoch boundary with an empty `RewardStore` (the default state at launch) is the canonical trigger — a legitimately threshold-signed empty-epoch advance freezes every then-unclaimed leaf under the prior root until a fresh non-zero root is signed. The in-source comment at `actor.rs:3522-3524` confirms the dev team knows this.

### [F044 — ECDSA wire format does not enforce low-S at construction](findings/F044-ecdsa-low-s-not-enforced-at-construction.md)
**HC 0.80 · rust-crypto-primitives**
`EcdsaSignature::from_bytes`/`from_rsv` (`ecdsa.rs:62-85`) does not enforce low-S despite a docstring claim and a wire-format comment promising "low-S only"; combined with `recover_address_from_prehash` silently calling `normalized_s()` on the verifier side, this leaves a cross-side asymmetry where Rust accepts both `(r, s, v)` and `(r, n-s, v^1)` for the same digest while Solidity strict-rejects high-S. Validator: today the DKLS producer always normalizes, so the bridge sees low-S and OZ `ECDSA.recover` accepts everything — but the in-protocol slashing-evidence dedup keys treat raw signature bytes as identity, so the malleability primitive is reachable inside the L2 today; bridge framing is forward-looking.

---

## Info — 1 finding (latent today, escalates on wire-up)

### [F110 — DKLS `refresh_phase4` and `refresh_complete_phase4` invoke the F107-defective `step5`; latent because `refresh.rs` is unreachable from production](findings/F110-dkls-refresh-step5-verification-skip-variant-of-F107.md)
**HC 0.88 · rust-threshold-signing**
Same root-cause as F107, distinct downstream consequence — silent permanent key drift after refresh via malicious non-zero polynomial bypassing the `verifying_pk == identity` check. Algebra: `Q = l_V^{-1} · (-(rest))` with public Lagrange weights, single scalar mul; combined with attacker-chosen non-zero polynomial constant, refresh silently drifts `poly_point` while `Party.pk` is preserved unchanged. Reachability confirmed: zero non-test callers of `refresh_phase*`/`refresh_complete_phase*` anywhere in `crates/hypersnap-crypto/` or `src/hyper/`, all 8 call sites inside `#[cfg(test)] mod tests`. Severity is INFO today; if a future commit wires refresh into the epoch lifecycle, re-rate as the persistent address survives across epochs (more severe than F107's per-epoch DKG pk corruption).

---

## Excluded — 1 finding (red-team invalidated)

[**F058 — `verify_lock_signature` unwired / "arbitrary bridge mint"**](findings/F058-verify-lock-signature-unwired-arbitrary-bridge-mint.md) — **INVALIDATED 0.92** by red-team validation. The unwired `verify_lock_signature` in `lock_event.rs:180` *is* dead code (no production callers), but it belongs to the **abandoned verkle-bridge design**, not the live bridge. The live L1 `HypersnapBridge.claim` consumes a keccak256 Merkle proof over leaves from `TokenLockState`, populated by `apply_token_lock` which correctly verifies Ed25519 + signer-set auth. The dead code's leaf format is byte-incompatible with what L1 expects. Classic two-pipeline confusion. The dead code is housekeeping-only (Low/Info).

---

## Iter-2 — closeout

All 27 iter-2 findings have now survived the validator's red-team 8-hypothesis walk: 9 WATERPROOF + 2 HAS_CAVEATS in the final batch (F117 WP, F119 WP, F121 HC, F135 WP, F137 WP, F149 HC, F151 WP, F153 WP, F154 WP, F157 WP, F158 WP); cumulative iter-2 verdicts 18 WP / 9 HC / 0 INVALIDATED. Dedupe walked 24 candidate pairs against the combined 56-finding corpus: 1 same-root-cause linkage (F107 ↔ F110, DKLS `step5` self-skip), 20 related-but-distinct cross-references (notably the F107/F108/F110/F114 DKLS inner-index-trust family, the F101/F104/F105/F158 chain-id/nonce-binding family, and the F132/F133 batch-hygiene complementary defects), 3 false-positive heuristic matches. See [`audit-index-iter2.md`](audit-index-iter2.md) for the iter-2-specific spotlight including the three revalidation wins that contradicted iter-1 rulings.
