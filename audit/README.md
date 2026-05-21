# Hypersnap — Audit Findings Index

**Audited commit:** [`6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae`](https://github.com/farcasterorg/hypersnap/commit/6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae) (branch `pow`)
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline, brain library `2921c8eb3756`
**Methodology:** Recon → Hunt → 8-hypothesis red-team Validate → Dedupe. Each finding here survived an independent validator agent's adversarial 8-hypothesis walk; findings the validator broke (1 — see footnote on F058) are excluded.

**Status:** Iteration 1 complete. Iteration 2 (gapfill-seeded hunt over an additional 69 files — DKLS23 internals, bulletproofs, EIP-712 signers, account stores, ingress) is in progress and not included below.

**Verdict shorthand:**
- **WP** — *WATERPROOF*: finding stands after the validator's red-team walk.
- **HC** — *HAS_CAVEATS*: finding stands, but the validator narrowed impact, swapped an example, or flagged a load-bearing assumption. Read the validator notes alongside the finding body.
- Confidence (0–1) is the validator's own.

---

## High — 17 findings

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

## Medium — 9 findings

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

## Low — 3 findings

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

## Excluded — 1 finding (red-team invalidated)

[**F058 — `verify_lock_signature` unwired / "arbitrary bridge mint"**](findings/F058-verify-lock-signature-unwired-arbitrary-bridge-mint.md) — **INVALIDATED 0.92** by red-team validation. The unwired `verify_lock_signature` in `lock_event.rs:180` *is* dead code (no production callers), but it belongs to the **abandoned verkle-bridge design**, not the live bridge. The live L1 `HypersnapBridge.claim` consumes a keccak256 Merkle proof over leaves from `TokenLockState`, populated by `apply_token_lock` which correctly verifies Ed25519 + signer-set auth. The dead code's leaf format is byte-incompatible with what L1 expects. Classic two-pipeline confusion. The dead code is housekeeping-only (Low/Info).

---

# Hypersnap — Iter-2 Findings Spotlight

**Audited commit:** [`6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae`](https://github.com/farcasterorg/hypersnap/commit/6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae) (branch `pow`)
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline, brain library `2921c8eb3756`

This is the iter-2-only spotlight. For the combined iter-1 + iter-2 index see [`audit-index.md`](audit-index.md). Iter-2 was a gapfill-seeded second-pass hunt against 69 additional scope files (DKLS23 internals, ed448-bulletproofs, KZG/verkle loaders, account-store batch hygiene, the Farcaster v2 ingress, notification webhooks).

**Iter-2 numbers:** 27 findings filed. 16 red-team validated to date (9 WATERPROOF, 7 HAS_CAVEATS, 0 INVALIDATED). 11 still in validation queue.

---

## Revalidation wins — three findings iter-1 missed

The whole point of running a phase-2 revalidation is to surface bugs the first pass closed too early. These three are exactly that:

| F-ID | Sev | Iter-1 disposition | Iter-2 verdict |
|---|---|---|---|
| **F138** | CRITICAL | (out of iter-1 scope; not covered) | **WATERPROOF 0.97** — chain halts on any honest multi-node deployment |
| **F133** | CRITICAL | (out of iter-1 scope; not covered) | **HAS_CAVEATS 0.75** — consensus fork via unauthenticated gRPC |
| **F132** | HIGH | iter-1 H035 ruled `stage_charge_message_fee` clean on crash-atomicity grounds | **WATERPROOF 0.96** — within-batch read-after-write hazard H035's methodology was not designed to detect |

F132 is the textbook revalidation case: the iter-1 specialist correctly walked the crash-atomicity checklist and concluded "no issue here", but that's the wrong checklist for this defect. The iter-2 gapfill seeded `fee_charger.rs` as a fresh scope file with a different attack class (`fee-trust-uniqueness-flow`), and a different specialist walked it cleanly. H035's note stays correct *within its declared scope*; F132 lives outside that scope.

F138 and F133 are bugs that iter-1's recon never touched: F138 sits at the `gossip_adapter` wire boundary that the iter-1 hunter for `gossip_adapter.rs` (H041) treated as a transport-only file, and F133 is in `fingerprint_store.rs` which only entered the queue when gapfill noticed it as uncovered.

---

## Validated iter-2 findings (16)

### Critical (2)

**[F138 — Proposer broadcast strips locks/transfers + zeros signed anchor metadata; chain halts on any honest multi-node deployment](findings/F138-proposer-pipeline-strips-locks-transfers-and-signed-anchor-fields-from-wire-broadcast.md)** · **WP 0.97**
`gossip_adapter::outbound_to_wire` hard-codes `locks: vec![], transfers: vec![]` and both `encode_hyper_block` / `decode_hyper_block` zero out `snapchain_anchor_*`, `missed_proposals`, `snapchain_range_*`. Peers recompute `signing_payload` over zeroed bytes → `SignatureVerificationFailed`; for the all-anchors-zero case the state-root replay also diverges → `StateRootMismatch`. The chain mechanically halts on any honest multi-node deployment past genesis. Validator also flagged `block_index.rs:35-63` as a THIRD production copy of the drop pattern (the finding had classified it as test-only).

**[F133 — `FingerprintStore` writes bypass txn_batch on the gRPC simulate path → per-validator divergence → consensus fork via unauthenticated RPC](findings/F133-fingerprint-store-direct-db-writes-during-simulate-cause-fork-and-free-poisoning.md)** · **HC 0.75**
`FingerprintStore::insert` (`self.db.put`) and `uniqueness_score`'s eviction (`self.db.commit`) bypass the engine's `txn_batch`. `merge_message` runs on the gRPC `submit_message` simulate path; any unauth caller plants/evicts fingerprints on one validator's local DB. Validator narrowed: the finding's "fee_balance → account_root" intermediate mechanism is wrong (account_root is purely trie-of-message-hashes); actual fork is divergent accept/reject when a poisoned fee crosses the `HyperFeeInsufficient` threshold. Severity stands; prose needs correction.

### High (7)

**[F091 — Cross-FID `lock_id` collision permanently strands victim's bridge-locked balance](findings/F091-lock-id-collision-across-fids-permanently-strands-victim-balance.md)** · **WP 0.97**
L2 per-FID `lock_id` dedup + L1 `claimed[lockId]` global nullifier + zero recovery path = any attacker with one funded FID can race the victim's burn and permanently nullify the L1 slot. Pinned test `same_lock_id_on_distinct_fids_is_allowed` literally asserts the bug.

**[F105 — App-PoW receipts have no epoch binding; one captured receipt replays every future epoch indefinitely](findings/F105-app-usage-receipt-no-epoch-binding-cross-epoch-replay.md)** · **WP 0.93**
`AppUsageReceiptBody.timestamp` is signed but never compared against `current_epoch()`. The receipt-count consumer credits blindly. One captured byte-identical receipt saturates `MAX_RECEIPTS_PER_APP_PER_EPOCH = 10_000` per (user, app) pair as a *floor* on §7 App-PoW reward inflation. F101 family.

**[F108 — DKLS signing trusts inner `parties.sender`; 1-packet panic-DoS + misattribution-blame](findings/F108-dkls-signing-trusts-inner-sender-for-routing-and-blame.md)** · **WP 0.95**
`sign_phase2/3` dispatch `kept[..]` and abort-blame strings on attacker-controlled inner `parties.sender`. One inbound `Phase1Send` permanently crashes the victim's signing actor (no `catch_unwind`) or frames an innocent committee member. F107 family.

**[F132 — `stage_charge_message_fee` reads accumulators from disk, not from the in-progress batch; same-FID fee-bearing messages silently free](findings/F132-stage-charge-message-fee-read-after-write-collapse.md)** · **WP 0.96**
Reads `fee_balance` / `total_fee_burned` / `proposer_fee_pot` via `self.db.get` instead of from `RocksDbTransactionBatch`. Successive same-FID messages in one chunk overwrite each other; only the last commits. Determinism-safe (no fork) but accounting silently breaks. Contradicts iter-1 H035.

**[F107 — DKLS `step5` skips DLog verification for any `ProofCommitment` whose inner `index` matches the verifier's own party_index](findings/F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md)** · **HC 0.85**
`t<n` produces silent ceremony-DoS via Lagrange cross-window mismatch; `t==n` produces silent group-pk corruption. Validator: titular "arbitrary-pk injection" overstated (attacker can't know DLog); per-recipient divergent-pk needs F023.

**[F114 — DKG zero-share init trusts inner `parties.sender`/`receiver` bytes; three reachable primitives (DoS / misattribution / silent corruption)](findings/F114-dkls-zero-share-init-trusts-inner-parties-sender-receiver.md)** · **HC 0.85**
DKG `phase4` dispatches on inner bytes; ceremony layer keys accumulator BTreeMaps on wire-sender; no cross-check. Primitives A (DoS) and B (framing) unconditional from one packet; C (silent ZeroShare-vec corruption surfacing at signing time with blame-less abort) needs F018/F023.

**[F116 — KZG loader silently treats Lagrange-basis G1 points as monomial powers of τ](findings/F116-kzg-loader-assumes-monomial-basis-no-lagrange-detection-or-conversion.md)** · **HC 0.72**
`HyperRuntimeFileConfig::build_srs` calls `into_srs_monomial` unconditionally with no basis detection. Validator: filed High but cryptographic claim is wrong — the wrong-basis map is linear and injective, KZG binding transfers; actual harm is honest verkle-opening verification failure (liveness/RPC bug only, no on-chain consumer). **Severity should drop to Medium.**

### Medium (1)

**[F101 — Custody-key JFS account-association proof is a publicly-served replayable bearer token](findings/F101-account-association-jfs-proof-replayable-no-chain-or-nonce-binding.md)** · **WP 0.92**
No chain-id, no nonce, no consumption — every other miniapp operation binds chain_id+nonce. Cross-chain front-run + Phase-B forward-dated replay both verified. Canonical parent of the F101/F104/F105/F158 family.

### Low (5)

**[F094 — Bridge-burn watcher resume cursor derived from drainable queue, not persisted high-watermark](findings/F094-bridge-burn-watcher-cursor-derived-from-drainable-queue.md)** · **WP 0.92**
Latent today (`BridgeBurnStore::remove` has no production caller); `apply_inbound_burn` replay marker prevents double-credit. Self-limits to liveness/RPC-budget.

**[F095 — `BridgeBurnStore` watermark poisonable, queue never pruned](findings/F095-watermark-poisoning-and-unbounded-queue-in-bridge-burn-store.md)** · **HC 0.85**
Cursor-poison (opposite-direction twin of F094) + unbounded queue. Unbounded-queue is Phase-3c-acknowledged tech-debt per `actor.rs:321-325` docstring; cursor-poison has no carve-out. Replay marker prevents double-credit.

**[F096 — `apply_inbound_burn` short-circuits on nullifier BEFORE signature verify](findings/F096-inbound-burn-nullifier-short-circuit-bypasses-signature-verification.md)** · **WP 0.93**
Implementation order reverses the function's own docstring. Reachable via unauth POST `/hyper/v1/messages` — unsigned forgery against a previously-applied `(source_chain_id, burn_id)` returns `Ok(false)` and produces a one-hop gossip rebroadcast. No state mutation; metrics pollution + gossip noise only.

**[F097 — `recovery_watcher` missing finality wait + poisonable cursor + panicking U256→u64 narrowing](findings/F097-recovery-watcher-missing-finality-wait-and-poisonable-cursor.md)** · **WP 0.93**
Recovery pipeline omits all three defensive primitives `bridge_burn` carries. Latent / Low because the store has no production read-consumer today; Medium when consumer wires up.

**[F104 — `FeeDepositBody` Ed25519 payload omits `chain_id`; replayable across hypersnap shards](findings/F104-fee-deposit-no-chain-id-binding-replayable-across-hypersnap-shards.md)** · **WP 0.90**
Sibling of F101 in `-v1` DST. Cross-shard replay moves victim primary→fee balance on victim's own FID — no extraction, only forced reservation. Gated on second `protocol_chain_id` being provisioned. Same defect class extends to `token_transfer.rs` and `token_lock.rs`.

### Info (1)

**[F110 — DKLS refresh inherits the F107 self-index-trust pattern via shared `step5`; latent because `refresh.rs` is unreachable from production](findings/F110-dkls-refresh-step5-verification-skip-variant-of-F107.md)** · **HC 0.88**
Algebra is sound (`Q = l_V^{-1} · (-(rest))` with public Lagrange weights bypasses the `verifying_pk == identity` check; refresh silently drifts `poly_point` while `Party.pk` is preserved). Reachability confirmed: zero non-test callers anywhere in production. If a future commit wires refresh into the epoch lifecycle, re-rate (persistent address survives across epochs — more severe than F107's per-epoch DKG corruption).

---

## Iter-2 findings still pending validation (11)

These survived hunt but have not yet survived the validator's adversarial 8-hypothesis walk. They are NOT included in the combined index above but are listed here so the iter-2 hunt result is fully accounted for:

| F-ID | Sev (specialist's call) | One-liner |
|---|---|---|
| F117 | High | Verkle lock keys omit domain byte → path-prefix panic / silent nullifier-subtree overwrite |
| F119 | High | `DLogProof::verify` panics on malformed challenge → 1-packet remote panic-DoS (DKG / OT / signing-init reachable) |
| F121 | Medium | IPA `from_bytes` uses `mod_order` not canonical → confidential-transfer wire-byte malleability |
| F135 | High | DA-PoW driver pads `served_key`; apply-path exact-byte lookup never matches → §5 reward signal = 0 |
| F137 | Low | Importer skips `extract_output_pubkeys` gate; malformed `one_time_pubkey` strands the output |
| F149 | Medium | Transfer codec `one_time_pubkey` unsigned → relay-attacker recipient-output-burn griefing |
| F151 | High | `SnapchainCodec` decode panics on peer Vote/Proposal/Commits BEFORE signature verify (F002 sibling) |
| F153 | High | Hyperblock threshold-ECDSA payload omits `signer_indices` → attacker-controlled slashing (F028 sibling) |
| F154 | High | Farcaster v2 batch endpoints unbounded `fids` array + uncapped pagination → multi-GB heap DoS unauth |
| F157 | Medium | `following_fid` filter unbounded follower enumeration → post-auth consensus-shared RocksDB DoS |
| F158 | High | JFS webhook signed payload no app_id/nonce/timestamp → cross-app replay / notification phishing |

11 findings × 2 parallel × ≈5 min each ≈ ~3 hunter-rounds remain. Next resume on `/audit-suite:audit-validate`.

---

## Methodology delta for iter-2

- **Gapfill iteration 1** seeded 69 tasks across uncovered files identified after iter-1 close. Hunt success rate on the iter-2 batch was 55 % (27 findings out of 49 unique tasks excluding tests-only ruled-outs) — substantially above iter-1's 33 %, reflecting that gapfill targets surfaced higher-yield scope (lower-coverage files tend to harbor more bugs).
- **Three same-root-cause clusters surfaced**: (1) DKLS inner-index trust pattern (F107/F108/F110/F114); (2) chain-id / nonce binding gaps in signed payloads (F101/F104/F105/F158); (3) F132/F133's adjacent storage-batch hygiene defects, which the iter-1 sweep had partially closed but on a narrower attack class.
- **`max_parallel=2` discipline confirmed** — this workspace hit Anthropic session limits twice during iter-2 hunt; both times the queue resumed cleanly without losing prior work because each dispatched hunter is independent.
