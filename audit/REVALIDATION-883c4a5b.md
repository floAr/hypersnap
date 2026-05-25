# Hypersnap — Fix Revalidation of commit `883c4a5b` ("fixes from audit")

**Fix commit:** [`883c4a5b35581042edcd8bdfbee8d56f3cc21c98`](https://github.com/farcasterorg/hypersnap/commit/883c4a5b35581042edcd8bdfbee8d56f3cc21c98) — *"fixes from audit"*, Cassandra Heart (CassOnMars), 2026-05-25, on PR [#28](https://github.com/farcasterorg/hypersnap/pull/28) (branch `pow`).
**Audited base (pre-fix):** [`6cff47c637…`](https://github.com/farcasterorg/hypersnap/commit/6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae) — the exact commit this audit was pinned to. The fix commit is its direct child.
**Diff size:** 74 files, +4,109 / −1,646.
**Audit harness:** [audit-suite](https://github.com/floAr/audit-suite) multi-agent pipeline. Revalidation by 6 domain specialists across 2 waves.

---

## What this commit is

A direct, self-documented response to this audit. The fix comments cite our finding IDs verbatim — e.g. `src/network/rate_limit.rs` opens with *"Audit finding F031: there was no rate limit on `/v1/validateMessage`…"*. Grepping the diff's added lines surfaces **53 of our 57 finding IDs**. Four are not cited by ID (F058, F104, F105, F110); of those, F058/F104/F105 were nonetheless addressed (F058 by rearchitecture, F104/F105 via new chain-id/epoch binding), and F110 rides F107's fix.

**Structural changes:**

| Change | File | Primary findings |
|---|---|---|
| **NEW** `src/network/rate_limit.rs` (+125) | per-IP token-bucket limiter | F031, F030 |
| **NEW** `src/hyper/shield.rs` (+216) | transparent→confidential move; chain_id+nonce+Ed25519 sig+commitment-opens-to-amount+DST | F104, F052, F149 |
| **NEW** `src/hyper/confidential_lock.rs` (+282) | rebuilt bridge lock; lock_id from nullifier; Schnorr spend-sig + Pedersen balance closure + double-spend gate | **F058**, F091, F062 |
| **DELETED** `src/hyper/token_lock.rs` (−371) | old lock path removed wholesale | — |
| gutted `src/hyper/lock_event.rs` (−241) | legacy lock-event logic stripped | F058, F117 |
| heavy `src/hyper/runtime.rs` (+885) | apply-path rewiring | many |

---

## Scoreboard

Scope of this revalidation: the 3 criticals + 28 highs (+ F110 info as a free rider on F107).

| Severity | Fixed | Partial | Not fixed |
|---|---|---|---|
| **Critical (3)** | F058, F133, F138 | — | — |
| **High (28)** | F005, F011, F013, F028, F040, F048, F105, F107, F114, F116, F117, F119, F132, F151, F153, F154 — **16** | F002, F004, F009, F018, F023, F024, F026, F031, F036, F108, F135, F158 — **12** | — |
| **Info (1)** | F110 | — | — |

**3/3 criticals closed. 0 findings untouched. The remaining risk lives entirely in the 12 partial highs — and ~8 of those have a residual that is still exploitable, not merely a missing hardening layer.**

All verdicts were adjudicated by static call-site tracing against the patched source at `883c4a5b`. No build was run. Several fixes ship their own regression tests (uncompiled here). The only verdict whose *magnitude* would benefit from a runtime check is F135 (statistical reward-collapse).

---

## Criticals — confirmed closed at the real call-sites

### F058 — verify-lock-signature unwired → arbitrary bridge mint · **FIXED**
The forge-mint root cause is gone. The L1-facing keccak `TokenLockState` bridge root is built solely by `runtime.rs::build_lock_merkle_tree` → `iter_all_locks()`, and the only two production emitters of `TokenLockState` now both authenticate: `apply_confidential_lock` (`confidential_lock.rs::validate_against_store` = Schnorr `schnorr_verify` over a chain-id/destination/nullifier-bound payload + Pedersen balance closure + `is_spent` nullifier double-spend check; `lock_id` derived from the spent nullifier) and `apply_token_escrow_bridge` (EIP-712). The deleted `verify_lock_signature` / `HyperLockEvent`→verkle pipeline still exists as dead code (`router.rs`, `builder.rs`, `importer.rs`, structural-only) but does **not** feed the bridge root.
**Residual (downgrade to Info):** the ungated `HyperLockEvent` verkle path survives as dead code — a gossiped `Body::Lock` still inserts attacker-chosen leaves into the verkle tree (state-bloat/DoS only, no mint). Worth deleting outright.

### F133 — FingerprintStore writes bypass txn_batch on simulate → fork + free poisoning · **FIXED**
`FingerprintStore::insert` is now `#[cfg(test)]`-only; production writes go through `stage_insert(…, &mut batch)`, and the eviction tail of `uniqueness_score(…, &mut batch)` now does `batch.delete(k)` instead of `self.db.commit`. `FeeCharger::stage_fee` / `record_fingerprint_if_cast` thread the engine batch through; `merge_message` passes `txn_batch`. `simulate_message` / `simulate_bulk_messages` build a local batch that is dropped (never committed) and trie-reloaded, so simulate performs zero durable fingerprint writes. Closes the consensus-fork, fee-free-poisoning, and forced-eviction variants. No residual.

### F138 — proposer broadcast strips locks/transfers + zeros signed anchor metadata · **FIXED**
`HyperActorOutbound::BroadcastBlock` now carries `locks`/`transfers`, populated from `pending.locks`/`pending.transfers` in `dispatch_dkls_signature` — the same messages the proposer applied locally. `outbound_to_wire` forwards them into `HyperWireBlock`; `wire_to_event` reads them back; `encode/decode_hyper_block` now use the `From<…HyperBlockMetadata>` impls that carry all six anchor / missed-proposals / range fields bidirectionally. Both the signature-mismatch and state-root-mismatch variants are closed; the simulation test's manual lock re-injection was removed, exercising the real wire path.
**Note:** `runtime.rs::decode_proto_block` still zeroes anchor fields but is `#[cfg(test)]`-only — latent Variant C, not a production path.

---

## Highs — fixed (16)

Each verified wired at the real call-site, not merely defined.

- **F005** read-validator protocol version · every panic site on the read-validator/gossip path is now a graceful drop (`read_validator.rs` `get_decided_value_height`→`Option`, `validate_protocol_version` guards, `commit_decided_value` `error!`+drop; `snapchain_read_node.rs::dispatch_decided_value` drops on missing/unknown variant).
- **F011** auto-deregister counter resets each epoch · new cross-epoch `HyperValidatorConsecutiveMisses` (RootPrefix 90) keyed on `validator_key`; `should_auto_deregister` reads the persistent counter. Regression test `auto_deregister_aggregates_across_epochs`.
- **F013** vouch puppet pump (default disabled) · `vouch_boost_min_vouchee_trust` 0.0→0.3 in `ScoringParams::default()`, in-protocol path uses that default — the puppet-pump on a genuinely low-trust sybil is suppressed by default. *(Residual overlaps F009: a sybil already inflated to trust≈1.0 by the F009 ring still clears the 0.3 gate.)*
- **F028** signing payload misses hash fields · `HyperBlockMetadata::signing_payload` (v2 DST) now binds `extra_rules_version` + `retained_message_count` (+ `signer_indices`, see F153); verify paths in `importer.rs` and `slashing.rs::verify_evidence_signatures` re-derive the identical payload.
- **F040** dkls supervisor no retry after abort · dispatch-time latch replaced with install-confirmation + TTL retry (`Dispatched{epoch,ticks_since}` + `has_dkls_share_for_epoch`; clears and re-fires `StartDkls` after `DKLS_RETRY_AFTER_TICKS=12`).
- **F048** kzg SRS silent random-tau fallback · `build_srs` returns `Err(MissingKzgSetup)` unless `allow_random_kzg_srs` (defaults false); every `random_unsafe` call-site is `#[cfg(test)]`.
- **F105** app-usage receipt no epoch binding · `AppUsageReceiptBody` gains a signed `epoch`; `apply_app_usage_receipt` rejects `body.epoch != current_epoch()` before any write. *(Silently fixed — not cited by ID — but correct.)*
- **F107** dkls step5 self-skip · `step5` now verifies **every** `ProofCommitment` unconditionally; the `index == party_index` self-skip is removed.
- **F114** dkls zero-share init trusts inner parties · `dkls_ceremony.rs` now cross-checks `parties.sender`/`receiver` against wire sender/receiver on all three zero-share/mul branches, dropping mismatches.
- **F116** kzg loader assumes monomial basis · `build_srs` requires `kzg_basis` to be declared and explicitly rejects Lagrange (`LagrangeKzgSetupNotSupported`) before `into_srs_monomial`. *(Conversion not implemented — detect-and-refuse satisfies the finding.)*
- **F117** verkle lock key missing domain byte → panic DoS · `insert_lock_into_tree` stores at `lock_verkle_key = 0x01‖lock_id` (33-byte); all three verkle domains now produce equal-length, disjoint-prefix keys, so neither panic site is reachable. Regression test reproduces the `[0x02;32]` construction and asserts no panic.
- **F119** dlogproof verify panic on malformed challenge · `InteractiveDLogProof::verify` now guards `self.challenge.len() != (T/8)` → `return false` before `U256::from_be_slice`; reached on both network-facing paths (DKG step5, OT base).
- **F132** stage-charge fee read-after-write collapse · `stage_charge_message_fee` reads via `*_through_batch` helpers that consult `batch.batch.get(key)` before disk; successive same-FID charges compose. Regression test `stage_charge_message_fee_composes_within_batch`.
- **F151** snapchain codec decode panics · `Codec<SignedConsensusMsg>::decode` and `Codec<sync::Response>::decode` now `?`-propagate via new fallible `Vote::try_from_proto` / `Proposal::try_from_proto` / `Address::try_from_vec` / `Commits::try_to_commit_certificate`; `network_connector.rs` logs the error instead of crashing. All three named message types covered.
- **F153** hyperblock threshold sig omits signer indices · `signing_payload` now binds `signer_indices` (sorted, length-prefixed) + `extra_rules_version` + `retained_message_count`, DST bumped to `-v2:`; sign + verify + slashing paths all pass `signer_indices`. Low-S enforced in `EcdsaSignature::from_bytes`. Closes attacker-steered slashing.
- **F154** farcaster batch endpoints unbounded · `MAX_BATCH_FIDS = 1024` enforced in `parse_batch_fids`; `MAX_PAGES_PER_FID = 20` caps pagination. Total work now deterministic and finite.

### Info
- **F110** dkls refresh step5 skip · same root-cause site as F107, now closed by the unconditional verify; refresh remains unreachable from production (severity stays info).

---

## Highs — partial: residuals still live

These are not hardening nits — each has a traced, working residual. **Treat the starred ones as effectively-unresolved highs.**

### ★ F002 — nil block proposal · **PARTIAL — remote panic DoS still live**
The validator/proposer unwraps were patched (`proposer.rs::add_proposed_value`, `validator.rs::add_proposed_value` now return `Validity::Invalid`). **But the finding's actual PoC fires earlier:** `snapchain_codec.rs:106` still does `proposal.height.unwrap()` on the peer `Channel::ProposalParts` decode path (`network_connector.rs:214`), which runs **before** `add_proposed_value`. A `FullProposal` with `height == None` from any gossip peer still panics the network task here.

### ★ F108 — dkls signing trusts inner sender · **PARTIAL — misattribution-blame intact**
The panic-DoS is fixed (the four `…get(&counterparty).unwrap()` in `sign_phase2/3` now return `Err(Abort)`). **But the primary fix was not applied:** `dkls_sign.rs::submit` still does a bare `received_1to2.insert(sender, transmit)` with no `parties.sender == wire sender` cross-check, no committee-membership check. Since `signing.rs` dispatches blame on `message.parties.sender`, an authenticated validator can still frame an innocent committee member for slashing. (Its sibling F114 *did* get the cross-check.)

### ★ F026 — dkls share selection / slashing bypass · **PARTIAL — slashing bypass intact**
The future-epoch leak is fixed (`produce_unsigned_block_dkls` now `.get(&current_epoch)` bound to the resolver). **But the slashing-bypass primitive is untouched:** `detect_conflicting_blocks` still returns `Err(DifferentEpochs)` and drops evidence when `a.signature.epoch != b.signature.epoch`. A validator holding two consecutive epochs' shares can sign two blocks at the same `canonical_block_id` with different epoch tags and evade equivocation slashing.

### ★ F009 — sybil amplification via eigentrust · **PARTIAL — ring saturation intact**
The fix is `crediter_trust_threshold 0.0→0.05` only; `scoring.rs` and `eigentrust.rs` are byte-identical pre/post. The draft's primary lever — top-N normalization saturating a ≥100-member sybil ring to trust≈1.0 — is unmitigated; such a ring trivially clears 0.05 and still captures Growth-market budget. The floor only strips the noise-floor tail of single low-trust crediters.

### ★ F031 — no rate limit on ingress · **PARTIAL — gRPC wide open**
`IpRateLimiter::allow` is invoked exactly once, in the HTTP `listener.accept()` loop (`main.rs:327`). Two gaps: (1) it gates TCP *accepts*, not requests — `serve_connection` services unlimited keep-alive/pipelined requests on one accepted connection, so a single reused connection floods `/v1/*` freely; (2) the **gRPC `HubService` listener has no limiter at all** — the finding's named `GetBlocks` / `submitMessage` / `submitBulkMessages` / `validateMessage` are direct gRPC methods, reachable unthrottled.

### ★ F036 — committee selection digest proposer-grindable · **PARTIAL**
Only the block-production seed was de-grinded (`committee_seed_for_block(epoch, height, parent_hash)`). The other five `select_signing_committee` callers still key on proposer-influenced `keccak256(signing_payload)` — reward issuance, trust snapshot, inbound burn, and notably the **bridge lock-merkle-root update** (the draft's Caller-C 1-bit grind lever). `select_signing_committee`/`rank_for` themselves were not made non-grindable.

### ★ F135 — da-pow driver zero-pads served key · **PARTIAL — reward collapse persists**
The named width defect is fixed (driver serves the natural-length key; `validate_da_response` accepts `CHALLENGE_PREFIX_BYTES..=256`; apply-path exact-byte `lookup.contains_key` now matches). **But the bundled secondary defect is untouched:** `derive_challenge_prefix` still emits a 16-byte SHA-truncated prefix that doesn't condition on the trie's structured key layout (shard byte + FID + type byte), and the prod producer still does `trie_values_with_prefix(prefix).next()`. So honest `lookup(&prefix)` returns `None` for ~all challenges → DA-PoW reward signal still ≈ zero across the validator set. *(Magnitude is statistical → the one NEEDS-RUNTIME item; recommend a devnet/epoch-count check.)*

### F158 — jfs webhook no app-id/nonce binding · **PARTIAL**
Cross-app bit-identical replay is blocked (`store.rs::claim_envelope(app_id, fid, blake3(body))`, invoked after JFS `verify_strict`). Residuals: (a) same-app branch is deliberately idempotent then re-runs `apply`, so stale-overwrite (replay an old `notifications_enabled` to overwrite newer URL/token) is **not** blocked; (b) the marker hashes raw JSON `body`, not canonical `signing_input`, so whitespace/key-order/base64 re-encoding yields a new hash and re-enables cross-app replay; (c) no signed `app_id`/`nonce`/`signed_at`/`domain`, so cross-deployment replay is unaddressed. This is the draft's interim Option-C, not the preferred Option B.

### F004 — epoch boundary race · **PARTIAL**
Primary fix landed: `import_block` now calls `epoch_resolver.observe_anchor(...)` on every block, unfreezing `current_epoch()` post-cutover (fixes the stale-epoch family: unstake maturation, rewards, slashing eviction, proposer-gate set). Deferred secondary races: cutover/genesis arithmetic still `anchor / EPOCH_LENGTH` with no offset; two desynchronized anchor mutexes persist; supervisor derives `next_epoch` from its private anchor; `build_driver` double-reads the anchor across `.await`; `refresh_proposer_context_loop` reads epoch/active-set/anchor across three `.await`s before the write.

### F024 — scheduler split-read + supervisor anchor jump · **PARTIAL**
Issue 1 fixed: new `should_propose_and_snapshot` takes the gating decision and the `(anchor_block, anchor_hash, anchor_ts)` snapshot under one lock, so the produced block's anchor matches the gating anchor. Issue 2 not fixed: the supervisor still computes a single `next_epoch` and has no catch-up loop over `[last_dispatched+1 .. next_epoch]` — an anchor jump past epoch N's lead window still leaves epoch N with no DKG group. (The new `dispatched`+`DKLS_RETRY_AFTER_TICKS` only re-fires the *same* epoch — that's the F040 fix.)

### F018 — dkls inner sender not bound to libp2p peer id · **PARTIAL**
Binding is wired end-to-end: `validator_event_signing_payload` binds `libp2p_peer_id`; `compute_active_peer_ids` builds the authenticated map; `actor.rs::check_dkls_sender_against_propagation_source` rejects frames whose inner `sender` doesn't map to the source peer. Residuals: (1) the check binds against libp2p `propagation_source` (the *forwarding* neighbor), not the gossipsub *originator* — in a multi-hop mesh this both false-rejects honest relayed frames and only authenticates direct neighbors; (2) `peer_id_for_party` indexes `nth(party_index-1)` into a set that *omits* validators with empty `libp2p_peer_id`, while the committee enumerates the full active set — during gradual rollout these orderings diverge; (3) two permissive fall-throughs (`propagation_source==None` or no registered peer-id ⇒ accept) leave the binding unenforced until every active validator has registered a peer-id.

### F023 — dkls round messages dropped and cross-routed · **PARTIAL**
Fixed: drop-on-early-arrival (`pending_dkls_inbound` buffer drained by `StartDkls`) and the DKG-side same-epoch overwrite guard. Residuals: (a) cross-digest sign routing — `build_aad(epoch, ROUND_TAG_SIGN, sender, receiver)` still omits the digest and `InboundDklsSign` filters only by `epoch()`, so a peer's Phase-1 sign frame for digest D_A still decrypts and submits into a same-epoch driver signing D_B; (b) `start_dkls_block_production` still does an unconditional `self.active_dkls_sign = Some(driver)` with no guard, so a block-production ceremony can silently clobber an in-flight scoring/lock-root ceremony.

---

## Notes & caveats

- **Methodology:** static call-site tracing against patched source at `883c4a5b` (originals at `6cff47c`), one domain specialist per cluster. The agents flagged **no** verdict as build-dependent to *decide*; only F135's reward-collapse *magnitude* is statistical (NEEDS-RUNTIME). Fixes shipping their own regression tests (F011, F117, F119, F132, F133, F153, …) were not compiled here — confirming those tests pass requires a build.
- **F058 reverses the iter-1 context:** iter-1 INVALIDATED F058 on a two-pipeline confusion over dead verkle-bridge code. The fix commit confirms that read was directionally right about the verkle path being dead — but the *critical* forge-mint via the keccak `TokenLockState` root was real and is now closed by the new gated emitters.
- **Recommended re-report set** (effectively-unresolved highs + one critical-adjacent cleanup): F002, F031, F108, F026, F009, F036, F135, F158. Per the runnable-PoC standard, each should ship a PoC compiled + run against `883c4a5b` before publication.
