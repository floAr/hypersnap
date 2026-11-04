# Hypersnap PR #34 security review at `7eb981b`

Audited commit: [`farcasterorg/hypersnap@7eb981b`](https://github.com/farcasterorg/hypersnap/tree/7eb981bdb75b98fd489772723047c25a695f8b89) (PR #34, `pow`). All file:line references in the findings are against this commit. This branch is that commit plus this `audit/pr34-7eb981b/` folder; no source file is changed.

> **Disclosure: AI-assisted audit.** This review was carried out by Claude Code agents (specialists for the bridge contracts, consensus/Malachite integration, the shard-0 ledger, PoQ and emission economics, pivot/genesis/epoch handling, p2p gossip, HTTP/RPC ingress, Falcon/PQ message authentication and Rust crypto primitives, plus a spec walk and a regression pass against the previous review round), coordinated by a human reviewer.
>
> - Of the 76 findings, 19 went through an independent validator run that tried to invalidate each one against 8 explicit hypotheses (9 for F005). All 3 Critical and all 12 High findings are in that set. The other 57 (Medium, Low and Informational) are specialist reports with file:line traces that have **not** had that second pass. The index below says which is which.
> - Every Critical and High finding has a PoC that runs against the pinned commit (`cargo test` or `forge test`), with its output checked in under `poc/<ID>/`.
> - Validation also removes or narrows claims. F047 was filed as Medium and is Low after validation: the fee gate can only fail for near-duplicate casts, because F054 already makes every other message free. F005 originally said that a wrong-unit block number (for example a millisecond timestamp) freezes the V1 bridge. Its own PoC control (`test_control_msTimestampJump_recoverable`) showed that the contract stays governable, so the claim was narrowed to the exact value `2^64-1`.
>
> Please treat this as you would any unfamiliar reviewer's output: check the file:line traces, run the PoCs, and push back where anything reads wrong.

## Severity summary

| Severity | Total | Published here | Withheld (coordinated disclosure) |
|---|---|---|---|
| Critical | 3 | 3 | 0 |
| High | 12 | 9 | 3 |
| Medium | 30 | 29 | 1 |
| Low | 25 | 24 | 1 |
| Informational | 6 | 6 | 0 |
| **Total** | **76** | **71** | **5** |

Five findings (F031, F035, F036, F041, F075) are withheld for now. They were reported privately to the Hypersnap team and to Farcaster/Snapchain, because they affect upstream as well. Their files in `findings/` are placeholders, and details will be added after coordinated disclosure.

## Index

"Validation" is the independent validator's verdict and confidence. `HAS_CAVEATS` means the core claim holds and the caveats are written into the finding. "not yet validated" means specialist report only. "PoC" points at the folder with the test, its README and its recorded output.

| ID | Severity | Title | Validation | PoC |
|---|---|---|---|---|
| [F001](findings/F001-header-fields-14-15-not-in-spec.md) | Informational | `HypersnapBlockHeader` fields 14/15 (`epoch_record_hash`, `bridge_action_hash`) diverge from FIP §17.7; no Rust-side pinned header vector | not yet validated | — |
| [F002](findings/F002-commit-digest-no-network-binding.md) | Medium | The commit digest `d` and the lock leaf carry no network identifier, so a certificate made on another Hypersnap network (testnet, devnet | not yet validated | — |
| [F003](findings/F003-lock-id-leaf-spec-gaps.md) | Informational | The spec (§13.5/§13.9) leaves the escrow lock ID, the lock-ID field widths, the leaf domain tag form and the v1/v2 `claimed` namespace | not yet validated | — |
| [F004](findings/F004-retired-set-unbounded-authority.md) | High | Retired validator sets keep full bridge authority forever: nothing binds `h.epoch` to `h.height`, so >2/3 of any past `set(e)` can mint | HAS_CAVEATS (0.85) | [poc/F004](poc/F004/) (build-backed, 12/12) |
| [F005](findings/F005-v1-single-owner-key-unbounded-authority.md) | High | V1 bridge: one ECDSA key has instant, uncapped mint authority, and a single signature at `blockNumber = 2^64−1` disables `pause` | HAS_CAVEATS (0.85) | [poc/F005](poc/F005/) (foundry, 10/10) |
| [F006](findings/F006-universal-upgrade-sig-does-not-commit-to-v2-immutables.md) | Medium | The universal V1 upgrade signature binds only a CREATE3 address, which does not commit to V2's verifier or epoch-1 set; the same signature | not yet validated | — |
| [F007](findings/F007-unclaimed-v1-retro-allocations-stranded-by-upgrade.md) | Low | Unclaimed V1 retroactive allocations become permanently unclaimable at the V2 upgrade, and nothing on-chain or in the upgrade script checks | not yet validated | — |
| [F008](findings/F008-shared-action-watermark-relay-order-kills-cancel.md) | Low | V2 governance actions share one watermark and never expire, so whoever relays first decides which of two decided actions takes effect | not yet validated | — |
| [F009](findings/F009-bridge-vote-spam-unbounded-decide-scan.md) | Medium | One validator can create unlimited distinct bridge actions for free, and every shard-0 block's `decide` loads all of them into memory, so a | not yet validated | — |
| [F010](findings/F010-consensus-falcon-bundled-not-lwe-ms2-spec-divergence.md) | Medium | Consensus keys and commit certificates use Falcon-512 (bundled), not LWE-FSA / LWE-MS2 as FIP §16.2–§16.6 specify, so the CERT-STARK | not yet validated | — |
| [F011](findings/F011-cert-verifier-statement-does-not-bind-bitmap-positions.md) | Medium | `ICertificateVerifier`'s statement is "each key in `signerBitmap` is a member of `setRoot`", but nothing fixes bit i to leaf i or fixes the | not yet validated | — |
| [F012](findings/F012-lock-proof-endpoint-serves-tip-root-not-anchored-root.md) | Low | `/hyper/v1/lock-tree/proof` returns a proof against the node's tip lock root, not the anchored `latestLockRoot`, and V2 accepts only the | not yet validated | — |
| [F013](findings/F013-lock-proof-endpoint-full-scan-per-request.md) | Informational | Each `/hyper/v1/lock-tree/proof` request reads every lock and rebuilds the whole tree on the async runtime (O(total locks) per | not yet validated | — |
| [F014](findings/F014-burn-recipient-encoding-mismatch-burns-skipped.md) | Medium | A burn to `bytes32(uint256(fid))`, the encoding the repo's own tests use, destroys the tokens on the EVM side, and the watcher skips it, so | HAS_CAVEATS (0.8) | [poc/H011](poc/H011/) (2/2) |
| [F015](findings/F015-burn-view-divergence-no-reconciliation.md) | Medium | The inbound-burn view is never reconciled | not yet validated | — |
| [F016](findings/F016-burn-dedupe-key-omits-contract-address.md) | Low | The inbound-burn identity is `(chain_id, burnId)` without the contract address, and the "known bridge contract address" is node config | not yet validated | — |
| [F017](findings/F017-burn-store-never-pruned-proposer-full-scan.md) | Low | The observed-burn store is never pruned | not yet validated | — |
| [F018](findings/F018-oversized-message-proposed-then-rejected-by-validate-body.md) | High | The shard-0 proposer has no per-message size limit, but `validate_body` rejects any message over `MAX_MESSAGE_BYTES` | HAS_CAVEATS (0.8) | [poc/F018](poc/F018/) (build-backed, 3/3) |
| [F019](findings/F019-scoring-result-unbounded-can-exceed-max-block-bytes.md) | Critical | The `ScoringResult` has one entry per scored FID and goes into one fixed block with no size check | HAS_CAVEATS (0.85) | [poc/F019](poc/F019/) (build-backed) |
| [F020](findings/F020-full-block-plus-own-certificate-exceeds-limit-unsyncable.md) | Medium | The proposal size budget does not reserve room for the block's own commit certificate | not yet validated | — |
| [F021](findings/F021-da-response-validity-depends-on-local-checkpoint.md) | Low | Whether a DA challenge response is valid depends on the validator's local boundary checkpoint | not yet validated | — |
| [F022](findings/F022-undecided-value-overwritten-by-unauthenticated-copy.md) | Critical | Any gossip peer can replace the stored body of a proposal that consensus is about to decide | HAS_CAVEATS (0.85) | [poc/F022](poc/F022/) (build-backed, 7/7) |
| [F023](findings/F023-unauthenticated-proposals-persisted-and-executed.md) | Medium | Every `FullProposal` for heights `next` and `next+1` from any peer is kept in memory and in RocksDB, with no count or byte limit | not yet validated | — |
| [F024](findings/F024-unbounded-validator-inflow-halts-or-captures-next-set.md) | High | Unbounded validator inflow in one epoch halts shard 0 or captures its next validator set | HAS_CAVEATS (0.75) | [poc/F024](poc/F024/) (build-backed, 6/6) |
| [F025](findings/F025-auto-deregistration-cancelled-by-bare-reregistration.md) | Medium | A validator that never proposes can cancel its own auto-deregistration with nothing more than a signed re-registration | not yet validated | — |
| [F026](findings/F026-validator-registry-spec-divergences.md) | Low | Validator registry rules differ from FIP §4.1/§4.5/§4.6/§4.8 in several places: who may deregister, multiple seats per FID, `INACTIVE` | not yet validated | — |
| [F027](findings/F027-genesis-snapshot-blake3-sync-trie-unverified-but-consensus-relevant.md) | Medium | The genesis-snapshot install checks the Keccak root and walks the stores, but it never checks the BLAKE3 sync trie | not yet validated | — |
| [F028](findings/F028-genesis-validators-hash-check-fails-open.md) | Low | When the release has no `GENESIS_VALIDATORS_HASH`, the check of the genesis validator file only logs a warning, and in this PR the constant | not yet validated | — |
| [F029](findings/F029-shard0-proposer-order-uses-stale-v1-seed-cache.md) | Medium | Shard 0 picks its Malachite proposers with the v1 fallback seed, while the state uses the beacon seed | not yet validated | — |
| [F030](findings/F030-submit-endpoint-unbounded-body-no-rate-limit.md) | Medium | The Hypersnap submit endpoint (`submit_address`, `POST /v1/submitMessage`) reads the whole request body into memory with no size limit | not yet validated | — |
| [F031](findings/F031-withheld.md) | High | Reported privately to the Hypersnap team and to Farcaster/Snapchain (affects upstream). Details will be added after coordinated disclosure. | — | — |
| [F032](findings/F032-bulk-submit-blocks-runtime-under-shard0-simulate-mutex.md) | Medium | `SubmitBulkMessages` counts as one request for the per-IP limiter, yet carries about 25k messages in 4 MiB | not yet validated | — |
| [F033](findings/F033-read-node-commits-not-bound-to-decided-value.md) | High | The read-node path checks that a decided value's `Commits` carry a valid quorum, but never checks that those commits are for that value | HAS_CAVEATS (0.8) | [poc/F033](poc/F033/) (build-backed, 4/4) |
| [F034](findings/F034-falcon-vote-digest-binds-value-shard-not-vote-shard.md) | Medium | A Falcon-512 vote signs `vote_digest(type, value.shard_index, height.block_number, round, hash)` | not yet validated | — |
| [F035](findings/F035-withheld.md) | Medium | Reported privately to the Hypersnap team and to Farcaster/Snapchain (affects upstream). Details will be added after coordinated disclosure. | — | — |
| [F036](findings/F036-withheld.md) | High | Reported privately to the Hypersnap team and to Farcaster/Snapchain (affects upstream). Details will be added after coordinated disclosure. | — | — |
| [F037](findings/F037-sync-response-cap-left-at-512mib-with-30s-timeout.md) | Low | The Hypersnap sync behaviour keeps Malachite's default `max_response_size` of 512 MiB, which is about 30 times the largest valid response | not yet validated | — |
| [F038](findings/F038-contact-info-sender-bound-to-forwarder-not-author.md) | Low | `handle_contact_info` binds the inner `ContactInfoBody.peer_id` to `propagation_source`, the mesh neighbour that forwarded the gossip | not yet validated | — |
| [F039](findings/F039-membership-topic-spec-divergences.md) | Low | The `membership` topic diverges from FIP §4.6/§4.10 | not yet validated | — |
| [F040](findings/F040-verify-signatures-counts-duplicate-signers-toward-quorum.md) | Medium | `verify_signatures` counts duplicate signers toward the quorum | HAS_CAVEATS (0.85) | [poc/F040](poc/F040/) (build-backed, 5/5) |
| [F041](findings/F041-withheld.md) | High | Reported privately to the Hypersnap team and to Farcaster/Snapchain (affects upstream). Details will be added after coordinated disclosure. | — | — |
| [F042](findings/F042-data-less-message-panics-data-shard-replay-sort.md) | Critical | A proposed data-shard block whose transaction holds two `Message`s with `data = None` panics every node that executes it | HAS_CAVEATS (0.8) | [poc/F042](poc/F042/) (build-backed, 6/6) |
| [F043](findings/F043-custody-key-remove-of-migrated-pair-never-reaches-snapchain.md) | Medium | A custody `KEY_REMOVE` of a migrated FID can never be relayed to snapchain | not yet validated | — |
| [F044](findings/F044-signer-ttl-not-enforced-on-shard0.md) | Low | Shard 0 never enforces a signer's `ttl` | not yet validated | — |
| [F045](findings/F045-scoring-thread-stalls-forever-on-a-missing-checkpoint.md) | Medium | The scoring thread scores epochs strictly in order, starting at epoch 1, and never skips one | not yet validated | — |
| [F046](findings/F046-signer-auth-index-node-local-feeds-genesis-trust-and-scoring.md) | High | A node-local signer index (prefix 83, outside every state root) feeds the genesis trust snapshot and every ScoringResult, so honest nodes | HAS_CAVEATS (0.75) | [poc/F046](poc/F046/) (build-backed, 5/5) |
| [F047](findings/F047-fee-gate-runs-after-store-merge-unpaid-messages-persist.md) | Low | After the pivot, the data-shard fee gate (`replica::charge_fee`) runs after the store merge has written to the block batch | HAS_CAVEATS (0.8) | source-only |
| [F048](findings/F048-custody-migration-races-pending-optimism-transfer.md) | Medium | `CUSTODY_MIGRATION` checks the EIP-712 signature against the classical custody that shard 0 has applied so far, not the custody on Optimism | not yet validated | — |
| [F049](findings/F049-da-pool-never-minted-pivot-height-left-at-default.md) | High | The node scores DA-PoW against a boundary height computed with `PIVOT_HEIGHT_0 = 0`, because `params_for` keeps the PoQ default | HAS_CAVEATS (0.9) | [poc/F049](poc/F049/) (build-backed, 4/4) |
| [F050](findings/F050-retro-minted-placeholder-and-emission-curve-diverge-from-fip9.md) | Medium | The emission schedule implements a different monetary policy from FIP §9 | not yet validated | — |
| [F051](findings/F051-retro-reference-implementation-not-reproducible-no-link-to-lock-tree.md) | Low | The retroactive "reference implementation" named by FIP §10.5 (`src/bin/retro_rewards_finalize.rs`) breaks every determinism rule that | not yet validated | — |
| [F052](findings/F052-miniapp-add-remove-churn-unbounded-app-pow-weight.md) | High | The per-epoch miniapp-add counter goes up on every `MINIAPP_ADD` and never goes down on `MINIAPP_REMOVE`, and nothing caps it per epoch | HAS_CAVEATS (0.85) | [poc/F052](poc/F052/) (build-backed, 5/5) |
| [F053](findings/F053-app-pow-credibility-floor-pays-zero-trust-sybils.md) | Medium | App PoW weighs each user by the full §8.4 credibility scalar, not by the FIP §7.1 `w_user = trust × age_factor` | not yet validated | — |
| [F054](findings/F054-fee-discount-waives-non-cast-fees-and-near-dup-check-evadable.md) | Low | The §12 fee discount is `max(trust, uniqueness)`, and every message class other than `CastAdd` gets `uniqueness = 1.0` | not yet validated | — |
| [F055](findings/F055-build-metrics-linear-fid-scan-per-edge-quadratic-scoring.md) | High | build_metrics does a linear scan over every FID per first-30-day engagement edge, so about 1M planted edges push scoring past its 60-minute | HAS_CAVEATS (0.75) | [poc/F055](poc/F055/) (build-backed) |
| [F056](findings/F056-poq-scoring-diverges-from-fip-sections-6-8.md) | Low | The consensus PoQ pipeline diverges from the in-repo FIP §6/§8 in several security-relevant places | not yet validated | — |
| [F057](findings/F057-seed-beacon-free-last-revealer-withholding-bias.md) | Low | The commit-reveal seed beacon lets every committed validator choose, after seeing all honest reveals, whether to reveal | not yet validated | — |
| [F058](findings/F058-da-latency-score-set-by-window-proposers.md) | Low | A validator's DA latency score is the height of the block that includes its response, which the shard-0 proposers choose, not the time the | not yet validated | — |
| [F059](findings/F059-poq-post-transfer-filter-missing-on-production-reader.md) | Medium | The FIP §8.1 post-transfer filter is not applied anywhere on the production PoQ path | not yet validated | — |
| [F060](findings/F060-app-receipts-signable-by-app-held-signers-without-user-action.md) | Medium | App-usage receipts can be signed by app-held signers with no user action, so a client holding users' signers can farm the AppUsage pool | not yet validated | — |
| [F061](findings/F061-outbound-bridge-activation-epoch-never-on-mainnet.md) | Medium | `Shard0Params::new` sets `bridge_outbound_activation_epoch = u64::MAX` on every network, and nothing on the production path changes it | not yet validated | — |
| [F062](findings/F062-validator-without-optimism-rpc-rejects-every-onchain-event-block.md) | Medium | A voting validator with the default empty `[onchain_events] rpc_url` has no Optimism view, so it prevotes nil on every shard-0 block that | not yet validated | — |
| [F063](findings/F063-genesis-all-or-nothing-over-fork-time-dependent-entry-checks.md) | Low | Genesis is all-or-nothing over entries checked at the fork timestamp, so one stale validator entry aborts the pivot on every node | not yet validated | — |
| [F064](findings/F064-native-rotate-then-replay-onboard-mints-unbounded-fids-one-pow.md) | Medium | A native custody rotation deletes the custody→FID index, and that index is the only replay guard on `NATIVE_ONBOARD` | not yet validated | — |
| [F065](findings/F065-native-custody-rotation-rejected-at-mempool-admission.md) | Low | NATIVE_CUSTODY_ROTATION is rejected at mempool admission, so native FIDs cannot rotate custody through the mempool | not yet validated | — |
| [F066](findings/F066-v1-proposeupgrade-not-pause-gated.md) | Informational | V1 `proposeUpgrade` is not `whenNotPaused` | not yet validated | — |
| [F067](findings/F067-stage-block-error-logged-then-batch-committed.md) | Informational | `BlockEngine::commit_block` and `ShardEngine::commit_and_emit_events` log a `stage_block` / `stage_shard_chunk` error and then commit the | not yet validated | — |
| [F068](findings/F068-data-shard-commit-persists-state-before-root-check.md) | Low | On shards 1 and 2, `ShardBlockProducer::commit` compares the Keccak root with the certified header's `state_root` only **after** | not yet validated | — |
| [F069](findings/F069-validator-reconnect-resub-flushes-every-topic-mesh.md) | Low | Every time a configured validator's PeerId opens a connection, the node runs `unsubscribe` + `subscribe` on all of its topics (at most once | not yet validated | — |
| [F070](findings/F070-native-onboard-falcon-key-not-bound-by-custody-signature.md) | Medium | The custody signature of `NATIVE_ONBOARD` does not cover `falcon_custody_key` or `falcon_recovery_key` | not yet validated | — |
| [F071](findings/F071-onboarding-stake-lock-consumable-by-any-custody.md) | Low | An onboarding stake lock records only its sponsor, and `onboard` never asks the sponsor to approve the custody that uses it | not yet validated | — |
| [F072](findings/F072-unsigned-message-identity-malleable-ecdsa-and-data-bytes.md) | Informational | FID-0 (`SIGNATURE_SCHEME_NONE`) messages are malleable by third parties | not yet validated | — |
| [F073](findings/F073-relay-rate-limited-message-stalls-shard-worker.md) | Medium | One rate-limited message stalls a relay shard worker for about 14 minutes, delaying signer removals on the other network | not yet validated | — |
| [F074](findings/F074-relay-deferred-queue-full-turns-deferrals-into-permanent-drops.md) | Low | When the relay deferred queue is full, deferrals become permanent drops and those messages are never relayed | not yet validated | — |
| [F075](findings/F075-withheld.md) | Low | Reported privately to the Hypersnap team and to Farcaster/Snapchain (affects upstream). Details will be added after coordinated disclosure. | — | — |
| [F076](findings/F076-shard0-miniapp-messages-replayable-no-nonce-or-seen-index.md) | Medium | Shard-0 miniapp messages have no replay guard: anyone can re-submit a captured MINIAPP_ADD / REMOVE / REGISTER / UNREGISTER for as long as | not yet validated | — |

## How to run the PoCs

Every PoC folder has a README with the exact file placement, command and expected output. The common setup:

**Rust PoCs** (F018, F019, F022, F024, F033, F040, F042, F046, F049, F052, F055)

1. Make a build tree from the audited commit: `git archive 7eb981b | tar -x -C <build-tree>`.
2. Put a Malachite checkout next to it as `../malachite` (the workspace uses path dependencies `../malachite/code/crates/*`), at the rev Hypersnap pins (`13bca14c`).
3. Copy the PoC's `*_poc_test.rs` to the path given in its README and add the `#[cfg(test)] mod ...;` line it names (F055 is a crate integration test and needs no wiring; `run_f055.sh` does the copy).
4. Run the README's command, for example `RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f022 -- --nocapture --test-threads=1`.

The runs were done on WSL2 Ubuntu with `rustc 1.95.0`. `--cap-lints allow` works around a rustc 1.95.0 lint ICE in `informalsystems-malachitebft-wal` and has nothing to do with the findings. F055 uses the release profile, as its README says.

**Foundry PoCs** (F004, F005, and `poc/H011` for F014)

1. `git archive 7eb981b contracts | tar -x -C <scratch>`, then add OpenZeppelin contracts and contracts-upgradeable v5.1.0 and forge-std under `contracts/lib/` (the remappings in `contracts/foundry.toml`).
2. Copy the PoC's `.t.sol` into `contracts/test/` and run `forge test --match-contract <name> -vv` (forge 1.2.3, solc 0.8.24).

None of the PoCs changes production code. Each README lists what the test exercises with real code and what is source-reasoned only.

## Methodology

1. Recon: top-down read of the PR diff and the FIP, an architecture map, and an attack-surface list that seeded hunt tasks per specialist.
2. Hunt: specialist agents worked the tasks against the pinned commit and filed findings with file:line traces, an attacker model and a red-team section.
3. Validate: a separate validator agent, with no stake in the finding, tried to invalidate the Critical, High and selected Medium findings against 8 explicit hypotheses and recalibrated severity.
4. PoC: every Critical and High finding (and several others) got a test against the pinned commit, with negative controls where they were useful.
5. Gap-fill and dedupe: uncovered files and cross-cutting themes got extra hunts, and related findings are linked (`related_findings`) rather than merged.

Some finding bodies mention hunt task IDs (`H0xx`), internal validation notes or exploratory harnesses under `poc/H0xx/`. Those are not published here; the PoCs listed in the index are the ones to run.
