# hypersnap — Condensed Audit Report (Critical & High, verified)

**Audited commit:** `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
**Audited branch:** `pow` — PR #34 "proof of work (restored)"
**Repository:** https://github.com/farcasterorg/hypersnap
**Pipeline:** audit-suite + audit-suite-brain @ `b2c8f8bade0b`
**Scope of this document:** the **13 Critical/High findings that survived adversarial validation** (verdict ≠ INVALIDATED) and are rooted in code PR #34 introduced. For the full set (23 findings incl. Medium/Low and the 1 invalidated), see [REPORT.md](REPORT.md); per-finding reachability traces are in [`traces/`](traces/).

## Revalidation verdict (prior audit, base `cab225f`)
- **Prior F001 (Critical — unsigned slashing evidence): FIXED.** `verify_evidence_signatures` now gates evidence ingestion; no bypass path found.
- **Prior F002 (High — lock admission skips verification): NOT fully fixed** → re-surfaces here as **F035**.

## Fix status — fix commit `5c25945` ("audit fixes", 2026-06-12)

Overlay over the 13 Critical/High below, revalidated against [`5c25945`](https://github.com/farcasterorg/hypersnap/commit/5c2594563df84c374fdce7cdeae06d3444da3b72) (direct child of `cab225f`). Full report: [REVALIDATION-5c25945.md](REVALIDATION-5c25945.md). Per-finding bodies below are **unchanged** and reflect the original OPEN state at `cab225f`.

| ID | Sev | Fix status | Residual (if any) |
|----|-----|-----------|-------------------|
| F028 | Critical | ✅ **FIXED** | BFT-safe `floor(2n/3)+1` derived in `build_driver`; static `=1` ignored for real sets |
| F070 | High | ✅ **FIXED** | Production router now `.with_custody_resolver(...)`; lenient `None` branch unreachable |
| F013 | High | ✅ **FIXED** | `height`/`round` None-guarded on the gossip decode arm |
| F016 | High | ✅ **FIXED** | `PENDING_DKLS_INBOUND_EPOCH_CAP=16` + eldest-epoch eviction |
| F024 | High | ✅ **FIXED** | `propagation_source` preserved + re-checked on drain (all 3 submit sites) |
| F025 | High | ✅ **FIXED** | Keccak permutation over `(epoch,set_hash,key)` replaces lexicographic index map (grind now hard, not free) |
| F035 | High | ✅ **FIXED** | Transparent-lock path rejected at ingress **and** block-import chokepoint (`importer.rs:269`) |
| F012 | High | ✅ **FIXED** | `hash==blake3(header)` re-derived + enforced on proposer + read-validator paths |
| F009 | High | ✅ **FIXED** | Conflict now keyed on signature-free `hyper_block_content_hash` |
| **F049** | High | ⚠️ **PARTIAL** | Rust honest-signer cap only; **contract has no `blockNumber` bound** → Byzantine-signer brick + `executeUpgrade` theft still open |
| **F002** | High | ⚠️ **PARTIAL** | INTERSECTION fix closes false-slash, but `slashed_validators_for_epoch`↔`get_active_validators_enforced` **self-recursion chain-halt remains** (one evidence row) |
| **F045** | High | ❌ **NOT FIXED** | `HypersnapBridge.sol` untouched; no chainId/address binding on universal digests |
| **F047** | High | ❌ **NOT FIXED** | `rotateOwner` still on shared watermark; public front-run primitive intact |

**Critical closed; 9/13 crit-high fixed.** Headline residual: the Solidity bridge contract was **not modified at all** (F045/F047 not fixed, F049 partial, Medium F048 not fixed), and F002 still carries a one-row chain-halt DoS. **Re-report set:** F002, F045, F047, F048, F049.

## Summary table

| ID | Sev | Verdict (conf) | Reachability | Title |
|----|-----|----------------|--------------|-------|
| **[F028](findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md)** | Critical | WATERPROOF (0.90) | LOCAL-CONFIG (default-on) → COMMITTEE-MEMBER | DKLS threshold hard-pinned to 1 → one validator forges group authority |
| **[F070](findings/F070-custody-sig-gate-unwired-in-production-router.md)** | High | WATERPROOF (0.90) | REMOTE-UNAUTH | Validator-registration custody gate unwired; any peer registers a validator key under any FID |
| **[F013](findings/F013-fullproposal-missing-height-unwrap-panic-on-gossip.md)** | High | WATERPROOF (0.92) | REMOTE-AUTHED-PEER | `FullProposal.height().unwrap()` panics the node on a height-less gossip frame |
| **[F016](findings/F016-pending-dkls-inbound-unbounded-epoch-keys.md)** | High | WATERPROOF (0.90) | REMOTE-UNAUTH | Unbounded `pending_dkls_inbound` epoch buffer → memory-exhaustion DoS |
| **[F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md)** | High | WATERPROOF (0.88) | REACHABLE (signer-compromise model) | Max-block watermark saturation bricks rotate/cancel while `executeUpgrade` still fires |
| **[F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md)** | High | HAS_CAVEATS (0.85) | RELAYER-ANY / OWNER-KEY | Universal control-plane sigs replay onto watermark-lagging deployments |
| **[F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md)** | High | HAS_CAVEATS (0.85) | REACHABLE (compromised old owner) | Owner-rotation front-run defeats key-compromise recovery |
| **[F024](findings/F024-buffered-dkls-dkg-drain-skips-sender-authentication.md)** | High | HAS_CAVEATS (0.84) | REACHABLE (bounded → liveness) | Buffered DKG drain skips [F018](findings/F018-dkls-signer-share-keystore-never-pruned-at-epoch-boundary.md) sender auth (broadcast-sender spoofing) |
| **[F025](findings/F025-committee-index-grinding-via-attacker-chosen-validator-key.md)** | High | HAS_CAVEATS (0.78) | REMOTE-UNAUTH | Committee membership grindable via attacker-chosen `validator_key` |
| **[F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md)** | High | HAS_CAVEATS (0.72) | REMOTE-AUTHED-PEER (needs epoch-B sig) | Cross-epoch evidence slashes innocent single-epoch signers |
| **[F035](findings/F035-hyperlockevent-mint-without-balance-closure.md)** | High | HAS_CAVEATS (0.70) | VALIDATOR(PROPOSER) | `HyperLockEvent` mints arbitrary value into signed verkle root, no balance closure |
| **[F012](findings/F012-block-hash-never-rederived-from-header-decouples-signed-value-from-committed-content.md)** | High | HAS_CAVEATS (0.60) | REACHABLE (constrained) | Signed block `hash` never re-derived from header → committed content unbound |
| **[F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md)** | High | HAS_CAVEATS (0.60) | LATENT / unproven in-tree | Slashing predicate keys conflict on signature-inclusive hash |

**Linked clusters (related-but-distinct):** bridge-watermark — F045 / F047 / F049 (and Medium F048); slashing-false-positive — F002 / F009 (and Medium F015).

---

## F028 — DKLS threshold hard-pinned to 1 *(Critical, WATERPROOF 0.90)*
**Files:** `src/main.rs`, `src/hyper/dkls_supervisor.rs`, `src/hyper/dkls_committee.rs`, `crates/hypersnap-crypto/src/dkls_threshold.rs`, `src/hyper/actor.rs`
**Reachability:** LOCAL-CONFIG (default-ON, `main.rs:1603 let dkls_threshold = 1u8;`) → exploited by any COMMITTEE-MEMBER.

The DKLS23 reconstruction threshold is taken verbatim from a static config field, never validated against active-set size, never floored to a BFT-safe value, and hard-coded to `1` on the production bootstrap path. The verifier (`sig_verify.rs`) only recovers the group address — there is no `signer_indices ≥ quorum` check anywhere — so a single committee-elected validator unilaterally produces the group threshold signature over hyperblocks, reward issuances, and bridge authorizations.

**Fix:** derive `threshold` from active-set size with a BFT-safe floor at `build_driver` time (e.g. `floor(2·n/3)+1`); reject construction when `threshold < 2` for non-devnet (`share_count > 1`) sets; treat the static `dkls_threshold = 1u8` as a hard error in that regime.

## F070 — Validator-registration custody gate unwired *(High, WATERPROOF 0.90)*
**Files:** `src/hyper/validator_registry.rs`, `src/hyper/router.rs`, `src/hyper/runtime.rs`, `src/hyper/importer.rs`, `src/hyper/config.rs`
**Reachability:** REMOTE-UNAUTH — a single crafted gossip `ValidatorEvent` (`actor.rs:1218` → `runtime.submit_message` → `router.rs:167`).

`validator_registry.rs` implements a correct, well-tested EIP-712 custody cross-signature gate — but it is **never reached in production**. `HyperRuntime::submit_message` builds the `HyperRouter` **without** `with_custody_resolver(...)`, so `route_inbound` takes the lenient `validate_event(.., None)` branch that skips the custody check; the strict `validate_and_check_quota` / `apply_validator_events` path is dead code (tests only), and the only other gate (`min_validator_trust_score`) defaults to `0.0`. Any peer can register an arbitrary validator key under any FID. **Composes directly with F025 (grind into committee) and F028 (threshold=1) into an unauthenticated → full-control chain.**

**Fix:** wire a real `CustodyResolver` into the production router so the strict EIP-712 custody-signature path runs on every `ValidatorEvent`; make the `None` (lenient) branch a hard error outside devnet.

## F013 — `FullProposal.height().unwrap()` remote crash *(High, WATERPROOF 0.92)*
**Files:** `src/network/gossip.rs`, `proto/src/lib.rs`, `proto/definitions/blocks.proto`
**Reachability:** REMOTE-AUTHED-PEER — any mesh peer with a valid libp2p identity.

On the gossip decode path, the `GossipMessage::FullProposal` arm calls `full_proposal.height()` (= `self.height.clone().unwrap()`) on a fully attacker-controlled prost message *before* the fallible `shard_id()` guard. In proto3 `height` is `Option<Height>`, so a peer can omit it; the `.unwrap()` panics and aborts the node. (The sibling `StatusMessage.height` is correctly `None`-guarded — this arm simply missed it.)

**Fix:** guard `full_proposal.height` (`match … { Some(h) => …, None => return None }`) before any use; drop the frame on `None`. Also fix the next reachable unwrap, `round()` (`proto/src/lib.rs:189`).

## F016 — Unbounded pre-StartDkls buffer *(High, WATERPROOF 0.90)*
**Files:** `src/hyper/actor.rs`, `src/hyper/gossip_adapter.rs`, `src/hyper/dkls_supervisor.rs`
**Reachability:** REMOTE-UNAUTH — any peer on the public `hyper/dkg/v1` topic.

The F023a fix buffers pre-`StartDkls` `InboundDkls` messages in `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>` keyed by an attacker-controlled `target_epoch`, with no authentication and no global cap or stale-epoch eviction. An attacker allocates unbounded per-epoch buffers that are never drained → memory-exhaustion DoS on every node on the topic.

**Fix:** bound `target_epoch` to a small window around the current epoch; cap total buffered epochs and evict stale/far-future ones; reject frames from non-committee/unauthenticated senders before buffering.

## F049 — Watermark saturation bricks recovery; `executeUpgrade` survives *(High, WATERPROOF 0.88)*
**Files:** `contracts/src/HypersnapBridge.sol`, `crates/hypersnap-crypto/src/bridge_payload.rs` · **Related:** [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md), [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md)
**Reachability:** REACHABLE, conditional on threshold-signer capability (the contract's own key-compromise threat model).

Every universal control-plane ceremony gates on a single shared 64-bit `latestBlock` with `blockNumber > latestBlock` and **no upper bound** (neither in the contract nor `bridge_payload.rs`). A single signature with `blockNumber = type(uint64).max` saturates the watermark, permanently reverting `rotateOwner`/`cancelUpgrade`/`pause`, while the permissionless, watermark-independent `executeUpgrade` still fires the pending implementation → permanent brick + custody theft.

**Fix:** bound accepted `blockNumber` to a sane forward window (`<= latestBlock + MAX_ADVANCE`, or bind to real L1 block height) on every universal entry point and in the Rust digest builders; gate `executeUpgrade` consistently.

## F045 — Universal control-plane signatures replay across deployments *(High, HAS_CAVEATS 0.85)*
**Files:** `contracts/src/HypersnapBridge.sol`, `crates/hypersnap-crypto/src/bridge_payload.rs` · **Related:** [F047](findings/F047-owner-rotation-race-front-run-defeats-key-compromise-recovery.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md), [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md)
**Reachability:** RELAYER-ANY (relay a superseded owner-signed universal payload onto a lagging sibling deployment) / OWNER-KEY (evil-impl variant).

Six payloads (`MERKLE_ROOT_UPDATE`, `OWNER_UPDATE`, `OWNER_ACCEPTANCE`, `UPGRADE`, `UPGRADE_CANCEL`, `PAUSE`) are deliberately universal — no chainId, no contract-address binding — and signed by the same threshold key for relay to every deployment. The only replay defense is the per-deployment monotonic watermark, which cannot reject a superseded universal signature on a watermark-lagging deployment (and deployments even share the same address, so address-binding alone wouldn't disambiguate — chainId binding is required).

**Fix:** bind every universal control-plane digest to deployment identity (chainId + deployment id/nonce) so a signature is no longer replayable across deployments.

## F047 — Owner-rotation front-run defeats key-compromise recovery *(High, HAS_CAVEATS 0.85)*
**Files:** `contracts/src/HypersnapBridge.sol`, `crates/hypersnap-crypto/src/bridge_payload.rs`, `src/hyper/runtime.rs` · **Related:** [F045](findings/F045-universal-control-sig-replay-on-lagging-deployments.md), [F048](findings/F048-pause-does-not-gate-proposeupgrade-late-propose-erases-lockout-window.md), [F049](findings/F049-watermark-saturation-bricks-rotate-and-cancel-while-execute-upgrade-survives.md)
**Reachability:** REACHABLE — a compromised old-owner (O1) key holder.

`rotateOwner` is a one-shot rotation gated solely by the shared monotonic watermark, sharing that namespace with `pause`/`proposeUpgrade`/`cancelUpgrade`/`claim`/`recoverERC20`, with **no priority**, and digests are public the moment a rotation tx enters the mempool. A compromised old owner front-runs the recovery `rotateOwner(N)` (any higher-watermark action triggers `StaleBlock` revert of the victim's rotation) to retain power, or rotates ownership to an attacker EOA — defeating the documented "immediate rotation" recovery.

**Fix:** give rotation a watermark namespace/priority that other consumers cannot starve, and remove the public front-run primitive (e.g. commit-reveal or a dedicated rotation counter).

## F024 — Buffered DKG drain skips sender authentication *(High, HAS_CAVEATS 0.84)*
**Files:** `src/hyper/actor.rs`, `src/hyper/dkls_wire_codec.rs`, `crates/hypersnap-crypto/src/dkls_ceremony.rs`
**Reachability:** REACHABLE but bounded — impact is liveness/blame (DKLS `sign_id` converts forgery to abort), not key compromise.

DKG broadcast messages carry an unauthenticated `sender: u8` party index. The F018 authentication (`check_dkls_sender_against_propagation_source`) binds it to the gossipsub originator — but the pre-`StartDkls` buffer discards `propagation_source`, and the drain (`actor.rs:1444`) submits buffered frames to the ceremony **without** re-running that check, enabling broadcast-sender spoofing. Distinct from F016 (buffer growth) and F021 (fail-open on empty peer-id).

**Fix:** preserve `propagation_source` in each buffer entry and re-apply `check_dkls_sender_against_propagation_source` on the drain path before feeding the ceremony.

## F025 — Committee membership grindable via chosen `validator_key` *(High, HAS_CAVEATS 0.78)*
**Files:** `src/hyper/dkls_committee.rs`, `src/hyper/dkls_supervisor.rs`, `src/hyper/validator_registry.rs`, `src/hyper/actor.rs`
**Reachability:** REMOTE-UNAUTH registration (rides F070), composing into deterministic committee capture.

Committee selection ranks party indices `1..=share_count`, and the index→validator mapping is just the lexicographic (BTreeMap) sort order of the freely-chosen 32-byte Ed25519 `validator_key`s. The F036 fix made the *seed* non-grindable, but the seed is deterministic and known far ahead, so an attacker grinds a keypair that sorts into a winning index slot for a target epoch. **Caveat:** under the shipped threshold=1 (F028) this buys deterministic targeting of the lone signer rather than a first break of threshold security; severity is fully realized once threshold > 1.

**Fix:** assign party indices via a non-grindable function (e.g. `hash(seed ‖ validator_key)`), require proof-of-possession + stake binding at registration, and raise the threshold (F028).

## F002 — Cross-epoch evidence slashes innocent single-epoch signers *(High, HAS_CAVEATS 0.72)*
**Files:** `src/hyper/slashing.rs`, `src/hyper/runtime.rs`, `src/hyper/actor.rs`, `src/hyper/slashing_store.rs` · **Related:** [F009](findings/F009-slashing-predicate-flags-benign-resign-as-doublesign.md), [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md)
**Reachability:** REMOTE-AUTHED-PEER for ingress, but the sink requires presenting a valid epoch-B committee threshold signature (collusion/quorum control).

The F026 cross-epoch path accepts two same-`canonical_block_id` blocks with different epoch tags as one "equivocation" and slashes the **union** of both blocks' signer sets (each resolved against its own epoch's active set). A validator who legitimately signed only one of the two epochs is evicted for the other committee's block. *(Validator note: the literal cross-epoch case can also manifest as a `slashed_validators_for_epoch` ↔ `get_active_validators_enforced` self-recursion / chain-halt rather than silent eviction.)*

**Fix:** restrict the penalized set to the **intersection** of the two blocks' resolved signers (validators who signed *both*); fix the recursion in the enforcement reader.

## F035 — `HyperLockEvent` mints into signed verkle root without balance closure *(High, HAS_CAVEATS 0.70)*
**Files:** `src/hyper/lock_event.rs`, `src/hyper/builder.rs`, `src/hyper/importer.rs`, `src/hyper/runtime.rs`, `src/hyper/mempool.rs`
**Reachability:** VALIDATOR(PROPOSER) — proposer-inserted `locks_in_block` (`gossip_adapter.rs:75`) reach `insert_lock_into_tree` with no re-validation (unlike transfers).

This is the **incomplete fix for prior F002.** The `HyperLockEvent` pipeline writes a caller-supplied plaintext `amount` straight into a verkle leaf with no Pedersen balance closure, no range proof, and no `lock_signature` check; the verkle root is then threshold-signed and posted as the cross-chain `hyper_state_root`. **Caveat:** the in-scope L1 `claim` consumes the balance-validated *merkle* root (from the confidential path), not this verkle root — so the live in-scope impact is threshold-signed state-root corruption / a latent mint primitive, not a demonstrated L1 drain.

**Fix:** remove the transparent-lock state-change path (mempool/HTTP ingress is already sealed by F058), OR require every applied `HyperLockEvent` to carry and pass the same balance-closure/range-proof/signature enforcement as confidential locks.

## F012 — Signed block `hash` never re-derived from header *(High, HAS_CAVEATS 0.60)*
**Files:** `src/consensus/proposer.rs`, `src/consensus/validator.rs`, `src/consensus/read_validator.rs`, `src/core/util.rs`
**Reachability:** REACHABLE but constrained.

Precommit signatures are computed over `ShardHash{ shard_index, hash }` only; no validate/commit/read path re-derives `hash` from `blake3(header)`. The state-root replay on the read-node commit path narrows the *body*, but not the *header* binding — so an attacker can finalize a replay-valid alternate `(header, body)` pair with `hash` set to the honest signed value and the honest Commits re-embedded, on a path validators never signed.

**Fix:** re-derive and enforce `hash == blake3(header)` on every receive path that consumes it as identity — reject the proposal/decided value otherwise.

## F009 — Slashing predicate keys conflict on signature-inclusive hash *(High, HAS_CAVEATS 0.60)*
**Files:** `src/hyper/slashing.rs`, `src/hyper/chain.rs`, `src/hyper/mod.rs`, `src/hyper/actor.rs`, `src/hyper/runtime.rs`, `src/hyper/dkls_sign_driver.rs` · **Related:** [F002](findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md), [F015](findings/F015-slashing-store-encode-block-drops-signed-fields.md)
**Reachability:** gate path is REMOTE-UNAUTH, **but harm is LATENT / precondition UNPROVEN in-tree** — no in-tree producer emits two distinct valid signatures over one `signing_payload` (recovery-id collision is ~2⁻¹²⁸ not ~50%; the producer is a fixed-cadence round-0 single proposer).

`detect_conflicting_blocks` declares a conflict whenever `hyper_block_hash` differs, but that hash mixes the non-deterministic threshold-ECDSA signature bytes, whereas the signed content is `signing_payload` (signature-free). So two valid signatures over identical content *would* be mis-slashed as double-signing — a real predicate defect, currently unreachable for lack of a benign double-signature producer.

**Fix:** define "conflict" on signed content (`signing_payload`), not on the signature-bearing `hyper_block_hash`.

---

*Generated from the audit-suite revalidation of PR #34. Verdicts/confidence are the independent validator's; reachability is from the trace stage ([`traces/`](traces/)). Full report with Medium/Low findings and the invalidated F003: [REPORT.md](REPORT.md).*
