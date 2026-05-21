---
id: F153
task: H153
attack_class: signing-payload-coverage
severity: high
status: draft
---

# F153 — Hyperblock threshold-ECDSA signing payload omits `signer_indices`, `extra_rules_version`, `retained_message_count`, and `envelope.payload`; malleated `signer_indices` in slashing evidence can slash arbitrary validators while still passing `verify_hyperblock_signature`

- **Task:** H153
- **Attack class:** `signing-payload-coverage`
- **Severity (provisional):** High. A peer who captures (or causes the production of) two threshold-signed conflicting `HyperBlock`s at the same height can re-broadcast both with their `signature.signer_indices` field overwritten with any arbitrary 1-based validator-index list. The signature still verifies — `signer_indices` is not part of `HyperBlockMetadata::signing_payload` — and `apply_evidence` persists the modified blocks verbatim. At the next epoch boundary, `slashed_validators_for_epoch` reads `signer_indices` from the persisted evidence and slashes every named index regardless of who actually signed. The same omission is exploitable on the much-easier "two conflicting blocks produced by a colluding 1-of-1 devnet share" path. Additional malleability vectors (same root cause) — `extra_rules_version`, `retained_message_count`, `envelope.payload` — are signed-free but flow into `hyper_block_hash`, producing forked block hashes for the same threshold-signed metadata and giving the same signature multiple distinct block-hash identities.
- **Status:** draft

## Scope files (primary)

- `code/hypersnap/src/hyper/sig_verify.rs:84-91` — `verify_hyperblock_signature` verifies the caller-supplied payload bytes; no opinion on which `HyperBlock` fields belong in those bytes.
- `code/hypersnap/src/hyper/mod.rs:397-428` — `HyperBlockMetadata::signing_payload`. **The authoritative list of fields the threshold committee actually signs over.** Compare to the consumer paths below for what gets trusted post-verify.
- `code/hypersnap/src/hyper/mod.rs:368-381` — `HyperBlockSignature` struct: `epoch`, `signer_indices`, `group_address`, `ecdsa_signature`. Only `epoch` flows into `signing_payload`; `signer_indices` and `group_address` do not.
- `code/hypersnap/src/hyper/mod.rs:291-328` — `HyperBlockMetadata` struct: nine fields. **`extra_rules_version` and `retained_message_count` are omitted from `signing_payload` but included in `hyper_block_hash` (`chain.rs:25-44`)**.
- `code/hypersnap/src/hyper/chain.rs:25-44` — `hyper_block_hash`. Hashes `extra_rules_version`, `retained_message_count`, `signature.epoch`, `signature.group_address`, `signature.ecdsa_signature` — all of which are NOT in the signed payload. The block hash thus depends on attacker-controllable bits when the metadata is held constant.

## Scope files (consumer paths that trust the malleable fields)

- `code/hypersnap/src/hyper/slashing.rs:89-108` — `verify_evidence_signatures` is the documented gate against unauthenticated slashing evidence. The doc-comment at lines 85-88 says it stops "any peer can publish two unsigned blocks naming arbitrary `signer_indices` and slash arbitrary validators at the next epoch boundary". The gate calls `verify_hyperblock_signature(&payload, &block.signature.ecdsa_signature, …)` with `payload = signing_payload(epoch)` — which **does not cover `signer_indices`**. So the documented threat model is half-blocked.
- `code/hypersnap/src/hyper/runtime.rs:3917-3961` — `slashed_validators_for_epoch`. Iterates persisted evidence and, for each block, reads `block.signature.signer_indices` directly to compute the slashed set. No re-check against the signing-payload coverage.
- `code/hypersnap/src/hyper/importer.rs:209-224` — score-tracker path. After signature verification, reads `block.signature.signer_indices` to call `tracker.record_commit_signature(epoch, signer)` per index. The names credited are attacker-controlled if the block has been malleated.
- `code/hypersnap/src/hyper/actor.rs:4031-4097` — regression test `inbound_evidence_rejects_unsigned_blocks` proves the developers identified the threat: "any gossip peer could publish two unsigned blocks naming arbitrary `signer_indices` and slash arbitrary validators". The fix added a gate (`verify_evidence_signatures`) that demands a valid threshold sig. **The fix is incomplete because the sig doesn't cover `signer_indices`.**

## Field-coverage table (signed vs. trusted post-verify)

| Field | In `signing_payload` (committee signs over)? | Used post-verify by? |
|---|---|---|
| `metadata.canonical_block_id` | yes | chain continuity, block index |
| `metadata.parent_hash` | yes (len-prefixed) | chain continuity |
| `metadata.hyper_state_root` | yes (len-prefixed) | verkle root check (`importer.rs:288`) |
| `metadata.missed_proposals[]` | yes | `update_scores_for_missed_proposals` |
| `metadata.snapchain_anchor_block` | yes | anchor binding |
| `metadata.snapchain_anchor_hash` | yes (len-prefixed) | anchor binding |
| `metadata.snapchain_range_start_block` | yes | anchor range |
| `metadata.snapchain_range_root` | yes (len-prefixed) | anchor range |
| `metadata.snapchain_anchor_timestamp` | yes | scoring auto-trigger `now_unix` |
| `signature.epoch` | yes | group-address lookup at verify time |
| **`metadata.extra_rules_version`** | **NO** | `hyper_block_hash` input (`chain.rs:33`), `block_index` persist |
| **`metadata.retained_message_count`** | **NO** | `hyper_block_hash` input (`chain.rs:34`), `block_index` persist |
| **`envelope.payload`** | **NO** | proto encoded with the block, persisted at `block_index.rs:54` / `gossip_adapter.rs:192`. Currently always `Vec::new()` from `builder.rs:267`, but consumers don't enforce that. |
| **`signature.signer_indices`** | **NO** | **scoring (`importer.rs:209-218` → `record_commit_signature`)**, **slashing (`runtime.rs:3948` → `slashed_validators_for_epoch`)**, slashing-store persistence (`slashing_store.rs:185`), http handler output (`http_handler.rs:1380`) |
| `signature.group_address` (declared) | NO (the *expected* group address comes from the runtime registry) | partial check at `sig_verify.rs:59-72` only — when present, must match expected; mismatch is hard-rejected. Not a covered field for malleability purposes. |
| `signature.ecdsa_signature` | n/a (it IS the signature) | the signature itself |

The starred rows are attacker-controllable. The high-impact ones are `signer_indices` (drives slashing + scoring) and the pair `(extra_rules_version, retained_message_count, envelope.payload)` (drive `hyper_block_hash` and thus the chain-id of parent_hash links).

## Why this is `signing-payload-coverage`, not `eip712-domain-or-replay-binding`

H153's scope is whether the verifier covers every field the apply-path then trusts. The omissions are not about cross-chain replay (the chain-id gap is a separate concern, mentioned below); they are about **post-verify malleability**. A field that is read with state-changing effect must be inside the signature, otherwise an attacker can clone-and-modify the in-flight wire bytes.

## Concrete attack scenarios

### Scenario A — slashing arbitrary validators via malleated `signer_indices`

**Setup.** Network is post-cutover. Epoch `E` has an active validator set `{V1, V2, …, V11}` (1-based indices). The threshold committee for `E` includes some subset, e.g., `{V3, V5, V7}` — DKLS23 2-of-3 threshold. The attacker Bob does NOT control any signing share for epoch `E`; he is a regular gossip peer.

**Step 1 — obtain conflicting threshold-signed blocks at the same height.** Bob observes the network (or, in a more aggressive scenario, induces this) and captures two threshold-signed `HyperBlock`s at the same `canonical_block_id` with different `hyper_state_root`s. Sources of such pairs:

- A legitimate fork: two committees signed two different blocks during a partition / view-change race. Both threshold signatures are real.
- Equivocation by the threshold committee itself: a malicious 2-of-3 committee (or, in devnet, a 1-of-1 holder) deliberately signs two blocks at the same height.
- Replayed-from-history: any prior conflicting-block pair the network has ever seen, even one that was already slashed for. Replay protection at `slashing_store` is keyed by evidence digest, not by validator identity — and the digest will differ after Bob's malleation.

For this attack Bob does NOT need to forge a signature. He needs to have a copy of two real ones.

**Step 2 — overwrite `signer_indices`.** Bob takes both blocks and rewrites the `signer_indices` field on each:

```rust
let mut block_a_evil = block_a.clone();
block_a_evil.signature.signer_indices = vec![1, 2, 4, 6, 8, 9, 10, 11];  // every validator Bob wants slashed
let mut block_b_evil = block_b.clone();
block_b_evil.signature.signer_indices = vec![1, 2, 4, 6, 8, 9, 10, 11];

// Both blocks still pass verify_evidence_signatures.
```

Because `signing_payload(epoch)` doesn't include `signer_indices`, the threshold ECDSA still recovers to the correct group address. `verify_hyperblock_signature` returns `Ok(())`.

**Step 3 — gossip the modified evidence.** Bob publishes `HyperActorEvent::InboundEvidence { block_a: block_a_evil, block_b: block_b_evil }`. The actor calls `detect_conflicting_blocks` (which only checks `(height, epoch)` match and `hash_a != hash_b`; both still hold because the `signer_indices` change reflects into `hyper_block_hash` per `chain.rs:38`). It then calls `verify_evidence_signatures(&evidence, &group_address)` — which passes for both blocks because the sig is over the unchanged `signing_payload`. The evidence is persisted at `slashing_store.rs:185` with `signer_indices = vec![1, 2, 4, 6, 8, 9, 10, 11]`.

**Step 4 — slash the named validators.** At epoch boundary `E → E+1`, the supervisor calls `slashed_validators_for_epoch(E, &active_set)`. The code at `runtime.rs:3948` reads `sig.signer_indices` from each persisted evidence block and inserts the matching validator keys into the slashed set. Bob has slashed V1, V2, V4, V6, V8, V9, V10, V11 — none of whom actually signed the conflicting blocks.

**Impact.** The slashed validators are removed from the next epoch's active set. With enough fan-out, Bob can force the active set below threshold, halting the chain. With more surgical targeting, Bob can slash specific honest validators to manipulate committee composition (combine with the committee-selection logic to grind the committee toward a known-colluding subset).

**Effort.** One observation of a real conflict (or one collusion with a 1-of-1 share holder, or one self-equivocation in any 2-of-N where Bob holds ≥1 share). Bob does NOT need to break the threshold.

### Scenario B — chain-split via malleated `extra_rules_version` / `retained_message_count`

`hyper_block_hash` (`chain.rs:25-44`) includes `extra_rules_version`, `retained_message_count`, and the `ecdsa_signature` bytes themselves. None are in the signing payload.

Bob, holding a single threshold-signed block:

1. Produces multiple distinct block hashes by varying `extra_rules_version` and/or `retained_message_count`.
2. Each variant has the same `(epoch, canonical_block_id, parent_hash, hyper_state_root)` — so importer state-root check (`importer.rs:288`) and chain continuity check (`chain.rs:96-110`) BOTH pass.
3. Different peers on the network see different `last_hash` after importing different variants. **Their `parent_hash` for the next block diverges. The chain splits.**

This was discovered by reading `chain.rs:11-15` (the doc comment specifying which fields go into the hash) against `mod.rs:397-428` (the actual signed-over list). The two diverge.

**Caveat:** Most call sites today set `extra_rules_version: 0` and `retained_message_count` is set by the builder (`builder.rs:253`) from the message count. So in practice a relayed honest block has consistent values. The attacker's variant has different values; honest peers run their own builder so the threat is only for pure-relay nodes that import without re-building. Severity here is contingent on which import path the network uses.

### Scenario C — `signature.ecdsa_signature` malleability multiplies (B)

Alloy `PrimitiveSignature::try_from` accepts both `(r, s, v)` and `(r, n-s, v^1)` — high-S is not rejected. So even with `extra_rules_version` / `retained_message_count` held constant, Bob can produce a second `ecdsa_signature` byte string that verifies against the same group address. Combined with `chain.rs:38` (which hashes `signature.ecdsa_signature` into the block hash), one threshold-signed metadata can manifest as TWO distinct block hashes. Same chain-split mechanic as Scenario B, achievable without any change to metadata.

### Scenario D — scoring credit theft via malleated `signer_indices` (lower severity)

In normal import flow (no slashing), the importer credits the listed `signer_indices` with `record_commit_signature` (importer.rs:209-218). Bob takes a real signed block and rewrites `signer_indices` to credit himself (or his collusion partners) instead of the real signers. The block still verifies. The accumulated score over many blocks shifts validator ranking on the FIP §5.4 weighted-score leaderboard — translates into ranked-set inclusion and reward distribution.

This is a strictly weaker attack than slashing (it's a creditor-game, not validator-exclusion), but uses the same root cause.

## Why the existing checks do not close the gap

| Check | What it gates | What it misses |
|---|---|---|
| `verify_hyperblock_signature` (sig_verify.rs:84) | Forged or wrong-key signature | Anything not in `signing_payload(epoch)` |
| `verify_evidence_signatures` (slashing.rs:89) | Unsigned evidence + cross-epoch attribution | `signer_indices` malleability on real-signed evidence |
| Chain `validate` (chain.rs:85-122) | `parent_hash` continuity | Doesn't notice the same threshold-sig yielding two distinct `hyper_block_hash` values |
| Verkle state-root check (importer.rs:288) | Wrong state transition | Doesn't cover signature-side fields or non-state metadata |
| Slashing-store dedup | Same evidence digest twice | Malleated evidence has a fresh digest; dedup doesn't trigger |

## Adjacent observations (not load-bearing but worth flagging)

### O1. `chain_id` is not bound in the hyperblock signing payload

`mod.rs:106-111` documents the protocol-wide invariant — "Embedded in every Ed25519-signed canonical payload (v2 DSTs) so a message signed for chain A cannot replay on chain B." The hyperblock uses **ECDSA**, not Ed25519, and `signing_payload` at lines 397-428 has no `chain_id` byte. Cross-shard replay is not closed by `chain_id`; it relies entirely on per-epoch group addresses diverging between shards. If two hypersnap deployments ever share a bootstrap config or a backed-up DKG state for the same epoch, the same threshold signature is valid on both. This is the F101/F104/F105 antipattern but the cross-shard hazard is gated by group-address divergence rather than left open. Strictly defense-in-depth.

The same is true for `verify_reward_issuance_signature`, `verify_trust_snapshot_signature`, and the bridge-payload signatures (`merkle_root_update`, `owner_update`, `owner_acceptance`, `pause`, `upgrade`, `upgrade_cancel`). Only `da_epoch_seed_signing_payload` (`rewards.rs:672-679`) binds `chain_id`. The bridge-payload set is intentionally universal (per bridge_payload.rs:8-15 documentation) — same sig is relayable to every EVM bridge — so chain-id-binding is a design choice there. But the hypersnap-internal signatures (issuance, trust snapshot, hyperblock, inbound burn) inherit the universality without an explicit decision recorded.

### O2. `EcdsaSignature::from_bytes` does NOT enforce low-S (compounds C)

`hypersnap-crypto/src/ecdsa.rs:62-69` parses via `alloy_primitives::PrimitiveSignature::try_from`. Alloy 0.8.26 does NOT reject high-S in this constructor; `recover_address_from_prehash` (`ecdsa.rs:98-102`) also silently handles both. The doc comment at `ecdsa.rs:27` claims "low-S only" but no code enforces it. So every signed payload has at least TWO valid `ecdsa_signature` byte strings — which by `chain.rs:38` translates into two block-hashes per signed metadata.

For cross-side parity: the EVM bridge (`HypersnapBridge.sol`) uses OZ `ECDSA.recover` which DOES reject high-S (per bridge_payload.rs:30 documentation). So the EVM side is stricter than the Rust side; high-S signatures verify in Rust but get rejected at the contract. The cross-side asymmetry doesn't itself break the bridge but means the Rust-side "valid sig" set is a SUPERSET of the contract-side accepted set. The compounding effect with Scenario C remains: chain-internal `hyper_block_hash` ambiguity.

The DKLS sign path (`dkls_threshold.rs:434-445`, `dkls_sign.rs:379-389`) already rejects `recovery_id ∈ {2,3}` and re-signs; it does NOT explicitly normalize high-S. The bridge_payload.rs:30-32 documentation says "DKLS23 reference normalizes; the wiring layer must verify and, if necessary, apply `s' = n - s; recovery_id ^= 1` and re-add 27 to v" — but no such verification exists in `ecdsa.rs` or in `dkls_sign.rs`. The DKLS reference's own normalization is the only line of defense; if a future DKLS upgrade or alternative sign path produces a high-S, the codebase will not catch it.

### O3. `envelope.payload` is unsigned and currently empty

`builder.rs:267` always sets `payload: Vec::new()`. But the wire format permits arbitrary bytes here (`mod.rs:359-361`: "Hyper-only payload that may include new message types or rule-specific annotations"). Future use of this field for any trusted purpose — analytics, anti-Sybil signals, validator-side feature flags — would inherit the malleability hole. Recommend either (a) include `payload` in `signing_payload`, or (b) hard-reject any non-empty `payload` in `import_hyper_block`.

### O4. `recovery_id ∈ {2,3}` is rejected at sign-time but NOT at verify-time

`dkls_sign.rs:379-389` and `dkls_threshold.rs:434-445` re-sign on `recovery_id > 1`. But the verifier (`sig_verify.rs:46-78` → `ecdsa.rs:62-69`) accepts any 65-byte signature that `PrimitiveSignature::try_from` accepts. The `v` byte goes through alloy's `from_bytes` constructor; alloy normalizes to `{0,1,27,28}` and rejects others. So the verifier IS implicitly safe for `v ∈ {2,3}` (they'd be rejected by alloy). Not exploitable today, but worth confirming under alloy version upgrades.

## Recommended fixes

### Fix A — minimal: include `signer_indices` in `signing_payload`

Modify `HyperBlockMetadata::signing_payload(epoch)` → `signing_payload(epoch, signer_indices: &[u64])`. Or, more cleanly, move the signing-payload computation to `HyperBlock::signing_payload(&self)` (taking both metadata and signature.signer_indices) and update all callers (`importer.rs:249`, `slashing.rs:95-98`, `actor.rs:2288, 3173, 4003, 4196`, `runtime.rs:5112`).

Append after the existing payload:

```
buf.extend_from_slice(&(signer_indices.len() as u32).to_be_bytes());
for idx in signer_indices {
    buf.extend_from_slice(&idx.to_be_bytes());
}
```

This single change closes Scenarios A and D. Tests to add:

- Take a real signed block, flip `signer_indices`, assert verify fails.
- Take a real conflicting-block pair, malleate `signer_indices` on either side, assert `verify_evidence_signatures` rejects.

### Fix B — close the chain-hash malleability

Either (a) include `extra_rules_version`, `retained_message_count`, and a digest of `envelope.payload` in `signing_payload`; or (b) make `hyper_block_hash` strictly equal to `keccak256(signing_payload(epoch) || signer_indices || ecdsa_signature)` — i.e., **derive block hash from exactly the signed bytes plus the signature**. Option (b) is structurally cleaner: any field not in the signature can't appear in the hash either.

### Fix C — enforce low-S in `EcdsaSignature::from_bytes`

After `PrimitiveSignature::try_from`, check `s` against `secp256k1_n/2` and reject otherwise. Implementation cost: ~5 lines + a feature gate if backwards compatibility for historical signatures is needed. Defense-in-depth against alloy version drift and against any future DKLS code path that doesn't normalize.

### Fix D — reject non-empty `envelope.payload` until it has a defined consumer

In `import_hyper_block`, before signature verification:

```rust
if !block.envelope.payload.is_empty() {
    return Err(ImportError::SignatureVerificationFailed); // or a new variant
}
```

Removes a latent attack surface for future feature additions.

### Fix E — bind `chain_id` in `signing_payload` (defense-in-depth, separate finding-class)

Per O1. Independent of A-D; closes the cross-shard replay window for any future scenario where two hypersnap deployments share a DKG state.

## Affected attack-class checklist items

- `signing-payload-coverage` — primary. The verifier does not cover every field the apply-path then trusts: `signer_indices`, `extra_rules_version`, `retained_message_count`, `envelope.payload`.
- `low-s-ecdsa-divergence` — compounding. Alloy does not enforce low-S; the doc-comment in `ecdsa.rs:27` claims it does. Same compounding role as F044/F101 noted for the EIP-191 paths, here for the ECDSA paths.
- `eip712-domain-or-replay-binding` — adjacent. The hyperblock signing payload omits `chain_id`; reliance on per-shard group-address divergence is implicit, not load-bearing in the code.

## Comparison to sibling iter-1 findings

| Finding | Domain | Root cause | Fix shape |
|---|---|---|---|
| F101 | EIP-191 JFS proof | no chain_id, no nonce | bind chain_id + nonce |
| F104 | Ed25519 fee-deposit | no chain_id | v2 DST with chain_id |
| F105 | Ed25519 app-receipt | no apply-time epoch binding | bind epoch in payload + apply check |
| **F153** | **ECDSA hyperblock + slashing evidence** | **`signer_indices` outside signed-over fields** | **include in `signing_payload`** |

F101/F104/F105 are about cross-context replay of an entire message; F153 is about within-context malleation of fields not covered by the sig. Different root, related family. Recommendation: treat F153 as the ECDSA-side counterpart to the Ed25519-side payload-coverage class.

## Reproduction sketch (Scenario A)

```rust
use crate::hyper::{HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
use crate::hyper::slashing::{detect_conflicting_blocks, verify_evidence_signatures};
use hypersnap_crypto::dkls_threshold::{run_honest_dkg, run_honest_sign};
use alloy_primitives::keccak256;

#[test]
fn malleated_signer_indices_passes_verify_evidence_signatures() {
    let dkg = run_honest_dkg(2, 3, [0xab; 32]).unwrap();
    let group_addr = dkg.group_address;

    let mut block_a = make_block(7, 5, vec![0xaa; 48]);
    let mut block_b = make_block(7, 5, vec![0xbb; 48]);

    // Sign both with the real 2-of-3 threshold committee.
    for block in [&mut block_a, &mut block_b] {
        let payload = block.envelope.metadata.signing_payload(block.signature.epoch);
        let digest = keccak256(&payload);
        let sig = run_honest_sign(&dkg, &digest, &[1, 2]).unwrap();
        block.signature.ecdsa_signature = sig.to_bytes().to_vec();
        block.signature.group_address = group_addr.as_slice().to_vec();
        block.signature.signer_indices = vec![1, 2];   // truthful signers
    }

    // Attacker malleates signer_indices to slash innocent validators 3..=11.
    block_a.signature.signer_indices = vec![3, 4, 5, 6, 7, 8, 9, 10, 11];
    block_b.signature.signer_indices = vec![3, 4, 5, 6, 7, 8, 9, 10, 11];

    let evidence = detect_conflicting_blocks(&block_a, &block_b).expect("conflict");
    // This SHOULD fail but currently passes — signing_payload doesn't cover signer_indices.
    verify_evidence_signatures(&evidence, &group_addr).expect("malleated evidence still verifies");

    // Now the persisted evidence carries attacker-chosen signer_indices.
    // slashed_validators_for_epoch will slash validators 3..=11 at the next boundary.
}
```

## Severity rationale (draft)

**High.** Scenario A delivers attacker-controlled validator exclusion under a realistic threat model — single observation of a fork (a non-Byzantine occurrence in any partition-tolerant chain) is sufficient. The slashing path is the documented protocol gate against double-signing; corrupting it lets an attacker remove honest validators or force the active set below threshold. The fix is small and structural; no protocol redesign needed. No on-chain economic loss directly, but consensus-set integrity loss is by definition high-severity in a PoS-style chain.

Downgrade to Medium if the validation pass determines that the supervisor's slash-finalization step cross-checks `signer_indices` against the per-epoch committee record (`dkls_committee.rs`) before exclusion. Searched for such a check; did not find one. The check would need to compare `signer_indices ⊆ committee_indices_for_epoch(epoch)`, which the codebase does not currently do.
