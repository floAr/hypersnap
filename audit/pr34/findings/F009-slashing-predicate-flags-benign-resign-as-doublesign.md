---
id: F009
specialist: consensus-malachite-tendermint
attack_class: double-sign-evidence-gating
severity_initial: high
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
title: "Slashing predicate keys 'conflict' on signature-inclusive block hash; two valid threshold signatures over identical block content (sign-ceremony restart / round retry) are mis-classified as double-sign evidence and slash honest signers"
related_findings:
  - F002
  - F015
relationship: related-but-distinct
file_paths:
  - code/hypersnap/src/hyper/slashing.rs
  - code/hypersnap/src/hyper/chain.rs
  - code/hypersnap/src/hyper/mod.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/dkls_sign_driver.rs
  - code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.6
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The hyper slashing path's notion of "conflicting blocks" is **strictly
broader** than consensus's notion of equivocation. `detect_conflicting_blocks`
(`slashing.rs:52`) declares two blocks at the same `canonical_block_id` a
slashable conflict whenever their `hyper_block_hash` differs. But
`hyper_block_hash` (`chain.rs:25`) mixes the **non-deterministic threshold
ECDSA signature bytes** (`ecdsa_signature`, and `group_address`) into the
digest. The actual consensus commitment — the *signed content* — is
`HyperBlockMetadata::signing_payload` (`mod.rs:403`), which does **not**
contain the signature.

Consequently, **two valid threshold signatures over byte-identical signed
content** (same `signing_payload`, i.e. the *same* canonical block / same
consensus decision) hash to two different `hyper_block_hash` values and are
mis-classified as a double-sign conflict. Both blocks pass
`verify_evidence_signatures` (they are genuinely signed by the epoch group
key), so the pair is accepted as authoritative evidence, persisted, and at
the next epoch boundary `slashed_validators_for_epoch` (`runtime.rs:4191`)
slashes the honest committee that produced them.

A second valid signature over identical content is a **normal, expected**
outcome in this codebase, not equivocation:

- **DKLS sign-ceremony restart (F045).** `DklsSignDriver::try_restart_for_recovery_id`
  (`dkls_sign_driver.rs:53`) and `DklsSignCoordinator::restart`
  (`dkls_sign.rs:217`) keep the *same digest* (= `keccak256(signing_payload)`)
  but regenerate the per-ceremony nonce (`instance_key`), so the retried
  attempt produces a **different `R` and thus a different `(r,s)` signature**
  over identical content (comment at `dkls_sign.rs:211-215`). The 65-byte
  ECDSA signature bytes differ; the signed payload does not.
- **Consensus round retry / re-proposal.** Malachite can re-attempt a height
  across rounds. Re-running block production for the same `(epoch, height,
  parent_hash)` selects the same deterministic committee
  (`actor.rs:2657`, `committee_seed_for_block`) and the same `signing_payload`
  — but a fresh sign ceremony yields a fresh nonce and a fresh signature.

DKLS threshold ECDSA here is non-deterministic (not RFC-6979); nothing
normalizes or canonicalizes the signature, and the slashing predicate never
compares the *signed payloads*. So the two notions of "double-sign" diverge:
consensus equivocation = two distinct committed *values* at one height; the
hyper predicate = two distinct *signature-bearing encodings* at one height.

## Impact

A legitimate consensus action (sign-ceremony recovery-id restart, or a round
retry) is mis-classified as double-sign evidence. Because the evidence is
genuinely signature-valid, it survives every existing gate
(`detect_conflicting_blocks` → `verify_evidence_signatures` →
`record_evidence`, `actor.rs:1587-1620`) and is enforced at the epoch
boundary against the **honest** signing committee.

Attack construction (insider griefing, no key compromise required):

1. A byzantine validator participates as a committee member in a block-
   production ceremony for height `H`. Every committee party learns the full
   finalized `EcdsaSignature` (`coordinator.output()`).
2. The ceremony restarts once (a recovery-id retry is common — recovery_id ∈
   {2,3} occurs ~50% of the time, see `dkls_sign.rs:211`), or a consensus
   round retry re-runs production for `H`. The attacker retains the signature
   from both executions: `sig1` and `sig2`, both valid over the identical
   `signing_payload` for `H`.
3. The attacker constructs `block_a` (content of `H` + `sig1`) and `block_b`
   (content of `H` + `sig2`) and gossips them as an `InboundEvidence` frame.
4. Every honest node runs `detect_conflicting_blocks` → distinct
   `hyper_block_hash` (signature bytes differ) → conflict;
   `verify_evidence_signatures` → both valid → persisted; epoch boundary →
   the entire honest committee (including the attacker's honest co-signers)
   is added to `slashed_validators_for_epoch`.

This lets a single committee member slash the rest of an honest committee,
or self-slash to manufacture a griefing/halt vector, **without ever forking
state**. It also means an honest node that legitimately restarted its own
sign ceremony can be slashed by replaying its own two outputs.

This is the inverse of the producer-can't-lie anti-pattern: here the gate is
*over-broad* rather than absent — it treats a non-conflict (same decision,
two valid sigs) as a conflict. The genuine-equivocation direction is fine
(`hyper_state_root` is inside `hyper_block_hash`, so two different state roots
are still caught), so the consistency bug is one-directional: **legitimate →
mis-slashed**.

## Root cause

`hyper_block_hash` (the identity used for "distinct") and `signing_payload`
(the identity used for "what the group committed to") are different field
sets. Specifically `hyper_block_hash` includes `ecdsa_signature` /
`group_address`, while `signing_payload` does not (it cannot sign itself).
The slashing predicate should define "distinct block" by **distinct signed
content**, not by distinct signature encoding.

Note this is *not* subsumed by F026/F028/F153 (those bind epoch tags,
extra-rules/retained-count, and `signer_indices` into the signing payload to
stop a *malicious proposer* manufacturing distinct hashes). Those fixes
hardened the signed payload; they did not change the fact that the *conflict
test* keys on the signature-inclusive `hyper_block_hash`. Two honest,
identical-content blocks with different nonces still differ under
`hyper_block_hash` and still trip the predicate.

## Recommended fix

Define "conflict" on signed content, not on the signature-bearing hash:

- In `detect_conflicting_blocks`, compare `a.envelope.metadata.signing_payload(a.signature.epoch, &a.signature.signer_indices)`
  against the equivalent for `b` (or a content-only digest that excludes
  `ecdsa_signature` / `group_address`). Two blocks are a genuine conflict
  only when the *signed payloads* differ at the same `canonical_block_id`
  (and the signer sets/epochs are consistent). Identical signed payload with
  differing signature bytes = same decision, **not** slashable.
- Equivalently, derive `block_a_hash`/`block_b_hash` from a signature-free
  canonical encoding so the dedupe key, the store key, and the conflict test
  all agree on content-identity.

## Verification notes

- `detect_conflicting_blocks` only checks `canonical_block_id` equality and
  `hash_a != hash_b` (`slashing.rs:52-77`); there is no signed-payload
  comparison.
- `hyper_block_hash` includes `signature.ecdsa_signature` and
  `signature.group_address` (`chain.rs:36-39`).
- `signing_payload` excludes the signature (`mod.rs:403-452`).
- `restart()` preserves `digest` and regenerates the per-ceremony nonce
  (`dkls_sign.rs:211-224`); `try_restart_for_recovery_id` drives it
  (`dkls_sign_driver.rs:51-61`).
- Enforcement reads `signer_indices` of *both* evidence blocks and slashes
  them (`runtime.rs:4191-4225`), so an honest committee on both sigs is
  penalized.
