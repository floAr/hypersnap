# H064 — dkls-sig-verify-fallback — RULED OUT

- specialist: rust-threshold-signing
- attack_class: dkls-sig-verify-fallback
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- primary file: code/hypersnap/src/hyper/sig_verify.rs
- outcome: no issue

## Scope

Central DKLS signature verifier for blocks/rewards/bridge. Hunt questions:
1. Does verification ever fall back to BLS or accept on address-mismatch / missing group-address?
2. Is the per-epoch group address fail-closed (reject if no address for the epoch)?
3. Can a signature for one digest-type (block) be accepted for another (rewards/lock-root/burn)?

## Findings

### 1. No BLS fallback; mismatch fails closed
`sig_verify.rs::dispatch` (lines 46-78) is pure secp256k1 ECDSA. There is no
conditional BLS path; `ExpectedGroupKey` carries only an `ecdsa: &Address`.
"BLS" appears only in comments/tests describing *empty legacy fields*, never a
verify path. `hypersnap-crypto/src/ecdsa.rs::verify_against_address` (139-150)
strictly returns `SignerMismatch` unless `recovered == expected`. The
`declared_group_address` arg is advisory (checked only when non-empty, lines
59-73); real authority is the recover-against-`expected_addr` at line 76. Empty
sig -> `NoSignatureMaterial`; len != 65 -> `BadEcdsaLength`. All fail-closed.

### 2. Per-epoch group address is fail-closed in every production caller
Every caller resolves the expected address via
`HyperRuntime::dkls_group_address_for_epoch(epoch)` (returns `Option`) and
errors when absent — none substitutes `Address::ZERO`:
- reward issuance: runtime.rs:565-567 `.ok_or(UnknownEpoch)`
- trust snapshot: runtime.rs:655-657 `.ok_or(UnknownEpoch)`
- lock merkle-root update: runtime.rs:1025-1027 `.ok_or(UnknownEpoch)`
- owner rotation (both epochs): runtime.rs:1145-1150 `.ok_or(UnknownEpoch)`
- inbound burn: runtime.rs:1332-1334 `.ok_or(UnknownEpoch)`
- da epoch seed: runtime.rs:3239-3246 `.ok_or(Custom "no group address")`
- block import: runtime.rs:4467-4469 `.ok_or(SignatureVerificationFailed)`;
  importer.rs:238-258
- slashing evidence: slashing.rs:89-108 `.ok_or(UnknownEpochGroupKey)`,
  fed from actor.rs:1605-1607.
The only `Address::ZERO` `expected` values are in unit tests exercising
empty/short-sig rejection, which fail before recovery.

### 3. No cross-digest-type / cross-purpose acceptance
`dispatch` does `keccak256(payload)` with no internal tag, so domain separation
lives in each payload builder — and each signed type carries a distinct,
collision-resistant domain tag:
- block: `b"hypersnap-hyperblock-v2:"` (mod.rs:404)
- reward issuance: `b"hypersnap-reward-issuance-v2:"` (rewards.rs:711)
- trust snapshot: `b"hypersnap-trust-snapshot-v1:"` (rewards.rs:745)
- da epoch seed: `b"hypersnap-da-epoch-seed-v1:"` (rewards.rs:734)
- inbound burn: `b"hypersnap-inbound-burn-v1"` (inbound_burn.rs:42)
- bridge root/owner/upgrade/pause/recover/lock-leaf:
  `keccak256(b"HYPERSNAP_..._V1")` prefixes (bridge_payload.rs:53-70), with a
  `domain_tags_distinct` test (bridge_payload.rs:446-463) and cross-side pinned
  vectors against the Solidity contract.
A block signature therefore produces a different keccak digest than a reward /
burn / lock-root / bridge payload and cannot be replayed across types. (The
bridge digests are intentionally universal across chains except `recoverERC20`,
which binds `chainId` — consistent with the documented design and out of this
hunt's scope.)

## Residual / not-in-scope notes
- Bridge `recovery_id ∈ {2,3}` regeneration and low-`s` normalization are
  documented as wiring-layer requirements (bridge_payload.rs:20-36); not part of
  this central verifier and not exercised here.
- This file was confirmed not directly touched by round 1; behavior is correct
  as audited.

Conclusion: the central DKLS verifier is fail-closed on missing/empty sig,
wrong length, address mismatch, and missing per-epoch group address, with no BLS
fallback and full digest-type domain separation. No finding.
