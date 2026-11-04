---
finding_id: F040
title: '`verify_signatures` counts duplicate signers toward the quorum'
severity: medium
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.85
poc:
  path: poc/F040
  kind: build-backed
  result: 5/5
related_findings:
- F011
- F033
---
# F040 — `verify_signatures` counts duplicate signers toward the quorum. PR #34 replaced upstream's single-pass signer walk with a `HashMap` lookup, so one validator's signature, repeated, counts as many signers.

- **Severity:** Medium (latent). Today it is masked by F033: the read path never binds `Commits` to the value, so a forger can reuse any genuine quorum certificate. Once F033 is fixed by cherry-picking snapchain #1089, this becomes the remaining hole: a single Byzantine validator (or one leaked key) can forge a quorum certificate for a block of its choice that read nodes and `block_receiver` accept. That would be **High** if the binding fix lands without this one. Confidence 0.85 (source-only).
- **Category:** signature-quorum / regression-vs-upstream
- **Specialist:** coordinator (from the F033 validation and the upstream check) · no hunt task
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). It is **introduced by the PR**: upstream snapchain main `f66b47c` and the fork base's snapchain content (v0.15.0) are not affected.
- **PoC:** [poc/F040](../poc/F040/)/ (build-backed unit test, 5/5 pass). With n=4 Falcon validators, one validator's precommit repeated 3x (and 4x) makes `verify_signatures` return true. Controls: 3 distinct signers → true; 1 or 2 signers → false; a tampered copy → false. `try_to_commit_certificate` does not dedupe.

## Code facts

1. The quorum check counts raw entries: `quorum.is_met(certificate.aggregated_signature.signatures.len(), expected.len())` (`src/core/util.rs:133-139`).
2. Each signature is then looked up in a `HashMap<&Address, &ConsensusPublicKey>` built from the validator set (`util.rs:122-131`, `141-147`). A repeated address hits the same entry every time; nothing tracks addresses already seen.
3. Every copy verifies, because the copies are byte-identical signatures over the same `Vote::new_precommit(height, round, value_id, address)` (`util.rs:149-163`).
4. Upstream (`snapchain` main `src/core/util.rs:178-193`) walks `expected_pubkeys` as a **single-pass iterator** with Itertools `contains`. That consumes the iterator up to the match, so a second copy of the same signer can never match, and the certificate is rejected.
5. Callers: `ReadValidator::verify_signatures` (`src/consensus/read_validator.rs:192`, used at `:345` on every decided value) and `block_receiver.rs:100`.

## Attack (after F033 is fixed)

1. The attacker controls one validator key of an n-member set.
2. It signs a precommit for a block hash of its choosing at (h, r) and repeats that `CommitSignature` until `len` meets the quorum threshold.
3. It gossips the decided value. Read nodes accept it as quorum-certified, and the F033 impacts (forged chunk commit, pre-pivot genesis inputs) return with a 1-of-n trust assumption instead of 0-of-n.

## Red-team

- *Does Malachite's own certificate type dedupe?* `try_to_commit_certificate` keeps the vector as is (no dedupe was seen on this path). To be confirmed by the PoC.
- *Is this reachable today?* Not as a separate impact, because F033 is strictly worse. Report it together with the F033 fix so the fix is complete.

## Recommendations

- Track seen addresses (a `HashSet`) and reject duplicates, or count `unique signers`, and weight by voting power if sets are ever weighted.
- Add a regression test: duplicated signatures must fail.
