# F040 PoC: `verify_signatures` counts duplicate signers toward quorum

Target: farcasterorg/hypersnap @ `7eb981b`. This uses the same WSL build tree as F022 (`<build-tree>`, with malachite at `<malachite>`).

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/core/f040_poc_test.rs`, wired as `#[cfg(test)] mod f040_poc_test;` at the end of `src/core/mod.rs`. A copy is here as `f040_poc_test.rs`.
- Run: `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f040 -- --nocapture --test-threads=1`
- The incremental build plus test run took about 2-3 minutes.
- Output: `F040-test-output.txt`.

## Fixture

- n = 4 Falcon-512 validators from `consensus_keys::test_key(1..=4)`. These are the same seeds as `certificate::test_support::test_validators`. They are wrapped with `SnapchainValidator::new_falcon` in one `StoredValidatorSet` for shard 1, effective at 0, inside `StoredValidatorSets`.
- Every signature is a genuine precommit: `key.sign(ConsensusDomain::Vote, Vote::new_precommit(height, round, Val(value_id), address).to_sign_bytes())`. This is the exact message that `verify_signatures` checks (`util.rs:149-163`).
- The test builds `proto::Commits` directly (shard 1, height 42, round 0, and a 32-byte hash chosen by the attacker). It passes them to the real `crate::core::util::verify_signatures`, which goes through `try_to_commit_certificate`.

## Tests and results

| Test | What it asserts | Result |
|---|---|---|
| `f040_one_signer_repeated_three_times_meets_quorum` | One validator's precommit, repeated 3 times, returns `true`. Repeated 4 times, it also returns `true`. | **RED** (pass, claim reproduced) |
| `f040_control_three_distinct_signers_meet_quorum` | 3 distinct honest signers out of 4 return `true`. | pass (control) |
| `f040_control_two_distinct_signers_fail_quorum` | 2 distinct signers return `false`, because that is below quorum. | pass (control) |
| `f040_control_single_signature_fails_quorum` | A single signature returns `false`. | pass (control) |
| `f040_control_tampered_copy_is_rejected` | 2 good copies plus 1 copy with a flipped byte return `false`. This shows that every copy really is signature-checked, so the duplicates pass on their own merit. | pass (control) |

**All 5 tests pass, and the claim reproduces.**
- `try_to_commit_certificate` does **not** dedupe. It maps the `signatures` vector 1:1 into `AggregatedSignature::new`.
- `quorum.is_met(len = 3, total = 4)` passes.
- Every copy hits the same `HashMap` entry and verifies.
- So one key is enough to produce a "quorum" certificate.

## Caveats

- This is a unit test of `verify_signatures` alone.
  - The callers are not driven: `ReadValidator::verify_signatures` (`read_validator.rs:192/345`) and `block_receiver.rs:100`.
  - Gossip ingress is not exercised. Prost keeps repeated `signatures` entries on decode, so nothing on the wire dedupes them either. This was not tested end to end.
- The test does not show the end-to-end forgery. As the finding says, F033 masks it today, because the read path does not bind the value to `Commits`. The PoC confirms the latent hole that remains once F033 is fixed.
- The validator set is equal-weight, with a count-based quorum. This matches the current `verify_signatures`, which ignores voting power.
