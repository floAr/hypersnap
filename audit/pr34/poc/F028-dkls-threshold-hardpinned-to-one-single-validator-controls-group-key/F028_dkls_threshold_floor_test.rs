// ============================================================================
// F028 — DKLS23 DKG threshold is hard-pinned to 1 (independent of active-set
//        size), so any single committee-elected validator unilaterally produces
//        the group threshold signature over hyperblocks, reward issuances, and
//        bridge authorizations.
//
// Finding:    findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md
// Trace:      findings/traces/F028-trace.md
// Commit:     cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
// Class:      threshold-vs-share-count-mismatch
//
// WHERE THIS BELONGS IN THE REPO
// ------------------------------
// This file is authored as a single self-contained module so it can be dropped
// in as-is, but each test mirrors (and is intended to be merged into) an
// existing in-tree `#[cfg(test)] mod tests` block:
//
//   * `derived_threshold_has_bft_floor`
//       -> belongs in code/hypersnap/src/hyper/dkls_committee.rs `mod tests`
//          (next to `selection_size_equals_threshold` / `pinned_vector_one_of_three`).
//          It exercises the BFT-floor that the supervisor's threshold derivation
//          (code/hypersnap/src/hyper/dkls_supervisor.rs::build_driver, line ~203,
//          `Parameters { threshold: inputs.threshold, share_count }`) MUST apply
//          before constructing `Parameters`. The production source of the
//          un-floored value is `let dkls_threshold = 1u8;` at
//          code/hypersnap/src/main.rs:1603.
//
//   * `single_party_signature_rejected_for_multi_validator_epoch`
//       -> belongs in code/hypersnap/src/hyper/sig_verify.rs `mod tests`
//          (next to `ecdsa_path_verifies` / `declared_group_address_mismatch_rejected`).
//          It exercises the quorum / cosigner-count floor that
//          `sig_verify::dispatch` (sig_verify.rs:46-77) MUST enforce on the
//          `signer_indices` carried by `proto::HyperBlockSignature`, on top of
//          the existing single-address recovery.
//
// PER-TEST ASSERTION & EXPECTED RESULT
// ------------------------------------
//   1. derived_threshold_has_bft_floor
//        For an active set of size N > 1, the threshold actually used to build
//        the DKLS driver/params must satisfy `threshold >= floor(2N/3)+1`
//        (equivalently: `threshold == 1` for N > 1 must be rejected). Today the
//        threshold is hard-pinned to 1, and `select_signing_committee` happily
//        returns a size-1 committee for any N -> ASSERTION FAILS on cab225f.
//        After the fix (BFT floor in build_driver + rejection of t==1 for n>1),
//        the size-1 committee is unreachable -> PASSES.
//
//   2. single_party_signature_rejected_for_multi_validator_epoch
//        A group signature produced by a 1-of-N committee (single signer) must
//        NOT verify as full group authority for an N > 1 active-set epoch. Today
//        `verify_hyperblock_signature` recovers one ECDSA address with NO
//        cosigner-count / quorum check, so the 1-of-N signature is ACCEPTED
//        -> ASSERTION FAILS on cab225f. After the fix (quorum floor on
//        `signer_indices` / rejection of a sub-quorum committee), it is rejected
//        -> PASSES.
//
// STATUS: UNVERIFIED — authored from source, not compiled.
// ============================================================================

use alloy_primitives::{keccak256, Address, B256};

use hypersnap::hyper::dkls_committee::select_signing_committee;
use hypersnap::hyper::sig_verify::{verify_hyperblock_signature, ExpectedGroupKey};
use hypersnap::proto;
use hypersnap_crypto::dkls_threshold::{run_honest_dkg, run_honest_sign};

/// BFT-safe reconstruction floor the integration layer is expected to apply:
/// `threshold >= floor(2 * share_count / 3) + 1` for any real (n > 1) set.
/// This mirrors the fix recommended in the finding
/// (dkls_supervisor.rs::build_driver) and in `dkls_threshold.rs` /
/// `select_signing_committee` guards.
fn bft_floor(share_count: u8) -> u8 {
    ((2u16 * share_count as u16) / 3) as u8 + 1
}

/// Test 1 — committee/threshold builder must honor a BFT floor for n > 1.
///
/// Belongs in: code/hypersnap/src/hyper/dkls_committee.rs `mod tests`.
///
/// We drive the same selector the actor uses at sign time
/// (`actor.rs:2659` -> `select_signing_committee`). For every multi-validator
/// active set, a correctly-floored threshold must yield a committee of at least
/// `floor(2N/3)+1` signers — never the lone signer the hard-pinned `t = 1`
/// produces today.
#[test]
fn derived_threshold_has_bft_floor() {
    // The production source value, hard-pinned at main.rs:1603.
    let hard_pinned_threshold: u8 = 1;

    // Representative real active-set sizes from the trace (5/10/32) plus the
    // smallest multi-validator set.
    for share_count in [2u8, 3, 5, 10, 32] {
        let floor = bft_floor(share_count);

        // What the system SHOULD do: derive a BFT-safe threshold from the real
        // active-set size. After the fix this is what build_driver feeds into
        // Parameters{threshold, share_count}.
        let derived_threshold = floor;

        // The derived threshold must meet the BFT floor and must never be the
        // single-signer value the code currently pins.
        assert!(
            derived_threshold >= floor,
            "n={share_count}: derived threshold {derived_threshold} below BFT floor {floor}"
        );
        assert!(
            derived_threshold > 1,
            "n={share_count}: multi-validator set must not use a single-signer threshold"
        );

        // Now assert the property end-to-end through the selector that prod
        // actually calls. The committee the chain accepts is exactly
        // `select_signing_committee(epoch, digest, share_count, threshold)`.
        //
        // (a) With the FIXED threshold, the committee is BFT-sized.
        let digest = B256::repeat_byte(0x28);
        let committee = select_signing_committee(7, &digest, share_count, derived_threshold)
            .expect("valid (threshold, share_count)");
        assert!(
            committee.len() as u8 >= floor,
            "n={share_count}: committee size {} below BFT floor {floor}",
            committee.len()
        );

        // (b) THE BUG: with the hard-pinned t = 1 the chain would accept a
        //     single-signer committee for this multi-validator set. The secure
        //     contract is that t = 1 is NOT a legal threshold for n > 1 — the
        //     selector (post-fix) must reject it rather than return one index.
        //
        //     On cab225f, `select_signing_committee(.., share_count, 1)` returns
        //     Ok(vec![<one idx>]) (len == 1), so this assertion FAILS. After the
        //     fix it returns Err(BadParameters)/refuses t==1 for n>1, so the
        //     single-signer committee is unreachable and this assertion PASSES.
        let one_of_n = select_signing_committee(7, &digest, share_count, hard_pinned_threshold);
        assert!(
            one_of_n.map(|c| c.len()).unwrap_or(0) != 1,
            "n={share_count}: t=1 must not yield a single-signer committee for a multi-validator set \
             (BFT floor = {floor})"
        );
    }
}

/// Test 2 — a 1-of-N signature must not verify as full group authority.
///
/// Belongs in: code/hypersnap/src/hyper/sig_verify.rs `mod tests`.
///
/// Mirrors the existing `ecdsa_signed_block_sig` fixture there, but builds the
/// group key as a 1-of-N (single-signer) DKG — exactly what the hard-pinned
/// `threshold = 1` produces for an N-validator epoch — and asserts the verifier
/// REJECTS it because fewer than a quorum of distinct cosigners signed.
#[test]
fn single_party_signature_rejected_for_multi_validator_epoch() {
    // A real multi-validator epoch: N = 5 active validators.
    let share_count: u8 = 5;
    let quorum_floor = bft_floor(share_count); // floor(2*5/3)+1 = 4

    let payload = b"f028-hyperblock-payload";
    let digest = keccak256(payload);

    // The vulnerable state F028 creates: a 1-of-N group key. DKG runs with the
    // real active-set size (share_count = N) but the hard-pinned threshold = 1.
    let dkg = run_honest_dkg(1, share_count, [0x28u8; 32]).expect("1-of-N dkg (the F028 state)");

    // A single elected committee member signs alone (signer_indices = [1]) and
    // produces a full (r,s,v) recovering to the group address — the
    // actor.rs:2711 single-member fast path.
    let sig = run_honest_sign(&dkg, &digest, &[1]).expect("single-party sign");

    let block_sig = proto::HyperBlockSignature {
        epoch: 0,
        signer_indices: vec![1], // ONE cosigner for a 5-validator epoch
        group_address: dkg.group_address.as_slice().to_vec(),
        ecdsa_signature: sig.to_bytes().to_vec(),
    };

    let expected = ExpectedGroupKey::ecdsa_only(&dkg.group_address);

    // Sanity: the byte-level signature genuinely recovers to the group address
    // (so the ONLY thing that can reject it is a quorum/cosigner-count floor,
    // not a malformed signature).
    assert!(
        sig.verify_against_address(&digest, dkg.group_address).is_ok(),
        "precondition: the 1-of-N signature recovers to the group address"
    );
    assert!(
        (block_sig.signer_indices.len() as u8) < quorum_floor,
        "precondition: a 1-signer committee is below the BFT quorum floor {quorum_floor}"
    );

    // SECURE/EXPECTED BEHAVIOR: a single-signer signature must NOT be honored as
    // group authority for a multi-validator epoch.
    //
    // On cab225f, `dispatch` (sig_verify.rs:46-77) performs only single-address
    // recovery with NO `signer_indices.len() >= quorum` check, so this returns
    // Ok(()) and the assertion FAILS. After the fix (quorum floor on the
    // cosigner count), it returns Err(..) and the assertion PASSES.
    let result = verify_hyperblock_signature(
        payload,
        &block_sig.ecdsa_signature,
        &block_sig.group_address,
        &expected,
    );
    assert!(
        result.is_err(),
        "1-of-{share_count} signature was accepted as group authority; \
         verifier must reject a sub-quorum (< {quorum_floor}) cosigner set"
    );
}
