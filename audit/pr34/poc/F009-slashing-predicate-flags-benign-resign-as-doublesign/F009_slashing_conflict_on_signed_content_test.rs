// ============================================================================
// Finding:  F009 — Slashing predicate keys "conflict" on the signature-inclusive
//           block hash; two valid threshold signatures over IDENTICAL signed
//           content (same `signing_payload`) are mis-classified as double-sign
//           evidence and slash the honest committee.
//
// Placement: this file is authored at
//   findings/tests/F009_slashing_conflict_on_signed_content_test.rs
//   It targets `code/hypersnap/src/hyper/slashing.rs::detect_conflicting_blocks`
//   and mirrors the in-tree `#[cfg(test)] mod tests` fixtures in that file
//   (the `make_block` helper, the `HyperBlock` / `HyperBlockMetadata` /
//   `HyperBlockSignature` / `HyperEnvelope` types). To run it in-tree, drop
//   the body of `mod tests` (the `make_block` helper plus the test fn) into the
//   existing `#[cfg(test)] mod tests` block of `slashing.rs`, or wire this file
//   in as a module of the `hypersnap` crate. It is kept here, READ-ONLY w.r.t.
//   `code/`, as the regression artifact for F009.
//
// Assertion (SECURE behavior):
//   `two_valid_sigs_same_payload_not_conflict` — two `HyperBlock`s with
//   byte-IDENTICAL `signing_payload` (same `canonical_block_id`, same epoch,
//   same `signer_indices`, same metadata) but DIFFERENT threshold-signature
//   bytes (`ecdsa_signature` / `group_address`) — i.e. the SAME consensus
//   decision signed twice with a fresh nonce — must NOT be classified as a
//   slashable conflict by `detect_conflicting_blocks`.
//
//   The test first proves the precondition the bug hinges on: the two blocks
//   share an identical `signing_payload` yet hash to different
//   `hyper_block_hash` values (because `hyper_block_hash` folds the signature
//   bytes into the digest — chain.rs:35-39 — while `signing_payload` excludes
//   them — mod.rs:403-452). It then asserts the SECURE outcome: same signed
//   content => NOT a conflict.
//
// Expected result:
//   FAILS on `cab225f`  — today `detect_conflicting_blocks` keys "distinct
//                         block" on `hyper_block_hash` inequality alone
//                         (slashing.rs:62-66), so it returns `Ok(evidence)`
//                         for this benign re-sign and the assertion that it is
//                         NOT a conflict fails.
//   PASSES after fix    — once "conflict" is defined on the signed content
//                         (compare `signing_payload`, or a signature-free
//                         canonical digest) instead of the signature-inclusive
//                         `hyper_block_hash`, identical-payload/different-sig
//                         blocks are rejected as a non-conflict.
//
// VALIDATOR NOTE (LATENT predicate defect):
//   Per findings/notes/F009-validation.md and findings/traces/F009-trace.md,
//   the validator verdict is HAS_CAVEATS / 0.6. The predicate defect is REAL
//   and production-live, but there is NO in-tree producer that currently emits
//   two distinct VALID threshold signatures over one identical `signing_payload`
//   at a single `canonical_block_id`: the DKLS recovery-id-restart trigger is
//   ~2^-128 (not ~50%) and never retains a second signature object, the
//   round-retry trigger is not wired in this round-0 fixed-cadence producer,
//   and a lone insider cannot harvest a second threshold signature unilaterally.
//   Therefore this is a regression test for PREDICATE CORRECTNESS (define
//   "conflict" on signed content, defense-in-depth), NOT a live exploit. It
//   exercises only the pure `detect_conflicting_blocks` predicate; it does not
//   claim an end-to-end slash is presently reachable in-tree.
//
// STATUS: UNVERIFIED
// ============================================================================

use crate::hyper::chain::hyper_block_hash;
use crate::hyper::slashing::detect_conflicting_blocks;
use crate::hyper::{
    HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope,
};

/// Build a `HyperBlock` with fully-specified, signature-bearing fields.
///
/// Mirrors the in-tree `slashing.rs::tests::make_block` fixture, extended so
/// the caller controls the signature bytes (`group_address` / `ecdsa_signature`)
/// independently of the signed content. The metadata fields here are exactly
/// the set that `HyperBlockMetadata::signing_payload` commits to, so two blocks
/// built with the same `height` / `epoch` / `signer_indices` / `state_root`
/// produce a byte-identical `signing_payload`.
fn make_block_with_sig(
    height: u64,
    epoch: u64,
    signer_indices: Vec<u64>,
    state_root: Vec<u8>,
    group_address: Vec<u8>,
    ecdsa_signature: Vec<u8>,
) -> HyperBlock {
    HyperBlock {
        envelope: HyperEnvelope {
            metadata: HyperBlockMetadata {
                canonical_block_id: height,
                parent_hash: vec![0u8; 32],
                hyper_state_root: state_root,
                extra_rules_version: 0,
                retained_message_count: 0,
                missed_proposals: vec![],
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_range_start_block: 0,
                snapchain_range_root: vec![],
                snapchain_anchor_timestamp: 0,
            },
            payload: vec![],
        },
        signature: HyperBlockSignature {
            epoch,
            signer_indices,
            group_address,
            ecdsa_signature,
        },
    }
}

/// SECURE behavior: two genuinely-signed blocks that commit to the SAME
/// content (identical `signing_payload`) but carry DIFFERENT signature bytes
/// represent the same consensus decision signed twice (e.g. a sign-ceremony
/// restart with a fresh nonce). They are NOT equivocation and must NOT be
/// classified as a slashable conflict.
#[test]
fn two_valid_sigs_same_payload_not_conflict() {
    let height = 10u64;
    let epoch = 5u64;
    let signer_indices = vec![1u64, 2, 3];
    let state_root = vec![0xaa; 48];

    // Same signed content; differing only in the (non-deterministic) threshold
    // signature bytes — exactly what a fresh-nonce re-sign of one decision
    // produces.
    let a = make_block_with_sig(
        height,
        epoch,
        signer_indices.clone(),
        state_root.clone(),
        /* group_address    */ vec![0x01; 20],
        /* ecdsa_signature  */ vec![0xa1; 65],
    );
    let b = make_block_with_sig(
        height,
        epoch,
        signer_indices.clone(),
        state_root.clone(),
        /* group_address    */ vec![0x02; 20],
        /* ecdsa_signature  */ vec![0xb2; 65],
    );

    // Precondition 1: the SIGNED CONTENT is byte-identical. This is the true
    // consensus commitment and is what "distinct block" should be keyed on.
    let payload_a = a
        .envelope
        .metadata
        .signing_payload(a.signature.epoch, &a.signature.signer_indices);
    let payload_b = b
        .envelope
        .metadata
        .signing_payload(b.signature.epoch, &b.signature.signer_indices);
    assert_eq!(
        payload_a, payload_b,
        "fixture invariant: both blocks must commit to identical signed \
         content (same signing_payload) — same consensus decision",
    );

    // Precondition 2: the signature-inclusive block hash nonetheless DIFFERS,
    // because `hyper_block_hash` folds `ecdsa_signature` / `group_address`
    // into the digest (chain.rs:35-39). This is the divergence the defective
    // predicate keys on.
    assert_ne!(
        hyper_block_hash(&a),
        hyper_block_hash(&b),
        "fixture invariant: differing signature bytes must yield different \
         hyper_block_hash (else the bug-trigger condition is not exercised)",
    );

    // The SECURE assertion: identical signed content => NOT a slashable
    // conflict. On `cab225f`, `detect_conflicting_blocks` returns
    // `Ok(evidence)` here (it sees different `hyper_block_hash` at the same
    // `canonical_block_id`), so this assertion FAILS — flagging the latent
    // predicate defect. After the fix (conflict defined on `signing_payload`),
    // it returns an error and this assertion PASSES.
    let result = detect_conflicting_blocks(&a, &b);
    assert!(
        result.is_err(),
        "SECURE: two valid signatures over an identical signing_payload at the \
         same canonical_block_id are the SAME decision, not double-sign \
         evidence; detect_conflicting_blocks must NOT classify them as a \
         slashable conflict. Got Ok(evidence) on cab225f — predicate keys on \
         the signature-inclusive hyper_block_hash instead of the signed content.",
    );
}
