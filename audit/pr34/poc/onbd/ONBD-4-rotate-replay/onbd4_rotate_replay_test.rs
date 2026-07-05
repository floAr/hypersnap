// ONBD-4 — red property PoC (build-verified, FAILS on 573d671).
//
// Placement: add to `mod tests` in `src/hyper/native_onboard.rs` (reuses the
// module's own test helpers `make_db`, `FakeAnchor`, `solve_pow`,
// `build_rotation`, and the `PrivateKeySigner`/`B256`/`SignerSync` imports
// already present there).
//
// Property asserted (should hold): replaying an onboarding body after the
// custody has rotated its FID away MUST be rejected (the POW/anchor was already
// spent). On 573d671 the only replay guard is `custody_to_fid[custody]`, which
// `apply_custody_rotation` deletes — so the replay succeeds and mints a SECOND
// FID from the SAME POW solve, and the assertion fails. Flips green once a
// permanent consumed-POW / ever-onboarded marker is enforced.
//
// Verbatim result on 573d671 (see test-output.txt):
//   ONBD-4: rotate-then-replay minted a second FID Ok(9223372036854775809)
//   from a single POW solve (custody freed by rotation; no consumed-POW marker)
//   (9223372036854775809 == HYPER_FID_BASE + 1)

#[test]
fn onbd4_rotate_then_replay_must_not_mint_second_fid() {
    let (db, _dir) = make_db();
    let chain_id = 10u64;
    let anchor_height = 100u64;
    let anchor_hash = [0x5au8; 32];
    let mut hashes = std::collections::HashMap::new();
    hashes.insert(anchor_height, anchor_hash);
    let anchor = FakeAnchor {
        tip: anchor_height,
        hashes,
    };

    // Build a POW onboarding body, keeping the custody signer so we can later
    // sign a rotation for it.
    let signer_a = PrivateKeySigner::random();
    let custody_a: [u8; 20] = signer_a.address().into();
    let nonce = solve_pow(&custody_a, &anchor_hash, MIN_DIFFICULTY_BITS);
    let gate_commitment = pow_gate_commitment(&nonce, MIN_DIFFICULTY_BITS);
    let typed = build_typed_data(
        chain_id,
        &custody_a,
        anchor_height,
        &anchor_hash,
        &gate_commitment,
    );
    let prehash = eip712_prehash(typed).unwrap();
    let sig = signer_a.sign_hash_sync(&B256::from(prehash)).unwrap();
    let body = proto::HyperNativeOnboardBody {
        custody_address: custody_a.to_vec(),
        custody_signature: sig.as_bytes().to_vec(),
        anchor_block_height: anchor_height,
        anchor_block_hash: anchor_hash.to_vec(),
        gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
            proto::PowSolution {
                nonce: nonce.clone(),
                difficulty_bits: MIN_DIFFICULTY_BITS,
            },
        )),
    };

    // 1) First onboarding: custody A gets FID X.
    let first = apply_onboarding(&db, &body, &anchor, chain_id, anchor_height).unwrap();
    let fid_x = first.fid;
    assert!(is_hyper_fid(fid_x));

    // 2) Rotate FID X from custody A to a fresh custody B. This deletes
    //    custody_to_fid[A].
    let signer_b = PrivateKeySigner::random();
    let custody_b: [u8; 20] = signer_b.address().into();
    let rot = build_rotation(chain_id, fid_x, &signer_a, custody_b, 1);
    apply_custody_rotation(&db, &rot, chain_id).unwrap();
    assert_eq!(lookup_custody_fid(&db, &custody_a).unwrap(), None);

    // 3) Replay the byte-identical original onboarding body.
    let replay = apply_onboarding(&db, &body, &anchor, chain_id, anchor_height);

    // PROPERTY: the replay must be rejected (the POW/anchor was already spent).
    // On 573d671 it instead succeeds and issues a SECOND FID from the same POW.
    assert!(
        replay.is_err(),
        "ONBD-4: rotate-then-replay minted a second FID {:?} from a single POW solve \
         (custody freed by rotation; no consumed-POW marker)",
        replay.map(|a| a.fid)
    );
}
