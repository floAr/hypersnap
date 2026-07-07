
    // ===================================================================
    // Revalidation PoCs for commit ab73681 (added to mod tests).
    // ===================================================================

    /// Shared setup: build a POW onboarding body under custody A (keeping A's
    /// signer so we can later sign a rotation), a fresh SRS-backed verkle tree,
    /// and a DB. Returns (db, dir, tree, body, signer_a, custody_a, chain_id).
    fn onbd_revalidation_setup() -> (
        Arc<RocksDB>,
        TempDir,
        hypersnap_crypto::verkle::VerkleTree,
        proto::HyperNativeOnboardBody,
        PrivateKeySigner,
        [u8; 20],
        u64,
    ) {
        let (db, dir) = make_db();
        let chain_id = 10u64;
        let anchor_height = 100u64;
        let anchor_hash = [0x5au8; 32];

        let signer_a = PrivateKeySigner::random();
        let custody_a: [u8; 20] = signer_a.address().into();
        let nonce = solve_pow(&custody_a, &anchor_hash, MIN_DIFFICULTY_BITS);
        let gate_commitment = pow_gate_commitment(&nonce, MIN_DIFFICULTY_BITS);
        let typed =
            build_typed_data(chain_id, &custody_a, anchor_height, &anchor_hash, &gate_commitment);
        let prehash = eip712_prehash(typed).unwrap();
        let sig = signer_a.sign_hash_sync(&B256::from(prehash)).unwrap();
        let body = proto::HyperNativeOnboardBody {
            custody_address: custody_a.to_vec(),
            custody_signature: sig.as_bytes().to_vec(),
            anchor_block_height: anchor_height,
            anchor_block_hash: anchor_hash.to_vec(),
            gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
                proto::PowSolution {
                    nonce,
                    difficulty_bits: MIN_DIFFICULTY_BITS,
                },
            )),
        };

        let mut rng = rand::rngs::OsRng;
        let srs = Arc::new(hypersnap_crypto::kzg::KzgSrs::random_unsafe(
            &mut rng,
            hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN,
        ));
        let tree = hypersnap_crypto::verkle::VerkleTree::new(srs);
        (db, dir, tree, body, signer_a, custody_a, chain_id)
    }

    // ONBD-4 — green PoC (FIXED). Exercises the PRODUCTION in-tree path
    // (`apply_onboard_to_tree`), unlike the 573d671-era PoC which drove the
    // now-dead `apply_onboarding` RocksDB path. Property: a rotate-then-replay
    // must NOT mint a second FID from a single POW solve. The permanent in-tree
    // `ever` marker makes the replay a no-op → this PASSES on ab73681.
    #[test]
    fn onbd4_rotate_then_replay_via_tree_mints_no_second_fid() {
        let (db, _dir, mut tree, body, signer_a, custody_a, chain_id) =
            onbd_revalidation_setup();

        // 1) First onboarding via the in-tree path → custody A gets FID X.
        let first = crate::hyper::builder::apply_onboard_to_tree(&mut tree, &body)
            .expect("fresh onboard assigns a FID");
        let fid_x = first.1;
        assert!(is_hyper_fid(fid_x));
        sync_onboarding_mirror_from_tree(&db, &tree, std::slice::from_ref(&body)).unwrap();
        assert_eq!(lookup_custody_fid(&db, &custody_a).unwrap(), Some(fid_x));

        // 2) Rotate FID X from custody A to a fresh custody B.
        let signer_b = PrivateKeySigner::random();
        let custody_b: [u8; 20] = signer_b.address().into();
        let rot = build_rotation(chain_id, fid_x, &signer_a, custody_b, 1);
        apply_custody_rotation(&db, &rot, chain_id).unwrap();
        assert_eq!(lookup_custody_fid(&db, &custody_a).unwrap(), None);

        // 3) Replay the byte-identical onboarding body through the in-tree path.
        let replay = crate::hyper::builder::apply_onboard_to_tree(&mut tree, &body);

        // PROPERTY (holds on ab73681): no second FID is minted.
        assert!(
            replay.is_none(),
            "ONBD-4: rotate-then-replay must not mint a second FID (got {:?})",
            replay
        );
    }

    // NEW (ab73681 fix-induced regression) — RED PoC. Property that SHOULD hold:
    // custody rotation is revocation, so after A rotates its FID to B, custody A
    // must stay unbound. It FAILS on ab73681: replaying A's onboard body drives
    // `sync_onboarding_mirror_from_tree`, which copies the never-cleared verkle
    // custody[A]=X binding straight back over the mirror (rotation only mutates
    // the RocksDB mirror, never the tree). The `ever` marker correctly blocks a
    // 2nd FID (ONBD-4) but does NOT stop the mirror resurrection — re-enabling
    // the revoked key A to pass `held_by_current` and re-rotate the FID.
    #[test]
    fn onboard_replay_must_not_resurrect_rotated_away_custody_binding() {
        let (db, _dir, mut tree, body, signer_a, custody_a, chain_id) =
            onbd_revalidation_setup();

        // Onboard A → tree + mirror.
        let fid_x = crate::hyper::builder::apply_onboard_to_tree(&mut tree, &body)
            .expect("fresh onboard")
            .1;
        sync_onboarding_mirror_from_tree(&db, &tree, std::slice::from_ref(&body)).unwrap();

        // Rotate A → B (mirror A deleted; TREE binding custody[A]=X untouched).
        let signer_b = PrivateKeySigner::random();
        let custody_b: [u8; 20] = signer_b.address().into();
        let rot = build_rotation(chain_id, fid_x, &signer_a, custody_b, 1);
        apply_custody_rotation(&db, &rot, chain_id).unwrap();
        assert_eq!(
            lookup_custody_fid(&db, &custody_a).unwrap(),
            None,
            "precondition: rotation revoked custody A"
        );

        // Replay A's onboard body. apply_onboard_to_tree is a no-op (ever marker,
        // no 2nd FID) — but import_block still passes the onboards list to the
        // mirror sync unconditionally:
        let noop = crate::hyper::builder::apply_onboard_to_tree(&mut tree, &body);
        assert!(noop.is_none(), "replay mints no new FID (ONBD-4 holds)");
        sync_onboarding_mirror_from_tree(&db, &tree, std::slice::from_ref(&body)).unwrap();

        // PROPERTY (should hold, FAILS on ab73681): A stays revoked.
        assert_eq!(
            lookup_custody_fid(&db, &custody_a).unwrap(),
            None,
            "REGRESSION: onboard replay resurrected rotated-away custody A -> fid {} \
             (mirror sync copied the never-cleared verkle binding back), defeating \
             rotation-based revocation",
            fid_x
        );
    }
