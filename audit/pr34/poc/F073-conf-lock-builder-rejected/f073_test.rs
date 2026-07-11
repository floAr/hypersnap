    #[test]
    fn f073_confidential_lock_builder_output_must_validate() {
        // F073 red-polarity PoC. A message built by the production wallet builder
        // build_confidential_lock MUST pass the runtime validator. It does not:
        // the builder sends blinding_diff = input_blinding - output_blinding for an
        // output_commitment that is never attached (BalanceClosureFailed), and an
        // empty range_proof (MissingRangeProof). This test asserts the property that
        // SHOULD hold (builder output validates) and therefore FAILS on current code.
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{
            create_stealth_output, scan_stealth_note, MemoryNoteStore, NoteStoreMut,
            PedersenCommitment, StealthKeypair,
        };
        use hypersnap_wallet::tx::confidential_lock::build_confidential_lock;
        use rand::rngs::OsRng;

        let mut rng = OsRng;

        // Build an input note that genuinely opens to (amount + fee).
        let recipient = StealthKeypair::generate(&mut rng);
        let stealth_in = create_stealth_output(&recipient.public_address(), &mut rng);
        let spend_secret =
            scan_stealth_note(&recipient, &stealth_in.tx_pubkey, &stealth_in.one_time_pubkey)
                .expect("scan");
        let amount = 100u64;
        let fee = 5u64;
        let input_blinding = Scalar::random(&mut rng);
        let input_commitment = PedersenCommitment::commit(amount + fee, &input_blinding);

        // Note store: this commitment is owned by the spend key and unspent.
        let mut store = MemoryNoteStore::new();
        store.record_note(input_commitment, stealth_in.one_time_pubkey);

        let chain_id = 1u64;
        let msg = build_confidential_lock(
            input_commitment,
            input_blinding,
            spend_secret,
            amount,
            fee,
            10,               // destination_chain_id
            vec![0xab; 20],   // destination_address
            chain_id,
        )
        .expect("builder");

        let body = match msg.body {
            Some(proto::hyper_message::Body::ConfidentialLock(b)) => b,
            _ => panic!("expected ConfidentialLock body"),
        };

        let res = validate_against_store(&body, chain_id, &store);

        // PROPERTY (fails on current code): the builder's message must validate.
        assert!(
            res.is_ok(),
            "F073: build_confidential_lock output must pass validate_against_store, got {:?}",
            res
        );
    }

