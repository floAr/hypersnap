    #[test]
    fn f071_relay_rewrite_output_pubkey_must_be_rejected() {
        // F071 red-polarity PoC. A gossip relay rewrites outputs[0].one_time_pubkey
        // AFTER the sender signed. The bare signing_payload() does not cover the
        // output pubkey, so schnorr_verify still passes and admission ACCEPTS the
        // mutated transfer. This test asserts the SECURITY PROPERTY (admission must
        // reject an envelope-tampered transfer) and therefore FAILS on current code.
        use crate::hyper::router::HyperRouter;
        use crate::hyper::transfer_codec::tx_to_proto_full;
        use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
        use hypersnap_crypto::tokens::{
            create_stealth_output, point_to_compressed_bytes, prove_value_range,
            scan_stealth_note, schnorr_sign, NoteStoreMut, Nullifier, PedersenCommitment,
            StealthKeypair, TransferInput, TransferOutput, TransferTx, DEFAULT_RANGE_BITS,
        };
        use rand::rngs::OsRng;

        let (mut rt, _dir) = make_runtime();
        let mut rng = OsRng;

        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();
        let stealth_in = create_stealth_output(&address, &mut rng);
        let value = 100u64;
        let r_in = Scalar::random(&mut rng);
        let in_commitment = PedersenCommitment::commit(value, &r_in);
        rt.note_store
            .record_note(in_commitment, stealth_in.one_time_pubkey);

        let spend_secret =
            scan_stealth_note(&recipient, &stealth_in.tx_pubkey, &stealth_in.one_time_pubkey)
                .expect("scan");
        let nullifier = Nullifier::derive(&spend_secret, &in_commitment);

        let r_out = Scalar::random(&mut rng);
        let stealth_out = create_stealth_output(&address, &mut rng);
        let out_commitment = PedersenCommitment::commit(value, &r_out);
        let (range_proof, _) =
            prove_value_range(value, &r_out, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        let mut tx = TransferTx {
            inputs: vec![TransferInput {
                commitment: in_commitment,
                nullifier,
                spend_signature: schnorr_sign(&spend_secret, &[0u8; 32], &mut rng),
            }],
            outputs: vec![TransferOutput {
                commitment: out_commitment,
                range_proof,
            }],
            fee_atoms: 0,
        };
        let payload = tx.signing_payload();
        tx.inputs[0].spend_signature = schnorr_sign(&spend_secret, &payload, &mut rng);
        let blinding_diff = r_in - r_out;

        // Honest wire message: intended recipient stealth address.
        let mut tx_proto =
            tx_to_proto_full(&tx, &blinding_diff, &[stealth_out.one_time_pubkey]);

        // Relay attack: overwrite the output pubkey with an UNRELATED attacker
        // stealth address. Nothing the bare digest covers is touched.
        let attacker = StealthKeypair::generate(&mut rng);
        let attacker_out = create_stealth_output(&attacker.public_address(), &mut rng);
        tx_proto.outputs[0].one_time_pubkey =
            point_to_compressed_bytes(&attacker_out.one_time_pubkey).to_vec();

        let msg = HyperRouter::outbound_transfer(tx_proto);
        let res = rt.submit_message(msg);

        // SECURITY PROPERTY (fails on current code): a transfer whose output
        // one_time_pubkey was rewritten after signing must NOT be admitted.
        assert!(
            res.is_err(),
            "F071: envelope not bound -- relay rewrote output one_time_pubkey \
             without invalidating the spend signature; admission accepted it \
             (pending={})",
            rt.pending_count()
        );
    }

