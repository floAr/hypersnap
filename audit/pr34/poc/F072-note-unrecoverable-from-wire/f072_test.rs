
#[cfg(test)]
mod f072_poc_tests {
    // F072 red-polarity PoC. A confidential transfer is built to a known
    // recipient, serialized, and decoded like a peer receiving it off gossip.
    // The recipient tries to recover the output using ONLY the on-chain
    // HyperTransferOutput fields (commitment, range_proof, one_time_pubkey). The
    // wire carries no tx_pubkey, so ChainOutput.tx_pubkey cannot be populated and
    // scan_notes returns nothing. This asserts the property that SHOULD hold
    // (recipient recovers a spendable note from wire data) and FAILS on current code.
    use super::{scan_notes, ChainOutput};
    use crate::tx::confidential_transfer::{
        build_confidential_transfer, ConfidentialInput, ConfidentialOutput,
    };
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    use hypersnap_crypto::tokens::{PedersenCommitment, StealthKeypair};
    use hypersnap_proto as proto;
    use prost::Message;
    use rand::rngs::OsRng;

    #[test]
    fn f072_recipient_cannot_recover_note_from_wire_data() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);

        // A spendable input note owned by the sender.
        let in_value = 100u64;
        let in_blinding = Scalar::random(&mut rng);
        let in_commitment = PedersenCommitment::commit(in_value, &in_blinding);
        let sender_secret = Scalar::random(&mut rng);

        let msg = build_confidential_transfer(
            vec![ConfidentialInput {
                commitment: in_commitment,
                blinding: in_blinding,
                value: in_value,
                spend_secret: sender_secret,
            }],
            vec![ConfidentialOutput {
                value: in_value,
                recipient: recipient.public_address(),
            }],
            0,
        )
        .expect("build");

        // Serialize + decode like a peer receiving it off gossip.
        let bytes = msg.encode_to_vec();
        let decoded = proto::HyperMessage::decode(&bytes[..]).expect("decode");
        let tx = match decoded.body {
            Some(proto::hyper_message::Body::Transfer(t)) => t,
            _ => panic!("expected Transfer body"),
        };

        // Reconstruct ChainOutputs from ONLY the wire fields available.
        // HyperTransferOutput has no tx_pubkey field, so it is forced empty.
        let chain_outputs: Vec<ChainOutput> = tx
            .outputs
            .iter()
            .map(|o| ChainOutput {
                tx_pubkey: Vec::new(),
                one_time_pubkey: o.one_time_pubkey.clone(),
                commitment: o.commitment.clone(),
            })
            .collect();

        let owned = scan_notes(&recipient, &chain_outputs);

        // PROPERTY (fails on current code): the recipient discovers its output.
        assert!(
            !owned.is_empty(),
            "F072: recipient could not discover its confidential output from wire \
             data -- HyperTransferOutput carries no tx_pubkey, so scan_notes \
             returned {} notes",
            owned.len()
        );
    }
}
