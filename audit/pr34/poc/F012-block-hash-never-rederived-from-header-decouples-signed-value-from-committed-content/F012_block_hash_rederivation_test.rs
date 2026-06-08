// ============================================================================
// Finding:   F012 — Block/ShardChunk `hash` is the consensus-committed value
//            but is never re-derived from blake3(header) on the
//            validate/commit/read-node paths, decoupling the signed value
//            from the header (and body) that actually get committed.
//
// Commit:    cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
// Class:     propose-value-misuse (consensus-malachite-tendermint)
//
// Placement: This is a crate-INTERNAL test (it uses non-`pub` test helpers
//            such as `crate::storage::store::test_helper` and the real
//            `ShardProposer` / `ReadValidator` APIs). To run it, drop it in
//            tree next to the code it exercises and register the module, e.g.
//            copy to `code/hypersnap/src/consensus/F012_block_hash_rederivation_test.rs`
//            and add `#[cfg(test)] mod F012_block_hash_rederivation_test;` to
//            `code/hypersnap/src/consensus/mod.rs`, then
//            `cargo test -p hypersnap proposed_value_hash_must_match_blake3_header`.
//            It is delivered here under findings/tests/ so that `code/` is not
//            modified. Fixtures mirror `src/consensus/read_validator_test.rs`
//            and `ShardProposer::propose_value` (proposer.rs:176-201).
//
// Assertion (SECURE behaviour, the thing the fix must establish):
//   1. `proposed_value_hash_must_match_blake3_header`
//        A shard chunk whose `hash` field does NOT equal
//        `blake3(header.encode_to_vec())` must be rejected as
//        `Validity::Invalid` by `ShardProposer::add_proposed_value`.
//        Built by taking a genuine, replay-valid proposal (which IS accepted),
//        then mutating a header field that the state-root replay does NOT
//        re-derive (`parent_hash`) while leaving the signed `hash` untouched.
//        The (header, body) pair is internally consistent (shard_root still
//        matches the body) but `blake3(header) != hash`.
//
//   2. `read_node_rejects_unbound_header` (optional, read-path)
//        `ReadValidator::process_decided_value` must reject a `DecidedValue`
//        whose embedded `Commits` validly quorum-sign `hash`, but whose
//        header/body do NOT hash to that signed `hash` (`parent_hash`
//        flipped). The honest `Commits` are reused verbatim, so signature
//        verification passes; only a `blake3(header)`-vs-`hash` re-derivation
//        would catch the substitution. SECURE => 0 values committed.
//
// Expected result:
//   FAILS on cab225f — no receive path re-derives blake3(header); the proposer
//   accepts the unbound chunk (`Validity::Valid`) and the read node commits it
//   (returns 1).
//   PASSES after the fix adds the `hash == blake3(header.encode_to_vec())`
//   check in `add_proposed_value` and on the read-node decided-value path.
//
// Validator caveat (HAS_CAVEATS, confidence 0.6): the V9+ commit path replays
// the body and enforces `header.shard_root`, so the BODY is constrained to a
// self-consistent transition — but that replay never binds the HEADER to the
// signed `hash`. These tests therefore mutate `parent_hash` (a header field the
// replay does not re-derive), keeping `shard_root`/transactions intact so the
// replay still passes; the surviving gap is the header->signed-value binding.
//
// STATUS: UNVERIFIED
// ============================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::consensus::consensus::{SystemMessage, ValidatorSetConfig};
    use crate::consensus::proposer::{Proposer, ShardProposer};
    use crate::consensus::read_validator::{Engine, ReadValidator};
    use crate::consensus::validator::{StoredValidatorSet, StoredValidatorSets};
    use crate::core::types::{Address, ShardId, SnapchainShard};
    use crate::proto::{self, Height, ShardChunk, ShardHeader};
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::test_helper::{
        self, commit_event, default_storage_event, new_engine_with_options, sign_chunk,
        EngineOptions, FID_FOR_TEST,
    };
    use informalsystems_malachitebft_core_types::{Round, Validity};
    use libp2p::identity::ed25519::Keypair;
    use prost::Message;
    use tokio::sync::{broadcast, mpsc};

    // --- helpers ------------------------------------------------------------

    /// Build a genuine, replay-valid `FullProposal` for the next height of
    /// `engine`, mirroring `ShardProposer::propose_value` (proposer.rs:176-201):
    /// the header carries the engine-computed `shard_root` for `messages`, and
    /// `hash = blake3(header.encode_to_vec())`.
    fn build_valid_shard_proposal(
        engine: &mut ShardEngine,
        proposer: &Address,
    ) -> proto::FullProposal {
        let shard_id = engine.shard_id();
        let height = engine.get_confirmed_height().increment();
        let event = default_storage_event(FID_FOR_TEST);
        let state_change = engine.propose_state_change(
            shard_id,
            vec![crate::storage::store::mempool_poller::MempoolMessage::OnchainEvent(event)],
            None,
        );

        let header = ShardHeader {
            parent_hash: vec![0u8; 32],
            timestamp: state_change.timestamp.clone().into(),
            height: Some(height),
            shard_root: state_change.new_state_root.clone(),
        };
        let hash = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();

        let chunk = ShardChunk {
            header: Some(header),
            hash,
            transactions: state_change.transactions.clone(),
            commits: None,
        };

        proto::FullProposal {
            height: Some(height),
            round: Round::from(0u32).as_i64(),
            proposed_value: Some(proto::full_proposal::ProposedValue::Shard(chunk)),
            proposer: proposer.to_vec(),
        }
    }

    fn new_shard_proposer(engine: ShardEngine, address: Address) -> ShardProposer {
        let (tx_decision, _rx) = broadcast::channel::<ShardChunk>(16);
        ShardProposer::new(
            address,
            SnapchainShard::new(engine.shard_id()),
            engine,
            test_helper::statsd_client(),
            tx_decision,
        )
    }

    async fn commit_shard_chunk(engine: &mut ShardEngine, keypair: &Keypair) -> ShardChunk {
        let shard_chunk = commit_event(engine, &default_storage_event(FID_FOR_TEST)).await;
        sign_chunk(keypair, shard_chunk).await
    }

    /// Build a `ReadValidator` over a clone of `read_node_engine`'s db, with a
    /// validator set that trusts `proposer_keypair`. Mirrors
    /// `read_validator_test::setup`.
    async fn new_read_validator(
        read_node_engine: &ShardEngine,
        proposer_keypair: &Keypair,
    ) -> (ReadValidator, mpsc::Receiver<SystemMessage>) {
        let (read_node_engine_clone, _) = new_engine_with_options(EngineOptions {
            db: Some(read_node_engine.db.clone()),
            ..Default::default()
        })
        .await;

        let proposer_address = Address(proposer_keypair.public().to_bytes());
        let validator_set_config = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![proposer_address.to_hex()],
            validator_bls_public_keys: vec![],
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
        };
        (read_validator, system_rx)
    }

    // --- test 1: proposer validate path ------------------------------------

    /// F012 (SECURE). A shard chunk whose `hash != blake3(header)` must be
    /// rejected as `Validity::Invalid` on the proposer validate path.
    ///
    /// FAILS on cab225f: `add_proposed_value` checks height/state-root but
    /// never re-derives `blake3(header)`, so the unbound chunk is accepted.
    /// PASSES after the fix adds the re-derivation check.
    #[tokio::test]
    async fn proposed_value_hash_must_match_blake3_header() {
        let (mut engine, _dir) = test_helper::new_engine().await;
        let address = Address([7u8; 32]);

        // A genuine proposal (hash == blake3(header)) is accepted — sanity that
        // the fixture exercises the real accept path, so the rejection below is
        // attributable to the hash binding, not an unrelated failure.
        let valid_proposal = build_valid_shard_proposal(&mut engine, &address);
        let mut proposer = new_shard_proposer(engine, address.clone());
        assert_eq!(
            proposer.add_proposed_value(&valid_proposal),
            Validity::Valid,
            "sanity: a genuine chunk with hash == blake3(header) must be Valid"
        );

        // Forge an alternate, self-consistent chunk: keep transactions and
        // shard_root (so the state replay still matches the body) but flip a
        // header field the replay does not re-derive (`parent_hash`). Reuse the
        // ORIGINAL signed `hash`, so hash != blake3(header_evil).
        let mut forged = valid_proposal.clone();
        if let Some(proto::full_proposal::ProposedValue::Shard(chunk)) =
            forged.proposed_value.as_mut()
        {
            let signed_hash = chunk.hash.clone();
            let header = chunk.header.as_mut().unwrap();
            header.parent_hash = vec![0xAB; 32]; // differs from honest header

            // Confirm we actually broke the binding: blake3(header_evil) != hash.
            let rederived = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();
            assert_ne!(
                rederived, signed_hash,
                "fixture precondition: mutated header must not hash to the reused signed value"
            );
            // The chunk keeps the OLD hash (the value consensus would sign).
            chunk.hash = signed_hash;
        } else {
            panic!("expected a Shard proposed value");
        }

        // SECURE: an unbound (header, hash) pair must be rejected.
        assert_eq!(
            proposer.add_proposed_value(&forged),
            Validity::Invalid,
            "F012: chunk whose hash != blake3(header) must be rejected as Invalid"
        );
    }

    // --- test 2: read-node decided-value path ------------------------------

    /// F012 (SECURE, read path). A `DecidedValue` whose `Commits` validly
    /// quorum-sign `hash` but whose header does NOT hash to that `hash` must be
    /// dropped by the read node (0 values committed).
    ///
    /// FAILS on cab225f: `verify_signatures` only checks the quorum signed
    /// `hash`; `commit_decided_value`/engine replay binds body->shard_root but
    /// never re-derives `blake3(header)`, so the forged header is committed.
    /// PASSES after the fix re-derives `blake3(header)` before commit.
    #[tokio::test]
    async fn read_node_rejects_unbound_header() {
        let proposer_keypair = Keypair::generate();
        let (mut proposer_engine, _d1) = test_helper::new_engine().await;
        let (read_node_engine, _d2) = test_helper::new_engine().await;

        // Honest, validly-signed chunk for height 1. `Commits` sign
        // ShardHash{hash: chunk.hash} only.
        let honest_chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;

        // Forge: reuse honest `hash` + honest `Commits`, flip `parent_hash`
        // (not re-derived by replay; shard_root/transactions kept intact).
        let mut forged_chunk = honest_chunk.clone();
        {
            let header = forged_chunk.header.as_mut().unwrap();
            header.parent_hash = vec![0xCD; 32];
            let rederived = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();
            assert_ne!(
                rederived, forged_chunk.hash,
                "fixture precondition: forged header must not hash to the signed value"
            );
        }
        // `hash` and `commits` are left exactly as the honest quorum produced
        // them, so signature verification will pass.
        assert_eq!(forged_chunk.hash, honest_chunk.hash);
        assert_eq!(forged_chunk.commits, honest_chunk.commits);

        let (mut read_validator, _system_rx) =
            new_read_validator(&read_node_engine, &proposer_keypair).await;

        let decided_value = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Shard(forged_chunk)),
        };
        let num_processed = read_validator.process_decided_value(decided_value).await;

        // SECURE: the read node must NOT finalize a (header, body) pair whose
        // blake3(header) differs from the signed value.
        assert_eq!(
            num_processed, 0,
            "F012: read node must reject a decided value whose header does not hash to the signed value"
        );
    }
}
