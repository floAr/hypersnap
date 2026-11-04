//! F022 build-backed PoC: the undecided-value store is keyed only by the
//! block's self-declared `hash`, written before validation with last-write-
//! wins, and `decide` commits whatever body is stored without re-checking it.
//!
//! An unauthenticated same-hash copy with a different body therefore
//! (1) carries the SAME consensus value id as the honest proposal (the id is
//! not bound to the body), (2) overwrites the honest entry in the store even
//! though validation rejects it, and (3) is the body that `decide` commits,
//! yielding a stored block that fails `validate_body` with `BadMessagesRoot`.
#![cfg(test)]

use crate::chain::block::{self, BlockError};
use crate::chain::certificate::{self, test_support::test_validators};
use crate::chain::epoch::EpochParams;
use crate::chain::block::ParentInfo;
use crate::chain::proposer::{
    commits_from_certificate, EpochSetSource, HypersnapShardProposer, Shard0Tip,
};
use crate::chain::shard_blocks::ShardBlockProducer;
use crate::chain::undecided::UndecidedValues;
use crate::chain::validator_sets::EpochSet;
use crate::consensus::proposer::Proposer;
use crate::proto::{
    self, full_proposal, FullProposal, Height, HypersnapBlock, HypersnapBlockHeader,
};
use crate::storage::db::RocksDB;
use crate::storage::store::account::StoreOptions;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::stores::StoreLimits;
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use informalsystems_malachitebft_core_types::{Round, Validity};
use prost::Message as _;
use std::sync::Arc;

// Added for run 2 (halt reproduction): a state-changing honest block.
use crate::mempool::mempool::MempoolMessagesRequest;
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::storage::store::node_local_state::LocalStateStore;
use crate::storage::store::test_helper::{self, EngineOptions, FID_FOR_TEST};
use crate::utils::factory::{events_factory, messages_factory};
use futures::FutureExt as _;
use std::panic::AssertUnwindSafe;
use tokio::sync::mpsc;

// ---- fixtures -------------------------------------------------------------

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

/// An honest, sealed block (empty body) for `shard_id` at `height`.
fn honest_block(shard_id: u32, height: u64) -> HypersnapBlock {
    let mut block = HypersnapBlock {
        header: Some(HypersnapBlockHeader {
            shard_id,
            height,
            timestamp: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    block::seal(&mut block);
    block
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

// ---- 1. value id is not bound to the body (root cause) --------------------

#[test]
fn value_id_is_not_bound_to_the_body_shard1() {
    let honest = honest_block(1, 1);
    // A same-hash copy: keep the honest header and hash bytes verbatim, swap
    // the body (one bogus transaction on a shard-1 block). Do NOT reseal.
    let mut copy = honest.clone();
    copy.transactions.push(proto::Transaction::default());
    assert_eq!(copy.hash, honest.hash, "copy keeps the honest hash");

    let hp = full_proposal(&honest, 0);
    let cp = full_proposal(&copy, 1000);
    // Same consensus value id despite different bodies.
    assert_eq!(hp.shard_hash(), cp.shard_hash(), "value id is identical");

    // The honest body is well-formed; the copy's body no longer matches the
    // header's messages_root.
    assert_eq!(block::validate_body(&honest), Ok(()));
    assert_eq!(
        block::validate_body(&copy),
        Err(BlockError::BadMessagesRoot)
    );
}

#[test]
fn value_id_is_not_bound_to_the_body_shard0() {
    let honest = honest_block(0, 1);
    let mut copy = honest.clone();
    copy.messages.push(proto::Message::default()); // junk user message
    assert_eq!(copy.hash, honest.hash);
    assert_eq!(full_proposal(&honest, 0).shard_hash(), full_proposal(&copy, 1000).shard_hash());
    assert_eq!(block::validate_body(&honest), Ok(()));
    assert_eq!(block::validate_body(&copy), Err(BlockError::BadMessagesRoot));
}

// ---- 2. the store overwrites the honest entry with the copy ---------------

#[test]
fn unauthenticated_copy_overwrites_the_stored_honest_value() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
    db.open().unwrap();

    let honest = honest_block(1, 1);
    let mut copy = honest.clone();
    copy.transactions.push(proto::Transaction::default());
    let hp = full_proposal(&honest, 0);
    let cp = full_proposal(&copy, 1000);
    let id = hp.shard_hash();

    let mut values = UndecidedValues::new(db.clone());
    values.add(hp.clone());
    // last write wins at key [height][declared hash]
    values.add(cp.clone());

    let stored = values.get(&id).expect("an entry under the honest id");
    assert_eq!(stored, cp, "the store now holds the attacker's copy");
    assert_ne!(stored, hp, "the honest value is gone");
    // The stored body is corrupt.
    let stored_block = stored.hypersnap_block().unwrap();
    assert_eq!(
        block::validate_body(&stored_block),
        Err(BlockError::BadMessagesRoot)
    );
}

// ---- 3. full decide path: shard 1 proposer commits the overwritten body ---

async fn shard1_proposer() -> (HypersnapShardProposer, Vec<tempfile::TempDir>) {
    let validators = test_validators(4, 1);
    let shard_dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RocksDB::new(shard_dir.path().join("shard1").to_str().unwrap()));
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

/// Build a quorum `Commits` for `hash` at (shard 1, height, round) using the
/// fixture validator set (3 of 4 = quorum).
fn quorum_commits(validators: &certificate::test_support::TestValidators, height: u64, hash: &[u8]) -> proto::Commits {
    let sigs = validators.sign(3, 1, height, 0, hash);
    let cert = certificate::build(&validators.set, 1, height, 0, hash, &sigs).unwrap();
    commits_from_certificate(&validators.set, &cert)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decide_commits_the_overwritten_body_and_stores_a_corrupt_block() {
    let validators = test_validators(4, 1);
    let (mut proposer, _dirs) = shard1_proposer().await;

    // 1. Honest proposal for the next height. propose_value stores it.
    let honest = proposer
        .propose_value(Height::new(1, 1), Round::new(0), std::time::Duration::from_secs(2))
        .await;
    assert_eq!(
        proposer.add_proposed_value(&honest),
        Validity::Valid,
        "the honest proposal validates"
    );
    let honest_block = honest.hypersnap_block().unwrap();
    assert_eq!(block::validate_body(&honest_block), Ok(()));
    let id = honest.shard_hash();

    // 2. Same-hash copy with junk in the user-message field (shard-1 blocks
    //    carry transactions, so a user message is illegal body too) — keep the
    //    honest header/hash, leave transactions empty so the cached execution
    //    is reused at commit (no replay panic; this isolates the store swap).
    let mut copy_block = honest_block.clone();
    copy_block.messages.push(proto::Message::default());
    assert_eq!(copy_block.hash, honest_block.hash);
    let copy = full_proposal(&copy_block, 1000);
    assert_eq!(
        proposer.add_proposed_value(&copy),
        Validity::Invalid,
        "the copy is rejected by validation"
    );

    // 3. The rejected copy is nonetheless the stored value under the honest id.
    let stored = proposer.get_proposed_value(&id).unwrap();
    assert_eq!(stored, copy, "the store holds the attacker's copy");

    // 4. decide for the honest value id commits the stored (copy) body.
    let commits = quorum_commits(&validators, 1, &id.hash);
    proposer.decide(commits).await;

    // 5. The committed/stored block is the attacker's body and fails validate_body.
    let on_chain = proposer.producer().store().get(1).expect("a stored block at height 1");
    assert!(
        !on_chain.messages.is_empty(),
        "the stored block carries the attacker's junk message"
    );
    assert_eq!(
        block::validate_body(&on_chain),
        Err(BlockError::BadMessagesRoot),
        "the committed block is unsyncable (BadMessagesRoot)"
    );
}

/// Negative control (run 1 had this as a `#[should_panic]` that did NOT panic).
/// Run 2 explains why, and asserts the negative directly instead of leaving a
/// red test. The honest block here is EMPTY, and the copy adds a bogus empty
/// `Transaction{fid:1}` with no messages. The commit-time cache key
/// `compute_block_events_hash` hashes only `system_messages[].block_event`
/// (engine.rs:3563) — it ignores user messages and transactions that carry no
/// block event. So the empty honest set and the junk-transaction copy produce
/// the SAME events hash: the cache HITS, the honest (empty) execution commits,
/// and nothing diverges. The halt needs the differing body to change the
/// block-events hash AND the trie — which is what Tests A/B do with a
/// MergeMessage block event. This is not a weaker claim: it pins the exact
/// condition the halt requires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_halt_when_the_differing_txn_carries_no_block_event() {
    let validators = test_validators(4, 1);
    let (mut proposer, _dirs) = shard1_proposer().await;
    let honest = proposer
        .propose_value(Height::new(1, 1), Round::new(0), std::time::Duration::from_secs(2))
        .await;
    assert_eq!(proposer.add_proposed_value(&honest), Validity::Valid);
    let honest_block = honest.hypersnap_block().unwrap();
    assert!(honest_block.transactions.is_empty(), "honest block is empty here");
    let id = honest.shard_hash();

    let mut copy_block = honest_block.clone();
    copy_block.transactions.push(proto::Transaction {
        fid: 1,
        ..Default::default()
    });
    let copy = full_proposal(&copy_block, 1000);
    let _ = proposer.add_proposed_value(&copy);
    assert_eq!(proposer.get_proposed_value(&id).unwrap(), copy);

    let commits = quorum_commits(&validators, 1, &id.hash);
    let result = AssertUnwindSafe(proposer.decide(commits)).catch_unwind().await;
    println!(
        "NEG CONTROL: panicked={} (expected false: events hash ignores non-block-event txns)",
        result.is_err()
    );
    assert!(
        result.is_ok(),
        "decide must NOT panic: the junk transaction carries no block event, so the \
         events-hash cache key is unchanged and the cached honest execution commits"
    );
}

// ===========================================================================
// Run 2: the shard 1/2 commit halt.
//
// The previous panic test used an EMPTY honest block, so the empty-copy's
// events hash matched the cache and no replay ran. Here the honest block
// carries a real, state-changing transaction (a signed cast from a registered
// FID), so the attacker copy's body (empty, or altered) has a different
// `compute_block_events_hash`. At commit the cache misses, the stored copy is
// replayed against the cached blake3 shard_root, the roots diverge, and
// `commit_shard_chunk` records a shard halt and panics.
// ===========================================================================

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

/// A shard-1 proposer whose mempool serves exactly one signed cast from a
/// registered FID, so `propose_value` yields a block with one state-changing
/// transaction. Returns the proposer and the height the honest block will take.
async fn shard1_proposer_with_cast() -> (HypersnapShardProposer, u64, Vec<tempfile::TempDir>) {
    let validators = test_validators(4, 1);
    let signer = test_helper::default_signer();

    // The honest body carries a BLOCK EVENT, not a bare user message: the
    // commit-time cache key `compute_block_events_hash` only covers
    // `system_messages[].block_event`, so a difference in user messages alone
    // never misses the cache. A MergeMessage block event (seqnum 1) folds a
    // signed cast into the trie, so it both changes the shard_root and gives a
    // non-empty events hash. ReadDataFromShardZero is active on devnet latest.
    let cast = messages_factory::casts::create_cast_add(FID_FOR_TEST, "honest", None, Some(&signer));
    let honest_event = events_factory::create_merge_message_event(cast, 1);

    // A mempool that answers the first pull with that block event, then nothing.
    let (tx, mut rx) = mpsc::channel::<MempoolMessagesRequest>(8);
    tokio::spawn(async move {
        let mut served = false;
        while let Some(req) = rx.recv().await {
            let msgs = if !served {
                served = true;
                vec![MempoolMessage::BlockEvent {
                    for_shard: 1,
                    message: honest_event.clone(),
                }]
            } else {
                vec![]
            };
            let _ = req.message_tx.send(msgs);
        }
    });

    let (mut engine, dir) = test_helper::new_engine_with_options(EngineOptions {
        messages_request_tx: Some(tx),
        ..Default::default()
    })
    .await;

    // Pre-pivot (snapchain) history: register the FID with storage + id + the
    // signer, so a cast from it merges. This advances the confirmed height.
    test_helper::register_user(
        FID_FOR_TEST,
        signer.clone(),
        test_helper::default_custody_address(),
        &mut engine,
    )
    .await;
    let fork_height = engine.get_confirmed_height().block_number;
    engine
        .enter_hypersnap_mode(Some(fork_height), crate::version::version::EngineVersion::latest())
        .unwrap();

    let genesis_parent = ParentInfo {
        height: fork_height,
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
        Arc::new(FixedTip(fork_height.max(1))),
    );
    (proposer, fork_height, vec![dir])
}

/// Test A (drop): honest block has one state-changing transaction; the copy
/// keeps the header + hash but has EMPTY transactions. `decide` for the honest
/// id commits the stored (empty) body, the cache misses, the replay of nothing
/// diverges from the cached shard_root, and the commit halts the shard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decide_halts_when_copy_drops_the_honest_transaction() {
    let validators = test_validators(4, 1);
    let (mut proposer, fork_height, _dirs) = shard1_proposer_with_cast().await;
    let h = fork_height + 1;

    // 1. Honest proposal carries a real transaction.
    let honest = proposer
        .propose_value(Height::new(1, h), Round::new(0), std::time::Duration::from_secs(2))
        .await;
    assert_eq!(
        proposer.add_proposed_value(&honest),
        Validity::Valid,
        "the honest proposal validates"
    );
    let honest_block = honest.hypersnap_block().unwrap();
    assert!(
        !honest_block.transactions.is_empty(),
        "the honest block carries a state-changing transaction"
    );
    assert_eq!(block::validate_body(&honest_block), Ok(()));
    let id = honest.shard_hash();

    // 2. Same-hash copy with the body dropped (empty transactions).
    let mut copy_block = honest_block.clone();
    copy_block.transactions.clear();
    assert_eq!(copy_block.hash, honest_block.hash, "copy keeps the honest hash");
    let copy = full_proposal(&copy_block, 1000);
    assert_eq!(copy.shard_hash(), id, "same consensus value id");
    assert_eq!(
        proposer.add_proposed_value(&copy),
        Validity::Invalid,
        "the empty-body copy is rejected by validation"
    );

    // 3. The rejected copy is the stored value under the honest id.
    assert_eq!(
        proposer.get_proposed_value(&id).unwrap(),
        copy,
        "the store holds the attacker's copy"
    );

    // 4. decide for the honest id: catch the panic and inspect the store.
    let commits = quorum_commits(&validators, h, &id.hash);
    let db = proposer.producer().store().db().clone();
    let before = proposer.producer().store().get(h).is_some();
    let result = AssertUnwindSafe(proposer.decide(commits)).catch_unwind().await;

    let panicked = result.is_err();
    let msg = result
        .as_ref()
        .err()
        .map(|e| panic_text(e.as_ref()))
        .unwrap_or_else(|| "<no panic>".to_string());
    let after = proposer.producer().store().get(h).is_some();
    let halt = LocalStateStore::read_shard_halt(&db, 1);
    println!(
        "TEST A: panicked={} msg={:?} block_at_h before={} after={} shard_halt={:?}",
        panicked, msg, before, after, halt
    );

    assert!(panicked, "decide must panic (shard halt); no panic observed");
    assert!(
        msg.contains("State change commit failed")
            || msg.contains("Committing a decided Hypersnap block failed"),
        "unexpected panic message: {}",
        msg
    );
    assert!(!before && !after, "no block must be committed at the halted height");
    let halt = halt.expect("a shard-halt record is written before the panic");
    assert_eq!(halt.shard_id, 1);
    assert_eq!(halt.height, h);
}

/// Test B (alter): the copy keeps the honest transaction but adds a second
/// state-changing cast to it. The body differs, so validation rejects it; at
/// commit the events hash misses, the altered body is replayed, the roots
/// diverge, and the shard halts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decide_halts_when_copy_alters_the_honest_transaction() {
    let validators = test_validators(4, 1);
    let (mut proposer, fork_height, _dirs) = shard1_proposer_with_cast().await;
    let h = fork_height + 1;

    let honest = proposer
        .propose_value(Height::new(1, h), Round::new(0), std::time::Duration::from_secs(2))
        .await;
    assert_eq!(proposer.add_proposed_value(&honest), Validity::Valid);
    let honest_block = honest.hypersnap_block().unwrap();
    assert!(!honest_block.transactions.is_empty());
    let id = honest.shard_hash();

    // Copy keeps the transaction but swaps the block event's payload for a
    // different signed cast at the same seqnum. The body (and so the events
    // hash) differs, validation rejects it, and the replay at commit folds the
    // other cast, diverging the shard_root.
    let mut copy_block = honest_block.clone();
    let signer = test_helper::default_signer();
    let other_cast = messages_factory::casts::create_cast_add(FID_FOR_TEST, "altered", None, Some(&signer));
    let other_event = events_factory::create_merge_message_event(other_cast, 1);
    copy_block.transactions[0].system_messages[0].block_event = Some(other_event);
    assert_eq!(copy_block.hash, honest_block.hash, "copy keeps the honest hash");
    let copy = full_proposal(&copy_block, 1000);
    assert_eq!(copy.shard_hash(), id);
    assert_eq!(
        proposer.add_proposed_value(&copy),
        Validity::Invalid,
        "the altered-body copy is rejected by validation"
    );
    assert_eq!(proposer.get_proposed_value(&id).unwrap(), copy);

    let commits = quorum_commits(&validators, h, &id.hash);
    let db = proposer.producer().store().db().clone();
    let before = proposer.producer().store().get(h).is_some();
    let result = AssertUnwindSafe(proposer.decide(commits)).catch_unwind().await;

    let panicked = result.is_err();
    let msg = result
        .as_ref()
        .err()
        .map(|e| panic_text(e.as_ref()))
        .unwrap_or_else(|| "<no panic>".to_string());
    let after = proposer.producer().store().get(h).is_some();
    let halt = LocalStateStore::read_shard_halt(&db, 1);
    println!(
        "TEST B: panicked={} msg={:?} block_at_h before={} after={} shard_halt={:?}",
        panicked, msg, before, after, halt
    );

    assert!(panicked, "decide must panic (shard halt); no panic observed");
    assert!(
        msg.contains("State change commit failed")
            || msg.contains("Committing a decided Hypersnap block failed"),
        "unexpected panic message: {}",
        msg
    );
    assert!(!before && !after, "no block must be committed at the halted height");
    assert!(halt.is_some(), "a shard-halt record is written before the panic");
}
