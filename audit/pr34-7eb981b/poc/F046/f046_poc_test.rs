//! F046 build-backed PoC: the node-local index `HyperSignerAuthByRequester`
//! (RootPrefix 83) feeds the PoQ F0 app filter, so two nodes with identical
//! consensus state but a different prefix-83 history build different genesis
//! `PivotRecord`s, and the pivot block of one is rejected by the other.
//!
//! Fixture: a copy of `pivot_test::two_nodes_build_the_same_genesis_and_accept_the_pivot_block`
//! (same eths, validators, genesis file, params, shard forks and `PivotInputs`).
//! Node A stands for a node whose shard-0 DB came from the upstream snapshot
//! or an older release (prefix 83 empty). Node B additionally holds 100
//! prefix-83 entries for app FID 1000 (`app_threshold` default = 100), i.e.
//! exactly what the merge path writes for 100 distinct users authorised by
//! FID 1000.
//!
//! Wired as `#[cfg(test)] mod f046_poc_test;` in `src/chain/mod.rs`.

use crate::chain::block::ParentInfo;
use crate::chain::genesis_file;
use crate::chain::pivot::{self, build_genesis, PivotInputs};
use crate::chain::shard0::auth::test_keys::*;
use crate::chain::shard0::engine::{Shard0Engine, Shard0Proposal};
use crate::chain::shard0::keys;
use crate::chain::shard0::test_support::{params, TestInputs};
use crate::chain::shard0::Shard0Params;
use crate::node::pivot_boot::record_differences;
use crate::proto::{
    self, FarcasterNetwork, GenesisValidator, IdRegisterEventType, OnChainEvent, PivotRecord,
    ShardForkPoint, ShardLink, SignerEventType,
};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{signer_auth_index, OnchainEventStore, StoreEventHandler};
use alloy_signer_local::PrivateKeySigner;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::sync::Arc;

const PIVOT: u64 = 100;
const FORK_HASH: [u8; 32] = [9u8; 32];
const FORK_TS: u64 = 160_000_000;
const APP_FID: u64 = 1000;
const USER_BASE: u64 = 10_000;
const P83: u8 = RootPrefix::HyperSignerAuthByRequester as u8;

// ---------------------------------------------------------------------------
// Fixture (copied verbatim from pivot_test.rs, whose helpers are private).
// ---------------------------------------------------------------------------

fn id_event(
    fid: u64,
    custody: &[u8],
    kind: IdRegisterEventType,
    ts: u64,
    tx: u8,
    log: u32,
) -> OnChainEvent {
    OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeIdRegister as i32,
        chain_id: 10,
        block_number: (ts / 2) as u32,
        block_timestamp: ts,
        transaction_hash: vec![tx; 32],
        log_index: log,
        fid,
        version: 1,
        body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
            proto::IdRegisterEventBody {
                to: custody.to_vec(),
                event_type: kind as i32,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

struct Validator {
    entry: GenesisValidator,
}

fn validator(fid: u64, eth: &PrivateKeySigner) -> Validator {
    let custody = falcon(fid as u8 + 40);
    let node = falcon(fid as u8 + 60);
    let consensus = falcon(fid as u8 + 80);
    let keys = genesis_file::EntryKeys {
        fid,
        network: FarcasterNetwork::Devnet,
        timestamp: FORK_TS as u32,
        deadline: (FORK_TS + 3_600) as u32,
        custody: &custody,
        node: &node,
        consensus: &consensus,
    };
    let signature = {
        use alloy_signer::SignerSync;
        eth.sign_hash_sync(&genesis_file::custody_migration_hash(&keys).into())
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([fid as u8; 32]);
    let entry = genesis_file::entry(&keys, signature, &mut rng).unwrap();
    Validator { entry }
}

fn open(dir: &tempfile::TempDir, name: &str) -> Arc<RocksDB> {
    let db = Arc::new(RocksDB::new(dir.path().join(name).to_str().unwrap()));
    db.open().unwrap();
    db
}

fn epoch0(db: &Arc<RocksDB>, eths: &[PrivateKeySigner]) {
    let store = OnchainEventStore::new(db.clone(), StoreEventHandler::new());
    let mut txn = RocksDbTransactionBatch::new();
    for (i, eth) in eths.iter().enumerate() {
        let fid = i as u64 + 1;
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    eth.address().as_slice(),
                    IdRegisterEventType::Register,
                    1_600_000_000,
                    fid as u8,
                    0,
                ),
                &mut txn,
            )
            .unwrap();
    }
    let other = PrivateKeySigner::from_bytes(&[90u8; 32].into()).unwrap();
    for (fid, tx) in [(1000u64, 50u8), (1001, 60)] {
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    other.address().as_slice(),
                    IdRegisterEventType::Register,
                    1_600_000_000,
                    tx,
                    0,
                ),
                &mut txn,
            )
            .unwrap();
        store
            .merge_onchain_event(
                id_event(
                    fid,
                    other.address().as_slice(),
                    IdRegisterEventType::Transfer,
                    1_700_000_000,
                    tx + 1,
                    3,
                ),
                &mut txn,
            )
            .unwrap();
    }
    db.commit(txn).unwrap();
}

struct Fixture {
    eths: Vec<PrivateKeySigner>,
    file: proto::GenesisValidatorFile,
    params: Shard0Params,
    shard_forks: Vec<ShardForkPoint>,
}

fn fixture() -> Fixture {
    let eths: Vec<PrivateKeySigner> = (1..=4u8)
        .map(|i| PrivateKeySigner::from_bytes(&[i + 10; 32].into()).unwrap())
        .collect();
    let validators: Vec<Validator> = eths
        .iter()
        .enumerate()
        .map(|(i, e)| validator(i as u64 + 1, e))
        .collect();
    let file = genesis_file::assemble(
        validators.iter().rev().map(|v| v.entry.clone()).collect(),
        FarcasterNetwork::Devnet,
    )
    .unwrap();
    let mut params = params();
    params.epochs.pivot_height_0 = PIVOT;
    params.min_validator_fid_age_secs = 90 * 24 * 3600;
    params.exempt_recoveries = vec![(1000, [51u8; 32])];
    let shard_forks = vec![
        ShardForkPoint {
            shard_id: 1,
            fork_height: 50,
            chunk_hash: vec![1u8; 32],
        },
        ShardForkPoint {
            shard_id: 2,
            fork_height: 60,
            chunk_hash: vec![2u8; 32],
        },
    ];
    Fixture {
        eths,
        file,
        params,
        shard_forks,
    }
}

struct Node {
    _dir: tempfile::TempDir,
    shard0: Arc<RocksDB>,
    social: BTreeMap<u32, Arc<RocksDB>>,
    /// Every consensus-prefix (k, v) BEFORE the genesis build.
    consensus_before: Vec<(Vec<u8>, Vec<u8>)>,
    /// Every prefix-83 (k, v) BEFORE the genesis build.
    p83_before: Vec<(Vec<u8>, Vec<u8>)>,
    record: Option<PivotRecord>,
}

fn scan_prefix(db: &RocksDB, p: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    db.for_each_iterator_by_prefix(
        Some(vec![p]),
        Some(vec![p + 1]),
        &PageOptions::default(),
        |k, v| {
            out.push((k.to_vec(), v.to_vec()));
            Ok(false)
        },
    )
    .unwrap();
    out
}

fn consensus_dump(db: &RocksDB) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for p in 0u8..255 {
        if keys::is_shard0_consensus_prefix(p) {
            out.extend(scan_prefix(db, p));
        }
    }
    out
}

/// Epoch-0 state, then `prep` (the node-local history), then optionally the
/// production `build_genesis`.
fn make_node(f: &Fixture, build: bool, prep: impl FnOnce(&Arc<RocksDB>)) -> Node {
    let dir = tempfile::TempDir::new().unwrap();
    let shard0 = open(&dir, "shard0");
    epoch0(&shard0, &f.eths);
    prep(&shard0);
    let social: BTreeMap<u32, Arc<RocksDB>> =
        [(1u32, open(&dir, "s1")), (2u32, open(&dir, "s2"))]
            .into_iter()
            .collect();
    let consensus_before = consensus_dump(&shard0);
    let p83_before = scan_prefix(&shard0, P83);
    let record = if build {
        let inputs = PivotInputs {
            params: &f.params,
            pivot_height: PIVOT,
            fork_block_hash: FORK_HASH,
            fork_timestamp: FORK_TS,
            shard_forks: f.shard_forks.clone(),
            shard_roots: [(1u32, [1u8; 32]), (2u32, [2u8; 32])].into_iter().collect(),
            genesis_file: &f.file,
            fname_cursor: 0,
            social: social.clone(),
        };
        Some(build_genesis(&shard0, &inputs).unwrap())
    } else {
        None
    };
    Node {
        _dir: dir,
        shard0,
        social,
        consensus_before,
        p83_before,
        record,
    }
}

/// What the merge path writes for `n` distinct users authorised by APP_FID.
fn inc_users(db: &Arc<RocksDB>, range: std::ops::RangeInclusive<u64>) {
    let mut txn = RocksDbTransactionBatch::new();
    for user in range {
        signer_auth_index::inc(db, &mut txn, APP_FID, USER_BASE + user).unwrap();
    }
    db.commit(txn).unwrap();
}

fn pivot_block_on(a: &Node, b: &Node, f: &Fixture) -> Result<(), String> {
    let parent = ParentInfo {
        height: PIVOT - 1,
        hash: FORK_HASH,
        timestamp: FORK_TS,
        epoch_ref_height: None,
        shard_links: vec![],
    };
    let mut ea = Shard0Engine::new(a.shard0.clone(), f.params.clone(), parent.clone()).unwrap();
    let mut eb = Shard0Engine::new(b.shard0.clone(), f.params.clone(), parent).unwrap();
    let links = vec![
        ShardLink {
            shard_id: 1,
            height: 50,
            block_hash: vec![1u8; 32],
            state_root: vec![1u8; 32],
        },
        ShardLink {
            shard_id: 2,
            height: 60,
            block_hash: vec![2u8; 32],
            state_root: vec![2u8; 32],
        },
    ];
    let block = ea
        .propose(
            &TestInputs {
                pivot: a.record.clone(),
                ..Default::default()
            },
            Shard0Proposal {
                timestamp: FORK_TS + 12,
                shard_links: links,
                ..Default::default()
            },
        )
        .unwrap();
    eb.validate(
        &block,
        &TestInputs {
            pivot: b.record.clone(),
            ..Default::default()
        },
        None,
        u64::MAX,
    )
    .map(|_| ())
    .map_err(|e| format!("{e} / {e:?}"))
}

fn eligibility_of(trust: &[proto::ScoredFid], fid: u64) -> Option<u32> {
    trust.iter().find(|t| t.fid == fid).map(|t| t.eligibility)
}

fn now_unix() -> u64 {
    FORK_TS + crate::core::types::FARCASTER_EPOCH / 1000
}

fn scoring_on(node: &Node, f: &Fixture, epoch: u64) -> proto::ScoringResult {
    let reader = crate::chain::scoring::HypersnapReader::new(
        node.shard0.clone(),
        node.social.clone(),
        f.params.clone(),
        proto::HyperValidatorSetRecord::default(),
    )
    .unwrap();
    let mut sp = proof_of_quality::ScoringParams::default();
    sp.market_budgets = BTreeMap::new();
    crate::chain::scoring::compute(&reader, epoch, now_unix(), &sp).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Headline: 100 prefix-83 users on node B only -> the genesis diverges and B
/// rejects A's pivot block with "PivotRecord differs".
#[test]
fn f046_prefix83_divergence_splits_genesis_and_rejects_pivot_block() {
    let f = fixture();
    let a = make_node(&f, true, |_| {});
    let b = make_node(&f, true, |db| inc_users(db, 1..=100));

    // Consensus inputs equal before the build; only prefix 83 differs.
    assert_eq!(a.consensus_before, b.consensus_before, "consensus prefixes equal");
    assert!(!keys::is_shard0_consensus_prefix(P83), "83 is node-local");
    assert_eq!(a.p83_before.len(), 0);
    assert_eq!(b.p83_before.len(), 100);

    let ra = a.record.clone().unwrap();
    let rb = b.record.clone().unwrap();
    assert_ne!(ra.trust_snapshot_root, rb.trust_snapshot_root);
    assert_ne!(ra.genesis_state_roots[0], rb.genesis_state_roots[0]);
    assert_ne!(ra, rb);
    let diff = record_differences(&rb, &ra);
    println!("F046 headline: record_differences(B, A) = {:?}", diff);
    assert!(diff.iter().any(|d| d == "trust_snapshot_root"));
    assert!(diff.iter().any(|d| d == "genesis_state_roots"));

    // The eligibility consensus key of FID 1000 differs on the built DBs.
    let ea = a.shard0.get(&keys::eligibility(APP_FID)).unwrap();
    let eb = b.shard0.get(&keys::eligibility(APP_FID)).unwrap();
    println!("F046 headline: eligibility(1000) A = {:?}, B = {:?}", ea, eb);
    assert_ne!(ea, eb);

    // Pivot vote: B validates A's pivot block against its own record.
    let err = pivot_block_on(&a, &b, &f).unwrap_err();
    println!("F046 headline: B.validate(A's pivot block) -> Err({})", err);
    assert!(err.contains("PivotRecord differs"));
    // And symmetrically.
    let err2 = pivot_block_on(&b, &a, &f).unwrap_err();
    assert!(err2.contains("PivotRecord differs"));
}

/// Directly: `write_trust_snapshot` on fresh copies -> F0 bit of FID 1000.
#[test]
fn f046_trust_snapshot_f0_bit_flips() {
    let f = fixture();
    let a = make_node(&f, false, |_| {});
    let b = make_node(&f, false, |db| inc_users(db, 1..=100));
    let ta = pivot::write_trust_snapshot(&a.shard0, &f.params, a.social.clone(), now_unix())
        .unwrap();
    let tb = pivot::write_trust_snapshot(&b.shard0, &f.params, b.social.clone(), now_unix())
        .unwrap();
    let ma = eligibility_of(&ta, APP_FID);
    let mb = eligibility_of(&tb, APP_FID);
    println!(
        "F046 direct: FID 1000 eligibility mask A = {:?}, B = {:?}; roots A = {}, B = {}",
        ma,
        mb,
        hex::encode(pivot::trust_snapshot_root(&ta)),
        hex::encode(pivot::trust_snapshot_root(&tb))
    );
    assert_eq!(ma.unwrap_or(0) & 1, 1, "A: F0 passes (not an app)");
    assert_eq!(mb.unwrap_or(0) & 1, 0, "B: F0 trips (app)");
    assert_ne!(pivot::trust_snapshot_root(&ta), pivot::trust_snapshot_root(&tb));
}

/// Control 1: no increments -> identical records, B accepts A's pivot block.
#[test]
fn f046_control_no_increments_records_equal() {
    let f = fixture();
    let a = make_node(&f, true, |_| {});
    let b = make_node(&f, true, |_| {});
    assert_eq!(a.p83_before, b.p83_before);
    assert_eq!(a.record, b.record);
    assert!(record_differences(b.record.as_ref().unwrap(), a.record.as_ref().unwrap()).is_empty());
    pivot_block_on(&a, &b, &f).unwrap();
    println!("F046 control (no inc): records equal, B accepts A's pivot block");
}

/// Control 2: 99 users (below app_threshold) -> records equal although the
/// prefix-83 contents differ; the pivot vote passes. Then a 100th user on B
/// only makes the later `ScoringResult` diverge (latent post-pivot split).
#[test]
fn f046_control_99_users_equal_record_then_latent_scoring_split() {
    let f = fixture();
    let a = make_node(&f, true, |_| {});
    let b = make_node(&f, true, |db| inc_users(db, 1..=99));
    assert_eq!(a.consensus_before, b.consensus_before);
    assert_ne!(a.p83_before, b.p83_before, "prefix 83 differs (0 vs 99)");
    assert_eq!(b.p83_before.len(), 99);
    assert_eq!(a.record, b.record, "99 users: same PivotRecord");
    pivot_block_on(&a, &b, &f).unwrap();
    println!("F046 control (99): records equal, pivot block accepted, p83 A=0 B=99");

    // Post-pivot: identical scoring while below the threshold ...
    assert_eq!(scoring_on(&a, &f, 1), scoring_on(&b, &f, 1));
    // ... a 100th user authorised by FID 1000, observed only by B's index.
    inc_users(&b.shard0, 100..=100);
    let sa = scoring_on(&a, &f, 1);
    let sb = scoring_on(&b, &f, 1);
    let ma = eligibility_of(&sa.trust, APP_FID);
    let mb = eligibility_of(&sb.trust, APP_FID);
    println!(
        "F046 latent split: after 100th user on B only, ScoringResult equal = {}; FID 1000 mask A = {:?}, B = {:?}",
        sa == sb,
        ma,
        mb
    );
    assert_ne!(sa, sb, "ScoringResult diverges at a later scoring height");
}

// ---------------------------------------------------------------------------
// Step 7 (realistic variant): real `merge_onchain_event` of KeyRegistry Add
// events with SignedKeyRequestMetadata{request_fid: 1000} on B; on A the same
// OnChainEvent rows with prefix 83 absent (what an upstream snapshot / older
// release holds).
// ---------------------------------------------------------------------------

fn signer_add(user: u64, request_fid: u64) -> OnChainEvent {
    use alloy_sol_types::SolValue;
    let meta = crate::connectors::onchain_events::SignedKeyRequestMetadata {
        requestFid: alloy_primitives::U256::from(request_fid),
        requestSigner: alloy_primitives::Address::repeat_byte(0x11),
        signature: vec![0u8; 65].into(),
        deadline: alloy_primitives::U256::from(1_900_000_000u64),
    };
    let mut key = vec![0u8; 32];
    key[..8].copy_from_slice(&user.to_be_bytes());
    let body = proto::SignerEventBody {
        key,
        key_type: 1,
        event_type: SignerEventType::Add as i32,
        metadata: meta.abi_encode(),
        metadata_type: 1,
    };
    assert_eq!(
        crate::connectors::onchain_events::get_request_fid_from_signer_event(&body),
        Some(request_fid)
    );
    OnChainEvent {
        r#type: proto::OnChainEventType::EventTypeSigner as i32,
        chain_id: 10,
        block_number: 800_000_000 + user as u32,
        block_timestamp: 1_650_000_000,
        transaction_hash: {
            let mut h = vec![0xabu8; 32];
            h[..8].copy_from_slice(&user.to_be_bytes());
            h
        },
        log_index: 0,
        fid: user,
        version: 1,
        body: Some(proto::on_chain_event::Body::SignerEventBody(body)),
        ..Default::default()
    }
}

fn merge_signer_adds(db: &Arc<RocksDB>, n: u64) {
    let store = OnchainEventStore::new(db.clone(), StoreEventHandler::new());
    let mut txn = RocksDbTransactionBatch::new();
    for user in 1..=n {
        store
            .merge_onchain_event(signer_add(USER_BASE + user, APP_FID), &mut txn)
            .unwrap();
    }
    db.commit(txn).unwrap();
}

fn drop_prefix83(db: &Arc<RocksDB>) {
    let mut txn = RocksDbTransactionBatch::new();
    for (k, _) in scan_prefix(db, P83) {
        txn.delete(k);
    }
    db.commit(txn).unwrap();
}

#[test]
fn f046_step7_real_signer_events_snapshot_vs_merged() {
    let f = fixture();
    // A: same signer events, prefix 83 absent (upstream snapshot / old release).
    let a = make_node(&f, true, |db| {
        merge_signer_adds(db, 100);
        drop_prefix83(db);
    });
    // B: merged through this release's `merge_onchain_event`.
    let b = make_node(&f, true, |db| merge_signer_adds(db, 100));
    let signer_rows = |n: &Node| {
        n.consensus_before
            .iter()
            .filter(|(k, _)| k[0] == RootPrefix::OnChainEvent as u8)
            .count()
    };
    println!(
        "F046 step7: OnChainEvent rows A = {}, B = {}; p83 A = {}, B = {}",
        signer_rows(&a),
        signer_rows(&b),
        a.p83_before.len(),
        b.p83_before.len()
    );
    assert_eq!(a.consensus_before, b.consensus_before, "consensus state equal");
    assert_eq!(a.p83_before.len(), 0);
    assert_eq!(b.p83_before.len(), 100);
    let ra = a.record.clone().unwrap();
    let rb = b.record.clone().unwrap();
    let diff = record_differences(&rb, &ra);
    println!("F046 step7: record_differences(B, A) = {:?}", diff);
    assert!(diff.iter().any(|d| d == "trust_snapshot_root"));
    let err = pivot_block_on(&a, &b, &f).unwrap_err();
    println!("F046 step7: B.validate(A's pivot block) -> Err({})", err);
    assert!(err.contains("PivotRecord differs"));
}
