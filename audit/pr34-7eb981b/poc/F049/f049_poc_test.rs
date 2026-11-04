//! F049 PoC: the DA pool is never minted because `scoring::params_for`
//! leaves `ScoringParams::pivot_height_0` at the PoQ default (0).
//!
//! Fixture: a copy of `scoring::tests::a_seed_forfeit_removes_the_da_answers_of_the_epoch`
//! (RocksDB in a TempDir, two validators `a` -> FID 1001 and `b` -> FID 1002
//! in `set(2)`), with 100 DA answers each written at absolute shard-0 heights,
//! as `shard0::work::da_response` stores them.

use crate::chain::scoring::{compute, params_for, HypersnapReader};
use crate::chain::shard0::emission::{Schedule, MAINNET_RETRO_MINTED};
use crate::chain::shard0::{keys, Shard0Params};
use crate::proto;
use crate::storage::db::RocksDB;
use proof_of_quality::reader::SnapchainStateReader;
use proof_of_quality::{da_pow, epoch_boundary_height, ScoringParams};
use std::collections::BTreeMap;
use std::sync::Arc;

const NOW: u64 = 1_800_000_000;
const DA: i32 = proto::WorkMarket::DataAvailability as i32;

/// A DB with 100 answers for `a` at `b2 + off_a` and for `b` at `b2 + off_b`,
/// where `b2 = params.epochs.boundary_height(2)`, and the reader over it.
fn fixture(
    params: Shard0Params,
    off_a: u64,
    off_b: u64,
) -> (tempfile::TempDir, HypersnapReader, u64) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
    db.open().unwrap();
    let (a, b) = ([1u8; 32], [2u8; 32]);
    let b2 = params.epochs.boundary_height(2);
    let mut txn = db.txn();
    for index in 0..100 {
        txn.put(keys::da_answered(2, &a, index), keys::u64_value(b2 + off_a));
        txn.put(keys::da_answered(2, &b, index), keys::u64_value(b2 + off_b));
    }
    db.commit(txn).unwrap();
    let member = |hash: [u8; 32], fid| proto::HyperValidatorSetMember {
        consensus_key_hash: vec![fid as u8; 32],
        weight: 1,
        node_key_hash: hash.to_vec(),
        fid,
    };
    let set = proto::HyperValidatorSetRecord {
        epoch: 2,
        members: vec![member(a, 1001), member(b, 1002)],
        ..Default::default()
    };
    let reader = HypersnapReader::new(db, BTreeMap::new(), params, set).unwrap();
    (dir, reader, b2)
}

fn da_rewards(r: &proto::ScoringResult) -> BTreeMap<u64, u64> {
    r.rewards
        .iter()
        .filter(|x| x.market == DA)
        .map(|x| (x.fid, x.amount))
        .collect()
}

const P: u64 = 5_000_000;

/// Headline (RED): a real pivot at P = 5,000,000, 100/100 answers within the
/// window, and the live `params_for` scoring mints nothing in the DA market.
#[test]
fn f049_live_params_for_mints_no_da_pool() {
    let params = Shard0Params::new(proto::FarcasterNetwork::Devnet, P);
    assert_eq!(params.epochs.epoch_length, 36_000);
    let (_dir, reader, b2) = fixture(params.clone(), 2, 20);
    assert_eq!(b2, P + 36_000);

    // Reader input: raw absolute heights, no subtraction.
    let counts = reader.da_answered_counts_for_epoch(2).unwrap();
    let sums = reader.da_response_block_sum_for_epoch(2).unwrap();
    assert_eq!(counts[&1001], 100);
    assert_eq!(counts[&1002], 100);
    assert_eq!(sums[&1001], 100 * (b2 + 2) as u128);
    assert_eq!(sums[&1002], 100 * (b2 + 20) as u128);

    // Root cause: params_for never carries the pivot of the node's params.
    let schedule = Schedule::new(0);
    let live = params_for(2, &schedule);
    println!(
        "F049 headline: Shard0Params pivot = {}, params_for(2).pivot_height_0 = {}, epoch_length_blocks = {}",
        params.epochs.pivot_height_0, live.pivot_height_0, live.epoch_length_blocks
    );
    assert_eq!(live.pivot_height_0, 0);
    assert_eq!(live.pivot_height_0, ScoringParams::default().pivot_height_0);
    let scoring_boundary = epoch_boundary_height(live.pivot_height_0, 2, live.epoch_length_blocks);
    assert_eq!(scoring_boundary, 36_000);

    // Direct form: da_score is 0 for both validators.
    let s_a = da_pow::da_score_fp(100, sums[&1001], scoring_boundary, 100);
    let s_b = da_pow::da_score_fp(100, sums[&1002], scoring_boundary, 100);
    println!("F049 headline: da_score_fp(live boundary {scoring_boundary}) a = {s_a}, b = {s_b}");
    assert_eq!((s_a, s_b), (0, 0));

    // Through the production compute.
    let pools = schedule.pools(2);
    let r = compute(&reader, 2, NOW, &live).unwrap();
    let da = da_rewards(&r);
    println!(
        "F049 headline: pools(2).da = {}, ScoringResult.minted = {}, DA rows = {:?}",
        pools.da, r.minted, da
    );
    assert!(pools.da > 0);
    assert!(da.is_empty(), "no DataAvailability reward rows");
    assert!(r.minted < pools.da);
    assert_eq!(r.minted, 0);

    // The no-rollover side: the next epoch's pools are a pure function of e.
    assert_eq!(Schedule::new(0).pools(3), schedule.pools(3));

    // Mainnet-schedule magnitude (retro-minted 50M), for the README.
    let mainnet = Schedule::new(MAINNET_RETRO_MINTED);
    println!(
        "F049 headline: mainnet schedule DA pool epoch 1 = {}, epoch 2 = {} (micro-units)",
        mainnet.pools(1).da,
        mainnet.pools(2).da
    );
}

/// The bug for any P >= 25: the latency term is 0 as soon as the pivot is
/// at least one response window.
#[test]
fn f049_threshold_any_pivot_at_least_window() {
    for &(p, expect_zero) in &[(1u64, false), (24, false), (25, true), (26, true), (1_000_000, true)] {
        let params = Shard0Params::new(proto::FarcasterNetwork::Devnet, p);
        let (_dir, reader, _b2) = fixture(params, 0, 0);
        let r = compute(&reader, 2, NOW, &params_for(2, &Schedule::new(0))).unwrap();
        let da = da_rewards(&r);
        println!("F049 threshold: P = {p}, answers at boundary+0, DA rows = {da:?}");
        assert_eq!(da.is_empty(), expect_zero, "P = {p}");
    }
}

/// Control 1 (wired): the same data with `pivot_height_0 = P` mints exactly
/// the DA pool, and ranks the faster validator higher.
#[test]
fn f049_control_wired_pivot_mints_full_pool() {
    let params = Shard0Params::new(proto::FarcasterNetwork::Devnet, P);
    let (_dir, reader, b2) = fixture(params, 2, 20);
    let schedule = Schedule::new(0);
    let mut p = params_for(2, &schedule);
    p.pivot_height_0 = P;
    let boundary = epoch_boundary_height(p.pivot_height_0, 2, p.epoch_length_blocks);
    assert_eq!(boundary, b2);
    assert_eq!(da_pow::da_score_fp(100, 100 * (b2 + 2) as u128, boundary, 100), 920_000);
    assert_eq!(da_pow::da_score_fp(100, 100 * (b2 + 20) as u128, boundary, 100), 200_000);

    let r = compute(&reader, 2, NOW, &p).unwrap();
    let da = da_rewards(&r);
    let pool = schedule.pools(2).da;
    println!("F049 control 1: pivot wired, pools(2).da = {pool}, DA rows = {da:?}, minted = {}", r.minted);
    assert_eq!(da.len(), 2);
    assert_eq!(da.values().sum::<u64>(), pool);
    assert!(da[&1001] > da[&1002], "latency 0.92 vs 0.2");
    // 0.92 / 1.12 of the pool, within rounding.
    let expect_a = (pool as u128 * 920 / 1120) as u64;
    assert!(da[&1001].abs_diff(expect_a) <= 1, "{} vs {}", da[&1001], expect_a);
}

/// Control 2 (masking): the devnet-harness shape (pivot 1, epoch_length 20).
/// All heights are below the scoring boundary 36,000, so saturating_sub gives
/// offset 0 and latency 1.0: the market is non-empty and the latency ranking
/// is hidden.
#[test]
fn f049_control_devnet_shape_masks_bug_and_ranking() {
    let mut params = Shard0Params::new(proto::FarcasterNetwork::Devnet, 1);
    params.epochs.epoch_length = 20;
    let (_dir, reader, b2) = fixture(params, 2, 20);
    assert_eq!(b2, 21);
    let schedule = Schedule::new(0);
    let r = compute(&reader, 2, NOW, &params_for(2, &schedule)).unwrap();
    let da = da_rewards(&r);
    println!("F049 control 2: devnet shape, heights {}..{}, DA rows = {da:?}", b2 + 2, b2 + 20);
    assert_eq!(da.len(), 2);
    assert_eq!(da.values().sum::<u64>(), schedule.pools(2).da);
    assert!(da[&1001].abs_diff(da[&1002]) <= 1, "equal shares: ranking masked");
}
