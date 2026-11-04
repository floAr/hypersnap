//! F019 PoC: the shard-0 `ScoringResult` exceeds `MAX_BLOCK_BYTES` at the
//! mainnet FID count. Wired as `#[cfg(test)] mod f019_poc_test;` in
//! `src/chain/mod.rs`.

use crate::chain::block::{self, BlockError, MAX_BLOCK_BYTES};
use crate::chain::scoring;
use crate::proto::{
    self, hypersnap_system_message::Message as Sys, HypersnapBlock, HypersnapBlockHeader,
    HypersnapSystemMessage, ScoredFid, ScoringResult,
};
use proof_of_quality::eligibility::{classify_one, compute_thresholds};
use proof_of_quality::metrics::FidMetrics;
use proof_of_quality::{InMemoryReader, ScoringParams};
use prost::Message as _;
use std::collections::BTreeMap;
use std::time::Instant;

/// `IdRegistry.idCounter()` on OP mainnet (coordinator addendum, F019 validation).
const MAINNET_FIDS: u64 = 3_357_387;
const NOW_UNIX: u64 = 1_780_000_000;
const DAY: u64 = 86_400;

/// The mask `classify_one` yields for a zero-activity FID under the real
/// default params, with thresholds computed by the real `compute_thresholds`
/// over a population of zero-activity FIDs.
fn zero_activity_mask() -> u32 {
    let params = ScoringParams::default();
    let p = &params.eligibility;
    let metrics: BTreeMap<u64, FidMetrics> =
        (1..=1_000u64).map(|f| (f, FidMetrics::new(f))).collect();
    let t = compute_thresholds(&metrics, p);
    let e = classify_one(&FidMetrics::new(1), p, &t);
    // Same mask with all-zero (default) thresholds, for robustness.
    let e0 = classify_one(&FidMetrics::new(1), p, &Default::default());
    println!(
        "F019: zero-activity mask = {:#04x} (thresholds from zero cohort: {:?}); with default thresholds = {:#04x}",
        e.0, t, e0.0
    );
    e.0 as u32
}

fn trust_only_result(n: u64, mask: u32) -> ScoringResult {
    ScoringResult {
        epoch: 1,
        trust: (1..=n)
            .map(|fid| ScoredFid {
                fid,
                trust_fp: 0,
                eligibility: mask,
            })
            .collect(),
        rewards: vec![],
        vouches: vec![],
        minted: 0,
    }
}

fn shard0_block_with(result: ScoringResult) -> HypersnapBlock {
    let mut b = HypersnapBlock {
        header: Some(HypersnapBlockHeader {
            shard_id: 0,
            height: 1,
            timestamp: 1,
            ..Default::default()
        }),
        system_messages: vec![HypersnapSystemMessage {
            message: Some(Sys::ScoringResult(result)),
        }],
        ..Default::default()
    };
    block::seal(&mut b);
    b
}

/// Level 1 + 3: the trust-only `ScoringResult` at the mainnet FID count, and a
/// sealed shard-0 block carrying it, which `validate_body` rejects.
#[test]
fn f019_mainnet_scoring_result_exceeds_max_block_bytes() {
    let mask = zero_activity_mask();
    assert_ne!(mask, 0, "zero-activity FIDs would be filtered out");

    let t0 = Instant::now();
    let result = trust_only_result(MAINNET_FIDS, mask);
    let size = result.encoded_len();
    let sys_len = HypersnapSystemMessage {
        message: Some(Sys::ScoringResult(result.clone())),
    }
    .encoded_len();
    println!(
        "F019: N={} trust entries, ScoringResult.encoded_len() = {} B ({:.2} MiB); MAX_BLOCK_BYTES = {} B; ratio = {:.3}x; built in {:?}",
        MAINNET_FIDS,
        size,
        size as f64 / (1024.0 * 1024.0),
        MAX_BLOCK_BYTES,
        size as f64 / MAX_BLOCK_BYTES as f64,
        t0.elapsed()
    );
    println!("F019: HypersnapSystemMessage(ScoringResult).encoded_len() = {} B", sys_len);
    assert!(size > MAX_BLOCK_BYTES);

    // The proposer's budget (engine.rs:747-757): room saturates to 0.
    let reserve = crate::chain::shard0::engine::BLOCK_RESERVE_BYTES;
    let room = MAX_BLOCK_BYTES.saturating_sub(reserve + sys_len + 5);
    println!("F019: proposer room = MAX_BLOCK_BYTES.saturating_sub({} + field_len(sys)) = {}", reserve, room);
    assert_eq!(room, 0);

    // Smallest N at which the trust list alone crosses the limit.
    let mut lo = 1u64;
    let mut hi = MAINNET_FIDS;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let b = shard0_block_with(trust_only_result(mid, mask)).encoded_len();
        if b > MAX_BLOCK_BYTES {
            hi = mid
        } else {
            lo = mid + 1
        }
    }
    println!("F019: smallest N (FIDs 1..=N) whose shard-0 block exceeds MAX_BLOCK_BYTES = {}", lo);

    let blk = shard0_block_with(result);
    let blen = blk.encoded_len();
    let v = block::validate_body(&blk);
    println!("F019: sealed shard-0 block encoded_len = {} B; validate_body = {:?}", blen, v);
    assert_eq!(v, Err(BlockError::TooLarge(blen)));

    // Control: the same block with a small result is structurally valid.
    let small = shard0_block_with(trust_only_result(1_000, mask));
    assert_eq!(block::validate_body(&small), Ok(()));
}

fn zero_activity_reader(n: u64) -> InMemoryReader {
    let mut r = InMemoryReader::new();
    for fid in 1..=n {
        r.add_fid(fid, NOW_UNIX - 400 * DAY);
    }
    r
}

/// Level 2: the real `scoring::compute` over a synthetic zero-activity
/// universe keeps every FID, and the per-entry cost extrapolates.
#[test]
fn f019_real_compute_keeps_every_zero_activity_fid() {
    let mask = zero_activity_mask();
    for &n in &[10_000u64, 100_000] {
        let reader = zero_activity_reader(n);
        let t0 = Instant::now();
        let r = scoring::compute(&reader, 1, NOW_UNIX, &ScoringParams::default()).unwrap();
        let el = t0.elapsed();
        let nz_trust = r.trust.iter().filter(|s| s.trust_fp > 0).count();
        let masks: std::collections::BTreeSet<u32> = r.trust.iter().map(|s| s.eligibility).collect();
        let size = r.encoded_len();
        let synth = trust_only_result(n, mask).encoded_len();
        println!(
            "F019 compute: N={} -> trust.len()={} (trust_fp>0: {}), masks={:?}, rewards={}, encoded_len={} B (synthetic trust-only: {} B), {:?}",
            n,
            r.trust.len(),
            nz_trust,
            masks.iter().map(|m| format!("{:#04x}", m)).collect::<Vec<_>>(),
            r.rewards.len(),
            size,
            synth,
            el
        );
        assert_eq!(r.trust.len() as u64, n, "compute filtered some zero-activity FIDs");
        assert!(size >= synth);
    }
}

/// Level 2 (full scale): run the real `scoring::compute` at the mainnet FID
/// count. Ignored by default (slow); run with `--ignored`.
#[test]
#[ignore]
fn f019_real_compute_at_mainnet_scale() {
    let reader = zero_activity_reader(MAINNET_FIDS);
    let t0 = Instant::now();
    let r = scoring::compute(&reader, 1, NOW_UNIX, &ScoringParams::default()).unwrap();
    let el = t0.elapsed();
    let size = r.encoded_len();
    let nz_trust = r.trust.iter().filter(|s| s.trust_fp > 0).count();
    println!(
        "F019 compute full: N={} -> trust.len()={} (trust_fp>0: {}), rewards={}, encoded_len={} B ({:.2} MiB) in {:?}",
        MAINNET_FIDS,
        r.trust.len(),
        nz_trust,
        r.rewards.len(),
        size,
        size as f64 / (1024.0 * 1024.0),
        el
    );
    assert!(size > MAX_BLOCK_BYTES);
    let blk = shard0_block_with(r);
    let blen = blk.encoded_len();
    let v = block::validate_body(&blk);
    println!("F019 compute full: shard-0 block encoded_len = {} B; validate_body = {:?}", blen, v);
    assert_eq!(v, Err(BlockError::TooLarge(blen)));
}
