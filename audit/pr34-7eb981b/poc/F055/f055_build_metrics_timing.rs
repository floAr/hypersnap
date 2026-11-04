//! F055 timing PoC: `build_metrics` runs `fids.contains(&k)` (a linear scan
//! of the sorted universe Vec) once per first-30-day engagement edge, in a
//! serial loop (`crates/proof-of-quality/src/metrics.rs:293-300`).
//!
//! Integration test of the `proof-of-quality` crate. It is placed at
//! `crates/proof-of-quality/tests/f055_build_metrics_timing.rs` in the WSL
//! build tree; no crate source is modified.
//!
//! Method: one `InMemoryReader` with a universe of N FIDs (default
//! 3,357,387 = OP mainnet `IdRegistry.idCounter()`, as in poc/F019). For each
//! configuration, S source FIDs get T edges each (E = S*T edges). Every
//! configuration is timed twice with identical edges:
//!   * `first_30d = 1` (the `contains` scan runs for every edge), and
//!   * control `first_30d = 0, later = 1` (the filter short-circuits on
//!     `c.first_30d > 0` before `fids.contains`, everything else identical).
//! The difference is the cost of the linear scan; divided by E it is the
//! per-edge cost.
//!
//! Env: F055_N (universe size), F055_CONFIGS = "mode:edges,mode:edges,..."
//! with mode in {high, uniform, low, absent}.

use proof_of_quality::metrics::build_metrics;
use proof_of_quality::reader::EngagementCount;
use proof_of_quality::InMemoryReader;
use std::collections::BTreeMap;
use std::time::Instant;

const SOURCES: u64 = 1_000;

fn targets(mode: &str, n: u64, per_source: u64, s: u64) -> Vec<u64> {
    match mode {
        // Attacker case: new FIDs engaging with each other, i.e. targets at
        // the top of the FID range (rank ~ N, so ~N compares per edge).
        "high" => (0..per_source).map(|j| n - SOURCES - j).collect(),
        // Targets spread over the universe (rank ~ N/2 on average).
        "uniform" => (0..per_source)
            .map(|j| {
                let x = (s.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ j.wrapping_mul(0xBF58_476D_1CE4_E5B9))
                    .wrapping_mul(0x94D0_49BB_1331_11EB);
                1 + (x % (n - 1))
            })
            .collect(),
        // Popular old accounts (low FIDs, rank small, scan stops early).
        "low" => (1..=per_source).collect(),
        // Targets outside the universe: full scan, never found.
        "absent" => (0..per_source).map(|j| n + 1 + j).collect(),
        other => panic!("unknown mode {other}"),
    }
}

fn fill(r: &mut InMemoryReader, mode: &str, n: u64, edges: u64, first: bool) {
    r.engagement.clear();
    let per_source = edges / SOURCES;
    for i in 0..SOURCES {
        let s = n - i; // sources: the newest FIDs
        let mut m = BTreeMap::new();
        for t in targets(mode, n, per_source, s) {
            if t == s {
                continue;
            }
            let c = if first {
                EngagementCount { first_30d: 1, later: 0 }
            } else {
                EngagementCount { first_30d: 0, later: 1 }
            };
            m.insert(t, c);
        }
        r.engagement.insert(s, m);
    }
}

fn count_edges(r: &InMemoryReader) -> u64 {
    r.engagement.values().map(|m| m.len() as u64).sum()
}

#[test]
fn f055_build_metrics_contains_timing() {
    let n: u64 = std::env::var("F055_N").ok().and_then(|v| v.parse().ok()).unwrap_or(3_357_387);
    let configs = std::env::var("F055_CONFIGS").unwrap_or_else(|_| "high:10000".to_string());
    let now = 1_800_000_000u64;

    let t0 = Instant::now();
    let mut r = InMemoryReader::new();
    for fid in 1..=n {
        r.add_fid(fid, now - 400 * 86_400);
    }
    println!("F055 universe N={} built in {:.1}s", n, t0.elapsed().as_secs_f64());

    for cfg in configs.split(',') {
        let (mode, e) = cfg.split_once(':').expect("mode:edges");
        let e: u64 = e.parse().unwrap();

        fill(&mut r, mode, n, e, false);
        let edges_ctrl = count_edges(&r);
        let t = Instant::now();
        let m = build_metrics(&r, now).unwrap();
        let ctrl = t.elapsed().as_secs_f64();
        let found_ctrl: usize = m.values().map(|x| x.outbound_first_30d.len()).sum();
        drop(m);

        fill(&mut r, mode, n, e, true);
        let edges = count_edges(&r);
        let t = Instant::now();
        let m = build_metrics(&r, now).unwrap();
        let hot = t.elapsed().as_secs_f64();
        let found: usize = m.values().map(|x| x.outbound_first_30d.len()).sum();
        drop(m);

        assert_eq!(edges, edges_ctrl);
        assert_eq!(found_ctrl, 0);
        if mode != "absent" {
            assert_eq!(found as u64, edges, "every in-universe first-30d edge is kept");
        } else {
            assert_eq!(found, 0);
        }
        let delta = hot - ctrl;
        println!(
            "F055 mode={} N={} edges={} first30d_run={:.2}s control_run={:.2}s scan_cost={:.2}s per_edge={:.3}ms kept={}",
            mode, n, edges, hot, ctrl, delta, delta * 1000.0 / edges as f64, found
        );
    }
}
