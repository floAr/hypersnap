// F002 residual chain-halt — STRUCTURAL MODEL of the exact call graph in
// hypersnap commit 5c25945 (src/hyper/runtime.rs + slashing_store.rs).
//
// This is NOT the production binary. The production crate cannot be built
// in this environment because the transitive native dependency
// `tikv-jemalloc-sys` fails its autotools `configure` against the MSVC
// toolchain (no GNU/mingw cc available). This standalone model reproduces
// the SAME recursion structure — same control flow, same keying, same
// "_active_set_at_epoch ignored / no depth guard / no memoization" — so the
// unbounded recursion can be OBSERVED running here.
//
// Mapping to production:
//   Store::get_for_epoch(epoch)          <- SlashingEvidenceStore::get_for_epoch
//   record() keyed under min(ea,eb)      <- SlashingEvidenceStore::make_key
//   get_active_validators_enforced(E)    <- runtime.rs:4102
//      -> slashed_validators_for_epoch(E-1)         (runtime.rs:4122)
//   slashed_validators_for_epoch(epoch)  <- runtime.rs:4238
//      resolve_signers(block) reads block.sig.epoch (runtime.rs:4262)
//      and calls get_active_validators_enforced(block_epoch) (runtime.rs:4264)

use std::collections::BTreeMap;

#[derive(Clone)]
struct Block {
    sig_epoch: u64, // HyperBlockSignature.epoch
}

#[derive(Clone)]
struct Evidence {
    block_a: Block,
    block_b: Block,
}

// Mirror of SlashingEvidenceStore: rows keyed under min(epoch_a, epoch_b).
struct Store {
    rows: BTreeMap<u64, Vec<Evidence>>,
}

impl Store {
    fn new() -> Self {
        Store { rows: BTreeMap::new() }
    }
    // Mirrors record() + make_key(): persist under min(epoch_a, epoch_b).
    fn record(&mut self, epoch_a: u64, epoch_b: u64, ev: Evidence) {
        let key = epoch_a.min(epoch_b);
        self.rows.entry(key).or_default().push(ev);
    }
    // Mirrors get_for_epoch(epoch).
    fn get_for_epoch(&self, epoch: u64) -> Vec<Evidence> {
        self.rows.get(&epoch).cloned().unwrap_or_default()
    }
}

struct Runtime {
    store: Store,
}

impl Runtime {
    // Mirror of runtime.rs:4102 get_active_validators_enforced.
    // prev = epoch - 1; epoch 0 returns the bootstrap set (base case).
    fn get_active_validators_enforced(&self, epoch: u64) -> BTreeMap<Vec<u8>, ()> {
        let prev = match epoch.checked_sub(1) {
            Some(p) => p,
            None => {
                // base: compute_active_set(0) over bootstrap; no recursion.
                let mut m = BTreeMap::new();
                m.insert(vec![0x11u8; 32], ());
                m.insert(vec![0x22u8; 32], ());
                return m;
            }
        };
        // runtime.rs:4122 — read slashed set for prev (this is the cycle door).
        let _slashed = self.slashed_validators_for_epoch(prev);
        // compute_active_set_with_filter over bootstrap (no events in PoC).
        let mut m = BTreeMap::new();
        m.insert(vec![0x11u8; 32], ());
        m.insert(vec![0x22u8; 32], ());
        m
    }

    // Mirror of runtime.rs:4238 slashed_validators_for_epoch.
    // `_active_set_at_epoch` is IGNORED in production (underscore-prefixed,
    // runtime.rs:4241) — we omit it entirely, matching that it cannot break
    // the cycle.
    fn slashed_validators_for_epoch(&self, epoch: u64) -> Vec<Vec<u8>> {
        let evidence = self.store.get_for_epoch(epoch);
        let mut slashed = Vec::new();
        for ev in evidence {
            // resolve_signers(block_a) — block_a.sig.epoch == epoch here, no new cycle.
            let _sa = self.resolve_signers(&ev.block_a);
            // resolve_signers(block_b) — block_b.sig.epoch == E for cross-epoch
            // evidence, which re-enters get_active_validators_enforced(E).
            let sb = self.resolve_signers(&ev.block_b);
            slashed.extend(sb);
        }
        slashed
    }

    // Mirror of the resolve_signers closure, runtime.rs:4256-4280.
    fn resolve_signers(&self, block: &Block) -> Vec<Vec<u8>> {
        let block_epoch = block.sig_epoch; // runtime.rs:4262
        // runtime.rs:4264 — NO depth guard, NO memoization.
        let active = self.get_active_validators_enforced(block_epoch);
        active.keys().cloned().collect()
    }
}

fn run_on_small_stack(rt: Runtime, epoch: u64) -> Result<(), ()> {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || {
            let _ = rt.get_active_validators_enforced(epoch);
        })
        .expect("spawn");
    handle.join().map_err(|_| ())
}

fn main() {
    let target_e = 2u64;
    let prev_e = target_e - 1; // 1

    // ---- BENIGN control: same-epoch evidence (epoch_a == epoch_b == E-1) ----
    let mut benign_store = Store::new();
    benign_store.record(
        prev_e,
        prev_e,
        Evidence {
            block_a: Block { sig_epoch: prev_e },
            block_b: Block { sig_epoch: prev_e }, // block_b @ E-1 -> recursion ends at E-2
        },
    );
    let benign_rt = Runtime { store: benign_store };
    let benign = run_on_small_stack(benign_rt, target_e);
    println!("BENIGN (same-epoch evidence) get_active_validators_enforced({target_e}): {benign:?}");

    // ---- MALICIOUS: adjacent cross-epoch evidence (epoch_a=E-1, epoch_b=E) ----
    let mut mal_store = Store::new();
    mal_store.record(
        prev_e,
        target_e, // stored under min = E-1
        Evidence {
            block_a: Block { sig_epoch: prev_e },   // E-1
            block_b: Block { sig_epoch: target_e }, // E  -> re-enters get_active_validators_enforced(E)
        },
    );
    let mal_rt = Runtime { store: mal_store };
    let malicious = run_on_small_stack(mal_rt, target_e);
    println!("MALICIOUS (cross-epoch evidence) get_active_validators_enforced({target_e}): {malicious:?}");

    // Assertions: benign returns, malicious aborts (stack overflow).
    assert!(benign.is_ok(), "benign control must return Ok");
    assert!(
        malicious.is_err(),
        "RESIDUAL PRESENT: cross-epoch evidence must cause unbounded recursion (Err)"
    );
    println!("\nF002 residual REPRODUCED in structural model:");
    println!("  benign   -> Ok  (recursion terminates)");
    println!("  malicious-> Err (unbounded recursion -> stack overflow -> thread abort)");
}
