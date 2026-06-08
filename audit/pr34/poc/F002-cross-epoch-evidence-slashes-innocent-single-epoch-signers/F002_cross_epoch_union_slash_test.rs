// ============================================================================
// Finding:  F002 — F026 cross-epoch evidence slashes innocent validators who
//           signed only ONE of the two epochs. The cross-epoch enforcement
//           path (`slashed_validators_for_epoch`) inserts the UNION of both
//           evidence blocks' resolved signer sets into the `slashed` set,
//           with NO intersection / "signed BOTH blocks" (equivocator)
//           predicate. A validator who signed only `block_a` (epoch A) is
//           evicted for an equivocating `block_b` (epoch B) they never signed
//           and could not have prevented.
//
// Placement: this file is authored at
//   findings/tests/F002_cross_epoch_union_slash_test.rs
//   It targets:
//     - code/hypersnap/src/hyper/slashing.rs::detect_conflicting_blocks
//     - code/hypersnap/src/hyper/runtime.rs::slashed_validators_for_epoch
//       (~line 4191) and ::get_active_validators_enforced (~line 4055)
//     - code/hypersnap/src/hyper/slashing_store.rs (record / get_for_epoch)
//   It exercises the REAL evidence types (`ConflictingBlocksEvidence`,
//   `detect_conflicting_blocks`) and the REAL enforcement reader on a live
//   `HyperRuntime`. To run it in-tree, drop the two `#[test]` fns (and the
//   `make_block` helper) into the existing `#[cfg(test)] mod tests` block of
//   `runtime.rs` — it relies on that module's `use super::*;`, the
//   `make_runtime()` fixture, and `tempfile::TempDir`. It is kept here,
//   READ-ONLY w.r.t. `code/`, as the regression artifact for F002.
//
// Assertion (SECURE behavior):
//   1. `cross_epoch_slash_uses_intersection_not_union` — given evidence of two
//      blocks at the SAME `canonical_block_id` with DIFFERENT epoch tags
//      (epoch_a != epoch_b) where `block_a` is signed only by validator V
//      (signer index 1) and `block_b` only by validator W (signer index 2) —
//      i.e. DISJOINT signer sets, no validator equivocated — the enforced
//      `slashed` set must be EMPTY. A validator who signed only ONE of the two
//      blocks did not double-sign and must NOT be slashed; only the
//      intersection (true equivocators) is slashable.
//
//   2. `cross_epoch_enforcement_no_infinite_recursion` (optional, #[ignore]d) —
//      `slashed_validators_for_epoch` must TERMINATE on genuine cross-epoch
//      evidence whose `block_b.epoch == queried_epoch + 1` (the H6 recursion
//      the validator flagged). Run under a watchdog thread; a non-returning
//      call (stack overflow / hang) is the failure.
//
// Expected result:
//   FAILS on `cab225f`  — `slashed_validators_for_epoch` (runtime.rs:4199-4226)
//                         iterates BOTH `ev.block_a` and `ev.block_b` and
//                         inserts every resolved signer key into one `slashed`
//                         BTreeSet — the UNION. V (block_a-only) and W
//                         (block_b-only) are BOTH inserted though neither
//                         equivocated, so the "empty slashed set" assertion in
//                         test 1 fails. Test 2 self-recurses to a stack
//                         overflow and never returns.
//   PASSES after fix    — once the cross-epoch path slashes only the
//                         INTERSECTION (validator keys present in BOTH blocks'
//                         resolved signer sets) and the self-recursion is
//                         broken, the disjoint-signer evidence slashes nobody
//                         (test 1) and enforcement terminates (test 2).
//
// VALIDATOR NOTE (HAS_CAVEATS / 0.72; see findings/notes/F002-validation.md):
//   The union-not-intersection defect is REAL and production-wired (the
//   `slashed` set feeds proposer selection / DKLS resolution via
//   `get_active_validators_enforced`). Two caveats shape this test:
//   (H1) Manufacturing `block_b` requires a VALID epoch-B threshold signature,
//        i.e. epoch-B committee collusion — this test isolates the ENFORCEMENT
//        set-semantics defect and does not re-assert the signature gate, which
//        `verify_evidence_signatures` covers.
//   (H6/H8) The headline cross-epoch PoC ("V silently evicted at the epoch-6
//        boundary") does NOT reproduce verbatim because `block_b.epoch ==
//        prev+1` triggers unbounded self-recursion before the function
//        returns. Test 1 therefore deliberately uses NON-adjacent epoch tags
//        (epoch_a=5, epoch_b=9, stored under min=5, neither == 5+1) so the
//        union defect is demonstrated in isolation WITHOUT tripping the
//        recursion; test 2 isolates the recursion separately.
//
// STATUS: UNVERIFIED
// ============================================================================

use super::*;

/// Build a `HyperBlock` with caller-controlled height, epoch, and
/// `signer_indices`. Mirrors the in-tree `slashing.rs::tests::make_block` and
/// `slashing_store.rs::tests::block` fixtures; extended so the caller controls
/// `signer_indices` (which is what the enforcement reader resolves against the
/// per-epoch active set).
fn make_block(
    height: u64,
    epoch: u64,
    signer_indices: Vec<u64>,
    state_root: Vec<u8>,
) -> crate::hyper::HyperBlock {
    crate::hyper::HyperBlock {
        envelope: crate::hyper::HyperEnvelope {
            metadata: crate::hyper::HyperBlockMetadata {
                canonical_block_id: height,
                parent_hash: vec![0u8; 32],
                hyper_state_root: state_root,
                extra_rules_version: 0,
                retained_message_count: 0,
                missed_proposals: vec![],
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_range_start_block: 0,
                snapchain_range_root: vec![],
                snapchain_anchor_timestamp: 0,
            },
            payload: vec![],
        },
        signature: crate::hyper::HyperBlockSignature {
            epoch,
            signer_indices,
            group_address: Vec::new(),
            ecdsa_signature: Vec::new(),
        },
    }
}

/// SECURE behavior: cross-epoch evidence whose two blocks have DISJOINT signer
/// sets (V signed only block_a, W signed only block_b) proves that NO single
/// validator equivocated. The enforced slashed set must be EMPTY — only the
/// intersection (validators that signed BOTH conflicting blocks) is slashable.
///
/// On `cab225f` the enforcement reader takes the UNION of both blocks' resolved
/// signer sets, so both V and W are slashed though neither double-signed; this
/// assertion FAILS. After the intersection fix it PASSES.
#[test]
fn cross_epoch_slash_uses_intersection_not_union() {
    let (mut rt, _dir) = make_runtime();

    // Three distinct validator keys. The active-set reader enumerates the
    // BTreeMap in key order, assigning 1-based signer indices: index 1 -> V,
    // index 2 -> W, index 3 -> U. The bootstrap set is returned identically
    // for every epoch (compute_active_set adds/removes only registry events,
    // and we seed none), so the same key ordering resolves at epoch_a and
    // epoch_b — letting us model "V signed block_a, W signed block_b" purely
    // via signer_indices.
    let vk_v = vec![0x01u8; 32]; // signer index 1
    let vk_w = vec![0x02u8; 32]; // signer index 2
    let vk_u = vec![0x03u8; 32]; // signer index 3 (signed neither)
    rt.bootstrap_validators = vec![
        (vk_v.clone(), vec![0u8; 48], vec![0u8; 32]),
        (vk_w.clone(), vec![0u8; 48], vec![0u8; 32]),
        (vk_u.clone(), vec![0u8; 48], vec![0u8; 32]),
    ];

    // Cross-epoch conflict at the same canonical height H=10.
    //   epoch_a = 5  -> block_a, signed ONLY by V (signer index 1)
    //   epoch_b = 9  -> block_b, signed ONLY by W (signer index 2)
    // Non-adjacent epoch tags (9 != 5+1) so the enforcement reader does NOT
    // self-recurse (see header / validation H6); the evidence is persisted
    // under min(5,9) = 5.
    let epoch_a = 5u64;
    let epoch_b = 9u64;
    let height = 10u64;
    let block_a = make_block(height, epoch_a, vec![1], vec![0xaa; 48]); // V
    let block_b = make_block(height, epoch_b, vec![2], vec![0xbb; 48]); // W

    // Real detection + persistence path.
    let evidence = crate::hyper::slashing::detect_conflicting_blocks(&block_a, &block_b)
        .expect("cross-epoch conflict is accepted evidence on cab225f");
    assert_eq!(evidence.epoch_a, epoch_a);
    assert_eq!(evidence.epoch_b, epoch_b);
    rt.record_evidence(&evidence)
        .expect("evidence persists to the slashing store");

    // Evidence is keyed under the lower epoch tag (min(5,9) = 5).
    let stored = rt.evidence_for_epoch(5).expect("read persisted evidence");
    assert_eq!(stored.len(), 1, "fixture invariant: one evidence row at epoch 5");

    // Enforced active set at epoch_a, used by the reader to resolve indices.
    let active = rt
        .validator_registry
        .compute_active_set(epoch_a, &rt.bootstrap_validators)
        .expect("active set at epoch_a");

    // The enforcement reader. SECURE: nobody equivocated (disjoint signer
    // sets), so the slashed set is the (empty) intersection.
    let slashed = rt
        .slashed_validators_for_epoch(5, &active)
        .expect("slashed_validators_for_epoch must return");

    assert!(
        !slashed.contains(&vk_v),
        "SECURE: V signed ONLY block_a (epoch {epoch_a}) and never signed \
         block_b (epoch {epoch_b}); V did not equivocate and must NOT be \
         slashed. On cab225f the enforcement path slashes the UNION of both \
         blocks' signers (runtime.rs:4199-4226), so V is wrongly evicted.",
    );
    assert!(
        !slashed.contains(&vk_w),
        "SECURE: W signed ONLY block_b (epoch {epoch_b}) and never signed \
         block_a (epoch {epoch_a}); W did not equivocate and must NOT be \
         slashed.",
    );
    assert!(
        slashed.is_empty(),
        "SECURE: with DISJOINT signer sets no validator double-signed, so the \
         intersection (true equivocators) is empty and the slashed set must be \
         empty. Got {slashed:?} on cab225f — the union of two disjoint \
         committees is slashed instead of the intersection.",
    );
}

/// SECURE behavior: enforcement must TERMINATE on genuine cross-epoch evidence
/// where `block_b.epoch == queried_epoch + 1` (epoch_a=5, epoch_b=6, queried at
/// 5). On `cab225f`, `slashed_validators_for_epoch(5)` resolves block_b against
/// `get_active_validators_enforced(6)`, which calls `slashed_validators_for_epoch(5)`
/// again — re-reading the same evidence and re-entering block_b — an unbounded
/// self-recursion (validator H6). The function never returns; the headline
/// false-slash PoC stack-overflows instead.
///
/// Marked `#[ignore]` by default: a true stack overflow aborts the whole test
/// binary (uncatchable), which would take the rest of the suite with it. Run
/// explicitly with `cargo test cross_epoch_enforcement_no_infinite_recursion
/// -- --ignored`. The watchdog treats a non-return within the budget as the
/// failure signal.
#[test]
#[ignore = "F002 H6 recursion: aborts the binary on cab225f via stack overflow; run with --ignored"]
fn cross_epoch_enforcement_no_infinite_recursion() {
    use std::sync::mpsc;
    use std::time::Duration;

    let vk_v = vec![0x01u8; 32];
    let vk_w = vec![0x02u8; 32];

    let (tx, rx) = mpsc::channel::<()>();
    let worker = std::thread::Builder::new()
        // Small, bounded stack so runaway recursion fails fast rather than
        // thrashing — the watchdog timeout is the primary guard.
        .stack_size(1 << 20)
        .spawn(move || {
            let (mut rt, _dir) = make_runtime();
            rt.bootstrap_validators = vec![
                (vk_v.clone(), vec![0u8; 48], vec![0u8; 32]),
                (vk_w.clone(), vec![0u8; 48], vec![0u8; 32]),
            ];
            // Adjacent epoch tags: block_b.epoch (6) == queried_epoch (5) + 1.
            let block_a = make_block(10, 5, vec![1], vec![0xaa; 48]);
            let block_b = make_block(10, 6, vec![2], vec![0xbb; 48]);
            let evidence =
                crate::hyper::slashing::detect_conflicting_blocks(&block_a, &block_b).unwrap();
            rt.record_evidence(&evidence).unwrap();
            let active = rt
                .validator_registry
                .compute_active_set(5, &rt.bootstrap_validators)
                .unwrap();
            // On cab225f this never returns (infinite self-recursion).
            let _ = rt.slashed_validators_for_epoch(5, &active);
            let _ = tx.send(());
        })
        .expect("spawn worker");

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {
            worker.join().expect("worker thread joined");
        }
        Err(_) => panic!(
            "SECURE: slashed_validators_for_epoch must TERMINATE on cross-epoch \
             evidence whose block_b.epoch == queried_epoch + 1. It did not \
             return within the watchdog budget — the H6 self-recursion \
             (get_active_validators_enforced(6) -> slashed_validators_for_epoch(5) \
             -> ...) is present on cab225f.",
        ),
    }
}
