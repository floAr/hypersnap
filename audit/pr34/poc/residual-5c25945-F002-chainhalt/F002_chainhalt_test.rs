// F002 residual (chain-halt) PoC test.
//
// Target: hypersnap commit 5c2594563df84c374fdce7cdeae06d3444da3b72
//         ("audit fixes" — the F002 INTERSECTION fix is here, the
//          recursion residual is NOT).
//
// This is the EXACT test that was inserted into
//   src/hyper/runtime.rs   (inside `#[cfg(test)] mod tests { ... }`)
// just before `fn validator_register_passes_when_trust_gate_disabled`.
// It reuses the module's existing `make_runtime()` helper and the
// production APIs `record_evidence`, `evidence_for_epoch`, and
// `get_active_validators_enforced`, plus the real `ConflictingBlocksEvidence`
// type and the real `SlashingEvidenceStore` (via `record_evidence`), so it is
// a faithful in-crate reproduction.
//
// BUILD STATUS in the delivery environment: UNVERIFIED-BY-BUILD.
// The hypersnap crate could not be compiled here because the transitive
// native dependency `tikv-jemalloc-sys` fails its autotools `configure`
// step against the MSVC toolchain (no GNU/mingw `cc` is installed), so
// rustc never type-checked this test. The recursion it exercises was
// instead OBSERVED with a runnable structural model that mirrors the same
// call graph (see f002_model_standalone.rs / README.md), which produced
// STATUS_STACK_OVERFLOW (0xC00000FD) on the malicious cross-epoch row and
// Ok on the benign same-epoch row.
//
// ---------------------------------------------------------------------------
// PASTE THE BLOCK BELOW into the `mod tests` module in src/hyper/runtime.rs.
// ---------------------------------------------------------------------------

    // ====================================================================
    // F002 residual (chain-halt) PoC — present at commit 5c25945.
    //
    // The intersection fix (UNION -> INTERSECTION) is in this commit, but
    // the `slashed_validators_for_epoch` <-> `get_active_validators_enforced`
    // self-recursion is NOT fixed. A single attacker-submitted ADJACENT
    // cross-epoch evidence row (epoch_a = E-1, epoch_b = E, stored under
    // min = E-1) makes the epoch-E cutover recurse without bound:
    //
    //   get_active_validators_enforced(E)
    //     -> slashed_validators_for_epoch(E-1)          (runtime.rs:4122)
    //     -> reads evidence at E-1; block_b has sig.epoch = E
    //     -> resolve_signers(block_b) calls
    //        get_active_validators_enforced(E)           (runtime.rs:4264)
    //     -> slashed_validators_for_epoch(E-1) -> ...    (back to start)
    //
    // No depth guard, no memoization, `_active_set_at_epoch` ignored
    // (runtime.rs:4241). Result: stack overflow -> node abort -> chain
    // halt at the epoch boundary.
    //
    // A real stack overflow ABORTS the process and cannot be caught with
    // catch_unwind. To make this observable, the malicious call is run on a
    // thread with a small (256 KiB) stack so it overflows fast.
    //
    // PLATFORM NOTE: on Windows a stack overflow on any thread terminates
    // the WHOLE process with STATUS_STACK_OVERFLOW (0xC00000FD); join()
    // does NOT return Err — the test runner itself is killed. On targets
    // whose runtime installs a guard-page handler that converts the
    // overflow into a thread panic, join() returns Err and the assertion
    // holds. Either way the BENIGN control (same-epoch evidence,
    // epoch_a==epoch_b==E-1, stored under E-1) runs FIRST on the SAME small
    // stack and returns Ok — so observing "benign returned, then the
    // process died on the malicious row" is itself the proof that the
    // difference is the cross-epoch recursion and not a setup error or the
    // small stack size. (This exact benign-Ok / malicious-overflow split is
    // demonstrated by the runnable structural model shipped alongside this
    // PoC; see README — the model produced STATUS_STACK_OVERFLOW on the
    // malicious row and Ok on the benign row.)
    // ====================================================================

    /// Build a HyperBlock signed for `epoch`, at `height`, with the given
    /// state-root marker and signer indices. Mirrors the block shape the
    /// slashing_store tests use.
    fn f002_block(epoch: u64, height: u64, root: u8, signers: Vec<u64>) -> crate::hyper::HyperBlock {
        crate::hyper::HyperBlock {
            envelope: crate::hyper::HyperEnvelope {
                metadata: crate::hyper::HyperBlockMetadata {
                    canonical_block_id: height,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![root; 48],
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
                signer_indices: signers,
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    /// Construct a `ConflictingBlocksEvidence` for two blocks at the same
    /// height, tagged with epochs `epoch_a` / `epoch_b`. This is exactly
    /// the in-memory shape the ingestion path hands to
    /// `runtime.record_evidence()` (which persists it under
    /// `min(epoch_a, epoch_b)` via the production `SlashingEvidenceStore`).
    fn f002_evidence(
        epoch_a: u64,
        epoch_b: u64,
        height: u64,
        root_a: u8,
        root_b: u8,
        signers_a: Vec<u64>,
        signers_b: Vec<u64>,
    ) -> ConflictingBlocksEvidence {
        let a = f002_block(epoch_a, height, root_a, signers_a);
        let b = f002_block(epoch_b, height, root_b, signers_b);
        let mut hash_a = [0u8; 32];
        hash_a[0] = root_a;
        let mut hash_b = [0u8; 32];
        hash_b[0] = root_b;
        ConflictingBlocksEvidence {
            epoch_a,
            epoch_b,
            canonical_block_id: height,
            block_a_hash: hash_a,
            block_b_hash: hash_b,
            block_a: Box::new(a),
            block_b: Box::new(b),
        }
    }

    /// Small-stack runner: invokes `get_active_validators_enforced(epoch)`
    /// on a thread with a 256 KiB stack. Returns Ok(()) if the call returns
    /// (whatever its Result), Err(()) if the thread aborts/panics (stack
    /// overflow on unbounded recursion).
    ///
    /// NOTE: the runtime is moved into the thread because HyperRuntime is
    /// not Sync-shareable by reference across the boundary here; we only
    /// need it to live for the duration of the call.
    fn f002_run_enforced_on_small_stack(
        rt: HyperRuntime,
        bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
        epoch: u64,
    ) -> Result<(), ()> {
        let handle = std::thread::Builder::new()
            .name(format!("f002-enforced-e{epoch}"))
            .stack_size(256 * 1024) // 256 KiB — small enough to overflow fast
            .spawn(move || {
                // We don't care about the Ok/Err value, only whether the
                // call RETURNS at all. On the malicious cross-epoch row the
                // recursion never returns; the thread overflows its stack
                // and aborts, which surfaces as Err on join().
                let _ = rt.get_active_validators_enforced(epoch, &bootstrap);
            })
            .expect("spawn small-stack thread");
        handle.join().map_err(|_| ())
    }

    /// F002 residual chain-halt PoC.
    ///
    /// Demonstrates that at commit 5c25945 a single adjacent cross-epoch
    /// evidence row turns the epoch-E enforced-active-set computation into
    /// unbounded recursion (stack overflow -> abort), while the benign
    /// same-epoch control returns normally.
    #[test]
    fn f002_cross_epoch_evidence_recurses_unbounded_on_epoch_boundary() {
        // ---- shared setup helpers --------------------------------------
        // Build a runtime with a small active set spanning epochs E-1 and E.
        // E is chosen >= 2 so that E-1 >= 1 and the recursion target epoch
        // E is a normal (prev = E-1 >= 0) branch of
        // get_active_validators_enforced.
        let target_e: u64 = 2; // E = 2  => prev = 1  (E-1)
        let prev_e: u64 = target_e - 1; // 1

        // Two validators in the bootstrap set (present at every epoch since
        // compute_active_set seeds from bootstrap and there are no events).
        let vk1 = vec![0x11u8; 32];
        let vk2 = vec![0x22u8; 32];
        let bootstrap = vec![
            (vk1.clone(), vec![0u8; 48], vec![0u8; 32]),
            (vk2.clone(), vec![0u8; 48], vec![0u8; 32]),
        ];

        // ---- BENIGN control: same-epoch evidence -----------------------
        // epoch_a == epoch_b == prev_e (E-1). Stored under min = E-1.
        // resolve_signers(block_b @ epoch E-1) calls
        // get_active_validators_enforced(E-1) which reads
        // slashed_validators_for_epoch(E-2). E-2 holds no evidence, so the
        // recursion terminates immediately. The outer call returns Ok.
        {
            let (rt, _dir) = make_runtime();
            let benign = f002_evidence(
                prev_e, prev_e, // both signed for E-1
                100,            // height
                0xaa, 0xbb,     // distinct state roots -> distinct hashes
                vec![1, 2],     // signers_a
                vec![1, 2],     // signers_b
            );
            rt.record_evidence(&benign).expect("record benign evidence");
            // Sanity: stored under E-1.
            assert_eq!(
                rt.evidence_for_epoch(prev_e).unwrap().len(),
                1,
                "benign same-epoch evidence must be stored under E-1"
            );
            let res = f002_run_enforced_on_small_stack(rt, bootstrap.clone(), target_e);
            assert!(
                res.is_ok(),
                "BENIGN control: get_active_validators_enforced(E) with \
                 same-epoch evidence must RETURN (no unbounded recursion); \
                 got thread abort"
            );
        }

        // ---- MALICIOUS: adjacent cross-epoch evidence ------------------
        // epoch_a = E-1, epoch_b = E. Stored under min = E-1.
        // get_active_validators_enforced(E)
        //   -> slashed_validators_for_epoch(E-1) reads this row
        //   -> resolve_signers(block_b @ epoch E) calls
        //      get_active_validators_enforced(E)  -> loops forever.
        {
            let (rt, _dir) = make_runtime();
            let malicious = f002_evidence(
                prev_e, target_e, // block_a @ E-1, block_b @ E  (cross-epoch)
                100,              // same height
                0xcc, 0xdd,       // distinct state roots
                vec![1, 2],       // block_a signers (epoch E-1)
                vec![1, 2],       // block_b signers (epoch E)
            );
            rt.record_evidence(&malicious)
                .expect("record malicious cross-epoch evidence");
            // Sanity: persisted under min(E-1, E) = E-1, exactly the F002 shape.
            assert_eq!(
                rt.evidence_for_epoch(prev_e).unwrap().len(),
                1,
                "cross-epoch evidence must persist under min = E-1"
            );
            let res = f002_run_enforced_on_small_stack(rt, bootstrap.clone(), target_e);
            assert!(
                res.is_err(),
                "RESIDUAL PRESENT: get_active_validators_enforced(E) with \
                 cross-epoch evidence must NOT return (unbounded recursion -> \
                 stack overflow -> thread abort). If this returned Ok, the \
                 recursion residual is fixed."
            );
        }
    }
