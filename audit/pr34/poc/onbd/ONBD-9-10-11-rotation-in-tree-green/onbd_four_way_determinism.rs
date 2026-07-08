// GREEN fix-confirmation PoC for the f4fc4af rotation-in-tree transition.
// Add this block to `mod tests` in `src/hyper/builder.rs`. It reuses that
// module's imports (VerkleTree, KzgSrs, VERKLE_DOMAIN, OsRng, PendingMessage,
// HyperBlockBuilder, read_onboard_rotation_nonce, read_onboard_custody_fid).
//
// What it pins (ONBD-9/10/11 revalidation):
//   The four consensus paths that derive the verkle root from a block's
//   messages — (1) the producer's scratch clone, (2) the proposer's own
//   self-import, (3) a peer importing the gossiped block, (4) cold-restart
//   replay — all funnel through `HyperBlockBuilder::apply_message` in the
//   canonical order onboards -> rotations -> transfers. Identical ordered
//   messages against an identical prior tree MUST derive a byte-identical root
//   AND rotation nonce; a stale (no-op) rotation folded into a follow-up block
//   must stay deterministic; and applying rotations BEFORE onboards WOULD fork
//   (order is load-bearing, not cosmetic).

fn rotation_body(fid: u64, current: [u8; 20], new: [u8; 20], nonce: u64)
    -> proto::HyperCustodyRotationBody {
    proto::HyperCustodyRotationBody {
        fid,
        current_custody: current.to_vec(),
        new_custody: new.to_vec(),
        nonce,
        current_custody_signature: vec![0u8; 65], // apply path is sig-agnostic
    }
}

fn onboard_body(custody: [u8; 20]) -> proto::HyperNativeOnboardBody {
    proto::HyperNativeOnboardBody {
        custody_address: custody.to_vec(),
        anchor_block_height: 0,
        anchor_block_hash: vec![0u8; 32],
        custody_signature: vec![0u8; 65],
        gate_proof: None,
    }
}

fn root_and_nonce(srs: std::sync::Arc<KzgSrs>, msgs: &[PendingMessage], fid: u64)
    -> (Vec<u8>, u64) {
    let mut tree = VerkleTree::new(srs);
    let mut b = HyperBlockBuilder::new(&mut tree);
    for m in msgs {
        b.apply_message(m).unwrap();
    }
    let root = tree.root_commitment().unwrap().to_bytes().to_vec();
    let nonce = read_onboard_rotation_nonce(&tree, fid);
    (root, nonce)
}

#[test]
fn onbd_four_way_rotation_apply_order_determinism() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let a = [0xaau8; 20];
    let bnew = [0xbbu8; 20];
    let fid = crate::hyper::HYPER_FID_BASE; // first assigned FID

    // Canonical block: onboard(A) then rotate A -> B, in one block.
    let canonical = vec![
        PendingMessage::Onboard(onboard_body(a)),
        PendingMessage::Rotation(rotation_body(fid, a, bnew, 1)),
    ];

    // Paths (1)/(2)/(3)/(4) all apply the same ordered messages against an
    // identical (here: empty) prior tree. Model two independent nodes.
    let (root_p, nonce_p) = root_and_nonce(srs.clone(), &canonical, fid);
    let (root_q, nonce_q) = root_and_nonce(srs.clone(), &canonical, fid);
    assert_eq!(root_p, root_q, "same ordered block must give same root");
    assert_eq!(nonce_p, 1, "rotation nonce must advance to 1");
    assert_eq!(nonce_q, 1, "rotation nonce must be identical across nodes");

    // Post-state: A tombstoned (unbound), B holds the FID.
    {
        let mut tree = VerkleTree::new(srs.clone());
        let mut b = HyperBlockBuilder::new(&mut tree);
        for m in &canonical {
            b.apply_message(m).unwrap();
        }
        assert_eq!(read_onboard_custody_fid(&tree, &a), None, "A must be revoked");
        assert_eq!(read_onboard_custody_fid(&tree, &bnew), Some(fid), "B holds FID");
    }

    // Stale rotation folded into a follow-up block: replay the SAME stale
    // rotation (nonce 1 consumed, A no longer holds FID) on two independent
    // nodes; both must no-op to a byte-identical root.
    let stale = vec![PendingMessage::Rotation(rotation_body(fid, a, bnew, 1))];
    let build_then_apply = |srs: Arc<KzgSrs>| -> Vec<u8> {
        let mut tree = VerkleTree::new(srs);
        {
            let mut b = HyperBlockBuilder::new(&mut tree);
            for m in &canonical { b.apply_message(m).unwrap(); }
        }
        let before = tree.root_commitment().unwrap().to_bytes().to_vec();
        {
            let mut b = HyperBlockBuilder::new(&mut tree);
            for m in &stale { b.apply_message(m).unwrap(); }
        }
        let after = tree.root_commitment().unwrap().to_bytes().to_vec();
        assert_eq!(before, after, "stale rotation must be a no-op on the root");
        after
    };
    let s1 = build_then_apply(srs.clone());
    let s2 = build_then_apply(srs.clone());
    assert_eq!(s1, s2, "no-op rotation must be deterministic across nodes");

    // Order-sensitivity witness: rotations-before-onboards derives a DIFFERENT
    // root (rotation no-ops because A is not yet bound, then onboard binds A and
    // never revokes it) — a fork. This is why onboards-before-rotations at all
    // four call sites is load-bearing.
    let wrong_order = vec![
        PendingMessage::Rotation(rotation_body(fid, a, bnew, 1)),
        PendingMessage::Onboard(onboard_body(a)),
    ];
    let (root_wrong, nonce_wrong) = root_and_nonce(srs.clone(), &wrong_order, fid);
    assert_ne!(root_p, root_wrong,
        "rotations-before-onboards MUST diverge (documents the fork risk)");
    assert_eq!(nonce_wrong, 0, "rotation no-ops when applied before its onboard");
}
