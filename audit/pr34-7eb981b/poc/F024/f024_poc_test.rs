//! F024 PoC: validator inflow per epoch is unbounded, seats are stakeless and
//! one FID gets up to 3 of them. A burst of registrations in epoch E that
//! pass the (mainnet-valued) trust gate lands in `set(E+2)` at full weight.
//! If those seats never sign, the honest members of `set(E+2)` can no longer
//! form a quorum (shard-0 halt). With enough seats, the newcomers alone form
//! a quorum (capture).
//!
//! Everything runs through the real shard-0 engine (`Net` harness of
//! `test_support.rs`: propose on node 0, validate on nodes 1-2, commit on
//! all): `node_attestation`, `validators::register` (with the 0.05 trust
//! gate fed by a real `ScoringResult` system message), `on_boundary` ->
//! `write_set_record(E+2)`, `Shard0Engine::epoch_set`, the real
//! `certificate::verify`, and the parent-certificate check in
//! `Shard0Engine::validate`.
//!
//! Wired as `#[cfg(test)] mod f024_poc_test;` in `src/chain/shard0/mod.rs`.

use super::auth::test_keys::*;
use super::keys;
use super::state::BlockState;
use super::test_support::*;
use super::Shard0Params;
use crate::chain::certificate::{self, CertificateError};
use crate::chain::validator_sets::EpochSet;
use crate::core::consensus_keys::{ConsensusDomain, ConsensusPrivateKey};
use crate::proto::{
    self, message_data::Body, CommitCertificate, HyperValidatorEventBody,
    HyperValidatorEventType, HypersnapBlock, MessageType, NodeAttestationBody, ScoredFid,
    ScoringResult,
};
use hypersnap_falcon::{domains, FalconSecretKey};
use prost::Message as _;
use std::collections::BTreeMap;

/// Mainnet `min_validator_trust_fp` (0.05, `mod.rs:130-134`). The devnet
/// default is 0, so the PoC switches the gate on explicitly.
const GATE: u32 = 50_000;
/// Epoch of the registration burst. Its seats join at `REG_EPOCH + 2`.
const REG_EPOCH: u64 = 2;
const JOIN_EPOCH: u64 = REG_EPOCH + 2;

fn gated_params() -> Shard0Params {
    let mut p = params();
    p.min_validator_trust_fp = GATE;
    p
}

fn tip_epoch(net: &Net) -> u64 {
    net.nodes[0].engine.tip().unwrap().header.unwrap().epoch
}

fn epoch_start(epoch: u64) -> u64 {
    PIVOT + (epoch - 1) * EPOCH_LEN
}

struct Attacker {
    fid: u64,
    custody: FalconSecretKey,
    nonce: u64,
}

/// Pivot block, then `k` FIDs (5001..) registered, funded and migrated to
/// Falcon custody.
fn setup(k: usize) -> (Net, Vec<Attacker>) {
    let mut net = Net::with_params(3, gated_params());
    net.run_empty();
    let owners: Vec<_> = (0..k).map(|i| eth(20 + i as u8)).collect();
    let mut p = net.proposal(vec![]);
    p.onchain_events = (0..k)
        .map(|i| id_register(5001 + i as u64, owners[i].address().as_slice(), 10 + i as u8))
        .collect();
    p.inbound_burns = (0..k)
        .map(|i| burn(5001 + i as u64, 100_000_000, 10 + i as u8))
        .collect();
    net.run(p);
    let mut out = Vec::new();
    for (i, owner) in owners.iter().enumerate() {
        let fid = 5001 + i as u64;
        let custody = falcon(11 + i as u8);
        let m = migration(&net, fid, &custody, owner);
        assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1, "migration of {fid}");
        out.push(Attacker {
            fid,
            custody,
            nonce: 1,
        });
    }
    (net, out)
}

fn attestation(net: &Net, a: &Attacker, node_key: &FalconSecretKey) -> proto::Message {
    let mut body = NodeAttestationBody {
        node_public_key: falcon_public(node_key),
        nonce: a.nonce,
        ..Default::default()
    };
    let unsigned = data(
        a.fid,
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(body.clone()),
        block_time(net),
    );
    body.node_signature = falcon_sign(
        node_key,
        domains::NODE_ATTESTATION_POP,
        &unsigned.encode_to_vec(),
    );
    falcon_message(
        &a.custody,
        data(
            a.fid,
            MessageType::NodeAttestation,
            Body::NodeAttestationBody(body),
            block_time(net),
        ),
    )
}

fn registration(
    net: &Net,
    a: &Attacker,
    consensus: &FalconSecretKey,
    node_key: &FalconSecretKey,
) -> proto::Message {
    let mut body = HyperValidatorEventBody {
        event_type: HyperValidatorEventType::Register as i32,
        validator_key: super::auth::falcon_key_hash(&falcon_public(consensus)).to_vec(),
        registration_epoch: tip_epoch(net),
        consensus_key: falcon_public(consensus),
        falcon_node_key: falcon_public(node_key),
        ..Default::default()
    };
    let payload = data(
        a.fid,
        MessageType::ValidatorRegister,
        Body::ValidatorEventBody(body.clone()),
        block_time(net),
    )
    .encode_to_vec();
    body.signature = falcon_sign(consensus, domains::VALIDATOR_CONSENSUS_POP, &payload);
    body.node_signature = falcon_sign(node_key, domains::VALIDATOR_NODE_POP, &payload);
    falcon_message(
        &a.custody,
        data(
            a.fid,
            MessageType::ValidatorRegister,
            Body::ValidatorEventBody(body),
            block_time(net),
        ),
    )
}

fn node_seed(i: usize, j: usize) -> u8 {
    40 + (3 * i + j) as u8
}
fn consensus_seed(i: usize, j: usize) -> u8 {
    70 + (3 * i + j) as u8
}

fn stored_trust(net: &Net, fid: u64) -> u32 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    state
        .txn()
        .get(&keys::trust_score(fid))
        .unwrap()
        .map(|v| u32::from_be_bytes(v.as_slice().try_into().unwrap()))
        .unwrap_or(0)
}

/// The inflow scenario: `k` FIDs each attest `seats` node keys in epoch 1,
/// get trust = GATE from the epoch-1 `ScoringResult` (if `scored`), and post
/// all `k * seats` registrations in ONE block of epoch 2. Returns the net
/// (tip = last block of epoch 3, i.e. right before set(4) takes over) and the
/// newcomers' consensus keys. Panics unless every registration is accepted.
fn inflow(k: usize, seats: usize) -> (Net, Vec<ConsensusPrivateKey>) {
    let (mut net, mut attackers) = setup(k);
    for (i, a) in attackers.iter_mut().enumerate() {
        for j in 0..seats {
            let m = attestation(&net, a, &falcon(node_seed(i, j)));
            assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
            a.nonce += 1;
        }
    }
    assert_eq!(tip_epoch(&net), 1);
    net.inputs.scoring.lock().unwrap().insert(
        1,
        ScoringResult {
            epoch: 1,
            trust: attackers
                .iter()
                .map(|a| ScoredFid {
                    fid: a.fid,
                    trust_fp: GATE,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        },
    );
    // The ScoringResult of epoch 1 lands at boundary(2) + SCORING_DELAY.
    while net.next_height() <= epoch_start(2) + params().scoring_delay {
        net.run_empty();
    }
    assert_eq!(tip_epoch(&net), REG_EPOCH);
    for a in &attackers {
        assert_eq!(stored_trust(&net, a.fid), GATE, "trust gate value of {}", a.fid);
    }

    let mut regs = Vec::new();
    let mut ckeys = Vec::new();
    for (i, a) in attackers.iter().enumerate() {
        for j in 0..seats {
            let c = falcon(consensus_seed(i, j));
            regs.push(registration(&net, a, &c, &falcon(node_seed(i, j))));
            ckeys.push(ConsensusPrivateKey::falcon(c));
        }
    }
    let n = regs.len();
    let b = net.run(net.proposal(regs));
    assert_eq!(b.messages.len(), n, "every registration passes register()");
    assert_eq!(b.header.unwrap().epoch, REG_EPOCH);

    // Run to the last block of JOIN_EPOCH - 1. The boundary of epoch 3 has
    // written set(4) from the registry.
    while net.next_height() < epoch_start(JOIN_EPOCH) {
        net.run_empty();
    }
    assert_eq!(tip_epoch(&net), JOIN_EPOCH - 1);
    (net, ckeys)
}

fn cert_by(set: &EpochSet, block: &HypersnapBlock, keys: &[ConsensusPrivateKey]) -> CommitCertificate {
    let height = block.header.as_ref().unwrap().height;
    let sigs: BTreeMap<_, _> = keys
        .iter()
        .map(|k| {
            let address = k.public_key().address();
            let bytes = certificate::precommit_sign_bytes(0, height, 0, &block.hash, &address);
            (address, k.sign(ConsensusDomain::Vote, &bytes))
        })
        .collect();
    certificate::build(set, 0, height, 0, &block.hash, &sigs).unwrap()
}

/// The bootstrap (honest) keys: all 4 genesis validators, all in every set.
fn honest_keys(net: &Net) -> Vec<ConsensusPrivateKey> {
    net.genesis.validators.keys.clone()
}

/// Propose the first block of JOIN_EPOCH on node 0 and validate it on nodes
/// 1-2 (its parent certificate is from the honest set(3), so this works).
fn propose_first_join_block(net: &mut Net) -> HypersnapBlock {
    let p = net.proposal(vec![]);
    let block = net.nodes[0].engine.propose(&net.inputs, p).unwrap();
    assert_eq!(block.header.as_ref().unwrap().epoch, JOIN_EPOCH);
    let parent_set = block
        .parent_certificate
        .as_ref()
        .map(|c| net.nodes[0].engine.epoch_set(c.epoch).unwrap().unwrap());
    for n in net.nodes.iter_mut().skip(1) {
        n.engine
            .validate(&block, &net.inputs, parent_set.as_ref(), u64::MAX)
            .unwrap();
    }
    block
}

/// Commit `block` with `cert` on every node, then propose its child on node 0
/// and run the real child validation (which checks the parent certificate
/// against set(JOIN_EPOCH)) on node 1.
fn child_validation(net: &mut Net, mut block: HypersnapBlock, cert: CommitCertificate) -> Result<(), String> {
    block.certificate = Some(cert);
    for n in net.nodes.iter_mut() {
        n.engine.commit(&block).unwrap();
    }
    let p = net.proposal(vec![]);
    let child = net.nodes[0]
        .engine
        .propose(&net.inputs, p)
        .map_err(|e| format!("propose: {e}"))?;
    let set = net.nodes[0].engine.epoch_set(JOIN_EPOCH).unwrap().unwrap();
    net.nodes[1]
        .engine
        .validate(&child, &net.inputs, Some(&set), u64::MAX)
        .map_err(|e| format!("validate: {e}"))
}

fn report(tag: &str, set: &EpochSet, newcomers: usize) {
    let total = set.record.total_weight;
    let new_fids = set.record.members.iter().filter(|m| m.fid >= 5001).count();
    assert_eq!(new_fids, newcomers);
    println!(
        "F024 {tag}: |set({JOIN_EPOCH})| = {} (honest 4 + newcomers {newcomers}), total_weight = {total}, \
         honest quorum? {} , newcomer-only quorum? {}",
        set.record.members.len(),
        set.is_quorum(4),
        set.is_quorum(newcomers as u64)
    );
}

// ---------------------------------------------------------------------------
// RED
// ---------------------------------------------------------------------------

/// ONE gated FID, 3 silent seats, against the 4-member bootstrap set: set(4)
/// has 7 members, the 4 honest signers have weight 4 and 3*4 > 2*7 fails.
/// The real certificate check rejects the honest certificate of the first
/// epoch-4 block, and the real child validation rejects a block built on it.
#[test]
fn f024_one_fid_three_silent_seats_halts_shard0() {
    let (mut net, _new) = inflow(1, 3);
    // set(3) is still the bootstrap set; set(4) holds the burst.
    let s3 = net.nodes[0].engine.set_record(3).unwrap().unwrap();
    assert_eq!(s3.members.len(), 4);
    let block = propose_first_join_block(&mut net);
    let set4 = net.nodes[0].engine.epoch_set(JOIN_EPOCH).unwrap().unwrap();
    report("halt k=1 seats=3", &set4, 3);
    assert_eq!(set4.record.total_weight, 7);

    let honest = cert_by(&set4, &block, &honest_keys(&net));
    let r = certificate::verify(&set4, &honest);
    println!("F024 halt: verify(all 4 honest signers) = {r:?}");
    assert!(matches!(r, Err(CertificateError::NoQuorum { weight: 4, total: 7 })));

    let child = child_validation(&mut net, block, honest);
    println!("F024 halt: child of an honest-only epoch-4 block -> {child:?}");
    assert!(child.is_err());
}

/// Exactly n_h/2 seats (2 for n_h = 4) already halts: 3*4 > 2*6 is false.
#[test]
fn f024_threshold_two_seats_halts_shard0() {
    let (mut net, _new) = inflow(1, 2);
    let block = propose_first_join_block(&mut net);
    let set4 = net.nodes[0].engine.epoch_set(JOIN_EPOCH).unwrap().unwrap();
    report("threshold k=1 seats=2", &set4, 2);
    let r = certificate::verify(&set4, &cert_by(&set4, &block, &honest_keys(&net)));
    println!("F024 threshold: verify(all 4 honest signers) = {r:?}");
    assert!(matches!(r, Err(CertificateError::NoQuorum { weight: 4, total: 6 })));
}

/// Capture: 3 gated FIDs x 3 seats = 9 newcomers vs 4 honest. set(4) has 13
/// members; the honest set has no quorum, the newcomers alone do (27 > 26),
/// and a block certified only by newcomers passes the real child validation.
#[test]
fn f024_three_fids_nine_seats_dominate_next_set() {
    let (mut net, new) = inflow(3, 3);
    let block = propose_first_join_block(&mut net);
    let set4 = net.nodes[0].engine.epoch_set(JOIN_EPOCH).unwrap().unwrap();
    report("capture k=3 seats=3", &set4, 9);
    assert_eq!(set4.record.total_weight, 13);

    let honest = certificate::verify(&set4, &cert_by(&set4, &block, &honest_keys(&net)));
    println!("F024 capture: verify(all 4 honest) = {honest:?}");
    assert!(matches!(honest, Err(CertificateError::NoQuorum { weight: 4, total: 13 })));

    let theirs = cert_by(&set4, &block, &new);
    let r = certificate::verify(&set4, &theirs);
    println!("F024 capture: verify(9 newcomers only) = {r:?}");
    assert!(r.is_ok());
    let child = child_validation(&mut net, block, theirs);
    println!("F024 capture: child of a newcomer-only epoch-4 block -> {child:?}");
    assert!(child.is_ok());
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

/// Normal inflow: one new seat. set(4) has 5 members, the honest 4 keep a
/// quorum (12 > 10) and the chain keeps committing epoch-4 blocks through
/// the harness (which validates every parent certificate).
#[test]
fn f024_control_one_seat_chain_continues() {
    let (mut net, _new) = inflow(1, 1);
    let block = propose_first_join_block(&mut net);
    let set4 = net.nodes[0].engine.epoch_set(JOIN_EPOCH).unwrap().unwrap();
    report("control k=1 seats=1", &set4, 1);
    let honest = cert_by(&set4, &block, &honest_keys(&net));
    assert!(certificate::verify(&set4, &honest).is_ok());
    let child = child_validation(&mut net, block, honest.clone());
    assert!(child.is_ok(), "{child:?}");
    // Drop the pending state of the probe child and keep running normally.
    for _ in 0..3 {
        net.run_empty();
    }
    assert_eq!(tip_epoch(&net), JOIN_EPOCH);
    println!(
        "F024 control: tip height {} in epoch {} after 1 new seat",
        net.nodes[0].engine.tip().unwrap().header.unwrap().height,
        tip_epoch(&net)
    );
}

/// Control: the trust gate is real. Without a ScoringResult the FID has
/// trust 0 < 50_000 and its registration is rejected by register().
#[test]
fn f024_control_trust_gate_rejects_unscored_fid() {
    let (mut net, mut attackers) = setup(1);
    let a = &mut attackers[0];
    let m = attestation(&net, a, &falcon(node_seed(0, 0)));
    assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
    a.nonce += 1;
    let reg = registration(&net, a, &falcon(consensus_seed(0, 0)), &falcon(node_seed(0, 0)));
    let r = net.nodes[0].engine.simulate_messages(&[reg], block_time(&net));
    println!("F024 control: unscored FID registration -> {:?}", r[0]);
    assert!(format!("{:?}", r[0]).contains("trust score is below"));
}

/// Control: the per-FID cap is 3 node attestations (so 3 seats per FID).
#[test]
fn f024_control_fourth_attestation_rejected() {
    let (mut net, mut attackers) = setup(1);
    let a = &mut attackers[0];
    for j in 0..3 {
        let m = attestation(&net, a, &falcon(node_seed(0, j)));
        assert_eq!(net.run(net.proposal(vec![m])).messages.len(), 1);
        a.nonce += 1;
    }
    let m = attestation(&net, a, &falcon(node_seed(0, 3)));
    let r = net.nodes[0].engine.simulate_messages(&[m], block_time(&net));
    println!("F024 control: 4th attestation -> {:?}", r[0]);
    assert!(r[0].is_err());
}
