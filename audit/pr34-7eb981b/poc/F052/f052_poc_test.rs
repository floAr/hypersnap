//! F052 PoC: `MiniappAdd` / `MiniappRemove` churn inflates the App-PoW
//! counter `[79][epoch][owner][user]` without bound. `add` increments it on
//! every add, `remove` never decrements it, and there is no per-epoch, fee,
//! nonce or replay bound on adds. The PoQ App-PoW weight is linear in it.
//!
//! Everything runs through the real shard-0 engine (`Net` harness of
//! `test_support.rs`: propose on node 0, validate on nodes 1-2, commit on
//! all). The registration block is a copy of
//! `engine_test::miniapp_register_add_and_receipt`.
//!
//! Wired as `#[cfg(test)] mod f052_poc_test;` in `src/chain/shard0/mod.rs`.

use super::auth::test_keys::*;
use super::miniapp;
use super::state::BlockState;
use super::test_support::*;
use crate::chain::scoring::HypersnapReader;
use crate::proto::{self, message_data::Body, MessageType};
use proof_of_quality::metrics::FidMetrics;
use proof_of_quality::reader::SnapchainStateReader;
use proof_of_quality::ScoringParams;
use std::collections::BTreeMap;

const DOMAIN: &str = "example.com";

/// `funded_net()` plus the registration of `example.com` by FID 1000 with its
/// custody Falcon key and the JFS proof of `owner` (verbatim from
/// `miniapp_register_add_and_receipt`).
fn registered_net() -> (Net, hypersnap_falcon::FalconSecretKey) {
    let (mut net, custody, owner) = funded_net();
    use alloy_signer::SignerSync;
    use base64::Engine as _;
    let header = format!(
        "{{\"fid\":1000,\"type\":\"custody\",\"key\":\"0x{}\"}}",
        hex::encode(owner.address())
    )
    .into_bytes();
    let payload = format!(
        "{{\"domain\":\"example.com\",\"chain_id\":{}}}",
        params().protocol_chain_id
    )
    .into_bytes();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let input = format!("{}.{}", b64.encode(&header), b64.encode(&payload));
    let signature = owner
        .sign_message_sync(input.as_bytes())
        .unwrap()
        .as_bytes()
        .to_vec();
    let metadata = proto::MiniappMetadata {
        name: "Example".into(),
        home_url: "https://example.com".into(),
        icon_url: "https://example.com/icon.png".into(),
        ..Default::default()
    };
    let reg = falcon_message(
        &custody,
        data(
            1000,
            MessageType::MiniappRegister,
            Body::MiniappRegisterBody(proto::MiniappRegisterBody {
                domain: DOMAIN.into(),
                metadata: Some(metadata),
                proof: Some(proto::AccountAssociationProof {
                    header,
                    payload,
                    signature,
                }),
            }),
            block_time(&net),
        ),
    );
    assert_eq!(net.run(net.proposal(vec![reg])).messages.len(), 1, "register");
    (net, custody)
}

fn add_msg(sk: &hypersnap_falcon::FalconSecretKey, fid: u64, ts: u64) -> proto::Message {
    falcon_message(
        sk,
        data(
            fid,
            MessageType::MiniappAdd,
            Body::MiniappAddBody(proto::MiniappAddBody { domain: DOMAIN.into() }),
            ts,
        ),
    )
}

fn remove_msg(sk: &hypersnap_falcon::FalconSecretKey, fid: u64, ts: u64) -> proto::Message {
    falcon_message(
        sk,
        data(
            fid,
            MessageType::MiniappRemove,
            Body::MiniappRemoveBody(proto::MiniappRemoveBody { domain: DOMAIN.into() }),
            ts,
        ),
    )
}

/// `k` add/remove pairs with distinct backdated timestamps.
fn churn(net: &Net, sk: &hypersnap_falcon::FalconSecretKey, k: u64) -> Vec<proto::Message> {
    let base = block_time(net) - 1000;
    (0..k)
        .flat_map(|i| {
            [
                add_msg(sk, 1000, base + 2 * i),
                remove_msg(sk, 1000, base + 2 * i + 1),
            ]
        })
        .collect()
}

fn adds_counter(net: &Net, epoch: u64, owner: u64, user: u64) -> u64 {
    let state = BlockState::new(net.nodes[0].engine.db().clone());
    let txn = state.txn();
    txn.get_u64(&miniapp::adds_by_epoch_key(epoch, owner, user))
        .unwrap()
}

fn miniapp_state(net: &Net) -> proto::MiniappState {
    read(
        net,
        &miniapp::state_key(&super::miniapp_rules::miniapp_id_from_domain(DOMAIN)),
    )
    .unwrap()
}

fn block_epoch(b: &proto::HypersnapBlock) -> u64 {
    b.header.as_ref().unwrap().epoch
}

/// Headline (RED): 200 add/remove pairs by FID 1000 on its own app in one
/// block, accepted by all 3 nodes. The counter is 200, the registry state is
/// unchanged, and the scoring reader returns 200 add events.
#[test]
fn f052_churn_200_pairs_one_block_counter_200() {
    let (mut net, custody) = registered_net();
    let msgs = churn(&net, &custody, 200);
    assert_eq!(msgs.len(), 400);
    let b = net.run(net.proposal(msgs));
    let epoch = block_epoch(&b);
    println!(
        "F052 headline: block {} (epoch {epoch}) included {} of 400 churn messages",
        b.header.as_ref().unwrap().height,
        b.messages.len()
    );
    assert_eq!(b.messages.len(), 400, "all accepted, validated on nodes 1-2");

    let counter = adds_counter(&net, epoch, 1000, 1000);
    let state = miniapp_state(&net);
    println!(
        "F052 headline: adds_by_epoch_key({epoch}, 1000, 1000) = {counter}, MiniappState.add_count = {}",
        state.add_count
    );
    assert_eq!(counter, 200);
    assert_eq!(state.add_count, 0, "net registry state unchanged");

    // The production scoring reader over node 0's DB.
    let reader = HypersnapReader::new(
        net.nodes[0].engine.db().clone(),
        BTreeMap::new(),
        params(),
        proto::HyperValidatorSetRecord::default(),
    )
    .unwrap();
    let events = reader.miniapp_add_events_for_epoch(epoch).unwrap();
    println!("F052 headline: reader.miniapp_add_events_for_epoch({epoch}) = {events:?}");
    assert_eq!(events.get(&(1000, 1000)), Some(&200));
}

fn metrics(fid: u64, cred_fp: u64) -> FidMetrics {
    let mut m = FidMetrics::new(fid);
    m.credibility_weight_fp = cred_fp;
    m
}

/// Scoring: 200 adds at the 0.10 credibility floor against a maximum-intensity
/// honest pair (1 add + 100 receipts at credibility 1.0) take 64.5% of the
/// AppUsage budget. With k = 2,000 the share is 94.8%.
#[test]
fn f052_scoring_share_vs_max_honest_pair() {
    let p = ScoringParams::default();
    let mut m = BTreeMap::new();
    m.insert(1000, metrics(1000, 100_000));
    m.insert(2001, metrics(2001, 1_000_000));
    let receipts: BTreeMap<(u64, u64), u32> = [((2000, 2001), 100)].into_iter().collect();
    for &(k, expect) in &[(200u32, 645_161u128), (2_000, 947_867)] {
        let adds: BTreeMap<(u64, u64), u32> =
            [((1000, 1000), k), ((2000, 2001), 1)].into_iter().collect();
        let r = proof_of_quality::app_pow::compute_app_pow_rewards(&receipts, &adds, &m, &p, 1_000_000);
        let got: BTreeMap<u64, u128> = r.iter().map(|e| (e.fid, e.amount)).collect();
        println!("F052 scoring: k = {k} adds at cred 0.10 vs honest pair -> {got:?} of 1,000,000");
        assert_eq!(got.values().sum::<u128>(), 1_000_000);
        assert!(got[&1000].abs_diff(expect) <= 1, "k = {k}: {} vs {expect}", got[&1000]);
    }
    // Control: with the honest count (1 add, as the registry shows at most)
    // the attacker's work is 0.5 vs 55, i.e. under 1%.
    let adds: BTreeMap<(u64, u64), u32> = [((1000, 1000), 1), ((2000, 2001), 1)].into_iter().collect();
    let r = proof_of_quality::app_pow::compute_app_pow_rewards(&receipts, &adds, &m, &p, 1_000_000);
    let got: BTreeMap<u64, u128> = r.iter().map(|e| (e.fid, e.amount)).collect();
    println!("F052 scoring control: k = 1 -> {got:?}");
    assert!(got[&1000] < 10_000);
}

/// Control (a): a second add without a remove is rejected; the guard is
/// "not currently added", not "not added this epoch".
#[test]
fn f052_control_double_add_rejected() {
    let (mut net, custody) = registered_net();
    let t = block_time(&net);
    let b = net.run(net.proposal(vec![add_msg(&custody, 1000, t - 10), add_msg(&custody, 1000, t - 9)]));
    assert_eq!(b.messages.len(), 1);
    let again = add_msg(&custody, 1000, t - 8);
    let r = net.nodes[0].engine.simulate_messages(&[again], block_time(&net));
    println!("F052 control (a): in-block double add -> {} of 2 included; next add -> {:?}", b.messages.len(), r[0]);
    assert!(matches!(&r[0], Err(e) if e.to_string().contains("already added")), "{:?}", r[0]);
    assert_eq!(adds_counter(&net, block_epoch(&b), 1000, 1000), 1);
}

/// Control (b): receipts are capped per (app, user, epoch). 101 receipts from
/// FID 2000's on-chain Ed25519 app signer give 100 accepted.
#[test]
fn f052_control_receipts_capped_at_100() {
    let (mut net, _custody) = registered_net();
    // FID 2000: an on-chain Ed25519 signer (from `signature_acceptance_matrix`).
    let s2 = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let mut signer_event = crate::utils::factory::events_factory::create_signer_event(
        2000,
        s2.clone(),
        proto::SignerEventType::Add,
        Some(1_700_000_100),
        None,
    );
    signer_event.transaction_hash = vec![77u8; 32];
    let mut p = net.proposal(vec![]);
    p.onchain_events = vec![signer_event];
    assert_eq!(net.run(p).system_messages.len(), 1, "the KeyRegistry event");

    let epoch = net.nodes[0].engine.tip().unwrap().header.unwrap().epoch;
    let t = block_time(&net);
    let id = super::miniapp_rules::miniapp_id_from_domain(DOMAIN).to_vec();
    let receipts: Vec<proto::Message> = (1..=101u64)
        .map(|nonce| {
            ed25519_message(
                &s2,
                data(
                    2000,
                    MessageType::AppUsageReceipt,
                    Body::AppUsageReceiptBody(proto::AppUsageReceiptBody {
                        miniapp_id: id.clone(),
                        action_type: "open".into(),
                        epoch,
                        nonce,
                    }),
                    t - 500 + nonce,
                ),
            )
        })
        .collect();
    let b = net.run(net.proposal(receipts));
    println!(
        "F052 control (b): 101 receipts (epoch {}) -> {} accepted",
        block_epoch(&b),
        b.messages.len()
    );
    assert_eq!(block_epoch(&b), epoch);
    assert_eq!(b.messages.len(), 100, "MAX_RECEIPTS_PER_APP_PER_EPOCH");
}

/// Control (c) epoch isolation and (d) byte-identical replay: after the churn
/// block, re-submitting the exact bytes of `add_0` and `remove_0` in a later
/// block is accepted (counter +1), and an add in the next epoch lands in that
/// epoch's counter only.
#[test]
fn f052_control_replay_and_epoch_isolation() {
    let (mut net, custody) = registered_net();
    let msgs = churn(&net, &custody, 200);
    let (add0, rem0) = (msgs[0].clone(), msgs[1].clone());
    let b = net.run(net.proposal(msgs));
    let epoch = block_epoch(&b);
    assert_eq!(b.messages.len(), 400);

    // (d) replay of byte-identical messages.
    let r = net.run(net.proposal(vec![add0.clone(), rem0.clone()]));
    println!(
        "F052 control (d): replayed add_0/remove_0 (hash {}) in block epoch {} -> {} accepted",
        hex::encode(&add0.hash),
        block_epoch(&r),
        r.messages.len()
    );
    assert_eq!(r.messages.len(), 2, "byte-identical replay accepted");
    assert_eq!(block_epoch(&r), epoch, "same epoch");
    assert_eq!(adds_counter(&net, epoch, 1000, 1000), 201);

    // (c) epoch isolation.
    while net.next_height() <= params().epochs.boundary_height(epoch + 1) {
        net.run_empty();
    }
    let n = net.run(net.proposal(vec![add_msg(&custody, 1000, block_time(&net) - 1)]));
    let e2 = block_epoch(&n);
    println!(
        "F052 control (c): add in epoch {e2}: counter({e2}) = {}, counter({epoch}) = {}",
        adds_counter(&net, e2, 1000, 1000),
        adds_counter(&net, epoch, 1000, 1000)
    );
    assert_eq!(n.messages.len(), 1);
    assert_eq!(e2, epoch + 1);
    assert_eq!(adds_counter(&net, e2, 1000, 1000), 1);
    assert_eq!(adds_counter(&net, epoch, 1000, 1000), 201);
}
