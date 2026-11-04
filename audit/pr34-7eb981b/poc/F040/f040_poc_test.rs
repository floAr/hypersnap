//! F040 PoC: `verify_signatures` counts duplicate signers toward quorum.
//! Wired as `#[cfg(test)] mod f040_poc_test;` in `src/core/mod.rs`.

use crate::consensus::validator::{StoredValidatorSet, StoredValidatorSets};
use crate::core::consensus_keys::{test_key, ConsensusDomain, ConsensusPrivateKey};
use crate::core::types::{ShardId, SnapchainShard, SnapchainValidator, SnapchainValidatorSet, Vote};
use crate::core::util::verify_signatures;
use crate::proto;
use informalsystems_malachitebft_core_types::{NilOrVal, Round};

const SHARD: u32 = 1;
const HEIGHT: u64 = 42;
const ROUND: i64 = 0;

struct Fixture {
    keys: Vec<ConsensusPrivateKey>,
    sets: StoredValidatorSets,
}

/// n = 4 Falcon validators (same `test_key` seeds as `certificate::test_support`).
fn fixture(n: u8) -> Fixture {
    let keys: Vec<ConsensusPrivateKey> = (1..=n).map(test_key).collect();
    let validators: Vec<SnapchainValidator> = keys
        .iter()
        .map(|k| {
            let ConsensusPrivateKey::Falcon { public, .. } = k else {
                unreachable!()
            };
            SnapchainValidator::new_falcon(SnapchainShard::new(SHARD), public.clone(), 0)
        })
        .collect();
    let stored = StoredValidatorSet {
        effective_at: 0,
        validators: SnapchainValidatorSet::new(validators),
        shard_ids: vec![SHARD],
    };
    Fixture {
        keys,
        sets: StoredValidatorSets::new(SHARD, vec![stored]),
    }
}

fn height() -> proto::Height {
    proto::Height {
        shard_index: SHARD,
        block_number: HEIGHT,
    }
}

fn value() -> proto::ShardHash {
    proto::ShardHash {
        shard_index: SHARD,
        hash: vec![0xAB; 32], // attacker-chosen block hash
    }
}

/// A genuine precommit signature by `key`, exactly as `verify_signatures` checks it.
fn precommit_sig(key: &ConsensusPrivateKey) -> proto::CommitSignature {
    let address = key.public_key().address();
    let vote = Vote::new_precommit(
        height(),
        Round::new(ROUND as u32),
        NilOrVal::Val(value()),
        address.clone(),
    );
    proto::CommitSignature {
        signer: address.to_vec(),
        signature: key.sign(ConsensusDomain::Vote, &vote.to_sign_bytes()),
    }
}

fn commits(signatures: Vec<proto::CommitSignature>) -> proto::Commits {
    proto::Commits {
        height: Some(height()),
        round: ROUND,
        value: Some(value()),
        signatures,
    }
}

#[test]
fn f040_one_signer_repeated_three_times_meets_quorum() {
    let f = fixture(4);
    let one = precommit_sig(&f.keys[0]);
    let forged = commits(vec![one.clone(), one.clone(), one.clone()]);
    let ok = verify_signatures(&forged, &f.sets);
    println!(
        "F040: n=4, 1 distinct signer x3 copies -> verify_signatures = {}",
        ok
    );
    assert!(ok, "duplicate signer was NOT counted toward quorum");

    // Same with 4 copies (all slots filled by one key).
    let forged4 = commits(vec![one.clone(), one.clone(), one.clone(), one.clone()]);
    let ok4 = verify_signatures(&forged4, &f.sets);
    println!("F040: n=4, 1 distinct signer x4 copies -> verify_signatures = {}", ok4);
    assert!(ok4);
}

#[test]
fn f040_control_three_distinct_signers_meet_quorum() {
    let f = fixture(4);
    let sigs = f.keys.iter().take(3).map(precommit_sig).collect();
    let ok = verify_signatures(&commits(sigs), &f.sets);
    println!("F040 control: n=4, 3 distinct signers -> verify_signatures = {}", ok);
    assert!(ok);
}

#[test]
fn f040_control_single_signature_fails_quorum() {
    let f = fixture(4);
    let ok = verify_signatures(&commits(vec![precommit_sig(&f.keys[0])]), &f.sets);
    println!("F040 control: n=4, 1 signature -> verify_signatures = {}", ok);
    assert!(!ok);
}

#[test]
fn f040_control_two_distinct_signers_fail_quorum() {
    let f = fixture(4);
    let sigs = f.keys.iter().take(2).map(precommit_sig).collect();
    let ok = verify_signatures(&commits(sigs), &f.sets);
    println!("F040 control: n=4, 2 distinct signers -> verify_signatures = {}", ok);
    assert!(!ok);
}

#[test]
fn f040_control_tampered_copy_is_rejected() {
    // Shows the copies are actually signature-checked (not skipped).
    let f = fixture(4);
    let one = precommit_sig(&f.keys[0]);
    let mut bad = one.clone();
    let last = bad.signature.len() - 1;
    bad.signature[last] ^= 0x01;
    let ok = verify_signatures(&commits(vec![one.clone(), one.clone(), bad]), &f.sets);
    println!("F040 control: 2 good copies + 1 tampered copy -> verify_signatures = {}", ok);
    assert!(!ok);
}
