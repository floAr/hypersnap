// ONBD-2 — red property PoC (build-verified, FAILS on 573d671).
//
// Placement: add to `mod tests` in `src/hyper/runtime.rs` (needs the crate-
// internal `make_runtime` + `seed_onchain_signer` helpers and `&mut self`
// access to `HyperRuntime`). Reuses `RewardStore::credit_balance`,
// `apply_onboarding_stake_lock`, `apply_onboarding_stake_release`, and the
// `native_onboard` signing-payload helpers.
//
// Property asserted (should hold): a REJECTED stake release must conserve the
// sponsor's total value (available balance + still-locked stake). On 573d671
// the release deletes+commits the lock (native_onboard.rs:1064-1067) BEFORE
// the fallible nonce check (runtime.rs:922-931), so a stale-nonce release
// destroys the lock while the refund is never credited — the assertion fails.
// Flips green once the release validates the nonce before any destructive
// write and commits delete+credit+nonce in one atomic batch.
//
// Verbatim result on 573d671 (see test-output.txt):
//   assertion `left == right` failed: ONBD-2: rejected stake release burned
//   5000000000 atoms (lock deleted before the nonce check, no refund)
//     left: 5000000000
//    right: 10000000000

#[test]
fn onbd2_rejected_stake_release_must_not_burn_staked_atoms() {
    use ed25519_dalek::{Signer, SigningKey};
    let (mut rt, _dir) = make_runtime();
    let chain_id = rt.protocol_chain_id;
    let sponsor: u64 = 4242;
    let stake_amount: u64 = 5_000_000_000;
    let starting_balance: u64 = 10_000_000_000;

    // Fund the sponsor and register an active ed25519 signer for it.
    rt.reward_store
        .credit_balance(sponsor, starting_balance)
        .unwrap();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let signer_pubkey = sk.verifying_key().to_bytes().to_vec();
    seed_onchain_signer(&rt, sponsor, sk.clone());

    // Sponsor locks `stake_amount` (nonce 1, short duration).
    let lock_id = crate::hyper::native_onboard::derive_stake_lock_id(sponsor, 1);
    let mut lock_body = proto::OnboardingStakeLockBody {
        sponsor_fid: sponsor,
        stake_lock_id: lock_id.to_vec(),
        amount_atoms: stake_amount,
        lock_duration_blocks: 1,
        nonce: 1,
        signer_pubkey: signer_pubkey.clone(),
        signature: vec![],
    };
    let lock_payload =
        crate::hyper::native_onboard::onboarding_stake_lock_signing_payload(&lock_body, chain_id);
    lock_body.signature = sk.sign(&lock_payload).to_bytes().to_vec();
    rt.apply_onboarding_stake_lock(&lock_body).unwrap();
    assert_eq!(
        rt.reward_store.balance_of(sponsor).unwrap(),
        starting_balance - stake_amount
    );

    // Advance the chain height so the lock is matured for release.
    rt.chain.last_height = Some(100);

    // Craft a release carrying a STALE nonce (1). The correct next nonce is 2,
    // so this must be rejected — but the delete happens first.
    let mut rel = proto::OnboardingStakeReleaseBody {
        sponsor_fid: sponsor,
        stake_lock_id: lock_id.to_vec(),
        nonce: 1, // stale: expected is 2
        signer_pubkey: signer_pubkey.clone(),
        signature: vec![],
    };
    let rel_payload =
        crate::hyper::native_onboard::onboarding_stake_release_signing_payload(&rel, chain_id);
    rel.signature = sk.sign(&rel_payload).to_bytes().to_vec();

    let bal_before = rt.reward_store.balance_of(sponsor).unwrap();
    let lock_before =
        crate::hyper::native_onboard::read_onboarding_stake_lock(&rt.db, &lock_id).unwrap();
    assert!(lock_before.is_some(), "lock must exist before release");
    let value_before = bal_before + lock_before.as_ref().map(|l| l.amount_atoms).unwrap_or(0);

    let res = rt.apply_onboarding_stake_release(&rel);
    assert!(res.is_err(), "stale-nonce release should be rejected");

    // PROPERTY: a rejected release must not destroy value.
    let bal_after = rt.reward_store.balance_of(sponsor).unwrap();
    let lock_after =
        crate::hyper::native_onboard::read_onboarding_stake_lock(&rt.db, &lock_id).unwrap();
    let value_after = bal_after + lock_after.as_ref().map(|l| l.amount_atoms).unwrap_or(0);
    assert_eq!(
        value_after, value_before,
        "ONBD-2: rejected stake release burned {} atoms (lock deleted before the \
         nonce check, no refund)",
        value_before.saturating_sub(value_after)
    );
}
