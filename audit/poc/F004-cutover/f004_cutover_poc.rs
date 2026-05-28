// PoC for R5 (4a7d9c6) F004 cutover-offset BROKEN-FIX.
//
// R5 introduced `epoch_for_with_offset` / `EpochManager::with_cutover`
// and threaded the cutover offset into the actor / supervisor /
// scheduler timing loops, but LEFT the runtime's authoritative
// `epoch_resolver` built `EpochManager::new()` (cutover = 0) at
// runtime.rs:339. Genesis DKLS material is installed at epoch 0
// (apply_cutover:4277 `install_dkls_group_address(0, ..)` and
// genesis.rs:88 `install_local_dkls_share(0, ..)`), but after
// `apply_cutover` the resolver reports `cutover / EPOCH_LENGTH`, not 0.
// The block-signing path (runtime.rs:4824-4829) looks up
// `dkls_signers.get(&epoch_resolver.current_epoch())` -> miss ->
// `NoDklsShare`.
//
// This test is inserted into `src/hyper/runtime.rs` `mod tests` and run
// with: cargo +nightly test --lib f004_poc -- --nocapture
// (use `--lib`, NOT `--bin hypersnap`: the test lives in the library
// crate; the binary test target is `main.rs` unittests and matches 0.)
// then the tree is restored with `git checkout -- src/hyper/runtime.rs`.

#[test]
fn f004_poc_cutover_epoch_resolver_divergence() {
    use crate::hyper::epoch::{epoch_for_with_offset, EPOCH_LENGTH};

    // Realistic mainnet cutover height; >> EPOCH_LENGTH (432_000).
    let cutover: u64 = 5_000_000;
    assert!(cutover >= EPOCH_LENGTH);

    let dir = TempDir::new().unwrap();
    let db = RocksDB::new(dir.path().to_str().unwrap());
    db.open().unwrap();
    let mut rng = rand::rngs::OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(
        &mut rng,
        hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN,
    ));
    let config = HyperRuntimeConfig {
        db: Arc::new(db),
        srs,
        mempool_capacity: 100,
        score_weights: ScoreWeights::default(),
        bootstrap_validators: vec![],
        max_reward_per_epoch: None,
        max_reward_per_epoch_per_market: std::collections::HashMap::new(),
        cutover_snapchain_block: cutover,
        min_validator_trust_score: 0.0,
        protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        scoring_params: proof_of_quality::ScoringParams::default(),
        seed_max_fid: 50_000,
        retro_vesting_on_protocol_epochs: RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
        local_transport_secret_bytes: [0u8; 32],
    };
    let mut rt = HyperRuntime::new(config);

    // Genesis 1-of-1 DKLS committee.
    let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).unwrap();

    // Real cutover application at the configured cutover block.
    let applied = rt.apply_cutover(cutover, &[0x11; 32], dkg.group_address, &[], &[]);
    assert!(applied.is_ok(), "apply_cutover failed: {:?}", applied.err());

    // Genesis material is keyed under the OFFSET-correct epoch, which is 0.
    assert_eq!(epoch_for_with_offset(cutover, cutover), 0);

    // BUG: the resolver reports the RAW epoch, not 0.
    let resolver_epoch = rt.epoch_resolver.current_epoch();
    println!("cutover={cutover} EPOCH_LENGTH={EPOCH_LENGTH}");
    println!("epoch_for_with_offset(cutover, cutover) = 0  <- genesis keyed here");
    println!("rt.epoch_resolver.current_epoch()       = {resolver_epoch}  <- signer looks up here");
    assert_ne!(
        resolver_epoch, 0,
        "if the resolver were cutover-aware this would be 0"
    );
    assert_eq!(resolver_epoch, cutover / EPOCH_LENGTH);

    // Install a genesis local share at epoch 0 (mirrors genesis.rs:88).
    rt.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

    // The signing path (runtime.rs:4824-4829) performs exactly this lookup.
    assert!(
        rt.dkls_signers.get(&resolver_epoch).is_none(),
        "signer unexpectedly found a share at raw epoch {resolver_epoch}"
    );
    // The genesis share IS present at epoch 0 -> the keying is the
    // divergence, not a missing install.
    assert!(rt.dkls_signers.get(&0).is_some());

    // End-to-end witness: block production fails (NoDklsShare or, if the
    // builder bails earlier, some other Err -- either way, no block).
    let produce = rt.produce_signed_block_dkls_local(0, vec![], 0, cutover, vec![0x11; 32], 0);
    println!(
        "produce_signed_block_dkls_local => {}",
        match &produce {
            Ok(_) => "OK (unexpected!)".to_string(),
            Err(e) => format!("Err({e:?})"),
        }
    );
    assert!(
        produce.is_err(),
        "production must fail post-cutover; the signer has no share at epoch {resolver_epoch}"
    );
}
