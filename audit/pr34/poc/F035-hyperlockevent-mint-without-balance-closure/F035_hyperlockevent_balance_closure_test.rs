// ===========================================================================
// Finding:  F035 — HyperLockEvent locks mint arbitrary wrapped value into the
//           threshold-signed verkle state root with no balance closure, range
//           proof, or signature verification.
//           (Incomplete fix for prior finding F002: PR #34 hardened *transfers*
//            and *confidential locks* with off-mempool re-validation, but the
//            transparent `HyperLockEvent` -> verkle path kept its weak,
//            structural-only application in `import_hyper_block`.)
// Commit:   cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
// Class:    balance-closure-not-enforced  (rust-bulletproofs-pedersen)
//
// Placement: hypersnap crate integration test. To run inside the tree, copy to
//            `code/hypersnap/tests/F035_hyperlockevent_balance_closure_test.rs`
//            and `cargo test -p hypersnap --test
//            F035_hyperlockevent_balance_closure_test`. Uses only the public
//            crate API (`HyperRuntime::{produce_signed_block_dkls_local,
//            import_block}`, the public `mempool` field, and the
//            `hypersnap_crypto` DKG helpers) — it does NOT reach into private
//            internals, mirroring the existing `consensus_test.rs` integration
//            harness and the in-module `import_block` fixtures in
//            `src/hyper/runtime.rs`.
//
// Assertion (SECURE behavior): a `HyperLockEvent` carried in a block's
//   `locks_in_block` payload whose plaintext `amount` is NOT backed by any
//   source-side balance / Pedersen balance-closure must be REJECTED by
//   `HyperRuntime::import_block` on every importer — exactly as transfers are
//   re-validated off-mempool (runtime.rs:4482-4524: `validate_against_store` +
//   `verify_balance_with_blinding_diff`). Today locks have no equivalent loop,
//   so the forged lock is admitted and `encode_lock_leaf` mints the attacker-
//   chosen `amount` into the threshold-signed verkle leaf.
//
// Expected result:
//   * FAILS on cab225f — `import_block` admits the unbacked lock and returns
//     Ok(block_hash); the forged `amount` is committed under the signed
//     `hyper_state_root`.
//   * PASSES after the fix — `import_block` rejects the block (e.g. a new
//     `ImportError::LockValidation`/balance-closure error mirroring the
//     transfer `TransferValidation` path), so the unbacked lock never reaches
//     the verkle tree.
//
// Caveat (impact scoping, from the validator trace, verdict HAS_CAVEATS):
//   The in-scope L1 `HypersnapBridge.claim` consumes the keccak256 *merkle*
//   lock-tree root (built only from balance-validated `TokenLockState`s via
//   `runtime.rs:921`), NOT the verkle `hyper_state_root` the forged leaf lands
//   in. So the demonstrated in-scope impact is threshold-signed cross-chain
//   state-root corruption / a latent mint primitive — it becomes live L1
//   fund-loss only if/when the (out-of-scope) L1 contract honors verkle-
//   inclusion claims. This test asserts the in-protocol invariant regardless.
//
// STATUS: UNVERIFIED
// ===========================================================================

use std::collections::HashMap;
use std::sync::Arc;

use hypersnap::hyper::runtime::{
    HyperRuntime, HyperRuntimeConfig, RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
};
use hypersnap::hyper::validator_score::ScoreWeights;
use hypersnap::proto;
use hypersnap::storage::db::RocksDB;
use hypersnap_crypto::kzg::KzgSrs;
use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
use tempfile::TempDir;

/// Build a fresh single-validator runtime over a temp RocksDB, sharing the
/// supplied SRS so two runtimes (proposer + victim) compute byte-identical
/// verkle roots. Mirrors `make_runtime()` in `src/hyper/runtime.rs` tests.
fn make_runtime(srs: Arc<KzgSrs>) -> (HyperRuntime, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = RocksDB::new(dir.path().to_str().unwrap());
    db.open().unwrap();

    let config = HyperRuntimeConfig {
        db: Arc::new(db),
        srs,
        mempool_capacity: 100,
        score_weights: ScoreWeights::default(),
        bootstrap_validators: vec![],
        max_reward_per_epoch: None,
        max_reward_per_epoch_per_market: HashMap::new(),
        cutover_snapchain_block: 0,
        min_validator_trust_score: 0.0,
        protocol_chain_id: hypersnap::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        scoring_params: proof_of_quality::ScoringParams::default(),
        seed_max_fid: 50_000,
        retro_vesting_on_protocol_epochs: RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
        local_transport_secret_bytes: [0u8; 32],
    };
    (HyperRuntime::new(config), dir)
}

/// A structurally-valid EVM-formatted lock. `amount` is attacker-chosen and
/// backed by NOTHING on the source side; `lock_signature` is the proto field
/// that `validate_lock_event` never reads. Mirrors `sample_lock` /
/// `sample_evm_event` in the in-tree tests.
fn forged_lock(lock_id_byte: u8, amount: u64) -> proto::HyperLockEvent {
    proto::HyperLockEvent {
        amount,
        dest_chain_id: 1, // Ethereum mainnet -> EVM length conventions
        dest_address: vec![0xab; 20],
        spend_pubkey: vec![0x02; 33],
        lock_id: vec![lock_id_byte; 32],
        lock_height: 100,
        lock_timestamp: 1_700_000_000,
        lock_signature: vec![0u8; 64],
    }
}

/// Drive the full malicious-proposer flow against `import_block` and return
/// the importer's result on the VICTIM node.
///
/// 1. A proposer runtime injects `lock` directly into its mempool (the
///    structural-only `submit_lock` gate accepts it — there is no source-side
///    balance to debit) and produces a fully-signed single-party DKLS block.
///    The produced block's `hyper_state_root` deterministically incorporates
///    `encode_lock_leaf(lock)`.
/// 2. A separate VICTIM runtime, sharing the same DKG group address + SRS,
///    imports that block via the production path `import_block(&block, &locks,
///    &transfers)` — exactly the slice the gossip adapter forwards verbatim
///    from a remote `HyperWireBlock.locks` (gossip_adapter -> InboundBlock ->
///    runtime.import_block).
fn import_forged_lock_on_victim(
    lock: proto::HyperLockEvent,
) -> Result<[u8; 32], hypersnap::hyper::importer::ImportError> {
    let mut rng = rand::rngs::OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).unwrap();

    // ---- Proposer: build + sign a block carrying the forged lock. ----
    let (mut proposer, _pd) = make_runtime(srs.clone());
    proposer.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

    // Genesis (height 0) empty block so the chain has a parent for height 1.
    let (block0, _, _) = proposer
        .produce_signed_block_dkls_local(0, vec![], 0, 0, vec![], 0)
        .unwrap();
    let block0_hash = proposer.import_block(&block0, &[], &[]).unwrap();

    // Inject the unbacked lock off-router straight into the proposer's
    // mempool (public field). The transparent-lock router ingress is sealed
    // (F058), but the block-application path is not — a malicious proposer
    // reaches it by placing the lock in the block payload it builds.
    proposer
        .mempool
        .submit_lock(lock.clone())
        .expect("structural-only mempool gate admits the unbacked lock");

    let (block1, locks, transfers) = proposer
        .produce_signed_block_dkls_local(1, block0_hash.to_vec(), 0, 0, vec![], 0)
        .unwrap();
    assert_eq!(
        locks.len(),
        1,
        "the forged lock must ride the produced block's payload"
    );

    // ---- Victim: import via the production state-change path. ----
    let (mut victim, _vd) = make_runtime(srs);
    victim.install_dkls_group_address(0, dkg.group_address);
    victim.import_block(&block0, &[], &[]).unwrap();

    victim.import_block(&block1, &locks, &transfers)
}

/// PRIMARY REGRESSION (F035): a proposer-supplied `HyperLockEvent` with an
/// arbitrary `amount` not backed by any source-side balance / Pedersen
/// closure must be REJECTED on import, mirroring how transfers are
/// re-validated off-mempool. On cab225f it is admitted and minted into the
/// verkle leaf, so this assertion FAILS pre-fix and PASSES once closure is
/// enforced on the lock path.
#[test]
fn proposer_lock_without_balance_closure_rejected() {
    let lock = forged_lock(0x11, 1_000_000_000);
    let result = import_forged_lock_on_victim(lock);

    assert!(
        result.is_err(),
        "SECURITY (F035): import_block admitted a HyperLockEvent whose amount \
         is backed by no source-side balance / Pedersen closure. The attacker-\
         chosen amount was minted into the threshold-signed verkle state root \
         with structural-only validation — transfers get \
         verify_balance_with_blinding_diff here, locks get nothing. \
         Got Ok({:?}); expected a balance-closure rejection.",
        result.ok()
    );
}

/// OPTIONAL (F035, signature dimension): the proto `lock_signature` field is
/// read NOWHERE in production — `validate_lock_event` never inspects it. A
/// lock with an absent/invalid `lock_signature` must therefore still be
/// rejected on import once per-lock authenticity is enforced. On cab225f the
/// (zero-filled) signature is ignored and the lock is admitted, so this
/// assertion FAILS pre-fix and PASSES after the fix.
#[test]
fn lock_signature_required() {
    // Identical structurally-valid lock, but with an explicitly empty
    // signature to make the "authenticity never checked" gap concrete.
    let mut lock = forged_lock(0x22, 500_000);
    lock.lock_signature = Vec::new();

    let result = import_forged_lock_on_victim(lock);

    assert!(
        result.is_err(),
        "SECURITY (F035): import_block admitted a HyperLockEvent with an empty \
         lock_signature. Per-lock authenticity is never established on the \
         transparent-lock verkle path (validate_lock_event never reads \
         lock_signature). Got Ok({:?}); expected a signature/authenticity \
         rejection.",
        result.ok()
    );
}
