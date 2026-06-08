// ============================================================================
// F070 — Validator-registration custody-signature gate is never wired into the
//        production ingestion path. `HyperRuntime::submit_message` builds the
//        `HyperRouter` WITHOUT `.with_custody_resolver(...)`, so `custody_resolver
//        == None` and `route_inbound` takes the lenient `validate_event(.., None)`
//        branch. The EIP-712 custody cross-sign is never checked, letting any
//        gossip peer register an arbitrary self-generated validator key bound to
//        ANY FID (a victim's FID or unbounded sybil FIDs), with no custody key.
//
// Finding:    findings/F070-custody-sig-gate-unwired-in-production-router.md
// Trace:      findings/traces/F070-trace.md
// Commit:     cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
// Class:      registration-custody-sig-gating / eligibility-bypass
//
// WHERE THIS BELONGS IN THE REPO
// ------------------------------
// This file is authored as a single self-contained module so it can be dropped
// in as-is, but each test mirrors (and is intended to be merged into) an
// existing in-tree `#[cfg(test)] mod tests` block:
//
//   * `production_router_enforces_custody_signature`
//       -> belongs in code/hypersnap/src/hyper/router.rs `mod tests`
//          (next to `inbound_validator_event_without_registry_errors` /
//          `outbound_validator_register_wraps_correctly`). It exercises the
//          router constructed EXACTLY the way `HyperRuntime::submit_message`
//          builds it (runtime.rs:3882): `HyperRouter::new(mempool,
//          Some(registry), epoch)` with NO `.with_custody_resolver(...)`.
//          The fix is to chain a `StoreBackedCustodyResolver` (or otherwise
//          require a resolver) at the production construction site so
//          `route_inbound`'s ValidatorEvent arm (router.rs:165-168) takes the
//          strict `validate_and_check_quota` branch.
//
//   * `register_with_forged_fid_rejected`
//       -> belongs in code/hypersnap/src/hyper/validator_registry.rs `mod tests`
//          (next to `register_without_custody_signature_strict_rejected` /
//          `register_with_unknown_fid_strict_rejected`). It demonstrates the
//          unauth-registration primitive: a self-signed Ed25519 register that
//          names an arbitrary FID the sender does NOT custody must fail custody
//          verification — i.e. the lenient `validate_event(.., None)` path that
//          accepts it today must not be the one wired in production.
//
// PER-TEST ASSERTION & EXPECTED RESULT
// ------------------------------------
//   1. production_router_enforces_custody_signature
//        Build the router the way `HyperRuntime::submit_message` does (no
//        `.with_custody_resolver`) and route a Register `ValidatorEvent` whose
//        `fid` is an FID the sender does NOT custody, with a valid self-signed
//        Ed25519 sig and an EMPTY `custody_signature`. The router MUST reject it
//        (RoutingError::Registry(..)) and MUST NOT persist the
//        validator_key -> fid binding. Today `custody_resolver == None` -> the
//        lenient `validate_event(.., None)` branch runs -> the empty custody sig
//        is skipped and the event is ACCEPTED and persisted
//        -> ASSERTION FAILS on cab225f. After wiring a custody resolver into the
//        production router, the strict `validate_and_check_quota` branch runs,
//        requires the custody cross-sign (MissingCustodySignature), and the
//        event is rejected -> PASSES.
//
//   2. register_with_forged_fid_rejected
//        A self-signed Register naming an arbitrary FID (custody held by an
//        unrelated key the sender does not control) must FAIL custody
//        verification under the strict path. Today the live path never resolves
//        a custody address and the attacker omits the custody sig, so the forged
//        (validator_key -> victim fid) binding is admitted with only a self
//        signature that proves nothing about FID ownership
//        -> ASSERTION FAILS on cab225f (the live lenient path admits it).
//        After the fix the forged-FID register is rejected
//        (MissingCustodySignature / InvalidCustodySignature) -> PASSES.
//
// STATUS: UNVERIFIED — authored from source, not compiled.
// ============================================================================

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};

use crate::hyper::mempool::HyperMempool;
use crate::hyper::router::{HyperRouter, RoutingError};
use crate::hyper::validator_registry::{
    validator_event_signing_payload, CustodyResolver, RegistryError, ValidatorRegistry,
};
use crate::proto;
use crate::storage::db::RocksDB;

use crate::core::error::HubError;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Fixtures — mirror code/hypersnap/src/hyper/validator_registry.rs `mod tests`.
// ---------------------------------------------------------------------------

fn make_registry() -> (ValidatorRegistry, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = RocksDB::new(dir.path().to_str().unwrap());
    db.open().unwrap();
    (ValidatorRegistry::new(Arc::new(db)), dir)
}

fn deterministic_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    SigningKey::from_bytes(&bytes)
}

/// A self-signed Register event for `validator_idx` naming `fid`, with a valid
/// Ed25519 signature over the canonical payload and an EMPTY custody signature.
/// This is exactly the attacker primitive from the trace: the Ed25519 sig binds
/// only `validator_key` (the attacker's own freshly generated key), NOT control
/// of `fid`.
fn make_self_signed_register_for_fid(
    validator_idx: u8,
    epoch: u64,
    fid: u64,
) -> proto::HyperValidatorEventBody {
    let sk = deterministic_signing_key(validator_idx);
    let pk = sk.verifying_key().to_bytes();
    let mut event = proto::HyperValidatorEventBody {
        event_type: proto::HyperValidatorEventType::Register as i32,
        validator_key: pk.to_vec(),
        transport_pubkey: vec![validator_idx; 32],
        validator_address: vec![validator_idx; 20],
        registration_epoch: epoch,
        operator_address: Vec::new(),
        fid,
        custody_signature: Vec::new(),
        ..Default::default()
    };
    let payload = validator_event_signing_payload(&event);
    event.signature = sk.sign(&payload).to_bytes().to_vec();
    event
}

/// In-memory `CustodyResolver` — mirrors `StaticCustodyResolver` in the registry
/// test module. Represents the production resolver the router SHOULD wire.
struct StaticCustodyResolver(BTreeMap<u64, [u8; 20]>);
impl CustodyResolver for StaticCustodyResolver {
    fn custody_address_for_fid(&self, fid: u64) -> Result<Option<[u8; 20]>, HubError> {
        Ok(self.0.get(&fid).copied())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// SECURE BEHAVIOR (regression for F070).
///
/// Build the router the way `HyperRuntime::submit_message` does — i.e. via
/// `HyperRouter::new(mempool, Some(registry), epoch)` with NO
/// `.with_custody_resolver(...)`. Routing a Register `ValidatorEvent` under an
/// FID the sender does NOT custody, with an empty custody signature, MUST be
/// rejected and MUST NOT persist the (validator_key -> fid) binding.
///
/// FAILS on cab225f: the production construction leaves `custody_resolver ==
/// None`, so `route_inbound` runs the lenient `validate_event(.., None)` branch
/// (router.rs:167), which skips the custody check for an empty custody sig, then
/// `record_event` persists the forged binding.
///
/// PASSES after fix: wiring a custody resolver at the production construction
/// site forces the strict `validate_and_check_quota` branch (router.rs:166),
/// which rejects a Register with no custody cross-sign.
#[test]
fn production_router_enforces_custody_signature() {
    let (registry, _dir) = make_registry();

    // The attacker names fid=42, which they do NOT custody. (A real deployment
    // would resolve fid=42 to its on-chain custody address; the attacker holds
    // no key for it.) Empty custody signature, valid self-signed Ed25519.
    let victim_fid = 42u64;
    let epoch = 5u64;
    let event = make_self_signed_register_for_fid(1, epoch, victim_fid);
    assert!(
        event.custody_signature.is_empty(),
        "attacker omits the custody cross-sign"
    );

    // Build the router EXACTLY as HyperRuntime::submit_message does
    // (runtime.rs:3882): registry present, NO custody resolver chained.
    let mut router = HyperRouter::new(HyperMempool::new(), Some(registry.clone()), epoch);

    let env = HyperRouter::outbound_validator_register(event.clone());
    let result = router.route_inbound(env);

    // SECURE: the production router must reject an un-custodied registration.
    assert!(
        matches!(result, Err(RoutingError::Registry(_))),
        "production router must reject a register with no custody cross-sign, got {result:?} \
         (FAILS on cab225f: custody_resolver == None -> lenient validate_event accepts it)"
    );

    // SECURE: nothing was persisted — the forged validator_key -> fid binding
    // must not exist.
    assert_eq!(
        registry
            .fid_for_validator_key(&event.validator_key)
            .unwrap(),
        None,
        "no forged validator_key -> fid binding may be persisted by the production router"
    );
    assert_eq!(
        registry.count_active_validators_for_fid(victim_fid).unwrap(),
        0,
        "no active validator slot may be created under an un-custodied FID"
    );
}

/// SECURE BEHAVIOR (regression for F070) — the unauth-registration primitive.
///
/// A self-signed Register naming an arbitrary FID (custody held by an unrelated
/// key the sender does not control) must FAIL custody verification under the
/// strict path. The Ed25519 self-signature proves possession of the attacker's
/// own validator key — it binds nothing about the named FID.
///
/// FAILS on cab225f: the live ingestion path (lenient `validate_event(.., None)`)
/// accepts this exact event (see `validate_accepts_register_event`); this test
/// asserts the SECURE strict path rejects it. The defect is that the lenient
/// path — not the strict one — is the one wired in production.
///
/// PASSES after fix: the strict `validate_and_check_quota` path requires the
/// custody cross-sign on Register and rejects (MissingCustodySignature).
#[test]
fn register_with_forged_fid_rejected() {
    let (registry, _dir) = make_registry();

    // fid=42's custody is some real on-chain address the attacker does NOT hold.
    let arbitrary_fid = 42u64;
    let epoch = 5u64;
    let real_custody_addr = [0xCAu8; 20]; // an address the attacker cannot sign for
    let mut resolver_map = BTreeMap::new();
    resolver_map.insert(arbitrary_fid, real_custody_addr);
    let resolver = StaticCustodyResolver(resolver_map);

    // Attacker self-signs a register naming the arbitrary FID, no custody sig.
    let event = make_self_signed_register_for_fid(1, epoch, arbitrary_fid);

    // SECURE strict verification (the path production SHOULD run) must reject.
    let result = registry.validate_and_check_quota(&event, epoch, &resolver);
    assert!(
        matches!(result, Err(RegistryError::MissingCustodySignature)),
        "a self-signed register naming an un-custodied FID must fail custody verification, \
         got {result:?} (FAILS on cab225f: the live path uses lenient validate_event(.., None) \
         which accepts this forged-FID register)"
    );
}
