// =============================================================================
// Finding:  F024 — Pre-StartDkls buffered DKG drain feeds round messages to the
//                   ceremony state machine WITHOUT the F018 sender/peer-id check
//                   (`check_dkls_sender_against_propagation_source`), enabling
//                   broadcast-sender spoofing into a target node's DKG accumulator.
// Attack class: broadcast-sender-spoofing (rust-threshold-signing).
// Audited commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
//
// Placement: paste these tests INTO the existing `#[cfg(test)] mod tests` block
//            in `code/hypersnap/src/hyper/actor.rs` (alongside the other DKLS
//            tests, e.g. near `auto_trigger_fires_evaluate_epoch_on_boundary_crossing`
//            and the F016 buffer tests). They use `super::*`, the private
//            `HyperActor { .. }` constructor, the private `dispatch(..)` method,
//            the private `pending_dkls_inbound` / `active_dkls` fields, and the
//            private `check_dkls_sender_against_propagation_source(..)` method —
//            all reachable only from inside that module. The helpers
//            `make_runtime_with_srs`, `KzgSrs`, `VERKLE_DOMAIN`, `OsRng`,
//            `RECENT_EVIDENCE_CAP`, `mpsc`, and the event/field types are already
//            in scope there.
//
// Assertion (SECURE behavior): a DKG broadcast frame buffered before StartDkls,
//            whose inner `sender` index does NOT match its authenticated gossip
//            `propagation_source`, must be REJECTED on drain — i.e. it must NOT
//            be handed to `driver.submit(..)` / the ceremony state machine. The
//            drain path must re-apply `check_dkls_sender_against_propagation_source`
//            exactly as the live ingress path does (`actor.rs:1373`), which in
//            turn requires the pre-StartDkls buffer to RETAIN the
//            `propagation_source` it currently discards (`actor.rs:1337`).
//
// Expected result:
//   * FAILS on cab225f — the buffer fill stores ONLY `encoded`
//       (`buf.push(encoded)`, ~actor.rs:1337) and drops `propagation_source`;
//       the StartDkls drain (~actor.rs:1430-1467) re-opens each frame and calls
//       `driver.submit(m)` (~actor.rs:1444) with NO sender/peer-id check. The
//       spoofed party-2 commitment lands in `proof_commitments[2]`, and phase4
//       aborts blaming the (innocent) spoofed party 2 — a remotely triggerable
//       DKG liveness failure + blame mis-assignment.
//   * PASSES after the fix — the buffer stores `(encoded, propagation_source)`
//       and the drain runs `check_dkls_sender_against_propagation_source` before
//       `submit`, dropping the spoofed frame. Party 2's genuine, source-matched
//       commitment (delivered via the authenticated live path) then lets the
//       ceremony complete without a party-2 abort.
//
// Impact: liveness / blame mis-assignment, BOUNDED. phase4's cryptographic
//         verification converts the forgery into a `DklsError::Abort { party }`
//         (a per-epoch DKG abort/stall + an innocent committee member named in
//         the blame), NOT a silently poisoned group key.
//
// STATUS: UNVERIFIED
// =============================================================================

// ---- The tests below are intended to be spliced into `mod tests`. -----------
//
// They rely on items already imported at the top of `mod tests`:
//   use super::*;                              // HyperActor, HyperActorEvent, ActiveDkls, RECENT_EVIDENCE_CAP, mpsc, ...
//   use crate::hyper::runtime::HyperRuntime;   // (via make_runtime_with_srs)
//   use hypersnap_crypto::kzg::KzgSrs;
//   use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
//   use rand::rngs::OsRng;                      // re-exported through super::*
//   use std::sync::Arc;
// and the helper `fn make_runtime_with_srs(srs: Arc<KzgSrs>) -> (HyperRuntime, TempDir)`.

use hypersnap_crypto::dkls23::protocols::Parameters;
use hypersnap_crypto::dkls_ceremony::{DklsCeremonyCoordinator, DklsRoundMessage};

/// Target epoch for the spoofed ceremony. Chosen >= 2 so that the
/// per-epoch peer-id registry (`compute_active_peer_ids`, cutoff =
/// epoch - EPOCH_BUFFER - 1 = epoch - 2) can resolve a Register event
/// seeded at epoch 0.
const TARGET_EPOCH: u64 = 5;

/// libp2p peer-id the registry binds to committee party 2 — the honest
/// committee member whose `sender` slot the attacker spoofs. Party 2 is
/// chosen (NOT party 1, the local victim) for two reasons: (a) it has a
/// registered peer-id, so the F018 check is in ENFORCING mode for it (not
/// the F021 fail-open caveat); (b) party 1 self-records its OWN
/// `proof_commitments[1]` on advance, which would overwrite a self-spoof,
/// whereas slot 2 is only ever filled by a peer frame.
const HONEST_PARTY2_PEER_ID: &[u8] = b"honest-party-2-peer-id-bbbbbbbb";
/// libp2p `propagation_source` the attacker's gossip frame actually
/// arrives from. Distinct from every honest committee peer-id, so the F018
/// check must reject a frame claiming `sender = 2`.
const ATTACKER_PEER_ID: &[u8] = b"attacker-mesh-peer-id-zzzzzzzzzz";

/// The committee party index the attacker spoofs as the inner `sender`.
const SPOOFED_SENDER: u8 = 2;

/// Construct a bare actor for direct `dispatch` calls, mirroring the
/// `auto_trigger_fires_evaluate_epoch_on_boundary_crossing` and F016
/// tests' direct `HyperActor { .. }` construction.
fn make_actor_for_dispatch(runtime: HyperRuntime) -> HyperActor {
    let (_in_tx, in_rx) = mpsc::channel(8);
    let (out_tx, _out_rx) = mpsc::channel(8);
    HyperActor {
        runtime,
        active_dkls: None,
        pending_dkls_inbound: std::collections::BTreeMap::new(),
        active_dkls_sign: None,
        pending_dkls_blocks: std::collections::BTreeMap::new(),
        pending_dkls_messages: std::collections::BTreeMap::new(),
        pending_sign_queue: std::collections::VecDeque::new(),
        inbound: in_rx,
        outbound: out_tx,
        statsd: None,
        da_response_producer: None,
        last_da_responded_epoch: None,
        last_da_seed_signed_for_epoch: None,
        recent_evidence: std::collections::VecDeque::with_capacity(RECENT_EVIDENCE_CAP),
    }
}

/// Seed the three committee validators (party indices 1, 2, 3) with known
/// `libp2p_peer_id`s, so that in particular
/// `runtime.peer_id_for_party(TARGET_EPOCH, 2) == Some(HONEST_PARTY2_PEER_ID)`.
///
/// This takes `check_dkls_sender_against_propagation_source` OUT of its
/// permissive "no peer-id registered" fail-open mode (`actor.rs:2472-2479`)
/// for the spoofed party: with a registered peer-id, the check actively
/// rejects a `sender = 2` frame whose source != HONEST_PARTY2_PEER_ID.
///
/// `peer_id_for_party` resolves party index against
/// `get_active_validators_enforced(epoch)` (members sorted by
/// validator_key) and then against `compute_active_peer_ids(epoch)`. With
/// the default `min_validator_trust_score == 0.0` the trust gate is
/// disabled, so three Register events at epoch 0 become the enforced active
/// set at TARGET_EPOCH, ordered by validator_key. We pick ascending keys
/// (0x11.., 0x22.., 0x33..) so party indices 1, 2, 3 line up with the DKLS
/// committee enumeration.
fn seed_committee_peer_ids(runtime: &HyperRuntime) {
    // (validator_key first byte, fid, peer_id) for parties 1, 2, 3.
    let members: [(u8, u64, &[u8]); 3] = [
        (0x11, 1, b"honest-party-1-peer-id-aaaaaaaa"),
        (0x22, 2, HONEST_PARTY2_PEER_ID),
        (0x33, 3, b"honest-party-3-peer-id-cccccccc"),
    ];

    for (key_byte, fid, peer_id) in members {
        let validator_key = vec![key_byte; 32];

        let body = proto::HyperValidatorEventBody {
            event_type: proto::HyperValidatorEventType::Register as i32,
            validator_key: validator_key.clone(),
            transport_pubkey: vec![0u8; 32],
            registration_epoch: 0,
            operator_address: vec![],
            signature: Vec::new(),
            fid,
            custody_signature: vec![],
            validator_address: vec![0xab; 20],
            libp2p_peer_id: peer_id.to_vec(),
        };

        // Key layout consumed by ValidatorRegistry::compute_active_set /
        // compute_active_peer_ids: [HyperValidatorEvent][32B key][8B epoch BE].
        let mut key = Vec::with_capacity(1 + 32 + 8);
        key.push(crate::storage::constants::RootPrefix::HyperValidatorEvent as u8);
        key.extend_from_slice(&validator_key);
        key.extend_from_slice(&0u64.to_be_bytes());

        let mut value = Vec::new();
        prost::Message::encode(&body, &mut value).expect("encode validator event body");
        runtime.db.put(&key, &value).expect("seed validator event");

        // Bind the FID so any FID-keyed path is consistent (harmless when
        // the trust gate is off).
        let mut fid_key = Vec::with_capacity(1 + validator_key.len());
        fid_key.push(crate::storage::constants::RootPrefix::HyperValidatorFidLookup as u8);
        fid_key.extend_from_slice(&validator_key);
        runtime
            .db
            .put(&fid_key, &fid.to_be_bytes())
            .expect("seed validator->fid binding");
    }
}

/// A FRESH party-1 coordinator + driver for `target_epoch`, NOT yet
/// started. The actor's `StartDkls` handler calls `driver.start()` itself.
fn fresh_party1_driver(target_epoch: u64, session_seed: &str) -> crate::hyper::dkls_driver::DklsDriver {
    let parameters = Parameters {
        threshold: 2,
        share_count: 3,
    };
    let session_id = format!("F024-{session_seed}-{target_epoch}").into_bytes();
    let coordinator =
        DklsCeremonyCoordinator::new(target_epoch, parameters, 1, session_id).unwrap();
    crate::hyper::dkls_driver::DklsDriver::new(coordinator, 0)
}

/// Wrap a broadcast `DklsRoundMessage` in the plaintext wire frame the
/// gossip codec produces for `receiver()==None` variants
/// (`[DISCRIMINATOR_PLAINTEXT][bincode(msg)]`) — i.e. the exact `encoded`
/// bytes the buffer stores and the drain re-opens.
fn plaintext_broadcast_frame(msg: &DklsRoundMessage) -> Vec<u8> {
    assert!(
        msg.receiver().is_none(),
        "only broadcast variants travel as plaintext frames"
    );
    let raw = msg.to_bytes();
    let mut out = Vec::with_capacity(1 + raw.len());
    out.push(crate::hyper::dkls_wire_codec::DISCRIMINATOR_PLAINTEXT);
    out.extend_from_slice(&raw);
    out
}

/// Capture EVERY round message that parties 2 and 3 emit toward party 1
/// during an honest run of `session_seed`'s 2-of-3 ceremony — i.e. exactly
/// the inbound traffic party 1 must consume to reach phase4. Returned in
/// emission order. Includes party-2 and party-3 broadcasts plus the
/// peer-to-peer frames addressed to party 1.
///
/// Used by the primary test to replay AUTHENTICATED peer traffic into the
/// victim's active driver, while deliberately WITHHOLDING party 2's
/// Phase2ProofCommitment so the only candidate occupant of
/// `proof_commitments[2]` is the attacker's spoof (on cab225f).
fn honest_peer_traffic_for_party1(target_epoch: u64, session_seed: &str) -> Vec<DklsRoundMessage> {
    let parameters = Parameters {
        threshold: 2,
        share_count: 3,
    };
    let session_id = format!("F024-{session_seed}-{target_epoch}").into_bytes();
    let mut coords: Vec<DklsCeremonyCoordinator> = (1..=3u8)
        .map(|i| {
            DklsCeremonyCoordinator::new(target_epoch, parameters.clone(), i, session_id.clone())
                .unwrap()
        })
        .collect();

    let mut for_party1: Vec<DklsRoundMessage> = Vec::new();
    for c in coords.iter_mut() {
        c.start().unwrap();
    }
    loop {
        let mut wire = Vec::new();
        for i in 0..coords.len() {
            for m in coords[i].drain_outbound() {
                wire.push(m);
            }
        }
        for m in &wire {
            let sender = m.sender();
            let receiver = m.receiver();
            // Record anything party 1 should receive: broadcasts from peers,
            // or p2p frames addressed to party 1, from senders 2 or 3.
            if sender != 1 && (receiver.is_none() || receiver == Some(1)) {
                for_party1.push(m.clone());
            }
            // Route within the honest set to keep the ceremony advancing.
            for c in coords.iter_mut() {
                if c.party_index() == sender {
                    continue;
                }
                if let Some(r) = receiver {
                    if c.party_index() != r {
                        continue;
                    }
                }
                c.submit(m.clone()).unwrap();
            }
        }
        for c in coords.iter_mut() {
            c.try_advance().unwrap();
        }
        if coords.iter().all(|c| c.output().is_some()) {
            return for_party1;
        }
        assert!(!wire.is_empty(), "honest capture stuck without completion");
    }
}

/// The party-2 Phase2ProofCommitment from `session_seed`'s honest run.
fn party2_proof_commitment(target_epoch: u64, session_seed: &str) -> DklsRoundMessage {
    honest_peer_traffic_for_party1(target_epoch, session_seed)
        .into_iter()
        .find(|m| {
            m.sender() == 2 && matches!(m, DklsRoundMessage::Phase2ProofCommitment { .. })
        })
        .expect("party 2 emits a Phase2ProofCommitment")
}

/// PRIMARY regression test for F024.
///
/// Buffer a DKG broadcast frame whose inner `sender = 2` does NOT match the
/// gossip `propagation_source` (it arrives from ATTACKER_PEER_ID, while the
/// registry binds party 2's slot — and more importantly here, the spoof is
/// a party-2 commitment from an INDEPENDENT ceremony). Trigger the StartDkls
/// drain. SECURE: the spoofed frame is rejected on drain (the F018 check is
/// re-applied) and never reaches `proof_commitments[2]`, so the victim's
/// ceremony does not abort blaming party 2.
#[tokio::test]
async fn buffered_drain_reapplies_sender_check() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let (runtime, _dir) = make_runtime_with_srs(srs);
    seed_committee_peer_ids(&runtime);

    // Sanity: the F018 oracle that the fix must re-apply on drain DOES
    // reject this spoof (party 2's slot, arriving from the attacker's
    // peer-id). We assert the registry is wired for the SPOOFED party so
    // the check is in ENFORCING mode (not the F021 fail-open caveat), and
    // that a source-mismatched claim is rejected.
    let actor_probe = make_actor_for_dispatch(runtime);
    // peer_id_for_party(.., 2) resolves the registered validator at party
    // index 2 — proving the registry is populated (NOT fail-open) for the
    // party the attacker spoofs.
    assert_eq!(
        actor_probe
            .runtime
            .peer_id_for_party(TARGET_EPOCH, SPOOFED_SENDER),
        Some(HONEST_PARTY2_PEER_ID.to_vec()),
        "registry must bind party 2 to a peer-id so the F018 check is enforcing \
         for the spoofed party, not in permissive fail-open mode"
    );
    // A frame claiming sender == 2 from the attacker's peer-id is rejected
    // by the very check the drain is supposed to call.
    assert!(
        !actor_probe.check_dkls_sender_against_propagation_source(
            TARGET_EPOCH,
            SPOOFED_SENDER,
            Some(ATTACKER_PEER_ID),
        ),
        "control: check_dkls_sender_against_propagation_source must reject a \
         sender=2 frame arriving from a non-matching propagation_source"
    );
    let mut actor = actor_probe;

    // Forge a party-2 Phase2ProofCommitment from an INDEPENDENT ceremony
    // (different session seed => different group key). It is well-formed
    // bincode but cryptographically inconsistent with the victim's
    // ceremony, so if it is admitted into proof_commitments[2] the victim's
    // phase4 will abort blaming party 2.
    let forged_pc = party2_proof_commitment(TARGET_EPOCH, "attacker-independent");
    let spoof_frame = plaintext_broadcast_frame(&forged_pc);

    // (1) The frame arrives on gossip BEFORE this node starts its ceremony,
    // so it is buffered. It carries the authenticated attacker source.
    actor
        .dispatch(HyperActorEvent::InboundDkls {
            target_epoch: TARGET_EPOCH,
            encoded: spoof_frame,
            propagation_source: Some(ATTACKER_PEER_ID.to_vec()),
        })
        .await
        .expect("InboundDkls buffering arm returns Ok(())");
    assert!(
        actor.pending_dkls_inbound.contains_key(&TARGET_EPOCH),
        "frame should have been buffered (no active ceremony yet)"
    );

    // (2) StartDkls drains the buffer. On cab225f the drain submits the
    // spoofed frame unauthenticated; the fix must drop it.
    let driver = fresh_party1_driver(TARGET_EPOCH, "victim");
    actor
        .dispatch(HyperActorEvent::StartDkls {
            driver: Box::new(driver),
        })
        .await
        .expect("StartDkls returns Ok(())");

    // (3) Deliver the GENUINE peer traffic for the victim's OWN session
    // (parties 2 and 3), so the ceremony can advance to phase4 — but
    // DELIBERATELY WITHHOLD party 2's genuine Phase2ProofCommitment. That
    // makes the attacker's spoofed party-2 commitment the only candidate
    // occupant of `proof_commitments[2]`:
    //   * cab225f: the spoof was admitted on the unauthenticated drain and
    //     survives to phase4 ⇒ `DklsError::Abort { party: 2 }`.
    //   * fix: the spoof was dropped on drain ⇒ slot 2 is empty ⇒ phase4
    //     never runs (insufficient broadcasts) ⇒ no party-2 abort.
    //
    // We feed the authenticated peer frames straight into the active
    // driver's coordinator (`pub coordinator`), the faithful equivalent of
    // the live gossip path submitting source-matched frames.
    let peer_traffic = honest_peer_traffic_for_party1(TARGET_EPOCH, "victim");
    {
        let active = actor
            .active_dkls
            .as_mut()
            .expect("StartDkls installed an active ceremony");
        for m in peer_traffic {
            // Withhold party 2's genuine commitment so it cannot overwrite
            // (last-write-wins) the attacker's spoof in slot 2.
            if m.sender() == 2 && matches!(m, DklsRoundMessage::Phase2ProofCommitment { .. }) {
                continue;
            }
            // Genuine peer frames are accepted by the coordinator's own
            // cryptographic checks; submit them as the authenticated live
            // path would.
            let _ = active.driver.coordinator.submit(m);
        }
    }

    // Drive the victim's ceremony forward through phase4. `try_advance`
    // returns the abort as an Err (it does NOT stash it in `error()`), so
    // the abort surfaces as the dispatch result here.
    let advance_result = actor.dispatch(HyperActorEvent::AdvanceDkls).await;

    // Extract any phase4 abort party from the dispatch error chain:
    //   HyperActorError::Dkls(DklsDriverError::Dkls(DklsError::Abort { party })).
    let abort_party = match &advance_result {
        Err(HyperActorError::Dkls(crate::hyper::dkls_driver::DklsDriverError::Dkls(
            hypersnap_crypto::dkls_threshold::DklsError::Abort { party, .. },
        ))) => Some(*party),
        _ => None,
    };

    // SECURE expectation: the ceremony has NOT aborted blaming the spoofed
    // party 2.
    //   * cab225f: the spoofed party-2 commitment was admitted on the
    //     unauthenticated drain, survived to phase4, and produced
    //     `Abort { party: 2 }` ⇒ this assertion fails (regression caught).
    //   * fix: the spoof was dropped on drain ⇒ slot 2 empty ⇒ phase4 never
    //     ran ⇒ AdvanceDkls returned Ok ⇒ `abort_party == None` ⇒ passes.
    assert_ne!(
        abort_party,
        Some(2),
        "F024: the victim's DKG aborted blaming the spoofed party 2 — the \
         pre-StartDkls drain admitted an attacker's broadcast (inner sender=2) \
         that arrived from a non-matching propagation_source, because the \
         buffer discarded the source (actor.rs:1337) and the drain skipped \
         check_dkls_sender_against_propagation_source (actor.rs:1444). The \
         drain MUST re-apply the F018 check, as the live path does at \
         actor.rs:1373."
    );
}

/// COMPANION regression test for F024.
///
/// The pre-StartDkls buffer must RETAIN the authenticated
/// `propagation_source` alongside `encoded`, because the drain cannot
/// re-apply `check_dkls_sender_against_propagation_source` without it.
///
/// On cab225f the buffer is typed `BTreeMap<u64, Vec<Vec<u8>>>` and the
/// fill arm does `buf.push(encoded)` (actor.rs:1337) — the source is
/// structurally absent. The fix must change the buffer element type to
/// carry the source (e.g. `Vec<(Vec<u8>, Option<Vec<u8>>)>`), at which
/// point this assertion (that the buffered entry exposes the source it was
/// received with) becomes satisfiable.
///
/// This test pins the contract at the buffer's value shape. It is written
/// against the SECURE shape; on cab225f it fails to compile / fails the
/// retention assertion because `propagation_source` was dropped.
#[tokio::test]
async fn buffer_preserves_propagation_source() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let (runtime, _dir) = make_runtime_with_srs(srs);
    seed_committee_peer_ids(&runtime);
    let mut actor = make_actor_for_dispatch(runtime);

    let forged_pc = party2_proof_commitment(TARGET_EPOCH, "attacker-independent");
    let spoof_frame = plaintext_broadcast_frame(&forged_pc);

    actor
        .dispatch(HyperActorEvent::InboundDkls {
            target_epoch: TARGET_EPOCH,
            encoded: spoof_frame.clone(),
            propagation_source: Some(ATTACKER_PEER_ID.to_vec()),
        })
        .await
        .expect("InboundDkls buffering arm returns Ok(())");

    let buffered = actor
        .pending_dkls_inbound
        .get(&TARGET_EPOCH)
        .expect("frame buffered under TARGET_EPOCH");
    assert_eq!(buffered.len(), 1, "exactly one buffered frame");

    // SECURE expectation: the buffered entry retains BOTH the encoded
    // frame AND the propagation_source it arrived with, so the drain can
    // re-run check_dkls_sender_against_propagation_source.
    //
    // On the SECURE shape `pending_dkls_inbound: BTreeMap<u64, Vec<(Vec<u8>,
    // Option<Vec<u8>>)>>`, the line below reads `(encoded, source)`. On
    // cab225f the element is a bare `Vec<u8>` (just `encoded`) and the
    // source is gone — so this destructure does not match the stored shape,
    // pinning the regression at the buffer's type.
    let (entry_encoded, entry_source) = &buffered[0];
    assert_eq!(
        entry_encoded, &spoof_frame,
        "buffered entry must retain the original encoded frame"
    );
    assert_eq!(
        entry_source.as_deref(),
        Some(ATTACKER_PEER_ID),
        "F024: the pre-StartDkls buffer MUST retain propagation_source; on \
         cab225f it stores only `encoded` (actor.rs:1337), making the F018 \
         drain check structurally impossible."
    );
}
