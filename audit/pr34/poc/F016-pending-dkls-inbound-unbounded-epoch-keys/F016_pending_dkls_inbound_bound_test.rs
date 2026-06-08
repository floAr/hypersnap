// =============================================================================
// Finding:  F016 — F023a pre-StartDkls buffer keyed by attacker-controlled
//                   `target_epoch` with no global cap or stale-epoch eviction,
//                   enabling unbounded memory growth from unauthenticated gossip.
// Attack class: mailbox-ordering-assumption (node-lifecycle-actor).
// Audited commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
//
// Placement: paste these tests INTO the existing `#[cfg(test)] mod tests` block
//            in `code/hypersnap/src/hyper/actor.rs` (after the other DKLS tests,
//            e.g. near `auto_trigger_fires_evaluate_epoch_on_boundary_crossing`).
//            They use `super::*`, the private `HyperActor { .. }` constructor,
//            the private `dispatch(..)` method, and the private
//            `pending_dkls_inbound` field — all of which are only reachable from
//            inside that module. The helpers `make_runtime_with_srs`,
//            `KzgSrs`, `VERKLE_DOMAIN`, `OsRng`, `RECENT_EVIDENCE_CAP` and the
//            event/field types are already in scope there.
//
// Assertion (SECURE behavior): feeding `InboundDkls` for many distinct,
//            attacker-chosen `target_epoch` values must NOT grow
//            `pending_dkls_inbound` without bound. The number of buffered epoch
//            keys must stay <= a small cap, and/or epochs far from the current
//            one must be rejected before buffering.
//
// Expected result:
//   * FAILS on cab225f — the buffering branch does
//       `self.pending_dkls_inbound.entry(target_epoch).or_default()` with the
//       ONLY bound being `PENDING_DKLS_INBOUND_CAP_PER_EPOCH` (per-epoch entry
//       count). There is no cap on the number of distinct epoch KEYS and no
//       stale/far-future rejection, so `pending_dkls_inbound.len()` grows 1:1
//       with the number of distinct attacker `target_epoch` values.
//   * PASSES after the fix — a global epoch-key cap (evicting oldest/farthest)
//       and/or a plausible-window check on `target_epoch` keeps the map bounded.
//
// STATUS: UNVERIFIED
// =============================================================================

// ---- The two tests below are intended to be spliced into `mod tests`. --------
//
// They rely on the following items already imported at the top of `mod tests`:
//   use super::*;                                  // HyperActor, HyperActorEvent, RECENT_EVIDENCE_CAP, ...
//   use crate::hyper::runtime::HyperRuntime;       // (via make_runtime_with_srs)
//   use hypersnap_crypto::kzg::KzgSrs;
//   use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
//   use rand::rngs::OsRng;                          // re-exported through super::*
//   use std::sync::Arc;
// and the helper `fn make_runtime_with_srs(srs: Arc<KzgSrs>) -> (HyperRuntime, TempDir)`.

/// Construct a bare actor for direct `dispatch` calls, mirroring the
/// `auto_trigger_fires_evaluate_epoch_on_boundary_crossing` test's direct
/// `HyperActor { .. }` construction. The inbound/outbound channels are unused
/// (we call `dispatch` directly) but must exist for the struct.
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

/// Regression test for F016.
///
/// An attacker on the public `hyper/dkg/v1` gossip topic emits `InboundDkls`
/// frames with a distinct, arbitrary `target_epoch` per frame. With no active
/// ceremony, each lands in the pre-StartDkls buffer keyed by `target_epoch`.
/// On `cab225f` there is no cap on the number of distinct epoch keys, so the
/// `BTreeMap` grows 1:1 with the attacker's epoch choices — unbounded memory.
///
/// SECURE behavior: the number of buffered epoch keys stays bounded by a small
/// cap regardless of how many distinct `target_epoch` values are fed.
#[tokio::test]
async fn pending_dkls_buffer_bounded_across_epochs() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let (runtime, _dir) = make_runtime_with_srs(srs);
    let mut actor = make_actor_for_dispatch(runtime);

    // Attacker feeds many distinct, attacker-chosen target_epochs. No active
    // ceremony exists for any of them, so each takes the buffering branch.
    // Far-future / wide range: none of these will ever receive a matching
    // honest StartDkls, so nothing is ever drained.
    const FLOOD_EPOCHS: u64 = 5_000;
    for i in 0..FLOOD_EPOCHS {
        // Spread across a wide, far-future range to model attacker control of
        // the full u64 target_epoch space (gossip_adapter copies it verbatim).
        let target_epoch = 1_000_000_000_u64 + i * 7;
        actor
            .dispatch(HyperActorEvent::InboundDkls {
                target_epoch,
                // Arbitrary bytes: the buffering branch pushes `encoded`
                // verbatim, BEFORE any decrypt / F018 authentication.
                encoded: vec![0xAB; 64],
                propagation_source: None,
            })
            .await
            .expect("InboundDkls buffering arm returns Ok(())");
    }

    // SECURE expectation: a global cap on the number of buffered epoch keys
    // (with eviction) and/or far-future rejection keeps this small. A
    // reasonable cap is on the order of the honest StartDkls window; we assert
    // it is at least far below the flood count. Pick a generous ceiling so the
    // test pins "bounded" without hard-coding the exact remediation constant.
    const MAX_BUFFERED_EPOCH_KEYS: usize = 256;
    let buffered_keys = actor.pending_dkls_inbound.len();
    assert!(
        buffered_keys <= MAX_BUFFERED_EPOCH_KEYS,
        "F016: pre-StartDkls buffer grew without bound across attacker-chosen \
         target_epochs: {} distinct epoch keys buffered after {} frames \
         (expected <= {}). On cab225f the BTreeMap has no global key cap and no \
         stale/far-future eviction, so it grows 1:1 with attacker epoch choices \
         — a remote, unauthenticated memory-exhaustion DoS.",
        buffered_keys,
        FLOOD_EPOCHS,
        MAX_BUFFERED_EPOCH_KEYS,
    );
}

/// Regression test for F016 (optional companion).
///
/// A single `InboundDkls` whose `target_epoch` is implausibly far from the
/// current/processable window must be dropped before being buffered. On
/// `cab225f` it is buffered unconditionally (no window check at the adapter or
/// at the head of the `InboundDkls` arm).
///
/// SECURE behavior: a far-future epoch leaves `pending_dkls_inbound` empty.
#[tokio::test]
async fn far_future_epoch_dkls_rejected() {
    let mut rng = OsRng;
    let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
    let (runtime, _dir) = make_runtime_with_srs(srs);
    let mut actor = make_actor_for_dispatch(runtime);

    // current epoch on a fresh runtime is 0; u64::MAX/2 is wildly out of range.
    let absurd_epoch = u64::MAX / 2;
    actor
        .dispatch(HyperActorEvent::InboundDkls {
            target_epoch: absurd_epoch,
            encoded: vec![0xCD; 64],
            propagation_source: None,
        })
        .await
        .expect("InboundDkls arm returns Ok(())");

    assert!(
        actor.pending_dkls_inbound.is_empty(),
        "F016: a far-future target_epoch ({}) was buffered instead of dropped; \
         the buffer must reject epochs outside the plausible StartDkls window. \
         buffered keys = {:?}",
        absurd_epoch,
        actor.pending_dkls_inbound.keys().collect::<Vec<_>>(),
    );
}
