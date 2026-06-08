// ============================================================================
// Finding:   F013 — FullProposal gossip arm calls height().unwrap() before the
//            shard-id guard, so a peer can crash any node with a height-less
//            FullProposal frame.
// Placement: src/network/gossip.rs test module (mirror of
//            src/network/gossip_test.rs — the existing gossip decode tests,
//            e.g. `test_hyper_envelope_messages_are_ignored_on_receive`).
//            To wire in: drop these fns into `gossip_test.rs` (or a
//            `#[cfg(test)] mod tests` in `gossip.rs`); they reuse that file's
//            imports and `statsd_client()` / `Config::new` harness.
//
// Assertion: A `GossipMessage::FullProposal` with `height = None` (proto3
//            omitted message field) fed through the REAL decode entry
//            (`SnapchainGossip::map_gossip_bytes_to_system_message`) is
//            dropped (returns `None`) and does NOT panic. The optional
//            second test does the same for the `round` follow-up.
//
// Expected:  PANICS on cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 — the
//            `FullProposal` arm's first statement is `full_proposal.height()`
//            (= `self.height.clone().unwrap()` in proto/src/lib.rs), which
//            unwraps `None` and aborts the actor thread before the existing
//            `shard_id()` Result guard is reached.
//            PASSES after the fix (guard `height`/`round` presence and
//            `return None` on the missing-field case, as the sibling `Status`
//            arm already does).
//
// STATUS: UNVERIFIED
// ============================================================================
//
// The harness below mirrors `test_hyper_envelope_messages_are_ignored_on_receive`
// in src/network/gossip_test.rs verbatim: build a real `SnapchainGossip` via
// `SnapchainGossip::create`, encode a real `proto::GossipMessage`, then call the
// real ingress `map_gossip_bytes_to_system_message(PeerId::random(), bytes, None)`.
//
// These imports assume placement inside `gossip_test.rs` (which already brings
// most of them in). Listed here so the file is self-describing.
use crate::consensus::consensus::SystemMessage;
use crate::network::gossip::{Config, SnapchainGossip};
use crate::proto::{self, FarcasterNetwork};
use crate::storage::store::test_helper::statsd_client;
use libp2p::{identity::ed25519::Keypair, PeerId};
use prost::Message as _;
use tokio::sync::mpsc;

const HOST_FOR_TEST: &str = "127.0.0.1";
// Distinct from the ports used by the existing gossip_test.rs tests.
const F013_BASE_PORT: u32 = 9482;

// Build a real, started-capable `SnapchainGossip` exactly the way the existing
// decode tests do. `map_gossip_bytes_to_system_message` is a `&mut self` method,
// so we need a live instance; nothing in the missing-`height` panic path touches
// the network, so a locally-bound instance is sufficient to exercise the sink.
async fn make_gossip(port_offset: u32) -> SnapchainGossip {
    let keypair = Keypair::generate();
    let addr = format!(
        "/ip4/{HOST_FOR_TEST}/udp/{}/quic-v1",
        F013_BASE_PORT + port_offset
    );
    let config = Config::new(addr.clone(), addr);
    let (system_tx, _system_rx) = mpsc::channel::<SystemMessage>(10);
    SnapchainGossip::create(
        keypair,
        &config,
        Some(system_tx),
        true,
        FarcasterNetwork::Devnet,
        statsd_client(),
        Vec::new(),
    )
    .await
    .unwrap()
}

// Encode a `GossipMessage::FullProposal` over the wire with the given
// `FullProposal`, using the REAL prost encoder — same path the broadcaster uses
// (see `GossipEvent::BroadcastFullProposal` in gossip.rs).
fn encode_full_proposal_frame(full_proposal: proto::FullProposal) -> Vec<u8> {
    proto::GossipMessage {
        gossip_message: Some(proto::gossip_message::GossipMessage::FullProposal(
            full_proposal,
        )),
    }
    .encode_to_vec()
}

/// F013 (primary): a `FullProposal` with `height` omitted (proto3 message field
/// left `None`) must be DROPPED, not panic the node.
///
/// On cab225f the arm's first statement `let height = full_proposal.height();`
/// calls `self.height.clone().unwrap()` on `None` and panics — a single
/// unauthenticated gossip frame aborts the actor thread. After the None-guard
/// fix the frame is dropped and this returns `None`.
#[tokio::test]
async fn fullproposal_without_height_is_dropped_not_panic() {
    let mut gossip = make_gossip(0).await;

    // proto3: `Height height = 1;` is a singular message field -> Option<Height>
    // in prost. Omitting it (`height: None`) is well-formed wire and decodes
    // successfully — the attacker's exact crafted frame.
    let full_proposal = proto::FullProposal {
        height: None,
        round: 0,
        proposer: vec![],
        proposed_value: None,
    };
    let bytes = encode_full_proposal_frame(full_proposal);

    // Real decode entry. On cab225f this line panics inside the FullProposal arm
    // (`height().unwrap()`) before the existing `shard_id()` guard is reached.
    // SECURE behavior: drop the frame, return None, never panic.
    let result = gossip.map_gossip_bytes_to_system_message(PeerId::random(), bytes, None);

    assert!(
        result.is_none(),
        "F013: a FullProposal frame with height=None must be dropped (None), \
         not routed; reaching this assert at all means the height().unwrap() \
         panic was fixed"
    );
}

/// F013 (optional follow-up): a `FullProposal` with a present `height` but the
/// `round().unwrap()` shape the validator flagged. `round` is a scalar
/// (`int64 round = 2`) that proto3 defaults to 0, so this constructs a
/// well-formed frame and asserts it is handled without panicking — guarding the
/// general "missing/invalid required-ish field on a peer-decoded FullProposal
/// must not panic" property. With a valid `height` present, the SECURE outcome
/// is that the frame is processed and routed (`Some`) OR dropped (`None`), but
/// in neither case does the node abort.
#[tokio::test]
async fn fullproposal_without_round_is_dropped() {
    let mut gossip = make_gossip(1).await;

    // Present height (so the height-guard passes) with a default round. This
    // exercises the path past the height check into `round()`/`shard_id()`,
    // confirming no panicking accessor remains downstream on a peer-decoded
    // FullProposal.
    let full_proposal = proto::FullProposal {
        height: Some(proto::Height {
            shard_index: 1,
            block_number: 0,
        }),
        round: 0,
        proposer: vec![],
        proposed_value: None,
    };
    let bytes = encode_full_proposal_frame(full_proposal);

    // Must not panic. We do not assert Some/None here (a valid height legitimately
    // routes); the regression property is "no abort on a peer-controlled frame".
    let _ = gossip.map_gossip_bytes_to_system_message(PeerId::random(), bytes, None);
}
