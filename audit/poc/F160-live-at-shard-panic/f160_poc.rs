// PoC for PR#32 (4a6bca5) F160 — LiveAtRateLimits::consume_for_fid `.unwrap()`
// node-crash on a FID routed to a shard the node does NOT host.
//
// ROOT CAUSE (src/mempool/mempool.rs:209-234):
//     let shard_id = self.message_router.route_fid(fid, self.num_shards);
//     let stores   = self.shard_stores.get(&shard_id).unwrap();   // <-- panics
// `num_shards` is network-wide (consensus.num_shards) but `shard_stores`
// only holds the locally-hosted subset (consensus.shard_ids; populated in
// snapchain_node.rs:83-123). On a subset-hosting validator (e.g.
// num_shards=2, shard_ids=[1]) ~half of all FIDs route to shard 2, which is
// absent from `shard_stores`, so `get(&2)` -> None -> `.unwrap()` -> panic.
// The LIVE_AT limiter is ALWAYS-ON (mempool.rs:712-719, no enable_rate_limits
// gate, unlike the general RateLimits), so this is reachable BY DEFAULT.
//
// REACHABILITY (gossip, no auth):
//   gossip.rs:943-956  gossiped UserMessage -> MempoolRequest::AddMessage(_, Gossip, None)
//   main.rs:1178-1183  validator system loop forwards SystemMessage::Mempool -> mempool_tx (no shard filter)
//   mempool.rs:1099    Mempool::run -> self.insert(message, source)
//   mempool.rs:899     insert -> route_mempool_message -> vec![route_fid(fid, num_shards)] (the NON-HOSTED shard)
//   mempool.rs:947     insert_into_shard(non_hosted, ..) -> message_is_valid(non_hosted, .., at_admission=true)
//   mempool.rs:813     message_is_valid -> message_exceeds_rate_limits
//   mempool.rs:712-713 is_live_at -> live_at_rate_limits.consume_for_fid(fid)
//   mempool.rs:212     shard_stores.get(&non_hosted).unwrap() -> PANIC
// No signature/engine validation precedes the limiter; is_live_at only
// inspects data.body. A real, honestly-signed LIVE_AT for any FID on a
// non-hosted shard triggers it (no forgery required) — also an honest-traffic
// stability bug, not solely an adversarial DoS.
//
// ----------------------------------------------------------------------------
// HOW TO RUN (this PoC is DESIGN-FAITHFUL, inserted into the library test mod):
//
//   The stock `setup(..)` helper in src/mempool/mempool_test.rs ALWAYS populates
//   shard_stores with shards 1..=num_shards (mempool_test.rs:77-82), so it CANNOT
//   model the subset-hosting topology (shard_ids ⊊ {1..=num_shards}) that the bug
//   requires. This PoC therefore builds the Mempool directly with num_shards=2 but
//   shard_stores = {1: ...} ONLY, mirroring snapchain_node.rs:83-123.
//
//   Insert the `#[tokio::test]` below into the `#[cfg(test)] mod tests` block at
//   the bottom of src/mempool/mempool_test.rs (it reuses that module's existing
//   imports: Mempool, mempool::Config, Stores, test_helper, create_user_data_add,
//   MempoolMessage, etc.), then under WSL nightly:
//
//     CARGO_TARGET_DIR=target-wsl-pr32 cargo +nightly test --lib \
//        f160_poc_live_at_unwrap_panic_on_non_hosted_shard -- --nocapture
//
//   Restore the tree afterwards:  git checkout -- src/mempool/mempool_test.rs
//
//   EXPECTED (bug present @ 4a6bca5): the `mempool.run()` task PANICS with
//     "called `Option::unwrap()` on a `None` value"  at mempool.rs:212,
//   the reply channel's sender is dropped, and `reply_rx.await` returns Err.
//   The test asserts that the panic occurred (reply_rx errs / task aborted),
//   demonstrating a remote, unauthenticated, default-config node crash.
//
//   AFTER FIX (graceful non-hosted handling): no panic; the LIVE_AT for a
//   non-hosted-shard FID is handled without crashing (rejected or skipped).
// ----------------------------------------------------------------------------

#[tokio::test]
async fn f160_poc_live_at_unwrap_panic_on_non_hosted_shard() {
    use std::collections::HashMap;

    // --- Build the subset-hosting topology the bug requires -----------------
    // num_shards = 2 (network-wide), but this node hosts ONLY shard 1.
    let num_shards: u32 = 2;

    let keypair = libp2p::identity::ed25519::Keypair::generate();
    let _ = &keypair;
    let statsd_client = StatsdClientWrapper::new(
        cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
        true,
    );

    let (mempool_tx, mempool_rx) = mpsc::channel(100);
    let (_messages_request_tx, messages_request_rx) = mpsc::channel(100);
    let (_shard_decision_tx, shard_decision_rx) = broadcast::channel(100);
    let (_block_decision_tx, block_decision_rx) = broadcast::channel(100);
    let (gossip_tx, _gossip_rx) = mpsc::channel(100);

    // shard_stores holds ONLY shard 1 — exactly what snapchain_node.rs:83-123
    // does for config.shard_ids = [1]. Shard 2 is deliberately ABSENT.
    let mut shard_stores: HashMap<u32, Stores> = HashMap::new();
    let (engine1, _tmp1) = test_helper::new_engine().await;
    shard_stores.insert(1, engine1.get_stores());
    assert!(!shard_stores.contains_key(&2), "shard 2 must NOT be hosted");

    let (block_engine, _) = block_engine_test_helpers::setup();

    let mut mempool_config = mempool::Config::default();
    mempool_config.enable_rate_limits = false; // DEFAULT — proves always-on LIVE_AT limiter
    let mut mempool = Mempool::new(
        mempool_config,
        FarcasterNetwork::Devnet,
        mempool_rx,
        messages_request_rx,
        num_shards,
        shard_stores,
        block_engine.stores(),
        gossip_tx,
        shard_decision_rx,
        block_decision_rx,
        statsd_client,
    );

    // --- Pick a FID that routes to the NON-HOSTED shard (2) -----------------
    // route_fid(fid, 2) = (u32::from_be_bytes(sha256((fid as u32).to_be_bytes())[..4]) % 2) + 1
    // FID 2 hashes to shard 2 (verified: FidOnDisk = u32). Sanity-check it here.
    let fid_on_non_hosted_shard: u64 = 2;
    let router = crate::mempool::routing::ShardRouter {};
    {
        use crate::mempool::routing::MessageRouter;
        assert_eq!(
            router.route_fid(fid_on_non_hosted_shard, num_shards),
            2,
            "FID must route to the non-hosted shard 2"
        );
    }

    // Run the validator mempool loop in a task; a panic inside it will drop the
    // reply sender (so reply_rx errs) and abort the JoinHandle.
    let handle = tokio::spawn(async move {
        mempool.run().await;
    });

    let live_at = create_user_data_add(
        fid_on_non_hosted_shard,
        proto::UserDataType::LiveAt,
        &"https://example.com/live".to_string(),
        None,
        None,
    );

    // Deliver via the SAME entrypoint gossip uses: AddMessage. Source::Gossip
    // mirrors the unauthenticated peer-forwarded path exactly.
    let (reply_tx, reply_rx) = oneshot::channel();
    mempool_tx
        .send(MempoolRequest::AddMessage(
            MempoolMessage::UserMessage(live_at),
            MempoolSource::Gossip,
            Some(reply_tx),
        ))
        .await
        .unwrap();

    // BUG PRESENT: consume_for_fid does shard_stores.get(&2).unwrap() -> panic.
    // The reply is never sent (sender dropped on panic) => reply_rx.await is Err,
    // and the mempool task terminates with a panic.
    let reply = reply_rx.await;
    let joined = handle.await; // JoinError if the task panicked

    assert!(
        reply.is_err() || joined.is_err(),
        "Expected the mempool task to PANIC on shard_stores.get(&2).unwrap() \
         (node crash). reply={:?}, joined_is_err={}",
        reply,
        joined.is_err()
    );
    assert!(
        joined.is_err(),
        "Expected JoinError from the panicked mempool task (node crash)."
    );
}
