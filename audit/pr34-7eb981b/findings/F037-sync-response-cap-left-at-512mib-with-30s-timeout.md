---
finding_id: F037
title: The Hypersnap sync behaviour keeps Malachite's default `max_response_size` of 512 MiB, which is about 30 times the largest valid response
severity: low
status: pending-validation
---
# F037 — The Hypersnap sync behaviour keeps Malachite's default `max_response_size` of 512 MiB, which is about 30 times the largest valid response (one block of at most 16 MiB plus its certificate). The PR also raised the sync request timeout from 5 s to 30 s. A peer that a syncing node picks as a sync source can stream up to 512 MiB into a buffer for each in-flight request. The buffer is allocated from the length prefix and filled as bytes arrive, and the node keeps the whole body before decoding it.

- **Severity:** Low. Memory pressure on syncing nodes from a malicious sync peer. It needs the attacker to be selected (it advertises a high tip through `Status` gossip, which is unauthenticated) and to have real bandwidth, about 140 Mbit/s to fill 512 MiB within the 30 s timeout. Confidence 0.7.
- **Category:** resource exhaustion (gossip-message-size-no-cap, sync request/response)
- **Specialist:** p2p-gossip · task H039
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). The 30 s `HYPERSNAP_SYNC_REQUEST_TIMEOUT` is new. The 512 MiB cap is the inherited Malachite default.
- **PoC:** None (source-only).

## Code facts

1. `sync::Behaviour::new(sync::Config::default().with_request_timeout(… HYPERSNAP_SYNC_REQUEST_TIMEOUT))` (`src/network/gossip.rs:685-691`) does not call `with_max_response_size`.
2. Malachite `sync::Config::default()` sets `max_request_size: 1 MiB` and `max_response_size: 512 MiB` (`malachite/code/crates/sync/src/behaviour.rs:47-55`). A setter `with_max_response_size` exists (`behaviour.rs:41-44`).
3. `read_length_prefixed` reads a u32 length, checks it against `max_len`, then `vec![0u8; len]` and `read_exact` (`malachite/code/crates/sync/src/rpc.rs:97-114`). Memory is committed as bytes arrive, up to 512 MiB, and is held until the timeout or completion. `map_sync_message_to_system_message` then decodes the full body again (`gossip.rs:1957-1972`).
4. `HYPERSNAP_SYNC_REQUEST_TIMEOUT = 30 s` (`gossip.rs:84-87`) gives a slow peer six times longer than snapchain's 5 s to fill the buffer.
5. `Status` gossip is attributed to the *forwarding* peer (`MalachitePeerId::from_libp2p(&peer_id)`, where `peer_id` is `propagation_source`; `gossip.rs:1320-1322`, `1876-1899`), and carries an unauthenticated height. Any peer can advertise a tip that makes it a sync candidate.

## Red-team

- *Is a valid response ever close to 512 MiB?* No. A `ValueResponse` carries one value: `HYPERSNAP_MAX_VALUE_BYTES` (17 MiB) plus a commit certificate. A `VoteSetResponse` is small.
- *Is the cap new?* No, it is the inherited Malachite default. This finding is about the Hypersnap configuration not tightening it while it tuned the timeout for block size.
- *Overlap with the gossipsub findings?* Different path (request-response, not gossipsub), and a different root cause (the cap is not configured).

## Recommendations

- `sync::Config::default().with_request_timeout(…).with_max_response_size(HYPERSNAP_MAX_VALUE_BYTES + 1 MiB)` in a Hypersnap namespace, and a matching `max_request_size` (requests are tiny, so 64 KiB).
- Optionally, score down or ban a sync peer whose response fails to decode or exceeds the expected size.
