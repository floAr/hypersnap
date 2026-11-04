---
finding_id: F069
title: Every time a configured validator's PeerId opens a connection, the node runs `unsubscribe` + `subscribe` on all of its topics (at most once
severity: low
status: pending-validation
related_findings:
- F039
---
# F069 — Every time a configured validator's PeerId opens a connection, the node runs `unsubscribe` + `subscribe` on all of its topics (at most once per 15 s). In libp2p-gossipsub 0.48, `unsubscribe` sends PRUNE with a 10 s backoff to every mesh peer and records the same backoff locally. The `subscribe` that follows then rebuilds each mesh only from peers that were **not** in it before. A validator restart, a QUIC re-dial or a connection flap therefore tears down every topic mesh on every node that sees it, on both sides, for about 10 s. The replacement mesh is drawn from whatever other subscribed peers are connected, including unscored sybils. A misbehaving validator can repeat this every 15 s.

- **Severity:** Low, source-only. Only a configured validator identity can trigger it (honest churn or a malicious validator). `flood_publish` (default `true`) still delivers each node's own publishes to every directly connected subscriber. IHAVE/IWANT gossip covers part of the gap. The impact is degraded relay, mostly for read nodes and for validators that are not fully meshed, plus a better position for mesh-poisoning sybils. It is not a halt. The code is reachable only in snapchain mode (`src/main.rs`). In Hypersnap mode `validator_peers` is never set, so the code is dead there.
- **Confidence:** 0.6. The gossipsub semantics were checked against the vendored `libp2p-gossipsub-0.48.0` source. Network-level effects (delivery loss, how long sybils hold mesh slots) were not measured.
- **Category:** topic-mesh-poisoning / subscription lifecycle
- **Specialist:** p2p-gossip · task H055
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `last_validator_resub_at`, `VALIDATOR_RESUB_COOLDOWN` and the resub block are absent at the merge base `bdef7b7` (`git show bdef7b7:src/network/gossip.rs | grep -c validator_resub` → 0). The boot one-shot (`gossip.rs:1246-1264`) fires once per process and is benign.
- **PoC:** None (not built). Test sketch: extend `gossip_test.rs:403`. Use three nodes A, B, C, where C is in A's `validator_peers`, and let A–B form a mesh on `contact_info`. Reconnect C to A. Within 10 s, check that `A.gossipsub.mesh_peers(contact_info)` no longer contains B and that B's mesh no longer contains A. Then publish a relayed message from a fourth peer D that is connected only to B, and check that A gets it only through IHAVE, after a delay.

## Code facts

1. **Trigger.** On `ConnectionEstablished`, `if self.validator_peers.contains(&peer_id)` and 15 s have passed since the last cycle, the node runs `unsubscribe(topic); subscribe(topic)` on every `local_topics` entry (`src/network/gossip.rs:1212-1225`, cooldown `:582`). This runs on **every** new connection from that PeerId, not only on the first (`other_established`/`num_established` is not checked). The cooldown is one timestamp per node, so one validator is enough to keep the cycle going.
2. **Who is a validator.** In snapchain mode, `validator_peers = build_validator_peer_ids(latest_validator_public_keys)` (`src/main.rs:446-455`). `hypersnap_main.rs` never calls `set_validator_peers` (the only call site is `main.rs:455`) and clears `direct_peers` after the pivot (`src/node/hypersnap_main.rs:886-889`). In Hypersnap mode both the resub cycle and the boot one-shot are therefore dead code.
3. **`unsubscribe` = LEAVE.** `leave()` removes the mesh and, for every mesh peer, calls `make_prune(…, on_unsubscribe = true)` (`libp2p-gossipsub-0.48.0/src/behaviour.rs:1136-1160`). That sets `backoffs.update_backoff(topic, peer, unsubscribe_backoff)` locally (`:1118-1126`) and sends PRUNE with `backoff = 10` (`unsubscribe_backoff` default 10 s, `config.rs:449`). The remote obeys the PRUNE backoff and drops us from its mesh (`behaviour.rs:1526-1571, 1575-…`).
4. **`subscribe` = JOIN, excluding prior mesh peers.** `join()` fills the new mesh with up to `mesh_n` (= 10, `gossip.rs:643`) random subscribed peers, excluding any peer with `is_backoff_with_slack(topic, p)` (`behaviour.rs:1018-1027`). So it excludes exactly the peers that were in the mesh a moment ago. If every subscribed peer was in the mesh (the usual case for a node with ≤ 10 subscribed peers), the new mesh is **empty** until the backoff and slack run out, about 10.5 s at a 500 ms heartbeat.
5. **Who fills the gap.** Any connected peer can SUBSCRIBE to any topic. There is no subscription filter, and the topic carries no binding to the validator set. `PeerScoreParams::default()` has no topic parameters (`gossip.rs:670-678`), so P3 mesh-delivery scoring never evicts a mesh peer that drops messages. After the cycle, a node with ≥ 10 sybil subscribers connected (incoming connections are capped at 100, `gossip.rs:704-709`) gets a mesh made entirely of sybils. Afterwards the heartbeat adds honest peers only to meet `mesh_outbound_min` (2, `config.rs:453`) or when the mesh drops below `mesh_n_low` (5). Inbound sybils can hold most slots after the backoff ends.
6. **Graft-in-backoff penalties when two nodes cycle together.** One validator connecting to many nodes makes them cycle at about the same time. Take X1 and X2, where X1 is in X2's mesh but X2 is not in X1's. X2 prunes X1 and sets a backoff on it. X1 then grafts X2 (X1 has no backoff on X2), and X2 charges X1 a behaviour penalty (`behaviour.rs:1407-1432`). With ~10 topics, P7 = −10·n² passes `graylist_threshold` (−80) at n ≥ 3. X2 then ignores all of X1's RPCs (`behaviour.rs:3221-3225`) until the penalty decays (×0.2 per second). The window is short, but it lines up with the mesh flush.
7. **`decided_values` is not cycled.** Those topics are subscribed later, by `SubscribeToDecidedValuesTopic`, and are not pushed to `local_topics` (`gossip.rs:1997-2006`). The recovery the cycle is meant to provide therefore skips the topic that read nodes depend on. This is minor and listed for completeness.

## Failure / attack path

- **Honest churn.** In snapchain mode, any validator restart or QUIC re-dial makes every node connected to it (validators and read nodes) flush every topic mesh. The prior mesh partners back off from each other for about 10 s. Relayed traffic depends on flood-published originals and IHAVE/IWANT for that window. Read nodes are not directly connected to most publishers, so they lose relay paths the most.
- **Malicious or faulty validator.** A validator that opens a new connection to each node every 15 s keeps the network in this state about two-thirds of the time. Combined with sybil subscribers (fact 5), the flush shifts victims' meshes toward attacker peers, which can then withhold forwarded consensus and decided-value traffic. Delivery then falls back to flood-publish and IHAVE.

## Red-team

1. *Is it attacker-reachable without a validator key?* No PeerId spoofing is possible (Noise authenticates the PeerId). One possible lever: make a validator re-dial the victim, for example by taking its connection slots or making it restart. That is indirect, so the trigger is rated insider/churn.
2. *Doesn't flood_publish make the mesh irrelevant?* For a node's own publishes to directly connected subscribers, yes. Forwarding by intermediate nodes uses only the mesh. That covers read nodes, non-fully-connected validator sets, and every message a node relays. Delivery degrades rather than stops.
3. *Is it only 10 s per event?* For honest churn, yes, plus up to 15 s between triggers. The longer-lasting effect is fact 5: after the flush, the replacement mesh can stay sybil-heavy because no topic score evicts it.
4. *Is mesh poisoning already possible without this?* Partly. Without topic scoring, sybils can win mesh slots at random (no topic score params are configured). The cycle adds a deterministic eviction of the current honest mesh that an insider can trigger on demand. That is the incremental issue.
5. *Hypersnap mode?* The code is dead there (fact 2), so the post-pivot network is unaffected. The finding is limited to the snapchain-mode binary this PR ships. Hypersnap mode also lacks the reconnect fix it was written for. That part was not filed: gossipsub's `handle_graft` records the grafting peer's topics (`behaviour.rs:1376-1384`) and the bootstrap-peer bounce sweep covers bootstrap peers, so the stall partly self-heals.
6. *Could the cycle be a no-op because `subscribe` re-adds the same peers?* No. `make_prune` sets the local backoff (fact 3), and `join` filters on it (fact 4).
7. *Severity?* There is no fund or state impact and no halt, and an insider or churn is needed. Low.

## Fix

- Do not cycle unsubscribe/subscribe to re-announce. Instead, when a known validator connects with `other_established > 0`, disconnect its stale connection, or send a targeted re-announcement. If cycling is kept, call it only for the reconnecting peer's case: when `gossipsub.all_peers()` shows that peer with no topics after the settle window (the existing bounce sweep already does this for bootstrap/direct peers).
- If a cycle stays, set `unsubscribe_backoff` low (1 s) and debounce per peer, not per node.
- Add topic score parameters (P3 mesh-delivery, P4 invalid deliveries) for the consensus, decided-value and mempool topics, and use a subscription filter so that only the expected topic set is accepted.
- Add the `decided_values` topics to `local_topics` when they are subscribed.

## Files

- `src/network/gossip.rs:582, 633-678, 724-768, 1194-1264, 1997-2006`
- `src/main.rs:446-455`; `src/node/hypersnap_main.rs:880-901`
- `libp2p-gossipsub-0.48.0/src/behaviour.rs:960-1050 (join), 1075-1160 (make_prune/leave), 1363-1440 (handle_graft), 3221-3225 (graylist)`; `config.rs:418, 449-453`
