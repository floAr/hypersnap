---
finding_id: F039
title: The `membership` topic diverges from FIP §4.6/§4.10
severity: low
status: pending-validation
related_findings:
- F010
---
# F039 — The `membership` topic diverges from FIP §4.6/§4.10. (a) Read nodes never subscribe to it, although the spec says "all peers, read nodes too" get the alerts. (b) A received `ValidatorTransitionAlert` is only logged, so no node acts on it ("read nodes that sync from V find other sync sources" is not implemented). (c) The alert carries no signature and no sender, and nothing checks it against the validator set. Because of (b) this cannot be exploited today. (d) The spec's peer-score exemption for `DEPARTING` validators is absent.

> **Status 2026-11-04 (post-validation):** Scope: introduced by the PR (the `membership` topic does not exist at bdef7b7).


- **Severity:** Low / Informational (spec-divergence). The code is safe today because alerts are inert. If (b) is later implemented as the spec describes, (c) becomes a sender-spoofing vector: any peer could forge `TRANSITION_DEPARTING` for honest validators and steer read nodes away from them. Which side looks wrong: the code, for (a), (b) and (d). For (c) the spec is underspecified. It should say that alerts are advisory only, or that they are signed by the validator or derivable from certified shard-0 state.
- **Category:** spec-divergence
- **Specialist:** p2p-gossip · attack class: sender-spoofing-inside-payload · task H040
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34).

## Code facts

1. Read nodes subscribe only to `read-node-peers` and `mempool`, plus `contact-info` (`src/network/gossip.rs:727-742`, `761-767`). `membership` and `certificate` are subscribed only in the validator branch of a Hypersnap namespace (`gossip.rs:743-759`).
2. The receive arm `GossipMessage::TransitionAlert(alert)` logs and returns `None` (`gossip.rs:1902-1914`).
3. `ValidatorTransitionAlert { validator_key, effective_epoch, transition, alert_block }` has no signature field (`proto/definitions/hypersnap.proto:114-119`, identical to the FIP §4.6 listing). Validators produce alerts from local shard-0 state (`chain/transitions.rs:50-75`; `node/hypersnap_main.rs:691-705`).
4. No `DEPARTING` peer-score handling exists (`PeerScoreParams::default()`, `gossip.rs:670-678`; grep `DEPARTING` in `src/network` → none).
5. FIP §4.10 also assigns the `certificate` topic to LWE-MS2 rounds. The node subscribes but publishes and handles nothing there. That is the consequence of the bundled-Falcon design already recorded in F010 and is not re-filed.

## Recommendations

- Subscribe read nodes to `membership` and implement the sync-source switch from **locally derived** transitions (shard-0 state through the replica). Treat gossip alerts as hints only, or sign them with the validator's Falcon key and check the signature against `set(epoch)`.
- Implement or remove the `DEPARTING` peer-score exemption, and update the FIP to match.
