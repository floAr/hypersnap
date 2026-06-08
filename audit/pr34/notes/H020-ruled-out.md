---
id: H020
specialist: p2p-gossip
attack_class: gossip-message-replay
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/network/gossip.rs
  - code/hypersnap/src/hyper/gossip_adapter.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/slashing_store.rs
  - code/hypersnap/src/hyper/mempool.rs
  - code/hypersnap/src/hyper/rewards.rs
---

# H020 — gossip-message-replay of InboundMessage / InboundEvidence — RULED OUT

## Scope
Replay of application-level hyper frames re-injected across peers/epochs after
state has changed: `HyperActorEvent::InboundMessage` (lock / transfer / other
hyper messages) and `HyperActorEvent::InboundEvidence` (slashing). Question:
can an old, validly-signed lock/transfer/evidence frame be re-gossiped later
to double-apply state or re-trigger slashing? Is there nonce / seen-cache /
epoch-binding replay protection?

## Method
1. Traced the gossip ingress for the hyper topics: `gossip.rs` `Gossipsub`
   message handler → `map_gossip_bytes_to_system_message` → (`HyperWire` arm,
   `gossip.rs:1099-1144`) → `wire_to_event_with_source` (`gossip_adapter.rs`) →
   `hyper_actor_tx` channel → actor `handle_event`.
2. For `InboundEvidence`, examined both the in-memory ring-buffer dedupe and
   the durable `slashing_store` keying.
3. For `InboundMessage`, enumerated every `submit_message` dispatch arm in
   `runtime.rs` and checked each downstream `apply_*` / mempool path for its
   own replay guard (nonce / nullifier / issued-set / epoch watermark /
   content-addressed key).

## Transport layer is sound (not the issue, but worth noting)
`gossip.rs:314` sets `ValidationMode::Strict` and `:324`
`MessageAuthenticity::Signed(key)`, and the libp2p gossipsub `message_id_fn`
provides its own msg-id dedupe. F018 (`:1110-1119`) binds the app-level sender
to the gossipsub originator. So the transport gives one layer of dedupe, but
the audit assumption is correctly that the *application* layer must not rely
on it — and it does not.

## InboundEvidence — replay-protected (two layers)
`actor.rs:1587-1620`. Each evidence frame is reduced to a content-addressed
dedupe key `(min(epoch_a,epoch_b), lo_hash, hi_hash)` (`:1589-1597`):

- **In-memory fast path:** `recent_evidence` VecDeque (cap
  `RECENT_EVIDENCE_CAP = 256`, `actor.rs:1038`). A replay present in the buffer
  is dropped (`hyper.evidence.dropped_replay`, `:1598-1600`).
- **Durable path:** `runtime.record_evidence` → `slashing_store.record`
  (`slashing_store.rs:50-71`). The row is keyed by `make_key`
  (`:153-168` = `(min_epoch, canonical_block_id, lo_hash, hi_hash)`), fully
  content-addressed and order-insensitive (hashes sorted). `record` checks
  existence and is idempotent — a replay lands on the same key and is a no-op
  put. The epoch-boundary consumer `slashed_validators_for_epoch`
  (`runtime.rs:4191`) reads the deduped store, so a replayed frame cannot
  double-record or re-slash even after the 256-entry ring buffer rotates past
  it.
- **Epoch binding:** F026 dedupe key and `verify_evidence_signatures`
  (`:1605-1607`) verify each evidence block against *its own epoch's* group
  key, so an old frame cannot be re-validated against a newer epoch's key.

Minor, non-finding observation: after the in-memory ring buffer rotates, a
replayed evidence frame still re-emits `EvidenceConfirmed` (one-hop
rebroadcast, `:1616-1618`) even though the durable `record` is a no-op. This
is at most trivial gossip amplification (bounded by gossipsub's own msg-id
dedupe at the next hop), not a state-integrity or double-slash issue.

## InboundMessage — every dispatch arm has its own replay guard
`actor.rs:1215-1223` forwards verbatim to `runtime.submit_message`
(`runtime.rs:3664`). There is no broad app-level seen-cache, but each arm is
individually replay-safe:

- **TokenTransfer** (`:3684`, `apply_token_transfer` `:700-737`) →
  `reward_store.apply_transfer(..., body.nonce)`. Per-FID strictly-monotonic
  nonce (`rewards.rs:373-386`, `expected = current+1`, else `NonceMismatch`).
  Replay fails once the nonce advances.
- **FeeDeposit / Shield** (`:3692`, `:3704`) — same per-FID nonce check.
- **InboundBurn** (`:3759`, `apply_inbound_burn` `:1292`) — threshold-sig
  verified, then `(source_chain_id, burn_id)` nullifier key checked
  (`:1348-1357`); already-processed burns short-circuit to `Ok(false)`.
- **RewardIssuance** (`:3669`, `apply_reward_issuance` `:561`) — per
  `(epoch, fid, market)` issued-set via `was_issued` / `credit_if_unissued`
  (`:576-626`). Re-applying an already-issued reward credits nothing.
- **TrustSnapshotUpdate** (`:3676`, `:638`) — epoch-monotonicity watermark
  `last_trust_snapshot_epoch` (`:646-653`); replaying an older-epoch snapshot
  is rejected `EpochRollback`.
- **Confidential Transfer** (`:3720-3743`) — nullifier-not-spent check via
  `validate_against_store(&note_store)` plus mempool nullifier dedupe
  (`mempool.rs:149-161`).
- **Miniapp register/update/etc.** — per-FID nonce key (`miniapp_nonce_kv`,
  `runtime.rs:3110`).
- **Lock** (router → `mempool.submit_lock`, `mempool.rs:119-129`) — admitted
  by `lock_id`; verkle insertion (`lock_event.rs:192-199`) is keyed by
  `lock_id`, so a re-gossiped lock overwrites the same leaf rather than
  producing a second state delta (content-addressed idempotency). The lock
  *mint / balance-closure* and *signature-verification* concerns are tracked
  separately under F035 and F002 respectively — those are forgery / mint
  correctness issues, not gossip-replay, and are out of this hunt's scope.

## Conclusion
Both target frame classes are replay-protected by epoch-binding plus a
per-arm replay primitive (monotonic nonce, nullifier set, issued-set, epoch
watermark, or content-addressed durable key). An old validly-signed
lock/transfer/evidence frame re-injected after state change cannot
double-apply or re-trigger slashing. No gossip-message-replay finding for
this hunt.
