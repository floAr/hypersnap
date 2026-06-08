---
id: F016
specialist: node-lifecycle-actor
attack_class: mailbox-ordering-assumption
file_paths:
  - src/hyper/actor.rs
  - src/hyper/gossip_adapter.rs
  - src/hyper/dkls_supervisor.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: F023a pre-StartDkls buffer keyed by attacker-controlled target_epoch with no global cap or stale-epoch eviction, enabling unbounded memory growth from unauthenticated gossip
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The F023a fix buffers `InboundDkls` round messages that arrive before the
matching `StartDkls` in `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>`,
keyed by `target_epoch`. The ordering assumption baked into this design is:
"every buffered epoch will eventually be drained by a matching `StartDkls`."
An adversary who controls gossip arrival (the threat model the buffer was
written for) violates that assumption. `target_epoch` is fully
attacker-controlled and the buffering path performs **no authentication**, so
an attacker can allocate an unbounded number of 256-entry per-epoch buffers
that are never drained — a memory-exhaustion DoS against every node on the
topic.

## Where

`src/hyper/actor.rs`, `dispatch` arm `HyperActorEvent::InboundDkls`
(lines ~1321-1395), buffering branch:

```rust
let is_active = self.active_dkls.as_ref()
    .map(|d| d.driver.target_epoch() == target_epoch)
    .unwrap_or(false);
if !is_active {
    let buf = self.pending_dkls_inbound.entry(target_epoch).or_default();
    if buf.len() < PENDING_DKLS_INBOUND_CAP_PER_EPOCH {   // 256
        buf.push(encoded);
    } else { /* warn + drop */ }
    return Ok(());                 // <-- returns BEFORE any decrypt/auth
}
```

Drain is the only removal path, on the matching `StartDkls` (line ~1430):

```rust
if let Some(buffered) = self.pending_dkls_inbound.remove(&target) { ... }
```

The per-epoch cap (`PENDING_DKLS_INBOUND_CAP_PER_EPOCH = 256`, line ~1045)
is the *only* bound. There is no cap on the number of epoch keys, no eviction
of stale-epoch entries, and no pruning on epoch advance / `DkgFinalized`.
A full-file grep confirms `pending_dkls_inbound` is mutated in exactly two
places: the `entry().or_default()` insert above and the `remove(&target)`
drain above.

## Why it is exploitable

1. **`target_epoch` is attacker-controlled and unvalidated.** The gossip
   adapter (`gossip_adapter.rs`, `wire_to_event`, line ~84) maps
   `proto::HyperWireDkg.target_epoch` straight into
   `HyperActorEvent::InboundDkls { target_epoch: d.target_epoch, .. }` with no
   range/committee check. The full `u64` space is reachable from the wire.

2. **The buffering branch runs before authentication.** On the `is_active`
   path the actor opens the codec frame (`open_dkls_round_message`, which
   decrypts/authenticates) and applies the F018 `propagation_source` ↔
   committee cross-check. On the **buffering** path none of that happens —
   `encoded` is pushed verbatim and the arm returns `Ok(())`. So the attacker
   need not be in any committee, need not hold a transport secret, and need
   not produce a well-formed frame; arbitrary bytes are accepted into the
   buffer.

3. **`StartDkls` only fires for a bounded, honest window of epochs.** The
   supervisor (`dkls_supervisor.rs`, lines ~105-150) dispatches `StartDkls`
   only for `first_undispatched..=next_epoch`, and breaks once
   `blocks_until_target > start_lead_blocks`. `build_driver` may also fail
   (`skip StartDkls`), so even an in-window epoch can lack a `StartDkls`.
   Therefore the vast majority of attacker-chosen epochs (far-future, or any
   epoch in which this node is not a committee member) will **never** receive
   a matching `StartDkls`, so their buffers are never `remove()`d.

4. **Result: unbounded growth.** Each distinct attacker-chosen `target_epoch`
   allocates a fresh `Vec` holding up to 256 `encoded` blobs. By varying
   `target_epoch` per frame, the attacker grows the `BTreeMap` without bound.
   Memory consumed ≈ (number of distinct epochs sent) × up to 256 ×
   |encoded|. No size limit on `encoded` was found at the adapter layer, so
   each entry can be sizable, amplifying the per-frame cost. This wedges the
   actor (OOM / allocator pressure) and is a liveness/availability failure
   for the whole DKG path — a node killed this way cannot participate in DKG
   or threshold signing.

## Ordering-assumption framing

This is squarely a mailbox-ordering-assumption bug. The buffer exists to
tolerate the reorder where `InboundDkls(epoch=E)` arrives before
`StartDkls(epoch=E)`. The implementation assumes the reorder is *transient*
and *bounded* — that a `StartDkls` for `E` is forthcoming. Because gossip
arrival is adversarially controllable and `target_epoch` is unauthenticated,
the attacker supplies the "early" half of the pair (`InboundDkls`) for epochs
whose "late" half (`StartDkls`) the honest supervisor will never emit. The
prerequisite-before-dependent buffer becomes a permanent leak.

## Severity

High. Remote, unauthenticated, low-cost (single gossip topic; no committee
membership or key material required) memory-exhaustion DoS against any node
subscribed to the DKG topic. Availability impact on the DKG/threshold-signing
subsystem; a sustained flood can OOM-kill validators. Not direct fund-loss,
hence not critical, but a network-wide liveness threat.

## Suggested remediation

- Bound the buffer globally: cap the number of distinct epoch keys
  (`pending_dkls_inbound.len()`), evicting lowest/oldest, in addition to the
  per-epoch cap.
- Reject `target_epoch` far outside the plausible window at the adapter or at
  the head of the `InboundDkls` arm (e.g., `target_epoch` must be within
  `[current_epoch - k, current_epoch + start_lead_window]`), so only epochs
  that could plausibly receive a `StartDkls` are bufferable.
- Prune stale-epoch buffers on epoch advance / once an epoch is finalized or
  passes.
- Optionally bound `|encoded|` for buffered (pre-auth) frames.

## Verification notes

- `target_epoch` provenance: `src/hyper/gossip_adapter.rs` ~L84-88.
- Buffering branch returns pre-auth: `src/hyper/actor.rs` ~L1334-1345.
- Sole drain path: `src/hyper/actor.rs` ~L1430.
- No prune/evict/clear of `pending_dkls_inbound` anywhere (grep over
  `actor.rs`: only insert + `remove(&target)`).
- Bounded StartDkls window: `src/hyper/dkls_supervisor.rs` ~L105-150.
