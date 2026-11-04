---
finding_id: F062
title: A voting validator with the default empty `[onchain_events] rpc_url` has no Optimism view, so it prevotes nil on every shard-0 block that
severity: medium
status: pending-validation
related_findings:
- F015
- F045
---
# F062 — A voting validator with the default empty `[onchain_events] rpc_url` has no Optimism view, so it prevotes nil on every shard-0 block that carries an IdRegistry or KeyRegistry event. The shipped mainnet compose sets up validators (`consensus_key_file`) but leaves that RPC unset, and the node only logs a `warn!`. If such validators hold more than 1/3 of the weight, no Farcaster registration, transfer, recovery or signer event reaches Hypersnap, and every round led by a correctly configured proposer with pending events times out. A smaller share still cuts the fault margin for those blocks.

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from time/defaults cross-cut 2026-11-04

- **Severity:** Medium, source-only. Honest misconfiguration, no attacker. The impact depends on how many genesis or later validators run the shipped template. Above 1/3 of the weight, on-chain events (FID registrations, custody transfers and recoveries, KeyRegistry signer adds and removes) stop for the whole network, and shard-0 throughput degrades in every round that an RPC-equipped proposer leads. Below 1/3, those blocks need ≥ 2/3 of the weight from the *configured* validators alone, so a few offline nodes stall on-chain events. Operators can fix it by editing config, but nothing in the node or template tells them they must.
- **Confidence:** 0.7. The code path is short and certain. Unmeasured: how genesis operators will configure their nodes, and whether events in a failed proposal are re-offered (a failed round loses the messages it pulled from the proposer's mempool; if the relay doesn't re-send, events are lost for good from that proposer).
- **Category:** zero-valued config reaches consensus validation / proposer-validator view divergence / unsafe default
- **Specialist:** cross-cut (time-and-defaults) · 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/watchers.rs`, `src/node/hypersnap_main.rs` and the shard-0 engine are new. The `[hypersnap]` validator section of `docker-compose.mainnet.yml` was added by the PR. `onchain_events::Config::default()` (empty `rpc_url`) is inherited.
- **PoC:** None, reasoned from source. Test sketch: `NodeWatchers { follower: false, onchain: None, .. }` as the validator's `Watchers`, and a proposal with one `Sys::OnChainEvent`. `engine.validate(..)` returns `Invalid("system message is not in this node's view")`.

## Code facts

1. **The view is optional and empty by default.** `start_watchers` builds `NodeWatchers { follower, ..Default::default() }` (`onchain: None`). If `app_config.onchain_events.rpc_url` is empty, it logs `warn!("No Optimism RPC endpoint: on-chain events are not watched")` and returns (`src/node/hypersnap_main.rs:382-414`). `onchain_events::Config::default()` has `rpc_url: String::new()` (`src/connectors/onchain_events/mod.rs:158-168`).
2. **A non-follower without a view accepts no event.** `onchain_event_ok = self.follower || self.onchain.is_some_and(|v| v.is_final(event, 0))` (`src/chain/watchers.rs:316-318`). `follower` is true only when `consensus_key_file` is empty (`hypersnap_main.rs:793`).
3. **One unseen event makes the whole block invalid.** In `Mode::Validate`, each `OnChainEvent` or `InboundBurn` must pass the view check, or the block fails with "system message is not in this node's view" (`src/chain/shard0/engine.rs:759-783`).
4. **The proposer has no such check.** In `Mode::Propose`, every final event from its own relay is included (`engine.rs:760-762`). The relay hands IdRegistry and KeyRegistry events (not StorageRent or Tier) to the mempool once they are final at its own head (`watchers.rs:180-230`). A proposer with an RPC therefore keeps proposing events that RPC-less validators reject.
5. **The shipped mainnet template.** `docker-compose.mainnet.yml:43-58`: the `[hypersnap]` section invites a validator ("A validator: its Falcon-512 consensus key. Without one, the node follows." with `consensus_key_file` commented in). It has no `[onchain_events]` section. The only Optimism URL it mentions is `recovery_watcher_rpc_url` (pre-pivot). The site docs (`site/docs/pages/node-types.mdx:71-80`) describe `ONCHAIN_CONFIG_RPC_URL` and `l1_rpc_url`, not `onchain_events.rpc_url`.
6. **No startup guard.** Nothing refuses to start a voting validator without the Optimism view. The same is true of `bridge_watchers` (F015).

## Failure path

1. Genesis validators start from the mainnet compose and add their Falcon keys. Some of them, weight `w`, don't add `[onchain_events] rpc_url`.
2. A FID registers or transfers on Optimism. Validators that have an RPC see it final at head − 64 − 2 and propose it.
3. The `w` validators prevote nil on that block. If `w > 1/3`, it never gets 2/3: the round times out, and the next proposer either has the RPC (fails again) or doesn't (proposes a block without events, which passes).
4. Result: shard 0 keeps going, but on-chain events never commit. New Farcaster FIDs can't migrate, register signers via KeyRegistry, or get their custody clock and escrow updated. Throughput drops roughly in proportion to the share of RPC-equipped proposers.

## Red-team

1. *Same as F015?* Same pattern (a validator-local view gates block validity, with no reconciliation), but a different subsystem and trigger. F015 covers inbound burns and their `bridge_watchers` config. This finding covers the much more frequent Optimism IdRegistry/KeyRegistry stream and its `onchain_events.rpc_url`, which the shipped template omits. Dedupe as related-but-distinct. One fix (a startup guard plus template keys) covers both.
2. *Do operators "obviously" set it?* Snapchain read nodes (the pre-pivot role of the same container) don't need it, and the template the PR ships doesn't mention it for the post-pivot validator. That is why it is rated Medium, not Low.
3. *Followers?* They return `true` (`follower` short-circuit) and are unaffected.
4. *Commit path?* `Mode::Commit` skips the view check, so a misconfigured validator still follows blocks decided without it.
5. *Safety?* Unaffected. This is liveness and functionality only.
6. *Event loss?* Unverified. If events in a failed proposal are dropped from the proposer's mempool and not re-relayed, the damage outlasts the config fix. Check `spawn_relay` (pending is cleared on hand-off, `watchers.rs:~225-232`) against the mempool's behaviour on a failed round.

## Fix

- Refuse to start a non-follower Hypersnap validator on mainnet or testnet without `onchain_events.rpc_url` (and, per F015, without at least one `bridge_watchers` entry). At minimum, log at `error!` and expose a health flag.
- Add `[onchain_events] rpc_url` and `[[hypersnap.bridge_watchers]]` to the mainnet compose `[hypersnap]` validator block, with a comment that they are required for voting.
- Longer term: the same view-reconciliation design as F015 (for example, drop an item a proposer has re-proposed N times without success).

## Files

- `src/node/hypersnap_main.rs:352-414, 793`
- `src/chain/watchers.rs:180-232, 306-331`
- `src/chain/shard0/engine.rs:759-797`
- `src/connectors/onchain_events/mod.rs:158-168`
- `docker-compose.mainnet.yml:43-58`
