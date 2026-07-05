---
id: ONBD-1
specialist: node-lifecycle-actor
attack_class: consensus-state-divergence
title: Hyper-native onboarding assigns FIDs from a per-node global counter at gossip-ingestion time, outside the consensus state root, so honest nodes permanently disagree on the custody→FID identity map (and, transitively, on custody-rotation and stake-binding state) with no recovery path
severity_initial: critical
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/native_onboard.rs
  - src/hyper/runtime.rs
  - src/hyper/actor.rs
  - src/hyper/builder.rs
validation:
  validator: validator
  verdict: CONFIRMED
  confidence: 0.88
  hypotheses_walked: 6
---

## Summary

The new `NativeOnboard` message is applied to authoritative RocksDB state
(`HyperNativeFidSequence`, `HyperNativeCustodyToFid`) inside
`HyperRuntime::submit_message`, which every node runs on **every inbound
gossip frame** (`HyperActorEvent::InboundMessage → runtime.submit_message`,
`actor.rs:1344-1352`) — with **no proposer/leader/sync gate**.
`apply_onboarding` (`native_onboard.rs:525-594`) assigns the new FID by reading
a **global, mutable, per-node** monotonic counter (`next_hyper_fid`,
`native_onboard.rs:171-183`) and writing `HyperNativeCustodyToFid[custody] =
fid` (`582-583`). The EIP-712 body commits to `custody`,
`anchor_block_height`, `anchor_block_hash`, `gate_commitment` — **not** to the
assigned FID (`native_onboard.rs:238-286`) — and there is **no per-custody
nonce**.

Because gossipsub imposes no total order across distinct originators, two
onboardings from distinct custodies are applied in different relative orders on
different nodes, so they receive **different FIDs on different nodes**. None of
this state is part of the consensus `hyper_state_root` (`builder.rs:247` =
verkle-tree `root_commitment()` only), so the divergence produces **no
state-root mismatch, no import failure, and no chain halt** — the honest
validator set silently, permanently disagrees on issued identity.

## Trace

Custodies `C_A`, `C_B` each broadcast a valid POW onboarding; current
`HyperNativeFidSequence = N` on all nodes.

- **Node 1**, gossip order A→B: `apply_onboarding(A)` → `C_A → N`, seq→N+1;
  `apply_onboarding(B)` → `C_B → N+1`, seq→N+2.
- **Node 2**, gossip order B→A: `C_B → N`, then `C_A → N+1`, seq→N+2.

The counter value converges (both reach N+2), but the binding does not:
node1 has `{C_A:N, C_B:N+1}`, node2 has `{C_A:N+1, C_B:N}`. FID `N` is owned by
different custodies on different nodes.

- **Silent:** the maps are off-root, so both nodes keep producing/importing
  blocks with byte-identical `hyper_state_root`; import never re-derives or
  checks onboarding state.
- **Unrecoverable:** replays are rejected `CustodyAlreadyOnboarded`
  (`native_onboard.rs:535-540`), so a node cannot re-run to fix its guess; a
  resynced node replays blocks (which never carry onboarding —
  `PendingMessage` has only `Lock`/`Transfer`) and rebuilds the map only from
  live gossip going forward. No admin reconcile path exists.
- **Amplification (same root cause):** custody rotation authorizes on
  `lookup_custody_fid(current) == fid` (`native_onboard.rs:723-734`), so a
  rotation of FID `N` signed by `C_A` succeeds on node1 and fails on node2
  (`CurrentCustodyMismatch`), forking rotation-nonce state too; stake binding
  (`stake_binding_key`) inherits the split.

## Why it breaks the established model

Every other message routed through `submit_message` (TokenTransfer,
FeeDeposit, custody rotation, stake lock/release) converges across nodes purely
via per-FID **monotonic-nonce gating** (`runtime.rs:839-847`, `922-931`;
rotation nonce `native_onboard.rs:747-754`): the nonce forces a deterministic
per-sender total order independent of gossip arrival and makes replays
idempotent. Onboarding is the sole message whose *output* (which FID a custody
receives) depends on the **global** counter value at local apply time, and it
has no nonce binding a custody to a specific FID — so the convergence mechanism
the rest of the system relies on cannot apply.

## Validation (8-hypothesis red-team → CONFIRMED)

Refutation hypotheses walked and defeated: (H1) proposer-only/mempool gate —
none exists, `submit_message` mutates at admission on every node; (H2)
reconciliation at import — `import_block` (`runtime.rs:4775-4899`) re-applies
only transfers+locks, `PendingMessage` (`builder.rs`) has no onboarding
variant, so onboarding can never enter a block; (H3) folded into a root/
checkpoint — no, written straight to RocksDB off `self.tree`; (H4) any
consensus reader — only off-root readers (rotation, stake binding), so no
main-ledger halt/fund-loss amplifier (this bounds the blast radius); (H5)
assignment secretly deterministic — no, mutable counter, FID not in the signed
payload; (H6) recoverable — no, replay-rejected and not reconstructable from
consensus.

## Impact / Severity

Permanent, unrecoverable divergence of issued-identity state across the honest
validator set — a fundamental agreement failure for the hyper-native
onboarding feature. Rated **Critical** under a consensus/state-divergence
rubric. A reviewer applying a strict "Critical = fund-loss/chain-halt of the
main ledger" rubric could argue **High**, since the blast radius is confined to
the off-root onboarding/rotation/stake subsystem (no demonstrated consumer that
halts the main ledger or moves funds).

## Suggested direction (non-binding)

Bring onboarding into the consensus model the rest of the system uses:
(a) route `NativeOnboard` through the mempool and assign the FID
deterministically during block production / `import_block` from block-canonical
order (like transfers), so every node re-derives the identical custody→FID
binding; and/or (b) remove the global counter and derive the FID
deterministically from custody/anchor (with collision handling) so assignment
is arrival-order-independent; and/or (c) fold `HyperNativeFidSequence` +
`HyperNativeCustodyToFid` (+ rotation/stake state) into the verkle state root so
a divergence halts the chain instead of silently forking identity.
