# Hypersnap — Project Overview (Recon)

> Audit target pinned at commit `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
> (branch `pow`, PR #34 "proof of work (restored)").
> Recon run under brain library SHA `b2c8f8bade0bf4b91d254eb4d5774b7fd3e3c1ea`.
> **Revalidation run** — see "Revalidation focus" below.

## What it is

Hypersnap is a Rust blockchain node ("hyper layer") layered on top of a
Snapchain / Farcaster-style hub. It runs a **Tendermint-family BFT consensus**
(vendored Informal Systems *Malachite* engine) over an actor runtime
(`ractor` + Tokio), and adds a second, application-specific **"hyper" state
machine** that:

- Maintains a **verkle-tree** of confidential token state (locks, transfers,
  notes/nullifiers) committed via **KZG** commitments.
- Runs **threshold ECDSA (DKLS23 over secp256k1)** among the active validator
  set to produce standard `(r,s,v)` signatures over hyperblocks, reward
  issuances, trust snapshots, bridge merkle-root updates, owner rotations, and
  pause/upgrade authorizations.
- Implements **validator economics** — a *Proof-of-Quality* emission engine
  (`crates/proof-of-quality`, `src/emission/`), EigenTrust-based reputation
  scoring, mutuality transforms, retro-reward vesting, and **slashing** of
  equivocating validators (`src/hyper/slashing*.rs`).
- Bridges HYPER tokens to EVM L1/L2 chains via an on-chain **`HypersnapBridge`**
  UUPS-upgradeable contract (`contracts/src/HypersnapBridge.sol`) that mints
  wrapped `SNAP` on merkle-proof of a threshold-signed lock-leaf root, and
  observes EVM-side `burn` events to credit the hyper layer.

## What it does (primary flows)

1. **Consensus & block production** — Malachite proposes/decides Snapchain
   blocks; the hyper layer produces threshold-signed `HyperBlock`s carrying a
   verkle state root. (`src/consensus/**`, `src/hyper/{proposer,builder,runtime}.rs`)
2. **Hyper message ingress** — lock events, transfers, validator-registry
   events, token stake/unstake arrive via gossip (`TOPIC_HYPER_MESSAGES`) or
   HTTP, are admitted to the hyper mempool, and applied into the verkle tree.
3. **Block application / import** — inbound `HyperBlock`s (with their
   locks/transfers) are verified (threshold sig + recomputed state-root match)
   and imported. (`src/hyper/importer.rs`, `runtime::import_block`)
4. **DKLS23 ceremonies** — DKG and threshold-signing rounds run as gossip
   ceremonies routed through `dkls_*` drivers and the wire codec.
5. **Slashing evidence** — conflicting-block evidence is gossiped on
   `TOPIC_HYPER_EVIDENCE`, re-detected + signature-verified, persisted, and
   consumed at epoch boundaries for penalty enforcement.
6. **Bridge** — lock leaves accumulate under a merkle root; the active set
   threshold-signs root updates / owner rotations / pause / upgrade payloads,
   relayed permissionlessly to `HypersnapBridge` on each chain. EVM burns are
   watched and credited back.
7. **HTTP / gRPC / admin APIs** — a large read/query API surface
   (`src/api/**`, `src/network/{http_server,admin_server,server}.rs`) plus a
   replication service for sync.

## Boundaries (what is in / out of audit scope)

**In scope (integration code authored for Hypersnap):**
- `src/**` — node, hyper layer, consensus integration, network, api, mempool,
  storage, emission.
- `proto/**` — wire definitions.
- `crates/hypersnap-crypto`, `crates/hypersnap-wallet`,
  `crates/proof-of-quality`, `crates/hypersnap-bridge-ceremony`.
- `contracts/src/HypersnapBridge.sol` (+ its EIP-6492 helper under
  `src/core/validations/contract_signature/`).

**Out of scope (vendored upstream, audit is integration-only):**
- `crates/dkls23` — vendored DKLS23 implementation (review the *integration*
  wrapper in `hypersnap-crypto`/`src/hyper/dkls_*`, not the primitive itself).
- `crates/ed448-bulletproofs` — vendored from Quilibrium ceremonyclient.
- `../malachite/**` — vendored Malachite consensus engine (path deps).
- OpenZeppelin contracts under `contracts/lib/**`.
- `contracts/deployer-ui/**` — TypeScript deployment UI (not on-chain logic).

## Revalidation focus

A prior audit at the older commit `64493318…` confirmed two issues, claimed
fixed by PR #34. Recon has located both fix sites; the hunt must verify
completeness and check for regressions introduced by the restored branch:

- **F001 (Critical) — slashing-evidence ingestion accepted unsigned blocks.**
  Fix site: `src/hyper/actor.rs` `InboundEvidence` handler now calls
  `detect_conflicting_blocks` then `verify_evidence_signatures`
  (`src/hyper/slashing.rs`) before `runtime.record_evidence`. The "F026"
  cross-epoch handling was added at the same time — a regression surface.
- **F002 (High) — mempool/block-application skipped signature verification of
  `HyperLockEvent`.** `src/hyper/importer.rs::import_hyper_block` verifies the
  *block* threshold signature and recomputes the verkle root, but per-lock
  `HyperLockEvent.lock_signature` is **still never verified** in production
  (`mempool::submit_lock` → `validate_lock_event` is structural only;
  `builder.rs` zero-fills `lock_signature`). Flagged for the hunt as a possibly
  incomplete fix.

See `architecture.md` and `attack-surface.md` for detail.
