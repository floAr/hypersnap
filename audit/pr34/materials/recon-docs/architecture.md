# Hypersnap — Architecture (Recon)

> Pinned commit `cab225f1…` (branch `pow`). Module map, dataflow, dependencies.

## 1. Workspace layout

Cargo workspace (`resolver = 2`). Root crate `hypersnap` (lib + bin) plus
members:

| Member | Role |
|---|---|
| `proto` | prost-generated wire types (`proto/definitions/*.proto`) |
| `crates/hypersnap-crypto` | ECDSA / BLS / KZG / verkle / merkle / DKLS integration, bridge payload+state encoders, transport AEAD |
| `crates/hypersnap-wallet` | wallet/key utilities |
| `crates/proof-of-quality` | PoQ scoring/emission primitives (app-pow, da-pow, eligibility, fees, scoring, uniqueness) |
| `crates/hypersnap-bridge-ceremony` | offline bridge ceremony calldata builder |
| `crates/dkls23` | **vendored** DKLS23 threshold ECDSA (out of scope) |
| `crates/ed448-bulletproofs` | **vendored** bulletproofs (out of scope) |
| `../malachite/**` (path deps) | **vendored** Malachite BFT consensus engine |

Top-level `src/` modules: `api`, `bin`, `bootstrap`, `connectors`,
`consensus`, `core`, `emission`, `hyper`, `jobs`, `mempool`, `network`,
`node`, `perf`, `storage`, `utils`, `version`.

## 2. Layered architecture

```
            ┌──────────────────────────────────────────────────────────┐
  EVM L1/L2 │ HypersnapBridge.sol (UUPS, ERC20Permit) — mint/burn/claim │
            └──────────────▲───────────────────────┬───────────────────┘
                threshold-signed │ root/owner/pause │ Burned events
                  merkle updates  │                  ▼
            ┌───────────────────────────────────────────────────────────┐
 HYPER      │ Hyper state machine (src/hyper/**)                          │
 LAYER      │  runtime ── actor (ractor) ── router ── builder/proposer    │
            │  verkle tree (KZG) ── mempool ── importer                   │
            │  DKLS23 DKG/sign drivers ── slashing ── emission/scoring    │
            └──────────────▲───────────────────────┬───────────────────┘
                gossip wire │ HyperWireMessage      │ HTTP/admin/RPC
            ┌───────────────────────────────────────────────────────────┐
 CONSENSUS  │ Malachite engine (vendored) via src/consensus/** +          │
 + NET      │ src/network/gossip.rs (libp2p gossipsub, mdns, quic)        │
            └──────────────▲───────────────────────┬───────────────────┘
            ┌───────────────────────────────────────────────────────────┐
 STORAGE    │ RocksDB (multi-CF) — src/storage/** (db, store, trie)       │
            └───────────────────────────────────────────────────────────┘
```

## 3. Key module-level dataflows

### 3.1 Gossip → actor (untrusted ingress)
`src/network/gossip.rs` (libp2p `gossipsub`) receives bytes on topics
(`consensus`, `mempool`, `decided-values`, and hyper topics). Per-variant size
caps (`MAX_HYPER_WIRE_BYTES=512KB`, etc.) are applied at ingress (F019).
Hyper frames are decoded by `src/hyper/gossip_adapter.rs::wire_to_event_with_source`
into `HyperActorEvent`s:
- `Block` → `InboundBlock { block, locks, transfers }`
- `Message` → `InboundMessage` (lock/transfer/validator-event)
- `Dkg` (round 11 DKLS-DKG / 12 DKLS-sign) → `InboundDkls{,Sign}` (carries
  `propagation_source` peer-id for F018 sender-binding)
- `Evidence` → `InboundEvidence { block_a, block_b }`

### 3.2 Block production & signing
`src/hyper/{proposer,builder}.rs` assemble a `HyperBlock`, compute the verkle
`root_commitment`, and threshold-sign the canonical signing payload
(`HyperBlockMetadata::signing_payload(epoch, signer_indices)`) via the DKLS23
sign driver. Verification is centralized in `src/hyper/sig_verify.rs`:
`verify_hyperblock_signature` recovers the 65-byte ECDSA sig to a keccak256
prehash and compares against the per-epoch DKLS group address resolved by
`runtime.dkls_group_address_for_epoch`. Same helper verifies reward issuance,
trust snapshot, DA epoch-seed, inbound-burn, and bridge owner/root payloads.

### 3.3 Block import
`HyperActorEvent::InboundBlock` → `runtime.import_block` →
`importer::import_hyper_block`:
1. verify block threshold signature (`sig_verify`),
2. replay all `locks`+`transfers` through `HyperBlockBuilder::apply_message`,
3. recompute verkle root and compare to signed `hyper_state_root`,
4. evict included entries from the hyper mempool,
5. `update_scores_for_block` credits proposer + signers.
   **Note:** per-lock `lock_signature` is NOT verified here (see attack-surface
   §F002). Lock authenticity is bound only transitively via the state-root +
   block threshold-sig (malicious-proposer threat model).

### 3.4 Slashing evidence
`InboundEvidence` → `detect_conflicting_blocks` (same `canonical_block_id`,
distinct block hash; accepts cross-epoch per F026) →
`verify_evidence_signatures` (each block verified against ITS OWN epoch group
key) → `runtime.record_evidence` → `SlashingEvidenceStore` (RocksDB,
idempotent on sorted block-hash key, capped at
`MAX_DISTINCT_CONFLICTS_PER_HEIGHT=8`). Confirmed evidence is re-broadcast on
`TOPIC_HYPER_EVIDENCE` and consumed at epoch boundary for penalty enforcement.

### 3.5 DKLS23 ceremonies
`src/hyper/dkls_{driver,sign_driver,supervisor,committee,wire_codec}.rs` +
`crates/hypersnap-crypto/src/dkls_*`. Wire codec seals P2P round messages to a
receiver's transport pubkey (AEAD); broadcast variants are plaintext. The actor
cross-checks inner sender vs libp2p `propagation_source` (F018) before
submitting to the driver. Pre-`StartDkls` round messages are buffered (F023a),
capped per epoch.

### 3.6 Emission / scoring / economics
`src/emission/{compute,eigentrust,mutuality,schedule,params}.rs` +
`crates/proof-of-quality/**` + `src/hyper/{scoring_driver,trust_store,
validator_score,validator_registry,rewards,retro_store}.rs`. Scoring runs at
epoch boundaries (single-party direct, multi-party via DKLS), threshold-signed,
and applied. Retro-reward vesting tranches applied per epoch.

### 3.7 Bridge (Rust ↔ Solidity)
`crates/hypersnap-crypto/src/{bridge_payload,bridge_state}.rs` build the
canonical signing payloads (`merkle_root_update`, `owner_update`,
`owner_acceptance`, …). The same byte layouts are parsed on-chain by
`HypersnapBridge.sol` (`ecrecover`, `MerkleProof`). `src/hyper/lock_event.rs`
`encode_lock_leaf`/`decode_lock_leaf` mirror the contract's leaf parsing — a
**cross-side encoding boundary** (serialization-boundary cross-cut).
`src/hyper/{bridge_burn_watcher,inbound_burn,token_escrow_*}.rs` watch EVM burns.

### 3.8 HTTP / admin / RPC
`src/network/http_server.rs` (HTTP→gRPC bridge, optional `IpRateLimiter`,
`authorization` header forwarding), `src/network/admin_server.rs`
(`authenticate_request` against `rpc_auth` user:pass list),
`src/network/server.rs` (tonic gRPC), `src/network/replication/**` (sync),
plus the read-only `src/api/**` query surface (SSRF guard in `src/api/ssrf.rs`).

## 4. External dependencies of note
- `libp2p 0.55` (gossipsub, mdns, noise, quic, request-response)
- `informalsystems-malachitebft-*` (path-vendored consensus)
- `dkls23` (vendored), `ed25519-dalek`, `sha2`, `blake3`, `hmac`
- `alloy-*` (EVM RPC/ABI/signing), `rocksdb` (git rev, multi-CF + jemalloc)
- `ractor` (actors), `tokio`, `tonic`/`prost`, `governor` (rate limit),
  `moka` (cache), `tantivy` (search index), `aws-sdk-s3`, `reqwest`.

## 5. Trust & integrity invariants (for the hunt)
- Every threshold-signed payload must cover all consensus-relevant fields
  (signing-payload-coverage cross-cut).
- Every gossip/HTTP/RPC byte→event boundary must validate before acting
  (untrusted-input-ingress cross-cut).
- Rust lock-leaf / bridge-payload encoders must byte-match the Solidity decoder
  (serialization-boundary cross-cut).
