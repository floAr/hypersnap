# Hypersnap — Attack Surface (Recon)

> Pinned commit `cab225f1…` (branch `pow`). Entry points, trust boundaries,
> untrusted-input ingress. Revalidation emphasis on F001/F002 surfaces.

## 1. Trust boundaries (overview)

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Gossip (libp2p) | local actor state | any network peer | `gossip.rs` size caps → `gossip_adapter.rs` decode → actor handlers |
| HTTP/gRPC API | node internals | any HTTP client | `http_server.rs` (rate limit, authz header), `server.rs` |
| Admin RPC | node operator | RPC caller | `admin_server.rs::authenticate_request` |
| On-chain (EVM) | threshold validator set | any relayer / EVM caller | `HypersnapBridge.sol` `ecrecover` + watermark + MerkleProof |
| EVM → hyper (burns) | EVM finality | EVM event payloads | `bridge_burn_watcher.rs`, `inbound_burn.rs` |
| DKLS wire | committee members | any gossip sender | `dkls_wire_codec.rs` AEAD + F018 peer-id bind |

## 2. Untrusted-input ingress points (gossip)

`src/network/gossip.rs` — libp2p gossipsub. Topics: `consensus`, `mempool`,
`decided-values`, hyper topics (`TOPIC_HYPER_{BLOCKS,MESSAGES,DKG,EVIDENCE}`).
Application-level per-variant caps (F019): `MAX_HYPER_WIRE_BYTES=512KB`,
`MAX_MEMPOOL_MESSAGE_BYTES=256KB`, `MAX_CONTACT_INFO_BYTES=4KB`,
`MAX_CONSENSUS_BYTES=64KB`, global transport cap 10MB.

`src/hyper/gossip_adapter.rs::wire_to_event_with_source` decodes `HyperWireMessage`:

| Wire body | Event | Downstream | Verification posture |
|---|---|---|---|
| `Block` | `InboundBlock{block,locks,transfers}` | `import_hyper_block` | block threshold-sig + state-root recompute; **no per-lock sig** |
| `Message` | `InboundMessage` | `runtime.submit_message` / mempool | structural `validate_lock_event` only on lock submit |
| `Dkg`(11/12) | `InboundDkls{,Sign}` | DKLS driver | AEAD frame + F018 sender↔peer-id bind |
| `Evidence` | `InboundEvidence` | detect+verify+record | F001 fix: sig-verified before persist |

## 3. Revalidation-critical surfaces

### 3.1 F001 — slashing-evidence ingestion (Critical, claimed fixed)
- **Ingress:** `TOPIC_HYPER_EVIDENCE` → `InboundEvidence` (`actor.rs` ~1587).
- **Fix observed:** handler runs `detect_conflicting_blocks`
  (`slashing.rs`) then `verify_evidence_signatures(ev, |epoch| runtime.
  dkls_group_address_for_epoch(epoch))` BEFORE `runtime.record_evidence`.
  `verify_evidence_signatures` verifies **each** block against its own epoch's
  group key (F026 cross-epoch).
- **Hunt must verify:**
  - Is the *enforcement* reader (epoch-boundary penalty) ALSO gated on
    verified evidence, or does it trust `signer_indices` from persisted
    `HyperWireEvidence` as ground truth? (`slashing_store.rs` stores blocks but
    `get_for_epoch`/`iter_all` return raw wire evidence — does the consumer
    re-verify?)
  - F026 cross-epoch path: can an attacker craft `epoch_a != epoch_b` to slash
    a validator who legitimately signed only one epoch? `signing_payload` uses
    `block.signature.epoch` + `signer_indices` — confirm the recovered signer
    set maps to the *penalized* validators correctly.
  - `MAX_DISTINCT_CONFLICTS_PER_HEIGHT=8` cap + `min(epoch_a,epoch_b)` keying:
    griefing/DoS or evidence-suppression via cap exhaustion.
  - `decode_hyper_block` drops `missed_proposals`/anchor fields when re-encoding
    in `slashing_store::encode_block` — does signing_payload still match?

### 3.2 F002 — `HyperLockEvent` signature verification (High, claimed fixed)
- **Field exists, never verified:** `HyperLockEvent.lock_signature`
  (`proto/definitions/hyper.proto:275`). Every production producer zero-fills
  it (`builder.rs:314`, `mempool.rs`, `router.rs`, `http_handler.rs`).
- `mempool::submit_lock` → `validate_lock_event` (`lock_event.rs:141`) checks
  **structure only** (amount≠0, lock_id len, dest/spend lengths). The doc-comment
  claims "Cryptographic signature verification happens in a separate pass
  against the source-side custody key" — **no such pass exists** in
  `importer.rs`, `builder.rs`, `runtime.rs`, or `mempool.rs`.
- `import_hyper_block` binds locks only via the recomputed verkle root vs the
  block threshold-sig, i.e. authenticity rests entirely on an honest proposer.
- **Hunt must verify:** whether PR #34's F002 "fix" actually added lock-signature
  verification anywhere, or only re-verified the *block* signature. If the
  latter, F002 is **not** fixed against a malicious/colluding proposer who can
  insert arbitrary locks (mint wrapped SNAP on L1 without a real source-side
  spend authorization).

### 3.3 Threshold-signed state-root / bridge payloads
- `sig_verify.rs` is the single chokepoint. `dispatch` requires 65-byte ECDSA,
  optional declared `group_address` must equal expected (fail-closed), recovers
  keccak256(payload) to expected address. Hunt: payload-coverage gaps (does
  `signing_payload` cover every field a verifier/contract relies on? e.g.
  `extra_rules_version`, anchor metadata, `signer_indices`), low-s/recovery-id
  handling in `hypersnap-crypto/ecdsa.rs`, cross-side asymmetry with
  `bridge_payload.rs` ↔ `HypersnapBridge.sol`.

## 4. HTTP / admin / RPC entry points
- `src/network/http_server.rs` — HTTP→gRPC; optional `IpRateLimiter`
  (`with_rate_limiter`), forwards `authorization` header. Hunt: unauth POST
  routes, body-size cap, rate-limit coverage, deserialization bombs.
- `src/network/admin_server.rs` — `authenticate_request` against comma-separated
  `user:pass` list (`rpc_auth`). Hunt: auth bypass, constant-time compare,
  privileged ops behind it.
- `src/network/server.rs` — tonic gRPC submit path → mempool.
- `src/network/replication/**` — sync/replication service (untrusted peer data).
- `src/api/**` — large read API; `src/api/ssrf.rs` SSRF guard (webhooks,
  user-hydrator, indexer). Hunt: SSRF bypass, query amplification.

## 5. On-chain entry points (`contracts/src/HypersnapBridge.sol`)
UUPS-upgradeable ERC20Permit (`SNAP`). Threshold-validator-set authorized via
`ecrecover` over 8 domain-separated payloads + strictly-monotonic 64-bit
block-number watermark:
- `updateMerkleRoot` (claim path), `claim` (MerkleProof of lock leaf, FAMILY_EVM),
- `burn` (EVM→hyper, emits `Burned`, `burnNonce`),
- `rotateOwner` / owner acceptance, `pause` (72h), `proposeUpgrade` /
  `cancelUpgrade` (48h delay), `recoverERC20` (chain-bound payload).
- Permit (EIP-2612) + EIP-6492 offchain-sig helper
  (`src/core/validations/contract_signature/`).
Hunt (solidity-bridge / proxy-access / state-machine / tokens): claim-sig
replay across chains (universal payloads are chain-agnostic by design — verify
watermark truly prevents cross-deployment replay), merkle-root monotonicity,
owner-rotate race, pause-vs-upgrade timing, uninitialized impl / UUPS lockdown,
recoverERC20 misuse, permit nonce confusion, leaf encoding asymmetry vs Rust.

## 6. Cross-cut review requirements (≥2 specialists each)
- **untrusted-input-ingress:** every byte→event boundary in §2 (gossip,
  HTTP, RPC, replication).
- **signing-payload-coverage:** every payload in `sig_verify.rs` + `bridge_payload.rs`.
- **serialization-boundary:** `lock_event.rs` / `bridge_payload.rs` ↔
  `HypersnapBridge.sol`; `slashing_store::encode_block` vs signing payload;
  `dkls_wire_codec.rs`.
