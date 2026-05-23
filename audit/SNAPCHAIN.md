# Snapchain — Inherited-Findings Audit Index

**Upstream repo:** [farcasterxyz/snapchain](https://github.com/farcasterxyz/snapchain) (`main` branch)
**Derived from:** the [hypersnap audit findings index](README.md) — 56 standing findings against the hypersnap fork (`farcasterorg/hypersnap@6cff47c637`).
**Method:** structural mapping, not a fresh audit. For each hypersnap finding, the code path was checked in snapchain to see whether the same defect exists. This is *not* a substitute for an 8-hypothesis red-team validation against snapchain itself — every entry below is a hypothesis that snapchain inherits the bug, anchored to file:line evidence; a snapchain-side validator pass is still required before any of these become Snapchain-attributed findings.

**Bottom line:** **9 of 56 hypersnap findings appear to apply to snapchain** (the consensus codec, gossipsub, HTTP ingress, RocksDB-atomicity surface). The remaining 47 are hypersnap-specific (bridge, DKLS23, verkle, KZG, ed448-bulletproofs, EigenTrust, validator economics, hyperblock anchors, confidential transfers, account-association, miniapp registration, notification webhooks, social-graph filter handlers) — those subsystems do not exist upstream.

---

## Inherited from snapchain — 9 findings to triage upstream

The hypersnap validator's verdict (WP / HC) is carried over because the root cause is structurally identical; the file paths below point at snapchain, not hypersnap. Severity reflects hypersnap's analysis — snapchain operators should re-rate against their own deployment model.

### Critical / High — consensus + codec panics on peer input before signature verify

#### [F002 — `add_proposed_value` unwraps peer-controlled `FullProposal` Option fields before validation](README.md#f002)
**WP carried over · severity High** — snapchain: `src/consensus/proposer.rs:210-211`
```rust
let header = chunk.header.as_ref().unwrap();
let height = header.height.unwrap();
```
Both `.unwrap()` calls occur before signature verification in the ProposedValue::Shard variant. Any gossipsub-reachable peer can crash the receiving shard actor with a malformed proto. Same primitive as hypersnap.

#### [F005 — `dispatch_decided_value` unwraps `DecidedValue` value chain on peer-controlled gossip input](README.md#f005)
**WP carried over · severity High** — snapchain: `src/node/snapchain_read_node.rs:190-205`
```rust
let shard_id = match decided_value.value.as_ref().unwrap() {
    proto::decided_value::Value::Shard(shard_chunk) => {
        shard_chunk.header.as_ref().unwrap().height.unwrap().shard_index
    }
    proto::decided_value::Value::Block(block) => {
        block.header.as_ref().unwrap().height.unwrap().shard_index
    }
};
let actors = self.consensus_actors.get(&shard_id).unwrap();
actors.cast_decided_value(decided_value).unwrap();
```
Read-nodes panic on a gossip `DecidedValue` proto with an unknown / missing oneof, an out-of-range `shard_index`, or a destination shard with no registered actor. Crashes every read-node in the fleet via libp2p gossip.

#### [F151 — `SnapchainCodec` decode panics on peer Vote / Proposal / SyncResponse fields before signature verify](README.md#f151)
**WP carried over · severity High** — snapchain: `src/consensus/malachite/snapchain_codec.rs:106` and `src/core/types.rs:423, 431, 465, 467`
- `snapchain_codec.rs:106`: `.unwrap()` on `proposal.height` in the StreamMessage decode path.
- `types.rs:423`: `panic!("Invalid vote type")` in `Vote::from_proto` when the proto `type` field is outside the documented enum range.
- `types.rs:431, 465, 467`: `.unwrap()` on `Vote::from_proto`'s `proto.height` and `Proposal::from_proto`'s `height` / `shard_hash`.

These run during malachite-codec decode, *before* the consensus signature verification step. Any libp2p peer reachable on the consensus or sync channels gets a one-packet panic primitive against the network-connector actor.

### Medium — networking / gossipsub / HTTP-ingress hygiene

#### [F017 — Gossipsub mesh has no peer scoring, no `validate_messages()`, default mesh_n_low / outbound_min, 100/100 connection limits](README.md#f017)
**HC carried over · severity Medium** — snapchain: `src/network/gossip.rs:297-333`
`mesh_n(10)` and `mesh_n_high(20)` are set but `mesh_n_low`, `outbound_min`, peer-scoring config, and `validate_messages()` callback are all absent. Connection limits are hardcoded at 100/100 (lines 331-332); a TODO at line 326 acknowledges they're high. Sybil-poisoned mesh can eclipse a snapchain node from any topic with no eviction path.

#### [F019 — No per-topic gossip message size cap; only the 10 MB libp2p transport cap is enforced](README.md#f019)
**WP carried over · severity Medium** — snapchain: `src/network/gossip.rs:45, 301`
`MAX_GOSSIP_MESSAGE_SIZE = 1024 * 1024 * 10` is the only ceiling; `map_gossip_bytes_to_system_message()` (lines 994-1102) does no per-topic / per-variant size validation. An attacker on any subscribed topic can amplify 10×–1000× over the legitimate frame size and grief the mesh.

#### [F021 — Autodiscovery `handle_contact_info` dials body-supplied address without binding to libp2p sender peer-id; `PeerId::from_bytes().unwrap()` panics on malformed bytes](README.md#f021)
**WP carried over · severity Medium** — snapchain: `src/network/gossip.rs:950, 960-970, 990`
`PeerId::from_bytes(&contact_info_body.peer_id).unwrap()` at line 950 panics on adversarial peer-id bytes. The `gossip_address` is then dialed at line 990 without binding `contact_info_body.peer_id` to the libp2p propagation source (only checked against already-connected peers). Eclipse + unconditional panic primitive against snapchain nodes.

#### [F030 — Unbounded HTTP body buffered via `Incoming::collect().await` with no transport-level cap](README.md#f030)
**WP carried over · severity High** — snapchain: `src/network/http_server.rs:3867, 3887, 3923, 3964`
Three `.collect().await` calls on hyper request bodies with no pre-buffer body-size limit; the `http1::Builder` at line 3964 is bare. Hyper defaults to unbounded body buffering. Anonymous public-internet POST of a multi-GB body OOM-kills the node before any application-level rejection runs.

#### [F031 — No rate limit on any HTTP / gRPC ingress endpoint](README.md#f031)
**WP carried over · severity High** — snapchain: no `tower::limit` / `RateLimit` / `governor::Governor` / `tower-governor` middleware anywhere on the HTTP or gRPC ingress. Grep returns only internal peer-bouncing comments (`gossip.rs:234, 646`), not ingress rate limiting. Anonymous CPU-grief on the `submit_message` / `submit_bulk_messages` / streaming `GetBlocks` paths is unbounded.

### High — storage atomicity

#### [F033 — Block / shard-chunk header committed in a SEPARATE RocksDB commit from state-mutation batch (cross-CF atomicity break)](README.md#f033)
**WP carried over · severity Medium-High** — snapchain: `src/storage/store/engine.rs:1791, 1798`; `src/storage/store/shard.rs:174`; `src/storage/store/block_engine.rs:968-969` (plus `block.rs:181`)
The shard engine commits its state-mutation batch with `self.db.commit(txn).unwrap()`, then independently calls `put_shard_chunk(shard_chunk)` which opens its own `db.commit(txn)?`. The block engine has the analogous two-commit pattern. A crash between the two commits leaves the trie / message stores at height H but the `ShardChunk` / `Block` header at H-1 — on-restart consensus divergence, and that divergence is then propagated to every bootstrapping peer via snapshot pollution.

---

## Hypersnap-only — 47 findings out of scope for snapchain

The following subsystems do not exist in upstream snapchain, so the associated findings cannot apply. This is a structural argument from absence (`grep` for the subsystem returns zero hits), not a per-finding code walk.

### Bridge + L1 (Solidity + Rust watcher)
F058 (invalidated), F062, F091, F094, F095, F096, F097 — `HypersnapBridge.sol`, `BridgeBurnStore`, `RecoveryWatcher`, lock/burn nullifier logic, claim merkle-root advance. No bridge in snapchain.

### DKLS23 threshold ECDSA (DKG + signing + refresh)
F018, F023, F026, F028, F036, F040, F045, F107, F108, F110, F114 — `crates/dkls23/**`, `dkls_ceremony.rs`, `dkls_sign.rs`, `dkls_supervisor`, `dkls_committee::select_signing_committee`, threshold-signed payload binding, recovery_id handling, inner-sender trust. Snapchain has no threshold signing — it uses validator-set Ed25519 directly.

### KZG / verkle / ed448-bulletproofs (proof systems)
F048, F116, F117, F119, F121 — `HyperRuntimeFileConfig::build_srs`, KZG SRS load, verkle trie inserts with domain bytes, DLogProof verify, ed448 IPA `from_bytes`. Snapchain has no commitment / proof system above libp2p + ed25519.

### Validator economics + emission + EigenTrust
F009, F010, F011, F012, F013, F014, F015 — EigenTrust scoring, vouching, retro-vesting, auto-deregister, mutuality, TrustScoreStore (snapchain-side check confirmed zero hits), RewardStore::credit_if_unissued. All hypersnap economic-protocol additions.

### Hyperblock pipeline + DA-PoW + slashing evidence
F004, F024, F132, F133 (snapchain-side check confirmed `FingerprintStore` absent in `src/storage/store/`), F135, F138, F153 — `EpochResolver`, scheduler proposer-context split read, `RewardStore::stage_charge_message_fee`, FingerprintStore writes bypass txn_batch, DA-PoW driver `served_key` padding, proposer pipeline strips locks/transfers from wire, hyperblock threshold-ECDSA payload. None of these structures exist in snapchain.

### Confidential transfers + privacy notes + stealth addresses
F044, F052, F137, F149 — `EcdsaSignature` wire format, privacy-note AEAD AAD, importer `extract_output_pubkeys` gate, `HyperTransferTx` codec. Snapchain stores public Farcaster messages only — no confidential transfers, no stealth one-time pubkeys, no Pedersen commitments.

### Runtime fork (`runtime.rs` apply-handler bloat + active-key gate)
F027 — snapchain-side check confirmed ABSENT. Snapchain dispatches messages via a single centralized `merge_message` match statement in `src/storage/store/engine.rs:1229-1297` (2442 LOC total) and applies the active-key gate once in `validate_user_message` (lines 1470-1500), not duplicated across 13 hand-inlined `apply_*` handlers.

### Hypersnap miniapp + notification + Farcaster-v2 batch / social-graph filter
F101, F104, F105, F154, F157, F158 — `apply_miniapp_register`, custody-key JFS account-association proof, `FeeDepositBody` ed25519 DST, app-PoW receipts, `/v2/farcaster/batch/*` endpoints, `following_fid` filter, JFS notification webhook. Confirmed ABSENT in snapchain: no AccountAssociation message type, no `/v2/farcaster/batch/*` endpoint surface, no notification webhook subsystem, no `following_fid` filter, no `social_graph.get_followers` reachable from a send-notification handler. Most of these are extensions hypersnap added on top of snapchain's core data layer.

---

## Adjacent observation worth flagging

**F154-adjacent — `submit_bulk_messages` accepts unbounded `repeated Message messages` array.** Snapchain's `submit_bulk_messages` endpoint (proto `SubmitBulkMessagesRequest`, handler at `src/network/http_server.rs:3176`) takes an unbounded message vector. This is not the same bug as F154 (snapchain has no per-FID pagination loop), but it is the same defect *class* — untrusted ingress array with no length cap, paired with F031's missing rate limiter. Amplification factor is lower than F154 (one message per array slot vs. K × N RocksDB pages per FID), but worth a defensive cap if F030 / F031 are taken upstream.

---

## Methodology + caveats

- **This is a structural mapping, not a snapchain audit.** Every PRESENT verdict is a hypothesis that snapchain inherits hypersnap's bug at the cited file:line, validated by inspection of the snapchain source but NOT validated by an adversarial 8-hypothesis walk against snapchain's own deployment model. Snapchain may have downstream mitigations (a panic-handling supervisor, an undocumented rate limiter at the load-balancer tier, ops-side body-size caps in the proxy in front of the HTTP server) that the structural check cannot rule out.
- **Severity numbers carried over from hypersnap.** Snapchain operators should re-rate per their own threat model — for example, F033's atomicity break is a much higher impact on hypersnap (which propagates state via S3 snapshots) than on snapchain (which may have different bootstrap semantics).
- **The 47 hypersnap-only findings are excluded on subsystem-absence grounds.** Where the subsystem exists in snapchain (consensus codec, gossipsub, HTTP server, RocksDB engine) every relevant finding was checked; where the subsystem does not exist (bridge, DKLS, verkle, KZG, economics, miniapps, notifications), the findings cannot apply by construction.
- **Next step for snapchain operators:** triage the 9 PRESENT findings against the snapchain threat model, run a `/audit-suite:audit-validate` pass against the snapchain repo if you want independent adversarial 8-hypothesis walks against the snapchain code (not the hypersnap code), and dedupe against any findings the snapchain team already has internally.
