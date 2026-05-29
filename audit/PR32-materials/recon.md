# PR #32 Scoped Delta-Recon — hypersnap @ `4a6bca5`

**Stated goal:** snapchain v17 protocol compatibility (FIP-268 LIVE_AT, gasless-signer nonce
surface, gossip mesh self-heal, codec hardening).
**Diff base:** `ab945ec..4a6bca5` (3 commits). **Reference upstream:** snapchain v0.12.0
(`C:\Projects\snapchain`).

This is a SCOPED delta-recon. Only behavior **changed by these 3 commits** is mapped. The full-repo
recon/hunt/validate/dedupe/report already produced 57 standing findings; pre-existing code is out of
scope except where flagged for dedupe linkage.

---

## 0. Scope partition of the 3 commits

| Commit | Subject | Treatment |
|---|---|---|
| `4879074` | shore up delta from snapchain for v17 compat (13 files, +822) | IN SCOPE — hunt |
| `b464cfb` | pulling in a fix from the audit (2 files, +99) | OUT OF SCOPE — this is the F151 fix (codec `try_from_proto` hardening). Handled by a separate backcheck task. DO NOT re-hunt. |
| `4a6bca5` | fix discrepancies from upstream, update Dockerfile (6 files, +709) | IN SCOPE — hunt |

**Important overlap:** the `b464cfb` audit-fix diff (`snapchain_codec.rs` + `core/types.rs`
`try_from_proto`/`try_to_commit_certificate`) is ALSO present inside the cumulative
`ab945ec..4a6bca5` delta. Those exact hunks are the F151 fix and are excluded here. The codec/types
changes are therefore NOT seeded as new hunt tasks — only flagged for the F151 backcheck and for
F002/F005/F151 dedupe linkage.

---

## 1. Per-file behavioral change summary (20 files)

### Out-of-scope / non-behavioral
- **`Dockerfile`** — adds `build-essential` to apt install line. Build-time only. No attack surface.
- **`src/api/http.rs`** — whitespace-only reformat of one `let fid` binding. No behavior change.
- **`proto/.../*.proto`** — schema additions (see 1.1). Generated code is the real surface.
- **`*_test.rs` (message_test, mempool_test, rate_limits_test, http_server_test, engine_tests)** —
  test-only. Ported from snapchain `c292bfd`/PR#899. Not runtime surface; useful as the parity oracle.

### 1.1 proto deltas (schema-level attack surface)
- **`message.proto`**: `UserDataType::USER_DATA_TYPE_LIVE_AT = 14` (FIP-268). New decodable enum value.
- **`request_response.proto`**: new `SignersByFidRequest{fid, page_size, page_token, reverse, requester_fids[]}`;
  `SignersByFidResponse` gains `current_user_nonce=5`, `requester_fid_nonces map<u64,u32>=6`.
- **`rpc.proto`**: `GetSignersByFid` request type changed `FidRequest` → `SignersByFidRequest`.
  Wire-compatible widening (adds repeated/optional fields), but expands the untrusted input struct.

### 1.2 `src/version/version.rs` (+26)
- Adds `EngineVersion::V17`, `ProtocolFeature::LiveAt` (enabled `>= V17`), `LATEST_PROTOCOL_VERSION 11→12`.
- **Devnet schedule jumps `V16 → V17` immediately** (`active_at: 0`). Mainnet V17 = 2026-06-04,
  Testnet V17 = 2026-05-21 (already past as of audit date 2026-05-29 → testnet LIVE_AT is LIVE).
- Verified parity vs snapchain version schedule.

### 1.3 `src/core/validations/message.rs` (validation gate)
- Hoists 4 regexes (`FNAME`, `TWITTER`, `GITHUB`, `GEO`) to `LazyLock<Regex>` (perf; behavior-preserving —
  same patterns). The previous per-call `Regex::new(...).unwrap()` is now a one-time init.
- Adds `UserDataType::LiveAt` validation arm: feature-gated on `ProtocolFeature::LiveAt`; value length
  `> 256` ⇒ `UrlValueTooLong`. **No URL/format/scheme validation** — any opaque ≤256-byte blob
  (including empty string = "clear") is accepted. Confirmed byte-for-byte parity with snapchain
  `message.rs:602`.

### 1.4 `src/mempool/mempool.rs` (+226) — FIP-268 LIVE_AT mempool coalescing + rate limit
- New `LiveAtRateLimits`: separate per-FID hourly budget `units * 5000`/hr; zero storage units ⇒ reject.
  Uses `storage_limits.units` (sum of legacy+2024+2025 unit counts) — distinct from the general
  `RateLimits` which sums `storage_limits.limits[].limit`. Both match upstream.
- New per-(shard,fid) single-slot LIVE_AT index (`live_at_messages_by_fid`) with LWW coalescing by
  `(timestamp, hash)` via `make_ts_hash` + `bytes_compare`. Newer LIVE_AT evicts older pending one,
  but ONLY on the `result.is_ok()` admission branch; a newer LIVE_AT that fails admission must not
  displace the prior pending one. Index cleaned on pull, on commit, and on storage-lend/rent commit
  (rate-limiter invalidation).
- Verified near-verbatim port of snapchain `mempool.rs` lines 760–1050. Comments/TODO author names
  differ (`aditi` vs `topocount`) but logic is identical.

### 1.5 `src/network/gossip.rs` (+97) — direct-peer mesh self-heal
- New per-peer state: `direct_peers`, `local_topics`, `boot_resub_done`, `last_force_bounce_at`,
  `peer_connected_at`, `direct_peer_force_bounce_count`.
- On reconnect-timer tick: for each connected `direct_peer` missing the `CONTACT_INFO` gossipsub
  subscription, after a 30s settle window and 60s bounce cooldown, **force-disconnect the peer**
  (`swarm.disconnect_peer_id`) to trigger a fresh SUBSCRIBE handshake.
- On first direct-peer connect: one-shot unsub/resub cycle of all local topics.
- Verified parity with snapchain gossip self-heal (`gossip.rs:434–600`). `direct_peers` is operator
  config (trusted), not attacker-controlled — but the bounce decision is driven by **peer-reported
  topic subscription state** (`gossipsub.all_peers()`), which is gossip-network input.

### 1.6 `src/main.rs` — gossip lifecycle reorder + channel resize
- `SystemMessage` channel capacity `1000 → 16384`.
- Gossip is now spawned **early** (before node/shard RocksDB init) instead of last in `start_servers`.
  `start_servers` signature changes from owning `gossip` to taking `gossip_tx` + `local_peer_id`.
  Behavioral reorder of startup; affects when gossip ingress begins relative to store readiness.

### 1.7 `src/network/server.rs` (gRPC) + `rpc_extensions.rs` — GetSignersByFid widening
- `get_signers_by_fid` now takes `SignersByFidRequest`. Computes `current_user_nonce` via
  `get_user_nonce(fid)` and, for **each** `requester_fid` in the request, `get_app_nonce(rf)` →
  one RocksDB read per requested FID. `requester_fids` is **unbounded** in the request struct.
- `SignersByFidRequest::page_options()` added; `page_size` is passed straight through (no cap —
  pre-existing shared `page_options` behavior).
- `get_user_nonce`/`get_app_nonce` pre-exist in `key_nonce_store.rs` (not in delta).

### 1.8 `src/network/http_server.rs` (+405) — JSON signer surface + KEY_ADD/KEY_REMOVE mapping
- New HTTP endpoints `GET /v1/signer` and `GET /v1/signersByFid` proxying the gRPC service.
- New request structs `SignerHttpRequest`, `SignersByFidHttpRequest` (the latter accepts BOTH
  snake_case and camelCase aliases for the same fields, with `to_proto()` merge precedence:
  `requester_fids` wins over `requesterFids`, `page_size.or(pageSize)`).
- New response DTOs `HttpSigner`/`HttpSignerResponse`/`HttpSignersByFidResponse` and proto→JSON
  mappers for `KeyAddBody`/`KeyRemoveBody` (previously returned an "unsupported" error).
- HTTP GET requests are parsed from the **query string** via `serde_qs::from_str` (v0.13). The 4 MiB
  body limit (`MAX_HTTP_BODY_BYTES`) does NOT apply to GET query strings.

---

## 2. DELTA ATTACK-SURFACE MAP

| Area | New/changed | Untrusted input reaches it via | What could go wrong |
|---|---|---|---|
| LIVE_AT validation (`message.rs`) | new UserDataType arm, no format validation | mempool ingress, gossip-forwarded UserDataAdd, RPC submit | feature-gate bypass before V17; ≤256B opaque value accepted (by design); divergence from upstream length/gate semantics → consensus split |
| LIVE_AT mempool coalescing (`mempool.rs`) | LWW single-slot index + separate rate limiter | mempool AddMessage (local + gossip) | LWW eviction bug → drop newer or keep older; index desync between `live_at_messages_by_fid` and `messages` BTreeMap → memory leak or stale-pointer logic; rate-limit invalidation gaps on lend/rent; `unwrap()` on `storage_limits`/`get(&shard_id)` panic for unrouted/zero-store FID |
| `get_signers_by_fid` (`server.rs`) | per-requester-FID RocksDB nonce reads | gRPC `SignersByFidRequest.requester_fids` (unbounded) | amplification DoS: one request → N store reads; no length cap on `requester_fids` (matches upstream, but newly reachable) |
| HTTP signer endpoints (`http_server.rs`) | `GET /v1/signer`, `GET /v1/signersByFid` | query string via `serde_qs` (NOT body-limited) | large `requester_fids[]` array in URL → amplified nonce reads; dual snake/camel alias confusion (`to_proto` precedence) → request-smuggling-style param ambiguity; KeyAdd/KeyRemove mapper now exposes signer key material / scopes over JSON |
| gossip direct-peer force-bounce (`gossip.rs`) | disconnect driven by peer-reported topic subs | gossipsub `all_peers()` subscription state | a peer that withholds/forges CONTACT_INFO subscription can induce repeated bounces of itself; cooldown/settle gating must hold or churn amplifies; only `direct_peers` (trusted config) targeted, so blast radius limited |
| main.rs startup reorder | gossip spawned before store init | gossip ingress (consensus/mempool topics) | messages arriving before shard stores ready → handler reads uninitialized/None store; channel 16384 backpressure change |
| codec `try_from_proto` (types.rs/codec) | OUT OF SCOPE (F151 fix) | consensus gossip / sync | — handled by F151 backcheck; flag for dedupe only |

---

## 3. SCOPED HUNT QUEUE (H200+)

Tight, parity-and-divergence focused. Codec/types hunks excluded (F151 backcheck owns them).

| ID | Specialist | File:lines (hypersnap) | Attack class | Hypothesis |
|---|---|---|---|---|
| **H200** | chain-economics | `src/mempool/mempool.rs:191–243` (`LiveAtRateLimits`) | rate-limit bypass / DoS | LIVE_AT budget keys off `storage_limits.units` (raw unit count) while general `RateLimits` keys off summed `limits[].limit`. Verify `units` is the intended quota basis and that `units==0`/lend-borrowed edge cases reject correctly; check `.unwrap()` on `get(&shard_id)`/`get_storage_limits` cannot panic for an attacker-chosen FID. |
| **H201** | chain-economics | `src/mempool/mempool.rs:760–860` (`prepare_live_at_insert`/`insert_into_shard`) | CRDT / mempool eviction | LWW coalescing: confirm a newer LIVE_AT that FAILS admission (gate/dup/rate-limit) does not evict the prior pending one, and that `live_at_messages_by_fid` never points to a key absent from `messages` (index/store desync → silent drop or unbounded `HashMap` growth). |
| **H202** | http-api-rocksdb | `src/network/server.rs:2698–2735` (`get_signers_by_fid`) | amplification DoS | `requester_fids` is unbounded; each entry is one `get_app_nonce` RocksDB read. Confirm no upstream-divergent missing cap and quantify single-request store-read amplification. |
| **H203** | http-api-rocksdb | `src/network/http_server.rs:1765–1809, 3865` (`SignersByFidHttpRequest` + `serde_qs` GET) | input parsing / DoS / param ambiguity | GET query parsed by `serde_qs` bypasses the 4 MiB body cap; a huge `requester_fids[]` URL amplifies nonce reads. Also check dual snake/camel alias `to_proto()` precedence for request-param confusion. |
| **H204** | p2p-gossip | `src/network/gossip.rs:548–605` (mesh self-heal sweep) | peer-induced churn | A direct peer that connects but never re-advertises CONTACT_INFO can be force-bounced repeatedly; verify 30s settle + 60s cooldown + `peer_connected_at` reconciliation actually bound churn and that `boot_resub` one-shot can't be re-armed to spam SUBSCRIBE RPCs. |
| **H205** | node-lifecycle-actor | `src/main.rs:631–645, 785, 1103` (early gossip spawn) | init ordering / TOCTOU | Gossip now ingests consensus/mempool topics before shard RocksDB stores finish init. Verify message handlers tolerate not-yet-ready stores (no `unwrap`/panic, no dropped-but-acked messages) and that the `1000→16384` channel resize doesn't mask backpressure loss. |
| **H206** | consensus-malachite-tendermint | `src/version/version.rs` + `src/core/validations/message.rs:638–646` | feature-gate / consensus split | Confirm LIVE_AT gate (`>= V17`), the 256-byte limit, and devnet's immediate `V16→V17` jump match snapchain exactly, so a hypersnap node cannot accept/reject a LIVE_AT message that snapchain would reject/accept (fork risk). Cross-ref engine-side hyper-trie landing (engine_tests oracle). |

Total: **7 pending tasks** (H200–H206).

---

## 4. SNAPCHAIN CROSS-REF POINTS (v17-compat claim verification)

Every in-scope changed file has a direct upstream counterpart; the PR is a faithful port. Verify these
pairs for the parity claim:

| hypersnap file | snapchain counterpart | Notes |
|---|---|---|
| `src/mempool/mempool.rs` (LiveAt blocks) | `C:\Projects\snapchain\src\mempool\mempool.rs` (`LiveAtRateLimits` L185–245; insert/coalesce L760–1050) | verbatim logic; only TODO author names differ |
| `src/core/validations/message.rs` (LiveAt arm) | `C:\Projects\snapchain\src\core\validations\message.rs:602` | identical 256-byte + gate |
| `src/network/gossip.rs` (self-heal) | `C:\Projects\snapchain\src\network\gossip.rs:434–600` | identical state + sweep |
| `src/network/server.rs` (`get_signers_by_fid`) | `C:\Projects\snapchain\src\network\server.rs:2493–2531` | identical nonce loop |
| `src/version/version.rs` | `C:\Projects\snapchain\src\version\version.rs` | verify V17 schedule timestamps & `protocol_version()` mapping |
| `proto/definitions/{message,request_response,rpc}.proto` | snapchain proto defs | confirm field numbers/types match for wire compat |

---

## 5. EXISTING-FINDING / DEDUPE LINKAGE (for dedupe stage, not re-hunted here)

| Subsystem touched by delta | Existing findings to link | Reason |
|---|---|---|
| codec `try_from_proto` / `try_to_commit_certificate` (`snapchain_codec.rs`, `core/types.rs`) | **F002 / F005 / F151** (codec cluster) | These delta hunks ARE the F151 fix; same code region as F002/F005. Route to F151 backcheck; dedupe should link any H200+ codec-adjacent finding here. |
| gossip (`network/gossip.rs`) | **F017 / F019 / F021** (gossip cluster) | New force-bounce/self-heal logic lives in the same module; H204 findings should be checked against these. |
| mempool (`mempool.rs`) | existing mempool findings | LIVE_AT rate-limit/coalescing is new code in the mempool subsystem; link H200/H201. |
| http (`http_server.rs`, `server.rs`) | existing http findings | new signer endpoints; link H202/H203. |

---

## 6. Specialists activated for this delta

All from the already-activated set (no bespoke specialist needed — delta is a faithful upstream port,
fully covered by existing domains):

- **chain-economics** — LIVE_AT rate limiting / mempool economics (H200, H201)
- **http-api-rocksdb** — signer HTTP/gRPC endpoints, nonce reads, query parsing (H202, H203)
- **p2p-gossip** — direct-peer mesh self-heal / force-bounce (H204)
- **node-lifecycle-actor** — gossip startup reorder, channel sizing (H205)
- **consensus-malachite-tendermint** — version gate / consensus-split parity (H206)

Not exercised by this delta: rust-threshold-signing, rust-crypto-primitives, rust-bulletproofs-pedersen,
solidity-bridge, solidity-proxy-access, evm-tokens, evm-state-machine.

---

## 7. Open questions for the operator

1. **F151 overlap:** the cumulative delta includes the F151 codec fix. Confirmed excluded from H200+.
   Should the dedupe stage auto-link H206 (consensus parity) to the F151 backcheck, or keep separate?
2. **`requester_fids` unbounded (H202/H203):** this matches snapchain upstream exactly. If it's a real
   amplification DoS, it's an upstream-inherited issue, not a hypersnap divergence — do you want it
   reported as a hypersnap finding or routed upstream?
3. **No compile attempt was made** (per scope this is recon only). Given R2/R3 history of non-compiling
   workspaces, flag whether the hunt stage should gate on a successful `cargo build` of `4a6bca5` first.
