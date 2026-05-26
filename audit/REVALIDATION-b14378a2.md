# Hypersnap — Fix Revalidation of commit `b14378a2` ("audit fixes")

**Fix commit:** [`b14378a256aa499f862f7dc11943499668232234`](https://github.com/farcasterorg/hypersnap/pull/28/changes/b14378a256aa499f862f7dc11943499668232234) — *"audit fixes"*, Cassandra Heart (CassOnMars), 2026-05-25 19:27 CDT, on PR [#28](https://github.com/farcasterorg/hypersnap/pull/28) (branch `pow`).
**Parent (round-1 fix, already revalidated):** [`883c4a5b…`](https://github.com/farcasterorg/hypersnap/commit/883c4a5b35581042edcd8bdfbee8d56f3cc21c98) — *"fixes from audit"*. This commit is its direct, single child.
**Audited base (pre-fix):** [`6cff47c…`](https://github.com/farcasterorg/hypersnap/commit/6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae) — the pinned audit commit.
**Round-2 delta:** 23 files, **+449 / −129** (vs `883c4a5b`). Saved at `.audit/pr28-b14378a2-delta.diff`; cumulative vs base at `.audit/pr28-b14378a2-full.diff`.
**Harness:** [audit-suite](https://github.com/floAr/audit-suite) — 4 domain specialists across 2 waves (max-parallel 2). Same static call-site tracing methodology as the round-1 revalidation.

---

## What this commit is

A **second-round, residual-targeted** patch. It does not touch the round-1 structural rewrite; it surgically addresses the residuals the round-1 revalidation (`REVALIDATION-883c4a5b.md`) left live. The added lines cite finding IDs directly — `F004, F009, F018, F023, F024, F026, F031, F036, F058, F108, F135, F158` — and the file set maps 1:1 onto the round-1 "still-live residuals / re-report candidates" list. Every file it touches is either a residual site or a regression-surface for a round-1 fix.

---

## ⚠️ The commit does not compile (production DA-PoW path)

**Independently verified.** The F135 fix added a 6th parameter `max_fid: u64` to `BlockEngineDaResponseProducer::new` (`src/hyper/da_response_producer_prod.rs:24-41`), but the sole production call site still passes 5 arguments:

```
src/main.rs:1404   BlockEngineDaResponseProducer::new(
                       engine, signer_sk, validator_pubkey, fid, chain_id,   // 5 args
                   );                                                         // new() needs 6
```

This is `error[E0061]: this function takes 6 arguments but 5 arguments were supplied`. There is exactly one `fn new` (6 params: `…, max_fid: u64`), the call site passes 5, and it is not `cfg`-gated — in Rust this is an unconditional, deterministic type error (no overloading, default args, or variadics exist to rescue it). So `b14378a2` will fail to build on the DA-PoW operator path.

**Verification status: EMPIRICALLY CONFIRMED via a full Linux build (WSL Ubuntu, Rust 1.95, gcc 13).** `cargo check --bin hypersnap` against the patched tree (with the pinned malachite sibling `13bca14c`) compiles the entire dependency graph — rocksdb (C++), jemalloc (C), malachite, and all of hypersnap's own crates — and fails with exactly:

```
src/main.rs:1404:40: error[E0061]: this function takes 6 arguments but 5 arguments were supplied
error: could not compile `hypersnap` (bin "hypersnap") due to 1 previous error
```

This is the **sole** compile error: every other round-2 fix (F018/F026/F036/F108/F002/F058/F023/F024/F004/F009/F031/F158) type-checks cleanly — only the F135 producer wiring is broken. So `b14378a2` is not buildable as committed and was evidently pushed without a compile. Build log: `.audit/build-wsl2-b14378a2.log`. *(An earlier attempt with Windows-native `cargo` failed in dependency build scripts — jemalloc/rocksdb need a C/C++ toolchain absent on Windows, and `pre-commit 0.5.2`'s `build.rs` is Unix-only — so the build was reproduced under Linux/WSL.)* **Everything below is adjudicated on source intent; several verdicts assume this one-line break is fixed before the commit is buildable.**

---

## Scoreboard — movement vs round-1

Scope: the 12 round-1 PARTIAL highs + F058's info residual, plus regression checks on the round-1 FIXED criticals/highs whose files this commit touched.

| Round-1 residual | Round-2 verdict | Movement |
|---|---|---|
| **F002** codec `height.unwrap()` pre-validation panic | **FIXED** | ✅ closed |
| **F018** dkls sender↔libp2p peer-id binding | **FIXED** | ✅ closed (hard residuals) |
| **F024** supervisor anchor-jump (no DKG group) | **FIXED** (primary) | ✅ closed; narrow liveness gaps remain |
| **F026** slashing bypass via `DifferentEpochs` drop | **FIXED** | ✅ closed; read-side index residual |
| **F036** committee seed proposer-grindable | **FIXED** | ✅ closed (all 6 callers) |
| **F058** dead verkle lock path (info) | **FIXED** | ✅ closed |
| **F108** dkls submit trusts inner sender (framing) | **FIXED** | ✅ closed |
| **F004** epoch-boundary race (deferred secondaries) | **STILL-PARTIAL** | ◑ one race closed |
| **F009** sybil ring saturation | **STILL-PARTIAL** | ✗ cap inert for the modeled ring |
| **F023** dkls cross-digest routing | **STILL-PARTIAL** | ◑ clobber closed, AAD binding not |
| **F031** gRPC ingress unthrottled | **STILL-PARTIAL** | ◑ HTTP fixed, gRPC still open |
| **F135** DA-PoW reward collapse | **STILL-PARTIAL** | ◑ root cause addressed + compile break |

**7 of 12 residuals closed. 0 regressions.** All round-1 FIXED criticals/highs whose files were touched (**F058, F133, F138, F132, F151, F040, F107, F114**) re-verified intact.

---

## Residuals newly closed (7)

### F002 — nil-block-proposal remote panic · **FIXED**
`snapchain_codec.rs:109-113` replaces the cited `proposal.height.unwrap()` with `proposal.height.ok_or_else(|| SnapchainCodecError::InvalidField(...))?`. Sweep of the proposal/vote decode→handle path confirms no other pre-validation `.unwrap()` on attacker-supplied fields: `core/types.rs` `Vote::try_from_proto`/`Proposal::try_from_proto` are fallible and the infallible `from_proto` is no longer called inbound; all sync codecs `?`-propagate. *Out-of-scope adjacent note: `consensus/malachite/host.rs:356/364` still `.unwrap()` on the sync/decided-value `Block::decode`/`ShardChunk::decode` path — a different surface than F002, not assessed here.*

### F018 — dkls inner sender not bound to libp2p peer-id · **FIXED**
Both reopened hard residuals closed: the cross-check now drives off the gossipsub **originator** (`gossip.rs:667` `message.source`, threaded via `:1007`) instead of the forwarding `propagation_source`; and `peer_id_for_party` (`runtime.rs:1239-1249`) now indexes `nth(party_index-1)` into the **full** active set and resolves the peer-id by `validator_key`, removing the omit-empty-peer-id ordering skew. The two permissive fall-throughs (`originator==None` or no registered peer-id ⇒ accept) survive as an **explicit, documented gradual-rollout posture** — with author-signing on in production and peer-ids registered, the strict branch engages.

### F024 — supervisor anchor jump leaves epoch with no DKG group · **FIXED** (primary)
`dkls_supervisor.rs:125-171` replaces the one-shot dispatch with a catch-up loop `for target in first_undispatched..=next_epoch` that builds a driver + fires `StartDkls` for every undispatched epoch in the gap. Issue-1 (scheduler split-read) was already the round-1 `should_propose_and_snapshot` fix. **Residual liveness gaps (new, narrower):** (1) `dispatched: Option<Dispatched>` tracks only the *last* target, so the F040 retry/`has_dkls_share_for_epoch` watchdog monitors only the last epoch of a catch-up burst; (2) `first_undispatched = …max(current_epoch)+1` permanently skips the *current* epoch on a node that starts mid-epoch with no share.

### F026 — cross-epoch double-sign evades equivocation slashing · **FIXED**
`slashing.rs:52-78`: the `e_a != e_b → Err(DifferentEpochs)` evidence drop is **deleted** (the variant is gone); `detect_conflicting_blocks` now emits `ConflictingBlocksEvidence{epoch_a, epoch_b}`. `verify_evidence_signatures` (`slashing.rs:89-101`) takes a per-epoch group-key resolver and verifies each block against its own epoch's key; wired at `actor.rs:1572-1604`, persisted under `epoch_a.min(epoch_b)`. The test flipped `rejects_different_epochs` → `accepts_cross_epoch_conflicts`. **Residual (new, read-side):** evidence is stored under `min(epoch)`, but enforcement (`runtime.rs:4070-4208`) resolves block_b's 1-based `signer_indices` against the *min*-epoch active set, not block_b's own epoch — the equivocator is still caught, but block_b's distinct-epoch co-signers can map to wrong keys (mis-slash) or fail to map. Recommend resolving each block's indices against its own `signature.epoch` set.

### F036 — committee selection digest proposer-grindable · **FIXED**
New `committee_seed_for_epoch(epoch, message_tag)` (`dkls_committee.rs:110-117`), a pure function of the consensus-pinned epoch + a fixed per-ceremony domain tag. All six production `select_signing_committee` callers in `actor.rs` now use a non-grindable seed: block-production (`committee_seed_for_block`, round-1), reward-issuance (`b"reward-issuance"`), trust-snapshot (`b"trust-snapshot"`), inbound-burn (`b"inbound-burn"`), **lock-merkle-root** (`b"lock-merkle-root"` — the draft's Caller-C grind lever), DA-epoch-seed (`b"da-epoch-seed"`). The proposer-controlled signing payload / lock-root is now used only as the signing digest, never as committee input.

### F058 — dead `HyperLockEvent` verkle path (info residual) · **FIXED**
`router.rs:133-142`: the `Body::Lock(_)` arm now returns `Err(RoutingError::Lock(...))` instead of `mempool.submit_lock`. This was the sole gossip sink for single Lock messages — `runtime.rs::submit_message` has no `Body::Lock` intercept and falls through to the router. The verkle insert is now fed only by block import (governed by block validation), so the gossip state-bloat/DoS vector is closed; `submit_lock` has no non-test callers.

### F108 — dkls `submit` trusts inner sender (committee-member framing) · **FIXED**
`dkls_sign.rs:287-315`: all three submit arms now enforce `transmit.parties.sender == <authenticated wire sender>` **and** `signing_committee.contains(&sender)` before insert. Since dkls23 dispatches slashing blame on `message.parties.sender` (`dkls23/protocols/signing.rs:349`), an attacker can no longer seat an entry whose inner sender names an innocent party — the framing primitive is gone. A member can still abort a ceremony blaming *themselves* (correct attribution, not framing).

---

## Residuals still live (5)

### ★ F009 — sybil amplification via eigentrust · **STILL-PARTIAL — ring saturation intact**
Round-2 adds a per-crediter cap in `scoring.rs:221-227`: `cap = uncapped_sum * max_growth_fraction_per_crediter` (default **0.05**, `lib.rs:288-298`), applied as `c.min(cap)`. **The cap is mathematically inert for the modeled threat.** It is *relative to the recipient's own total*, so in the draft's scenario (recipient credited by 100 equal sybils) each crediter contributes ~1% < 5% and `min(cap)` never binds. The code's own comment concedes it needs "at least 20 distinct reciprocating crediters to saturate" — i.e. it does nothing for N ≥ 21, precisely the ≥100-member ring. `eigentrust.rs` and the top-N normalization (`scoring.rs:106-141`) that saturates the ring to trust≈1.0 are byte-identical to round-1. The ring still clears the 0.05 trust floor and captures Growth-market budget. Exploitable from genesis under shipped defaults.

### ★ F031 — ingress rate limiting · **STILL-PARTIAL — gRPC still wide open**
**HTTP half FIXED:** the limiter moved to per-request granularity — `Router::with_rate_limiter` per connection (`main.rs:357-358`) + `limiter.allow(peer_ip)` inside the per-request `handle()` (`http_server.rs:3323-3331`, 429 on reject). This closes the round-1 keep-alive/pipelining bypass. **gRPC half still live:** `main.rs:280-282` adds only `concurrency_limit_per_connection(64)` to `HubServiceServer`; the `IpRateLimiter` is invoked nowhere on the gRPC path. Concurrency-limit ≠ rate-limit (fast serial RPCs flood freely; multiply by opening N connections for N×64 budget). The named methods — `submit_message`, `submit_bulk_messages`, `get_blocks`, `validate_message` (`network/server.rs`) — remain rate-unbounded, and gRPC auth is **off by default** (`server.rs:409-410`, empty `allowed_users`), so they are reachable unthrottled on a default deployment. The `rate_limit.rs:5` module doc still falsely claims it covers `GetBlocks`.

### ★ F135 — DA-PoW driver reward collapse · **STILL-PARTIAL — root cause addressed, but does not compile + magnitude unverified**
The structural defect *is* addressed: `derive_challenge_prefix` (`da_pow.rs:90-118`) now derives `derived_fid = 1 + (seed % max_fid)` and emits a real 5-byte structured trie-key prefix (`[shard_byte, fid_u32_be]` via `TrieKey::for_fid`) instead of `SHA256(...)[0..16]`; the prod producer resolves the actual stored key. So an honest validator storing any message for `derived_fid` would now return a matching key rather than `None`. **But three things keep it off FIXED:** (1) **compile break** — `main.rs:1404` omits the new `max_fid` arg to `::new` (see top of report); (2) **magnitude is unverified** — `derived_fid` is pseudo-random in `[1, max_fid]` where the verifier hard-codes `seed_max_fid = 50_000` (a "conservative upper bound" per its own comment); FIDs above it are never challenged, in-range FIDs with no stored messages still miss, and a partial-replica validator not hosting the shard returns `None`; (3) **producer/verifier `max_fid` must agree exactly** or prefixes diverge — currently unverifiable because the producer call site is the broken one. This remains the one **NEEDS-RUNTIME** item: once the arity break is fixed, measure the actual challenge hit-rate on a devnet across an epoch. *(Stale comment "16" at `da_pow_driver.rs:84`.)*

### F004 — epoch boundary race · **STILL-PARTIAL**
Round-2 closed the `refresh_proposer_context_loop` race: it now snapshots the anchor first and derives `epoch = epoch_for(anchor.block)` from that same snapshot (`scheduler.rs:251-274`), instead of three independent reads across `.await`. **Deferred races still untouched:** cutover/genesis arithmetic is still bare `anchor_block / EPOCH_LENGTH` with no offset (`epoch.rs:22-23`); the supervisor keeps a *separate* anchor mutex (`u64`) from the scheduler's `LatestAnchor` struct — two desynchronized anchor sources; `build_driver` re-reads the supervisor anchor in a second lock across `.await` (`dkls_supervisor.rs:90` vs `:233`).

### F023 — dkls round messages cross-routed · **STILL-PARTIAL**
Residual (b) **closed**: `StartDklsSign` now refuses a same-epoch active ceremony (`actor.rs:1531-1538`), non-block ceremonies serialize through `pending_sign_queue`, and block-production warns-before-replace only on a different digest — the unconditional silent `active_dkls_sign = Some(driver)` clobber is gone. Residual (a) **not closed**: `build_aad(epoch, round_tag, sender, receiver)` (`dkls_wire_codec.rs:100`) still omits the digest and inbound sign frames filter only by `epoch()` (`actor.rs:1486-1517`), so a same-epoch Phase-1 frame for digest D_A still decrypts and `submit()`s into a driver signing D_B. **Severity contained:** the dkls23 `sign_id` is set to the digest and folded into each party's OT `mul_sid` (`signing.rs:371-378`), so a wrong-digest frame fails the multiplication check and `Abort`s rather than forging a signature; combined with the F108 sender-binding, the only injectable cross-digest frame is one the attacker authors as themselves. Net residual = **attributable liveness griefing** (an authenticated committee member can stall the single same-epoch sign ceremony), no cross-digest forgery.

---

## Notes & caveats

- **Methodology:** static call-site tracing against patched source at `b14378a2` (working tree checked out at the commit), one domain specialist per cluster, 2 waves at max-parallel 2 (the hard cap for this workspace). No build run — consistent with the round-1 revalidation. The one independently-confirmed *deterministic* defect (the `main.rs:1404` arity break) does not require a build to establish.
- **No regressions.** F058, F133, F138, F132, F151, F040, F107, F114 all re-verified intact; the files this commit touched did not undo any round-1 fix. The `gossip_adapter.rs +4` is a `#[cfg(test)]` field rename for F026, not a change to `BroadcastBlock`/metadata serialization (F138 safe).
- **Newly surfaced sub-residuals** (not in the round-1 report, worth tracking): F026 read-side `signer_indices`-vs-epoch resolution mismatch (mis-slash of block_b co-signers); F024 current-epoch catch-up skip + single-`Option` retry tracking.
- **Net live risk after round-2:** F009 (sybil ring — cap inert), F031 (gRPC unthrottled, auth-off default), F135 (compile break + unverified magnitude), plus the partial F004/F023 races. F009 and the gRPC half of F031 are the two that are *fully* exploitable on a default deployment with no caveat.

## Recommended re-report set

Effectively-unresolved after two fix rounds — carry forward to publication:
- **F009** — sybil ring saturation (the shipped cap does not bind for the modeled ring).
- **F031** — gRPC ingress unthrottled + auth-off-by-default.
- **F135** — compile break (blocker) + reward-collapse magnitude unverified (NEEDS-RUNTIME).
- **F004 / F023** — remaining epoch-boundary / cross-digest races (lower severity, partial).
- **New sub-residuals** — F026 signer-index/epoch resolution; F024 current-epoch skip.

Per the runnable-PoC standard, any of these published as findings should ship a PoC compiled + run — which **first requires the team to fix the `main.rs:1404` arity break** so the tree builds.
