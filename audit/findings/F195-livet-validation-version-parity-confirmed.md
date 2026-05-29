---
id: F195
task: H211-fork
attack_class: consensus-divergence
severity: informational
status: draft
---

# F195 — LIVE_AT validation + V17 activation + state-transition: PARITY CONFIRMED (full surface swept)

## Summary

Differential sweep of the PR#32 (`4a6bca5`) v17/LIVE_AT (FIP-268) surface against snapchain
v0.12.0 (authoritative v17 spec). Goal: find any hypersnap↔snapchain mismatch that could make
two honest nodes reach a different accept/reject or state decision on the same input, or activate
V17 at a different point. **No fork-relevant divergence found.** All four assigned surfaces are a
faithful, behavior-identical port of upstream. This is a clean negative.

## What was swept (hypersnap file:line vs snapchain file:line)

### 1. Validation predicate — `validate_user_data_add_body` LIVE_AT arm
- hypersnap `src/core/validations/message.rs:641-648` vs snapchain `message.rs:602-609` — **IDENTICAL.**
  Both: `!version.is_enabled(ProtocolFeature::LiveAt) => UnsupportedFeature`; `value_bytes.len() > 256
  => UrlValueTooLong`; otherwise accept (incl. empty string = "clear"). Same `> 256` (not `>=`),
  same error variants, same feature gate.
- The only diff is **match-arm ORDER** (hypersnap places the `LiveAt` arm after `ProfileToken`,
  snapchain places it before `Username`). Rust match arms over non-overlapping enum patterns are
  order-independent — **behavior-identical, not a divergence.**
- `value_bytes = body.value.as_bytes()` (UTF-8 byte length) — identical in both (`message.rs:571`).
- `validate_message` signature + body identical (`message.rs:97-125`); only stylistic
  `len()==0` vs `.is_empty()` clippy diff. All other changed predicates in the +36 delta are the
  4 regex `LazyLock` hoists (`FNAME`/`TWITTER`/`GITHUB`/`GEO`) — same patterns, one-time init,
  behavior-preserving.
- `message_test.rs` (+66) ports upstream's own contract tests (boundary 256 = ok, 257 = TooLong,
  V16 = UnsupportedFeature, V17 = ok). They encode exactly the upstream contract and would catch
  threshold/gate drift. They do NOT exercise the engine state-transition path (covered by
  `engine_tests::test_live_at_user_data_lands_in_hyper_trie`).

### 2. Version activation determinism — `src/version/version.rs`
- hypersnap `version.rs` runtime code (lines 1-295) is **byte-identical** to snapchain `version.rs`
  runtime code, including the full V0-V17 mainnet/testnet/devnet schedules, `version_for`,
  `is_enabled` (`LiveAt => self >= V17`), `protocol_version` (`V17 => 12`), `LATEST_PROTOCOL_VERSION
  = 12`. The only file diff is in the `#[cfg(test)]` module (hypersnap omits upstream's two new
  schedule tests) — no runtime effect.
- **Activation trigger is keyed on the message/block timestamp, NOT wall clock, on the consensus
  path** — matching snapchain exactly:
  - Consensus-authoritative gate: `engine.rs:1220 / block_engine.rs:369,549,734,865,925` all use
    `EngineVersion::version_for(&FarcasterTime::new(block_timestamp), network)`. Proposer
    (`proposer.rs:218,504,600`) and read-validator (`read_validator.rs:128`) likewise key on
    `proposal.timestamp`/header timestamp. Identical to snapchain's corresponding sites.
  - Soft mempool/gRPC-submit gate uses `EngineVersion::current(network)` (wall clock) at
    `mempool.rs:516,784` and `server.rs:1258,2015` — **identical to snapchain** (`mempool.rs:522,794`,
    `server.rs:1156,1913`). This is upstream's intended design: mempool admission is advisory; the
    binding accept/reject for block contents is re-decided by every node against the **block
    timestamp**, so no two honest nodes can disagree on whether V17 is live for a committed message.
    No wall-clock-driven consensus decision exists.
- Devnet `active_at: 0 => V17` immediate jump is **byte-identical** to snapchain
  (`version.rs:194-198`). Devnet is single-version (no schedule history) and is not the F004 #28
  genesis/cutover machinery; the F004 cutover is hypersnap-specific genesis bootstrap and does not
  re-key the version schedule. No interaction introduced.

### 3. hypersnap-specific v17 integration (introduced surface)
- `live_at` / `LiveAt` / `live_at_messages_by_fid` appear ONLY in mempool, version, validations,
  and tests. **They are NOT wired into any hypersnap-specific subsystem** (PoW/scoring, DKLS, fees,
  verkle) — Grep across `src` returns zero matches outside those four areas.
- hypersnap DOES have an introduced "hyper shadow store" (`hyper_stores`,
  `StateContext::Hyper`) that snapchain lacks. LIVE_AT is dual-written there via
  `merge_message_hyper` (`engine.rs:1302-1338`). **This is NOT a fork vector:**
  - The dual-write keys on `MessageType::UserDataAdd` generically (`engine.rs:1322`), not on the
    inner `UserDataType`, so LIVE_AT=14 flows through `user_data_store.merge` like any UserData type
    — no type-specific allow-list that could omit LIVE_AT.
  - The hyper store has its OWN trie/keyspace (`with_state_context(StateContext::Hyper)`,
    `engine.rs:252`). The consensus `shard_root` is computed exclusively from `self.stores.trie` via
    `update_trie` (`engine.rs:1409-1425`, fed only by the main-store `merge_message` events at
    `engine.rs:990-998`). `merge_message_hyper` is NOT followed by any `update_trie` on the consensus
    trie. Hyper merges are explicitly "best-effort" (errors logged, block not failed) — safe precisely
    because they never contribute to the consensus root.
  - `engine_tests::test_live_at_user_data_lands_in_hyper_trie` confirms LIVE_AT lands in both legacy
    and hyper stores with LWW overwrite semantics — a read-side shadow, not a consensus input.

### 4. mempool LIVE_AT coalescing → block contents — state-transition determinism
- The user-message application sort `get_message_priority` (`engine.rs:951-984`) is **byte-identical**
  to snapchain (`engine.rs:960-993`): LIVE_AT → priority 4 ("other UserDataAdd"), `sort_by` with
  `then_with(timestamp)` tie-break. `Vec::sort_by` is stable, so equal-priority/equal-timestamp
  messages preserve block-supplied order — deterministic across all nodes applying the same block.
- Mempool LWW coalescing (`live_at_messages_by_fid`, `prepare_live_at_insert`, `live_at_lww_compare`
  by `(timestamp, hash)`) is a near-verbatim port of snapchain `mempool.rs` 760-1050. Coalescing only
  affects which message a PROPOSER selects from its local mempool; the proposed block is then
  validated deterministically by every node via the timestamp-keyed engine path above. Non-deterministic
  proposer selection (if any) is not a fork by itself — validation of the proposed block is
  deterministic and version-keyed identically on every node. (The LWW eviction-only-on-`is_ok()`
  correctness and the `live_at_rate_limits` `.unwrap()` panic surface are the province of the parallel
  H200/H201 chain-economics tasks and F160; not re-hunted here.)

## Divergence
None fork-relevant. Differences observed are limited to: match-arm ordering (semantically inert),
a `len()==0` vs `.is_empty()` clippy style diff, and the `#[cfg(test)]` module (hypersnap omits two
upstream schedule tests — a TEST-COVERAGE gap, not a runtime divergence; see Remediation).

## Fork impact
None. A hypersnap node and a snapchain v0.12.0 node accept exactly the same set of LIVE_AT messages
and reject exactly the same set, and both activate V17 at the identical (timestamp-keyed) boundary on
the consensus path. The introduced hyper shadow store cannot perturb the consensus shard_root.

## PoC status
No PoC — this is a negative result. The differential was established by direct source comparison of
the authoritative consensus paths (engine/block_engine/proposer/read_validator version derivation,
the validation predicate, and the state-transition sort) plus an exhaustive Grep proving LIVE_AT is
absent from every hypersnap-specific subsystem and from the consensus-trie write path. A regression
PoC would require constructing a divergent input; none exists, so a "differential accept/reject" PoC
is not constructible against this surface.

## Severity
Informational (clean parity / negative finding).

## Remediation
Optional hardening only: port snapchain's two omitted `version.rs` activation-schedule tests
(`test_live_at_activation_schedule`, `test_gasless_signers_activation_schedule`) and the
`test_*_feature_gate` tests into hypersnap's `version_test` module so future edits to the V17
boundary timestamps or `is_enabled` mapping are caught by hypersnap's own CI rather than relying on
upstream. No runtime change required.
