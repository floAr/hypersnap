# Revalidation: validator-registration / router / API auth

- AUDITED commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- NEW "audit fixes" commit: `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child)
- Reviewer scope: F070, F039, F011
- Date: 2026-06-12

## Summary table

| ID | Verdict | Confidence | One-line reason |
|----|---------|-----------|-----------------|
| F070 | FIXED | 0.93 | Production `submit_message` now builds the router `.with_custody_resolver(StoreBackedCustodyResolver)`, forcing the strict `validate_and_check_quota` (EIP-712 custody + per-FID cap) path; lenient `None` branch no longer reachable on any live ingestion path. |
| F039 | FIXED | 0.97 | Both `retry_onchain_events` and `retry_fname_events` now call `authenticate_request(&request, &self.allowed_users)?` as their first statement, matching sibling guarded admin RPCs. |
| F011 | PARTIALLY_FIXED | 0.8 | Shard variant of `validate_protocol_version` now has a staleness heuristic that can `ExitWithError`, but it is a best-effort 60-day time-bounded detector, not a producer-asserted version guard — a stale node still silently applies divergent chunks within the grace window. |

---

## F070 — Validator-registration custody gate unwired in production router

**Verdict: FIXED — confidence 0.93**

### What the finding required
Every inbound `ValidatorEvent` flows through `HyperRuntime::submit_message`, which
built `HyperRouter` **without** a `CustodyResolver`. With `custody_resolver == None`,
`route_inbound` took the lenient `ValidatorRegistry::validate_event(.., None)` branch,
skipping the EIP-712 custody cross-sign and the per-FID 3-cap. The recommended fix was
to wire a real `StoreBackedCustodyResolver` into the production router so the strict
`validate_and_check_quota` path runs on every event.

### What the new commit does
`src/hyper/runtime.rs` (inside `submit_message`, which begins at line 3693) now
constructs a real resolver and attaches it:

```rust
// runtime.rs ~3920-3933 (new commit)
use crate::hyper::validator_registry::StoreBackedCustodyResolver;
use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};
let handler = StoreEventHandler::new_no_persist();
let onchain = OnchainEventStore::new(self.db.clone(), handler);
let custody: std::sync::Arc<dyn crate::hyper::validator_registry::CustodyResolver> =
    std::sync::Arc::new(StoreBackedCustodyResolver::new(onchain));

let mut router = HyperRouter::new(
    std::mem::take(&mut self.mempool),
    Some(self.validator_registry.clone()),
    self.epoch_resolver.current_epoch(),
)
.with_custody_resolver(custody);
```

`HyperRouter::route_inbound` (`src/hyper/router.rs:159-172`) now takes the strict
branch because `custody_resolver` is `Some`:

```rust
match self.custody_resolver.as_deref() {
    Some(r) => registry.validate_and_check_quota(&event, self.current_epoch, r)?,
    None => ValidatorRegistry::validate_event(&event, self.current_epoch, None)?,
}
registry.record_event(&event)?;
```

`validate_and_check_quota` (`src/hyper/validator_registry.rs:421`) is unchanged from the
audited commit and is correct: it resolves the FID custody address
(`CustodyAddressUnknown` if absent), requires a custody signature on Register
(`MissingCustodySignature`, line 437), runs the EIP-712 cross-sign via
`validate_event(.., Some(&custody))`, and enforces `MAX_VALIDATORS_PER_FID`.
`StoreBackedCustodyResolver::custody_address_for_fid`
(`src/hyper/validator_registry.rs:97-118`) is a real implementation that reads the
latest `IdRegister` on-chain event for the FID and returns its `to` field — not a stub.

### Adversarial checks
- **Only one production router construction.** `grep "HyperRouter::new"` over the new tree:
  the single non-test call site is `runtime.rs:3882`, now chained with
  `.with_custody_resolver(...)`. Every other `HyperRouter::new(.., None, ..)` is inside
  `#[cfg(test)]` in `router.rs`.
- **No alternative lenient ingress.** `validate_event(.., None)` survives at
  `importer.rs:74`, but `apply_validator_events` is still dead code (grep for callers
  outside its own definition: none), so it provides no live bypass — consistent with the
  finding's own analysis.
- **Both ingestion points covered.** Gossip (`actor.rs InboundMessage`) and local submit
  (`LocalSubmitMessage`) both funnel through `submit_message`, which is the patched site.
- **Devnet/test escape?** The resolver is attached unconditionally for every
  `submit_message` call regardless of network — there is no devnet branch that reverts to
  `None`. The fix applies in production.

Residual: the pre-router trust-floor gate is still default-off (`min_validator_trust_score
== 0.0`), but that was never the custody enforcement — the custody gate is now the binding
control. No residual gap on the documented attack path.

---

## F039 — Admin retry RPCs missing authenticate_request guard

**Verdict: FIXED — confidence 0.97**

### What the finding required
`retry_onchain_events` and `retry_fname_events` on the public `AdminService` gRPC socket
had no guard of any kind (no `authenticate_request`, no `allow_debug()`), letting any
client reaching the gRPC port trigger unbounded L1-RPC / fname-registry rescans. Fix: add
`authenticate_request(&request, &self.allowed_users)?` as the first statement of both.

### What the new commit does
`src/network/admin_server.rs`:

- `retry_onchain_events` — `authenticate_request(&request, &self.allowed_users)?;` at
  line 214 (first statement of the method body, before the `into_inner().kind` match).
- `retry_fname_events` — `authenticate_request(&request, &self.allowed_users)?;` at
  line 249 (first statement).

`authenticate_request` is the same imported guard
(`use crate::network::rpc_extensions::authenticate_request;`, line 6) used by the already-
guarded `upload_snapshot` (line 276) and `run_onchain_events_migration` (line 311), and
`self.allowed_users` is the same credential map. Both retry methods now match the guarded
siblings exactly.

### Adversarial checks
- The guard runs before any `.send(...)` onto `onchain_events_request_tx` /
  `fname_request_tx`, so the attacker-controlled work is gated.
- The service is only mounted when `enabled() == !allowed_users.is_empty()`, i.e. exactly
  when `allowed_users` is non-empty, so the guard is meaningful (not fail-open) for this
  service in its mounted configuration.

### Residual (out of primary scope)
The finding's *secondary* observations were not addressed (file unchanged):
- `rpc_extensions.rs:155-157` fail-open `if allowed_users.is_empty() { return Ok(()); }`
  (moot for AdminService, relevant to `HubService` submit when `rpc_auth` unset — an
  intentional "auth disabled" mode).
- `rpc_extensions.rs:184` non-constant-time password compare (`password == parts[1]`).

These are low-severity side notes, not the core finding. The core finding (two unguarded
mutating retry RPCs) is fully closed.

---

## F011 — Shard read-validator no protocol-version enforcement

**Verdict: PARTIALLY_FIXED — confidence 0.8**

### What the finding required
`ReadValidator::validate_protocol_version` only enforced a version on the `Block`
(shard-0) variant; the `Shard` (`ShardChunk`) variant fell into the `_ =>` no-op arm and
returned `true` unconditionally, so a stale read-node would silently commit post-upgrade
chunks under its own locally-derived `EngineVersion` and diverge with no `ExitWithError`
halt. Recommended fixes: (a) compare the timestamp-derived version against the binary's
known-version ceiling and halt if past the schedule horizon, or (b) add a signed `version`
field to `ShardHeader` and check it symmetrically with `Block`.

### What the new commit does
`src/consensus/read_validator.rs:238-309` replaces the no-op with a dedicated `Shard` arm
implementing recommendation (a) as a heuristic:

```rust
Some(proto::decided_value::Value::Shard(chunk)) => {
    if let Engine::ShardEngine(engine) = &self.engine {
        if engine.network == FarcasterNetwork::Devnet { return true; }
        let timestamp = FarcasterTime::new(header.timestamp);
        let derived = EngineVersion::version_for(&timestamp, engine.network);
        if derived == EngineVersion::latest()
            && EngineVersion::next_version_timestamp_for(&timestamp, engine.network).is_none()
        {
            const SHARD_STALENESS_GRACE_SECS: u64 = 60 * 24 * 60 * 60; // 60d
            if let Some(horizon) = EngineVersion::latest_schedule_active_at(engine.network) {
                if timestamp.to_unix_seconds() > horizon.saturating_add(SHARD_STALENESS_GRACE_SECS) {
                    // ExitWithError("... Does your node need an upgrade?")
                    return false;
                }
            }
        }
    }
}
```

The new helper `EngineVersion::latest_schedule_active_at`
(`src/version/version.rs:298-312`) returns the max `active_at` of the binary's
network-specific schedule. The supporting calls (`version_for`, `latest`,
`next_version_timestamp_for`) exist, `ShardEngine.network` exists
(`storage/store/engine.rs:179`), and `validate_protocol_version` is invoked on the commit
path (`read_validator.rs:~350`, before `commit`, returning 0/drop on `false`), so the halt
is reachable in production.

The same commit also adds an F012 fix in this file
(`validate_block_hash_matches_header`, lines 173-204) that rederives `blake3(header)` and
binds it to the proto `hash` for both `Block` and `Shard` — orthogonal to F011 but it does
add a body-integrity check on the shard read path.

### Why PARTIALLY_FIXED (residual gaps)
The fix is a time-bounded staleness *detector*, not the producer-asserted version guard
the finding identified as the robust fix. The documented divergence path is still open
inside the detector's blind spots:

1. **60-day grace window.** A stale binary keeps committing shard chunks under its
   locally-derived version for up to 60 days past its own latest known `active_at`. The
   finding's core scenario — a time-gated upgrade with changed application semantics —
   produces divergence *immediately* at the new boundary, but the halt does not fire until
   chunk timestamps exceed `latest_known_active_at + 60d`. During that window the node
   silently diverges, which is exactly the harm the finding describes.

2. **Horizon is the binary's, not the network's.** The halt threshold is
   `latest_schedule_active_at(network) + 60d`, where `latest_schedule_active_at` reads the
   *stale binary's own* schedule. If the real new upgrade's `active_at` is only slightly
   past the binary's known horizon, the network forks well before the stale node's
   60-day-past-its-own-horizon trigger.

3. **Gated on `derived == EngineVersion::latest()`.** The halt only arms when the node is
   already at its newest known version and sees no known future upgrade. A node that is
   stale relative to the network but whose timestamp still maps below its own latest entry
   never enters the check at all.

4. **No signed version field added.** `ShardHeader` still carries no `version`/`chain_id`
   (recommendation (b) not taken), so there is no producer-asserted value to verify —
   detection remains purely local/heuristic and cannot distinguish an honest off-cycle
   deploy from a genuine missed upgrade except by the coarse 60-day timer.

Net: the worst-case "silent indefinite divergence with no operator signal" is mitigated
(a sufficiently-stale node will eventually halt), but the documented divergence on a
time-gated upgrade boundary is not closed end-to-end — there is a multi-week window of
silent divergence before the safety halt engages.

### Confidence rationale
High confidence the code compiles, is reachable on the production shard read path, and
materially reduces the exposure (0.8). Held below FIXED because the residual grace-window
divergence is a real instance of the originally-reported failure mode, not merely a
hardening nicety.
