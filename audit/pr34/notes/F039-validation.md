# F039 validation — Admin retry RPCs missing authenticate_request guard

Validator: validator (deliberate-disagreement). Commit pinned `cab225f`, HEAD confirmed identical.

Finding claim: gRPC `retry_onchain_events` / `retry_fname_events` on `MyAdminService`
have neither `authenticate_request` nor `allow_debug()`, are mounted on the shared
public gRPC socket (no interceptor), and let any reachable client trigger
unbounded external L1-RPC / fname-registry refetch work → DoS / resource-grief (medium).

## Core facts verified (file:line)

- `admin_server.rs:205-235` `retry_onchain_events` — NO guard. `.send(RetryFid|RetryBlockRange)` immediately.
- `admin_server.rs:237-261` `retry_fname_events` — NO guard. `.send(RetryFid|RetryFname)` immediately.
- `admin_server.rs:263-326` `upload_snapshot` / `run_onchain_events_migration` DO call `authenticate_request` first; `submit_on_chain_event` (109) / `submit_user_name_proof` (158) call `allow_debug()`. The two retry methods are the unique gap — guard inventory in the finding is exactly correct.
- `main.rs:301-312` mount: `HubServiceServer` wrapped in `InterceptedService(rate_limit_interceptor)`; `AdminServiceServer::new(admin_service)` added RAW (no interceptor) on the SAME `grpc_socket_addr`. Confirmed: rate-limit interceptor wraps Hub only.
- `main.rs:318` `server.serve(grpc_socket_addr)` — single socket; no separate admin bind/port.
- Downstream wired in production: `main.rs:1026/1042/1063` connector run-loops subscribe the receivers; loops at `onchain_events/mod.rs:1169-1192` and `fname/mod.rs:398-417` dispatch the requests. Not test-only.
- `retry_block_range` (`onchain_events/mod.rs:1266-1288`) builds one `Filter` with attacker-controlled `from_block`/`to_block` and calls `get_logs_with_retry` against L1 RPC.

## 8-hypothesis walk

### 1. Upstream auth / gate — INVALIDATED (impact-narrowing, not finding-killing)
The finding's own mounting argument has a mis-attribution: `enabled()` keys on
`admin_rpc_auth` (`main.rs:78`, `cfg.rs:102`), NOT `rpc_auth` as the finding body states
("enabled() returns true whenever rpc_auth is configured"). Substance is unaffected —
the AdminService is still mounted whenever `admin_rpc_auth` is non-empty, with these two
methods unguarded. But the bigger upstream gate the finder under-weighted is the
**bind address**. `cfg.rs:132-138` default `rpc_address = 127.0.0.1:<port>` with an
explicit comment that gRPC auth ships off-by-default so loopback is the default posture
and "operators exposing these ports publicly must opt in via config." So the
"publicly reachable" precondition is operator-configuration-dependent, not default.
Verdict on this hypothesis: the unauthenticated-reachability is real ONLY when the
operator binds `rpc_address` to a non-loopback interface (a common hub posture, but an
explicit opt-in the codebase warns about). This narrows the claim from "default-exposed"
to "exposed under the standard public-hub config."

### 2. Consumer-side impact — STANDS (with severity ceiling)
Consumers re-validate before merge (events flow through mempool/runtime validation),
so there is NO state-forgery / on-disk corruption — the finding correctly says so.
Impact is purely resource-grief: forces `eth_getLogs` / fname-registry refetch.
`retry_block_range` issues ONE un-batched giant filter (contrast `sync_historical_events`
at `mod.rs:974-989` which chunks 1000-block batches), so a huge range typically gets
rejected by the provider → up to 5 retries with `RETRY_TIMEOUT_SECONDS` sleeps
(`mod.rs:936-958`), then returns. Per-call cost is bounded; the primitive is repetition.

### 3. Downstream enforcement — STANDS
No lower layer re-checks auth for these sends. The send is unconditional once the method
is entered. Merge-time validation prevents forgery (already counted in #2) but does not
prevent the wasted external-RPC work, which is the claimed harm.

### 4. PR HEAD currency — STANDS
`git rev-parse HEAD` == `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, identical to pin. No drift.

### 5. Spec carve-out — PARTIALLY MITIGATES
`admin_server.rs:101` carries the author comment: "This should probably go in a separate
'DebugService' that's not mounted for production." This is an acknowledgement that the
admin surface is debug-flavored and ideally not production-mounted — but it is NOT a
documented "intentionally unauthenticated" carve-out, and the code DOES mount it in
production whenever `admin_rpc_auth` is set. The two retry methods being unauthenticated
while sibling methods are authenticated is clearly an oversight, not a documented design
choice. Finding stands; the comment slightly softens it to "known-rough surface."

### 6. Reachability of harm — STANDS (gated by #1 bind + rate limit)
When `rpc_address` is public and `admin_rpc_auth` is set, an anonymous client reaches
the unguarded methods and triggers real external-RPC work. Amplification is capped by
the gRPC per-IP rate limiter (120 req/min/IP, `main.rs:288`) which DOES apply to the
shared socket connection layer. So sustained but rate-limited grief. Medium is appropriate.

### 7. Test wiring — STANDS
Receivers are subscribed in production run-loops (`main.rs:1026/1042/1063`), gated only on
`!fnames.disable` and non-empty onchain RPC URLs (normal validator config). Buggy path is
production-reachable, not test-only. If a node runs without those connectors, `.send()`
returns Err → `Status::internal`, no work — a no-op, not a crash.

### 8. PoC mechanics — NEEDS_MORE_DATA
No executable PoC is attached. The prose is supported by static evidence (guard absence +
mount + downstream wiring), all independently confirmed above. A PoC would need to assert
that an unauthenticated gRPC call to `retry_onchain_events` returns `Ok(Empty)` AND that
`get_logs` fires — the latter requires a live L1 endpoint. Claim is evidentially sound
without a PoC; absence of PoC is a completeness gap, not a correctness defect.

## Overall

Verdict: HAS_CAVEATS. Confidence 0.8.

The technical core is correct and independently confirmed at every step: the two retry
methods genuinely lack any auth/network guard, they are mounted raw (no interceptor) on
the shared gRPC socket, and the downstream external-RPC work is production-wired. Two
caveats keep this from WATERPROOF:
1. Mis-attribution in the body: gating is `admin_rpc_auth`, not `rpc_auth` (cosmetic;
   substance holds).
2. Reachability requires the operator to bind `rpc_address` publicly — the default is
   loopback with an explicit security comment. So the precondition is "public hub
   posture," not "out-of-the-box." Medium severity is justified for that posture
   (DoS/resource-grief, no state forgery, rate-limited amplification); it would be Low
   if scoped to the default loopback bind.

## Open follow-ups (NOT new findings)
- `rpc_extensions.rs:184` `password == parts[1]` non-constant-time compare — already noted
  in the finding body as a secondary observation; confirmed present. Timing side-channel on
  admin password, low severity.
- `rpc_extensions.rs:155-157` fail-open on empty `allowed_users` — confirmed; also guards
  `HubService::submit_message` (`server.rs:1192`) / submit_bulk. Intentional "auth disabled"
  mode per the localhost-default comment; flagged for the specialist's awareness only.
