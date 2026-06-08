---
id: F039
specialist: http-api-rocksdb
attack_class: unauth-post-route
title: Admin retry RPCs (retry_onchain_events / retry_fname_events) reachable without authenticate_request guard
file_paths:
  - code/hypersnap/src/network/admin_server.rs
  - code/hypersnap/src/network/rpc_extensions.rs
  - code/hypersnap/src/main.rs
  - code/hypersnap/src/connectors/onchain_events/mod.rs
  - code/hypersnap/src/connectors/fname/mod.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: medium
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.8
  hypotheses_walked: 8
  validated_at: 2026-06-08T12:45:00+00:00
---

## Summary

The gRPC `AdminService` is mounted on the public gRPC socket with **no
transport-level auth interceptor**. Per-method authentication is the only
gate. Two state-affecting admin RPCs —
`retry_onchain_events` and `retry_fname_events` — call **neither**
`authenticate_request(...)` **nor** the `allow_debug()` network restriction.
Any client able to reach the gRPC port can invoke them, triggering
unbounded external L1-RPC / fname-registry scanning work on the node.

## Where

`code/hypersnap/src/network/admin_server.rs`, `impl AdminService for
MyAdminService`. Per-method guard inventory:

| Method | `authenticate_request`? | `allow_debug()`? |
|---|---|---|
| `submit_on_chain_event` (L103) | no | yes (network-gated) |
| `submit_user_name_proof` (L152) | no | yes (network-gated) |
| `retry_onchain_events` (L205) | **no** | **no** |
| `retry_fname_events` (L237) | **no** | **no** |
| `upload_snapshot` (L263) | yes | n/a |
| `run_onchain_events_migration` (L298) | yes | n/a |

`retry_onchain_events` and `retry_fname_events` have **no guard of any
kind**. They `.send(...)` onto `onchain_events_request_tx` /
`fname_request_tx` immediately on the attacker's call.

## Reachability / mounting

`code/hypersnap/src/main.rs` L301-312:

```rust
let grpc_svc = tonic::codegen::InterceptedService::new(
    HubServiceServer::from_arc(grpc_service),
    rate_limit_interceptor,        // <-- wraps HubService only
);
let mut server = Server::builder()
    .concurrency_limit_per_connection(64)
    .add_service(grpc_svc);

if admin_service.enabled() {       // enabled() == !allowed_users.is_empty()
    let admin_service = AdminServiceServer::new(admin_service);
    server = server.add_service(admin_service);   // no interceptor
}
```

The rate-limit interceptor wraps only `HubServiceServer`. `AdminServiceServer`
is added raw on the **same** `grpc_socket_addr`. `enabled()` returns true
whenever `rpc_auth` is configured — i.e. precisely when the operator
believes admin is locked down. So once auth is configured (the normal
production posture), the AdminService is exposed and the only protection
is the per-method `authenticate_request` call, which these two routes omit.

## Impact

Downstream of the unguarded sends:

- `OnchainEventsRequest::RetryBlockRange { start_block_number,
  stop_block_number }` → `retry_block_range(start, stop)`
  (`connectors/onchain_events/mod.rs` L1181-1186). The block range is
  fully attacker-controlled with no bound. A single anonymous call with a
  huge range forces the node to scan/refetch that range against the L1
  RPC endpoint — CPU-grief plus exhaustion of the operator's upstream L1
  RPC quota/rate-limit.
- `OnchainEventsRequest::RetryFid(fid)` / `FnameRequest::RetryFid` /
  `RetryFname` → repeated external refetch work
  (`connectors/onchain_events/mod.rs` L1175, `connectors/fname/mod.rs`
  L405-413). Unauthenticated, unbounded repetition = CPU/network grief.

No on-disk corruption (events are re-validated before merge), so this is
a denial-of-service / resource-grief primitive rather than a state-forgery
one. Severity: medium.

## Secondary observations (same auth path)

`rpc_extensions.rs::authenticate_request` (L151-195) has two further
weaknesses, noted for completeness:

1. **Fail-open on empty config (L155-157):** `if allowed_users.is_empty()
   { return Ok(()); }`. For the AdminService this is moot (the service is
   only mounted when `allowed_users` is non-empty). But the same function
   guards `HubService::submit_message` / `submit_bulk_messages`
   (`network/server.rs` L1192, L1265); when `rpc_auth` is unset those
   mutating endpoints are fully open. That is an intentional "auth
   disabled" mode, but it means the *guarded* submit routes silently
   become unauthenticated under the empty-config that the retry routes
   also rely on.
2. **Non-constant-time secret comparison (L184):** `if password ==
   parts[1]` compares the configured password with `==` (early-exit byte
   compare), a timing side-channel on the admin password. Low severity,
   but trivial to fix with a constant-time compare.

## Note on the HTTP submit path (in scope, ruled clean)

`http_server.rs` POST routes were also enumerated. `/v1/submitMessage` and
`/v1/submitBulkMessages` forward the `authorization` header into the gRPC
metadata and dispatch to `HubService::submit_message` /
`submit_bulk_messages`, both of which call `authenticate_request` and
validate-before-broadcast (`simulate_message_for_shard_typed` runs before
the mempool enqueue, `network/server.rs` L453-472). Body size is capped at
4 MiB via `read_limited_body` / `Limited`. The HTTP layer is **not** the
finding; the gap is the two unguarded admin gRPC retry methods.

## Recommended fix

Add `authenticate_request(&request, &self.allowed_users)?;` as the first
statement of both `retry_onchain_events` and `retry_fname_events` (matching
`upload_snapshot` / `run_onchain_events_migration`). Optionally also bound
the `RetryBlockRange` span and gate the debug-submit/retry surface behind a
separate DebugService not mounted in production. Switch the password check
to a constant-time comparison.
