---
id: H075
specialist: node-lifecycle-actor
attack_class: router-untrusted-dispatch
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
relates_to: F070, F058
file_paths:
  - code/hypersnap/src/hyper/router.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/validator_registry.rs
  - code/hypersnap/src/hyper/importer.rs
---

# H075 — router-untrusted-dispatch — ruled out (no new distinct finding)

## Scope

`src/hyper/router.rs` — `HyperRouter::route_inbound` dispatch of untrusted
inbound `proto::HyperMessage` bodies. Hunt: can a message type reach a
state-changing handler without the validation other ingress paths apply?
Also: verify the F058 transparent-`HyperLockEvent` seal holds and that no
other body type is under-validated.

## What I checked

`route_inbound` (`router.rs:131-317`) is an exhaustive match over
`proto::hyper_message::Body`. Of all variants:

- **`Lock`** (`router.rs:133-142`) — sealed: returns `RoutingError::Lock`,
  never inserts into the verkle tree. F058 seal **holds**. Confirmed by
  tests `inbound_lock_at_router_layer_is_sealed`,
  `full_wire_round_trip_lock_sealed_at_router`,
  `duplicate_inbound_lock_sealed_at_router` (router.rs:444-583) and the
  runtime-level `submit_message_transparent_lock_sealed` (runtime.rs:5274).
- **`Transfer`** (`router.rs:143-156`) — sealed at the router; must go
  through `submit_message`, which runs `validate_against_store` +
  `verify_balance_with_blinding_diff` + output-pubkey extraction
  (runtime.rs:3720-3743) before mempool admission.
- **All other state-changing bodies** (RewardIssuance, TrustSnapshotUpdate,
  TokenTransfer, FeeDeposit, ConfidentialLock, Shield, LockMerkleRootUpdate,
  OwnerRotation, InboundBurn, TokenEscrowClaim, TokenEscrowBridge,
  TokenStake, TokenUnstake, NodeAttestation, AppUsageReceipt, Miniapp*,
  DaChallengeResponse, DaEpochSeed) — the router returns
  `UnsupportedMessageType` (fail-closed). In production these are
  **intercepted by `HyperRuntime::submit_message` before the router is even
  constructed** (runtime.rs:3669-3847), each dispatched to its own `apply_*`
  handler that performs body-specific validation. Even a caller that bypassed
  the runtime and invoked `route_inbound` directly would hit the
  `UnsupportedMessageType` rejection — no state change.

The only body that actually flows **through** the router into a
state-changing handler is **`ValidatorEvent`** (`router.rs:157-171`),
which calls `record_event` after validation. Both branches
(strict `validate_and_check_quota`, lenient `validate_event(.., None)`)
require and verify at least one signature before `record_event`.

## Why ruled out (not a new finding)

The single live router-dispatched state-changing path (ValidatorEvent) is
under-validated **only** because production constructs the router at
runtime.rs:3882 without `.with_custody_resolver(...)`, forcing the lenient
`validate_event(.., None)` branch and skipping the EIP-712 custody
cross-sign / per-FID cap. That is **exactly and entirely** the already-
confirmed finding **F070** (registration-custody-sig-gating, high). The
importer's `apply_validator_events` (importer.rs:65-79) mirrors the same
lenient/strict branch and is itself dead code, also noted under F070.

No *additional* message type reaches a state-changing handler with weaker
validation than the mempool/import path:
- The F058 Lock seal holds.
- Transfer is sealed and re-validated strongly in the runtime.
- Every other body is fail-closed at the router and intercepted+validated
  upstream by `submit_message`.

The internal validation correctness of the individual `apply_*` handlers
(reward issuance, owner rotation, fee deposit, etc.) is a separate
attack-class surface already covered by F035/F045/F047/F048/F049/F068 and is
out of scope for router-dispatch.

## Residual uncertainty

Low. The router match is exhaustive (Rust compile-time guarantee), so no
body variant can silently fall through. The only dispatch gap converges on
F070, which is already filed.
