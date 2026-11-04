---
finding_id: F065
title: NATIVE_CUSTODY_ROTATION is rejected at mempool admission, so native FIDs cannot rotate custody through the mempool
severity: low
status: pending-validation
related_findings:
- F064
---
# F065 — `NATIVE_CUSTODY_ROTATION` must have `fid = 0` and `SIGNATURE_SCHEME_NONE`, so the mempool treats it as an FID-0 message. `fid0_dedupe_key` has no case for it, and its catch-all returns `Err("this message type cannot have fid 0")`. Every such rotation is rejected at admission, over RPC and over gossip. The custody of a non-migrated native FID cannot be rotated through the mempool.

> **Status (2026-11-04):** Severity **Low** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from regression pass 2026-11-04

- **Severity:** Low, source-only. A security-relevant feature does not work: a native FID's owner cannot revoke a leaked custody key by rotating it. There is a workaround: a `CUSTODY_MIGRATION` to a Falcon key resolves native custody through `classical_custody_of` (`registry.rs:78-87`), and the FID then rotates with `CUSTODY_ROTATION`. A thief of the key can do the same migration, so recovery is a race either way. No loss of funds follows from this alone. It is not Informational, because the migration workaround is not documented and no wallet builder for the native rotation exists in the tree.
- **Confidence:** 0.85. Admission path is certain from source. Not built.
- **Category:** dead feature / mempool-engine mismatch (native onboarding)
- **Specialist:** regression pass vs. old lineage, 2026-11-04 (found while re-checking ONBD-9/10)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard0/{precheck,onboarding}.rs` are new since merge-base `bdef7b7`. Not a regression of an old finding.
- **PoC:** None. Unit-test sketch: build a valid `NATIVE_CUSTODY_ROTATION` (fid 0, scheme None) and call `mempool.message_is_valid(0, …, true)` with `set_hypersnap(params, …)`. Expected: `Err(validation_failure("this message type cannot have fid 0"))`.

## Code facts

1. The message form is fixed: fid 0, `SIGNATURE_SCHEME_NONE`, FID named in the body (`proto/definitions/hypersnap_bodies.proto:241-250`). `rotate` requires `Role::Unsigned` (`src/chain/shard0/onboarding.rs:381-383`). `auth::open` allows scheme None only with fid 0 (`src/chain/shard0/auth.rs:161-166`).
2. Every Hypersnap type routes to shard 0 (`src/mempool/routing.rs:64`).
3. Admission runs `check_fid0` on shard 0 (`src/mempool/mempool.rs:966-968`, reached from `insert_into_shard`, `:1144`). It calls `fid0_dedupe_key` (`:726-730`), and any `Err` becomes a validation failure.
4. `fid0_dedupe_key` handles `TokenEscrowClaim`, `TokenEscrowBridge` and `NativeOnboard`. Everything else with fid 0 hits `_ => Err(invalid("this message type cannot have fid 0"))` (`src/chain/shard0/precheck.rs:38-72`).
5. The engine accepts the same message in a block (`engine.rs:577-579`). Tests submit it through `net.proposal(...)` and never through the mempool. So the mismatch is not covered by a test.

## Impact

- A user with a non-migrated native FID cannot rotate custody. The only way to the 161 handler is a proposer that writes the message into its own block.
- This currently hides F064 from ordinary users. Fix the two findings together.

## Fix

- Add a `NativeCustodyRotation` arm to `fid0_dedupe_key`: run the stateless part of `rotate` (address forms and the EIP-712 signature over `(fid, current, new, nonce)`), and use `b"rotate:" ‖ fid ‖ nonce` as the dedupe key.
- Fix F064 in the same change. Otherwise this fix makes F064 open to any user.

## Files

- `src/chain/shard0/precheck.rs:17-72`
- `src/chain/shard0/onboarding.rs:374-430`
- `src/mempool/mempool.rs:717-744, 966-968, 1144`
- `src/mempool/routing.rs:64`
- `proto/definitions/hypersnap_bodies.proto:241-250`
