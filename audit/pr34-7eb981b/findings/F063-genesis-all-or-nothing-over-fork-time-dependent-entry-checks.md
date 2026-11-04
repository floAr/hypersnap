---
finding_id: F063
title: Genesis is all-or-nothing over entries checked at the fork timestamp, so one stale validator entry aborts the pivot on every node
severity: low
status: pending-validation
related_findings:
- F028
- F046
- F024
---
# F063 — (date: the fork time, when snapchain shard 0 reaches `PIVOT_HEIGHT − 1`, which no operator controls) `build_genesis` applies every genesis validator entry with `?`, at `ctx.timestamp = fork_timestamp`. Each entry passes only if checks that depend on the fork time and on live Optimism or social state still hold: the custody-migration `deadline` is after the fork, the classical custody address is unchanged, the FID's effective age is ≥ 90 days, and its trust is ≥ 0.05 in the fork-time snapshot. One stale entry aborts the genesis on every node. The pivot then needs a rollback release with a new `PIVOT_HEIGHT` and a new genesis file. Any single genesis participant can cause this, by accident or on purpose (a custody transfer or recovery on Optimism, or a short deadline).

> **Status (2026-11-04):** Severity **Low** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from time/defaults cross-cut 2026-11-04

- **Severity:** Low, source-only. It is a liveness failure of the one-time pivot event, and recoverable: FIP §17.8 rollback, `check_marker` moving the abandoned pivot aside (`pivot_boot.rs:103-152`). No funds or safety are affected. It is not Informational because the trigger time is set by snapchain block production, the failure is network-wide, and it hands each genesis participant a veto.
- **Confidence:** 0.8. The code path is certain. Likelihood depends on the release process: how close to the fork the file is assembled and the rehearsal run, and what deadline the entries use.
- **Category:** honest-time liveness / all-or-nothing genesis / insider griefing
- **Specialist:** cross-cut (time-and-defaults) · 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`src/chain/pivot.rs`, `src/chain/shard0/{registry,validators}.rs`, `src/bin/hypersnap_pivot.rs` are new).
- **PoC:** None, reasoned from source. Test sketch in `pivot_test.rs`: a genesis file whose single entry has `deadline = fork_timestamp`. `build_genesis` returns `Err("genesis entry of FID …: invalid: deadline has passed")`.

## Code facts

1. **All-or-nothing.** For each entry and each of `custody_migration`, `node_attestation` and `validator_register`, `engine.apply_genesis_message(&ctx, …).map_err(…)?` runs with `ctx = { height: pivot_height, epoch: 1, timestamp: inputs.fork_timestamp, genesis: true }` (`src/chain/pivot.rs:396-420`). Any error aborts `build_genesis`. `pivot_boot` returns that error (`src/node/pivot_boot.rs:442`), so the Hypersnap node cannot start.
2. **Deadline against the fork time.** `custody_migration`: `if (body.deadline as u64) <= ctx.timestamp { invalid("deadline has passed") }` (`src/chain/shard0/registry.rs:259-261`). The deadline is a required free argument of `hypersnap_pivot entry --deadline <farcaster time>`, documented only as "It must be after the fork block" (`src/bin/hypersnap_pivot.rs:7-8, 55-59`). The tool does not check it against anything.
3. **Optimism custody at the fork.** `classical_custody_of(txn, onchain, fid)` must equal the EIP-712 signer of the entry (`registry.rs:262-274`). Any `IdRegistry` transfer or recovery of a genesis FID between signing and the fork breaks it.
4. **Age at the fork.** `register`: `effective_age(txn, fid, ctx.unix_time()) < min_validator_fid_age_secs (90 d)` → invalid (`src/chain/shard0/validators.rs:191-193`). There is no `genesis` bypass; `genesis` only sets `join_epoch = 1` (`:229`). The clocks come from `write_fid_clocks`, which counts every non-exempt transfer as a custody change (`pivot.rs:243-286`). The mainnet `EXEMPT_RECOVERIES` is empty at 7eb981b (see CROSSCUT T4), so a recovery also resets the clock.
5. **Trust at the fork.** `register`: `trust < min_validator_trust_fp (0.05)` → invalid (`validators.rs:194-201`). Trust comes from the snapshot computed at `now_unix = fork_timestamp` over the fork-time social graph (`pivot.rs:380-383, 290-321`). F046 shows part of that input is node-local.
6. **The fork time is not chosen.** `fork_timestamp` is the timestamp of snapchain shard-0 block `PIVOT_HEIGHT − 1`, a constant fixed in the release (`pivot_guard::params::pivot_height`, currently `None`). The calendar time depends on snapchain's block rate after the release is cut.

## Impact

- A genesis entry made with a short deadline (the wallet CLI defaults a deadline to `timestamp + 3600`, `crates/hypersnap-wallet/src/main.rs:302`; the pivot tool has no default), or a fork that comes later than planned, makes the pivot fail everywhere at once. Each node has already stopped its snapchain read node at the fork block and written the marker (`read_validator.rs:111-129`), so the whole Hypersnap fleet sits idle until a rollback release.
- A genesis participant can deliberately transfer or recover their FID on Optimism (one L2 transaction) after the release is cut. That veto costs them only their own validator seat.
- Trust drifting below 0.05 between the rehearsal and the fork does the same without any action from the participant. This risk is small for real operators.

## Red-team

1. *Does the rehearsal catch it?* `hypersnap_pivot` can build the genesis from a stopped read node (`hypersnap_pivot.rs:95-106`), but it uses the *current* state and time. It cannot predict a later custody change or the real fork timestamp. It catches stale data at rehearsal time only.
2. *Is a fail-closed genesis the right design?* Fail-closed is right for safety: nodes must agree. But the FIP could instead define "an entry that fails is skipped", which every node would compute deterministically. The `PivotRecord` already commits to the resulting set. The concern is that one entry's failure is global.
3. *`MIN_VALIDATORS`?* Skipping entries could leave fewer than 3. Then failing is correct, and the rule should be "fail only if the surviving set is too small".
4. *Already filed?* No. F028 is about the genesis hash failing open, F046 about node-local trust input, F024 about validator inflow. None covers the time-dependent entry checks.
5. *Is the deadline needed at all for genesis entries?* The `PivotRecord` and `GENESIS_VALIDATORS_HASH` already bind the file to one release. The deadline protects post-pivot replays of a migration, which the "already migrated" check covers too.

## Fix

- Make genesis deterministic but tolerant: skip an entry whose application fails, record the skipped FIDs in the `PivotRecord`, and fail only if fewer than `MIN_VALIDATORS` remain.
- Or bypass the time-dependent checks for `ctx.genesis` (deadline, age, trust), since the release vets the genesis set. Keep the EIP-712 custody check, but document that a custody change before the fork removes the entry.
- In `hypersnap_pivot entry`, require a `--deadline` at least N days past the expected fork, and print the margin.
- Generate `EXEMPT_RECOVERIES` before assembling the file, and re-run the rehearsal as close to the fork as possible.

## Files

- `src/chain/pivot.rs:243-321, 380-420`
- `src/chain/shard0/registry.rs:234-287`
- `src/chain/shard0/validators.rs:186-201, 229`
- `src/node/pivot_boot.rs:103-152, 430-446`
- `src/bin/hypersnap_pivot.rs:7-11, 44-60, 95-106`
- `src/consensus/read_validator.rs:107-129`
