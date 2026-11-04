---
finding_id: F076
title: 'Shard-0 miniapp messages have no replay guard: anyone can re-submit a captured MINIAPP_ADD / REMOVE / REGISTER / UNREGISTER for as long as'
severity: medium
status: pending-validation
related_findings:
- F052
- F064
- F072
- F044
- F060
---
# F076 — Shard 0 has no general replay protection. `auth::open` bounds the timestamp only from above, shard 0 keeps no seen-hash index, and the mempool's duplicate check never matches a Hypersnap type. Most shard-0 types are still safe because of an account, spend-key, custody, rotation or escrow nonce, or a per-epoch "already done" record. The four miniapp-collection and registry types have none of these. Their only guard is a state precondition that the victim's own next action resets. So a byte-identical `MINIAPP_ADD`, `MINIAPP_REMOVE`, `MINIAPP_REGISTER` or `MINIAPP_UNREGISTER` that the victim signed once can be re-submitted by anyone, any number of times, until the victim revokes the signing key.

- **Severity:** Medium, source-only. The bug is pre-launch, like every shard-0 economics issue at `7eb981b`. Two independent harms:
  - **Economic.** A miniapp owner can re-count real users' adds of its app every block, weighted by *their* credibility, without their cooperation. This is F052's unbounded counter, but fed by victims' signatures instead of the attacker's own low-credibility FIDs. It is minted and never clawed back.
  - **Griefing.** Persistent reversal of a victim's later actions. Example: once a developer has unregistered a domain, they can never keep it registered under the same FID again. Example: once a user has removed an app, they can never keep it in their collection. Both last until the signing key is revoked, and for a migrated FID's account key that means a custody rotation, which resets the age clock.

  Not High, because the economic leg depends on F052's counter (fixing F052 cuts it to at most +1 per (epoch, owner, user)) and the griefing leg moves no funds.
- **Confidence:** 0.8. Byte-identical replay of a `MINIAPP_ADD`/`MINIAPP_REMOVE` pair is **build-backed**: F052 PoC control (d), `poc/F052/README.md` (hash `5ded32ef…` re-accepted in a later block, counter 200 → 201). The `REGISTER`/`UNREGISTER` replays and the per-type table are source-only.
- **Category:** message authentication / replay protection (missing nonce or seen-set on state-toggling messages)
- **Specialist:** chain-economics follow-up (from the internal validation notes, "Open follow-ups")
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** `src/chain/shard0/` (incl. `auth.rs`, `miniapp.rs`) does not exist in `bdef7b7`.
- **PoC:** Partial. F052's `f052_control_replay_and_epoch_isolation` shows the add/remove leg. Not built: (1) a third-party replay of an `UNREGISTER` after a re-`REGISTER` by the same FID, expected to be accepted and leave `MiniappState.active = false`; (2) an old `REMOVE` replayed after a fresh `ADD`, expected to be accepted and leave `add_key` absent. Both use the F052 harness unchanged.

## Why nothing stops a replay

1. `auth::open` checks the hash, signature, network, size and only `ts > block_timestamp + MAX_FUTURE_SECONDS` (`src/chain/shard0/auth.rs:143-146`). There is no lower timestamp bound.
2. `apply_message` keeps no record of applied message hashes (`src/chain/shard0/engine.rs:428-591`).
3. The mempool's `message_already_exists` looks the hash up in the snapchain message store by `type_to_set_postfix` (`src/mempool/mempool.rs:449-490`). Every Hypersnap type hits the `Err` arm of `type_to_set_postfix` (`src/storage/store/account/message.rs:50-89`) and returns `false` ("not a duplicate"). It is not a consensus check anyway: any proposer can include the message.
4. `auth::resolve` only requires that the signer is active *now* (`auth.rs:259-339`). Ed25519 app signers come from the on-chain or gasless key set. A migrated FID's `AccountKey` is the current custody Falcon key. Falcon-signer `ttl` is not enforced on shard 0 (F044), so it does not close the window either.
5. Shard-0 blocks are public (sync, read nodes, gossip), so capturing a message needs no access.

## Per-type table (shard-0 dispatch, `engine.rs:440-586`)

| # | Type | Replay guard | Class |
|---|---|---|---|
| 1 | `KEY_ADD` (shard-0 path) | user-nonce CAS `check_and_set_user_nonce` (`registry.rs:464`; gasless merge `gasless_key_merge.rs` step 4), `falcon_signer` exists | REPLAY-SAFE (nonce) |
| 2 | `KEY_REMOVE` | user or app nonce + `check_deadline` (`registry.rs:560, 625-631`) | REPLAY-SAFE (nonce) |
| — | `VERIFICATION_ADD_ETH_ADDRESS` / `VERIFICATION_REMOVE` | snapchain `VerificationStore` CRDT merge (`verifications.rs:180`), only when `on_shard0(version)` | Out of scope (snapchain rules) |
| — | `LEND_STORAGE` | always rejected after the pivot (`engine.rs:476-480`) | N/A |
| 3 | `CUSTODY_MIGRATION` | state: "FID is already migrated" (`custody_of` is never deleted) + `deadline` (`registry.rs:256-261`) | REPLAY-SAFE (state, permanent) |
| 4 | `CUSTODY_ROTATION` | custody nonce `record.nonce + 1` + `deadline` (`registry.rs:313-318`) | REPLAY-SAFE (custody nonce) |
| 5 | `SPEND_KEY_ADD` | account nonce + "already has this spend key" (the record is kept after revoke) (`ledger.rs:806-824`) | REPLAY-SAFE (nonce) |
| 6 | `SPEND_KEY_REVOKE` | account or spend-key nonce + "already revoked" (`ledger.rs:857-872`) | REPLAY-SAFE (nonce) |
| 7 | `TOKEN_TRANSFER` | `authorize_spend`: account nonce or per-spend-key nonce (`ledger.rs:58-103, 132`) | REPLAY-SAFE (nonce) |
| 8 | `FEE_DEPOSIT` | account nonce (app signer of an unmigrated FID uses the same stream) or `authorize_spend` (`ledger.rs:155-165`) | REPLAY-SAFE (nonce) |
| 9 | `TOKEN_STAKE` | account nonce (`ledger.rs:198`) | REPLAY-SAFE (nonce) |
| 10 | `TOKEN_UNSTAKE` | account nonce (`ledger.rs:244`) | REPLAY-SAFE (nonce) |
| 11 | `TOKEN_LOCK` | account nonce; the lock ID is derived from it (`ledger.rs:625-630`) | REPLAY-SAFE (nonce) |
| 12 | `TOKEN_ESCROW_CLAIM` | escrow nonce (`ledger.rs:484-490, 513`) | REPLAY-SAFE (escrow nonce) |
| 13 | `TOKEN_ESCROW_BRIDGE` | escrow nonce (`ledger.rs:663`) | REPLAY-SAFE (escrow nonce) |
| 14 | `NODE_ATTESTATION` | account nonce + "node key already has an attestation" (`validators.rs:56-65`) | REPLAY-SAFE (nonce) |
| 15 | `NODE_ATTESTATION_REVOKE` | account nonce (`validators.rs:103`) | REPLAY-SAFE (nonce) |
| 16 | `VALIDATOR_REGISTER` | time window `registration_epoch == ctx.epoch` (FIP l.314 "This prevents replay") + state "active or announced". Inside the epoch the reactivation branch cannot re-fire: a fresh join is `epoch+2`, and a used reactivation clears `auto_deregistered`/`inactive` (`validators.rs:157-159, 210-228`) | REPLAY-SAFE (epoch window + state) |
| 17 | `VALIDATOR_DEREGISTER` | epoch window + `leave_epoch != 0` (`validators.rs:262-283`) | REPLAY-SAFE (epoch window + state) |
| 18 | `DA_CHALLENGE_RESPONSE` | `body.epoch == ctx.epoch`, response window, `da_answered(epoch, node, index)` (`work.rs:88-110`) | REPLAY-SAFE (epoch + seen record) |
| 19 | `BRIDGE_ACTION_VOTE` | `body.epoch == ctx.epoch`, `bridge_vote(epoch, action, node)` exists (`bridge_actions.rs:48-80`) | REPLAY-SAFE (epoch + seen record) |
| 20 | `SEED_COMMIT` | `t == epoch+2` + commit exists (`seed.rs:67-80`) | REPLAY-SAFE (epoch + state) |
| 21 | `SEED_REVEAL` | `t == epoch+1`, reveal window, reveal exists (`seed.rs:94-114`) | REPLAY-SAFE (epoch + state) |
| 22 | `APP_USAGE_RECEIPT` | `body.epoch == ctx.epoch` + `app_receipt(epoch, owner, user, nonce)` exists (`work.rs:162-173`) | REPLAY-SAFE (epoch + receipt nonce) |
| 23 | `MINIAPP_REGISTER` | state only: "the domain is already registered" (active). The account-association proof has no expiry (`account_association.rs:152`); there is no nonce and no timestamp check (`miniapp.rs:97-149`) | **REPLAYABLE, WITH EFFECT** |
| 24 | `MINIAPP_UNREGISTER` | state only: active and `author_fid == fid`. The body is just `domain` (`miniapp.rs:151-166`) | **REPLAYABLE, WITH EFFECT** |
| 25 | `MINIAPP_UPDATE` | last-write-wins on `ts < updated_at_timestamp` (`miniapp.rs:184-190`). Equal-ts reapply is idempotent, older updates are rejected. *Exception:* after a replayed `REGISTER` resets `updated_at_timestamp`, any superseded update can be replayed (rollback, row 23) | REPLAYABLE, HARMLESS (alone) |
| 26 | `MINIAPP_ADD` | state only: `add_key(fid, id)` absent + `MAX_ADDS_PER_FID` (`miniapp.rs:195-224`). Each replay does `adds_by_epoch_key(epoch, current owner, fid) += 1` | **REPLAYABLE, WITH EFFECT** |
| 27 | `MINIAPP_REMOVE` | state only: `add_key(fid, id)` present (`miniapp.rs:226-245`) | **REPLAYABLE, WITH EFFECT** |
| 28 | `NATIVE_ONBOARD` | state: custody→FID index, deleted by a native rotation | REPLAYABLE, WITH EFFECT — **already F064** |
| 29 | `NATIVE_CUSTODY_ROTATION` | rotation nonce (`onboarding.rs:395-424`); FID-0 malleability is F072 and does not cause double execution | REPLAY-SAFE (rotation nonce) |
| 30 | `ONBOARDING_STAKE_LOCK` | account nonce + "stake lock exists" (`onboarding.rs:476-481`) | REPLAY-SAFE (nonce) |
| 31 | `ONBOARDING_STAKE_RELEASE` | account nonce; the lock is deleted (`onboarding.rs:513-515`) | REPLAY-SAFE (nonce) |

**Counts (31 types in scope):** 25 REPLAY-SAFE, 1 REPLAYABLE HARMLESS (`MINIAPP_UPDATE`), 5 REPLAYABLE WITH EFFECT. Of those five, 4 are new here (`MINIAPP_REGISTER`, `MINIAPP_UNREGISTER`, `MINIAPP_ADD`, `MINIAPP_REMOVE`) and 1 is F064 (`NATIVE_ONBOARD`). Out of scope: 2 snapchain verification types (snapchain CRDT) and `LEND_STORAGE` (always rejected).

The pattern: every token, key, custody and validator type was given a nonce or an epoch binding. The four miniapp types, which come from the Native Miniapp Index FIP and were folded into shard 0 (FIP l.2316), were given none.

## What a third party can do with captured messages (window: until the signing key is revoked; no time bound)

- **`MINIAPP_ADD` + `MINIAPP_REMOVE` pair (any order)** from user U for domain d. Re-submit the pair in every block. Each add does `adds_by_epoch[e][owner(d)][U] += 1` with U's credibility. The pair nets out in `add_count` and in U's collection, so U sees nothing. The beneficiary is whoever owns d *at replay time* (`state.author_fid`), so it also follows a domain to a new owner. This is the worst case (attack path below).
- **`MINIAPP_REMOVE` alone.** After U re-adds d, replay the old remove: U's add is deleted. U cannot keep d in the collection.
- **`MINIAPP_ADD` alone.** After U removes d, replay the old add: d is back in U's collection and uses one of U's 100 `MAX_ADDS_PER_FID` slots. Re-adding many of U's past apps can fill the cap and block U from adding new ones.
- **`MINIAPP_UNREGISTER`** from developer D for d. After D re-registers d, replay it: d is inactive again. Receipts (`work.rs:143-150` `miniapp_owner` requires `active`) and adds stop for d. D cannot keep d registered under that FID.
- **`MINIAPP_REGISTER`** from D. After D unregisters, replay it: d is active again with D's *old* metadata and `add_count` reset to 0 while the per-user `add_key` records remain. If d was later registered by another FID B, then once B unregisters, D's stale register reassigns d to D. That needs D's custody address to be unchanged so the association proof still verifies. Combined with row 25, any superseded `MINIAPP_UPDATE` of D can then be replayed in order, so metadata can be rolled back to any earlier version.

## Attack path (worst case: App-PoW capture with other users' credibility)

1. Attacker A owns miniapp d (registered with an account-association proof for a domain A controls). This is the same precondition as F052.
2. A scans shard-0 history and collects, for every FID U that has ever both added and removed d, one `MINIAPP_ADD` and one `MINIAPP_REMOVE` (byte-identical, still signed by a key that is active for U). Organic churn supplies these. An app can also encourage it by prompting users to add and later to "reset" the app.
3. In every block of epoch e, A submits, for every harvested U, `REMOVE_U` (if U currently has d added) then `ADD_U`, `REMOVE_U`, `ADD_U`, ... The relative order is free because each guard only checks the current state. A needs no key, and the messages pass `auth::open`/`resolve` because U's signer is still active.
4. `adds_by_epoch_key(e, A, U)` grows by the number of pairs per block. There is no per-epoch cap (F052). App-PoW weights each U by U's full credibility (F053), and a miniapp add has weight 5.0 against 0.5 for a receipt (FIP l.615-616). A's share of the App-PoW pool approaches 100% with real, high-credibility users' weight. F052's capture needed A's own floor-credibility sybils (c = 0.10).
5. At the scoring boundary the reward is minted to A (`boundary.rs:160-170`) and never clawed back. Victims' visible state is unchanged.
6. A victim can stop it only by revoking the signer that signed the pair: an on-chain or gasless `KEY_REMOVE` for an app signer, or a `CUSTODY_ROTATION` for a migrated account key. A custody rotation restarts the FID's age clock (`registry.rs:329` `last_custody_change`) and escrows its balance (`ledger::custody_change`), so it has a PoQ cost.

Bounds: realistic per-block inclusion (F052 caveats: the `enable_rate_limits` default is off, the 12k-messages-per-block cap) and the size of the harvestable pool, i.e. users who ever added *and* removed d. Before launch that pool is empty, and it grows with organic use.

## Red-team

1. *Hidden dedupe anywhere?* No. There is no seen-hash write in `apply_message`. The mempool duplicate check is a no-op for Hypersnap types (fact 3). F052 control (d) re-accepted the identical hash through propose, validate and commit on 3 nodes. STANDS.
2. *Is the old signer still valid?* Yes, unless the victim revoked it. App signers are long-lived (years). Falcon-signer TTL is not enforced (F044). STANDS, and the window is bounded only by key revocation.
3. *Can the attacker see the messages?* Shard-0 blocks are public. STANDS.
4. *By design (sets are idempotent)?* No. The same module implements last-write-wins by timestamp for `MINIAPP_UPDATE` (`miniapp.rs:184`), so ordering was considered. Snapchain's add/remove stores resolve the same conflict by timestamp with tombstones. FIP l.314 shows the authors treat replay as something to prevent. No FIP text permits replaying a superseded add or remove. STANDS.
5. *Does fixing F052 fix this?* Only the magnitude of the economic leg. With a distinct-per-epoch add count, one replayed add per epoch still counts a user who removed the app as a fresh add every epoch, and the griefing legs remain. Distinct root cause (missing replay guard vs. a counter that never decrements). Kept separate.
6. *Do `REGISTER` replays really verify?* The account-association proof is checked against the FID's *current* classical custody (`miniapp.rs:110-124`) and has no expiry. It holds while custody is unchanged. PARTIAL: it fails after a custody transfer.
7. *Severity inflation?* Pre-launch, source-only for 2 of the 4 types, no fund loss to victims, and the economic leg needs organic add/remove history. Hence Medium, not High.
8. *Overlap with F064/F072?* F064 is `NATIVE_ONBOARD` only, with a different guard (the custody index). F072 is FID-0 hash malleability, with no double execution. This finding is the miniapp types. Related, not duplicate.

## Fix

- **General (recommended):** give shard 0 a replay window. Reject `ts < block_timestamp − REPLAY_WINDOW` in `auth::open` (for example one epoch or a few hours, which must exceed honest mempool latency), and keep a seen-hash index `[prefix][hash] → expiry` over that window, pruned at boundaries. The index must be keyed on a canonical identity, or FID-0 malleability (F072) lets a variant through.
- **Miniapp types specifically:** add per-entity last-write-wins. Store `last_op_ts` per `(fid, miniapp_id)` for add/remove and per `miniapp_id` for register/unregister (and keep it across unregister), and reject `ts <= last_op_ts` with a hash tiebreak, as snapchain's CRDT stores do. Alternatively put the four types on the FID's account-nonce stream. That serializes them with token operations, so the per-entity timestamp is less intrusive for app signers.
- Also fix F052: count distinct `(epoch, owner, user)` adds instead of incrementing on every add.

## Files

- `src/chain/shard0/auth.rs:143-146` (no lower timestamp bound), `:259-339` (`resolve`: the signer is checked only for being active now)
- `src/chain/shard0/engine.rs:428-591` (dispatch, no seen-hash)
- `src/chain/shard0/miniapp.rs:97-245` (register / unregister / update / add / remove)
- `src/mempool/mempool.rs:449-490`, `src/storage/store/account/message.rs:50-89` (the duplicate check does not cover Hypersnap types)
- Guards of the safe types: `ledger.rs:43-103, 484-490`, `registry.rs:256-318`, `validators.rs:21-27, 157, 262-283`, `work.rs:88-110, 162-173`, `seed.rs:67-114`, `bridge_actions.rs:48-80`, `onboarding.rs:395-424, 448-515`
- Evidence: `poc/F052/README.md` (control d), the internal validation notes ("Open follow-ups")
