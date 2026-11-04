---
finding_id: F064
title: A native custody rotation deletes the custody→FID index, and that index is the only replay guard on `NATIVE_ONBOARD`
severity: medium
status: pending-validation
related_findings:
- F065
- F019
- F053
---
# F064 — A native custody rotation deletes the custody→FID index, and that index is the only replay guard on `NATIVE_ONBOARD`. Once the custody address has rotated its FID away, the same onboarding message (same PoW, same anchor) is valid again and issues a new FID. Repeating rotate + replay within the 1024-block anchor window gives any number of native FIDs for one gate proof. Regression of old ONBD-4.

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from regression pass 2026-11-04

> **Status 2026-11-04 (post-validation):** Note: the "more native FIDs feed F019" leg is moot, because F019 overflows at today's mainnet FID count without extra FIDs. The core (unbounded FIDs from one PoW) and Medium stand.


- **Severity:** Medium, source-only. It bypasses the onboarding sybil gate: the cost per native FID drops from one 2^30 hashcash to two messages. More native FIDs feed F019 (an unbounded `ScoringResult` can halt shard 0; it estimates ~230k native FIDs) and F053 (zero-trust sybils paid by App PoW). It is not High today because of F065: the mempool rejects every `NATIVE_CUSTODY_ROTATION`, so only a proposer that writes its own block can include the rotations. If F065 is fixed by adding a dedupe key for the rotation and nothing else, any user can do this.
- **Confidence:** 0.8. The state-machine path is certain from source. The validate path runs `apply_message` only, with no precheck and no message-hash dedupe (`engine.rs:428-597`, `:820-860`). Not built.
- **Category:** replay / sybil-gate bypass (native onboarding)
- **Specialist:** regression pass vs. old lineage (cab225f..f4fc4af), 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard0/onboarding.rs` does not exist at merge-base `bdef7b7`. This is a **regression of old ONBD-4**. The old lineage fixed ONBD-4 with a permanent "ever onboarded" marker per custody. The rewrite has no such marker.
- **PoC:** None, reasoned from source. Engine-test sketch, extending `native_onboarding_by_pow_and_by_stake` (`engine_test.rs:1108-1133`): onboard `user` by PoW **without** `falcon_custody_key` → FID `F1 = 2^63`. Build `NATIVE_CUSTODY_ROTATION{fid: F1, current: user, new: eth(40), nonce: 1}` signed by `user` (fid 0, `SIGNATURE_SCHEME_NONE`). Run `net.proposal(vec![rotation, m.clone()])`, which bypasses the mempool the way a proposer would. Expected: both messages accepted, `native_fid_key(2^63 + 1)` = `user`. Repeat with `eth(41)`, `eth(42)`, … The existing assertion at `:1131-1132` passes only because `user` still holds `F1`.

## Code facts

1. **The only replay guard is the custody index.** `onboard` checks `custody_index_key(custody)` and nothing else (`src/chain/shard0/onboarding.rs:333-335`). There is no record of which gate proof, anchor or message has been used. The EIP-712 form binds custody, anchor height, anchor hash and the gate commitment (`:129-159`, checked at `:276-285`). It does not bind the FID or a nonce.
2. **Rotation deletes the guard.** `rotate` runs `txn.delete(custody_index_key(&current))` (`:421`) and writes the index for the new custody (`:422`).
3. **Rotation is cheap and needs only the old custody.** It needs `Role::Unsigned` (`:381-383`), the FID not migrated (`:387-389`), `nonce = previous + 1` (`:394-398`, which is 1 for a fresh FID), an EIP-712 signature by the current custody (`:399-408`), and a `new` custody with no native FID (`:409-411`). The new custody does **not** sign. Any fresh 20-byte value works.
4. **The replay is still in its window.** The anchor must be within `onboard_anchor_window = 1024` blocks (`:305-309`, `mod.rs:153`). The PoW is a pure function of `(custody, anchor_hash, nonce)` (`:93-100`, `:256-265`), so it stays valid. An unsigned onboarding has no envelope signature to refresh (`:233-246`).
5. **Nothing dedupes executed messages.** `apply_message` → `onboarding::onboard` (`engine.rs:574-576`). The mempool `fid0_keys` dedupe applies only while a message with that key is pending (`src/mempool/mempool.rs:731-742`). `message_already_exists` cannot see shard-0 onboardings, because `type_to_set_postfix(NativeOnboard)` errors and the code then returns `false` (`mempool.rs:449-480`, `src/storage/store/account/message.rs:50-90`).
6. **The loop works within one block.** Messages apply in order on one `BlockState`, so `[onboard, rotate F1, onboard (replay), rotate F2, onboard (replay), …]` in a single block issues one FID per replay. `max_messages_per_block` (12 000) is enforced only in `Mode::Propose` (`engine.rs:831`).

## Attack

- **Today (F065 present):** a validator, when it proposes, includes `NATIVE_CUSTODY_ROTATION` messages it built itself. Honest validators re-execute them and accept, because validation does not run `precheck`. One 2^30 PoW per 1024 blocks gives up to ~6 000 native FIDs per proposed block (two messages each, under the 12 000 proposer cap). A Byzantine proposer can exceed the cap, because validate does not enforce it.
- **After a naive F065 fix:** any user. The mempool dedupes by custody only while a message is pending (fact 5). Alternate rotate and replay, one pair per block.
- Each FID ends with a custody the attacker chose (fact 3; the attacker can hold those keys). A CUSTODY_MIGRATION to Falcon then makes each one usable (`registry.rs:78-87` resolves native custody).

## Invariant (restated from old ONBD-4)

*One gate proof (PoW solution or stake binding) yields at most one native FID, and that FID's issuance cannot be replayed by any later state change.* The stake arm keeps this through `stake_binding_key` (`:323-328`, `:342-344`). The PoW arm does not.

## Red-team

1. *Is the anchor window the real limit?* It limits each PoW to 1024 blocks, not to one FID. Fact 6 makes the count per window large.
2. *Does `custody_of(F)` block rotation?* Only for FIDs onboarded with a Falcon key. The attacker omits it.
3. *Does `ledger::custody_change` fail on an empty FID?* No. It moves a zero balance and scans empty vouch sets (`ledger.rs:365-400`).
4. *Did the old fix survive somewhere else?* Search for an "ever" or consumed-PoW key: none among the onboarding `RootPrefix` values 110-115 and 144 (`keys.rs:508-514`).
5. *Is this F019 or F053?* No. Those findings assume each native FID costs one 2^30 PoW. This one removes that cost.

## Fix

- Record the consumed gate: write `pow_consumed[sha256(custody ‖ anchor_hash ‖ nonce)]` (or simply `onboarded_ever[custody]`) in a consensus prefix, and never delete it. That is what the old ONBD-4 fix did.
- Or keep the custody index on rotation as a tombstone (`custody → RETIRED`), so the original custody can never onboard again.
- Add a test: onboard, rotate, replay → rejected.

## Files

- `src/chain/shard0/onboarding.rs:93-100, 129-159, 256-285, 296-372, 374-430`
- `src/chain/shard0/engine.rs:428-597, 820-860`
- `src/chain/shard0/mod.rs:153-154`
- `src/mempool/mempool.rs:449-480, 717-744`
- `src/chain/shard0/engine_test.rs:1108-1133`
