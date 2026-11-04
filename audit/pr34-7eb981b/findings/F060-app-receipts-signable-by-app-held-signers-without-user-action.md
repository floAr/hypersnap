---
finding_id: F060
title: App-usage receipts can be signed by app-held signers with no user action, so a client holding users' signers can farm the AppUsage pool
severity: medium
status: pending-validation
related_findings:
- F052
- F053
- F054
---
# F060 — FIP §7.3 says that the user's signature on an `AppUsageReceipt` "prevents fabricated usage. If the user does not interact, there can be no valid receipt." The code accepts a receipt signed by any active app signer of the user (`Role::AppSigner`). For a non-migrated FID, that includes every legacy `KeyRegistry` signer, and those keys pass every message type with no scope check. Those signer keys are held by the apps that requested them, not by the user. So any app that holds users' signers can sign up to 100 receipts per user per epoch for a miniapp that it (or a partner FID) owns, with no user action, at each user's full credibility weight. A client with signers for a large share of active users can take most of the AppUsage pool (30% of each epoch's emission).

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from spec-rule walk 2026-11-04

> **Status 2026-11-04 (post-validation):** Note: the code matches FIP §7.3's field definition ("a signer of the user"); the gap is with the spec's guarantee that a receipt cannot exist without user interaction.


- **Severity:** Medium, source-only. Direct mis-allocation of the AppUsage pool, every epoch, with no collusion from users. FIP §7.6 accepts app/user *collusion* as unsolvable, but it states that unilateral fabrication is impossible. Here unilateral fabrication is possible for anyone who holds signers. Not High: the attacker must already hold many real users' signers (a client or a signer-collecting app), and abuse is visible on chain (receipt volume per signer).
- **Confidence:** 0.8. The code path is certain. It rests on one external fact: legacy Farcaster signers are Ed25519 keys that the requesting app generates and keeps (the `requestFid` model that the PoQ F0 filter itself counts). Not built.
- **Category:** spec guarantee not enforced / reward-claim fabrication (App PoW)
- **Specialist:** spec-to-code compliance walk (PoQ + emission), 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: the receipt handler and App PoW are new since merge-base `bdef7b7`. The signer custody model (app-held `KeyRegistry` keys) is inherited from Farcaster/snapchain.
- **PoC:** None, reasoned from source and not built. Engine-test sketch: register miniapp `D` owned by FID `O`. For user FID `U` (not migrated) with an `OnChain` Ed25519 signer `K` (any signer, as if requested by app `O`), submit 100 `APP_USAGE_RECEIPT{miniapp_id: D, epoch: e, nonce: 1..100}` signed by `K`. Expected: all accepted (`work.rs:152-189`). `app_receipt_counts_for_epoch(e)[(O, U)] = 100`, and `O`'s app work is `100 × 0.5 × cred(U)`.

## Spec rules

- §7.3: `bytes user_signature = 5; // Signature by a signer of the user (Section 16.8 rules)`. "The signature of the user prevents fabricated usage. If the user does not interact, there can be no valid receipt."
- §7.5 item 2: "The node verifies the signature of the user and makes sure that the FID is registered."
- §7.6: "Collusion … The user must sign each receipt (cost: one signer operation)."

## Code facts

1. **The handler takes any app signer.** `work::app_receipt` (`src/chain/shard0/work.rs:152-189`) checks four things:
   - `role` is `Role::AppSigner`;
   - `body.epoch == ctx.epoch`;
   - a 16-byte `miniapp_id` that names an active miniapp;
   - a fresh nonce, and `count < max_receipts_per_app_per_epoch` (100) per `(epoch, owner, user)`.

   It does not tie the receipt to the miniapp, to the signer's `requestFid`, or to any user-held key.
2. **For a non-migrated FID, any active Ed25519 signer is an `AppSigner`.** See `auth::resolve` (`src/chain/shard0/auth.rs:270-284`). Scopes are checked only for `ActiveKey::Gasless`. `ActiveKey::OnChain` (legacy `KeyRegistry` keys) admits every message type (`src/storage/store/account/active_key.rs:60-68`). Most mainnet FIDs are non-migrated with `OnChain` signers.
3. **The weight is the user's full credibility.** `accumulate_app_work` adds `count × 0.5 × credibility(user)` to the owner's work (`crates/proof-of-quality/src/app_pow.rs:44-73`). For real users this is 0.5-1.0 (F053 covers the floor for sybils), so 100 receipts from one real user count 25-50.
4. **Receipts are free.** They are shard-0 messages with no fee charge (F053 fact 5; the fee schedule covers shard-1/2 user messages, F054).
5. **Miniapp adds use the same role.** `MINIAPP_ADD` also accepts `Role::AppSigner` (`src/chain/shard0/miniapp.rs:80`). A signer-holding app can therefore also drive F052's add/remove churn on behalf of every user whose signer it holds.

## Attack path

1. App `X` runs a client or a "sign in with Farcaster" flow, and holds legacy signers for `N` active, credible users. Each user did authorize the signer, for some purpose.
2. `X` registers miniapp `D`, under its own FID or a partner FID to avoid any `requestFid`-based heuristic.
3. Each epoch, `X` signs 100 receipts per user for `D` (`100·N` shard-0 messages, no fee). It optionally adds `MINIAPP_ADD`/`REMOVE` churn (F052).
4. `D`'s owner gets `Σ_users 50 × cred(u)` of app work. Honest apps get at most what their users really do. With `N = 50k` users at credibility 0.6, `X`'s work is 1.5M receipt-units. An honest app needs 50k users each sending 100 real receipts at the same credibility just to match.

## Red-team

1. *Is this just the collusion risk that §7.6 accepts?* No. Collusion needs the user's participation. Here the user does nothing, and the FIP sentence "If the user does not interact, there can be no valid receipt" is false for app-held signers.
2. *Do signers really sit with apps?* For legacy `KeyRegistry` signers, yes. The requesting app generates the Ed25519 key and the user's custody signs `KeyRegistry.add`. PoQ's own F0 filter counts these `requestFid` relationships (`reader.rs` `signer_authorizations`).
3. *Can the user stop it?* Only by revoking the signer (an Optimism `KeyRegistry.remove`, which costs gas), which most users never do. Migrated FIDs with scoped Falcon signers can avoid it by not granting the receipt scope (`check_scopes`, `auth.rs:301, 334`).
4. *Does the 100-receipt cap bound it?* It bounds it per user, not per app, so the attack scales with `N`.
5. *Would the F0 app filter catch `X`?* F0 removes an *app FID* from Growth eligibility. It does not apply to App PoW recipients or to the users whose receipts are counted.
6. *Already filed?* F052 is add-churn (one FID, unbounded count). F053 is the sybil credibility floor. Neither covers fabricating receipts for real users through held signers.

## Fix

- Require an explicit receipt scope: accept `APP_USAGE_RECEIPT` only from a key whose scopes include it (gasless or Falcon signer), never from unscoped legacy `OnChain` keys. Or require the user's custody/account key.
- At least, reject receipts whose signer's `requestFid` (or its F0 custody cluster) owns, or is linked to, the miniapp. Note this alone is bypassable through partner FIDs.
- Cap receipts per user across all apps per epoch, or give each user a fixed receipt budget that they split, so one signer holder can't direct all of a user's weight.
- Update FIP §7.3/§7.6 to state the real trust model of app-held signers.

## Files

- `src/chain/shard0/work.rs:152-189`
- `src/chain/shard0/auth.rs:258-338`
- `src/storage/store/account/active_key.rs:60-68`
- `src/chain/shard0/miniapp.rs:75-82`
- `crates/proof-of-quality/src/app_pow.rs:44-73, 136-170`
- `src/chain/scoring.rs:235-250`
- `docs/spec/FIP-proof-of-work-tokenization.md` §7.3, §7.5, §7.6
