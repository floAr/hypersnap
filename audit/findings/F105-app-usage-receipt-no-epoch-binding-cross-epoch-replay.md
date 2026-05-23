---
id: F105
task: H105
specialist: rust-crypto-primitives
attack_class: signing-payload-or-dst-collision
severity: high
status: draft
related_findings:
  - id: F104
    relationship: related-but-distinct
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.93
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F105 — App-PoW receipts have no epoch / timestamp binding to the apply path; one signed receipt can be replayed across every future epoch to inflate the app-owner's §7 score

- **Task ID:** H105
- **Specialist:** rust-crypto-primitives
- **Attack class:** signing-payload-or-dst-collision (replay-window / nonce-scope mismatch)
- **Severity (draft):** High
- **Status:** draft

## Summary

`AppUsageReceiptBody.timestamp` is included in the canonical Ed25519
signing payload but **the apply path never validates it against any
epoch boundary or expiry window**. The replay-protection key the
runtime writes is

```
[HyperAppReceipt][epoch_at_apply BE u64][app_owner_fid BE][user_fid BE][nonce BE]
```

where `epoch_at_apply = self.epoch_resolver.current_epoch()` — i.e.,
the epoch number is *chosen by whoever submits the message*, not by
whoever signed it. The user's signature binds `(miniapp_id, user_fid,
app_owner_fid, timestamp, nonce, action_type, user_signer_pubkey)`
and chain_id — but **not the epoch**. The proto file makes this
explicit (`hyper.proto:631-634`):

> `// Farcaster timestamp (seconds since FARCASTER_EPOCH).`
> `// Informational — the storage epoch is the runtime's`
> `// current_epoch() at apply time, not derived from this.`

Consequence: **any party who observes a single valid receipt** (a
miniapp's backend, a relayer, an indexer, a malicious gossip peer)
can re-submit the exact same byte-identical signed receipt in every
subsequent epoch. Each resubmission lands at a distinct storage key
(`epoch=N`, `epoch=N+1`, `epoch=N+2`, …) so the duplicate-key check
on line 2224 of `runtime.rs` never trips, and each lands as a fresh
`(user, app, epoch)` receipt that counts toward the app's §7 App-PoW
score in that epoch.

One genuine user interaction therefore credits the app's
`app_owner_fid` forever, every epoch, with no further user
involvement — and the per-epoch cap of 10_000 receipts per (user,
app) becomes the attacker's *minimum* replayable harvest (the
attacker can build a cache of last epoch's 10_000 distinct nonces
from the user and replay all of them every epoch).

## Affected files

- `code/hypersnap/src/hyper/app_usage_receipt.rs:36, 77-93` — signing payload (`RECEIPT_DST`, layout)
- `code/hypersnap/src/hyper/runtime.rs:2125-2142` — `app_receipt_key`, `app_receipt_count_key`
- `code/hypersnap/src/hyper/runtime.rs:2181-2254` — `apply_app_usage_receipt` (no epoch/timestamp check)
- `code/hypersnap/proto/definitions/hyper.proto:620-649` — `AppUsageReceiptBody` ("Informational" timestamp)
- `code/hypersnap/src/hyper/router.rs:259-265` — receipt dispatched to runtime with no caller-identity restriction
- `code/hypersnap/crates/proof-of-quality/src/scoring.rs:385-403` — `app_receipt_counts_for_epoch` consumes the inflated per-epoch count

## Field-coverage table

| Field | In `app_receipt_signing_payload` (signed) | Checked by `apply_app_usage_receipt` |
|---|---|---|
| DST `b"hypersnap-app-receipt-v2..."` | yes | n/a |
| `chain_id` | yes (BE u64) | implicit (verify uses `self.protocol_chain_id`) |
| `miniapp_id` (16 B) | yes | **NO** — not cross-checked against any registered miniapp / against `app_owner_fid` |
| `user_fid` | yes | yes (signer-auth via `get_active_key`) |
| `app_owner_fid` | yes | yes (used in storage key) |
| `timestamp` | **yes** | **NO** — never compared to current epoch, never compared to a window, never written to storage |
| `nonce` | yes | partial — only scoped to `(epoch_at_apply, app, user)`, not globally per `(app, user)` |
| `action_type` | yes (len-prefixed) | structural only (non-empty, ≤ 64 B) |
| `user_signer_pubkey` | yes | yes (must be on active-key list for `user_fid`) |
| `epoch` | **NO** | n/a (storage uses apply-time `current_epoch()`) |

The two starred gaps combine to enable the attack: `timestamp` is
signed but unused; `epoch` is used but unsigned.

## Exploit walkthrough

### Setup

A user with FID 7 opens a miniapp owned by `app_owner_fid = 42`. The
app's backend produces a canonical receipt:

```
miniapp_id     = sha256("farcaster-miniapp:" || domain)[..16]
user_fid       = 7
app_owner_fid  = 42
action_type    = "open"
timestamp      = current_farcaster_ts
nonce          = 1
user_signer    = ed25519 pk of user 7's authorized signer
user_signature = SIGN(payload || DST || chain_id || ...)   // 64 B
```

The app calls `submit_message` once. Runtime is at `epoch = E`. The
receipt lands at `HyperAppReceipt[E][42][7][1]`. Counter
`HyperAppReceiptCount[E][42][7] = 1`.

So far, normal behaviour — user actually used the app once.

### Attack step 1 — observe the receipt

Receipts are routed through the runtime (`router.rs:259`) which means
they ride the gossip mesh as `HyperMessage` envelopes. Every peer on
the network sees the bytes. Even without gossip access, the app's own
backend has them — and `submit_message` has no caller-identity gate
(anyone can submit any signed receipt; the runtime just dispatches to
`apply_app_usage_receipt`). RocksDB also retains the receipt body
keyed by `HyperAppReceipt[...]` (line 2244) so any node operator can
fetch it.

### Attack step 2 — wait for the epoch boundary

When the runtime ticks to epoch `E+1`, `self.epoch_resolver.current_epoch()`
returns `E+1`. The on-disk key `HyperAppReceipt[E+1][42][7][1]` is
empty.

### Attack step 3 — re-submit the byte-identical receipt

The attacker re-broadcasts the same `HyperMessage` (or constructs a
new envelope around the same `AppUsageReceiptBody`). At
`apply_app_usage_receipt`:

- `validate_app_usage_receipt(body, chain_id)` succeeds — same DST,
  same chain_id, same bytes; the Ed25519 signature still verifies.
  No timestamp / freshness check is performed.
- `get_active_key(..., user_fid=7, user_signer_pubkey=...)` returns
  `Some(_)` (the user's signer is still authorized).
- `count = self.app_receipt_count(E+1, 42, 7)` returns 0 (or whatever
  current epoch-`E+1` count is, well under the cap).
- `self.db.get(app_receipt_key(E+1, 42, 7, 1))` returns `None` —
  **the key is unique because the epoch byte changed**.
- All four gates pass. The runtime writes
  `HyperAppReceipt[E+1][42][7][1] = body_bytes` and bumps
  `HyperAppReceiptCount[E+1][42][7] = 1`.

App-PoW score for `app_owner_fid = 42` in epoch `E+1` is incremented
on the basis of a single user interaction that actually happened in
epoch `E`.

### Attack step 4 — scale

The attacker repeats for every subsequent epoch indefinitely. If the
attacker has captured 10_000 distinct `(nonce_i, action_i)` receipts
from honest user activity in some prior epoch, they can replay all
10_000 every epoch, saturating the per-(user, app) cap with zero new
user participation — which means `MAX_RECEIPTS_PER_APP_PER_EPOCH`
becomes a *floor* on guaranteed-replayable score, not a cap.

The same attack scales across users: any app that ever harvested
receipts from N distinct users can keep generating N × 10_000
receipt-credits per epoch.

### Why the existing replay protections don't catch this

| Protection | Where | Why it fails |
|---|---|---|
| Ed25519 signature | `validate_app_usage_receipt` | Same bytes verify forever. |
| Duplicate-nonce check | `runtime.rs:2224-2234` | Keyed by `(epoch, app, user, nonce)`. Distinct epochs → distinct keys → never collides. |
| Rate limit | `runtime.rs:2212-2220` | Per-epoch. The cap *resets* every epoch. |
| Signer-auth (`get_active_key`) | `runtime.rs:2198-2208` | Persists across epochs by design. Revoking the signer would invalidate the replay, but only after a separate signer-revoke event. |
| Timestamp | `body.timestamp` is signed | **Never read by the apply path.** |

## Comparison to sibling messages (which are not vulnerable)

This gap is `AppUsageReceipt`-specific. Other Ed25519-signed messages
in the same family use one of two patterns that block cross-epoch
replay:

- **`TokenTransfer` / `TokenStake` / `MiniappAdd` / `MiniappUpdate` /
  `MiniappRegister` / `NodeAttestation`** — all use a per-FID
  monotonic `nonce` (`HyperTokenNonce`, `MiniappRegisterNonce`, etc.)
  scoped to the FID only, never to the epoch. Submission `n` requires
  `expected = current + 1`. Replay across epochs is impossible because
  the nonce-counter only moves forward.
- **`DaChallengeResponse`** — the body contains an explicit `epoch`
  field that IS signed; the apply path rejects on `body.epoch != current_epoch`.

`AppUsageReceipt` deliberately departed from both patterns —
documented in `hyper.proto:635-639` as *"Per-(user, app, epoch)
replay/dedup nonce. Distinct nonces for distinct receipts within an
epoch; reuse rejects on key-collision."* The phrase "within an epoch"
is doing the load-bearing work, but nothing in the signing payload or
the apply path actually enforces that the user-asserted timestamp
matches the apply-time epoch.

## Recommended fixes (any one closes the attack)

### Fix A — bind an explicit `epoch` field, sign it, check it (preferred)

Add `uint64 epoch = 9;` to `AppUsageReceiptBody`. Include it after
`chain_id` in `app_receipt_signing_payload`. In
`apply_app_usage_receipt`, after the structural validation:

```rust
let now = self.epoch_resolver.current_epoch();
if body.epoch != now {
    return Err(RewardError::Custom(format!(
        "app receipt epoch {} does not match current epoch {}",
        body.epoch, now,
    )));
}
```

Then the storage key can use `body.epoch` (which is now identical to
`current_epoch()`). A receipt signed for epoch `E` is structurally
unusable at any other epoch.

### Fix B — promote `nonce` to a per-(user, app) monotonic counter (like `MiniappAdd`)

Replace the per-(user, app, epoch) reset with a single
`HyperAppReceiptNonce[user][app]` counter that monotonically grows.
Replay of an already-consumed nonce is rejected forever. Loses the
rate-limit semantics so would need a per-(user, app, epoch) count
maintained independently.

### Fix C — enforce a timestamp freshness window

Require `|body.timestamp - now_farcaster_ts| <= TIMESTAMP_WINDOW_SECS`
in the apply path. Less robust (clock skew, replay within window),
but simplest. Should be combined with the storage key carrying a
truncation of `timestamp` to make cross-epoch replay unusable.

Fix A is the cleanest because it mirrors `DaChallengeResponseBody`,
which already solved this same problem with an explicit signed-epoch
field.

## Adjacent (related, weaker) observations

These are listed for completeness; they do not warrant separate
findings on top of the cross-epoch replay because the cross-epoch
replay subsumes them.

### O1. `miniapp_id` is signed but never cross-checked against `app_owner_fid`

`miniapp_id` rides on the receipt and is committed in the signing
payload, but `apply_app_usage_receipt` never verifies that this
`miniapp_id` is owned by `app_owner_fid` (or even exists in the
native miniapp index). A malicious app can collect a user's receipt
intended for `app_owner_fid = 42, miniapp_id = X` and produce a valid
storage record at `(epoch, 42, user, nonce)` regardless of which
miniapp the user thought they were interacting with. Storage is keyed
by `app_owner_fid`, so this is "wrong-miniapp credit", not
"wrong-app-owner credit" — but it means downstream consumers of
`miniapp_id` (analytics, dashboards, anti-Sybil heuristics built on
top of the receipt stream) cannot trust that field.

### O2. Doc-comment drifted from `v1` to `v2`

`app_usage_receipt.rs:10` claims the DST is `b"hypersnap-app-receipt-v1\x00"`
(25 B). Code at line 36 uses `b"hypersnap-app-receipt-v2"` padded
with NULs to 32 B. Stale documentation, not a runtime bug. Same drift
exists in `token_stake.rs` (already noted in `H103-ruled-out.md`),
suggesting a codebase-wide doc update was missed during the v1→v2
DST rotation.

### O3. Ed25519 `pk.verify` (cofactor-form) rather than `verify_strict`

Same observation as in F103/F045 — RFC8032 cofactor-form is used,
which accepts mixed-order point signatures. Per-FID active-key check
makes signature malleability low-impact for receipts, *but* it does
mean that the same logical receipt has multiple distinct signature
encodings, each of which would lay down a distinct on-disk record
under the cross-epoch replay primitive of this finding. Defence in
depth: switch to `verify_strict`.

## Reproduction sketch

```rust
use ed25519_dalek::SigningKey;
let sk = SigningKey::from_bytes(&[3u8; 32]);

let (mut rt, _dir) = make_runtime();          // current_epoch() == E0
seed_onchain_signer(&rt, 7, sk.clone());

let body = sign_app_receipt(7, 42, "open", 1, &sk);
rt.apply_app_usage_receipt(&body).unwrap();   // OK, lands at (E0, 42, 7, 1)
assert_eq!(rt.app_receipt_count(E0, 42, 7).unwrap(), 1);

// Advance one or more epochs (test helper or manipulate epoch_resolver).
rt.epoch_resolver.force_advance(1);
let E1 = rt.epoch_resolver.current_epoch();
assert!(E1 > E0);

// Same bytes, same signature, same nonce. Should fail. Currently passes:
rt.apply_app_usage_receipt(&body).unwrap();
assert_eq!(rt.app_receipt_count(E1, 42, 7).unwrap(), 1);  // attacker scored
```

## Severity rationale (draft)

**High.** Direct economic impact on §7 App-PoW reward allocation:
the attack inflates an app owner's score without any new user
participation, and the rate-limit cap (`MAX_RECEIPTS_PER_APP_PER_EPOCH =
10_000`) provides only an upper bound — replay can saturate to that
cap every epoch, indefinitely, with one-time-collected receipts.

The attack requires no key compromise, no special network position
(anyone with a copy of the receipt bytes can re-submit), and no
collusion with validators. It is asymptotically free for the
attacker. It does NOT enable theft of user funds, but it does enable
arbitrary draining of the App-PoW reward pool toward attacker-favored
apps, which is the headline §7 economic invariant.

Downgrade to Medium if the validation pass determines that
out-of-this-file mempool / scoring-driver code rejects receipts whose
on-chain landing epoch differs from `timestamp / SECS_PER_EPOCH`
(searched `mempool.rs`, `scoring_driver.rs`, `scoring.rs` — no such
check found).
