---
id: F158
task: H158
attack_class: untrusted-input-ingress
severity: high
status: draft
---

# F158 — Notification webhook accepts JFS-signed events with no binding to `app_id`, destination URL, timestamp, or nonce — captured-envelope replay enables cross-app notification subscription spoofing, force-unsubscribe of any subscriber, and notification-phishing attribution to a mini app the attacker does not control

- **Task:** H158
- **Attack class:** untrusted-input-ingress (JFS-replay variant; sibling of F101)
- **Severity (provisional):** High. Any single JFS-signed event ever produced by a Farcaster client and observed by an attacker (mini app operators, MITM on a mini app's webhook receiver, log scrapers, third-party SDK telemetry) is **forever replayable** against any other `app_id` on the same hypersnap deployment, and remains valid as long as the user's app key is still active in the on-chain KeyRegistry (months to years). The signed payload contains no `app_id`, no `notification_url` binding, no destination authority binding, no chain-id, no nonce, and no timestamp. The handler at `webhook_handler.rs:73-152` extracts `<app_id>` from the URL path only; the JFS verifier never sees it. This breaks the spec's implicit "destination-binding via URL choice" assumption that holds only when each mini app runs its own dedicated webhook receiver — and hypersnap is explicitly a **multi-tenant** notification proxy.
- **Status:** draft

## Scope files

- `code/hypersnap/src/api/notifications/webhook_handler.rs:73-202` (handler — primary)
- `code/hypersnap/src/api/notifications/jfs.rs:135-218` (verifier — confirms no payload binding beyond `fid` and `key`)
- `code/hypersnap/src/api/notifications/types.rs:62-84` (`MiniappEventPayload` — wire format has `event` + optional `notificationDetails` only; no nonce/timestamp/app_id)
- `code/hypersnap/src/api/notifications/mod.rs:36-60` (documents the multi-tenant `/v2/farcaster/frame/webhook/<app_id>` wire format)
- `code/hypersnap/src/api/notifications/store.rs:62-95` (`upsert` overwrites unconditionally — no `updated_at` monotonicity check; older replay overwrites newer state)
- `code/hypersnap/src/api/notifications/app_store.rs:53-80` (`RegisteredApp.signer_fid_allowlist` — opt-in defense, empty by default)

## Summary

The notification webhook receiver authenticates each incoming `miniapp_added` / `miniapp_removed` / `notifications_enabled` / `notifications_disabled` event purely by Ed25519 JFS signature. The wire format the spec defines (and that `MiniappEventPayload` mirrors verbatim) is:

```json
{ "event": "miniapp_added", "notificationDetails": { "url": "...", "token": "..." } }
```

That payload — once signed by Alice's active app key — is a **publicly replayable bearer** because **nothing in the signed bytes constrains where, when, or for which mini app the event is valid**. Specifically, the signed payload contains:

- No `app_id` field → cross-app replay is unconstrained at the signature layer.
- No `webhook_url` / destination URL → cross-deployment replay (e.g., a competing hypersnap instance, a different cloud region) is unconstrained.
- No `chain_id` / `domain_id` → cross-deployment replay is unconstrained.
- No `nonce` / `jti` → same-event replay against the same destination is unconstrained.
- No `iat` / `exp` / `signed_at` → replay is valid for the entire lifetime of the user's app key.

The handler at `webhook_handler.rs:78-94` reads `<app_id>` from the URL path, looks it up in `NotificationAppStore`, then calls `verify(&body, jfs_lookup)` at `:101` which validates the signature and confirms the signer is currently active for `header.fid`. The verified `(fid, payload)` pair is then passed to `apply(&app_id, fid, kind, &payload)` at `:141`, which writes to `NotificationStore` keyed by `(app_id, fid)` — the `app_id` originating from the URL path, not from any signed source.

So the entire trust chain from URL path → store key is unauthenticated; the only authenticated assertion the handler verifies is "some active app key for `fid` signed *some* mini-app event at *some* unbounded point in the past."

## Concrete attack scenarios

### Scenario 1 — cross-app notification subscription spoofing → notification phishing

**Setup.** Alice (fid 42) installs legitimate mini app M_A in her Farcaster client (Warpcast). Her client signs:

```json
{ "event": "miniapp_added",
  "notificationDetails": { "url": "https://warpcast.example/n/alice", "token": "tok-alice-v1" } }
```

and POSTs to `/v2/farcaster/frame/webhook/<app_id_A>` on hypersnap. M_A's operator (or any logging proxy on that path) captures the envelope.

Mallory operates a separate mini app M_B (or simply has rented an `app_id_B` on the same hypersnap deployment — `app.create` is open to any custody-key holder per H156's findings). Mallory:

1. Re-POSTs Alice's captured JFS envelope verbatim to `/v2/farcaster/frame/webhook/<app_id_B>`.
2. The JFS signature still verifies (the signed bytes don't reference `app_id_A`).
3. `header.fid = 42`, Alice's app key is still on-chain → `is_active_signer(42, …)` returns true.
4. `apply(&"app_id_B", 42, MiniappEventKind::Added, …)` writes:

   ```
   (app_id_B, fid=42) → { url: "https://warpcast.example/n/alice",
                           token: "tok-alice-v1", enabled: true }
   ```

Alice is now an "enabled subscriber" for app_id_B in hypersnap's view, even though her Warpcast client never sent that event for B. The persisted `notification_url` is *Alice's real client endpoint* — because that's what was in the captured payload. The persisted `token` is *Alice's real Warpcast token for app M_A*.

**Exploit primitive — phishing notifications attributed to M_A.** Mallory calls the developer-facing send endpoint:

```
POST /v2/farcaster/frame/notifications/<app_id_B>
x-api-key: <Mallory's app_id_B send secret>
{ "notification": { "title": "Your account is at risk",
                    "body": "Tap to verify your seed phrase",
                    "target_url": "https://mallory-phish.example/seed" },
  "target_fids": [42] }
```

(send_handler is H157's scope but the relevant property is well-documented — the per-app send secret is the only auth, and the per-app secret authenticates Mallory as the legitimate sender for `app_id_B`.)

Hypersnap fans out:

```
POST https://warpcast.example/n/alice
{ "notificationId": "<Mallory-chosen UUID>",
  "title": "Your account is at risk", "body": "Tap to verify your seed phrase",
  "targetUrl": "https://mallory-phish.example/seed",
  "tokens": ["tok-alice-v1"] }
```

Alice's Warpcast client receives this. It looks up `tok-alice-v1` in its local token store and finds **"this token was minted for mini app M_A"**. The client renders the notification under M_A's identity: M_A's icon, M_A's name. Alice taps the notification and is sent to `mallory-phish.example/seed` while believing she is interacting with M_A.

This is the spec's notification model breaking under the multi-tenant proxy assumption: per the spec, each mini app's webhook URL is unique to that mini app, so the per-token attribution `(token → mini app)` in the client is a sound binding. In hypersnap's deployment, the unique-webhook-URL invariant holds at the URL level (each `app_id` has a distinct path), but the JFS signature does not bind that distinction, so the attacker can route notifications through **any** `app_id` while the client still attributes them to the **original** app.

### Scenario 2 — same-app force re-enable / stale-URL overwrite (DoS)

Alice's lifecycle on the same app_id_A:

1. `t=0`: Alice adds M_A, client signs `notifications_enabled` with URL `https://wc.example/n/alice-v1`, token `tok-v1`. Captured by M_A's operator.
2. `t=1`: Alice toggles notifications off. Client signs `notifications_disabled`, POSTs to `/webhook/app_id_A`. Hypersnap calls `set_enabled(app_id_A, 42, false, t1)`.
3. `t=2`: Alice rotates her client (uninstalls/reinstalls Warpcast). Client signs `notifications_enabled` again with NEW URL `https://wc.example/n/alice-v2`, NEW token `tok-v2`. Hypersnap upserts.

Attacker (M_A's operator or any captor of the `t=0` envelope) replays the original `t=0` envelope to `/webhook/app_id_A`:

```
upsert(app_id_A, 42, { url: "https://wc.example/n/alice-v1",  // stale
                       token: "tok-v1",                       // stale, invalid in client
                       enabled: true, updated_at: t_now })
```

`store.rs::upsert` (lines 62-95) unconditionally overwrites the primary record and the URL-grouping index. The `updated_at` field is the server's `current_unix_secs()`, not anything from the signed payload, so the store has **no signal that this is stale data**. Alice's current `tok-v2` registration is now replaced by the stale `tok-v1` pointing at her old client endpoint.

Subsequent legitimate fan-outs from M_A's developer to `app_id_A` are POSTed to `https://wc.example/n/alice-v1` with `tok-v1`. The client either returns `invalidTokens` (per spec, which hypersnap then *deletes* the record — `sender.rs:140`) or the endpoint is now unreachable. Either way, Alice silently stops receiving M_A's notifications, and the only "fix" requires her to remove + re-add the mini app to her client — which she will not know to do, because no failure surfaces to her.

### Scenario 3 — force-unsubscribe arbitrary user from arbitrary app

Mallory wants to unsubscribe Alice from app_id_C. Mallory captures any old `miniapp_removed` event Alice's client has ever signed for ANY mini app (e.g., from when she removed some other mini app M_X). The signed payload is just:

```json
{ "event": "miniapp_removed" }
```

— with **no app context whatsoever**. Mallory POSTs this exact envelope to `/webhook/app_id_C`. JFS verifies (signature is Alice's, app key still active). `apply` reaches `MiniappEventKind::Removed` arm at `:199` and calls `self.store.delete(app_id_C, 42)`. Alice's subscription to app_id_C is hard-deleted from RocksDB. The legitimate app_id_C operator's notifications to Alice silently stop.

The "force-unsubscribe" primitive is the most attacker-friendly variant of this class because it requires only a single captured `miniapp_removed` envelope to deploy against **every** app Alice subscribes to on hypersnap.

### Scenario 4 — cross-deployment / cross-region replay

Hypersnap is deployed by multiple operators (the file documents itself as a proxy that any operator can run). An envelope signed by Alice for Operator-X's hypersnap can be replayed against Operator-Y's hypersnap. The signed bytes contain no deployment identifier. This compounds Scenarios 1-3 because the captor of an envelope on one deployment can attack any user-app pairing on every other deployment.

## Why the existing checks do not close the gap

| Defense in handler | What it gates | Replay window it leaves open |
|---|---|---|
| `JfsError::SignerNotActive` lookup (jfs.rs:201) | Stale-post-rotation key | Pre-rotation: months/years where Alice's app key is unchanged |
| `app.signer_fid_allowlist` (webhook_handler.rs:113-119) | Cross-FID poisoning (Bob impersonating Alice) | Same-FID cross-app (Mallory → app_id_B with Alice's envelope). Default is empty, so wide open by default. |
| `app_id` URL-path check (`:78-94`) | Routing to a non-existent app | Cross-app within the deployment is still wide open whenever both apps exist (which is the attack precondition anyway) |
| `MiniappEventKind::parse` (`:131`) | Garbage event strings | Doesn't constrain replay — all four legitimate event kinds are weaponizable per the scenarios above |
| `assert_safe_url` SSRF (`:180-184`) | Replay carrying an attacker-injected URL pointed at internal infra | Doesn't help — the replayed URL is Alice's *real* public URL, which passes SSRF cleanly |
| `apply.notifications_enabled requires details` (`:172`) | Empty-detail replay of `notifications_enabled` | Replays carrying valid details remain unconstrained |
| `MAX_BODY_BYTES = 64 KiB` (`:30, :210`) | Body-cap DoS | Unrelated to replay |
| 32-byte / 64-byte length checks in jfs.rs | Malformed-sig | Unrelated to replay |
| Active-signer-after-verify ordering | Active-signer-side rate-budget | Unrelated to replay |

There is no replay-protection layer of any kind: no nonce store, no signed timestamp, no body-bound destination, no per-`(fid, app_id)` last-seen-event-hash.

## Why the spec rationale does not protect hypersnap

Read the Farcaster Mini App spec linked at `mod.rs:30`: clients POST events to the mini app's **own** declared webhook URL. That URL is per-mini-app, controlled by the mini app's own infrastructure, and isn't proxied through a multi-tenant operator. Under that deployment model, the implicit "the destination URL identifies the app" binding is provided by the URL itself, even though it is not in the signature — because only the mini app's own server is at that URL.

Hypersnap explicitly inverts this model: it is a multi-tenant proxy where many mini apps share the same domain and differ only by the `<app_id>` path segment. The spec's implicit URL-binding evaporates: hypersnap accepts all incoming events at all `<app_id>` paths, and the JFS layer cannot tell which path the event was meant for. The mod.rs comment at lines 4-7 advertises this exactly:

> Hypersnap acts as a multi-tenant proxy for Farcaster Mini App notifications.

without acknowledging that the spec's signature design assumed a non-proxied deployment. This is the same class of finding as F101's "JFS account-association proof is replayable because chain_id is not bound" — same root cause (a JFS-style envelope used as a bearer authorization with no body-side replay nullifiers), different attack surface (notification token state versus on-chain account binding).

## Compounding factor — store overwrites are unconditional

`NotificationStore::upsert` (store.rs:62-95) does not gate on `updated_at` ordering. It always commits the new record. So a replayed older event with smaller "intended" timestamp will silently overwrite a newer legitimate event — there is no monotonic-timestamp invariant on the store. (The handler writes `updated_at = current_unix_secs()` server-side, not from the signed payload, because the signed payload has no `iat` field — so even adding a monotonic check at the store would require adding a signed timestamp first.)

## Recommended fix

The fix path must extend the wire format to include replay nullifiers AND have hypersnap consume them. Two options, both forward-compatible with the Farcaster JFS schema (which allows arbitrary additional JSON fields in `payload`):

**Option A (minimal — closes intra-deployment cross-app replay):**

Require the JFS payload to include an `app_id` field. Reject any event whose `payload.app_id != <app_id from URL path>`. This is a one-line check in `apply` (or just after JFS verify in `handle`). It does NOT close cross-deployment replay or same-app replay, but it removes the scenario-1 (cross-app phishing) and scenario-3 (force-unsubscribe across apps) primitives in one step. Farcaster client SDKs would need to start emitting `payload.app_id`, but that change is also forward-compatible (older hypersnap deployments ignore the unknown field).

**Option B (full nonce + window — preferred):**

Require the JFS payload to include:

```json
{
  "event": "miniapp_added",
  "app_id": "<the mini app's hypersnap app_id>",
  "nonce": "<32-byte hex>",
  "signed_at": <unix seconds>,
  "notificationDetails": { ... }
}
```

In the handler:

1. Verify the JFS signature as today.
2. Require `payload.app_id == <app_id from URL path>`.
3. Require `abs(now - payload.signed_at) ≤ signed_at_window_secs` (mirror the EIP-712 path's window from app_handler.rs: default 300 s).
4. Look up `payload.nonce` in a per-`(fid)` nonce LRU (same shape as `WebhookAuthVerifier`'s nonce store; capacity 100k, TTL `2 × signed_at_window_secs`). Reject if already seen, insert after successful apply.

This makes every signed envelope single-use against this deployment and bounds the replay window to ±5 minutes. Cross-deployment replay is still unaddressed by Option B alone — for that, also include a `domain` field naming the hypersnap deployment URL (mirroring the F101 fix recommendation), and require it to equal a config-configured `notifications.expected_domain`.

**Option C (interim defense without spec changes):**

Until the wire format can be evolved, gate the receiver with a `(fid, signature)` LRU: hash the JFS envelope bytes (or the `signature` field, which is uniquely tied to one signed message) and require uniqueness across the LRU window. This blocks bit-for-bit envelope replay but does NOT block "different envelope, different signature" cases where Alice's client legitimately signed multiple events that all should remain valid — i.e. this is anti-replay-only, not anti-cross-app. It is a strict subset of Option B's nonce check, useful as a same-day mitigation.

## Cross-references

- **F101** — the EIP-191 (custody) variant of this exact class. Same root cause (`JFS proof is a replayable bearer because the signing input binds no chain/nonce/deadline`), different attack surface (on-chain account association vs. notification registration). The Option-B fix recipe is identical in shape.
- **H156-ruled-out** — confirms `app_handler.rs` (mini app management) has proper EIP-712 + nonce + signed_at + body-bound `requestHash`. The notification webhook is the only ingress in the `notifications/` module that does NOT have this protection — because it deliberately mirrors the Farcaster JFS spec, which was designed for a non-proxied deployment.
- **F030 / F031** — body-cap and rate-limit cross-cuts; they bound the *spam volume* of replay attempts but not the *correctness* of replay acceptance. Even with a perfect per-IP rate limit, one valid replay per minute is enough to maintain a hostile state forever.
- **F138** — proposer-pipeline-strips-signed-fields finding is structurally adjacent: in both, an authentication-bearing piece of context (signed field set / app_id) is conceptually outside the signed bytes. Here the missing field never existed at all; in F138 the field existed but was stripped.

## Affected attack-class checklist items

- `untrusted-input-ingress` (primary): a publicly-POSTable endpoint accepts state-changing writes that mutate per-user notification registration based on a long-lived replayable bearer.
- `eip712-domain-or-replay-binding` (spirit-of, applied to JFS / EIP-191-adjacent envelopes): no chain/nonce/destination binding.
- `sender-spoofing-inside-payload` (variant): the *receiver* (app_id) is taken from outside the signed payload while the *sender* (fid) is inside. Asymmetric trust boundary.

## Tests to add

- **Cross-app replay rejected.** Sign a `miniapp_added` envelope as fid=42; POST to `/webhook/app_id_A` (success); POST the identical bytes to `/webhook/app_id_B` (must fail under fix). Currently passes both.
- **Force-unsubscribe via captured `miniapp_removed` rejected.** Sign once for app_id_X, replay to app_id_Y, assert app_id_Y has no record change. Currently the record is deleted.
- **Same-envelope replay rejected.** POST identical bytes twice to `/webhook/app_id_A` within the LRU window; second must fail (under Option B/C). Currently both succeed.
- **Stale-`signed_at` rejected.** Build a payload with `signed_at = now - 1h`; assert 400 (under Option B).
- **Cross-deployment replay rejected.** Build a payload with a `domain` mismatch; assert 400 (under Option B + domain binding).
- **Active-signer rotation between sign and replay.** Sign at t=0 with key K_1; later remove K_1 from on-chain KeyRegistry; replay the t=0 envelope at t=1. Today this is the only natural defense, and it relies on Alice noticing she needs to rotate (which she will not — app key rotation is a privileged maintenance event Farcaster users do rarely). Assert that the replay is rejected solely by the active-signer check at t=1 — confirming the "Option B is required because we can't rely on rotation as a defense" claim.
