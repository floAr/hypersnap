---
finding_id: F043
title: A custody `KEY_REMOVE` of a migrated FID can never be relayed to snapchain
severity: medium
status: pending-validation
---
# F043 — A custody `KEY_REMOVE` of a migrated FID can never be relayed to snapchain. The code forbids the EIP-712 body signature that FIP §16.10 allows, and the message must be `FALCON512`, which the outbound relay always drops. When custody revokes a signer pair on Hypersnap, its Ed25519 half stays active on snapchain.

- **Severity:** Medium. This is a revocation-propagation failure for the case that matters most: custody revoking a compromised or abandoned app signer, without the signer's cooperation. Hypersnap removes the pair, and the replica `remove_gasless_key` outbox only reaches Hypersnap's own data shards. On snapchain, which most Farcaster clients read, the attacker keeps posting as the user with the Ed25519 half. The snapchain gasless TTL slides on use, so an attacker who keeps using the key keeps it alive. The workaround is a separate classical-custody EIP-712 `KEY_REMOVE` submitted directly to snapchain, which needs the secp256k1 custody key, the key the user migrated away from. Confidence 0.85, source-only.
- **Category:** spec divergence with security impact (role-resolution / revocation propagation; H034 "can revoked keys still act")
- **Specialist:** falcon-pq-message-auth · task H034
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). This is **PR-introduced**: snapchain v0.15 has no migrated FIDs, pairs or relay.
- **PoC:** None. Test sketch: in the relay crate, `outbound_decision(custody_key_remove_falcon_msg, NET, &al)` returns `Drop(FalconOnly)`. In the node, `registry::key_remove` with `signature_type = custody`, scheme `FALCON512` and a 65-byte `body.signature` returns `Err("a custody KEY_REMOVE of a migrated FID has no body signature")`.

## Code facts

1. FIP §16.10, *Signer removal*: "For a migrated FID, a `KEY_REMOVE` by custody must contain a Falcon-512 custody signature in the extension. It can also contain an EIP-712 signature, so that snapchain accepts it after the relay."
2. Code (`src/chain/shard0/registry.rs:580-592`):
   - The custody branch requires `env.scheme == Scheme::Falcon`, so the message can't have an extension or an Ed25519 half.
   - It rejects any non-empty `body.signature`, so no EIP-712 is possible.
   - The Falcon custody signature is the message signature, not an extension field.
3. The relay outbound filter returns `FilterReason::FalconOnly` for `SIGNATURE_SCHEME_FALCON512` (`crates/hypersnap-relay/src/filter.rs:186-189`). `to_ed25519_form` does the same (`:234`). A snapchain custody `KEY_REMOVE` also needs a 65-byte EIP-712 `body.signature` (`filter.rs:204-206`).
4. Hypersnap removes the pair (`registry.rs:620-643`) and sends `remove_gasless_key` only to its own data shard (`:636-641`, applied at `engine.rs:666-690`). Nothing reaches snapchain.
5. By contrast, a pair self-revoke (`DUAL`, `registry.rs:594-610`) is relayed: the rewrite to Ed25519 is accepted as `KEY_REMOVE_BY_SELF`. But self-revoke needs the pair's own keys, and in the compromise case the attacker may hold them while the user doesn't.

## Attack path

1. A user with migrated FID V has a pair (E, F) issued to an app. The app or its keys get compromised.
2. The user revokes it on Hypersnap with the custody key (the intended PQ-safe path). Hypersnap drops E and F.
3. The relay drops the message (`FalconOnly`). On snapchain, E remains V's gasless signer, and the attacker keeps casting, reacting and changing user data as V there. Each use extends E's sliding TTL.
4. Inbound, snapchain-side messages by E for V are rejected by Hypersnap (a migrated FID with an Ed25519 signature), so the two networks diverge silently.

## Red-team

1. *Can the user put the EIP-712 signature somewhere else?* No. The Falcon branch has no extension, and `body.signature` must be empty.
2. *Can the user send a separate snapchain-only `KEY_REMOVE` through Hypersnap?* An Ed25519-scheme or EIP-712 `KEY_REMOVE` for a migrated FID is rejected on shard 0, so the only way is direct submission to snapchain with the secp256k1 custody key. **The strongest reason this might be overstated:** that workaround exists if the user still controls the classical custody address. The FIP explicitly intends one message to cover both networks, and a user who migrated for PQ safety may have retired that key.
3. *Is snapchain integrity in scope?* The relay is part of the PR, and FIP §16.8/§16.10 make relay parity a stated property.
4. *Does the TTL eventually expire E?* Only if E goes unused for the full `ttl` (≤ 90 days). An attacker keeps it alive.

## Recommendations

- Allow the custody `KEY_REMOVE` of a migrated FID to be dual-form, or allow an optional 65-byte EIP-712 `body.signature` (ignored by Hypersnap, kept for snapchain) when `signature_scheme` is `FALCON512`, and have the relay forward such a message in snapchain form. Otherwise document clearly that custody revocation doesn't propagate, and have wallets also submit the classical-custody removal.
- Add a relay test that a custody revocation of a pair produces a snapchain-acceptable message.
