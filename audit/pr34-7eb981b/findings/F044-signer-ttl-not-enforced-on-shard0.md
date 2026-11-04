---
finding_id: F044
title: Shard 0 never enforces a signer's `ttl`
severity: low
status: pending-validation
---
# F044 — Shard 0 never enforces a signer's `ttl`. An expired Falcon-512 signer or signer pair (`FalconSignerRecord.ttl`, required to be 1 s to 90 days) keeps the `AppSigner` role on shard 0 forever, while shards 1 and 2 reject it. On V23 networks, expired gasless Ed25519 keys also keep signing shard-0 verifications, which the snapchain block shard rejected before the pivot.

- **Severity:** Low. Shard-0 `AppSigner` powers are limited:
  - node attestation and revocation (which also bump the account nonce, so they can grief pending account-key operations),
  - miniapp register, unregister, update, add and remove,
  - app usage receipts (PoQ input),
  - verifications on V23 networks,
  - `FEE_DEPOSIT` for non-migrated FIDs.

  None of these moves tokens. A user who relied on expiry instead of revocation leaves a dormant key usable for these actions. Confidence 0.85, source-only.
- **Category:** role-resolution-bypass (revoked or expired key still acts)
- **Specialist:** falcon-pq-message-auth · task H034
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** The gasless sub-case is a regression against snapchain v0.15's block-engine rule.
- **PoC:** None. Test sketch: add a Falcon signer with `ttl = 1` and the `MiniappAdd` (or `NodeAttestation`) scope. Apply a message with that scope at `added_at_time + 10`. Shard 0 accepts it, while `replica::check_signer` on shard 1 returns `"the signer expired"`.

## Code facts

1. `registry::key_add` stores `ttl` (validated to `1..=MAX_KEY_TTL_SECONDS`) and `added_at_time` for Falcon signers and pairs (`src/chain/shard0/registry.rs:403-413, 434-460`).
2. Shards 1 and 2 enforce the sliding TTL: `last_use + ttl < block_timestamp` gives `"the signer expired"` (`src/chain/replica.rs:143-151`). The last use is a shard-local key (`HyperFalconSignerLastUse`, `replica.rs:55-61`) that shard 0 never reads or writes.
3. `auth::resolve` checks pair binding, scopes and the signature only (`src/chain/shard0/auth.rs:293-310, 330-336`). It never checks `ttl`.
4. For the Ed25519 gasless case, `resolve` checks `active.admits` only (`auth.rs:270-283`). Snapchain's block engine enforced `check_and_bump_last_used_at` for shard-0 verifications (`src/storage/store/block_engine.rs:1199-1213`). After the pivot, Hypersnap shard 0 handles verifications itself when V23 is active (`src/chain/shard0/engine.rs:457-473`, `verifications.rs:116-119`), and data shards reject direct verifications under V23 (`engine.rs:3074-3083`). So the gasless TTL isn't enforced for verifications at all on those networks. V23 is devnet-only at 7eb981b.
5. FIP §16.10 lists `ttl` in `FalconSignerRecord` but doesn't define shard-0 semantics. The code comment at `replica.rs:146-147` calls it "the snapchain sliding TTL (FIP §16.10)".

## Red-team

1. *Maybe TTL is meant to be data-shard only?* Nothing says so, and an asymmetric expiry is surprising for a security property. **The strongest reason this is minor:** none of the shard-0 `AppSigner` actions moves value, and a cautious user revokes rather than waits for expiry.
2. *Could shard 0 compute the sliding window?* Not with today's data: last-use lives on the data shards. A fixed expiry (`added_at_time + ttl`, unless refreshed by a shard-0 use) or replicating last-use is needed.
3. *Scopes limit the damage?* Yes. Falcon signers must list explicit scopes (`validate_falcon_signer_scopes` rejects empty scopes, `src/core/validations/key.rs:378-380`). Only keys that were scoped for shard-0 types are affected.

## Recommendations

- Enforce expiry in `auth::resolve` for Falcon signers and pairs. Either track a shard-0 last-use key (bumped on each shard-0 use and read together with the replica-reported last use), or document a fixed expiry.
- For gasless Ed25519 keys in the shard-0 verification path, call `check_and_bump_last_used_at` as `block_engine.rs` does.
