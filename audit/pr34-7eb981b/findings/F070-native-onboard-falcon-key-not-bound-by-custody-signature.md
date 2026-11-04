---
finding_id: F070
title: The custody signature of `NATIVE_ONBOARD` does not cover `falcon_custody_key` or `falcon_recovery_key`
severity: medium
status: pending-validation
related_findings:
- F064
- F065
- F071
- F072
---
# F070 — The custody signature of `NATIVE_ONBOARD` does not cover `falcon_custody_key` or `falcon_recovery_key`. Anyone who sees a pending onboarding can copy its custody signature, PoW and anchor, put in their own Falcon-512 key, and sign the copy with that key. Both versions pass the mempool precheck and block execution. The first to land creates the FID, and if it is the attacker's copy, the attacker's Falcon key becomes the FID's custody. The victim's custody address is then permanently tied to an FID the attacker controls.

- **Severity:** Medium, source-only. Any pending native onboarding can be hijacked by any gossip peer, or deterministically by the next shard-0 proposer. The attacker gets a native FID without paying the 2^30 PoW. The victim loses the PoW and can never onboard that custody address again. `custody_index[A]` points to the hijacked FID, and `native_fid_key(F) = A`, so anything that resolves "the native FID of address A" resolves to an account the attacker controls (impersonation). No tokens are lost, because the new FID is empty. Not High: a victim can recover by onboarding a new address with a new PoW, and the race needs a gossip win unless the attacker is the proposer.
- **Confidence:** 0.8. The binding gap is certain from source. Winning the race is reasoned, not measured. Not built.
- **Category:** unbound authorization / front-running (SIGNATURE_SCHEME_NONE + Falcon onboarding)
- **Specialist:** rust-crypto-primitives · task H053
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/shard0/onboarding.rs` does not exist at merge base `bdef7b7`.
- **PoC:** None. Engine-test sketch, next to `native_onboarding_by_pow_and_by_stake` (`src/chain/shard0/engine_test.rs:1108`): build `m = onboard_message(&net, &user, Pow(pow), Some(&falcon(32)))`. Decode its body, set `falcon_custody_key = falcon_public(&falcon(99))`, and re-wrap it with `falcon_message(&falcon(99), d)`. Keep `custody_signature` unchanged, since the attacker never holds `user`. Expected: `net.run(net.proposal(vec![forged]))` accepts it, `custody(FIRST_NATIVE_FID).falcon_custody_key == falcon_public(&falcon(99))`, and the honest `m` is then rejected with "the custody address already has a native FID". Also call `precheck::fid0_dedupe_key(&forged, …)` and expect `Ok(Some(b"onboard:" ‖ A))`, the same key as `m`.

## Code facts

1. **The EIP-712 struct has four fields.** `HyperNativeOnboard{custody, anchor_block_height, anchor_block_hash, gate_commitment}` (`src/chain/shard0/onboarding.rs:129-159`). It has no Falcon key, recovery key, nonce or message hash. The gate commitment covers only the PoW nonce and difficulty, or the stake-lock tuple (`:76-91`). The PoW hash covers only `(custody, anchor_hash, nonce)` (`:93-100`).
2. **The Falcon key proves possession only of itself.** With a `falcon_custody_key`, the message must be `SIGNATURE_SCHEME_FALCON512`, signed by that key (`:236-241`, `auth::Envelope::verify_falcon`, `auth.rs:84-93`). The person who chooses the key signs the envelope, and the custody signature never binds that choice. Without a key, the message is `SIGNATURE_SCHEME_NONE` (`:235`).
3. **Precheck accepts the substituted message.** The custody signature is recovered over the 4-field prehash and compared with `custody_address` (`:283-292`). The mempool dedupe key is `"onboard:" ‖ custody` (`precheck.rs:66-71`), so the honest copy and the forged copy collide. The first one admitted wins and the other gets `duplicate` (`src/mempool/mempool.rs:731-742`).
4. **Execution writes the attacker's key as custody.** `onboard` re-runs the precheck, then checks the anchor window, the stake binding and the custody index (`onboarding.rs:296-335`). It issues the FID and stores `FidCustodyRecord{falcon_custody_key: body.falcon_custody_key, falcon_recovery_key: body.falcon_recovery_key, …}` (`:356-367`). `falcon_recovery_key` is not even checked to be a Falcon key or different from the custody key. `custody_migration` checks both (`registry.rs:246-253`).
5. **The victim cannot take it back.** The FID now has a custody record, so `NATIVE_CUSTODY_ROTATION` is refused ("a migrated FID rotates with CUSTODY_ROTATION", `onboarding.rs:387-389`), and `CUSTODY_MIGRATION` is refused ("FID is already migrated", `registry.rs:254-256`). `CUSTODY_ROTATION` and recovery need the attacker's Falcon keys. `custody_index[A]` is set (`:343`), so A can never onboard again (`:333-335`).
6. **The comparable path does bind the key.** `CUSTODY_MIGRATION`'s EIP-712 signature is over `second_signature_payload` with only `eip712_signature` cleared (`crates/hypersnap-messages/src/second.rs:28-32`). That payload includes `falcon_custody_key` and `falcon_recovery_key`. Onboarding uses a hand-built 4-field struct instead.
7. **The unsigned variant is also open.** If the victim onboards with `SIGNATURE_SCHEME_NONE` (no Falcon key), the attacker can *add* a Falcon key (fact 2). This turns the victim's classical native FID into a migrated one that the attacker controls.

## Attack

1. Victim V submits `NATIVE_ONBOARD{custody A, sigA, anchor, pow, falcon K_V}` (or no key) to node N. N admits it and gossips it (`check_fid0` runs on RPC and gossip, `precheck.rs:1-4`).
2. Attacker X, a gossip peer, builds `NATIVE_ONBOARD{custody A, sigA, anchor, pow, falcon K_X, recovery R_X}`, signs it with K_X, and floods it. Nodes that admit X's copy first reject V's as a duplicate. A shard-0 proposer that sees both, or a Byzantine proposer that builds X's copy itself, includes X's copy. Validation re-runs only `apply_message`, and that accepts it.
3. FID F is issued with custody K_X. V's message then fails "the custody address already has a native FID".
4. X repeats this for every native onboarding it sees. It harvests FIDs without doing PoW (F064 multiplies this further).

## Red-team

1. *Does the envelope Falcon signature stop it?* No. X signs with its own key, which is the key the body names (fact 2).
2. *Does the PoW bind the key?* No. It binds `(custody, anchor_hash, nonce)` (fact 1).
3. *Is the anchor or gate commitment unique per message?* Unique per custody and anchor, not per key. X reuses them as they are.
4. *Can V re-submit after losing?* Only from a new address, with new PoW (fact 5).
5. *Is the race unrealistic?* Mempool admission is first-come per key, with no fee priority. Gossip is a race, but a proposer wins deterministically. With F023-style proposer freedom, one Byzantine proposer per rotation suffices.
6. *Is this F064 (replay after rotation)?* No. F064 replays V's own message after V's own rotation. This one substitutes a key into another user's pending message. The fixes differ: F064 needs a consumed-gate marker, and this one needs the key bound into the signature.
7. *Is the FIP silent, so it's "by design"?* The proto comment says the Falcon signature is the key's proof of possession (`hypersnap_bodies.proto:228-239`). PoP is not authorization by the custody holder. The migration path (fact 6) shows that the intended rule is that the custody key authorizes the new Falcon key.
8. *Is there funds loss?* No. The FID is new and empty. Severity reflects that.

## Fix

- Add `falcon_custody_key_hash` and `falcon_recovery_key_hash` (keccak, or `bytes32(0)` when absent) to the `HyperNativeOnboard` EIP-712 struct. Alternatively, sign `second_signature_payload` with `custody_signature` cleared, the same way `CUSTODY_MIGRATION` does.
- Validate `falcon_recovery_key` the way `custody_migration` does: it must be a valid key and different from the custody key.
- Add a test: substituting the Falcon key into an honest onboarding is rejected at precheck.

## Files

- `src/chain/shard0/onboarding.rs:76-100, 129-159, 224-292, 296-367, 387-389`
- `src/chain/shard0/precheck.rs:66-71`; `src/mempool/mempool.rs:717-744`
- `src/chain/shard0/registry.rs:233-256`; `crates/hypersnap-messages/src/second.rs:18-32`
- `proto/definitions/hypersnap_bodies.proto:228-239`
- `src/chain/shard0/engine_test.rs:1040-1133`
