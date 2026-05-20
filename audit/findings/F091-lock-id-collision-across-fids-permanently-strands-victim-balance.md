---
id: F091
task: H091
specialist: solidity-bridge
attack_class: bridge-claim-replay-or-leaf-collision
file_paths:
  - code/hypersnap/src/hyper/token_lock.rs
  - code/hypersnap/src/hyper/rewards.rs
  - code/hypersnap/src/hyper/lock_tree.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/contracts/src/HypersnapBridge.sol
  - code/hypersnap/crates/hypersnap-bridge-ceremony/src/main.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: high
status: draft
---

# F091 — Cross-FID `lock_id` collision lets any attacker permanently strand a victim's bridge-locked balance

- **Attack class:** `bridge-claim-replay-or-leaf-collision`
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\token_lock.rs` (live EVM-bridge leaf encoder + signer-auth gate) plus the storage-side replay-protection in `rewards.rs::apply_lock`.
- **Severity (provisional):** **High** — direct, permanent loss-of-funds-to-bridge for the victim (their L2 balance is debited; the L1 wrapped-token mint that would have made them whole is *permanently* blocked by `claimed[lockId] = true`). Not a steal-to-attacker, but a **burn-the-victim's-balance** attack costing the attacker only ~1 atom + one TokenLockBody.
- **Direct fund loss to attacker?** No.
- **Direct fund loss / freeze for victim?** Yes — the victim's L2 balance is permanently transferred into the unclaimable `TokenLockState`, and no governance path can unwind it on L1.

## Summary

`HypersnapBridge.claim` keys its replay-nullifier (`mapping(bytes32 => bool) public claimed`) on `lockId` alone (`HypersnapBridge.sol:100, 186, 217`). The L2 side, however, treats `lock_id` as **per-`sender_fid`**: `RewardStore::apply_lock` checks duplicate `lock_id` only against the same FID (`rewards.rs:306` — `lock_state(sender_fid, &state.lock_id)`), and the storage key is the concatenation `RootPrefix::HyperTokenLocked || fid_be || lock_id` (`rewards.rs:209-215`). The Rust authors documented this asymmetry as an intentional design choice in `rewards.rs:1036-1058`:

> "Same lock_id on distinct FIDs is allowed — the storage key includes both. **The bridge contract treats lock_id as globally unique, but enforcement of that is up to the user generating the IDs.**"

`lock_id` is a user-supplied 32-byte field on `TokenLockBody` (`token_lock.rs:78-99`, `validate_token_lock` only checks `len == 32`); it is propagated network-wide via the gossip layer in clear. An attacker who observes a victim's `TokenLockBody` extracts `lock_id`, signs their own `TokenLockBody` with the **same `lock_id`** but a **distinct `sender_fid` (their own)**, their own `destination_address`, and `amount = 1`. Both bodies pass `apply_token_lock` (different FIDs → no per-FID collision). Both `TokenLockState`s land in `RewardStore`. The runtime tree builder (`build_lock_merkle_tree` → `iter_all_locks` → `lock_tree::build_lock_tree`) includes **both** leaves; the validator set threshold-signs the resulting root. The attacker submits `claim` first; the contract sets `claimed[lock_id] = true` and mints to the attacker's address (amount = 1). The victim's later `claim` call reverts with `AlreadyClaimed(lockId)` (`HypersnapBridge.sol:186`). The victim's L2 balance was debited at lock time; the wrapped-token mint that would have made them whole on L1 is now **unreachable**.

## Description

### The two-side mismatch

**L1 side (`contracts/src/HypersnapBridge.sol:100, 173-220`)**

```solidity
mapping(bytes32 => bool) public claimed;
...
function claim(... bytes32 lockId, address recipient, uint256 amount, uint32 destinationChainId, bytes32[] calldata merkleProof) external whenNotPaused {
    ...
    if (claimed[lockId]) revert AlreadyClaimed(lockId);
    ...
    bytes32 leaf = keccak256(abi.encodePacked(
        DOMAIN_LOCK_LEAF, lockId, bytes1(FAMILY_EVM),
        bytes4(destinationChainId), bytes20(recipient), bytes32(amount)
    ));
    if (!MerkleProof.verifyCalldata(merkleProof, latestRoot, leaf)) revert BadMerkleProof();
    claimed[lockId] = true;
    _mint(recipient, amount);
}
```

`claimed` is keyed **only on `lockId`**, not on `(lockId, recipient, amount, destinationChainId)` or the leaf hash. First successful claim "burns" `lockId` globally.

**L2 side (`code/hypersnap/src/hyper/rewards.rs:269-335`)**

```rust
pub fn apply_lock(&self, sender_fid: u64, amount: u64, nonce: u64, state: &TokenLockState) -> Result<(), RewardError> {
    ...
    if self.lock_state(sender_fid, &state.lock_id)?.is_some() {     // ← per-FID, not global
        return Err(RewardError::LockIdCollision { fid: sender_fid, ... });
    }
    ...
    batch.put(Self::lock_key(sender_fid, &state.lock_id), state_bytes);  // key = prefix || fid || lock_id
    ...
}
```

`lock_id` collision is checked against the same FID only. The storage key embeds `sender_fid`, so two FIDs with the same `lock_id` coexist in distinct DB rows.

This is **affirmed by an in-source test** (`rewards.rs:1036-1058`) that exercises and pins the cross-FID-coexistence behavior. The accompanying doc-comment punts global uniqueness to "the user generating the IDs" — but no user-side enforcement exists.

### Leaves both land in the tree

`apply_token_lock` (`runtime.rs:720-747`) is the only authenticated entry point that creates `TokenLockState` from a `TokenLockBody`. It does NOT cross-check the lock_id against other FIDs:

```rust
pub fn apply_token_lock(&mut self, body: &proto::TokenLockBody) -> Result<(), RewardError> {
    validate_token_lock(body)?;             // structural + Ed25519
    let active = get_active_key(...)?;       // signer-set auth
    if active.is_none() { return Err(SignerNotAuthorized { fid: body.sender_fid }); }
    let state = state_from_body(body);
    self.reward_store.apply_lock(body.sender_fid, body.amount, body.nonce, &state)
}
```

`apply_token_escrow_bridge` (`runtime.rs:3199-3280`) is a second entry that creates `TokenLockState` under the sentinel `sender_fid = 0`. Its dedup is also per-`(fid=0, lock_id)`. **Cross-path collision (escrow-bridge vs. apply_token_lock) is therefore also unprotected.**

The validator-side merkle builder (`runtime.rs:755-766`, `lock_tree.rs:50-62`) walks `RewardStore::iter_all_locks()` (`rewards.rs:222-242`), which returns **every** `TokenLockState` across all FIDs, and turns each into a leaf. Both colliding leaves are present in the signed root.

### The leaf encoder confirms identical leaves on identical (lockId, chain, recipient, amount)

`token_lock.rs::encode_token_lock_leaf` delegates to `hypersnap_crypto::bridge_payload::lock_leaf_evm`:

```rust
keccak256(
    keccak256("HYPERSNAP_LOCK_LEAF_V1")  // 32B domain tag
    || lock_id                            // 32B
    || FAMILY_EVM (= 0x00)                // 1B
    || destination_chain_id (u32 BE)      // 4B
    || recipient                          // 20B
    || amount (u256 BE)                   // 32B
)
```

**`sender_fid` is NOT in the leaf preimage.** Confirmed by the in-source pinned test `leaf_does_not_depend_on_sender_fid` (`token_lock.rs:359-370`). The contract recomputes the leaf the same way (`HypersnapBridge.sol:204-211`). The two encoders are byte-identical — cross-side encoding parity holds (F053 conclusion unchanged), but that parity is precisely what enables this attack: the leaf the attacker injects is a *legitimate* leaf indistinguishable from a victim's leaf at claim time.

### Cross-side asymmetry re-verified

I diffed the Rust `lock_leaf_evm` (`crates/hypersnap-crypto/src/bridge_payload.rs:191-206`) against `HypersnapBridge.sol:204-211` field-by-field — they agree on every byte (domain tag, lock_id, family byte = 0, chain_id width = 4 BE, recipient width = 20, amount width = 32 BE). A pinned cross-side test (`bridge_payload.rs::cross_side_pinned_vectors` line 437-443) asserts the exact leaf hash `0x946e398b...`. **No encoding-asymmetry bug.** The bug is at the *storage/dedup* layer, one level above the encoder.

### Signer-auth gate is correctly enforced

`apply_token_lock` (`runtime.rs:720-742`) chains:
1. `validate_token_lock` — Ed25519 signature over the signing payload (DST + sender_fid + amount + nonce + dest_chain + dest_addr + lock_id + signer_pubkey), with the signer_pubkey itself bound into the payload to prevent rotation-replay.
2. `get_active_key(onchain, db, txn, sender_fid, signer_pubkey)` — must return `Some(_)`; otherwise `SignerNotAuthorized`.
3. `apply_lock` — nonce monotonic, balance sufficient, per-FID lock_id unique.

All three gates fire. The auth path is sound; this finding is **not** about bypassing auth — the attacker **legitimately signs** with their own key from their own FID.

### What does the offline ceremony tool prove?

`crates/hypersnap-bridge-ceremony/src/main.rs:307-320` **does** dedupe `(lock_id, destination_chain_id)` pairs and `bail!`s on collision, with a comment "they'd collide on-chain":

```rust
let mut seen = std::collections::HashSet::new();
for (_, _, parsed, _) in &entries {
    let key = (parsed.lock_id, parsed.destination_chain_id);
    if !seen.insert(key) {
        bail!("duplicate (lock_id, destination_chain_id) pair: {} on chain {}", ...);
    }
}
```

This proves the team **knows** about the collision concern at the on-chain layer. But the ceremony tool is for **manual / offline** root-building from a curated JSON snapshot. The **runtime** root-builder (`runtime.rs::produce_signed_lock_merkle_root_local` → `build_lock_merkle_tree` → `lock_tree::build_lock_tree`) does NOT have this dedup. It just calls `iter_all_locks()` and hashes every state. So the only path enforcing global uniqueness exists, but it is bypassed on the live signing path.

## Impact

### Concrete attack scenario

Assume victim Alice (FID=100, balance=1,000,000 atoms) wants to bridge 500,000 atoms to her EVM address `0xAlice`. Attacker Eve (FID=200, balance ≥ 1 atom) targets Alice.

1. **Alice signs** `TokenLockBody { sender_fid: 100, amount: 500_000, nonce: ..., destination_chain_id: 8453, destination_address: 0xAlice, lock_id: 0xLLLL... }` and submits it via HTTP. The actor `LocalSubmitMessage`s it (`actor.rs:1141-1155`): **applied locally**, **then broadcast to peers**.
2. **Eve observes** the broadcast (any peer on the gossip mesh sees the body — `actor.rs:1714-1744` confirms `Body::TokenLock` is just another gossip message; no encryption / privacy). Eve extracts `lock_id = 0xLLLL...`.
3. **Eve signs** `TokenLockBody { sender_fid: 200, amount: 1, nonce: ..., destination_chain_id: 8453, destination_address: 0xEve, lock_id: 0xLLLL... }` and submits it to any validator (could be the same one Alice used, or a different one). It passes `validate_token_lock` (Eve's own signature, her own active key, distinct FID), passes `apply_lock` (Eve's per-FID lock_id row at `[prefix][200_be][0xLLLL...]` is empty), and persists.
4. **At the next merkle-root posting**, both leaves are in the tree:
   - Alice's leaf: `keccak256(... 0xLLLL... || 0x00 || 8453 || 0xAlice || 500000 ...)` = `L_alice`
   - Eve's leaf:   `keccak256(... 0xLLLL... || 0x00 || 8453 || 0xEve   || 1      ...)` = `L_eve`
   `L_alice ≠ L_eve` (recipient + amount differ). The merkle tree contains both, sorted ascending.
5. **Eve races to L1.** She calls `HypersnapBridge.claim(blockNumber, root, ownerSig, 0xLLLL..., 0xEve, 1, 8453, eve_proof)`. The contract:
   - Verifies the threshold sig over the new root: passes.
   - Checks `claimed[0xLLLL...]`: false. Sets it to **true** after the mint.
   - Recomputes `leaf` from `(lock_id, recipient=0xEve, amount=1, chain=8453)`: equals `L_eve`.
   - Verifies merkle proof against the root: passes (`L_eve` is in the tree).
   - `_mint(0xEve, 1)`. Emits `Claimed(0xLLLL..., 0xEve, 1)`.
6. **Alice calls** `HypersnapBridge.claim(blockNumber, root, ownerSig, 0xLLLL..., 0xAlice, 500000, 8453, alice_proof)`. The contract reverts at line 186: `AlreadyClaimed(0xLLLL...)`.
7. **Alice's 500,000 atoms** remain in `RewardStore`'s `TokenLockState`. There is no on-chain governance path to clear `claimed[0xLLLL...]`; the L1 contract has no admin reset, no per-leaf override, no expiry. There is no L2-side "burn the lock" path that returns Alice's balance — `apply_lock` is the only entry-point that mutates this row, and it only inserts.

**Cost to Eve:** 1 atom of her own balance + one `TokenLockBody` (network fee). **Loss to Alice:** 500,000 atoms, **permanent**.

### Amplification

- **Mass denial.** Eve can scrape the gossip mesh for *every* TokenLockBody and inject a counter-lock for each, for ~1 atom/victim. Cost scales linearly; harm to victims scales by their bridge volume.
- **Reorg / nonce griefing not required.** Eve does not need to control any validator, predict any seed, or front-run at the L1 mempool layer. She only needs:
  - one funded FID (any user has this), and
  - gossip-mesh observation (any peer has this).
- **Pre-image hijack.** Alice's lock_id is *literally* the only thing Eve needs from the network. There is no client-side mechanism to "reserve" a lock_id before signing, and the signing payload binds the lock_id with the rest of the body (so Alice can't randomize it after the fact).
- **Escrow-bridge path also vulnerable.** `apply_token_escrow_bridge` uses sentinel `fid=0`. An attacker with any custody address can grief escrow-bridge users by reusing their announced `lock_id` from the alternate path. Cross-path collision is undetected.
- **Recovery is contract-side only.** Any fix requires either (a) upgrading the L1 contract to make `claimed` key on the leaf hash rather than `lockId`, or (b) coordinated migration that signs a "compensation merkle root" for stranded victims — neither is part of the current design.

### Why this matters more than F062

F062 (empty-root freeze) requires a validator-side bug or signing-key compromise to trigger. F091 requires only that an attacker (a) hold a funded FID, and (b) observe the public gossip mesh. **No validator misbehavior is needed.** Severity should be High.

## Evidence (file:line)

### L1 side — lockId is the sole nullifier key

- `code/hypersnap/contracts/src/HypersnapBridge.sol:100` — `mapping(bytes32 => bool) public claimed;` keyed only on `lockId`.
- `code/hypersnap/contracts/src/HypersnapBridge.sol:186` — `if (claimed[lockId]) revert AlreadyClaimed(lockId);`
- `code/hypersnap/contracts/src/HypersnapBridge.sol:204-211` — leaf preimage; lockId, family, destChainId, recipient, amount only (no FID, no sender identifier).
- `code/hypersnap/contracts/src/HypersnapBridge.sol:217-219` — `claimed[lockId] = true; _mint(recipient, amount);`

### L2 side — per-FID dedup, not global

- `code/hypersnap/src/hyper/rewards.rs:209-215` — `lock_key` = `prefix || fid_be || lock_id`.
- `code/hypersnap/src/hyper/rewards.rs:306-311` — collision check `lock_state(sender_fid, &state.lock_id)` — per-FID only.
- `code/hypersnap/src/hyper/rewards.rs:1036-1058` — pinned test affirming cross-FID coexistence; doc-comment punts to "user generating the IDs".
- `code/hypersnap/src/hyper/runtime.rs:720-747` — `apply_token_lock` does not consult other-FID rows.
- `code/hypersnap/src/hyper/runtime.rs:3232-3242` — escrow-bridge path checks only `lock_state(0, &lock_id)` (sentinel-FID dedup; ignores real-FID rows).

### Leaf encoder doesn't bind sender

- `code/hypersnap/src/hyper/token_lock.rs:110-120` — `encode_token_lock_leaf` calls `lock_leaf_evm(lock_id, dest_chain, recipient, amount)`; sender_fid not included.
- `code/hypersnap/src/hyper/token_lock.rs:359-370` — pinned test `leaf_does_not_depend_on_sender_fid`.
- `code/hypersnap/crates/hypersnap-crypto/src/bridge_payload.rs:191-206` — canonical leaf encoder.

### Tree builder includes all states without dedup

- `code/hypersnap/src/hyper/rewards.rs:222-242` — `iter_all_locks` walks every `TokenLockState` row, no filter.
- `code/hypersnap/src/hyper/lock_tree.rs:50-62` — `build_lock_tree` maps every state to a leaf; only ordering is by leaf hash.
- `code/hypersnap/src/hyper/runtime.rs:755-766, 774-809` — runtime root-building / DKLS-signing has no `(lock_id, chain)` dedup pass.

### Asymmetry: offline tool DOES dedupe, runtime path does NOT

- `code/hypersnap/crates/hypersnap-bridge-ceremony/src/main.rs:307-320` — `(lock_id, destination_chain_id)` HashSet check; bails with comment "they'd collide on-chain". The runtime path is the **opposite** behavior.

### Gossip-side observability of lock_id

- `code/hypersnap/src/hyper/actor.rs:1141-1155` — `LocalSubmitMessage`: apply locally, **then** broadcast.
- `code/hypersnap/src/hyper/actor.rs:1714-1744` — every `Body::TokenLock` is a plain gossip-mesh message kind ("token_lock"); no encryption/sealing.

### User-supplied lock_id has no entropy / non-collision constraint

- `code/hypersnap/src/hyper/token_lock.rs:128-167` — `validate_token_lock` only checks `lock_id.len() == 32`. No randomness floor, no derivation rule, no commit-reveal.

## Suggested remediation

A single fix on either side closes the attack. Defence-in-depth requires both.

### L1 side (preferred — closes ALL cross-FID and cross-path collisions, including any future code path that creates colliding states)

Change `claimed` to key on the **leaf hash**, not `lockId`:

```solidity
mapping(bytes32 => bool) public claimedLeaf;
...
if (claimedLeaf[leaf]) revert AlreadyClaimed(leaf);
...
claimedLeaf[leaf] = true;
_mint(recipient, amount);
```

This makes `claimed` precisely as discriminating as the merkle leaf set — two leaves with identical lockId but different (recipient, amount, chain) are nullified independently. The original `lockId`-keyed mapping is retained as a deprecated read for off-chain consumers, or removed in a clean V2 upgrade.

Storage-layout note: requires a UUPS upgrade. The `__gap[44]` budget at `HypersnapBridge.sol:102` accommodates a new mapping slot.

### L2 side — globally-unique lock_id enforcement

Add a global `(lock_id) → Option<sender_fid>` index alongside the existing `(fid, lock_id)` storage, and reject any second insertion at the same `lock_id`. Concrete patch shape:

```rust
// rewards.rs — at top of apply_lock, before per-FID check:
fn lock_id_global_key(lock_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(RootPrefix::HyperTokenLockIdIndex as u8); // new prefix
    k.extend_from_slice(lock_id);
    k
}
...
if self.db.get(&lock_id_global_key(&state.lock_id))?.is_some() {
    return Err(RewardError::LockIdCollision { fid: 0xFFFFFFFFFFFFFFFFu64, lock_id_hex: hex::encode(&state.lock_id) });
}
...
batch.put(lock_id_global_key(&state.lock_id), &sender_fid.to_be_bytes());
```

Same write must be added to `apply_token_escrow_bridge` (`runtime.rs:3245-3273`) so the escrow path participates in the global index.

Migration: the global index is forward-only; existing state would need a one-shot scan to populate. Drop the in-source test `same_lock_id_on_distinct_fids_is_allowed` (`rewards.rs:1041-1058`) and the cross-FID-allowance doc-comment.

### Runtime root-builder dedup (cheap defense-in-depth)

Mirror the ceremony tool's check in `lock_tree::build_lock_tree`:

```rust
let mut seen = std::collections::HashSet::new();
for s in &states {
    let key = (s.lock_id.clone(), s.destination_chain_id);
    if !seen.insert(key) {
        // Drop the duplicate OR abort tree-building OR log+exclude.
        // Aborting halts the bridge but is the safest default.
    }
}
```

This is the smallest possible change; it doesn't fix the on-chain mismatch but at least refuses to sign a root that contains a known collision-pair. Validator operators can then triage off-chain.

## What this finding does NOT claim

- The Rust↔Solidity leaf encoder bytes are equal (re-verified vs. F053; no drift). The bug is at the *uniqueness* layer above the encoder.
- `validate_token_lock`'s Ed25519 + signer-set auth is correctly enforced (runtime.rs:720-742) — re-verified per task request.
- F058's invalidated dead-code path (`HyperLockEvent` / verkle pipeline) remains out of scope. This finding is purely against the **live** `TokenLockBody` → `TokenLockState` → keccak-merkle pipeline.
- No L1-side re-emission / root-rewind needed. The attack uses the standard signed-root flow.
