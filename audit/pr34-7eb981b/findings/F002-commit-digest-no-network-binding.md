---
finding_id: F002
title: The commit digest `d` and the lock leaf carry no network identifier, so a certificate made on another Hypersnap network (testnet, devnet
severity: medium
status: pending-validation
related_findings:
- F004
- F005
- F034
---
# F002 — The commit digest `d` and the lock leaf carry no network identifier, so a certificate made on another Hypersnap network (testnet, devnet, shadow fork) is a valid mainnet-bridge certificate when consensus keys are reused

- **Severity:** Medium. The impact is Critical (unlimited mint, permanent takeover of the bridge validator set). It is gated on an operational precondition: more than 2/3 of the mainnet validator weight also signs on another Hypersnap network with the same Falcon consensus keys. The code does nothing to stop that reuse.
- **Category:** cross-side-encoding-asymmetry / missing domain separation; also spec-divergence (the spec defines no network binding for `d`).
- **Specialist:** solidity-bridge · task H002
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Summary

Every V2 trust decision checks one thing: that `set(epoch)` signed
`d = keccak256("hypersnap-commit-v1" || u32 shard || u64 height || u32 round || block_hash)`
(`contracts/src/HypersnapBridgeV2.sol:425-431`, `:458-469`). The node produces the same value
(`src/core/consensus_keys.rs:30-52`, called from `src/core/types.rs:145-151`). Validators sign
it under the Falcon domain `"hypersnap-consensus-vote-v1"` (`crates/hypersnap-falcon/src/domains.rs:209`).
None of these layers identifies the Hypersnap network:

| Layer | Network-bound? | Where |
|---|---|---|
| Falcon vote domain | no, one constant for all networks | `domains.rs:209` |
| Commit digest `d` | no: shard, height, round, block_hash only | `consensus_keys.rs:30-52`, `BridgeV2.sol:425-431` |
| Header (`block_hash = keccak(header)`) | no network field | `proto/definitions/hypersnap.proto:15-31` |
| `set_root` member leaf | no: key hash, weight, node key hash, fid | `src/chain/validator_sets.rs:15-31` |
| Lock ID / lock leaf | no: `keccak("hypersnap-lock-v1"‖fid‖nonce)`, leaf binds EVM chain only | `src/chain/shard0/ledger.rs:527-533`, `bridge_payload.rs:243-258` |
| `ICertificateVerifier` public inputs | no network or bridge identity | `contracts/src/interfaces/ICertificateVerifier.sol:33-40` |

User messages, by contrast, are network-bound: `MessageData.network` is inside the Falcon `MSG`
payload. Consensus votes, which the bridge actually trusts, are not.

On top of that, every network uses the same bridge destination chains:
`Shard0Params::new` sets `bridge_chain_ids: vec![1, 10]` for any `FarcasterNetwork`
(`src/chain/shard0/mod.rs:121-145`; only `retro_minted` and the trust threshold depend on the
network). A testnet or devnet lock to chain 10 therefore produces a leaf that has exactly the
format of a mainnet lock to OP mainnet.

So the bridge on chain 10 accepts any shard-0 header from *any* Hypersnap network, as long as
its precommits are by keys in mainnet `set(e)` with more than 2/3 of mainnet `totalWeight[e]`.
Signer membership is checked against the *mainnet* `setRoot[e]`. The other network's own set
does not matter, only which keys signed.

## Attacker model

- **Attacker:** anyone. The attacker needs no key and no validator role, only the ability to
  relay public data (gossip/RPC of another network) to the mainnet bridge.
- **Precondition:** in some epoch `e`, the keys that hold more than 2/3 of mainnet `set(e)`
  weight also precommit shard-0 blocks of another Hypersnap network (public testnet, devnet,
  or a shadow fork started from mainnet state with the real validator keys). Each validator
  has weight 1 (`src/chain/shard0/validators.rs:132`), so this means more than 2/3 of the
  validators *by count*. Reuse is plausible here:
  - the validator set is small and run by a few operators who are likely to also run testnet;
  - `hypersnap_pivot` derives the consensus key from `--keys/consensus.falcon` without regard to
    `--network` (`src/bin/hypersnap_pivot.rs:257-268`), so the same keys directory works for
    every network;
  - nothing in the node refuses a key that is registered on another network, and no doc says
    reuse is unsafe.
- No validator acts dishonestly. Every signature is an honest precommit on its own network.

## Impact (once the outbound bridge is activated)

1. **Mint without backing.** On the other network the attacker locks an arbitrary amount of free
   testnet tokens to chain 10 and a recipient they control. They wait for a certified shard-0
   header of epoch `e` above mainnet `latestHeight`, call `advanceRoot(testnetHeader, cert)`
   (`BridgeV2.sol:276-282`), then call `claim(lockId, recipient, amount, 10, proof)`
   (`:289-310`). The leaf format, lock ID derivation and chain ID all match. SNAP is minted on
   OP mainnet against no mainnet lock.
2. **Permanent bridge takeover through the handoff.** If the other network's epoch-`e` boundary
   block is certified by the reused keys, `advanceEpoch(testnetHeader, testnetRecord, cert)`
   (`:250-272`) installs the *other network's* `next_set_root` / `next_total_weight` as mainnet
   `setRoot[e+1]`. Only one handoff is possible per epoch (`latestEpoch` advances), so the honest
   mainnet handoff is then rejected with `WrongEpoch`. From then on, whoever controls the
   testnet/devnet set of `e+1` controls every V2 anchor, upgrade and pause, and joining a
   testnet set is cheap (free stake; `min_validator_trust_fp = 0` on devnet). The attacker can
   front-run because the other network's boundary record for `e` may already exist (when that
   network's epochs run ahead) when mainnet `latestEpoch` reaches `e`.
3. **Governance replay.** A header of the other network whose `bridge_action_hash` is
   `bridgeActionHash(ACTION_PAUSE, 0, 0)` or an `ACTION_UPGRADE` with `chainId = 0` ("applies on
   every chain", `:336`) is accepted by `pause` / `proposeUpgrade` on mainnet. Testnet
   governance votes (`src/chain/shard0/bridge_actions.rs:38-91`) are cheap to pass.
4. **Liveness grief (weaker precondition).** Anchoring another network's header with a much
   larger height raises `latestHeight` (`:471-475`). After that, `advanceRoot` refuses every
   real mainnet header (`StaleHeight`) until mainnet passes that height, so claims are stuck on
   a foreign lock root. A colliding lock ID (same `fid`/`nonce` on both networks) claimed through
   the foreign root also marks the real mainnet lock as `claimed`. That mainnet lock then becomes
   unclaimable, which burns the user's funds.

Today the outbound bridge is off on every network (`bridge_outbound_activation_epoch: u64::MAX`,
`mod.rs:144`), so lock roots are zero and impacts 1 and 4 are latent. Impacts 2 and 3 do not
need locks and apply as soon as V2 is live.

## Red-team (invalidation hypotheses walked)

1. *Does the header or block hash bind the network?* No. There is no network field in
   `HypersnapBlockHeader`, and the bridge does not check `parent_hash` or chain continuity, so
   any well-formed shard-0 header works.
2. *Does `set_root` bind the network?* No (`validator_sets.rs:15-31`). The bridge also checks
   membership against the mainnet root, not the foreign root.
3. *Does the Falcon domain differ per network?* No, it is a single registry constant.
4. *Does the CERT-STARK interface take a network input?* No (`ICertificateVerifier.sol:33-40`).
   A verifier that implements the interface as documented accepts the foreign certificate.
5. *Do foreign locks fail the chain-ID check?* No. `bridge_chain_ids = [1, 10]` on every network.
6. *Is reuse really needed by >2/3?* Yes, and that is why this is Medium and not Critical. The
   finding is the missing domain separation, which standard designs include (Cosmos `chain_id`
   in sign bytes, the Ethereum fork-version/genesis root in BLS domains). Hypersnap already
   binds `network` in user messages and in `hypersnap/<network_id>/` gossip topics
   (spec §4.10, line 439).
7. *Is this the spec's intent?* The spec defines neither `d` nor any network binding
   (§16.5–16.6, lines 1635-1720). The CERT-STARK statement's public inputs leave out network
   identity. So the spec has the same gap, and the code follows it.
8. *Can equivocation slashing deter it?* No. There is no double-sign slashing in `src`, and
   cross-network votes would be indistinguishable from mainnet equivocation anyway.

## Proof of concept

This is structural and not executed end-to-end. The CERT-STARK verifier does not exist, and
the OZ libs are not installed in `contracts/lib`. The argument is complete from the code: the
existing `BridgeV2Test._cert` helper (`contracts/test/utils/BridgeV2Test.sol:89-118`) builds a
valid certificate from `(epoch, setRoot, weight, d, bitmap)` alone. Nothing a foreign network
would change (genesis, parent chain, network enum) enters any of those inputs.

## Fix

1. Bind the network into the commit digest on both sides, e.g.
   `d = keccak256("hypersnap-commit-v1" || bytes32 network_id || u32 shard || u64 height || u32 round || block_hash)`.
   Use `network_id = keccak256(PivotRecord)` or the pivot block hash, not only the 1-byte
   `FarcasterNetwork` enum, so that shadow forks are also separated. Store it as an immutable
   in V2 (committed by the v1 owner's upgrade signature, like `SET_ROOT_EPOCH1`). Do the same
   for prevote/nil digests and the MS2 `sid`.
2. Also bind the network into the lock ID (or leaf) and `bridge_action_hash` for defense in depth.
   Make `bridge_chain_ids` network-specific (testnet → OP Sepolia/Sepolia only).
3. Update FIP §16.5/§16.6 to define `d`, including the network binding, and add `network_id` to
   the CERT-STARK statement.
4. Operationally, document that consensus keys must never be reused across networks, and have
   the node refuse to start with a key that carries a different network tag.

## Requirements for the future CERT-STARK verifier

The verifier only sees `d`. It cannot add network binding by itself. It must verify the Falcon
signatures over exactly `"hypersnap-consensus-vote-v1" || d` with `d` treated as an opaque
public input, so that once fix (1) is applied, the network binding carried in `d` cannot be
bypassed. If the fix instead adds a separate `networkId` public input, the verifier must bind it
into the signed message and must not take it from the proof.
