---
finding_id: F016
title: The inbound-burn identity is `(chain_id, burnId)` without the contract address, and the "known bridge contract address" is node config
severity: low
status: pending-validation
related_findings:
- F014
---
# F016 — The inbound-burn identity is `(chain_id, burnId)` without the contract address, and the "known bridge contract address" is node config. A second bridge contract on a watched chain collides with processed burn IDs, and those burns are lost.

- **Severity:** Low. It needs a second watched deployment or a redeploy on the same chain. The planned V1→V2 path is an in-place proxy upgrade and is not affected.
- **Category:** spec-divergence / loss-of-funds (latent)
- **Specialist:** shard0-ledger-state · attack class: inbound-burn-double-credit-or-loss · task H011
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Finding

- The watcher store key is `[64][source_chain_id][burn_id]` (`bridge_burn_store.rs:45-51`). The
  shard-0 processed-set key is `keys::inbound_burn(source_chain_id, burn_id)`
  (`keys.rs:370`, `ledger.rs:760-763`). Neither includes the emitting contract.
- `burnId = ++burnNonce` counts per contract instance, starting at 1
  (`HypersnapBridge.sol:384`, `HypersnapBridgeV2.sol:325`).
- `contracts/README.md:83-84` says the canonical identifier is
  **`(chainId, contractAddress, burnId)`**. FIP §13.6(a) says the event "must come from the known
  bridge contract address". In the code that address is per-validator config
  (`BridgeWatcherConfig.contract_address`, `hypersnap_main.rs:114-124`). It is not part of the
  consensus params or `release_constants_hash` (`pivot.rs:60-80`).
- `bridge_watchers` is a `Vec`, so two entries can share a `source_chain_id`. They then share one
  store keyspace and one per-chain watermark (`bridge_burn_store.rs:155-160`).

**Consequences when a second contract emits burns on a watched chain** (a redeploy at a new
address, or old and new deployments both watched during a migration):

1. The new contract's `burnId` 1, 2, … equal IDs that are already in
   `HyperInboundBurnProcessed`. `BurnView::pending` filters them out as processed
   (`watchers.rs:288-290`). If one were proposed, `ledger::inbound_burn` would reject it as
   "burn already processed" (`ledger.rs:761-763`). The tokens are burned on the EVM side and
   never credited.
2. With both contracts watched, `record` overwrites one contract's unprocessed burn with the
   other's that has the same ID (`bridge_burn_store.rs:56-66`). Only one of the two can ever be
   credited.
3. The shared watermark makes the second watcher resume from the first watcher's height after a
   restart. It can skip the second contract's range.

**Ruled out (a question raised during the hunt).** V1 and V2 share `burnNonce` in storage slot 2
of the same UUPS proxy (`HypersnapBridgeV2.sol:69, 113, 130`; tested by
`test_burn_atMinimum`/upgrade suites). IDs continue across the upgrade and the emitter address
does not change, so the in-place upgrade causes no collision or double credit. A rogue contract
that emits the same event signature is filtered out by `Filter::address` (`bridge_burn_watcher.rs:207-211`).

## Red-team walk

1. *"There will only ever be one proxy per chain."* The FIP does not say so. A redeploy is the
   only recovery if, for example, the V1 owner key (F005) or an upgrade goes wrong. The README
   already defines the identity with the contract address.
2. *"Validators would configure the same address."* Correct, if they coordinate. The point is
   that the system makes no attempt to make the address a consensus fact.
3. *Double credit?* No path found. The processed set is per `(chain, burnId)` and checked in the
   same `MsgTxn`, so the collision fails closed. Users lose funds; there is no inflation.
4. *Chain id truncation:* `uint32(block.chainid)` is harmless for chains 1 and 10 . The watcher uses its configured chain id and ignores the event's `sourceChainId`
   data field. These match only if the configuration is correct.

## Recommendation

Include the contract address in the processed-set key and the store key (`chain ‖ address ‖
burnId`), or explicitly forbid two watchers per chain and fix the address in release constants.
Align README, FIP §13.6 and `hyper.proto` on one identity. Cross-check the event's
`sourceChainId` and the RPC's `eth_chainId` against the configured chain id at startup.

## Evidence

`src/chain/bridge_burn_store.rs:45-66, 155-160`; `src/chain/shard0/ledger.rs:749-773`;
`src/chain/shard0/keys.rs:370`; `src/chain/watchers.rs:283-302`;
`src/node/hypersnap_main.rs:84, 114-124, 386-410`; `src/chain/pivot.rs:60-80`;
`contracts/README.md:74-86`; `contracts/src/HypersnapBridgeV2.sol:68-69, 113, 130, 317-328`.
