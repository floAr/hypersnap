---
id: H063
specialist: solidity-bridge
attack_class: onchain-event-reorg-finality
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/bridge_burn_watcher.rs
  - code/hypersnap/src/hyper/bridge_burn_store.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/contracts/src/HypersnapBridge.sol
---

# H063 — bridge_burn_watcher reorg / finality / double-credit — ruled out

Hunt scope: `src/hyper/bridge_burn_watcher.rs` decodes untrusted on-chain
`Burned` events into hypersnap credit. Checked: finality wait before
crediting; reorged-out burn still crediting (and not reverted); same event
processed twice (dedup); spoofed event (wrong contract / wrong topic).

## Pipeline (drawn explicitly)

`HypersnapBridge.burn()` emits `Burned(uint256 indexed burnId, address indexed
sender, bytes32 indexed hypersnapRecipient, uint256 amount, uint32
sourceChainId)` with `burnId = ++burnNonce` (monotonic per contract,
`HypersnapBridge.sol:378-385`).

1. Watcher `scan_range` (`bridge_burn_watcher.rs:201-299`) reads logs and
   `record`s a `HyperObservedBurn` into `BridgeBurnStore`, keyed
   `(source_chain_id, burn_id)`.
2. Actor signing flow (`actor.rs:3119` `refresh_inbound_burns` /
   `actor.rs:3173` `start_dkls_inbound_burns_multi_party`) enumerates the
   store, skips already-processed, threshold-signs, and calls
   `runtime.apply_inbound_burn`.
3. `apply_inbound_burn` (`runtime.rs:1292`) verifies the threshold signature,
   then nullifies on `(source_chain_id, burn_id)` at
   `RootPrefix::HyperInboundBurnProcessed` and credits the balance atomically.

## Why each vector is closed

### Finality wait (no premature credit)
`run` only scans up to `finalized_head = head - finality_confirmations`
(`bridge_burn_watcher.rs:174-179`); `next_block > finalized_head` sleeps. A
burn is never persisted (and therefore never credited) until it is
`finality_confirmations` (default 64, FIP §13.8) blocks deep. Reorgs shallower
than the confirmation depth occur entirely above `finalized_head` and so are
never recorded. This matches the recovery_watcher F097 fix.

### Reorged-out-after-credit (residual, accepted by design)
A credited burn can only be reorged out by a reorg deeper than
`finality_confirmations`. The module documents this as a source-chain
consensus failure that is the operator's problem to detect
(`bridge_burn_watcher.rs:10-18`), consistent with OP finality assumptions and
the protocol's stated threat model. No revert path exists, but reaching the
condition requires breaking the chain's finality guarantee — out of scope for a
single-watcher code bug. Documented design assumption, not a defect.

### Double-processing / dedup
Two independent layers:
- Store key is `[prefix][source_chain_id BE][burn_id 32B]`
  (`bridge_burn_store.rs:44-50`); re-recording the same `(chain, burnId)` is an
  idempotent overwrite. The REORG_GUARD=32 restart re-scan
  (`bridge_burn_watcher.rs:148-154`) therefore only re-writes identical keys.
- The permanent nullifier at `HyperInboundBurnProcessed`, checked atomically
  with the balance write in `apply_inbound_burn` (`runtime.rs:1348-1388`) and
  pre-checked at signing-flow enumeration (`actor.rs:3135`, `actor.rs:3194`),
  caps each `(chain, burnId)` at exactly one credit even across watcher
  restart, re-scan, duplicate logs, or a burn re-mined under the same burnId.
  `burnId` is contract-monotonic, so a post-finality canonical burn has a
  single stable id.

### Spoofed event (wrong contract / wrong topic)
The `eth_getLogs` filter binds both `.address(bridge_contract_address)` and
`.event_signature(Burned::SIGNATURE_HASH)` (`bridge_burn_watcher.rs:211-215`),
and the contract address is required to be non-zero (`run` rejects
`Address::ZERO`, `bridge_burn_watcher.rs:138-142`; config layer enforces a
20-byte address, `config.rs:390-402`). A conformant RPC cannot return
foreign-contract or wrong-topic0 logs. Even given a malicious RPC, the credit
additionally requires a valid validator-set threshold signature
(`apply_inbound_burn` verifies before nullifier/credit, `runtime.rs:1332-1344`,
F096), so a single watcher fed bad data cannot unilaterally credit.

### Cross-side decode agreement
Non-indexed data is ABI `(uint256 amount, uint32 sourceChainId)`; watcher reads
`data[..32]` as the amount (`bridge_burn_watcher.rs:264-284`) — correct. The
indexed `hypersnapRecipient` decode requires FID in the front 8 BE bytes with
24 zero trailing bytes and rejects fid==0 (`decode_hypersnap_recipient`,
`:305-318`), with round-trip tests. Amounts above u64::MAX are skipped. No
asymmetry that admits a forged credit.

## Minor (non-finding) observations
- `block_batch == 0` in config would make `next_block + block_batch - 1`
  underflow at `:179`; operator-controlled config only, liveness not
  credit-safety, default is 8000. Not in H063 scope.
- The doc comment (`:38-40`) describes resume as `last + 1 - REORG_GUARD` based
  on the last burn block, while post-F094 the resume is `watermark -
  REORG_GUARD` where `watermark` is the highest scanned finalized block
  (`bridge_burn_store.rs:127-145`). The code path is strictly more
  conservative (re-scans at least as much), so it is safe; only a stale
  comment.

## Conclusion
No reorg/finality/double-credit/spoof defect in the watcher. Finality is
waited before persistence; dedup is enforced by both the store key and a
permanent atomic nullifier; the log filter and downstream threshold-signature
check close spoofing. Ruled out.
