---
finding_id: F015
title: The inbound-burn view is never reconciled
severity: medium
status: pending-validation
related_findings:
- F021
---
# F015 — The inbound-burn view is never reconciled. A burn that ≥1/3 of validators lack is re-proposed forever and fails every round its holders lead. OP burns are persisted at the unsafe head −64 and are never re-checked.

- **Severity:** Medium (shard-0 liveness and bridge integrity. Needs a divergence of validator views or an Optimism unsafe-head reorg deeper than 64 blocks. No attacker can cause it alone.)
- **Category:** consensus-liveness / proposer-validator-divergence / bridge-finality
- **Specialist:** shard0-ledger-state · attack class: inbound-burn-double-credit-or-loss, proposer-validator-divergence · task H011
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## How a burn becomes a credit (code facts)

1. **Watcher.** Each validator's `bridge_burn_watcher::run` polls `eth_blockNumber` (the
   *latest*, unsafe head), scans only up to `head - finality_confirmations` (64, not
   configurable from `BridgeWatcherConfig`) (`bridge_burn_watcher.rs:162-196`), and writes each
   decoded `Burned` log to its node-local `BridgeBurnStore`. The store is written once. It is
   never re-validated against the chain, and entries are never removed: `remove` has no
   non-test caller.
2. **Proposer.** `pending_inbound_burns()` returns every stored burn that is older than
   `BURN_PROPOSAL_DELAY_SECS = 30` s and not yet processed (`watchers.rs:283-302`). The proposer
   puts all of them into each proposal (`proposer.rs:186`). In `Mode::Propose` it does not check
   the burn against any view. It only drops a burn when `apply_system` fails, for example when
   the FID is unregistered or the chain is paused (`engine.rs:788-797`).
3. **Validator.** For each `InboundBurn` in a proposal, `inbound_burn_ok` requires the validator's
   *own* store to hold a byte-identical record (`watchers.rs:273-278, 319-321`). Otherwise the
   whole block fails: "system message is not in this node's view" (`engine.rs:772-783`), and the
   result is `Validity::Invalid` (`proposer.rs:83-87`).

Safety therefore rests on: a burn is credited only if validators with ≥2/3 of the weight have
it in their stores. That part is sound. A single proposer, or a <1/3 minority with a lying
RPC, cannot credit a burn that does not exist.

## Problem A: a burn missing from ≥1/3 of the stores is never dropped (liveness)

Nothing reconciles one validator's store with the others'. Suppose a burn B is in the stores of
a set H of validators but not of a set M with >1/3 of the weight. Then:

- every block proposed by a member of H contains B (step 2) and gets <2/3 of the prevotes, so
  each round that H leads times out;
- no proposer ever stops including B, because it stays in H's stores forever and is "pending"
  until processed;
- B is never credited.

If the views split so that **every** validator holds some burn that >1/3 of the others lack,
then no proposal can pass and shard 0 halts. For example, two RPC providers each recorded a
different version of the same `burnId` after a reorg. The store key is `(chain, burnId)`, and
`is_final` compares recipient, amount, block and tx hash, so the two versions conflict.

Ways a persistent difference can arise. None of them heals on its own: the watermark has
already passed the block, and a restart re-scans only `REORG_GUARD = 32` blocks below it.

- **A validator with no bridge watcher.** `bridge_watchers` is optional and empty by default
  (`hypersnap_main.rs:84,144`). With none configured, `burns = None` and `inbound_burn_ok`
  returns `false` for every burn (`watchers.rs:319-321`). With an entry whose `rpc_url` is
  empty, the watcher logs `info` and exits, and its store stays empty. No startup check stops a
  voting validator from running without a watcher. If such validators hold >1/3 of the weight,
  no burn is ever credited, and every proposal from a validator *with* a watcher fails.
- **An RPC that returned incomplete `eth_getLogs`** for one range. The watcher treats an empty
  result as success and advances the watermark (`:183-196`).
- **Different `contract_address` / `source_chain_id` / `deployment_block` settings.** These are
  node-local, not consensus or release constants. `release_constants_hash` covers
  `DEFAULT_FINALITY_CONFIRMATIONS` but no bridge address (`pivot.rs:60-80`). One example: a
  validator that joins later and sets `deployment_block` to a recent block lacks older burns that
  are still pending for unregistered FIDs. When such an FID registers, the old validators
  propose the burn and the new ones reject it.
- **A source-chain reorg after persistence** (Problem B).

## Problem B: OP burns are final at unsafe head −64 (128 s), and a credit is never reversed

On OP mainnet, 64 blocks are 128 s of the **unsafe** head. Blocks become *safe* only after their
batch is derived from L1, and *finalized* only after that L1 block finalizes (roughly 15-20 min).
The watcher never uses `BlockNumberOrTag::Safe` or `Finalized`. If the unsafe chain reorgs deeper
than 64 blocks, for example because the sequencer's batches are not included or derive
differently:

- **Phantom credit.** Validators that recorded B persist it, and B is credited once ≥2/3 have
  it. B's burn transaction is no longer canonical, so the user still holds the wrapped tokens,
  and shard 0 has minted `amount` with no backing (`Meta::BridgedIn` rises). Nothing reverses an
  inbound credit.
- **Stuck credit for the replacement burn.** After the reorg, a different burn reuses the same
  `burnId`. Validators that recorded the old version never re-scan that range. If the
  replacement is credited first, the old version can never apply ("burn already processed").
  The legitimate post-reorg burner loses funds unless ≥2/3 of the validators hold the new
  version.

The spec matches the code here. FIP §13.6 and §13.8 set 64 blocks, and the §13.7 table calls
"64 blocks on Optimism" conservative. That rationale counts blocks. OP's actual guarantee is
L1-derivation based, and an unsafe-head reorg is not bounded by a block count. For chain 1
(Ethereum L1), 64 blocks (12.8 min, about 2 epochs) is close to finality, so this part applies
to the OP watcher.

## Red-team walk

1. *"Tendermint tolerates bad proposers; rounds just rotate."* True for a <1/3 minority of bad
   proposers. Here the honest proposers are the ones that fail, because they honestly hold a burn
   that >1/3 of the others lack. With a two-way split, every proposer fails.
2. *"The 30 s delay covers watcher lag."* It covers transient lag only. All the triggers above
   are permanent: the watermark has advanced past them.
3. *"Operators must configure watchers."* The code treats the watcher as optional, with no
   startup check and only an `info` log. The FIP (§17.6, §13.6) says every validator watches. The
   node should enforce that on a voting validator.
4. *"OP reorgs >128 s don't happen."* They are rare. But the bound OP actually guarantees is
   `safe`/`finalized`, not a block count, and the cost of being wrong (an unbacked mint, with no
   reversal) is high. Hence Medium and not Low.
5. *"A single proposer can credit a fake burn."* No. Each validator checks its own view and 2/3
   is needed. Ruled out.
6. *"A rogue contract emitting the same event."* The `getLogs` filter is on the configured
   address. A rogue contract matters only if ≥2/3 of the validators misconfigure to it. That is
   the trust assumption, not a bug.
7. *"Validators who disagree could manually delete the store entry."* No tooling or endpoint
   does this, and deleting it on the H side would be needed on every H member.
8. *Trust assumptions stated:* ≥2/3 honest weight; RPCs honest but possibly
   inconsistent/incomplete; sequencer honest-but-faulty for Problem B.

## Recommendation

- Scan to `BlockNumberOrTag::Finalized` (or at least `Safe`) on OP-stack chains instead of
  `latest − N`, or make the depth per chain and a consensus/release parameter.
- Make the bridge contract address(es), chain ids and deployment blocks release constants (in
  `release_constants_hash`), not node config. Refuse to vote as a validator without a running
  watcher for each.
- Give the proposer a fallback. Do not include a burn that failed to gather a quorum in the last
  K rounds or heights. Track which burns were in rejected proposals and back off. Order burns
  so that one stuck burn does not poison all proposals, for example one burn per block,
  re-chosen after a failure.
- Periodically re-verify unprocessed store entries against the chain, using the receipt by
  `source_tx_hash` at a finalized block, and drop the ones that disappeared. Re-scan when the
  canonical block hash at a stored `source_block_number` changes.

## Evidence

- `src/chain/bridge_burn_watcher.rs:162-196` (head − 64, watermark advance), `:286-294` (record)
- `src/chain/bridge_burn_store.rs:88-98` (`remove`, test-only caller at `:277`)
- `src/chain/watchers.rs:242, 265-302, 319-332`
- `src/chain/shard0/engine.rs:363-373, 759-797`; `src/chain/shard0/proposer.rs:72-89, 181-188`
- `src/node/hypersnap_main.rs:84, 114-124, 386-410`; `src/chain/pivot.rs:60-80`
- FIP §13.6, §13.7 ("Reorg on the source chain"), §13.8
