---
finding_id: F047
title: After the pivot, the data-shard fee gate (`replica::charge_fee`) runs after the store merge has written to the block batch
severity: low
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.8
poc:
  path: null
  kind: source-only
  result: null
related_findings:
- F046
---
# F047 — After the pivot, the data-shard fee gate (`replica::charge_fee`) runs after the store merge has written to the block batch. When the fee check fails, `merge_message` returns an error, but the store writes stay in the batch and are committed. Only the trie update is skipped. Casts, links, reactions, user data and verifications from FIDs with no fee balance are therefore stored and served for free, and PoQ, which reads the stores, counts them. The trie and the stores also stop agreeing.

> **Status (2026-11-04):** Severity **Low** (validated 0.8, HAS_CAVEATS). PoC: no path (source-only). State: validated.

> **Status 2026-11-04 (post-validation):** Severity **Low** (validated from Medium). Rescoped: fees are 0 for every non-cast type and for unique casts (F054), so the bug only fires for a near-duplicate CastAdd from a sender without fee balance. It becomes a Medium full fee bypass once F054 is fixed, so fix the two together. The LinkAdd/ReactionAdd and DA examples below do not apply. See the internal validation notes.


- **Category:** msgtxn-partial-write (shard0-ledger-state persona, applied to the data-shard fee path) / checkpoint-input (PoQ reads stores, not the trie)
- **Specialist:** shard0-ledger-state · task H035 (side finding while tracing node-local inputs for H025)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** The fee gate is new; snapchain v0.15 has no fee.
- **PoC:** None. Test sketch: use a post-pivot data-shard engine (`hypersnap_mode`) and an FID with a zero `fee_balance` replica. Replay a block with one `CastAdd` from it. Expect a merge-failure `HubEvent`, an unchanged state root, and yet `CastStore::get_cast_add(fid, hash)` returns the cast after commit.

## Code facts

1. `merge_message` merges into the store first, writing to `txn_batch` (`src/storage/store/engine.rs:2607-2640` and the other types). After that, in `hypersnap_mode`, it calls `replica::charge_fee` and returns `Err(StoreError(..))` if the fee balance does not cover the fee (`engine.rs:2706-2719`). The code comment says so: "It runs after the merge, so a duplicate or invalid message gives its own error".
2. `charge_fee` errors when `balance − unsettled < fee`. Base fees are CastAdd 1.0, Link/ReactionAdd 0.1, UserData/VerificationAdd 0.5 (`src/chain/replica.rs:192-245`).
3. The caller in the replay loop (`engine.rs:2356-2397`) handles `Err` by recording a validation error and committing a merge-failure HubEvent. It does not undo the store writes. There is no savepoint or per-message batch. `update_trie` runs only on `Ok` (`engine.rs:2368-2373`).
4. Data-shard proposals include messages whose merge fails (`shard_blocks.rs:353-386` passes all mempool messages to `hypersnap_propose`). Nothing checks the fee before admission (grep `charge_fee` has one caller).
5. PoQ reads the stores of the data-shard checkpoint: `LinkStore::get_link_adds_by_fid` for followees, cast-add scans for casts, active days and replies (`src/chain/poq_reader.rs:120-170, 325-360, 426-470`).

## Attack path

An attacker controls many sybil FIDs with no fee balance (only storage units are needed, as in snapchain). They post casts, follows and reactions at the normal rate limits. Every message fails `charge_fee`, but each is stored, served by the API, and counted at the next boundary checkpoint. The intended per-message cost (§12) and the uniqueness surcharge (the fingerprint is not even recorded on failure, `engine.rs:2719`) do not apply. For PoQ, follows and engagement among sybils are free. Trust still needs EigenTrust inflow from seeds, which limits the gain. Active days and casts metrics are free to fill.

A side effect: the store and the trie disagree. A failed `LinkAdd` or `ReactionAdd` can replace an earlier remove in the store's CRDT set, while the trie keeps the old message. A DA challenge on that trie leaf can then not be answered by anyone: `challenged_leaf` resolves the value from the stores, the hash mismatches, and it returns `None` (`checkpoints.rs:166-187`).

## Red-team

1. *Does the store merge really write before returning?* Yes. Stores take `txn_batch` by `&mut` and put records directly (snapchain design). The error in step 1 comes after the merge returned `Ok`.
2. *Do validators reject the block?* No. The error is a per-message validation error, as for any failed merge, and the root (trie) is the same on all nodes. That is why this is not a fork.
3. *Maybe the mempool filters zero-balance FIDs?* No fee check outside `merge_message` was found (grep `charge_fee`, `fee_balance` in `src/mempool`, `src/network`: none).
4. *Is storage-unit pruning the real limit?* After the pivot, pruning is disabled (`engine.rs:2376-2380`), so stored unpaid messages accumulate up to the storage-limit check in the store merge.

## Recommendations

- Check the fee before the store merge: compute `charge_fee` on a scratch batch first, or check `balance − unsettled ≥ base_fee × max_multiplier`. Or snapshot the batch length and truncate it on error. A per-message `RocksDbTransactionBatch` merged on success is the cleanest fix.
- Add the test from the PoC sketch, plus a test that a failed message leaves no store record.
