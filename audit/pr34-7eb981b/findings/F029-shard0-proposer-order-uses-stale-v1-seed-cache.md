---
finding_id: F029
title: Shard 0 picks its Malachite proposers with the v1 fallback seed, while the state uses the beacon seed
severity: medium
status: pending-validation
related_findings:
- F024
- F025
---
# F029 — Shard 0 picks its Malachite proposers with the v1 fallback seed, while the state uses the beacon seed. `Shard0Reader` builds `set(e)` before the boundary block of `e` commits, when `epoch_seed(e)` is not stored yet. It then falls back to the v1 formula and caches the result for the whole epoch. From epoch 3 on, the boundary block stores the commit-reveal (v2) seed instead. Long-running nodes, restarted nodes and the in-state participation accounting therefore use different proposer orders for shard 0.

- **Severity:** Medium (liveness and validator-accounting integrity; no funds at direct risk). Two impacts: (a) shard 0 stalls or slows down when 1/3 to 2/3 of the voting weight has restarted inside the same epoch, which a normal rolling upgrade does. (b) From epoch 3 on, auto-deregistration (§4.7/§4.8) never fires for an offline validator, which removes the only in-protocol remedy for validator attrition. Raise it to High if the operator treats (b) as a path to a permanent halt (offline seats build up to ≥ 1/3 with no recovery, as in F024).
- **Category:** epoch-boundary-race / consensus-input divergence (cached pre-boundary state)
- **Specialist:** consensus-malachite-tendermint · attack class: epoch-boundary-race · task H014
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **Trigger:** none adversarial. It happens in every epoch `e ≥ 3` with at least one `SEED_REVEAL`. The node's own `SeedResponder` commits and reveals automatically (`src/node/hypersnap_main.rs:719,961-962`), so this is every epoch in production. A single validator posting one reveal is also enough.
- **PoC:** None. Reasoned from source; the crate was not built. A test should drive `Shard0Proposer::validator_set(boundary_height(3))` on a node whose DB holds a reveal for epoch 3. It should compare `epoch_order` before committing the boundary block, after committing it on the same `Shard0Proposer`, and on a fresh `Shard0Reader` (a restart). The first two match each other (v1, cached). The third differs (v2). The existing beacon test (`shard0/engine_test.rs:2420-2470`) checks only the stored seed and never runs Malachite proposer selection.

## Code facts

1. **The proposer order comes from the seed.** `EpochSet::validator_set` → `SnapchainValidatorSet::new_epoch(validators, self.seed)` sorts by `keccak256(seed || address)` into `epoch_order` (`src/chain/validator_sets.rs:91-106`, `src/core/types.rs:419-435`). Malachite's `select_proposer` uses `epoch_order[(h + r + shard) mod n]` (`src/core/types.rs:672-680`). Malachite drops proposals from anyone other than the expected proposer (`malachite core-consensus/src/handle/proposal.rs:155-167`).
2. **The boundary block stores the beacon seed.** `on_boundary` → `seed::on_boundary` stores `keccak256("hypersnap-epoch-seed-v2" || e || reveals…)` when `e ≥ 3` and any reveal exists. Otherwise it stores the v1 `epoch_seed(e, H_last(e−1))` (`src/chain/shard0/seed.rs:131-146`, `boundary.rs:28-30`).
3. **The reader falls back to v1 before that block commits.** `read_epoch_set` sees no stored seed and computes the **v1** formula from block `boundary_height(e) − 1` (`src/chain/shard0/reader.rs:87-118`). It ignores the reveals in state. The doc comment ("the seed … is known before the boundary block commits") predates the beacon.
4. **The result is cached for the whole epoch and never refreshed.** `Shard0Reader::epoch_set` caches the first `Some` result per epoch and evicts only the lowest epoch key (`reader.rs:40-62`). `Shard0Proposer` has its own reader, built once at startup (`shard0/proposer.rs:98`, `node/hypersnap_node.rs:320`).
5. **The first query falls in the window.** After `Decided(h_b − 1)`, the host calls `get_validator_set(h_b)` → `Shard0Proposer::validator_set` → `reader.epoch_set(e)` (`consensus/malachite/host.rs:309-313`, `shard0/proposer.rs:144-147`). Block `h_b − 1` is committed and `h_b` is not, so the v1 fallback runs and its set is cached.
6. **The state uses the stored seed.** `pre_steps` calls `validators::epoch_set(&txn, cert.epoch)` with the stored v2 seed. `record_participation` → `record_proposals` charges `consecutive_missed` to `set.proposer(0, h, r)` for `r < decided` and resets the proposer of `decided` (`shard0/engine.rs:340-346`, `validators.rs:363-392`). Auto-deregistration needs `auto_deregister_threshold` = 100 consecutive misses (`shard0/mod.rs:135`).
7. **Data shards are not affected.** They use the shared node reader (`hypersnap_node.rs:225,265`). It first asks for `set(e)` only after the local shard 0 has committed `h_b`, because a data block's epoch comes from its parent's `epoch_ref_height` ≤ the local tip, and `decide` waits for shard 0. So it reads the stored v2 seed, which matches `FeeSettlement`'s in-state proposer check (`engine.rs:379-386`, `views.rs:104-110`).

## Consequences

**(a) Restart split on shard 0.** A node that has run across `h_b` uses the cached v1 order for all of epoch `e`. A node that (re)starts after `h_b` committed (crash, upgrade, or restore from a snapshot past `h_b`) reads the stored v2 seed and uses the v2 order. Each group ignores the other group's proposals as coming from a non-proposer.
- If neither group has more than 2/3 of the weight (restarted weight between 1/3 and 2/3), a round decides only at a slot `k` where `order_v1[k] == order_v2[k]` and that validator is online. Two independent permutations share no such slot with probability ≈ 1/e ≈ 37%. In that case shard 0 cannot decide any height until more nodes restart. Otherwise each height needs up to `n` rounds with growing timeouts.
- The split heals once more than 2/3 of the weight is on one order (the rollout finishes or everyone restarts). It also heals at the next boundary, where every running node caches v1 again.
- While restarted weight is below 1/3, restarted nodes act as offline on shard 0 and reduce its fault margin. They still follow through commit certificates.
- A rolling upgrade spread over part of an epoch (36,000 shard-0 blocks) passes through the dead zone, so normal operations stall the shard that carries the outbox, fee settlements, scoring and bridge roots.

**(b) Auto-deregistration is disabled.** Running nodes choose shard-0 proposers by v1, but the state charges and credits them by v2. Take an offline validator X:
- On data shards (v2, correct), X gets `+1` for each of its round-0 slots, about 2 per `n` heights.
- On shard 0, `decided` is usually 0, because the actual v1 round-0 proposer is usually online. The state then *credits* the v2 slot-0 validator for the height, which is X once every `n` shard-0 heights, and resets X's counter to 0.
- X's counter therefore stays in single digits and never reaches 100. Offline seats are never removed.
- The flip side: honest validators whose v2 slot precedes a decided round > 0 are charged for misses they did not make. Their own proposals reset these charges often, so wrongful removal is unlikely.
- This removes the mechanism that F024 and F025 rely on as the recovery path. Offline seats build up across epochs. At ≥ 1/3 the chain halts with no in-protocol fix.

**(c) The beacon gives shard 0 no protection.** On running nodes, shard-0 proposer order in every epoch is the grindable v1 seed (one grinding point at the last block of `e−1`), which the beacon was added to remove. Data shards use the beacon order. This matches the spec text (FIP §4.9 defines only v1, and §18 item 6 lists the beacon as a possible future fix). However, the code's beacon (`hypersnap-epoch-seed-v2`, `SEED_COMMIT`/`SEED_REVEAL`, DA-reward forfeits) is itself an undocumented spec divergence. See the leads.

## Red-team (invalidation hypotheses walked)

1. *Is `set(e)` really queried before `h_b` commits?* Yes. The host fetches the next height's set right after `decide` returns (`host.rs:309-313`), and the boundary block's own round needs `set(e)` to pick its proposer. `ConsensusReady` and the `StartHeight` restarts query it the same way.
2. *Is anything stored before commit that the reader would see?* No. `read_epoch_set` uses `BlockState::new(db)` over committed data. Proposal or validate execution of `h_b` is not committed, and the fallback's own `txn.put` is never applied.
3. *Does anything invalidate the cache?* No. No code path clears `sets` (grep `sets.lock` hits only `epoch_set`). Eviction removes the lowest epoch only, so the current epoch stays.
4. *Are reveals actually present?* Yes. The `SeedResponder` is wired into the production node loop and commits and reveals every epoch. Its test asserts that the v2 seed is stored for epoch 3.
5. *Could all nodes agree anyway?* Only if none of them restarts after `h_b` of any epoch ≥ 3. Then (a) does not occur, but (b) and (c) always do.
6. *Do data shards hit the same split?* No, as shown in fact 7. A data shard's first query for `set(e)` follows the local commit of `h_b`. A future change that adds an early query (for example a set prefetch) would spread the problem.
7. *Is (b) blocked by data-shard misses outpacing shard-0 resets?* Only if data shards produced about 50× more heights than shard 0 between X's shard-0 slots. The block times are the same (`block::BLOCK_TIME`), so no.
8. *Already filed?* No. F024 and F025 cover set inflow and re-registration. No finding covers seed or proposer-order consistency.

## Recommendations

- Make `read_epoch_set` compute the seed the way `seed::on_boundary` does: read the `SEED_REVEAL` records of `e` from committed state, which the reveal margin fixes before `h_b − 1`. Better, factor out one `compute_epoch_seed(txn, e, parent_hash)` that both functions call.
- Do not cache a set that was built from a fallback seed, or check it against the stored seed after `h_b` commits and replace it.
- Add a test that runs a beacon epoch through `Shard0Proposer::validator_set` before and after the boundary commit and on a fresh reader, and asserts the three `epoch_order`s are equal. Also assert that `record_participation` charges the proposer Malachite actually selected.
- Spec: either add the commit-reveal beacon to §4.9, with its seed formula, reveal margin, forfeits and the rule that all three shards use it from the boundary block, or remove it.
