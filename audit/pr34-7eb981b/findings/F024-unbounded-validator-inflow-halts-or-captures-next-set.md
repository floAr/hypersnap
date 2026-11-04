---
finding_id: F024
title: Unbounded validator inflow in one epoch halts shard 0 or captures its next validator set
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.75
poc:
  path: poc/F024
  kind: build-backed
  result: 6/6
related_findings:
- F025
- F026
- F029
---
# F024 — Nothing limits how many validators can join in one epoch. Seats cost no stake, and one FID gets up to 3. A burst of registrations in epoch N whose validators never sign makes up 1/3 or more of `set(N+2)`, and that halts every shard at the epoch N+2 boundary. Nothing in the protocol can recover from it. With more than 2/3, the attacker controls the chain and the bridge.

> **Status (2026-11-04):** Severity **High** (validated 0.75, HAS_CAVEATS). PoC: poc/F024 (build-backed, 6/6). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity High (validated), **shard 0 only**: data shards continue under set(N+1). Bridge capture is not reachable at 7eb981b; it is a requirement on V2. PoC: poc/F024 (6/6; 1 FID × 3 seats halts a 4-member set, 3 FIDs × 9 seats capture shard 0).


- **Severity:** High (permanent, network-wide liveness loss with no in-protocol recovery. The attacker needs about `n_honest / 6` FIDs, each 90+ days old with trust ≥ 0.05). It would be Critical if the trust gate turns out to be easy to pass at scale, because the >2/3 capture then mints on the EVM bridge. It would be Medium if the bootstrap and honest set are large (hundreds) **and** the trust gate is strong. The trust assumptions are below.
- **Category:** epoch-set-handoff-gap / validator-set Sybil weight (missing churn limit, seat-per-FID multiplier)
- **Specialist:** pivot-genesis-epoch · attack class: epoch-set-handoff-gap · task H015
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Code facts

1. **The only per-seat costs are signatures plus an FID gate.** `register` (`src/chain/shard0/validators.rs:143-248`) checks these: account-key role, `registration_epoch == ctx.epoch`, a consensus-key PoP, a node-key PoP, an attestation of the node key by the same FID, `effective_age >= 90 d`, and `trust_score >= min_validator_trust_fp` (50,000 = 0.05; `src/chain/shard0/mod.rs:130-134`). It has no stake: FIP §12 says "A validator slot does not have a token cost … `STAKE_TYPE_VALIDATOR` is reserved and has no effect."
2. **One FID gets up to `MAX_NODES_PER_FID` = 3 seats.** Each seat needs a distinct attested node key (`validators.rs:204-208`). An FID may hold 3 attestations (`validators.rs:62-64`, `mod.rs:126`). Nothing limits validators per FID. Every member has weight 1 (`members_at`, `validators.rs:126-137`).
3. **No limit on joins per epoch or on set size.** `join_epoch = ctx.epoch + 2` (`validators.rs:229`). `write_set_record(e+1)` at the boundary of `e` takes every record with `is_member(v, e+1)` (`boundary.rs:33`, `validators.rs:333-341`). The code has no `MAX_VALIDATORS`, no churn cap and no probation weight. Grep finds only `MIN_VALIDATORS` and a crawler-only `MAX_VALIDATORS_QUERIED`.
4. **A joiner never has to show it is live.** The `JOINING` alert (`src/chain/transitions.rs:26-36`) is informational only. A seat has full weight from the first block of `N+2`, whether or not the key has ever signed anything.
5. **The only removal mechanism needs committed blocks.** Auto-deregistration counts missed proposals from the parent certificate of committed shard-0 blocks (`record_participation`/`record_proposals`, `validators.rs:345-393`, called from `engine.rs:345,386`). Even when it fires, it takes effect at `epoch + 2`. Voluntary deregistration needs the attacker's key. The engine has no fallback to a previous set when `set(e)` cannot reach quorum (no hits for `epoch_set` fallback in `src/chain`, `src/consensus`, `src/node`).
6. **The bridge accepts the poisoned set.** `set(N+2)`'s root goes into the `EpochBoundaryRecord` at the first block of `N+1` (`boundary.rs:33-41`), and the **honest** `set(N+1)` certifies it. `advanceEpoch` on the EVM side therefore installs `setRoot[N+2]` legitimately (FIP §13.4).

## Attack

Let `n_h` be the number of honest members of `set(N+2)` and `A` the attacker's seats. With weight 1 each, quorum needs `3·signers > 2·(n_h + A)`.

- **Halt:** if the attacker's seats never sign, honest signers reach quorum only when `n_h > 2A`. So `A ≥ n_h / 2` halts the chain. That needs `K = ceil(n_h / 6)` qualifying FIDs (3 seats each). Examples:
  - bootstrap of 3 (spec minimum): 1 FID (2 seats).
  - `n_h` = 20: 4 FIDs.
  - `n_h` = 100: 17 FIDs.
- **Capture:** `A > 2·n_h` gives the attacker its own quorum. With `n_h` = 20 that is 41 seats, or 14 FIDs.

Steps:
1. Before epoch N, get `K` FIDs with effective age ≥ 90 days and trust ≥ 0.05, migrated to Falcon custody. They can be the attacker's own reputable accounts or bought ones. Post 3 `NODE_ATTESTATION`s per FID. Attestations take effect at once, and posting them in epoch N also works.
2. In epoch N, post `3K` `VALIDATOR_REGISTER` messages. To deny honest parties time to respond in-protocol, post them in the last blocks of N. A counter-registration made after the boundary joins at N+3, too late. One inclusion by any proposer is enough. A message that passes `register` is valid, so honest validators cannot reject the block that carries it.
3. At the boundary of N+1, `set(N+2)` (with the attacker seats) is written and certified by the honest `set(N+1)`.
4. At the first block of N+2, the attacker's seats do not sign. No shard-0 block of epoch N+2 can get a certificate. Shards 1 and 2 also use `set(N+2)` once `epoch_ref_height` reaches N+2. With no blocks there are no auto-deregistrations, and the set cannot change. **The chain stops permanently.** Restarting needs an off-chain coordinated fork that edits the registry or the set.
5. With capture (`A > 2·n_h`), the attacker certifies any header from epoch N+2 on. Examples are a fake `bridge_lock_root` passed through `advanceRoot` (mint on the EVM bridge), a forged boundary record that installs its own `set(N+3)`, and censorship of all deregistrations.

Below the halt line (`A` slightly under `n_h/2`), the same seats still add a propose-timeout for every slot they hold until auto-deregistration removes them. F025 shows that they can cancel that removal indefinitely.

## Red-team (invalidation hypotheses walked)

1. *Is the trust gate a strong Sybil barrier?* Partly. EigenTrust from the seed cohort is meant to push sock-puppet rings to the noise floor (FIP §8), so making new sybils is hard. But the halt needs only `n_h/6` **real** reputable FIDs, which a single well-connected actor or a small group may already own or can buy. One FID alone triples its weight. The severity depends on this; see the rating line.
2. *Are 3 seats per FID really possible?* Yes. Registration enforces node-key uniqueness and consensus-key uniqueness only. Each seat has its own attested node key, and attestations are capped at 3 per FID. Nothing caps validators per FID.
3. *Can honest validators counter by registering more seats?* Only in the same epoch N, and only with their own qualifying FIDs. A burst in the last blocks of N leaves no time. Registrations in N+1 join at N+3.
4. *Can honest proposers censor the registrations?* Only as off-protocol policy. Every proposer must include them for this to work, and validators cannot reject a block that carries a valid registration. The attacker needs a single inclusion.
5. *Does Malachite or the engine fall back to the old set?* No. `epoch_set(e)` is read for the certificate's epoch, and nothing falls back to the previous set.
6. *Is this spec-intended?* The spec chose "no token cost" (§12) and weight 1 (§4.9). It also assumes `f < n/3` (§4.7) but has no rule that keeps a single epoch's inflow below `n/3`. The halt with no recovery is therefore not a stated tradeoff. It is a gap in both spec and code.
7. *Do the seats have to run a node?* No. They need keys and signatures only. The `JOINING` state carries no requirement.
8. *Is this already filed?* No. F004 covers the EVM side accepting retired sets. F008/F009 cover vote watermark and spam. H003 confirmed only that `MIN_VALIDATORS` keeps the set non-empty. This finding is about too many seats, not too few.

## Recommendations

- Cap the inflow: joins at epoch `e` must stay well below `1/3` of `set(e)`, for example `≤ floor((|set(e-1)|-1)/3) / 2`, with extra registrations queued FIFO to later epochs. Optionally add a `MAX_VALIDATORS`.
- Weight seats per FID, or limit validators per FID to 1, so the FID-level credibility gate actually maps to consensus weight.
- Add probation: a joiner gets weight 0 (or does not count toward `total_weight`) until it has signed a certificate or a ShardReady-style liveness attestation. An alternative is an in-epoch exclusion rule: if no shard-0 block commits for `X` rounds at an epoch boundary, fall back to `set(e-1)` minus joiners.
- Spec: state the inflow bound in §4.4/§4.5, and state in §4.7 what restores liveness when `≥ 1/3` of a new set is absent.
