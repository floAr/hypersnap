---
finding_id: F059
title: The FIP §8.1 post-transfer filter is not applied anywhere on the production PoQ path
severity: medium
status: pending-validation
related_findings:
- F056
- F046
- F048
- F051
- F053
---
# F059 — The FIP §8.1 post-transfer filter is not applied anywhere on the production PoQ path. The crate's reader contract says "the implementation applies the filter; the crate trusts it". But the production reader (`src/chain/poq_reader.rs`, used through `HypersnapReader`) returns the lifetime follow graph, lifetime engagement counts, lifetime cast counts and lifetime reply counts, with no timestamp check. So a bought or transferred FID keeps the previous custodian's followers (EigenTrust mass), engagers (eligibility F1-F6), interaction partners and growth crediters. Only the age-factor reset is left, and it fades out over 180 days. A related bug: the new-user split puts every pre-transfer event in `first_30d` permanently. One self-transfer therefore turns a FID's whole engagement history into "new-user" engagement for its counterparties, which feeds the code's composite new-user factor.

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: owner from spec-rule walk 2026-11-04

- **Severity:** Medium, source-only. This mis-allocates the Growth pool (20% of each epoch's emission) and the eligibility gate, every epoch. It defeats the FIP's stated defence against account sales (§2 "Defenses", §6.6 "Custody change or account sale", §8.7 "Custody agreement in all inputs"). It is not High because the age factor still scales the bought FID's own trust and credibility to about 0 at transfer, and it takes 180 days to reach full value. The reclassification lever (item B) needs aged FIDs that the attacker controls and one Optimism transfer each. Its size depends on the mainnet distribution of `real_new_user_share`, which is unmeasured.
- **Confidence:** 0.9 that the filter is absent on the production path (every reader method was checked and none reads a timestamp against `effective_ts` except the 30-day split). 0.5 on the size of item B.
- **Category:** spec divergence / custody-agreement bypass (PoQ inputs)
- **Specialist:** spec-to-code compliance walk (PoQ + emission), 2026-11-04
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced.** `src/chain/poq_reader.rs`, `src/chain/scoring.rs` and `crates/proof-of-quality/**` do not exist at merge-base `bdef7b7`.
- **PoC:** None, reasoned from source and not built. Test sketch: in a `PoqReader` over a temp DB, merge a follow `j → i` and a like `j → cast of i`, both with timestamp `T`. Set `with_effective_ts_overrides({i: T + 1000})`, which stands for a transfer of `i` after the events. Expected by FIP §8.1 / §8.2.2: `followees(j)` lacks `i` and `engagement_from(j)` has no entry for `i`. Actual: both are present, and the like is counted as `first_30d`.

## Spec rules

- §8.1: "PoQ uses casts, replies, mentions, reactions, and follows. It filters each event when it uses the event: an event with timestamp ts between FIDs (a, b) counts only if `ts > max(a.effective_ts, b.effective_ts)`. For a one-sided metric (for example, the cast count of an FID), only the `effective_ts` of that FID applies."
- §8.2.2: "A follow edge `j → i` contributes only if its `followed_at` is post-transfer for `j` and for `i`." `out_degree_post_transfer(j)`.
- §6.1: `count(a → b)` "is the number of post-transfer events … The timestamp must be post-transfer for `a` and for `b`".
- §8.3: F1 "Post-transfer cast count", F2 "… post-transfer", the calibration cohort "total post-transfer casts" and "days with one or more post-transfer casts".
- §6.6: "Custody change or account sale: the post-transfer filter removes events from before the transfer. … The growth of the old custodian does not move with the FID."
- §8.7: "No input contains activity of a previous custodian."

## Code facts

1. **The crate delegates the filter to the reader.** `crates/proof-of-quality/src/reader.rs:12-19`: "Every engagement / follow input is post-transfer … The implementation applies the filter; the crate trusts it." The trait docs repeat this for `followees` (`:65-69`), `engagement_from` (`:71-76`), `total_casts` (`:78-79`), `active_days` (`:81-83`) and `replies_received` (`:85-88`). The crate uses `effective_ts` only for the age factor (`metrics.rs:233-234`) and the composite's real-new-user window (`metrics.rs:340-344`).
2. **The production reader applies no filter.** `HypersnapReader` (`src/chain/scoring.rs:157-186`) forwards every social read to `PoqReader`.
   - `followees` (`src/chain/poq_reader.rs:325-356`) returns every `LinkAdd` follow target. It never reads `data.timestamp`. The crate's `out_degree` is the count of all follows (`crates/proof-of-quality/src/scoring.rs:71-83`).
   - `engagement_from` (`poq_reader.rs:360-424`) counts every like, recast and reply. `bump` (`:365-372`) only splits by `ts_unix <= source_eff + 30d`. Nothing drops `ts <= max(source_eff, target_eff)`, and the target's `effective_ts` is never read.
   - `total_casts` and `active_days` (`:426-432`, scan at `:120-165`) count every `CastAdd` of the FID.
   - `replies_received` (`:447-489`) counts every `CastsByParent` key under the FID, with no timestamp. Its own module doc (`:23-25`) still says it is "currently 0".
3. **The retro tool did apply it.** `src/bin/retro_rewards_finalize.rs:65-74, 1594-1759` filters with `ts > max(u.effective_ts, f.effective_ts)`. So the authors meant the rule, and only the consensus reader lost it. (Per F051 the retro tool is not on the production path.)
4. **Pre-transfer events become "new-user" events for good.** In `bump`, `source_eff > 0 && ts_unix <= cutoff` puts every event before `effective_ts + 30 days` into `first_30d` (`poq_reader.rs:362-369`). That includes the whole pre-transfer history. `build_metrics` copies these into `outbound_first_30d` (`metrics.rs:293-299`). `apply_new_user_share` (`metrics.rs:331-380`) then counts them:
   - as F5 "new-user" engagement if the engager's trust is below 0.0001;
   - as `real_new_user_share` (the composite's `(share + 0.001)^½` factor, `scoring.rs:350-372`) if the engager's trust is ≥ 0.0001 and its `effective_ts` is within 90 days of now.
5. **Transfers do move `effective_ts`.** An Optimism `Transfer` sets `last_custody_change` (`src/chain/shard0/registry.rs:188-205`, `src/chain/pivot.rs:263-269`), and `HypersnapReader::new` installs these clocks as `effective_ts` overrides (`src/chain/scoring.rs:51-71`). A self-transfer is a valid transfer (FIP §2 "Defenses" accepts that it resets age).

## Impact

A. **Account sale keeps the graph.** The buyer of an established FID `f` gets:
   - all of `f`'s inbound follows, so its EigenTrust raw mass;
   - all of `f`'s engagers and casts, so F1-F6 pass at once (eligibility also drives the vouch evaluation, `boundary.rs:76-118`);
   - all of `f`'s reciprocal pairs, so its growth crediters.

   `trust_fp = min(1, raw/norm) × age_factor` (`scoring.rs:136-143`) and the age term of credibility start at 0 after the transfer. Because the composite raises credibility to the 4th power and trust to the ½ (F056), the bought FID earns little at first. It then rises linearly to the full pre-sale level over 180 days (36 epochs), and it keeps that level after. Under the FIP, the buyer starts with an empty post-transfer graph and must rebuild it. The same holds on the crediter side: after its age ramps, a bought FID credits others with the previous owner's relationships. The FIP lists this exact attack ("Buy an old FID", §2; "account sale", §6.6) as defended.

B. **Self-transfer lever on `real_new_user_share`.** The attacker controls aged FIDs `A_1..A_k` that have engaged heavily with a target `T` over time. Each `A_i` self-transfers once (one Optimism tx). From then on all of `A_i`'s past events into `T` are `first_30d`. `A_i` keeps its raw EigenTrust mass (item A), so its trust passes 0.0001 once `ratio × age_days/180 ≥ 0.0001`: about 2 days for `ratio = 0.01`. For the next 90 days those events count as "real new-user" engagement into `T`. `T`'s composite factor goes from `√0.001 ≈ 0.032` (share 0) toward `√(share + 0.001)`: about 0.5 at share 0.25, a ~16× multiplier on `T`'s Growth-pool weight. The attacker can repeat this every 90 days. The cost is the `A_i`'s own age reset. While `A_i`'s trust is still below 0.0001, the same events count as F5 new-user engagement instead, which can push honest counterparties toward failing F5. F056 item 2's trust escape mostly masks that. *Size not measured:* it depends on the honest mainnet distribution of `real_new_user_share`.

C. **Secondary.** `interaction_entropy` (credibility, 0.20 weight) and `engager_entropy` (F3, composite symmetry) are computed from lifetime, pre-transfer partners (`metrics.rs:283-292, 301-316`).

## Related spec divergences (Low, same functions, not filed separately)

- §6.1 / §8.3 F2 list mentions (and §6.1 follows) as engagement events. `engagement_from` counts likes, recasts and replies only. The module doc (`poq_reader.rs:17-20`) calls mention-only engagement a TODO.
- §8.3 F6 `replies_received`: the code counts every reply key under the FID, including the FID's own self-replies and replies from FIDs outside the universe (`poq_reader.rs:447-489`). The trait doc (`reader.rs:85-88`) says "casts with one or more replies". Self-reply threads lift F6.
- Time base (AMBIGUOUS spec): §8.1 says "timestamp", and the only timestamp on these events is the user-signed Farcaster `data.timestamp`, not a block time. A future filter should say which one it uses.

## Red-team

1. *Does another layer filter?* No. `HypersnapReader` adds only the clock overrides (`scoring.rs:51-71`). `score_fids` → `build_metrics` → `follow_graph` (`crates/proof-of-quality/src/scoring.rs:472-487, 490-513`) uses reader output as is. I searched `src/` and `crates/` for `post.transfer`. The only implementations are in the retro tool and in doc comments.
2. *Does the store layer drop old messages on transfer?* No. Outside of API, indexing and webhook code, the only places that match `IdRegisterEventType::Transfer` are the age clock (`pivot.rs:265`, `registry.rs:189`) and token escrow (`ledger::custody_change`). No store deletes an FID's social messages on a transfer.
3. *Is the age factor enough?* Not by the FIP's terms. §8.1 and §8.7 require custody agreement in every input as well as the age reset. Item A shows the graph comes back in full after 180 days.
4. *Is this the same as F056?* No. F056 lists formula and constant divergences in the crate. This is a missing input filter in the node's reader, and item B is a separate misclassification bug.
5. *Is F048 the same?* No. F048 is a migration vs Optimism-transfer race. This finding is about what PoQ counts after any transfer.
6. *Is the composite factor in item B in scope, given the FIP doesn't define it?* It is the code's consensus rule (F056 item 4). The lever comes from the missing lower bound, which breaks even the code's own stated intent (`reader.rs:29-33`: `first_30d` is a subset of post-transfer events).
7. *Exempt recoveries?* `EXEMPT_RECOVERIES` keeps the old `effective_ts` for listed recovery transfers (`pivot.rs:265-268`). The mainnet list is empty today (`src/chain/data/exempt_recoveries_mainnet.txt`), so it doesn't change this finding.

## Fix

- Have `PoqReader` take the `effective_ts` map for the whole universe (it already gets overrides) and filter each event by `ts > max(eff(a), eff(b))`:
  - follows: link `data.timestamp` against both ends;
  - reactions and replies: against the actor and the parent-cast author;
  - casts and active days: against the author;
  - `replies_received`: replier and author, excluding self-replies.
- In `bump`, only classify an event as `first_30d` if `source_eff < ts ≤ source_eff + 30d`. Drop events at or before `source_eff`.
- Add a production-reader test that transfers an FID and checks that its trust, eligibility and growth inputs reset.
- Note the OP Mainnet migration timestamps that the retro tool flags (`retro_rewards_finalize.rs:1021-1022, 1124-1127`). A filter keyed on `registered_at` must not drop legitimate history for those FIDs. Base it on custody changes only, or treat registration as no lower bound.

## Files

- `src/chain/poq_reader.rs:11-25, 120-165, 325-489`
- `src/chain/scoring.rs:43-81, 157-186`
- `crates/proof-of-quality/src/reader.rs:12-33, 56-88`
- `crates/proof-of-quality/src/metrics.rs:222-320, 331-380`
- `crates/proof-of-quality/src/scoring.rs:52-111, 136-160, 220-280, 350-372, 472-513`
- `src/chain/shard0/registry.rs:188-205`, `src/chain/pivot.rs:246-282`
- `src/bin/retro_rewards_finalize.rs:65-74, 1594-1759` (the alternative reader that does filter)
- `docs/spec/FIP-proof-of-work-tokenization.md` §2, §6.1, §6.6, §8.1, §8.2.2, §8.3, §8.7
