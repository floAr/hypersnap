---
finding_id: F054
title: The §12 fee discount is `max(trust, uniqueness)`, and every message class other than `CastAdd` gets `uniqueness = 1.0`
severity: low
status: pending-validation
related_findings:
- F047
- F052
- F053
- F055
---
# F054 — The §12 fee discount is `max(trust, uniqueness)`, and every message class other than `CastAdd` gets `uniqueness = 1.0`. So `LinkAdd`, `ReactionAdd`, `UserDataAdd` and `VerificationAdd` always cost 0, for every sender, and their base fees (0.1 / 0.1 / 0.5 / 0.5 tokens) are dead code. For `CastAdd`, a near-duplicate counts only if it shares all 64 top bits of the SimHash. Appending one random token moves a copy into a new bucket, so a zero-trust spammer pays 0 for casts too. The fee schedule doesn't price spam or sybil graph-building.

- **Severity:** Low, source-only (economic/design). No funds are lost. But FIP §12 says fee revenue is the long-run sustainability path, and the anti-spam role of fees is gone. It also makes the sybil inputs of F053 and F055 (reactions, follows) free.
- **Confidence:** 0.9 for the non-cast part (pure arithmetic). 0.7 for the cast evasion: the bucket evasion is clear from the code, but its success rate per mutation is estimated, not measured.
- **Category:** fee-discount bypass / anti-spam ineffective
- **Specialist:** chain-economics · task H027
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `src/chain/replica.rs`, `src/chain/fingerprint_store.rs` and `crates/proof-of-quality/src/{fees,uniqueness}.rs` are new. The non-cast part also follows the in-repo FIP §12 text literally, so it is a spec-level flaw that the code inherits.
- **PoC:** None, reasoned from source and not built. One-line check: `compute_effective_fee_micro(BASE_FEE_REACTION_ADD, 0, UNIQUENESS_ENC_FULL) == 0` (this is the `fees.rs` arithmetic: `discount = max(0, 10000) = 10000`, multiplier 0).

## Code facts

1. **Non-cast uniqueness is full.** `charge_fee`: `let uniqueness = if t == MessageType::CastAdd { fingerprint ... } else { UNIQUENESS_ENC_FULL }` (`src/chain/replica.rs:225-232`). `UNIQUENESS_ENC_FULL = 10_000` (`crates/proof-of-quality/src/fees.rs:31-33`).
2. **The discount takes the max, so the fee is 0.** `discount = trust_enc.min(10000).max(uniqueness_enc.min(10000))` and `fee = base · (10000 − discount) / 10000` (`fees.rs:65-78`). With uniqueness 10000, the fee is 0 for any trust. `charge_fee` then returns before reading the balance (`replica.rs:233-236`).
3. **So the base-fee table is unreachable for four of the five classes.** `base_fee`: `LinkAdd | ReactionAdd => 100_000`, `UserDataAdd | VerificationAddEthAddress => 500_000` (`replica.rs:192-198`, mirrored in `fees.rs:22-26`).
4. **Cast near-dup lookup is one exact-bucket scan.** `uniqueness_score` scans only the bucket `[87][simhash_high u64]` (`src/chain/fingerprint_store.rs:147-155`) and counts entries with Hamming distance ≤ 6 (`:186`). The module doc says this targets "the exact-content-repost case" (`fingerprint_store.rs:13-17`). A near-duplicate whose top 64 bits differ in even one bit is never seen.
5. **A new user pays 0 for unique content.** Uniqueness 10000 with 0 near-duplicates (`uniqueness.rs:86-89`). The FIP intends this ("A new user who posts fully unique content also pays no fee").

## Attack path

1. A zero-trust FID (for example a 30-bit-hashcash native onboarding) sends any number of likes, recasts, follows, user-data and verification messages. Each one is charged 0, and after the pivot stores no longer prune (`src/storage/store/engine.rs:472`).
2. For casts, it appends a random suffix (or changes a few characters) to each copy. The 3-gram SimHash moves bits across all 128 positions, so the top-64-bit bucket almost always changes, near_dup_count = 0, and the fee is 0.
3. Result: the only cost is block space. The fee gate never stops spam, and the reaction/follow volume that feeds PoQ (F053 interaction entropy, F055 first-30-day edges) is free.

## Red-team

1. *Is the zero non-cast fee intended?* The FIP §12 text gives the same formula and the same "uniqueness 1.0" rule, so it is literally per spec. But §12 also has a base-fee table with non-zero LinkAdd/ReactionAdd fees, and both describe fees as the sustainability path. The two can't both be intended. Severity is Low because the code matches the text.
2. *Does storage or rate limiting replace the fee?* After the pivot "every FID behaves as Pro" and the stores keep every message (`storage/store/engine.rs:472, 2961`). The mempool rate limiter is off by default.
3. *Does trust gating stop sybils anyway?* For Growth, yes (crediter floor). For App PoW (F053) and scoring cost (F055), it doesn't.
4. *Is the cast bucket evasion overstated?* SimHash is locality-sensitive: a small edit flips a few bits, spread over 128 positions. The probability that all flips land in the low 64 bits is about 2^-k for k flipped bits. A spammer can also just test locally until the top half differs. So the evasion is reliable.
5. *Already filed?* F047 is about the order of the fee gate (unpaid messages persist). This finding is about the fee value being 0. They are distinct.

## Fix

- Spec and code: use `uniqueness = trust` (or 0) for non-cast classes, or apply the discount as `1 − trust·uniqueness`, so the base fees take effect for zero-trust senders.
- For casts, use multi-band LSH (for example 4 × 32-bit bands) so near-duplicates in any band are found, or index on several bit-sampled keys.
- Add tests: a zero-trust `ReactionAdd` is charged `BASE_FEE_REACTION_ADD`, and a one-character edit of a stored cast is detected.

## Files

- `src/chain/replica.rs:192-236`
- `crates/proof-of-quality/src/fees.rs:22-33, 65-78`
- `crates/proof-of-quality/src/uniqueness.rs:75-89`
- `src/chain/fingerprint_store.rs:13-17, 147-200`
