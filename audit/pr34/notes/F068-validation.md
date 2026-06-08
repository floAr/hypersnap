# F068 validation — empty-text CastAdd permanently evades the per-message fee

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f` (verified HEAD == pin).

## Mechanic re-derived from source (independent of finding body)

- `compute_effective_fee_micro` = `base × max(0, 1 − max(trust, uniqueness))`,
  no minimum-fee floor; `fee==0` short-circuits with zero charge
  (`crates/proof-of-quality/src/fees.rs:58-71`; `src/hyper/fee_charger.rs:124-126`).
- `stage_fee` derives CastAdd uniqueness from `text` only and defaults to `""`
  when the body is missing/non-cast (`fee_charger.rs:107-121`).
- `record_fingerprint_if_cast` early-returns on `text.is_empty()`
  (`fee_charger.rs:167-169`) so NO empty-text fingerprint is ever inserted.
- `uniqueness_score` of empty text → bucket for `fingerprint("")==0`
  (`uniqueness.rs:24-26`, test `empty_text_zero_fingerprint` line 134) is never
  populated → `near_dup_count==0` → `uniqueness_score_from_neighbor_count(0)==1.0`
  (`uniqueness.rs:75-78`; `fingerprint_store.rs:176`).
- Fresh Sybil FID: `trust_store.get` → `None` → `unwrap_or(0.0)` (`fee_charger.rs:95-99`).
  So `max(0.0, 1.0)=1.0` → multiplier 0 → fee 0. Confirmed.
- Cast validation permits empty text when embeds/embeds_deprecated/mentions present
  (`src/core/validations/cast.rs:65-71`). Reachable.
- Production wiring: `stage_fee` at `engine.rs:1311`, `record_fingerprint_if_cast`
  at `engine.rs:1336`, both on the live merge batch. NOT test-only.

## 8-hypothesis walk

1. **Upstream auth / gate — PARTIALLY INVALIDATED (impact only).**
   No upstream gate negates the zero-fee path. BUT a parallel anti-spam bound
   exists: per-FID message pruning to `max_count` storage units
   (`store.rs:1019-1068`, `get_prune_size_limit`). This caps *stored* casts per
   FID, so "unbounded accumulation" is bounded for stored state. It does NOT bound
   network/gossip throughput, and Sybils spread across FIDs; the fee is a distinct
   per-message throughput throttle. Bug stands; "unbounded" framing slightly
   overstated for storage but accurate for throughput.

2. **Consumer-side impact — STANDS.** `uniqueness` is consumed ONLY by the fee
   path (grep: appears in fee_charger + fingerprint_store; reward calc uses
   `trust`, not uniqueness). uniqueness=1.0 is therefore NOT inert — it directly
   waives the full 1.0-token CastAdd base fee. Real economic benefit.

3. **Downstream enforcement — STANDS.** No lower layer re-charges. `apply_fee_deposit`
   / `HyperFeeBalance` / `HyperFeeInsufficient` (engine.rs:1311-1331) only fire
   when a non-zero fee is staged; a zero fee never touches the balance gate.

4. **PR HEAD currency — STANDS.** `git rev-parse HEAD == cab225f1...` matches the
   pinned commit exactly. No drift.

5. **Spec carve-out — STANDS.** fees.rs doc says "new users posting novel content
   pay nothing" (intentional), but NOTHING documents empty-text-with-embed casts
   being scored as novel. No FIP/comment/TODO marks this gap as deferred or known.
   The fee_charger doc explains uniqueness=1.0 for *other Add types* (identity dedup)
   but is silent on empty-text CastAdds. Undocumented gap, not an accepted deviation.

6. **Reachability of harm — STANDS.** CastAdd base=1_000_000 (non-zero), real FID
   (≠0), validation accepts empty-text+embed/mention/reply. Every guard the fee
   path could hit is cleared; fee deterministically resolves to 0.

7. **Test wiring — STANDS.** Buggy code is invoked from the production merge path
   (engine.rs:1311/1336), not just tests. fee_charger.rs has no test module, so the
   empty-text branch is unverified by tests — reinforcing rather than weakening the bug.

8. **PoC mechanics — STANDS (prose-level; no executable PoC supplied).** The finding's
   step-by-step exploit matches the code exactly: each transition (validation pass →
   uniqueness 1.0 → fee 0 → no fingerprint insert → repeat) is line-confirmed above.
   No assertion-passes-for-wrong-reason risk because there is no test asserting it;
   the claim rests on direct code reading, which checks out.

## Overall

Verdict: HAS_CAVEATS. Confidence: 0.82.
The zero-fee path is real, reachable, and undocumented; uniqueness=1.0 yields a
genuine fee waiver (not inert); conservation/split math is correctly excluded from
the defect. The single caveat: per-FID pruning (`store.rs:1019`) bounds *stored*
cast count, so the "unbounded / permanently accumulate" framing overstates the
storage dimension — the surviving harm is unbounded *zero-cost throughput* of
embed/reply/mention spam, especially under Sybil FIDs. Severity Medium
(spam/grief, no fund loss, burn/proposer conservation intact) is appropriate and
not overstated.

## Open follow-ups (NOT new findings — for specialist consideration)
- Secondary observation in the body (uniqueness ignores embeds/parent even for
  non-empty text) is a related but distinct weakness; left to the originating
  specialist.
- A short non-empty text (`chars.len() < n`) falls back to `xxhash_128`
  (`uniqueness.rs:28-30`); fingerprints ARE inserted there, so that sub-case is
  scored — does not affect the empty-text claim.
