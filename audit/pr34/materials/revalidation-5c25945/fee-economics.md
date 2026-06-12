# Revalidation — fee-economics (chain-economics specialist)

- AUDITED commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- NEW (fixes) commit: `5c2594563df84c374fdce7cdeae06d3444da3b72`
- Method: static diff + new-code read, adversarial residual check.

---

## F068 — Empty-text CastAdds (embed/mention/reply-only) permanently evade the per-message fee

**Verdict: FIXED — confidence 0.9**

### What the bug was
Pre-fix, `stage_fee` derived `uniqueness` from the cast's raw `text`
only, while `record_fingerprint_if_cast` early-returned for empty text
(`if text.is_empty() { return Ok(()) }`). The two halves disagreed: an
empty-text cast carrying an embed/parent/mention was *scored* but never
*fingerprinted*, so its SimHash bucket stayed empty forever →
`uniqueness == 1.0` → `effective_fee == 0` → unbounded zero-cost
embed-only / reply-only / mention-only spam.

### What the fix does
Both halves now route through a single new helper
`canonical_cast_content(data)` that builds a deterministic content string
folding in `text` + `embeds` (URL / CastId) + `embeds_deprecated` +
`mentions` + `parent` with disambiguating tag prefixes
(`t:`,`|u:`,`|c:`,`|d:`,`|m:`,`|p:`).

- New `src/hyper/fee_charger.rs:116-120` — `stage_fee` scores
  `uniqueness_score(&canonical, …)` instead of `text`.
- New `src/hyper/fee_charger.rs:173-184` — `record_fingerprint_if_cast`
  now `stage_insert(data.fid, &canonical, …)`, guarded by
  `if canonical.is_empty() { return Ok(()) }` (only truly-empty casts,
  which validation rejects, are skipped).
- New helper `src/hyper/fee_charger.rs:194-247`
  (`canonical_cast_content`).

Because the same canonical key is now both scored and inserted, an
empty-text cast that carries an embed/parent/mention is fingerprinted on
first use; subsequent identical or near-identical embed/parent/mention
casts are detected as near-duplicates (`hamming ≤ NEAR_DUP_HAMMING_THRESHOLD = 6`),
driving `uniqueness` below 1.0 and charging the fee. The systematic
charged-zero path described in F068 is closed. The fingerprint store
(`fingerprint_store.rs`) is content-agnostic (it hashes whatever string
it is handed), so no further change there was required; short canonical
strings (`chars.len() < ngram`) fall back to exact `xxhash_128`, so even
a tiny `|u:x` body collides at Hamming 0 for identical reposts.

### Adversarial residual check
- *Distinct-URL-per-cast* (the literal exploit step "each with a distinct
  embed URL") still yields `uniqueness == 1.0` and fee 0. **This is not a
  residual F068 gap** — it is the fee mechanism's intended behaviour and
  is identical to how an ordinary cast with genuinely novel *text* has
  always behaved (novel content earns the uniqueness discount). F068's
  distinguishing defect was the *unconditional* zero independent of
  duplication; that is fixed. Any "novel content is cheap" critique
  applies equally to text casts and is a separate design concern, not
  this finding.
- Tag prefixes prevent `"abc"` from colliding with `"abc"+embed`, so the
  fix does not introduce a new collision-based bypass.
- Ordering: embeds/mentions are emitted in proto-declared order; two
  casts that reorder the same embeds would produce different canonical
  strings and thus not be flagged as dups. Minor and not an F068 evasion
  of the empty-text class (the empty-text unconditional zero is gone
  regardless of ordering).

F068 status downgrade is justified: the medium-severity systematic
bypass is eliminated; only the pre-existing, by-design "novel content is
discounted" property remains.

---

## F003 — Ring-vouch sybil amplification, no vouch caps (EigenTrust)

**Verdict: NOT_APPLICABLE (UNCHANGED) — confidence 0.97**

F003 was already `INVALIDATED` in the prior validation pass. Per the
revalidation instruction, the only task is to confirm the new commit did
not touch the relevant code.

- `git diff cab225f 5c25945 -- 'src/emission/*'` is **empty**.
- The finding's two files —
  `src/emission/eigentrust.rs` and `src/emission/mutuality.rs` — are
  present at the fix commit and byte-identical to the audited commit.
- No vouch-cap / mutual-vouch / min-vouchee-trust gate was added; none
  was expected, as the finding was invalidated.

Conclusion: no change relevant to F003. Verdict carries over as
NOT_APPLICABLE / UNCHANGED (still invalidated).

---

## Summary table

| ID   | Verdict                  | Confidence | One-line reason |
|------|--------------------------|-----------|-----------------|
| F068 | FIXED                    | 0.90      | `canonical_cast_content` now feeds both `stage_fee` and `record_fingerprint_if_cast`, so empty-text embed/reply/mention casts are fingerprinted and duplicates pay the fee; unconditional charged-zero path removed. |
| F003 | NOT_APPLICABLE (UNCHANGED)| 0.97     | Already invalidated; emission/eigentrust/mutuality files byte-identical in fix commit (empty diff). |
