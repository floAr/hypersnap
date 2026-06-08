---
id: F068
specialist: chain-economics
attack_class: fee-debit-split-integrity
title: Empty-text CastAdds (embed/mention/reply-only) permanently evade the per-message fee
severity_initial: medium
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - src/hyper/fee_charger.rs
  - src/hyper/fingerprint_store.rs
  - crates/proof-of-quality/src/fees.rs
  - src/core/validations/cast.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.82
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

# Summary

A `CastAdd` whose `text` is empty but which carries an embed, a mention,
or a parent (i.e. an embed-only post, a reply, or a mention-only post) is
a fully valid, fee-bearing message, yet it is **always charged a fee of
zero** — no matter how many identical or spammy ones the sender posts.
The fee mechanism (FIP-proof-of-quality §4) is supposed to make spam
costly for low-trust users; this lets a low-trust/zero-trust attacker
emit unbounded embed-only and reply casts at zero cost, defeating the
anti-spam fee for that entire message subtype.

The debit==burn+proposer conservation invariant itself is **intact**
(verified below); the defect is a systematic *charged-zero* path, which
is one of the explicit H068 hunt questions ("Can fee be skipped (charged
0) for some message types?").

# Root cause

The effective fee is `base × max(0, 1 − max(trust, uniqueness))`
(`crates/proof-of-quality/src/fees.rs:58`). For a zero-trust sender the
fee is fully determined by `uniqueness`: `uniqueness == 1.0` ⇒ fee 0.

For CastAdd, `FeeCharger::stage_fee` derives uniqueness from the cast's
`text` only (`src/hyper/fee_charger.rs:107-121`):

```rust
let uniqueness = if class == FeeClass::CastAdd {
    let text = data.body.as_ref().and_then(|b| match b {
        proto::message_data::Body::CastAddBody(c) => Some(c.text.as_str()),
        _ => None,
    }).unwrap_or("");
    self.fingerprint_store.uniqueness_score(text, data.timestamp as u64, batch)?
} else { 1.0 };
```

`uniqueness_score` measures near-duplication against the rolling
fingerprint window. The window is populated by
`record_fingerprint_if_cast`, which is called after a successful merge —
but it **early-returns for empty text** (`src/hyper/fee_charger.rs:167`):

```rust
if text.is_empty() {
    return Ok(());
}
self.fingerprint_store.stage_insert(data.fid, text, ...);
```

So the two halves of the cast-uniqueness machinery disagree on empty
text:

1. `stage_fee` *scores* empty text (`uniqueness_score("")`), but
2. `record_fingerprint_if_cast` *never inserts* a fingerprint for empty
   text.

Because no empty-text fingerprint is ever written, the empty-text
SimHash bucket stays permanently empty. Every empty-text cast therefore
sees `near_dup_count == 0` ⇒ `uniqueness_score == 1.0`
(`src/hyper/fingerprint_store.rs:176`, via
`uniqueness_score_from_neighbor_count(0)`), and with any trust value
`compute_effective_fee_micro` returns 0 (`fees.rs:67-70`,
`(1.0 - 1.0).max(0.0) == 0.0`). `stage_fee` then hits the `fee == 0`
short-circuit (`fee_charger.rs:124`) and stages no charge.

Cast validation explicitly permits empty text as long as embeds,
embeds_deprecated, or mentions are present
(`src/core/validations/cast.rs:65-71` — `CastIsEmpty` only fires when
text AND embeds AND embeds_deprecated AND mentions are all empty). So
the zero-fee class is large and useful to a spammer:

- embed-only casts (link/image spam, each with a distinct embed URL),
- reply casts that carry only a parent + empty text,
- mention-only casts (tagging/notification spam).

A secondary contributor: uniqueness is scored over `text` alone and
ignores `embeds`, `embeds_deprecated`, `mentions`, and `parent`. Even
for non-empty text, two casts that differ only in their embed/parent are
treated as identical content; but the empty-text case is the clean,
unconditional bypass.

# Exploit

Sender FID with `trust == 0` (a brand-new/Sybil FID) wants to flood the
network:

1. Submit `CastAdd { text: "", embeds: [<unique URL>], type: Cast }`.
   Validation passes (has an embed). Merge succeeds.
2. `stage_fee`: `text == ""`, `uniqueness_score("") == 1.0` (bucket never
   populated), `effective_fee = 1_000_000 × max(0, 1 − 1.0) = 0` ⇒ no
   charge.
3. `record_fingerprint_if_cast`: `text.is_empty()` ⇒ no fingerprint
   written, so step 2 stays true forever.

Repeat unbounded. None of these casts ever require a fee deposit
(`apply_fee_deposit`) and none deplete `HyperFeeBalance`, so the
`HyperFeeInsufficient` gate in
`src/storage/store/engine.rs:1311-1331` never fires.

# Conservation invariant (verified sound)

For completeness, the in-scope debit/split arithmetic is correct:

- `split_burn_proposer(total)` returns `burn = total*6000/10000`,
  `proposer = total − burn`, so `burn + proposer == total` exactly for
  all `total` (`fees.rs:82-86`) — no minted or lost atoms.
- `stage_charge_message_fee` debits exactly `total` from the fee balance
  and increments the burn accumulator by `burn` and the proposer pot by
  `proposer` on the same batch (`rewards.rs:637-679`); the
  read-through-batch helpers (F132 fix) make this hold across multiple
  same-FID charges in one shard chunk.
- Underflow is guarded: `cur < total` ⇒ `InsufficientBalance` before any
  subtraction (`rewards.rs:646-653`).
- `compute_effective_fee_micro` floors and clamps the multiplier to
  `[0,1]`, so the fee can never exceed `base` (no overcharge).

The integrity defect is purely the charged-zero path above, not the
split math.

# Impact

- Anti-spam fee (§4) is fully bypassable for embed-only, reply-only, and
  mention-only casts by any account regardless of trust.
- Because the fee is the economic throttle on low-trust message volume,
  this reopens the spam/Sybil-amplification surface the fee was designed
  to close.
- No fund loss and no break of burn/proposer conservation, hence Medium
  rather than High.

# Suggested fix

- Make `stage_fee` and `record_fingerprint_if_cast` agree on what gets
  fingerprinted: either fingerprint empty-text casts too (so duplicates
  drive uniqueness down), or fold a canonicalized digest of
  `embeds`/`embeds_deprecated`/`mentions`/`parent` into the SimHash input
  so empty-text-but-non-empty-body casts are scored on their actual
  content.
- Alternatively, treat empty text as `uniqueness = 0.0` for fee purposes
  (no novel textual content ⇒ no uniqueness discount), forcing
  embed/reply spam through the trust-only discount.
