# Revalidation: gossip decode / proto findings

- AUDITED commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- NEW "audit fixes" commit: `5c2594563df84c374fdce7cdeae06d3444da3b72`
- Scope: F013, F022 (`src/network/gossip.rs`, `proto/src/lib.rs`, `proto/definitions/blocks.proto`)

---

## F013 — FullProposal `height().unwrap()` panic on height-less gossip frame

**Verdict: FIXED** — confidence 0.95

### What changed
The `FullProposal` arm of `map_gossip_bytes_to_system_message` in
`src/network/gossip.rs` no longer calls the panicking `full_proposal.height()`
accessor. It now reads `height` through a `None`-guarded `let-else` and drops
the frame if absent, and it additionally guards a negative `round` (which would
panic in `FullProposal::round()` via `try_into().unwrap()`).

New code, `src/network/gossip.rs:1058-1075`:
```rust
let Some(height) = full_proposal.height.clone() else {
    warn!(peer_id = peer_id.to_string(), "Dropping FullProposal with missing height");
    return None;
};
if full_proposal.round < 0 {
    warn!(peer_id = peer_id.to_string(), round = full_proposal.round,
          "Dropping FullProposal with negative round");
    return None;
}
```
Downstream, `height` is only used in `debug!`, and shard routing goes through
`full_proposal.shard_id()` (`proto/src/lib.rs:139`), which returns `Result` and
is `is_err()`-guarded. The panicking `height()`/`round()` accessors in
`proto/src/lib.rs:190` and `:196` are unchanged but are no longer reachable on
the gossip decode path; the fix added doc-comments declaring the caller-must-
validate contract.

### Adversarial check
- Both unwraps named in the finding are now guarded *before* use: the `Option<Height>`
  unwrap (replaced by `let-else`) and the `round` `try_into().unwrap()` (gated by `round < 0`).
- The negative-round guard is correct: `self.round` is `i32`; `Round::new` takes the
  converted value, and `try_into()` to the target int type fails (and would `unwrap()`-panic)
  only on negatives — `round < 0` is the exact precondition.
- `shard_hash()` (which still `panic!`s on an invalid proposal type) is NOT called on
  this arm — only `shard_id()` is, which is `Result`-based and None-safe.
- No other accessor on this arm dereferences a peer-controlled `Option` unconditionally.
  The size cap (see F022) runs first, before the height/round guards and before
  `encode_to_vec()`.

Residual: none on the gossip path. The panicking `height()`/`round()` accessors remain
in `proto/src/lib.rs` for non-gossip (locally-produced/post-validation) callers, by design
and documented; not reachable from attacker-controlled decode.

---

## F022 — FullProposal & DecidedValue gossip paths lack per-variant size cap

**Verdict: FIXED** — confidence 0.93

### What changed
Two new constants and two new per-variant caps were added in
`src/network/gossip.rs`:

- `MAX_FULL_PROPOSAL_BYTES = 2 * 1024 * 1024` and
  `MAX_DECIDED_VALUE_BYTES = 2 * 1024 * 1024` (gossip.rs:63-64).
- `DecidedValue` arm (gossip.rs:1021-1032): `if decided_value.encoded_len() >
  MAX_DECIDED_VALUE_BYTES { warn!; return None; }` runs *before* constructing
  `SystemMessage::DecidedValueForReadNode`.
- `FullProposal` arm (gossip.rs:1043-1052): `if full_proposal.encoded_len() >
  MAX_FULL_PROPOSAL_BYTES { warn!; return None; }` runs at the *top* of the arm,
  before the height/round guards, before `full_proposal.encode_to_vec()`, and
  before `SystemMessage` dispatch.

### Adversarial check
- Both arms named in the finding (the two uncapped paths bounded only by the 10 MB
  transport ceiling) now have an explicit `encoded_len()` cap, matching the pattern of the
  other arms (ContactInfo/Consensus/Status/HyperWire/Mempool).
- Cap placement is correct: for `FullProposal` the cap is the first statement in the arm, so
  the oversized frame is rejected before the heavy `encode_to_vec()` re-encode the finding
  flagged as the 2x-amplification step. For `DecidedValue` the cap precedes the downstream
  `SystemMessage`.
- Note: `encoded_len()` is computed on the already-decoded message (the outer
  `GossipMessage::decode` at gossip.rs:989 still allocates the decoded tree first), but
  the decoded message is itself bounded by the 10 MB transport ceiling, and the cap prevents
  the *additional* re-encode/forward amplification, which is exactly the F019/F022 intent.
  This is the same model used by every other capped arm in this file, so the fix is consistent
  with the established hardening.
- The evidence-topic path (`HyperWire`, capped at `MAX_HYPER_WIRE_BYTES`) was already covered
  per the finding and is unchanged.

Residual: none for the two flagged arms. The finding's secondary observation
(`MAX_HYPER_WIRE_BYTES` may under-size a legitimate two-block evidence frame) is a separate
availability concern, out of scope for this DoS fix, and not addressed in this commit.

---

## Summary table

| ID   | Verdict | Confidence | One-line reason |
|------|---------|-----------|-----------------|
| F013 | FIXED   | 0.95      | `height()` unwrap replaced by `let-else` guard and negative-`round` guard added before any use on the gossip arm; panicking accessors no longer reachable from decode. |
| F022 | FIXED   | 0.93      | `MAX_FULL_PROPOSAL_BYTES`/`MAX_DECIDED_VALUE_BYTES` (2 MB) caps now gate both arms via `encoded_len()` before re-encode/dispatch, mirroring the other capped variants. |
