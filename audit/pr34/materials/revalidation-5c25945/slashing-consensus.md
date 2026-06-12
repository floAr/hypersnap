# Revalidation — slashing false-positive cluster + block-hash binding

- AUDITED commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- FIX commit:     `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child)
- Method: static diff + read of the new reachable paths; adversarial residual-case check.

## Summary table

| ID   | Verdict          | Confidence | One-line reason |
|------|------------------|------------|-----------------|
| F002 | PARTIALLY_FIXED  | 0.85       | Intersection penalty correctly applied, but the `slashed_validators_for_epoch` ↔ `get_active_validators_enforced` self-recursion / chain-halt sub-issue is untouched. |
| F009 | FIXED            | 0.93       | Conflict now keyed on a new signature-free `hyper_block_content_hash` (signing-payload-equivalent), not the sig-bearing `hyper_block_hash`. |
| F012 | FIXED            | 0.9        | `hash == blake3(header)` is now re-derived and enforced on both proposer validate paths and the read-validator decided-value path, before commit. |
| F015 | FIXED            | 0.95       | `encode_block` now copies all six previously-zeroed signing-payload fields plus the full signature struct; stored evidence round-trips for re-verification. |

---

## F002 — Cross-epoch evidence slashes innocent single-epoch signers

**Verdict: PARTIALLY_FIXED — confidence 0.85**

The primary defect (UNION instead of INTERSECTION) is fixed.
`slashed_validators_for_epoch` now resolves each block's signers into its
own `BTreeSet` via a `resolve_signers` closure and only slashes
`signers_a.intersection(&signers_b)`.

New code — `src/hyper/runtime.rs:4284-4290`:
```rust
let signers_a = ev.block_a.as_ref().map(resolve_signers).unwrap_or_default();
let signers_b = ev.block_b.as_ref().map(resolve_signers).unwrap_or_default();
for vk in signers_a.intersection(&signers_b) {
    slashed.insert(vk.clone());
}
```
An epoch-A-only signer is no longer in `signers_b`, so the documented
griefing-eviction of the honest other-epoch committee is closed. Confirmed
reachable: this is the function `get_active_validators_enforced`
(runtime.rs:4122) calls at every epoch boundary.

**Residual gap — the self-recursion / chain-halt is NOT fixed.**
The F002 writeup names a second sub-issue: a `slashed_validators_for_epoch`
↔ `get_active_validators_enforced` self-recursion. That recursion is present
in both commits and is left unchanged. `resolve_signers` still calls
`self.get_active_validators_enforced(block_epoch, ...)` where
`block_epoch = sig.epoch` of a stored evidence block
(`src/hyper/runtime.rs:4262-4267`):
```rust
let block_epoch = sig.epoch;
let active = match self
    .get_active_validators_enforced(block_epoch, &self.bootstrap_validators)
{ ... };
```
Trace the cycle. Evidence is stored under `min(epoch_a, epoch_b)`
(`slashing_store.rs::make_key`, line 165). Take adjacent cross-epoch
evidence `(epoch_a = E-1, epoch_b = E)` — exactly the F002 attack shape,
and reachable because `detect_conflicting_blocks` never requires
`epoch_a == epoch_b`. It is stored under `E-1`. At the epoch-`E` cutover:

1. `get_active_validators_enforced(E)` → `slashed_validators_for_epoch(E-1)`
   (runtime.rs:4122).
2. That reads the evidence at `E-1`; `block_b` has `sig.epoch = E`, so
   `resolve_signers` calls `get_active_validators_enforced(E)` again
   (runtime.rs:4264).
3. → `slashed_validators_for_epoch(E-1)` → back to step 2.

There is no depth guard, no memoization, and the `_active_set_at_epoch`
parameter that could have broken the cycle is ignored (prefixed `_`,
runtime.rs:4241). Result: unbounded re-entry → stack overflow → epoch-boundary
chain halt, triggerable by one attacker-submitted adjacent cross-epoch
evidence row. The intersection change is orthogonal and does not bound the
recursion. Because the explicitly-listed recursion/chain-halt half of the
finding remains, this is PARTIALLY_FIXED, not FIXED.

---

## F009 — Slashing predicate keys conflict on signature-inclusive hash

**Verdict: FIXED — confidence 0.93**

The conflict predicate no longer keys on `hyper_block_hash` (which mixes in
`ecdsa_signature` and `group_address`). A new signature-free
`hyper_block_content_hash` was added at `src/hyper/chain.rs:62-119` covering
exactly the `signing_payload` field set (canonical_block_id, parent_hash,
hyper_state_root, extra_rules_version, retained_message_count,
missed_proposals, all `snapchain_*` fields, epoch, and sorted
signer_indices) and explicitly NOT the signature bytes.

`detect_conflicting_blocks` now uses it (`src/hyper/slashing.rs:68-72`):
```rust
let hash_a = hyper_block_content_hash(a);
let hash_b = hyper_block_content_hash(b);
if hash_a == hash_b {
    return Err(EvidenceError::SameBlock);
}
```
The evidence's `block_a_hash`/`block_b_hash` (which feed `make_key`) are set
from these content hashes too (slashing.rs:78-79), so dedupe key, store key,
and the conflict test all agree on content identity.

Adversarial check: two valid threshold signatures over byte-identical
content (the DKLS recovery-id restart / round-retry case) now produce
identical content hashes → `SameBlock` → not slashable. Genuine state-root
equivocation still differs in `hyper_state_root` → still detected. A new
regression test `identical_content_distinct_signatures_is_not_a_conflict`
(slashing.rs) asserts exactly this. No residual.

---

## F012 — Signed block hash never re-derived from header

**Verdict: FIXED — confidence 0.9**

`hash == blake3(header)` is now enforced on every receive path named in the
finding, before the value is stored/committed.

Proposer validate paths:
- `ShardProposer::add_proposed_value` — `src/consensus/proposer.rs:235-241`:
  `expected_hash = blake3::hash(&header.encode_to_vec())`; returns
  `Validity::Invalid` on mismatch (before `add_proposed_value` storage).
- `BlockProposer::add_proposed_value` — `src/consensus/proposer.rs:631-641`:
  same check, returns `Validity::Invalid` on mismatch.

Read-validator decided-value path:
- New `validate_block_hash_matches_header` — `src/consensus/read_validator.rs:177-201`
  re-derives `blake3(header)` for both `Block` and `Shard` variants.
- Called in `process_decided_value` after `verify_signatures` and before
  commit — `src/consensus/read_validator.rs:341-350`; returns `0` (drop) on
  mismatch.

Adversarial check: `verify_signatures` derives `commits` from
`block.commits` and verifies the quorum signed `commits.value` (the
`ShardHash{hash}`). The F012 forgery required keeping `block.hash` = the
honestly-signed value while swapping in `header_evil`. With the new check,
the read node also requires `block.hash == blake3(header_evil)`; satisfying
both means `blake3(header_evil)` equals the honest signed hash — a blake3
preimage/collision. The forgery path is closed on both full-validator and
read-node paths. HyperBlocks are intentionally exempted (separate
threshold-sig integrity model), which is consistent with the finding's
scope (snapchain Block/ShardChunk). No residual on the documented path.

---

## F015 — Slashing store encode_block drops signed fields

**Verdict: FIXED — confidence 0.95**

`encode_block` (`src/hyper/slashing_store.rs:177-210`) now copies every
metadata field from the source block instead of zeroing six of them. The
previously hard-coded `missed_proposals: vec![]`, `snapchain_anchor_block: 0`,
`snapchain_anchor_hash: vec![]`, `snapchain_range_start_block: 0`,
`snapchain_range_root: vec![]`, `snapchain_anchor_timestamp: 0` are all
replaced with real values:
```rust
missed_proposals: md.missed_proposals.iter().map(|mp| proto::MissedProposal {
    validator_key: mp.validator_key.clone(), round: mp.round }).collect(),
snapchain_anchor_block: md.snapchain_anchor_block,
snapchain_anchor_hash: md.snapchain_anchor_hash.clone(),
snapchain_range_start_block: md.snapchain_range_start_block,
snapchain_range_root: md.snapchain_range_root.clone(),
snapchain_anchor_timestamp: md.snapchain_anchor_timestamp,
```
The signature struct (epoch, signer_indices, group_address,
ecdsa_signature) is also preserved (slashing_store.rs:203-208). Cross-checked
against `HyperBlockMetadata::signing_payload` (`src/hyper/mod.rs:403-452`):
every field the signature commits to is now persisted, so re-decoded
evidence reproduces the original `signing_payload` and the stored threshold
signature re-verifies. The durability invariant the finding flagged is
restored. No residual.
