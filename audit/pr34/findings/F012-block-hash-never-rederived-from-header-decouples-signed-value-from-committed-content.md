---
id: F012
specialist: consensus-malachite-tendermint
attack_class: propose-value-misuse
file_paths:
  - src/consensus/proposer.rs
  - src/consensus/validator.rs
  - src/consensus/read_validator.rs
  - src/core/util.rs
  - proto/src/lib.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: Block/ShardChunk `hash` is the consensus-committed value but is never re-derived from blake3(header) on validate/commit/read-node paths, decoupling the signed value from the header and body that actually get committed
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.6
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00+00:00
---

## Summary

The Malachite consensus value for a snapchain block/shard chunk is
`FullProposal::shard_hash()` = `ShardHash { shard_index, hash: block.hash }`
(`proto/src/lib.rs:147-161`). Precommit signatures are computed over exactly
this `ShardHash` and nothing else (`core/util.rs:147-155`,
`Vote::to_sign_bytes` → `proto::Vote{ value: shard_hash }`). So the only thing
2/3 of validators ever sign is the opaque `hash` byte string.

The proposer constructs `block.hash = blake3(block_header.encode_to_vec())`
(`consensus/proposer.rs:569`) and `chunk.hash = blake3(shard_header.encode_to_vec())`
(`consensus/proposer.rs:185`). But **no validation, commit, or read-node code
path ever re-derives that hash from the header and compares it to the supplied
`hash` field.** The `hash` field is therefore a free-floating, proposer/relayer-
set field that is *outside* the header it is supposed to commit to, yet it *is*
the value consensus signs and the value used as the chain's parent-hash link and
canonical block identity.

Because the signed `hash` is not bound to `header` (and `header` in turn binds
the body via `state_root` / `events_hash` / `shard_witnesses_hash`), a peer that
possesses a validly-signed `Commits` for height H can attach to it a block whose
`hash` equals the signed value but whose `header` and body
(`transactions`, `events`, `shard_witness`, `parent_hash`, `state_root`,
`events_hash`) are arbitrary. On the read-node / decided-value path this block is
committed verbatim with no re-derivation and no state replay, so the persisted,
finalized block content is attacker-controlled while still passing signature
verification.

## Affected code (file:line)

- `proto/src/lib.rs:147-161` — `FullProposal::shard_hash()` returns
  `ShardHash { hash: block.hash | chunk.hash }`. The consensus value is the
  raw proposer-supplied `hash` field, not a re-derivation of `blake3(header)`.
- `src/core/util.rs:147-155` — precommit `Vote` is built from
  `certificate.value_id` (= `commits.value` = the `ShardHash`). The signed bytes
  cover only height, round, and the `hash`. Nothing in the header or body is
  signed except transitively *if* `hash == blake3(header)` were enforced.
- `src/consensus/proposer.rs:185, 569` — the only places `blake3(header)` is
  computed are the proposer's *construction* of `hash`. There is no
  corresponding re-derivation on receipt.
- `src/consensus/proposer.rs:206-274` (`ShardProposer::add_proposed_value`) and
  `:593-678` (`BlockProposer::add_proposed_value`) — the validate path checks
  `header.height`, `chain_id`, `version`, `shard_witnesses_hash`, runs
  `validate_state_change` for `state_root`/`events_hash`, but **never checks that
  `block.hash == blake3(header)` / `chunk.hash == blake3(header)`**. The proposal
  is then stored keyed by the unverified `shard_hash()` (`validator.rs:281`,
  `proposer.rs:202/589`).
- `src/consensus/validator.rs:281` — `let value = full_proposal.shard_hash();`
  takes the consensus value straight from the unverified `hash` field; the
  returned `ProposedValue.value` is that hash. Validity is computed from header
  checks that do not include the hash.
- `src/consensus/read_validator.rs:143-171, 175-249` — the decided-value path:
  `verify_signatures` proves a quorum signed `commits.value` (the hash), then
  `process_decided_value` → `commit_decided_value` (`:49-100`) commits the block
  verbatim. There is **no** `blake3(header)` re-derivation and **no** state-
  transition replay binding the body to the signed hash. (`block_engine.commit_*`
  replays only on the full-validator commit path, and only when
  `WriteDataToShardZero` is enabled; the read-node decided-value path does not
  gate the body to the signed value at all.)

## Why the header checks do not save this

The `add_proposed_value` validators do re-run the state transition and check
`state_root`/`events_hash`/`shard_witnesses_hash` *of the header they received*.
That binds the body to the header. But it does **not** bind the header to the
signed value, because the signed value is `block.hash`, and `block.hash` is never
compared to `blake3(header)`. The integrity argument "the hash commits to the
header, the header commits to the body" silently fails at its first link: the
signed `hash` is an independent field, not a digest of the header.

Two consequences follow:

1. **Identity / fork-link corruption (full validators too).** A proposer can set
   `block.hash` to any value; honest validators store and commit it unverified.
   The next block's `parent_hash` is `previous_block.hash` (`proposer.rs:541-543`),
   so the canonical hash chain is built from values never tied to header content.
   A proposer can commit a block whose stored `hash` differs from
   `blake3(header)`, breaking the invariant that block identity = header digest.

2. **Decided-value content forgery (read nodes).** Given any signed
   `Commits{value=H}` (observed on the wire), a relayer can wrap it with a
   `Block`/`ShardChunk` whose `hash == H` but whose `header`+body are arbitrary.
   `verify_signatures` passes (it only checks the quorum signed `H`), and the read
   node commits the forged header (state_root, parent_hash, events_hash) and body
   to its store with no re-derivation and no replay. Read nodes therefore finalize
   attacker-chosen state that no validator endorsed.

## Attack scenario (read node)

1. Honest validators reach consensus on height H and sign
   `ShardHash{ hash: blake3(header_honest) }`. The `Commits` (quorum of
   precommit signatures over that hash) is observable on gossip / sync.
2. A malicious relayer crafts a `Block` with `hash = blake3(header_honest)`
   (the signed value) but replaces `header` with `header_evil`
   (different `state_root`, `parent_hash`, `events_hash`) and replaces
   `transactions`/`events`/`shard_witness` with arbitrary content. It attaches the
   real `Commits`.
3. The relayer delivers this `DecidedValue` to a read node
   (`read_validator::process_decided_value`).
4. `verify_signatures` recomputes the signed `Vote` from `commits.value`
   (= the honest hash) and the quorum signatures verify — the relayer did not
   touch `hash` or `commits`. The check passes.
5. `commit_decided_value` persists `header_evil` + forged body. The read node's
   view of finalized state at height H diverges arbitrarily from the validators'.
   No re-derivation of `blake3(header_evil)` (which would not equal `hash`) is ever
   performed, so the mismatch is invisible.

## Impact

- Read nodes can be made to finalize arbitrary, attacker-chosen block content
  (state root, transactions, events, parent link) while passing quorum-signature
  verification. This is finalized-state forgery against any read node / light
  consumer, i.e. a consensus-safety / fork break on the read path.
- The canonical hash chain (block identity, parent-hash links) is built from a
  field that is never bound to the header it is supposed to digest, undermining
  the integrity of the chain even for full validators.
- Severity initial: high. The signed value does not cover the committed content;
  a quorum-valid signature can be replayed onto forged header/body on a path that
  performs no re-derivation and no replay.

## Root cause

`block.hash` / `chunk.hash` is treated as the consensus value identity but is a
proposer-set proto field, and the system relies on the invariant
`hash == blake3(header)` without ever enforcing it on any receive path. The
construction side computes the digest (`proposer.rs:185, 569`); every validation
and commit side trusts the field as-is.

## Fix

- On every receive path that consumes the `hash` as a value identity, re-derive
  and enforce it before use:
  - In `ShardProposer::add_proposed_value` / `BlockProposer::add_proposed_value`,
    reject the proposal as `Validity::Invalid` unless
    `chunk.hash == blake3(chunk.header.encode_to_vec())` /
    `block.hash == blake3(block.header.encode_to_vec())`.
  - In `read_validator::verify_signatures` (or before `commit_decided_value`),
    after confirming the quorum signed `commits.value`, require that the
    committed block/chunk's `hash` equals `blake3(header)` AND re-run the state
    transition (or otherwise bind body→header) so the signed hash transitively
    covers the committed content. Drop the decided value on mismatch.
- Add regression tests: (a) a proposal whose `hash` does not match
  `blake3(header)` is rejected; (b) a `DecidedValue` carrying a valid `Commits`
  but a header/body whose `blake3(header)` differs from `commits.value` is
  dropped by the read node.
