---
id: F002
task: H002
specialist: consensus-malachite-tendermint
attack_class: nil-block-proposal
severity: high
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.85
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  note: "Core thesis stands; 4 of 5 cited panic sites unaffected. One cited site (validator.rs:283) is unreachable because snapchain_codec.rs:106 panics earlier on the same outer-height field — same crash, different file:line. See findings/notes/F002-validation.md."
---

# Remote-triggerable panics in `add_proposed_value` from malformed peer proposals

## Summary

`ShardProposer::add_proposed_value`, `BlockProposer::add_proposed_value`, and
`ShardValidator::add_proposed_value` each contain `unwrap()`s on
attacker-controlled, sub-optional fields of a peer-supplied `FullProposal`.
A single malformed (effectively nil/partial) proposal sent by **any** peer
through the gossip layer causes the receiving validator to panic and crash.
The validator-side guard that should have returned `Validity::Invalid`
(`if header.height.is_none() { return Validity::Invalid; }`,
`proposer.rs:610`) is dead code — it sits **after** the unwrap that would
have panicked.

This is the classic "nil-block" footgun: the receiving handler does not
tolerate a proposal whose chunk/block header is missing or whose header has
no `height` set, even though the on-wire `proto::FullProposal` /
`proto::ShardChunk` / `proto::Block` types all allow those fields to be
absent (prost wraps message-valued fields in `Option`).

## Description

Peer proposals arrive at
`HostMsg::ReceivedProposalPart` (`src/consensus/malachite/host.rs:174–185`)
and are forwarded into `ShardValidator::add_proposed_value`, which in turn
dispatches to either `BlockProposer::add_proposed_value` or
`ShardProposer::add_proposed_value`. All three call sites unwrap optional
fields whose presence is controlled by the remote proposer.

### 1. `ShardValidator::add_proposed_value` — panics if `height` is omitted

`src/consensus/validator.rs:283`:

```rust
if self.shard_id.shard_id() != full_proposal.shard_id().unwrap() {
```

`FullProposal::shard_id()` is defined in `proto/src/lib.rs:139–145` and
returns `Err("No height in FullProposal")` whenever the optional `height`
field is `None`. A peer that simply omits `height` from the `FullProposal`
wire message therefore triggers an `unwrap()` panic before validation has
any chance to reject the message.

### 2. `ShardProposer::add_proposed_value` — panics on missing header / missing inner height

`src/consensus/proposer.rs:206–212`:

```rust
if let Some(proto::full_proposal::ProposedValue::Shard(chunk)) =
    full_proposal.proposed_value.clone()
{
    let header = chunk.header.as_ref().unwrap();      // line 210
    let height = header.height.unwrap();              // line 211
```

`ShardChunk::header` is `Option<ShardHeader>` in the proto and
`ShardHeader::height` is `Option<Height>`. A peer that sends a
`ProposedValue::Shard(chunk)` where `chunk.header == None`, or where
`chunk.header.height == None`, triggers a panic on receipt — the
explicit `Validity::Invalid` returns later in this function are never
reached for the nil-header case.

### 3. `BlockProposer::add_proposed_value` — dead nil-handling check

`src/consensus/proposer.rs:578–613`:

```rust
if let Some(proto::full_proposal::ProposedValue::Block(block)) =
    &full_proposal.proposed_value
{
    let header = block.header.as_ref().unwrap();      // line 582
    let height = header.height.unwrap();              // line 583
    ...
    if header.height.is_none() {                      // line 610 (unreachable)
        error!("Received block with missing height");
        return Validity::Invalid;
    }
```

Same pattern as (2). The author intended to gracefully reject blocks with
missing `height` (line 610), but the unwrap on line 583 panics first,
making the explicit guard dead code. Lines 614–629 (missing-witness checks)
correctly use `is_empty()` / `is_none()` and `return Validity::Invalid`,
which highlights the inconsistency.

### Why this is a nil-block-proposal bug

Tendermint-family consensus distinguishes between *Nil* (decided no-value)
and *Val* (decided some value), and well-formed proposers only ever emit
the latter via `propose_value`. Once a node accepts gossip from any peer,
however, that peer can craft a `FullProposal` whose **payload** is nil in
the sense that the application requires non-`None` sub-fields the proto
does not guarantee. The application must therefore validate
`Option`-typed payload fields before dereferencing them. The three sites
above do not, so an unfaithful peer can convert "I sent a partial block"
into "you crash and halt your shard until restart".

### Note on the genesis parent hash (sibling bug)

While auditing, `src/consensus/proposer.rs:173` writes
`parent_hash = vec![0, 32]` for the genesis shard chunk — a **2-byte** vec
containing the bytes `0x00 0x20`, not the intended 32-byte zero hash. The
analogous code path for blocks (`proposer.rs:535`) correctly uses
`vec![0; 32]`. This produces a malformed genesis chunk hash whose
downstream effects are out of scope for this finding but are worth a
follow-up; the proposed value with this short parent-hash still reaches
validators and will collide in any "parent hash must be 32 bytes"
invariant downstream.

## Impact

- **Liveness / DoS — high.** A single malformed gossip message from a
  validator (or anyone able to forge proposals if signatures aren't
  pre-checked here, which they aren't — see the `TODO: Validate proposer
  signature?` at `proposer.rs:258` and `:650`) crashes the receiving
  node's shard actor. Repeated delivery to a quorum crashes the network.
- **Even an honest, buggy proposer is dangerous.** A proposer that
  forgets to populate `header.height` (e.g. during an upgrade) takes down
  every peer that processes its proposal.
- **No double-spend / state-corruption path observed** here — the panic
  occurs before any state mutation — so the bug is liveness-only.
  That keeps it below "critical" but the cross-network blast radius and
  the dead-code intent on line 610 make it firmly **high**.

## Evidence

- `src/consensus/validator.rs:283` — `full_proposal.shard_id().unwrap()`
  panics when the peer omits `height`.
- `src/consensus/proposer.rs:210` — `chunk.header.as_ref().unwrap()` panics
  when peer omits `chunk.header`.
- `src/consensus/proposer.rs:211` — `header.height.unwrap()` panics when
  peer omits `chunk.header.height`.
- `src/consensus/proposer.rs:582` — `block.header.as_ref().unwrap()` panics
  when peer omits `block.header`.
- `src/consensus/proposer.rs:583` — `header.height.unwrap()` panics when
  peer omits `block.header.height`.
- `src/consensus/proposer.rs:610` — the dead guard `if header.height.is_none()`
  that the code's author clearly intended to catch this case.
- `proto/src/lib.rs:139–145` — confirms `FullProposal::shard_id()` returns
  `Err` (not panic) on missing `height`, so the failure mode at the
  validator is purely the unwrap.
- `src/consensus/malachite/host.rs:174–185` — entry point from the network
  layer that hands peer-controlled bytes directly to
  `add_proposed_value`.
- Sibling defect: `src/consensus/proposer.rs:173` — `vec![0, 32]` instead
  of `vec![0; 32]` for the genesis chunk's parent hash.

## Suggested remediation

1. **Replace every `unwrap()` on peer-controlled `Option` fields with an
   explicit `Validity::Invalid` return** before any other validation.
   Concretely, at the top of each `add_proposed_value` implementation
   (ShardProposer + BlockProposer) and in `ShardValidator::add_proposed_value`:

   ```rust
   let chunk_or_block = match full_proposal.proposed_value.as_ref() {
       Some(v) => v,
       None => { error!(...); return Validity::Invalid; }
   };
   let header = match chunk.header.as_ref() {
       Some(h) => h,
       None => { error!(...); return Validity::Invalid; }
   };
   let height = match header.height {
       Some(h) => h,
       None => { error!(...); return Validity::Invalid; }
   };
   ```

   The dead guard at `proposer.rs:610` should be promoted to run *first*,
   not last.

2. **Validate `FullProposal::height` in the validator path** before
   calling `shard_id()`. `ShardValidator::add_proposed_value` should
   handle the `Err` arm of `full_proposal.shard_id()` instead of
   panicking. Treat a `FullProposal` with no `height` as
   `Validity::Invalid` and return.

3. **Verify the proposer signature first.** The two `// TODO: Validate
   proposer signature?` comments at `proposer.rs:258` and `:650` indicate
   that even the *origin* of the proposal is unauthenticated at this
   layer. Combined with (1) and (2), a signed envelope check should run
   before any header dereferencing so that only authenticated validators
   can even reach the parsing path.

4. **Fix the genesis parent-hash typo** at `proposer.rs:173`: replace
   `vec![0, 32]` with `vec![0; 32]` so the shard chunk's genesis parent
   matches the protocol's 32-byte hash invariant (and matches the block
   path at `proposer.rs:535`).

5. **Add fuzz / property tests** that feed `add_proposed_value` random
   `FullProposal` protos with arbitrary `None`-filled sub-fields and
   assert that *no input* causes a panic — only `Validity::Invalid`
   returns.
