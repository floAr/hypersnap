---
id: F151
task: H151
attack_class: serialization-boundary
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-23T00:00:00Z
  note: "All 9 panic triggers (a-i) reach unfiltered from gossip / sync request-response without consensus-key auth. Sibling-to-F002 attribution is correct: different impl Codec<...> blocks, different channels, different actor crash radius. No upstream gate, no spec carve-out, HEAD matches pin. PoC not supplied (H8 NEEDS_MORE_DATA) — strongly recommended for the 9-case omnibus. See findings/notes/F151-validation.md."
---

# F151 — `SnapchainCodec` decode panics on peer-controlled `Vote` / `Proposal` / sync-`Commits` fields (Channel::Consensus and Channel::Sync DoS surface, distinct from F002's Channel::ProposalParts path)

- **Task ID:** H151
- **Attack class:** serialization-boundary
- **Severity (draft):** High
- **Status:** draft

## Summary

The Malachite consensus codec (`SnapchainCodec`) decodes peer-supplied
gossip and sync messages and immediately calls into helper conversion
functions (`Vote::from_proto`, `Proposal::from_proto`, `Address::from_vec`,
`Commits::to_commit_certificate`) that `unwrap()` or `copy_from_slice`
on attacker-controlled `Option`/length-variable fields. Decoding is
invoked from network tasks **before any consensus-layer signature
verification**, so any peer subscribed to the gossip mesh can publish
a malformed `ConsensusMessage` / `SyncResponse` and crash receiving
validators and read-nodes.

This is a sibling of F002 (which documented panics on the
`Channel::ProposalParts` path in `add_proposed_value` and called out
`snapchain_codec.rs:106` as a single related codec panic site). The
present finding covers a **larger, structurally separate** panic
surface in the same file:

- `Channel::Consensus` (Vote/Proposal gossip) — completely unaddressed by F002.
- `Channel::Sync` `VoteSetResponse` (peer sync replies) — unaddressed by F002.
- `Channel::Sync` `ValueResponse` `Commits` conversion — unaddressed by F002.

All three sit in `snapchain_codec.rs::decode` and reach distinct panic
sites in `core/types.rs`. Remediation is the same shape (validate
optionals, validate lengths, propagate a `SnapchainCodecError` instead
of panicking), but the call graph and exposed channels are different
from F002's, so it warrants tracking as its own finding (and patch
landing).

## Affected files

- `code/hypersnap/src/consensus/malachite/snapchain_codec.rs:34-56` — `Codec<SignedConsensusMsg<...>>::decode` (Vote/Proposal gossip)
- `code/hypersnap/src/consensus/malachite/snapchain_codec.rs:217-265` — `Codec<sync::Response<...>>::decode` (ValueResponse + VoteSetResponse)
- `code/hypersnap/src/consensus/malachite/snapchain_codec.rs:232` — `commits.to_commit_certificate()` on peer-supplied Commits
- `code/hypersnap/src/consensus/malachite/snapchain_codec.rs:246-254` — vote-set decode loop iterating into `Vote::from_proto`
- `code/hypersnap/src/core/types.rs:430-447` — `Vote::from_proto` (panics)
- `code/hypersnap/src/core/types.rs:474-482` — `Proposal::from_proto` (panics)
- `code/hypersnap/src/core/types.rs:74-78` — `Address::from_vec` (panics on wrong length)
- `code/hypersnap/src/core/types.rs:720-742` — `Commits::to_commit_certificate` (panics)
- `code/hypersnap/src/consensus/malachite/network_connector.rs:192-209` — Channel::Consensus invocation of codec
- `code/hypersnap/src/consensus/malachite/network_connector.rs:232-254` — Channel::Sync status invocation
- `code/hypersnap/src/consensus/malachite/network_connector.rs:308` — sync ValueResponse handling
- `code/hypersnap/proto/definitions/blocks.proto:40-46` — Vote proto (height/value optional, voter bytes unconstrained)
- `code/hypersnap/proto/definitions/blocks.proto:62-70` — Proposal proto (height/value optional, proposer bytes unconstrained)

## Concrete panic sites and triggers

### 1. Vote decode (Channel::Consensus) — `Vote::from_proto`

```
// snapchain_codec.rs:40-44
Some(consensus_message::ConsensusMessage::Vote(vote)) => {
    Ok(SignedConsensusMsg::Vote(SignedVote {
        message: Vote::from_proto(vote),
        signature: Signature(message.signature),
    }))
}
```

`Vote::from_proto` (core/types.rs:430-447) panics on three peer-controlled inputs:

```
// core/types.rs:431-447
pub fn from_proto(proto: proto::Vote) -> Self {
    let vote_type = match proto.r#type {
        0 => VoteType::Prevote,
        1 => VoteType::Precommit,
        _ => panic!("Invalid vote type"),          // (a) panic on type != {0,1}
    };
    let shard_hash = match proto.value {
        None => NilOrVal::Nil,
        Some(value) => NilOrVal::Val(value),
    };
    Self {
        vote_type,
        height: proto.height.unwrap(),             // (b) panic on missing height
        round: Round::from(proto.round),
        voter: Address::from_vec(proto.voter),     // (c) panic if voter.len() != 32
        shard_hash,
    }
}
```

`Address::from_vec` (core/types.rs:74-78) uses `copy_from_slice` against a fixed-32 buffer:

```
pub fn from_vec(vec: Vec<u8>) -> Self {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&vec);                   // panics if vec.len() != 32
    Self(bytes)
}
```

Three peer-craftable wire forms therefore crash the receiver:
- (a) `Vote.type = 2` (or any unknown enum tag; `prost` decodes enum-as-i32 verbatim).
- (b) `Vote.height = None` (omit field 2 — Height is a message-valued field, so absence is valid wire encoding).
- (c) `Vote.voter` with `len != 32` (proto type is `bytes`, no length constraint; trivially craftable as empty or 16 bytes).

### 2. Proposal decode (Channel::Consensus) — `Proposal::from_proto`

```
// snapchain_codec.rs:46-50
Some(consensus_message::ConsensusMessage::Proposal(proposal)) => {
    Ok(SignedConsensusMsg::Proposal(SignedProposal {
        message: Proposal::from_proto(proposal),
        signature: Signature(message.signature),
    }))
}
```

`Proposal::from_proto` (core/types.rs:474-482):

```
pub fn from_proto(proto: proto::Proposal) -> Self {
    Self {
        height: proto.height.unwrap(),             // (d) panic on missing height
        round: Round::from(proto.round),
        shard_hash: proto.value.unwrap(),          // (e) panic on missing value
        pol_round: Round::from(proto.pol_round),
        proposer: Address::from_vec(proto.proposer), // (f) panic if proposer.len() != 32
    }
}
```

Three additional peer-craftable wire forms crash the receiver:
- (d) `Proposal.height = None`.
- (e) `Proposal.value = None` (`ShardHash` is message-valued, absence allowed).
- (f) `Proposal.proposer.len() != 32`.

### 3. Sync VoteSetResponse decode — fan-out of (a)/(b)/(c)

`snapchain_codec.rs:246-254` decodes the vote-set:

```rust
let signed_votes = vote_set
    .votes
    .into_iter()
    .zip(vote_set.signatures)
    .map(|(vote, signature)| SignedVote {
        message: Vote::from_proto(vote),           // each peer-supplied Vote
        signature: Signature(signature),
    })
    .collect();
```

Any single malformed `Vote` element triggers panic (a), (b), or (c).
A peer answering a `SyncVoteSetRequest` can therefore crash the
requester by including one malformed vote alongside any number of
well-formed ones. The same panic class is reached as in case 1, but
the channel is `Channel::Sync` (sync-protocol response delivery) rather
than the consensus gossip channel — different network task, different
upstream gate, same crash.

Secondary issue in this loop: `votes.zip(signatures)` silently truncates
to the shorter `Vec`. A peer can send 100 votes and 1 signature (or
vice-versa) and the decoder silently drops the unpaired entries with no
error. This is not a panic, but it is a silent encoding asymmetry — the
on-wire schema asserts a one-to-one pairing that the codec does not
enforce. (Downstream signature verification rejects mismatches, so this
sub-issue is not exploitable for forgery on its own, but it is a real
serialization-boundary defect.)

### 4. Sync ValueResponse decode — `Commits::to_commit_certificate`

`snapchain_codec.rs:227-243`:

```
proto::sync_response::SyncResponse::Value(value) => {
    let commits = value.commits.ok_or_else(...)?;
    let commit_certificate = commits.to_commit_certificate(); // panics inside
    ...
}
```

`Commits::to_commit_certificate` (core/types.rs:720-742):

```rust
let height = self.height.unwrap();                 // (g) panic on missing height
let round = Round::from(self.round);
let value_id = self.value.clone().unwrap();        // (h) panic on missing value
let signatures = self.signatures.iter().map(|commit| CommitSignature {
    address: Address::from_vec(commit.signer.clone()),  // (i) panic if signer.len() != 32
    signature: Signature(commit.signature.clone()),
}).collect();
```

A peer answering `SyncValueRequest` can crash the requester with a
`Commits` whose `height`, `value`, or any single `signatures[i].signer`
is malformed.

This same `Commits::to_commit_certificate` is also reached from
`read_validator.rs:231/244` and `host.rs:332/336` (DecidedValue commits)
and from `util.rs:103` (post-block signature verify). All four call
sites trust the field-presence shape — but the codec is the
earliest, network-edge instance, and the only one reachable from
arbitrary peers without prior signature gating.

## Reachability — concrete trace per channel

### Channel::Consensus (cases a/b/c/d/e/f)

1. Attacker is a peer subscribed to `CONSENSUS_TOPIC` gossipsub mesh.
   Gossipsub strict mode authenticates the libp2p peer-id only, not
   the consensus validator-key — same precondition F002 validation
   documented at `findings/notes/F002-validation.md:36-39,107-108`
   (`src/network/gossip.rs:283-296`).
2. Attacker publishes a `ConsensusMessage` proto with
   `consensus_message = Vote(Vote { type: 2, .. })` (case a) or any
   other malformed variant from §1–§2 above.
3. Receiver dispatch lands in
   `network_connector.rs:192-209`:
   `self.codec.decode(data)` → `SnapchainCodec::decode` →
   `Vote::from_proto(vote)` → panic.
4. The codec panic occurs inside the network task. Per F002 validation
   §H2: panic in the network/host actor aborts the actor; the in-flight
   value is lost; a malicious peer can replay the message and cause
   repeated actor restarts, effectively DoS'ing consensus on the
   shard. (Same supervisor-restart caveat as F002 — but in this case
   the panic is in the codec callsite owned by the network task, not
   the host actor's `add_proposed_value`. The crash radius therefore
   covers a *different* set of consensus actors: anything wired to the
   gossip output port.)

### Channel::Sync (cases g/h/i + vote-set fan-out)

1. Attacker is a peer that the local node has selected as a sync
   source (or one that responds to a broadcast sync request).
2. Attacker sends a `SyncResponse` containing a malformed `Commits`
   (case g/h/i) or a malformed embedded `Vote` (cases a/b/c via
   `VoteSetResponse.votes`).
3. Receiver dispatch at `network_connector.rs:308`-ish lands in
   `Codec<sync::Response>::decode` → either
   `commits.to_commit_certificate()` (panic) or `Vote::from_proto`
   in the `zip` loop (panic).

A read-node syncing initial state from a malicious archival peer is
crashed before it ever finishes catching up. Sync-stalling alone is a
liveness-loss vector, and the panic worsens it by tearing down the
sync actor.

## Why this is not already covered by F002 / F005

- **F002** covers `add_proposed_value` (inner unwraps on
  `ProposedValue::Shard(chunk).header` / `Block(block).header`) and
  `snapchain_codec.rs:106` (outer `proposal.height.unwrap()` inside
  `Codec<StreamMessage<FullProposal>>::decode`, the proposal-parts
  channel). F002 explicitly does **not** cover the
  `Codec<SignedConsensusMsg>` or `Codec<sync::Response>` impls, and
  it does **not** cover `Vote::from_proto` / `Proposal::from_proto`
  / `Address::from_vec` / `Commits::to_commit_certificate`. The F002
  validation note "open follow-ups #1" recommends folding the
  `snapchain_codec.rs:106` outer-height panic into F002 but does
  **not** mention the additional panic sites enumerated here.
- **F005** covers a *different* protocol-version panic — read-validator
  `DecidedValue.value` unknown-oneof unwrap in
  `core/util.rs::verify_signatures` and
  `core/message.rs::get_decided_value_height`. It does not touch the
  consensus-msg or sync-response codec paths.

The cleanest remediation packages F002 + F151 together as
"all peer-controlled `Option`/length-variable unwraps in the codec
and proto conversion helpers" — but the channels, attacker
prerequisites, and crashed actor identities differ between F002 and
F151, so they should track as separate findings until the patch lands.

## Secondary observation — non-fatal serialization-boundary defects

While auditing this file, two non-fatal serialization-boundary issues
were observed and are recorded here for downstream consideration
(they are not the primary claim of F151):

### S1. `Codec<StreamMessage<FullProposal>>::encode` drops stream metadata

`snapchain_codec.rs:103-125`. The decode synthesizes
`StreamId = height || round`, `sequence = 0`,
`content = StreamContent::Data(proposal)`. The encode emits only the
inner `FullProposal` proto bytes, discarding stream_id, sequence, and
content-variant. `encode(decode(b)) != b` for all `b` that re-encode
differently from the inner proto — but more importantly, this codec
breaks Malachite's `StreamMessage` abstraction by silently dropping
the multi-part proposal sequence number. Works in practice because the
proposer always sends single-part proposals (the source-code comment
at line 99 acknowledges this), but the codec lies to its consumer
about what's been serialized. If a future change introduces multi-part
proposals (e.g., for large transaction batches), this will silently
corrupt sequence ordering.

### S2. Vote / Proposal signing payload has no chain-id / network-id binding

`core/types.rs:449-451` and `:483-486`:

```
pub fn to_sign_bytes(&self) -> Vec<u8> {
    self.to_proto().encode_to_vec()
}
```

The signed payload is `Vote{type, height={shard_index, block_number},
round, voter, value}` or `Proposal{height, round, pol_round, proposer,
value}`. Neither carries any FarcasterNetwork / chain-id discriminator,
even though `BlockHeader` does carry `FarcasterNetwork chain_id`
(`blocks.proto:139`). A `value = NilOrVal::Nil` precommit (the
nil-block case) is therefore identical across any two networks that
share `shard_index` and `block_number` — a validator-key reused across
networks would yield a valid cross-network nil-precommit signature.
This is a sibling of F101 / F104 / F105's chain-id-binding theme but
at the consensus signing-payload layer. Tracking here for visibility;
a separate finding would be appropriate if validator-key reuse across
networks is in the threat model.

## Suggested remediation (per primary panic class)

1. Change `Vote::from_proto` and `Proposal::from_proto` to
   `TryFrom<proto::Vote>` / `TryFrom<proto::Proposal>` returning
   `Result<Self, SnapchainCodecError::InvalidField>`. The codec
   already has the `InvalidField(String)` variant; the
   `SignedConsensusMsg` decode arms should call `try_from` and `?`
   the error, returning a codec error instead of panicking.
2. `Address::from_vec` should return `Result<Self, _>` and assert
   `vec.len() == 32` explicitly. Every caller in `from_proto` /
   `to_commit_certificate` should propagate the error.
3. `Commits::to_commit_certificate` should likewise be fallible;
   `snapchain_codec.rs:232` should `?` the result rather than calling
   it directly.
4. Reject unknown `VoteType` enum tags at the proto-conversion layer
   (return `Err`, not `panic!`).
5. Enforce `votes.len() == signatures.len()` in `VoteSetResponse`
   decode — return `InvalidField` on mismatch instead of silently
   truncating.

## Severity rationale

High (liveness / DoS). Remote-triggerable panic by any subscribed
gossip peer; no prior signature verification gate; affects the
consensus gossip channel (which validators must subscribe to in order
to participate) and the sync channel (which catching-up nodes must
trust to make progress). The blast radius is the entire fleet of
nodes that share a gossip mesh with the attacker. Not credit-loss or
value-extraction, but it is a clean and cheap consensus-halt vector
that does not require any compromised validator key.

(Severity matches F002, which got "high" for the analogous panic
class on the proposal-parts channel.)
