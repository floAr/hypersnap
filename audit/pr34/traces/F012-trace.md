# F012 trace — block/chunk `hash` (signed consensus value) never re-derived from blake3(header) on the read-node decided-value path

Pinned commit `cab225f`. Code read-only under `code/hypersnap`.

This trace follows the SURVIVING vector per the validator: not "arbitrary
body committed verbatim" (the V9+ commit path replays + enforces the state
root), but the substitution of an *alternate, self-consistent* `(header, body)`
pair — a valid state transition reproducing the header's root — whose
`blake3(header)` differs from the honest signed value `H`, with its `hash`
field forced to `H` and the honest `Commits` embedded. `verify_signatures`
passes (quorum signed `H`), the replay passes (body→header root is internally
consistent), and the read node finalizes a `(header, body)` pair that no
validator ever signed. No code on this path ever re-derives `blake3(header)`
and compares it to the signed `hash`.

## Entry point(s) (file:line)

Two peer-controlled ingress points deliver an attacker-framed `proto::DecidedValue`:

- Gossip: `src/main.rs:949-950` — `SystemMessage::DecidedValueForReadNode(decided_value)`
  → `node.dispatch_decided_value(decided_value)`
  (`src/node/snapchain_read_node.rs:189`). The frame is peer-controlled
  (decided-values gossip topic).
- Sync (state-sync `ValueResponse`):
  `src/consensus/malachite/read_sync.rs:344-361` — the block/chunk is decoded
  from peer-supplied `value_bytes`
  (`proto::Block::decode(value_bytes)` / `proto::ShardChunk::decode(...)`,
  `:350/:354`) and forwarded via
  `self.host.cast(ReadHostMsg::ProcessDecidedValue { value, ... })` at `:358`.
  Note `:358` is cast BEFORE and independently of the malachite sync
  certificate check `process_input(... ValueResponse ...)` at `:362`, so the
  read-validator commit path is not gated by any upstream `value_id == hash(value)`
  check. The embedded `commits` come from the decoded block itself, so the
  relayer controls block content and the embedded `Commits` independently.

## Trust boundary crossed

Network → finalized local state. A `DecidedValue` arriving from a remote peer
(gossip or sync) is the untrusted input; the sink persists it as the read
node's finalized block/chunk at height H. The only authentication applied is a
quorum-signature check over `commits.value` (the `ShardHash{hash}`), which the
attacker leaves untouched — they reuse a genuine honest `Commits`.

## Call path (ordered file:line hops)

1. `src/main.rs:950` `node.dispatch_decided_value(decided_value)` (gossip)
   — OR — `src/consensus/malachite/read_sync.rs:358`
   `host.cast(ReadHostMsg::ProcessDecidedValue { value, .. })` (sync).
2. `src/node/snapchain_read_node.rs:236` `actors.cast_decided_value(decided_value)`
   → `src/consensus/malachite/spawn_read_node.rs:139`
   `host_actor.cast(ReadHostMsg::ProcessDecidedValue { value, sync })`.
3. `src/consensus/malachite/read_host.rs:79-80`
   `ReadHostMsg::ProcessDecidedValue` → `state.validator.process_decided_value(value)`.
4. `src/consensus/read_validator.rs:214` `process_decided_value(value)`:
   - `:218` `get_decided_value_height` (reads `header.height` — F005 None-guard only).
   - `:228` `self.verify_signatures(&value)` — the ONLY authentication gate.
   - `:235` `validate_protocol_version` (checks `header.version` vs schedule; not hash).
   - `:249` `self.commit_decided_value(&value, height)` (when `height == last_height+1`).
5. `src/consensus/read_validator.rs:143-171` `verify_signatures`:
   - `:150-159` pulls `commits` from the block/chunk-embedded `commits` field.
   - `:170` `verify_signatures(&commits, &self.validator_sets)`
     → `src/core/util.rs:147-155`: rebuilds the precommit `Vote` from
     `certificate.value_id` (= `commits.value` = `ShardHash{hash}`) and verifies
     quorum Ed25519 signatures over `vote.to_sign_bytes()`. **The verified bytes
     cover only height/round/`hash`. `block.hash`/`chunk.hash` is never compared
     to `blake3(header)`; `header`/body are never an input to this check.**
6. `src/consensus/read_validator.rs:49-93` `commit_decided_value`:
   - Shard: `:58` `shard_engine.commit_shard_chunk(&shard_chunk)`.
   - Block: `:76` `block_engine.commit_block(&block)`.
7. Sink (shard): `src/storage/store/engine.rs:2042` `commit_shard_chunk`:
   - `:2045` reads `header.shard_root`; `:2093-2105` `replay_proposal(... shard_root ...)`
     recomputes the trie and `panic!`s on root mismatch (`:2102-2104`).
   - This binds **body → header.shard_root**, but performs **no
     `blake3(header)` re-derivation** and never compares to `shard_chunk.hash`
     (the signed value). An alternate header whose `shard_root` is reproduced by
     the attacker's body passes; its `blake3(header)` need not equal `H`.
   - Sink (block): `src/storage/store/block_engine.rs:commit_block` replays via
     `replay_proposal` under `ProtocolFeature::WriteDataToShardZero` (V9+, the
     live branch); same property — state root enforced, `blake3(header)` not.

## Attacker capability / preconditions

- Observe one genuine signed `Commits` for height H (the quorum precommit
  signatures over `ShardHash{hash: H}`), available on gossip/sync. The attacker
  does not forge any signature.
- Be a peer the victim read node ingests from (gossip on the decided-values
  topic, or a sync `ValueResponse` peer). No validator key required.
- Construct an alternate `(header_evil, body_evil)` that is a VALID state
  transition replayable against the victim's current trie at H-1 and reproduces
  `header_evil.shard_root`/`state_root` (so `replay_proposal` does not panic).
  Set `block.hash`/`chunk.hash = H` and embed the honest `Commits`.
  - This is the validator's narrowing: the body is NOT arbitrary; it must be a
    self-consistent, replay-valid transition. But `header_evil` may differ from
    the honest header in fields the replay does not re-derive
    (`parent_hash`, `events_hash`, `timestamp`), and in any case the whole
    `(header, body)` pair was never the one validators signed over (they signed
    `H = blake3(header_honest)`, and nothing ties `H` to `header_evil`).

## Guards on the path

- `verify_signatures` (`read_validator.rs:170` → `core/util.rs:125-161`): quorum
  + signer-set + per-signature Ed25519 over `value_id`. Passes — attacker reuses
  honest `Commits` and leaves `hash` = H untouched. Does NOT bind header/body.
- `validate_protocol_version` (`read_validator.rs:173-212`): checks
  `header.version` against the time-based schedule. Passes for a well-formed
  `header_evil`. Does not touch `hash`.
- F005 None-guards (`get_decided_value_height`, oneof-variant drops): liveness
  guards only; no `blake3(header)` check.
- `replay_proposal` state-root enforcement (`engine.rs:2093-2105`;
  `block_engine.rs` V9+): binds body → header root, panicking on mismatch. This
  is the guard that defeats the finding's original "arbitrary body" framing, but
  it does NOT close the header→signed-value gap — it never re-derives
  `blake3(header)` nor compares against `shard_chunk.hash`/`block.hash`.
- **Absent guard (root cause):** No call site on the receive/commit/read path
  re-derives `blake3(header.encode_to_vec())` and asserts it equals the signed
  `hash`. Grep of `src/consensus/**` for `blake3` returns only proposer-side
  CONSTRUCTION (`src/consensus/proposer.rs:185` shard, `:569` block) plus
  witness-hash sites — no verification site exists.

## Reachability verdict

REACHABLE (constrained). The path entry-point → sink is fully wired in
production (gossip via `main.rs:950`; sync via `read_sync.rs:358`; both reach
`read_validator::process_decided_value` → `commit_decided_value` → engine
commit). The signature gate passes on attacker-reused honest `Commits`; no guard
on the path re-derives `blake3(header)` from the committed header to bind it to
the signed value `H`. A read node therefore finalizes a `(header_evil, body_evil)`
pair that no validator signed.

Justification / scope of harm: the unconstrained "arbitrary finalized state"
outcome is NOT reachable on the live (V9+) path — `replay_proposal` forces the
committed body to be a valid transition reproducing the header's state/shard
root, panicking otherwise. The reachable harm is (i) read-path safety divergence:
the read node accepts an alternate self-consistent block the validator quorum
never endorsed, and (ii) header-field forgery in fields the replay does not
re-derive (`parent_hash`, `events_hash`, `timestamp`) while still matching the
replayed root, corrupting the canonical hash/parent-link identity
(`parent_hash = previous_block.hash`, proposer.rs:542, is built from the
never-re-derived `hash`). Verdict consistent with validation HAS_CAVEATS
(confidence 0.6): the header→signed-value binding gap is real and reachable; the
exploit envelope is narrower than the finding's original "arbitrary content"
wording.
