# F012 validation — red-team walk

Finding: Block/ShardChunk `hash` (the Malachite-signed consensus value) is never
re-derived from `blake3(header)` on any receive/validate/commit path, decoupling
the signed value from the header+body that actually get committed.

Validator role: deliberate disagreement. Pinned commit `cab225f`.

## Core technical claim — CONFIRMED

- `blake3(...)` over a header appears ONLY in proposer *construction*
  (`src/consensus/proposer.rs:185` shard, `:569` block). Grep of
  `src/consensus/**` for `blake3` returns only those two construction sites plus
  witness-hash sites — there is **no** `hash == blake3(header)` re-derivation on
  any validate/commit/read path. (Grep confirmed.)
- The signed value is the raw `hash` field: `FullProposal::shard_hash()`
  (`proto/src/lib.rs:147-161`) returns `ShardHash { hash: block.hash | chunk.hash }`,
  and `verify_signatures` (`src/core/util.rs:147-155`) builds the precommit `Vote`
  from `certificate.value_id` = `commits.value` = that `ShardHash`. Nothing ties
  `commits.value.hash` to `block.hash`, nor `block.hash` to `blake3(header)`.
- `read_validator::verify_signatures` (`src/consensus/read_validator.rs:150-170`)
  uses the **block-embedded** `block.commits` (not the sync certificate), so a
  relayer independently controls block content and the embedded Commits. It only
  proves a quorum signed `commits.value`; it never compares to `block.hash` or
  `blake3(header)`.
- `parent_hash = previous_block.hash` (`proposer.rs:542`) — the canonical chain
  link is built from the never-re-derived `hash`. Claim holds.

So the "missing blake3(header) re-derivation" mechanic is real and present at the
pinned commit. The disagreement is about **impact magnitude**, driven by H2/H3/H6.

## 8-hypothesis walk

### H1 — Upstream auth / gate. PARTIALLY INVALIDATED (impact-narrowing)
On the sync path the decided block is forwarded to `ProcessDecidedValue`
(`read_sync.rs:358`) independently of the malachite sync state machine's
certificate check (the `ProcessDecidedValue` cast at :358 precedes and is not
gated by `process_input(... ValueResponse ...)` at :362). So there is no upstream
malachite "value_id == hash(value)" gate that saves the read path. The gossip
path (`spawn_read_node.rs:139`) is likewise ungated. H1 does NOT save the finding.
STANDS on whether a gate exists; noted here because it is the first place a
reviewer would look.

### H2 — Consumer-side impact. PARTIALLY INVALIDATED (significant)
The finding's strongest wording — "the read node commits the forged header + body
to its store with no re-derivation and **no state replay**" (lines 73-74, 100-101,
118-121) — is **incorrect at this commit for the live version**. Both commit
sinks replay and enforce the state root:
- `ShardEngine::commit_shard_chunk` (`engine.rs:2042`) always calls
  `replay_proposal` (`engine.rs:525`), which recomputes the trie and returns
  `EngineError::HashMismatch` if `root1 != shard_root` (`:593-605`); the caller
  `panic!`s on `Err` (`:2102-2104`). Body is bound to header's `shard_root`.
- `BlockEngine::commit_block` (`block_engine.rs:916`) replays via
  `replay_proposal` whenever `ProtocolFeature::WriteDataToShardZero` is enabled
  (`:938`). That feature is `>= V9` (`version.rs:239`); mainnet is V9 since
  2025-09-10 and is V17 today (`version.rs:97,127-130`), so the replay branch is
  the live one. Only the legacy `else` branch (`:980-984`, pre-V9) does a verbatim
  `put_block` with no replay.

Consequence: an attacker **cannot** commit *arbitrary* body/state-root as the
finding claims. The committed body must be a *valid state transition from the read
node's current trie* that reproduces the header's `state_root`/`shard_root`.

What survives H2: the **header is still not bound to the signed `hash`.** An
attacker can craft an *alternate, internally self-consistent* (header, body) pair
— valid transition, matching root — whose `blake3(header)` differs from the signed
H, set its `hash` field = H, embed the honest Commits. Replay passes (consistent),
`verify_signatures` passes (signed H). The read node finalizes a block that no
validator endorsed. That content is attacker-*chosen* (they pick the messages) but
not fully arbitrary (must be a valid transition + replayable against current
state). This is still a read-path safety divergence, but the impact is narrower
than "finalize arbitrary attacker-chosen state root / events / parent link verbatim."

### H3 — Downstream enforcement. PARTIALLY INVALIDATED
The state-root replay (H2) is exactly the downstream layer that re-verifies what
the finding said "is committed verbatim." It does not close the header→hash gap,
but it does close the "body is arbitrary" half of the impact claim. The
`events_hash` / `parent_hash` portions of the header are *not* separately replayed
on the read path, so a header carrying a wrong `parent_hash` or `events_hash`
(while still matching the replayed state_root) is not caught — that residual is
real and supports a fork-link / events-divergence claim.

### H4 — PR HEAD currency. NEEDS_MORE_DATA (no drift evidence here)
Workspace is pinned at `cab225f`; the read path / proposer / version schedule were
all inspected at that commit. No newer HEAD was fetched (no network in scope). The
F005/F033/F185 fix comments already present in the code show this is a
post-hardening snapshot; none of those fixes add a `blake3(header)` check, so the
gap persists at the pinned commit. Treat as STANDS-at-pin.

### H5 — Spec carve-out. NEEDS_MORE_DATA → STANDS
No doc-comment, README, or SECURITY note found asserting "block.hash is trusted /
re-derivation intentionally deferred." The construction-only blake3 is presented as
the canonical identity, implying the invariant is assumed, not intentionally
skipped. No carve-out invalidates the finding.

### H6 — Reachability of harm. PARTIALLY INVALIDATED (impact-narrowing)
Reachable but constrained. The attack requires: (a) a real signed `Commits` for
height H (observable on gossip/sync — yes); (b) an alternate (header, body) that
*replays validly* against the victim read node's current state and reproduces a
matching `state_root`/`shard_root`. (b) is a non-trivial constraint the finding's
"arbitrary content" framing omits — the attacker must construct a valid state
transition (e.g. with their own valid messages), and it must replay against the
read node's exact trie at H-1. Within that envelope the harm (read node finalizes
a header the validators never signed; corrupted `parent_hash`/`events_hash`;
divergent chain identity) is real and reachable. The "full validators' canonical
hash chain is built from an unverified field" sub-claim is also reachable: all
honest nodes do agree on the same (header, hash=X) pair they each received, but
since X is never tied to blake3(header), nothing prevents a proposer from setting
X != blake3(header), permanently breaking the identity invariant on-chain.

### H7 — Test wiring. STANDS
`process_decided_value` → `commit_decided_value` → `commit_block` /
`commit_shard_chunk` is the production read-node path (`read_host.rs:79-80`,
`read_validator.rs:49-93`, :214-255), reached from both sync
(`read_sync.rs:358`) and gossip (`spawn_read_node.rs:139`). Not test-only.

### H8 — PoC mechanics. NEEDS_MORE_DATA
No executable PoC accompanies the finding. The prose attack (step 5: "commit
persists header_evil + forged body … no re-derivation of blake3(header_evil) is
ever performed") would, as written, FAIL at `replay_proposal`'s root check for any
body that does not reproduce the header's root — i.e. the literal "replace body
with arbitrary content" PoC would `panic`, not silently commit. A correct PoC must
use a *replay-valid* alternate block (see H2/H6). The header→hash decoupling itself
is provable (no blake3 check exists), but the "arbitrary content" assertion as
phrased does not hold against the live replay path.

## Overall verdict: HAS_CAVEATS (confidence 0.6)

The root mechanic — `block.hash`/`chunk.hash` (the signed consensus value) is
never re-derived from `blake3(header)` on any receive path — is CONFIRMED and
genuine. The header-to-signed-value binding is absent, enabling (i) a
fork/identity-link corruption where on-chain `hash` need not equal `blake3(header)`
and (ii) a read-node divergence where a relayer substitutes an alternate
self-consistent block carrying a valid quorum signature over a different content's
hash.

Caveats that materially reduce the stated impact:
1. The "no state replay, arbitrary body committed verbatim" claim is wrong for the
   live (V9+) version: both `commit_shard_chunk` and `commit_block` replay and
   enforce the state/shard root, panicking on mismatch. The attacker's body is
   constrained to a valid, replayable state transition — not arbitrary.
2. The verbatim-`put_block` no-replay path exists only pre-V9 (legacy), not the
   current network.
3. The exploit envelope (valid transition reproducing the header root, replayable
   against the victim's current trie) is narrower than "arbitrary attacker-chosen
   state root/events/parent link."

The finding should stand as a real header→signed-value binding gap with
fork-link/identity and read-path-divergence impact, but the impact section
("finalize arbitrary attacker-chosen block content … no re-derivation and no state
replay") is overstated and should be downgraded to "attacker-chosen *valid-
transition* content + arbitrary non-state-root header fields (parent_hash,
events_hash, timestamp)." Severity HIGH is defensible on the safety-divergence /
chain-identity grounds; the "arbitrary finalized state" framing is not.

## Open follow-ups (not new findings)
- `events_hash` and `parent_hash` portions of the header are not independently
  re-derived/verified on the read-node commit path even though the state_root is
  replayed; worth a dedicated look at whether a header with a forged
  `events_hash`/`parent_hash` (but matching state_root) is silently accepted.
- The sync `ValueResponse` handler decodes with `.unwrap()` on
  `proto::Block::decode(value_bytes)` (`read_sync.rs:350,354`) — peer-controlled
  bytes; orthogonal to F012 but a panic-DoS surface (likely already covered by an
  F005-family finding).
