# F009 trace — slashing predicate keys "conflict" on signature-inclusive block hash

Stage: trace (reachability only; verdict unchanged — see `findings/notes/F009-validation.md`,
HAS_CAVEATS / 0.6). Commit `cab225f`. All paths under `code/hypersnap`.

## What this trace establishes

The structural defect is real and the *gate path* is fully wired and
remotely reachable: a gossiped `Evidence` frame carrying two `HyperBlock`s
flows entry→sink (detect → verify → record → epoch-boundary slash) with **no
signed-payload comparison anywhere**. What is NOT demonstrably reachable in
this tree is the *benign collision precondition* — i.e. an in-tree producer
that legitimately emits two distinct-but-valid threshold signatures over an
identical `signing_payload` at one `canonical_block_id`. That precondition is
latent. Both facts are traced below.

## Entry point(s)

- **Remote, peer-supplied:** `gossip_adapter.rs:96-101` —
  `proto::hyper_wire_message::Body::Evidence(e)` decodes `e.block_a` /
  `e.block_b` into two `HyperBlock`s and emits
  `HyperActorEvent::InboundEvidence { block_a, block_b }`. The two blocks are
  attacker-chosen wire bytes; no relation between them is checked here.
- **Actor dispatch (sink-entry):** `actor.rs:1587`
  `HyperActorEvent::InboundEvidence => detect_conflicting_blocks(&block_a, &block_b)?`.
- **Enforcement read-side (terminal sink):** `runtime.rs:4191`
  `slashed_validators_for_epoch(...)`, invoked at the epoch boundary.

## Trust boundary crossed

Network → node. The `Evidence` frame arrives over gossip from any peer.
`gossip_adapter.rs` performs only structural decode (`decode_hyper_block`);
it does not authenticate the *submitter* and does not compare the two blocks'
signed content. Authenticity is deferred to `verify_evidence_signatures`,
which (correctly) checks each block's signature against its own epoch group
key — but that check passes for two genuinely-signed blocks and never asks
whether they committed to the *same* payload. So a frame of two
benign-but-distinctly-signed blocks crosses the boundary as authoritative.

## Call path (ordered file:line hops)

1. `gossip_adapter.rs:96` — wire `Evidence` body received from peer.
2. `gossip_adapter.rs:97-100` — `block_a`/`block_b` decoded from peer bytes.
3. `gossip_adapter.rs:101` — emit `HyperActorEvent::InboundEvidence`.
4. `actor.rs:1587-1588` — dispatch calls `detect_conflicting_blocks(&block_a, &block_b)`.
5. `slashing.rs:56-60` — height gate: `canonical_block_id` equality (passes for same height).
6. `slashing.rs:62-66` — **the defect:** `hash_a = hyper_block_hash(a)`,
   `hash_b = hyper_block_hash(b)`; conflict declared iff `hash_a != hash_b`.
   No `signing_payload` comparison.
7. `chain.rs:25-44` — `hyper_block_hash` folds `signature.epoch`,
   `signature.group_address` (l.36-37) and `signature.ecdsa_signature`
   (l.38-39) into the digest. Two valid sigs over identical metadata →
   different hashes → `Ok(evidence)` (slashing.rs:68-76).
   (Contrast: `mod.rs:403-452` `signing_payload` excludes the signature, so
   the *signed content* is identical.)
8. `actor.rs:1589-1601` — dedupe key is `(min_epoch, lo_hash, hi_hash)`;
   distinct sig bytes ⇒ distinct hashes ⇒ not deduped.
9. `actor.rs:1605-1607` — `verify_evidence_signatures(...)`.
10. `slashing.rs:93-109` — each block verified against its OWN epoch group
    key over its OWN `signing_payload` (l.98-101). Two genuinely-signed
    blocks both pass; no cross-block payload equality test.
11. `actor.rs:1608` — `runtime.record_evidence(&evidence)` persists the pair.
12. (epoch boundary) `runtime.rs:4191` — `slashed_validators_for_epoch`.
13. `runtime.rs:4199-4226` — iterates BOTH `ev.block_a`/`ev.block_b`, reads
    each `signature.signer_indices` (l.4217), resolves to validator keys via
    the epoch active set, inserts into `slashed`. Purely index-driven; no
    re-check of payload, state-root, or content distinctness.
14. Sink: the honest committee that signed both blocks is returned in the
    slashed set.

## Attacker capability / preconditions

Gate path (steps 1-14) requires only: **gossip-peer reach** (publish an
`Evidence` frame) PLUS possession of two `HyperBlock`s that (i) share
`canonical_block_id`, (ii) each carry a valid epoch-group threshold
signature, (iii) differ in `ecdsa_signature`/`group_address` bytes. Given
two such blocks, no key compromise and no validator role are needed to drive
the slash.

The load-bearing precondition is **(iii) two distinct valid sigs over the
SAME signed payload.** Assessment of whether that is producible in this tree:

- **DKLS recovery-id restart (finding's primary trigger):** The finding
  claims recovery_id ∈ {2,3} "occurs ~50% of the time" forcing a ceremony
  re-run that yields a second signature. This is contradicted by the code:
  recovery_id ∈ {2,3} (R.x ≥ curve order) has probability ~2⁻¹²⁸ per attempt
  (`crates/hypersnap-crypto/src/dkls_sign.rs:464`, `dkls_threshold.rs:439`).
  The ~50% figure conflates low-s EIP-2 normalization (`s' = n-s;
  recovery_id ^= 1`, `bridge_payload.rs:30-32`), which is a deterministic
  in-place fixup of the SAME signature, not a re-run. Furthermore the
  rejected attempt returns `Err(RecoveryIdOutOfRange)` BEFORE any
  `EcdsaSignature` is materialized (`dkls_sign.rs:417-426`); only the final
  accepted sig is finalized into a block (`actor.rs:1574-1581`). The attacker
  cannot "retain sig1" — there is no sig1 object. **Not reachable as stated.**

- **Consensus round-retry / re-proposal:** This codebase's producer is a
  fixed-cadence single-proposer scheduler with round hardcoded to 0
  (`scheduler.rs:167`), `next_height()` advancing only on observed
  `BroadcastBlock` (`scheduler.rs:222-228`). A repeated `ProduceBlockDkls`
  for an unfinalized height recomputes the SAME digest and overwrites
  `pending_dkls_blocks[digest]` (`actor.rs:2698`); only the finalized sig is
  ever attached and broadcast (`actor.rs:2761-2790`). No wired path emits two
  finalized, differently-signed blocks for one height. **Not demonstrated.**

- **Insider harvesting:** A single byzantine committee member cannot
  unilaterally produce a t-of-n threshold signature; honest co-signers run
  exactly one ceremony per height (scheduler→finalize) and have no wired path
  to voluntarily co-sign a second ceremony for an already-decided payload.
  So even an insider cannot harvest two valid sigs over one payload through
  the wired protocol. **Not demonstrated.**

Net: there is **no in-tree producer** of the benign collision. The harm is
latent — the predicate would mis-slash IF such a pair existed, but the tree
provides no path that creates one.

## Guards on the path

- `slashing.rs:56-60` height gate — does not help (collision is same height).
- `slashing.rs:64-65` `SameBlock` (byte-identical) reject — bypassed: the
  two benign blocks differ in signature bytes, so they are NOT byte-identical.
- `actor.rs:1598-1601` replay dedupe — bypassed: keyed on the
  signature-inclusive hashes, which differ.
- `actor.rs:1605` / `slashing.rs:89-110` `verify_evidence_signatures` — the
  one real authenticity guard; it confirms both sigs are genuine but, by
  design, does NOT compare signed payloads, so it admits the benign pair.
- `runtime.rs:4199-4226` enforcement — no content/payload/state-root
  re-check; index-driven only. No guard here either.
- **Missing guard (root cause):** nowhere on the path is
  `a.signing_payload(...)` compared to `b.signing_payload(...)`. That single
  comparison would reject the benign collision.

## Reachability verdict

**REMOTE-UNAUTH (gate path) — but harm is LATENT / precondition UNPROVEN in-tree.**

Justification: The detect→verify→record→slash chain is reachable by any
gossip peer with no authentication and no validator/committee role (steps
1-14 are fully wired; `verify_evidence_signatures` is the only auth and it is
payload-blind). However, exploitation additionally requires two valid
threshold signatures over an identical `signing_payload` at one
`canonical_block_id`, and **no in-tree producer generates such a pair**: the
recovery-id-restart trigger is ~2⁻¹²⁸ (not ~50%) and never materializes a
retained second signature; the round-retry trigger is not wired in this
round-0 fixed-cadence producer; and a lone insider cannot harvest a second
threshold signature unilaterally. The predicate defect is genuine and
production-live, but its trigger is presently latent: it would be weaponized
the moment any future/off-path component (alternate signing client,
re-sign-on-restart recovery, multi-region producer, protocol evolution)
legitimately emits a second valid signature over an already-decided payload.
Classify the wired reach as REMOTE-UNAUTH; classify the end-to-end harm as
latent/defense-in-depth pending an in-tree benign-collision producer.

## Relevant files

- `code/hypersnap/src/hyper/gossip_adapter.rs:96-101` (remote entry)
- `code/hypersnap/src/hyper/actor.rs:1587-1620` (dispatch / dedupe / verify / record)
- `code/hypersnap/src/hyper/slashing.rs:56-66` (defective conflict predicate), `:89-110` (payload-blind verify)
- `code/hypersnap/src/hyper/chain.rs:25-44` (signature-inclusive `hyper_block_hash`)
- `code/hypersnap/src/hyper/mod.rs:403-452` (signature-excluding `signing_payload`)
- `code/hypersnap/src/hyper/runtime.rs:4191-4229` (index-driven enforcement sink)
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs:417-426,464` (recovery-id ~2⁻¹²⁸; no retained second sig)
- `code/hypersnap/src/hyper/scheduler.rs:167,222-228` (round-0 fixed-cadence producer — no re-proposal)
