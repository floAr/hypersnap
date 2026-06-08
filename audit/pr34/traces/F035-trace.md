# F035 — reachability trace

Finding: HyperLockEvent locks mint arbitrary wrapped value into the threshold-signed
verkle state root with no balance closure, range proof, or signature verification.
Commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`. Verdict (unchanged): HAS_CAVEATS.

This trace shows entry-point → sink reachability for the WEAK transparent-lock path.
It does not re-judge the verdict.

## Entry point(s)

Untrusted ingress is the proposer-supplied `locks` payload of a remote
`HyperWireBlock`, decoded from libp2p gossip:

- `src/hyper/gossip_adapter.rs:69-78` — `wire_to_event_with_source`, arm
  `Body::Block(b)`. The block body is decoded, but the lock list is taken
  **verbatim** from the wire frame:
  `HyperActorEvent::InboundBlock { block, locks: b.locks, transfers: b.transfers }`
  (line 75). `b.locks` is attacker-controlled bytes (`Vec<proto::HyperLockEvent>`)
  and is NOT cross-checked against the local mempool.

The malicious value is the plaintext `amount` (and `dest_address`) of each
`HyperLockEvent` the proposer places in `b.locks`.

## Trust boundary crossed

Network → consensus/state. A remote peer's gossip frame (the block proposer's
`HyperWireBlock`) crosses into the local node's state-transition machinery. The
only authenticity the node demands downstream is the block-level threshold ECDSA
signature over the metadata; the *contents* of `locks_in_block` are trusted to be
what an honest proposer would have produced. Per-lock authenticity / balance is on
the far side of this boundary and is never re-established.

## Call path (block ingress → verkle-state-root sink)

1. `src/hyper/gossip_adapter.rs:69-78` — `wire_to_event_with_source`
   (`Body::Block`): emits `InboundBlock { locks: b.locks, .. }`. Attacker bytes
   enter as `locks`.

2. `src/hyper/actor.rs:1241-1248` — `HyperActor` event loop, `InboundBlock` arm:
   `self.runtime.import_block(&block, &locks, &transfers)?` (line 1248). Forwards
   the untrusted `locks` slice unchanged into the runtime.

3. `src/hyper/runtime.rs:4461-4535` — `HyperRuntime::import_block`. Resolves the
   epoch DKLS group address (4467-4469), then **re-validates every TRANSFER
   off-mempool** (4482-4524: `tx_from_proto` + `extract_blinding_diff` +
   `validate_against_store` (4511-4518) + `verify_balance_with_blinding_diff`
   (4519-4523) — Pedersen balance closure). **There is NO equivalent loop over
   `locks_in_block`.** Locks fall straight through to
   `import_hyper_block_with_index(.., locks_in_block, ..)` (4526-4535). This is the
   load-bearing asymmetry: transfers get balance closure here, locks get nothing.

4. `src/hyper/importer.rs:238-305` — `import_hyper_block(_with_index)`. Verifies
   ONLY (a) the block threshold ECDSA signature over the signing payload
   (`verify_hyperblock_signature`, 252-258) and (b) that the recomputed verkle root
   equals the proposer-stated `hyper_state_root` (285-292). Between those two it
   pushes every lock into the apply queue: `messages.push(PendingMessage::Lock(lock.clone()))`
   (263-265) and applies each via `builder.apply_message(msg)` (270-283). No
   per-lock signature, commitment, range proof, or balance check.

5. `src/hyper/builder.rs:113-118` — `HyperBlockBuilder::apply_message`,
   `PendingMessage::Lock(event)` arm: `insert_lock_into_tree(self.tree, event)?`.

6. `src/hyper/lock_event.rs:192-201` — `insert_lock_into_tree` (the SINK):
   - `validate_lock_event(event)?` (196) — the ONLY check ever run on a lock.
   - `let leaf = encode_lock_leaf(event);` (197) — serializes the plaintext
     `amount` (8B BE) into the verkle leaf.
   - `tree.insert(&key, leaf)` (199) — writes the attacker-chosen amount into a
     verkle-tree leaf. That tree's `root_commitment()` (importer.rs:285) is the
     `hyper_state_root` the threshold set signs.

   `validate_lock_event` (lock_event.rs:141-171) checks only `amount != 0`,
   `lock_id.len()==32`, non-empty `dest_address`/`spend_pubkey`, and EVM length
   conventions (158-168). It NEVER reads `lock_signature` and NEVER evaluates any
   `Σin − Σout − fee` relation. The module doc (lock_event.rs:1-14) states
   source-side balance enforcement is "a known gap" (Phase B-3).

Sink: the proposer-chosen plaintext `amount` is committed under the
threshold-signed verkle `hyper_state_root` with structural-only validation.

### Contrast — the strong path that DOES enforce closure (not on this trace)
- Transfers, same `import_block`: `runtime.rs:4482-4524` re-runs
  `validate_against_store` + `verify_balance_with_blinding_diff` (explicit comment
  4471-4478: "defends against a malicious proposer who included a transfer
  off-mempool").
- Confidential locks: `src/hyper/confidential_lock.rs:156-186`
  `validate_against_store` (Pedersen closure at 182, Schnorr at 171, nullifier at
  166), wired only via `runtime.rs:860-913` `apply_confidential_lock` — the only
  non-test writer of `TokenLockState`, which feeds `build_lock_merkle_tree`
  (runtime.rs:921). The transparent-lock verkle path bypasses all of this.

## Attacker capability / preconditions

- Requires being (or colluding with) the **block proposer**: the exploited
  `locks_in_block` comes from `b.locks` in the proposer's `HyperWireBlock`, and the
  block must carry a valid threshold ECDSA signature over the metadata (the verkle
  root). So the attacker must either be the proposer for that height or induce the
  threshold-signing set to sign a verkle root they did not independently audit per
  lock (locks carry no independently verifiable authenticity).
- Non-proposer peers CANNOT inject via mempool: F058 seals the transparent-lock
  ingress — `src/hyper/router.rs:133-142` rejects gossip/RPC `Body::Lock`
  ("transparent lock path removed; use ConfidentialLockBody") and
  `src/hyper/http_handler.rs:1706-1743` rejects HTTP-posted locks (mempool stays
  empty). BUT F058 does NOT seal the block-application path: `b.locks` from a remote
  `HyperWireBlock` bypasses the router entirely (gossip_adapter → InboundBlock →
  import_block). The proposer-inserted weak lock path remains live.

## Guards on the path and why they don't enforce balance closure

- `verify_hyperblock_signature` (importer.rs:252-258): authenticates the BLOCK
  (threshold ECDSA over metadata), not individual locks. A proposer who legitimately
  holds/obtains the signature passes it regardless of lock contents.
- Verkle-root equality check (importer.rs:285-292): only confirms the recomputed
  root equals the proposer-stated root. The lock leaf is a deterministic function of
  the event, so a balanced vs. unbalanced amount produce equally-valid roots — this
  check cannot distinguish them.
- `validate_lock_event` (lock_event.rs:141-171): structural only (amount≠0, lengths,
  EVM conventions). No Pedersen closure, no range proof, no `lock_signature` read.
- Wire-format gap: `HyperLockEvent` carries no input commitment, no `r_diff`
  blinding delta, and no range proof, so balance closure
  (`commit_in − (amount+fee)·B == r_diff·B_blinding`) is structurally impossible on
  this path even if a check were added. `lock_signature` (hyper.proto field) is read
  nowhere in production (every occurrence is a `vec![0u8; 64]` fixture or the
  unrelated block-level signature).

## Reachability verdict

**VALIDATOR(PROPOSER)** — reaching the verkle-leaf sink with an attacker-chosen,
balance-unenforced `amount` requires being or colluding with the block proposer (the
locks ride the proposer's signed `HyperWireBlock`); non-proposer mempool/gossip/HTTP
ingress is sealed by F058 (router.rs:133, http_handler.rs:1706).

Downstream caveat: the in-scope L1 `HypersnapBridge.claim` consumes the **keccak256
merkle** lock-tree root (`src/hyper/lock_tree.rs`, built only from balance-validated
`TokenLockState`s via `runtime.rs:921-932`), NOT the verkle `hyper_state_root` the
forged leaf lands in. So the demonstrated in-scope impact is threshold-signed
cross-chain state-root corruption / a latent mint primitive; live L1 fund-loss
depends on an out-of-scope L1 contract honoring verkle-inclusion claims.
