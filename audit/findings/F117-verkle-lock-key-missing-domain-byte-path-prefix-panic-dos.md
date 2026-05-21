---
id: F117
task: H117
attack_class: kzg-srs-or-verkle-encoding
severity: high
status: draft
---

# F117 — Verkle insertions for locks omit the 1-byte domain discriminator, allowing an attacker-chosen `lock_id` to collide with the path-prefix of a future nullifier or note-commitment insert and panic the block builder (consensus liveness DoS)

- **Task:** H117
- **Attack class:** kzg-srs-or-verkle-encoding (verkle-specific: path-prefix / key-length / domain-extension collision; "two distinct keys hash to the same path-prefix → silent overwrite" — here the failure mode is a noisy panic, not silent overwrite, but the panic is itself the DoS lever)
- **Severity (provisional):** High (any external party submitting a `HyperLockEvent` chooses the full 32-byte `lock_id`; by picking `lock_id = [0x02, n_0, ..., n_{30}, n_{30}]` for any nullifier `(n_0..n_{31})` an attacker can later observe being inserted, or by inserting a lock first and then waiting for that nullifier prefix to be transferred, every honest validator panics during `HyperBlockBuilder::apply_message` with `"verkle tree key length is inconsistent (parent is a leaf)"`; the panic is not caught by `apply_message`/`build_envelope`, propagates through the actor task, and kills the proposer/importer thread on every validator that re-applies the block. Same lock_id repeated by every validator → coordinated all-validators-dead halt.)
- **Status:** draft

## Scope files

- `code/hypersnap/crates/hypersnap-crypto/src/verkle.rs` — the 256-ary tree's `insert_recursive` / `prove_inclusion` / `verify_inclusion`
- `code/hypersnap/src/hyper/builder.rs` — defines the 1-byte domain prefixes (`KEY_DOMAIN_LOCK = 0x01`, `KEY_DOMAIN_NULLIFIER = 0x02`, `KEY_DOMAIN_NOTE_COMMITMENT = 0x03`) and the `nullifier_verkle_key` / `note_commitment_verkle_key` constructors
- `code/hypersnap/src/hyper/lock_event.rs` — `insert_lock_into_tree` (the actual production path; uses raw `lock_id`, **not** `lock_verkle_key`)

## Summary

The verkle tree in `crates/hypersnap-crypto/src/verkle.rs` is a depth-= 256-ary trie where each byte of the key selects a child slot, and key length determines tree depth (`verkle.rs:7-10`: *"a `k`-byte key produces a tree of depth `k`"*). When two keys have the property "one is a strict path-prefix of the other," the longer-key insert traverses through the spot where the shorter key has placed a `Leaf` and triggers a panic at one of two sites:

```rust
// verkle.rs:112-143
fn insert_recursive(node: &mut VerkleNode, key: &[u8], depth: usize, value: Vec<u8>) {
    if depth + 1 == key.len() {
        if let VerkleNode::Internal { children, commitment } = node {
            *commitment = None;
            children.insert(key[depth], Box::new(VerkleNode::Leaf { value }));
        } else {
            panic!("verkle tree key length is inconsistent (parent is a leaf)");  // (A)
        }
        return;
    }
    match node {
        VerkleNode::Internal { children, commitment } => {
            *commitment = None;
            let slot = key[depth];
            let child = children.entry(slot)
                .or_insert_with(|| Box::new(VerkleNode::new_internal()));
            Self::insert_recursive(child, key, depth + 1, value);
        }
        VerkleNode::Leaf { .. } => {
            panic!("verkle tree key length is inconsistent (hit leaf at non-terminal depth)");  // (B)
        }
    }
}
```

`builder.rs:21-32` documents the **intended** design:

```rust
const KEY_DOMAIN_LOCK: u8 = 0x01;
const KEY_DOMAIN_NULLIFIER: u8 = 0x02;
const KEY_DOMAIN_NOTE_COMMITMENT: u8 = 0x03;

// Lock leaves use the lock_id directly as the key (32 bytes). To prevent
// collision with nullifiers and note commitments, we prepend a 1-byte
// discriminator on each.
```

The comment says "we prepend a 1-byte discriminator on each." Code reality:

- `nullifier_verkle_key` *does* prepend `0x02`, producing a 33-byte key (`builder.rs:34-39`).
- `note_commitment_verkle_key` *does* prepend `0x03`, producing a 33-byte key (`builder.rs:41-51`).
- `lock_verkle_key` exists (`builder.rs:53-58`), would prepend `0x01` — but is **never called anywhere in the codebase**:

```sh
$ rg 'lock_verkle_key' code/hypersnap/
code/hypersnap/src/hyper/builder.rs:53:fn lock_verkle_key(lock_id: &[u8]) -> Vec<u8> {
```

The actual production lock insertion goes through `insert_lock_into_tree` (`lock_event.rs:258-266`):

```rust
pub fn insert_lock_into_tree(
    tree: &mut hypersnap_crypto::verkle::VerkleTree,
    event: &proto::HyperLockEvent,
) -> Result<(), LockError> {
    validate_lock_event(event)?;
    let leaf = encode_lock_leaf(event);
    tree.insert(&event.lock_id, leaf);   // ← raw 32-byte lock_id, no discriminator
    Ok(())
}
```

So in production:

- Locks live at **32-byte** paths whose first byte is the first byte of `lock_id` (which the user fully controls and which `validate_lock_event` does *not* constrain — `lock_event.rs:210-240` only checks length, EVM dest-address format, and signature shape).
- Nullifiers live at **33-byte** paths whose first byte is `0x02`.
- Note commitments live at **33-byte** paths whose first byte is `0x03`.

## The crash construction

Define `nf_key = [0x02, n_0, n_1, ..., n_{31}]` — 33 bytes — for some nullifier `n = (n_0..n_{31})` an attacker will eventually want to disrupt. By submitting a `HyperLockEvent` whose `lock_id` (which is *entirely user-supplied*, see `http_handler.rs:1701-1710` for the round-trip wiring) equals `[0x02, n_0, n_1, ..., n_{30}, n_{30}]` (32 bytes, first byte 0x02, last byte set to repeat the 30-th byte of the nullifier), the verkle tree ends up in the following shape after the lock is applied:

- depth 0: Internal, child at slot `0x02` is Internal
- depth 1: Internal, child at slot `n_0` is Internal
- …
- depth 30: Internal, child at slot `n_{29}` is Internal (depth-31 node)
- depth 31: Internal, child at slot `lock_id[31] = n_{30}` is **`Leaf{ value = encode_lock_leaf(...) }`**

Now a legitimate transfer adds nullifier `n` to the same tree (`builder.rs:121-124`). `tree.insert(&nullifier_verkle_key(&n), vec![1u8])` calls `insert_recursive` with the 33-byte `nf_key`. Walking the recursion:

- depth=0 … depth=30: identical traversal, all Internals exist, no panic.
- depth=31: the function takes the `match node { Internal { … } => … }` branch, computes `slot = key[31] = n_{30}`, calls `children.entry(n_{30}).or_insert_with(new_internal)`. **The slot is already occupied — by the `Leaf` the attacker placed.** `entry().or_insert_with()` only inserts when the slot is empty, so the existing `Leaf` is returned. The recursion calls `insert_recursive(child, key, depth=32, value)` with `child = &mut Leaf`.
- depth=32: `depth + 1 == 33 == key.len()`, so this is the terminal case. It executes the `if let VerkleNode::Internal { … } = node` check on `node = &mut Leaf`. The match fails, the `else` branch runs:

```rust
panic!("verkle tree key length is inconsistent (parent is a leaf)");   // verkle.rs:123
```

The panic unwinds through `Self::insert_recursive` → `Self::insert_recursive` (recursive frames) → `VerkleTree::insert` (`verkle.rs:107-110`) → `apply_message` in `builder.rs:119-134`:

```rust
PendingMessage::Transfer(tx_proto) => {
    let tx = tx_from_proto(tx_proto)?;
    for input in &tx.inputs {
        self.tree.insert(&nullifier_verkle_key(&input.nullifier.0), vec![1u8]);  // ← panic here
    }
    …
}
```

`apply_message` has no `catch_unwind`. `build_envelope_with_full_anchor` (`builder.rs:228-269`) has no `catch_unwind`. The panic propagates to the actor task driving block production / import, which dies. **A grep across `code/hypersnap/src/` for `catch_unwind` returns zero hits**, so no wrapper rescues the thread.

## Symmetric construction: pre-existing lock + new transfer

The same crash also occurs in the natural order: an attacker waits until they observe a public transfer with nullifier `n = (n_0..n_{31})` in the mempool (mempool is gossip-broadcast, so visible to everyone before block inclusion). They submit a lock_id `[0x02, n_0, ..., n_{30}, n_{30}]` to the *same* mempool window. The block proposer applies messages in some order; if the lock is applied first (or in the same block), the next transfer's nullifier insertion panics. Because mempool ordering is `BTreeMap`-deterministic (`mempool.rs:46-48` keys lock by `lock_id` lexicographically, transfers by nullifier), the attacker controlling `lock_id` can *force* lock-first ordering by choosing a `lock_id` that sorts before the transfer's nullifier — `lock_id = [0x02, n_0, …, n_{30}, n_{30}]` and `nullifier_key = [0x02, n_0, …, n_{31}]` differ at byte 32 onward; if `n_{30} < n_{31}` lock sorts first, and even when it doesn't the attacker can rerun lock submission with different bytes.

Actually even simpler: the builder applies `PendingMessage`s in the **order the proposer passes them in** (`builder.rs:244-246`, plain `for msg in messages`), and the proposer pulls from the mempool in BTreeMap order over `MessageKey::Lock` then `MessageKey::Transfer` (separate maps, locks iterated first). Locks are always applied before transfers within a block. So as long as the attacker's lock and the victim's transfer end up in the same block, the lock is applied first, the leaf is placed, and the transfer's nullifier insertion panics.

## Symmetric construction: pre-existing nullifier + new lock

Equivalent collision in the opposite direction:

1. Honest user transfers; a nullifier `n` is inserted at depth 32 (Leaf in slot `n_{31}` of node at depth 32, reached via path `[0x02, n_0, ..., n_{30}]`).
2. Attacker submits a lock with `lock_id = [0x02, n_0, ..., n_{30}, n_{30}]`. Insertion:
   - depth=0..29: Internals exist; descend.
   - depth=30: Internal at depth 30 has child at slot `n_{29}` = depth-31 Internal. Descend.
   - depth=31: `depth + 1 == 32 == key.len()` — terminal. `if let VerkleNode::Internal { … } = node`. The node here is the depth-31 Internal (the parent of the depth-32 nullifier subtree). Match succeeds; the lock's Leaf is placed at slot `lock_id[31] = n_{30}` of the depth-31 Internal. **This is the slot where the nullifier's path continues** — but the nullifier subtree is at slot `n_{29}` not `n_{30}`, wait let me retrace…

Re-do carefully. Nullifier key `[0x02, n_0, n_1, …, n_{31}]` (33 bytes). Recursion:

- depth=0, slot=0x02
- depth=1, slot=n_0
- …
- depth=k, slot=n_{k-1}
- depth=31, slot=n_{30}, child becomes new Internal at depth 32
- depth=32, terminal, store Leaf at slot=n_{31} of depth-32 Internal.

So the nullifier *creates* an Internal at depth 32, accessed via depth-31 node's slot `n_{30}`. That Internal at depth 32 holds a Leaf at slot `n_{31}`.

Now the attacker's lock_id `[0x02, n_0, …, n_{30}, n_{30}]` (32 bytes). Recursion:

- depth=0…29: identical to above.
- depth=30, slot=n_{29}, child is the depth-31 Internal (exists from nullifier path).
- depth=31, terminal (`depth + 1 == 32 == key.len()`): `if let VerkleNode::Internal { … } = node`. `node` is the depth-31 Internal. Match succeeds. `children.insert(lock_id[31] = n_{30}, Leaf{ … })`. **This OVERWRITES the existing child at slot `n_{30}`**, which is the depth-32 Internal that holds the nullifier's Leaf!

`BTreeMap::insert` returns the previous value but the calling code (`verkle.rs:121`) does not capture it. The entire nullifier subtree is silently dropped. The nullifier ceases to be a member of the tree from the root-commitment perspective; the verkle inclusion proof for the nullifier now fails — but more dangerously, **the nullifier "no longer exists" in the state-root**.

For the purposes of "is this nullifier double-spent?", the nullifier set lives in the verkle tree (`builder.rs:121-124`). A nullifier silently removed via lock-overwrite is **a path back to double-spending the original note**. The transfer that originally created the nullifier was already accepted (block applied), so its outputs exist; but the nullifier's verkle entry is gone, so a re-spend of the same input cannot be detected via verkle-membership lookup (only by the off-tree `NoteStoreMut::mark_spent` index — see `builder.rs:166-172`. That index does persist the nullifier separately. So in the current pipeline the double-spend detection still works via the off-tree index, but the verkle root no longer reflects the true nullifier set, which is the canonical state commitment that the threshold-signed hyperblock metadata advertises. Cross-light-client verification against the verkle root would now accept "nullifier not present" for an actually-spent note.)

So the same construction has **two distinct bad outcomes** depending on insertion order:

- **Lock first, then nullifier:** panic at `verkle.rs:123` → block-production / import crash.
- **Nullifier first, then lock:** silent overwrite of the entire depth-32 subtree at slot `n_{30}` → verkle root no longer authenticates the nullifier set.

## Reproduction strategy

The crash construction needs only one nullifier the attacker can predict. Two channels:

1. **Mempool snooping.** Transfers are gossiped through the standard hyper-message libp2p mesh (`gossip_adapter.rs`, `router.rs`). A mempool-watching attacker sees the victim's transfer and its nullifiers, then races a lock submission to the same proposer.
2. **Self-nullifier targeting.** The attacker doesn't need a victim — they can build their own transfer in two pieces. First derive the nullifier `n` for their own note off-line. Then submit `(lock_id = [0x02, n_0, …, n_{30}, n_{30}], transfer with input nullifier n)` as a single bundle. The proposer applies the lock first (lock ordering, see above), then panics on the transfer. Every validator that re-imports this block crashes identically — **deterministic cascade halt of every validator running the same code**.

Pre-image grinding to find an attacker-controlled nullifier with desired prefix is unnecessary because the attacker chooses the *lock_id* (the more-constrained value, 0x02 fixed first byte). They take any existing nullifier `n` they want to disrupt and compute the matching lock_id deterministically. Cost: O(1) work, one HTTP POST to `/hyper/v1/messages`.

## Why mempool / validation don't catch it

`validate_lock_event` (`lock_event.rs:210-240`) checks: amount ≠ 0, lock_id length = 32, dest_address non-empty, spend_pubkey non-empty, and EVM-family length rules. It does **not** reject lock_id values whose first byte equals 0x01/0x02/0x03 (the reserved domain bytes). The reserved-byte concept is invisible at the validation layer.

`HyperMempool::insert_lock` (mempool.rs) calls `validate_lock_event` then dedupes by lock_id. No domain-byte filter.

`HyperBlockBuilder::apply_message` (builder.rs:113-135) calls `insert_lock_into_tree(self.tree, event)` and `self.tree.insert(...)` directly with the unchecked `lock_id`. No domain-byte filter.

So a malicious lock with `lock_id[0] = 0x02` (or 0x03 or 0x01) flows end-to-end through validation, mempool admission, block proposal, and block import with no rejection.

## Why the unit tests don't catch this

`verkle.rs`'s tests (`verkle.rs:370-599`) only use keys of length 4 (e.g. `b"abcd"`, `b"aaaa"`). They never construct a key that is a strict path-prefix of another key. Specifically there is no test that inserts `b"abc"` then `b"abcd"`, or vice versa.

`lock_event.rs`'s tests insert lock_ids like `vec![0x01; 32]` and `vec![0x02; 32]` (e.g. `lock_event.rs:563-573`) — first bytes 0x01 and 0x02 — but does not also insert a nullifier with matching prefix in the same tree. The `distinct_lock_ids_produce_independent_entries` test (`lock_event.rs:558-575`) explicitly uses lock_ids `[0x01;32]` and `[0x02;32]` *but never mixes with a nullifier insertion*, so the panic doesn't fire.

`builder.rs::locks_and_transfers_co_exist_in_tree` (`builder.rs:523-577`) *does* mix lock + transfer in one tree, but the lock_id is `[0xa1; 32]` (first byte 0xa1, far from any reserved domain byte) and the transfer's nullifier is freshly derived (random), so the prefix collision is astronomically unlikely. Replace the lock_id in that test with `[0x02, nf[0], nf[1], …, nf[30], nf[30]]` and the test would panic.

No test in the codebase asserts that ill-chosen lock_ids cannot cause a tree-shape inconsistency. The unit-test coverage is "happy-path only" for the cross-domain insertion case.

## Why the other H117 levers were ruled out

Each Lagrange / verkle-specific lever from the task description was walked:

1. **Key-derivation (path bytes → leaf-index mapping).** *Open* — this finding.
2. **Domain-extension / path-length attacks (two distinct keys hash to the same path-prefix → silent overwrite or panic).** *Open* — this finding (both panic and silent-overwrite variants are reachable).
3. **Node-encoding canonicality (multiple byte encodings of the same node yield distinct root commitments?).** Closed. The commitment is `commit_evaluations(srs, &evals)` where `evals[i]` is determined entirely by which child sits at slot `i` and that child's `commitment_value()`. The eval vector is canonical (sorted by slot, fixed size 256, missing slots = `Fr::ZERO`). G1 compressed encoding (`G1Affine::to_compressed`) is unique for a given group element. There is no aliasing in node-byte representation.
4. **Branching factor & polynomial degree.** Closed. Domain = 256, polynomial degree ≤ 255, SRS sized to `VERKLE_DOMAIN = 256` so `g1_powers.len() = 257` — one slot of headroom. `commit` enforces `coeffs.len() <= g1_powers.len()` at `kzg.rs:127-132`.
5. **Commitment-to-node binding (does the commitment cover ALL children or just the value bytes?).** Closed. `compute_commitment` initializes `evals = vec![Fr::ZERO; VERKLE_DOMAIN]` then fills each occupied slot — all 256 slots contribute, not just the populated ones. So changing slot 17 from empty to "child X" *and* simultaneously changing slot 200 from "child Y" to empty both change the commitment.
6. **Inclusion-proof completeness vs partial-proof attacks.** Closed. `verify_inclusion` (`verkle.rs:325-357`) checks `proof.steps.len() == key.len()`, `proof.steps[0].commitment == root_commitment`, `step.slot == key[i]` for every step, KZG pairing for every step, and the chained constraint `step.evaluation == hash_to_fr(LEAF_DOMAIN_or_INTERNAL_DOMAIN, next-level-thing)`. There is no way for a prover to truncate or skip levels.
7. **Aggregation when proving multiple leaves.** Not present (Step-13 deferred per `verkle.rs:9-11`). No multi-leaf aggregator exists yet; if added it must be re-audited.
8. **Basis confusion.** Already filed as F116 (KZG loader monomial-vs-Lagrange). F117 is *distinct* — F116 is about how the SRS bytes are interpreted; F117 is about how key bytes are mapped to tree paths.

Lever (2) ("two distinct keys hash to the same path-prefix") is the load-bearing one. The intended mitigation (1-byte domain discriminator on every insert) is documented but only half-implemented.

## Severity calibration vs F058 / audit-index note

The audit-index entry for F058 (line 146) notes that the live L1 `HypersnapBridge.claim` does *not* consume verkle proofs — it consumes a separate keccak-256 Merkle proof. So F117 is **not** a path to "mint arbitrary tokens on L1." It is a path to:

1. **Hypersnap-side consensus liveness DoS** — every validator panics when applying the malicious block, so the chain halts. The verkle tree *is* on the live hyperblock construction path (`builder.rs:18-20, 247-251`), so this is reachable in production today.
2. **State-root divergence at light-client / RPC consumers** — anyone using the hyperblock's `hyper_state_root` (which is the verkle root) to verify inclusion of a nullifier via the verkle inclusion proof receives a "nullifier not in state" response after an overwrite, even though the nullifier was honestly created. This affects the HTTP/RPC `lock-tree/proof` and related endpoints (`http_handler.rs:112-117`), though the live L1 contract does not consume these.

The DoS in (1) is the dominant concern: every validator deterministically panics on the same block, no individual recovery is possible (the next block-import retry hits the same panic), so the chain stays down until either an operator manual-patches the verkle tree or the offending block is censored out by every validator. **Severity: High** — adversary-induced consensus halt at trivial cost (one HTTP POST, no on-chain stake required) and the recovery story is "manual operator intervention on every node."

## Recommended fix

**Layer 1 — make every verkle-tree insert go through a discriminator-prefixing constructor.** Wire `insert_lock_into_tree` to use the existing `lock_verkle_key(&event.lock_id)` helper rather than raw `event.lock_id`. The fix is a one-line change in `lock_event.rs:264`:

```rust
-    tree.insert(&event.lock_id, leaf);
+    tree.insert(&crate::hyper::builder::lock_verkle_key(&event.lock_id), leaf);
```

`lock_verkle_key` would need to be made `pub` (currently `fn lock_verkle_key`). Every lock-related HTTP/RPC handler that constructs verkle proofs (`http_handler.rs:695-711`, `lock_tree.rs`) must also be updated to call the same key constructor, and the L1 bridge contract — if it ever consumes verkle proofs — must be told that locks live at 33-byte paths now.

**Layer 2 — assert at the verkle-tree boundary that all keys share a fixed length.** Currently `VerkleTree` accepts arbitrary key lengths and depth = key length. This is the design that permits prefix-collisions in the first place. Adding `VerkleTree::new_with_fixed_depth(srs, depth)` and rejecting (or splitting trees for) keys of any other length would foreclose this entire class:

```rust
pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
    assert_eq!(key.len(), self.expected_depth, "verkle key length must equal tree depth");
    …
}
```

With every insert at depth 33, neither panic site (A) nor (B) is reachable from valid inserts.

**Layer 3 — reject reserved-domain-byte lock_ids at validation time.** Even with Layer 1 applied, defense-in-depth: `validate_lock_event` should reject lock_ids whose first byte is 0x01/0x02/0x03 (or, more robustly, whose first byte falls in any value reserved by `KEY_DOMAIN_*` constants). This bounds the damage if any future insertion path forgets the discriminator prefix.

**Layer 4 — catch-unwind around the actor-task message-application loop.** `apply_message`'s panics should be promoted to `BuilderError` and surface to the proposer/importer with a "skip this message / abort this block" decision, not crash the actor. This is a defence-in-depth measure for unrelated future verkle panics (e.g. assertion failures inside `compute_commitment` / FFT bounds).

**Layer 5 — pinned cross-side test vector for prefix-collision rejection.** Add a test in `lock_event.rs::tests` that constructs `lock_id = [0x02; 32]` plus a transfer with nullifier `[0; 32]` and asserts the build either succeeds (Layer 1+3 applied) or returns an explicit `BuilderError` (no panic). The current test suite would let this regression slip through silently.

## Affected attack-class checklist items

- **kzg-srs-or-verkle-encoding:** verkle key-derivation / path-prefix collision — this finding.
- **merkle-leaf-domain-separation:** the verkle tree *does* domain-separate Leaf vs Internal hashing (LEAF_DOMAIN / INTERNAL_DOMAIN at `verkle.rs:21-22`), so the second-preimage class is blocked at the hash layer. But the *key-derivation* layer (where 0x01/0x02/0x03 discriminators are supposed to live) is broken, which is a sibling concern of merkle-leaf-domain-separation at the tree-key seam.
- **cross-side-encoding-asymmetry:** lock leaves living at 32-byte paths whereas everything else lives at 33-byte paths is itself an encoding asymmetry that any future L1 verkle-proof verifier needs to know about. The protocol does not pin this in a cross-side test vector today.
- **Anti-pattern: "we'll add the discriminator later."** `lock_verkle_key` is the textbook deferral — defined, documented in the module header comment, never called. F116 hits the same anti-pattern on a different lever.

## References

- Verkle insert recursion + panic sites:
  `code/hypersnap/crates/hypersnap-crypto/src/verkle.rs:107-143`
- Domain prefix constants + unused `lock_verkle_key`:
  `code/hypersnap/src/hyper/builder.rs:21-58`
- Lock insertion *without* discriminator (the live path):
  `code/hypersnap/src/hyper/lock_event.rs:258-266`
- Lock validation (does not reject reserved first bytes):
  `code/hypersnap/src/hyper/lock_event.rs:210-240`
- User-supplied lock_id ingress:
  `code/hypersnap/src/hyper/http_handler.rs:1693-1727`
- Block builder applies messages with no `catch_unwind`:
  `code/hypersnap/src/hyper/builder.rs:113-135, 228-269`
- Nullifier / commitment key constructors (the 33-byte side):
  `code/hypersnap/src/hyper/builder.rs:34-51`
- Related (distinct) findings on the verkle/KZG stack:
  - `findings/drafts/F048-kzg-srs-silent-random-tau-fallback-in-production-config.md` (different lever, same module)
  - `findings/drafts/F116-kzg-loader-assumes-monomial-basis-no-lagrange-detection-or-conversion.md` (different lever, sibling H116)
  - `findings/drafts/F058-...md` (live-bridge invalidation — confirms verkle is **not** on the L1-mint path, but **is** on hypersnap state-root path; informs severity)
