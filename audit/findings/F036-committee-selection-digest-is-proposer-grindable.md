---
id: F036
task: H036
specialist: rust-threshold-signing
attack_class: committee-selection-grinding
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.94
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F036: DKLS signing committee is keyed on a proposer-controlled digest with no commit-reveal, letting a proposer grind the hyperblock contents to pick a friendly threshold committee (or exclude themselves)

## Summary

`select_signing_committee(epoch, digest, share_count, threshold)`
(`code/hypersnap/src/hyper/dkls_committee.rs:53-89`) selects which
`threshold`-of-`share_count` validators sign a given message by
sorting `keccak256("hypersnap-dkls-committee-v1\0" || epoch || digest
|| index)` over the candidate party indices and taking the `threshold`
lowest. The seed has exactly two non-trivial inputs: the integer
`epoch` and the 32-byte `digest`. The epoch is consensus-fixed and not
grindable, but for the most security-critical caller — DKLS-signed
hyperblock production — `digest` is `keccak256(metadata.signing_payload(epoch))`
where `signing_payload` (`code/hypersnap/src/hyper/mod.rs:397-427`)
commits to a long list of fields the proposer itself chose: the
mempool contents (via `hyper_state_root`), the `missed_proposals`
list, the chosen `snapchain_anchor_block` / `_hash` /
`_timestamp`, and `canonical_block_id`.

There is no commit-reveal, no VRF, no delay between "proposer decides
what to put in the block" and "committee is computed from the block
digest", and no randomness beacon mixed into the rank seed. A
proposer can therefore grind these proposer-chosen inputs offline —
flipping one entry in `missed_proposals`, advancing the
`snapchain_anchor_block` by one, reordering or excluding a mempool
message — and recompute the committee for free at each iteration until
they find a digest that yields a committee they like. Concretely:

- **Self-exclusion** (denial of duty / slashing avoidance): a
  proposer who does not want to participate in the ceremony for their
  own block grinds until their own `party_index` is not in the
  bottom-`threshold` ranks.
- **Self-inclusion + colluder packing**: a colluding cohort of `k`
  validators with `k ≥ threshold` (or `k = threshold` exactly) grinds
  until the bottom-`threshold` ranks are exactly their indices. They
  then hold the entire signing committee for that hyperblock and can
  unilaterally produce or withhold the threshold ECDSA signature
  without consulting any honest validator.

Because the bridge-claim flow, reward issuances, and the lock-merkle-
root update all funnel through the same DKLS sign queue keyed off
this same selector (`actor.rs:2658, 2682, 2813, 2879`), the same
class of grinding applies at every site whose digest carries
proposer freedom (state-root via mempool ordering, snapshot
anchor timestamp, etc.). The `da_epoch_seed` call site
(`actor.rs:2945-2956`) is the only one whose payload is rigid
(`(chain_id, target_epoch)`), so its committee is grind-free.

## Description

### Rank seed and its inputs

```rust
fn rank_for(epoch: u64, digest: &B256, index: u8) -> B256 {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(b"hypersnap-dkls-committee-v1\x00");
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(digest.as_slice());
    buf.push(index);
    keccak256(&buf)
}
```
(`code/hypersnap/src/hyper/dkls_committee.rs:82-89`)

Every input byte fed into the rank hash is either constant
(`"hypersnap-dkls-committee-v1\0"`, the per-party index `index`) or a
function of two outside parameters: `epoch` and `digest`. The selector
has no other entropy source.

### Caller A — hyperblock signing (the highly-grindable one)

```rust
let epoch  = block.signature.epoch;
let payload = block.envelope.metadata.signing_payload(epoch);
let digest = alloy_primitives::keccak256(&payload);
...
let committee = crate::hyper::dkls_committee::select_signing_committee(
    epoch, &digest, share_count, threshold,
)?;
```
(`code/hypersnap/src/hyper/actor.rs:2287-2308`)

`metadata.signing_payload(epoch)` covers every field a proposer can
choose:

```rust
buf.extend_from_slice(DST);                                  // const
buf.extend_from_slice(&epoch.to_be_bytes());                 // consensus
buf.extend_from_slice(&self.canonical_block_id.to_be_bytes()); // proposer (slot height)
buf.extend_from_slice(&(self.parent_hash.len()).to_be_bytes());
buf.extend_from_slice(&self.parent_hash);                    // consensus (last block)
buf.extend_from_slice(&(self.hyper_state_root.len()).to_be_bytes());
buf.extend_from_slice(&self.hyper_state_root);               // proposer (chosen mempool subset)
buf.extend_from_slice(&(self.missed_proposals.len()).to_be_bytes());
for mp in &self.missed_proposals {                            // proposer (chosen list)
    buf.extend_from_slice(&(mp.validator_key.len()).to_be_bytes());
    buf.extend_from_slice(&mp.validator_key);
    buf.extend_from_slice(&mp.round.to_be_bytes());
}
buf.extend_from_slice(&self.snapchain_anchor_block.to_be_bytes());      // proposer (chooses tip)
buf.extend_from_slice(&(self.snapchain_anchor_hash.len()).to_be_bytes());
buf.extend_from_slice(&self.snapchain_anchor_hash);                     // proposer (chosen anchor)
buf.extend_from_slice(&self.snapchain_range_start_block.to_be_bytes()); // proposer
buf.extend_from_slice(&(self.snapchain_range_root.len()).to_be_bytes());
buf.extend_from_slice(&self.snapchain_range_root);                      // function of chosen anchors
buf.extend_from_slice(&self.snapchain_anchor_timestamp.to_be_bytes());  // proposer
```
(`code/hypersnap/src/hyper/mod.rs:397-427`)

The proposer controls at minimum:

1. `canonical_block_id` — they propose for "their" slot but if they
   skip a slot they can propose for a later one, shifting the input.
2. `hyper_state_root` — derived from `mempool.drain()` (`runtime.rs:
   4307-4313`). Proposers pick which mempool messages to drain (FIFO
   today, but a proposer who controls their own mempool decides what
   is in it: which transfers, which lock events, what order). Each
   permutation hashes differently and changes `digest`.
3. `missed_proposals` — proposer asserts which earlier proposers
   missed their slot. Including/excluding any entry changes the
   digest. The current node accepts whatever the proposer puts here at
   import time (no liveness adjudication that would force a particular
   list).
4. `snapchain_anchor_block`, `_hash`, `_timestamp` — proposer chooses
   which anchor to bind to (within the snapchain tip ± reorg window).
   The anchor poller surfaces a window of recent anchors; the proposer
   picks one. A 1-bit grind: "is the latest anchor good enough or
   shall I anchor one block earlier?".
5. `snapchain_range_start_block` and `snapchain_range_root` — a
   function of the chosen anchor range; same grinding lever as (4).

### How much grinding does an attacker get?

Each grinding lever is cheap: keccak256 over ~200 bytes plus an O(N)
re-rank over N ≤ 32. On a single core at conservative ~1M
keccak256s/sec that is ~30M committee evaluations per minute.

To achieve a *specific* committee (e.g., self + two colluders out of
N=10, t=3) the proposer needs to hit a `1 / C(10,3) = 1/120`-likely
event — well under one second of search.

To merely *exclude themselves* from a committee of size t out of N,
they need to land a digest where their rank is not in the bottom
`t`. With t=5, N=10, this is a `1 - 5/10 = 50%`-likely event per
trial — one or two iterations.

Combined with multiple independent levers (anchor choice, missed-proposals
membership, mempool reorder), even a non-colluding lone proposer can
trivially refuse signing duty by grinding to "I'm not in the
committee" and then deferring the work to the committee that pops
out. Other validators have no way to distinguish "this proposer
genuinely is not in the committee for this digest" from "this proposer
grinded so they're not in the committee".

### What downstream slashing or accountability would expose this?

Searching `src/hyper/slashing.rs`, `src/hyper/evidence/`, and the
DKLS supervisor for any rule along the lines of "a validator that
*could have been* in a committee for a block they proposed but is not"
produces no matches. `detect_conflicting_blocks` only checks for two
distinct blocks at the same height — it cannot detect grinding.
Equivocation evidence requires two competing proposals; grinding produces a
single proposal.

The only structural check is that the digest, once produced, is
deterministic — every honest validator agrees on which committee
*should* sign once they see the block. They have no way to recompute
"would a different committee have been selected if the proposer had
chosen anchor block B-1 instead of B?".

### Caller B — reward issuances and trust snapshot

```rust
let payload = crate::hyper::rewards::issuance_signing_payload(&iss);
let digest  = alloy_primitives::keccak256(&payload);
let committee = ... select_signing_committee(epoch, &digest, share_count, threshold)?;
```
(`code/hypersnap/src/hyper/actor.rs:2655-2664`)

`issuance_signing_payload` covers the canonical scoring output for
the epoch; the unsigned payload should be byte-identical across all
honest validators (it is derived from a reader over committed state
plus `anchor_timestamp`). However, `anchor_timestamp` reaches the
unsigned-issuance through `start_dkls_scoring_multi_party(..., anchor_timestamp)`
(`actor.rs:2648`), and `anchor_timestamp` was a proposer choice in
the block that triggered scoring. A proposer who knows the scoring
auto-trigger uses their `snapchain_anchor_timestamp` can therefore
indirectly grind the issuance digest by perturbing the anchor
timestamp of the block whose import triggers scoring. The grinding
power is small (timestamps are bounded by validity), but the lever is
not absent.

### Caller C — lock merkle root

```rust
let payload = hypersnap_crypto::bridge_payload::merkle_root_update_signing_payload(
    block_number, root,
);
let digest = alloy_primitives::keccak256(&payload);
let committee = ... select_signing_committee(epoch, &digest, share_count, threshold)?;
```
(`code/hypersnap/src/hyper/actor.rs:2873-2885`)

`block_number = self.runtime.last_block_height()` — set by the last
imported block, i.e., by the last proposer. A proposer who is about
to publish a block at height H can pick *whether to also burn an
empty block* at H+1 vs immediately moving to a lock root update at H,
giving them a 1-bit grind on `block_number`. `root` is the canonical
lock-tree root, deterministic given state.

### Caller D — DA epoch seed

```rust
let payload = crate::hyper::rewards::da_epoch_seed_signing_payload(
    target_epoch, self.runtime.protocol_chain_id,
);
let digest = alloy_primitives::keccak256(&payload);
```
(`code/hypersnap/src/hyper/actor.rs:2945-2956`,
 `code/hypersnap/src/hyper/rewards.rs:672-679`)

This caller is **grind-free**: the payload is the fixed tuple
`(DST, chain_id, target_epoch)`. The same `target_epoch` always
produces the same digest and the same committee. Good baseline; the
other callers should be moved toward this shape.

## Impact

- **Liveness — proposer dodges signing duty.** A proposer can grind
  every block they make to ensure they are not in the committee for
  it. With t < N this is trivial. Without a "you should have been in
  the committee for your own block" check, the chain cannot
  distinguish this from honest non-selection. Aggregated across many
  blocks this both (a) shifts the signing workload disproportionately
  onto other validators (a small DoS) and (b) lets a Byzantine
  proposer always avoid accountability for the produced signature
  (they are not on the signer list, so they can plausibly claim no
  involvement).
- **Safety — collusion can capture the committee.** A colluding
  cohort of size `t` (out of N) needs `~C(N,t)` grinding iterations to
  pack themselves into the entire selected committee for a block they
  proposed. For realistic N=10/t=3, that's 120 keccak256+sort
  iterations — under a millisecond. Once they hold the entire
  committee they can:
    - withhold the threshold signature ⇒ the block never gets signed,
      stalling the chain at that height;
    - produce two contradictory threshold signatures for two
      conflicting versions of the same block ⇒ equivocation that
      isn't easily traceable to any individual validator (the signer
      list is short and all in the colluder cohort);
    - sign messages that other (non-grinding) validators would not
      have agreed to — e.g., a reward issuance the bridge contract
      would otherwise reject — because the signing committee no longer
      includes any honest "veto" parties.
- **Cross-domain reuse.** The same committee selector is used for
  bridge-relevant flows: lock merkle root updates, inbound burns,
  reward issuances. A grindable selector means a colluding cohort can,
  for any high-value message they manage to inject through the right
  proposer slot, also be the only validators signing it.
- **No detection path.** Slashing only fires on `detect_conflicting_blocks`.
  Grinding produces one block, not two; it does not trip any
  in-protocol evidence rule. Once the block is imported the digest is
  consensus, and there is no committee-fairness invariant that nodes
  could ever check.

## Evidence

- `code/hypersnap/src/hyper/dkls_committee.rs:82-89` — `rank_for`
  hashes only `(DST || epoch || digest || index)`. No randomness
  beacon, no proposer commitment, no delayed reveal.
- `code/hypersnap/src/hyper/dkls_committee.rs:53-80` —
  `select_signing_committee` is a deterministic function of
  `(epoch, digest, share_count, threshold)`. No nonce. No salt.
- `code/hypersnap/src/hyper/mod.rs:397-427` —
  `HyperBlockMetadata::signing_payload` enumerates the proposer-
  chosen fields baked into `digest`. Specifically:
  `canonical_block_id`, `parent_hash` (proposer can defer to a
  reorged parent), `hyper_state_root` (mempool-permutation-dependent),
  `missed_proposals` (free-form proposer assertion),
  `snapchain_anchor_*` (proposer-chosen anchor block ± window),
  `snapchain_range_*`.
- `code/hypersnap/src/hyper/actor.rs:2287-2308` — block production
  digest path:
  `epoch = block.signature.epoch; payload = metadata.signing_payload(epoch); digest = keccak256(payload); committee = select_signing_committee(epoch, &digest, ...)`.
- `code/hypersnap/src/hyper/runtime.rs:4291-4313` —
  `produce_envelope_with_full_anchor` is what the proposer's local
  actor calls; `let (locks, transfers) = self.mempool.drain();`
  proves the proposer chooses (via local mempool state) which
  messages go in and therefore what `hyper_state_root` becomes.
- `code/hypersnap/src/hyper/actor.rs:2655-2697` — scoring
  issuances + trust snapshot reach the committee selector via
  `keccak256(issuance_signing_payload(iss))`, which itself reads
  `anchor_timestamp` chosen by the upstream proposer.
- `code/hypersnap/src/hyper/actor.rs:2873-2902` — lock-root update
  digest depends on `block_number = self.runtime.last_block_height()`,
  which the previous proposer set.
- `code/hypersnap/src/hyper/actor.rs:2945-2956` and
  `code/hypersnap/src/hyper/rewards.rs:672-679` — DA epoch-seed is
  the **only** caller whose payload has no proposer-chosen entropy.
- `code/hypersnap/src/hyper/slashing.rs` — searching for any rule
  involving committee fairness or "this validator could have been on
  this committee but is missing" returns zero matches. Slashing is
  conflicting-blocks-only.

## Suggested remediation

The fix is to break the "proposer picks the digest" → "digest
picks the committee" pipeline. The standard mitigation is to seed
committee selection from a value the proposer **could not have
controlled at block-build time**. Several composable options:

1. **Decouple the committee seed from the message digest.** Use a
   per-epoch randomness beacon as the seed and reuse the same
   committee for every signing within a small window. Concretely:
   `rank = keccak256(DST || epoch || da_epoch_seed[epoch] || index)`.
   The `da_epoch_seed` is already DKLS-signed (`actor.rs:2945`,
   `rewards.rs:672`) and computed for the *next* epoch by the
   *current* committee, so by the time a proposer drafts a block in
   epoch N the seed for epoch N was committed-to in epoch N-1 — they
   cannot grind it. This is the cleanest fix; the seed already exists.
2. **Bind the committee to the parent block's digest, not this
   block's.** `rank = keccak256(DST || epoch || parent_hash ||
   parent_signing_committee_root || index)`. The proposer of block H
   cannot grind block H-1 retroactively. (Block H-1's proposer can
   still grind for block H's committee, but with a one-block lookahead
   the grinding domain is constrained by parent finality.)
3. **VDF / commit-reveal on the message digest.** Require proposers
   to commit to `digest` one block in advance; only the next
   block can sign using that committed digest. Heavier protocol
   surgery.
4. **Mandatory inclusion of self in own block's committee.** If a
   validator proposes block H, require that validator to be in the
   committee for block H (regardless of rank). This kills the self-
   exclusion lever specifically (but not the colluder-packing one).
5. **Slashing for "proposer of block H not in committee of block H".**
   At import time, the committee for the block is recomputable from
   the block; check whether the block's proposer-key validator-index
   is in that committee, and emit slashing evidence if not. Cheapest
   to add; addresses the self-exclusion lever (1-bit grinding) but
   not the colluder-packing lever.
6. **Independently of the above: add a `da_epoch_seed`-style
   `block_seed` field to `HyperBlockMetadata`** that is **not** under
   the keccak256 used to bind the signature, but **is** under the
   committee selector. Source the field from a delay-revealed
   randomness beacon (BLS-on-prev-epoch-tag) so that no proposer
   knows it at build time. Drop-in compatible with the existing
   `select_signing_committee` signature.

Of these, **(1) is the lowest-cost real fix** because the
randomness it requires is already in the protocol; the change is
plumbing only: replace the `digest` argument in the four caller sites
with the relevant epoch seed (or a hash of `(epoch_seed, msg_kind)`
if you want per-message-class committee rotation within the epoch).
Pin a backward-compat note that the old selector remains for the
DA epoch-seed signing itself (avoid a chicken-and-egg cycle — that
caller must keep using a non-beacon-derived selector since it is
*producing* the next beacon value).
