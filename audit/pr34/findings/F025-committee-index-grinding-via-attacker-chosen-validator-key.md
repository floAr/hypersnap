---
id: F025
specialist: rust-threshold-signing
attack_class: committee-selection-grinding
title: Committee membership is grindable via attacker-chosen validator_key because party indices are assigned by lexicographic key order against a fully predictable per-epoch committee seed
severity_initial: high
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/dkls_committee.rs
  - code/hypersnap/src/hyper/dkls_supervisor.rs
  - code/hypersnap/src/hyper/validator_registry.rs
  - code/hypersnap/src/hyper/actor.rs
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.78
  hypotheses_walked: 8
  validated_at: 2026-06-08T12:30:00Z
---

## Summary

The DKLS23 signing committee for any future epoch is selectable in advance
by an attacker who grinds the bytes of their `validator_key` (a 32-byte
Ed25519 public key freely chosen at registration). The F036 fix made the
committee *seed* non-grindable, but committee selection runs over **party
indices** `1..=share_count`, and the index→validator mapping is simply the
lexicographic (BTreeMap) sort order of the active validator keys. Because
the per-epoch committee seed is deterministic and known far in advance, an
attacker can pre-compute which indices win for a target epoch, then grind
an Ed25519 keypair whose public key sorts into a winning index slot —
biasing committee membership toward their own (sybil) validators.

## Root cause: two independently-deterministic layers compose into a grind

Committee selection (`dkls_committee.rs:53` `select_signing_committee`)
ranks **indices**, not keys:

```rust
rank(i) = keccak256("hypersnap-dkls-committee-v1\0" || epoch || digest || i)
```

The `threshold` indices with lowest rank win. The inputs are `epoch` and
the seed `digest` only — there is no dependence on validator identity. The
seed itself is built to be non-grindable (F036):

- `committee_seed_for_epoch(epoch, message_tag)` (`dkls_committee.rs:110`)
  depends only on `epoch` and a static per-ceremony tag.
- `committee_seed_for_block(epoch, height, parent_hash)`
  (`dkls_committee.rs:119`) depends only on consensus-pinned values.

Consequence: the *set of winning indices* for a target epoch/ceremony is a
pure function of public, predictable values. An attacker knows months ahead
(epoch length is 432,000 anchor blocks, `epoch.rs:14`) exactly which
`party_index` values will be on the committee.

The second layer — the index→validator assignment — lives in the
supervisor (`dkls_supervisor.rs:194-200`):

```rust
let mut own_idx: Option<u8> = None;
for (i, vk) in active.keys().enumerate() {
    if vk == &inputs.local_validator_key {
        own_idx = Some((i + 1) as u8);
        break;
    }
}
```

`active` is a `BTreeMap<Vec<u8>, _>` keyed on `validator_key`, so
`party_index = 1-based position of the key in lexicographic order`. There
is no epoch-randomized shuffle, no VRF, no commit-reveal — the position is
a direct function of the raw key bytes the attacker chose at registration.

## Why this is grindable

`validator_key` is a 32-byte Ed25519 public key (`validator_registry.rs:375`
enforces only the 32-byte length). The registrant generates the keypair
off-chain and is free to grind candidate keypairs cheaply (one Ed25519
keygen per attempt). Nothing binds the key bytes to anything unpredictable:

- The Ed25519 signature (`verify_event_signature`) only proves the
  registrant holds the private key — any ground key still verifies.
- The EIP-712 custody cross-sign (`verify_custody_signature`) commits to
  whatever `validator_key` the attacker supplies; the attacker controls the
  custody key for their own sybil FIDs and re-signs each candidate.
- The trust-floor gate (`validate_register_with_trust`) gates on the FID's
  *trust score*, not on key bytes.
- The per-FID cap is `MAX_VALIDATORS_PER_FID = 3`
  (`validator_registry.rs:24`), but a sybil attacker controls many FIDs, so
  the cap does not constrain the attack.

### Attack procedure

1. Target a future epoch `E` (and a ceremony tag, e.g. `b"reward-issuance"`,
   or the block path's `(E, height, parent_hash)` once the parent is known).
2. Compute the winning index set
   `W = select_signing_committee(E, committee_seed_for_epoch(E, tag),
   share_count, threshold)`. `share_count` for epoch `E` is the size of the
   active set, which is itself derivable from the public registry one epoch
   ahead (`EPOCH_BUFFER = 1`).
3. For each sybil validator, grind Ed25519 keypairs until the key sorts into
   a lexicographic position that lands on a winning index `w ∈ W`. Because
   the position is `rank within the full sorted key list`, the attacker
   targets a byte-prefix bucket; with knowledge of the other (already
   registered) keys this is a direct sort-position computation, not even a
   brute force in many cases.
4. Register the ground keys before epoch `E − EPOCH_BUFFER − 1` so they are
   in the active set at `E`.

The result: the attacker disproportionately (or, with enough sybils,
entirely) populates the `threshold`-sized signing committee for epoch `E`.

## Impact

DKLS23 requires *exactly* `threshold` parties to sign. If an attacker lands
`threshold` of the committee slots, they unilaterally control the group
signature for that epoch's ceremonies: hyperblock production, reward
issuance, trust-snapshot, lock-merkle-root, inbound-burn, and DA-PoW seed
(all the `committee_seed_for_epoch` call sites in `actor.rs:3054-3357` plus
the block path at `actor.rs:2657`). Concretely:

- **Forge/withhold threshold signatures** for any of the above ceremonies in
  the captured epoch (e.g. sign an attacker-favorable lock-merkle-root or
  inbound-burn, or deny service by refusing to sign).
- **Targeted exclusion / DoS**: grind to *avoid* committee membership for
  honest-heavy epochs, or to exclude a specific honest validator from
  pivotal ceremonies, since the attacker can shift the whole index map by
  inserting ground keys at chosen sort positions.

Because the committee for an epoch is fixed and predictable, the attacker
can also pre-position across many future epochs in one registration wave.

This is exactly the committee-selection-grinding class: F036 closed the
proposer-grinds-the-seed door; this finding shows the
attacker-grinds-their-own-position-in-the-index-map door is still open.

## Severity: High

A sybil-capable adversary gains deterministic control over future signing
committees, defeating the threshold trust assumption of every DKLS23
ceremony. Requires registering `threshold`-many sybil validators (subject to
trust floor and per-FID caps), so it is not free, but the grind itself is
cheap and the payoff is full control of an epoch's threshold signer set.

## Suggested direction (non-binding)

Mix an unpredictable, per-epoch beacon into the index assignment so a
validator cannot pre-compute its `party_index` at registration time.
Options: derive the index ordering from
`keccak256(committee_seed(epoch) || validator_key)` (sort by that hash
instead of by raw key bytes) so the position depends on a value the
attacker cannot grind a key against without also fixing the epoch seed —
or, better, key the per-index `rank_for` on the validator_key directly
(rank validators, not abstract indices) under the non-grindable seed, so
the selection ranks identities rather than sort positions. Any fix must
keep the mapping deterministic and identical across all honest nodes for a
given epoch.

## Notes / residual uncertainty

- The block path additionally binds `parent_hash` into the seed, which is
  only known one block ahead; that narrows the pre-computation window for
  the block ceremony but the epoch-tag ceremonies
  (`reward-issuance`, `trust-snapshot`, `lock-merkle-root`,
  `inbound-burn`, `da-epoch-seed`) depend only on `epoch` and a static
  tag and are fully predictable arbitrarily far ahead.
- `select_signing_committee` is called with `epoch` as the first arg and
  the seed as `digest`; the seed already incorporates the epoch, so the
  selection is well-domain-separated — the grind is on the *index map*, not
  on the seed.
