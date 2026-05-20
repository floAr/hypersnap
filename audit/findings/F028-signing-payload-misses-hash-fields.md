---
id: F028
task: H028
specialist: node-lifecycle-actor
attack_class: signing-payload-field-coverage-gap
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.95
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# F028 — Threshold-signed payload omits `extra_rules_version` and `retained_message_count`, allowing one signature to authenticate multiple distinct block hashes

- **Task ID:** H028
- **Specialist:** node-lifecycle-actor
- **Attack class:** signing-payload-field-coverage-gap
- **Severity (draft):** High
- **Status:** draft

## Summary

`HyperBlockMetadata::signing_payload(epoch)` (the byte string actually
threshold-signed by validators) does not commit to two fields that
`hyper_block_hash` includes in the canonical block identity:

- `extra_rules_version` (u32)
- `retained_message_count` (u64)

Because `hyper_block_hash` is the value used as the next block's
`parent_hash` (chain.rs:129), as the storage key in `block_index.rs`,
and as the equivocation discriminator in `slashing.rs::detect_conflicting_blocks`,
a malicious threshold signer (or 1-of-1 dev key, or anyone in possession
of one validly-signed block from a colluding committee) can derive
arbitrarily many byte-distinct hyperblocks **all carrying the same valid
threshold signature**. This breaks block-uniqueness at the chain layer
and enables a malicious evidence submitter to slash the signing
committee for two blocks the committee only signed once.

## Affected files

- `code/hypersnap/src/hyper/mod.rs:397` — `HyperBlockMetadata::signing_payload`
- `code/hypersnap/src/hyper/chain.rs:25` — `hyper_block_hash`
- `code/hypersnap/src/hyper/slashing.rs:51` — `detect_conflicting_blocks` (downstream impact)
- `code/hypersnap/src/hyper/importer.rs:249` — `signing_payload` consumer

## Side-by-side field coverage

| # | Field | In `signing_payload` | In `hyper_block_hash` |
|---|---|---|---|
| 1 | DST | `b"hypersnap-hyperblock-v1:"` | `b"hypersnap-block-hash-v1"` |
| 2 | `epoch` (BE u64) | yes | yes |
| 3 | `canonical_block_id` (BE u64) | yes | yes |
| 4 | `parent_hash` (len32+bytes) | yes | yes |
| 5 | `hyper_state_root` (len32+bytes) | yes | yes |
| 6 | `extra_rules_version` (BE u32) | **NO** | **YES** |
| 7 | `retained_message_count` (BE u64) | **NO** | **YES** |
| 8 | `missed_proposals` (len32+entries) | yes | no |
| 9 | `snapchain_anchor_block` (BE u64) | yes | no |
| 10 | `snapchain_anchor_hash` (len32+bytes) | yes | no |
| 11 | `snapchain_range_start_block` (BE u64) | yes | no |
| 12 | `snapchain_range_root` (len32+bytes) | yes | no |
| 13 | `snapchain_anchor_timestamp` (BE u64) | yes | no |
| 14 | `signature.group_address` (len32+bytes) | n/a | yes (self-reference) |
| 15 | `signature.ecdsa_signature` (len32+bytes) | n/a | yes (self-reference) |

Rows 6 and 7 are the forgeable gap: any value of `extra_rules_version`
or `retained_message_count` produces a verifying signature but a
*different* `hyper_block_hash`.

(Rows 8–13 are "mute" fields — they were committed to by the signer
but are absent from the canonical identity. That direction is the
less-severe corollary discussed below.)

## Exploit walkthrough

### Variant 1 — same signature, two block hashes (parent-hash fork)

Let `S` be the threshold signature over `signing_payload(E)` for a block
`B` at height `H` with `parent_hash=P`, `hyper_state_root=R`,
`extra_rules_version=v`, `retained_message_count=n`.

A malicious proposer (or any holder of `(B, S)`) constructs:

```
B1 = B with extra_rules_version = v,   retained_message_count = n
B2 = B with extra_rules_version = v+1, retained_message_count = n
B3 = B with extra_rules_version = v,   retained_message_count = n+1
…
```

All carry signature `S`. `verify_hyperblock_signature` succeeds for all
of them (importer.rs:249 re-derives the same `signing_payload(E)` bytes,
which are invariant under rows 6/7).

Yet `hyper_block_hash(B1) != hyper_block_hash(B2) != hyper_block_hash(B3)`
(chain.rs:33–34 mix both fields into SHA-256). A partitioned network can
end up with peers that imported `B1` versus `B2`: their `ChainTracker.last_hash`
differs, so the next block — even one honestly produced — fails
`ParentHashMismatch` on one side of the partition. Honest builders
cannot recover without restart-from-state surgery.

### Variant 2 — manufactured slashing evidence

`detect_conflicting_blocks` (slashing.rs:67–71) flags two blocks as a
slashable conflict iff:
- same `canonical_block_id`,
- same `epoch`,
- `hyper_block_hash(a) != hyper_block_hash(b)`,
- both threshold signatures verify.

Variant 1 produces exactly that quadruple: `B1` and `B2` at the same
height, same epoch, both verify under the epoch's group key
(`verify_evidence_signatures` calls `signing_payload(epoch)` — same
input as the original signing — slashing.rs:95–98), but have distinct
`hyper_block_hash` values. **Any peer that can replay one validly-signed
block can frame the signing committee for double-signing.** Since
penalty enforcement happens at the next epoch boundary, by the time the
slashes are challenged, the misbehavior record is already on-chain.

### Variant 3 — divergent `retained_message_count` truncation

`retained_message_count` is a u64 the importer trusts as a hint about
how many messages the block "really" applied (the `MAX_MESSAGES_PER_BLOCK`
ceiling lives over this value in `validate_block_size`, builder.rs:274).
A malicious signer can leave the actual `payload` empty but advertise
`retained_message_count = MAX_MESSAGES_PER_BLOCK`. Because the signature
covers neither the count nor the payload, importers downstream that key
metrics, mempool eviction, or block-size accounting off this field
diverge from the on-the-wire reality.

## Why the gap is not "mute"

`extra_rules_version` is the protocol-rule pinning field — its purpose
in the type system is to let the network roll out new validation rules.
A 1-of-1 threshold key (genesis, recovery, or post-DKG-failure modes)
that signs once can produce blocks under arbitrary `extra_rules_version`
values, defeating the very rule pinning the field was added to provide.

## Recommended fix

In `HyperBlockMetadata::signing_payload`, after the `hyper_state_root`
block (mod.rs:406), append:

```rust
buf.extend_from_slice(&self.extra_rules_version.to_be_bytes());
buf.extend_from_slice(&self.retained_message_count.to_be_bytes());
```

Match the exact byte order used by `hyper_block_hash` (BE u32 then BE
u64) so the two derivations stay byte-identical on the overlap.

Additionally, **either** drop the "mute" fields from `signing_payload`
(rows 8–13) **or** add them to `hyper_block_hash`. The current
asymmetry means a block's identity (`hyper_block_hash`) can be the same
for two blocks the committee signed under different missed-proposal
ledgers or snapchain anchors — the inverse asymmetry, less impactful
but still surprising. The cleaner invariant is: *every byte that
matters to consensus appears in both digests, in the same order, with
length prefixes that match.*

The fix is a hard fork (changes the bytes the validator set signs);
schedule under the `extra_rules_version` mechanism it is meant to
protect.

## Mitigations / open questions

- Is there an out-of-band check that rebuilds the block from
  `messages[]` and rejects mismatched `retained_message_count`?
  Searched `importer.rs`, `runtime.rs`, `chain.rs` — found none.
- Is `extra_rules_version` actually read by any validator gate today?
  If yes, the impact is rule-skip; if no, it is parent-hash fork plus
  slashing-evidence forgery only.

## Reproduction sketch

```rust
let mut m = HyperBlockMetadata { /* ... extra_rules_version: 0, retained_message_count: 5, ... */ };
let payload_a = m.signing_payload(7);

m.extra_rules_version = 1;
m.retained_message_count = 999_999;
let payload_b = m.signing_payload(7);

assert_eq!(payload_a, payload_b);            // SAME bytes signed
// but hyper_block_hash differs:
let h_a = hyper_block_hash(&block_a_with_sig);
let h_b = hyper_block_hash(&block_b_with_sig);
assert_ne!(h_a, h_b);                        // DIFFERENT identity
// → slashing.rs::detect_conflicting_blocks(&block_a, &block_b) returns Ok(evidence)
```
