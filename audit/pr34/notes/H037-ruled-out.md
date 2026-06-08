---
id: H037
specialist: rust-bulletproofs-pedersen
attack_class: nullifier-not-domain-separated
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/builder.rs
  - code/hypersnap/src/hyper/lock_event.rs
  - code/hypersnap/crates/hypersnap-crypto/src/verkle.rs
---

# H037 — lock (0x01) vs nullifier (0x02) verkle-key domain separation: ruled out

## Hunt

Confirm whether the verkle-key derivation in `builder.rs` lets a lock key
collide with — or strict-prefix — a nullifier key (F117 domain byte). A
collision/prefix would let an attacker overwrite a nullifier with a lock
entry (or vice versa), enabling double-spend or nullifier suppression.

## What the code does

Domain discriminators (`builder.rs:30-32`):

- `KEY_DOMAIN_LOCK = 0x01`
- `KEY_DOMAIN_NULLIFIER = 0x02`
- `KEY_DOMAIN_NOTE_COMMITMENT = 0x03`

Key builders all prepend the discriminator byte:

- `nullifier_verkle_key` (`builder.rs:34`): `0x02 || nullifier[0..32]` → 33 bytes.
- `note_commitment_verkle_key` (`builder.rs:41`): `0x03 || commitment[..min(32)]`,
  zero-padded to 33 bytes.
- `lock_verkle_key` (`builder.rs:53`): `0x01 || lock_id`.

`lock_id` length is enforced to be exactly 32 bytes by `validate_lock_event`
(`lock_event.rs:145`, `lock_id.len() != 32 → BadLockIdLength`), and
`insert_lock_into_tree` (`lock_event.rs:192`) calls `validate_lock_event`
*before* building the key and inserting. Therefore every production lock key
is exactly `0x01 || 32B` = 33 bytes.

## Why no collision or prefix is possible

The verkle tree is a byte-trie of depth = key length: `insert_recursive`
(`verkle.rs:112`) branches on `key[depth]` at each level and stores the leaf
at the terminal slot when `depth + 1 == key.len()`.

1. At depth 0, lock / nullifier / note-commitment keys branch into three
   disjoint slots (0x01 / 0x02 / 0x03). Their subtrees never overlap, so a
   lock leaf and a nullifier leaf can never occupy the same path even when
   their inner 32 bytes are identical.
2. All three key types are exactly 33 bytes. Two equal-length byte sequences
   that differ in their first byte cannot be a strict prefix of one another,
   so the cross-domain prefix/panic condition described in the F117 fix
   comment (`lock_event.rs:188-191`, leaf-at-non-terminal-depth panic at
   `verkle.rs:140`) is unreachable.

The regression test `lock_with_attacker_chosen_nullifier_prefix_does_not_panic`
(`lock_event.rs:398`) exercises exactly the attacker case: `lock_id = [0x02;32]`
inserted, then a nullifier with identical inner bytes inserted — both land in
disjoint subtrees and succeed.

## Wiring check (two-pipeline-confusion guard)

The only non-test caller that inserts a lock into the verkle tree is
`insert_lock_into_tree`, reached via `HyperBlockBuilder::apply_message`
(`builder.rs:116`). The receive-side / state-change path
(`importer.rs:269-271`) reuses the same `HyperBlockBuilder::apply_message`,
so it cannot bypass the length check. No production path calls
`lock_verkle_key` directly with an unvalidated, non-32-byte `lock_id`
(all other call sites are in `#[cfg(test)]` modules).

## Conclusion

Lock (0x01) and nullifier (0x02) key domains are correctly domain-separated:
distinct leading discriminator + equal 33-byte length make collision and
prefix overwrite impossible, and the length invariant is enforced on every
production insertion path. The F117 fix is present and wired. No finding.
