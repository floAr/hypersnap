---
finding_id: F011
title: '`ICertificateVerifier`''s statement is "each key in `signerBitmap` is a member of `setRoot`", but nothing fixes bit i to leaf i or fixes the'
severity: medium
status: pending-validation
related_findings:
- F040
---
# F011 — `ICertificateVerifier`'s statement is "each key in `signerBitmap` is a member of `setRoot`", but nothing fixes bit i to leaf i or fixes the member count; a verifier built to that statement can count one validator's key and signature many times

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation.

> **Status 2026-11-04 (post-validation):** Severity **Medium** (recalibrated 2026-11-04 from Low). Unsound route to the no-recovery state; see the F006 addendum.


- **Category:** cross-side-cert-statement-mismatch.
- **Specialist:** falcon-pq-message-auth · task H009
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** `poc/H009/merkle_index_ambiguity.py` (`python -I merkle_index_ambiguity.py`). It is a line-for-line port of `src/chain/merkle.rs` and `member_leaf`. For a 5-member set, member 4's leaf verifies against the true `set_root` both at `(index 4, size 5)` and at `(index 1, size 2)`. With the size fixed to 5, the alias is rejected and no other aliases exist.

## What each side means by a certificate

| | Rust node (`certificate::verify`, `src/chain/certificate.rs:123-190`) | `ICertificateVerifier` (`contracts/src/interfaces/ICertificateVerifier.sol:10-16`, `:29-30`) |
|---|---|---|
| Signer identity | bit `i` (MSB-first in byte `i/8`, `:40-42`) **is** `record.members[i]`. The node has the full member list, so position is fixed by construction. | Statement 1: "Each key in `signerBitmap` is a member of `setRoot`." The `@param` says "bit i = member i of set(epoch) in sorted order", but the statement does not require the proof to open leaf `i`, and the bit order within a byte is not stated. |
| Member count `n` | `members.len()`, used for the exact bitmap length and the zero padding (`:131-146`) | Not a public input. `setRoot` (RFC 6962, `merkle.rs:5-9`) does not commit `n`. `signerBitmap.length` gives `n` only to within 8. |
| Distinct signers | Signer indices come from distinct bits. Members are unique (`build_record` sorts and dedups, `validator_sets.rs:40-41`). | Not stated. |
| Weight | `Σ members[i].weight` over set bits, `3w > 2·total` (`:160-161`, `validator_sets.rs:130-132`) | "The weight of those keys is more than 2/3 of `totalWeight`". With repeated keys, "those keys" is ambiguous (set or multiset). |
| Signed bytes | Falcon over `CONSENSUS_VOTE ‖ vote_digest(commit)` = `"hypersnap-consensus-vote-v1" ‖ d`. This is the same `d` as `certPayloadDigest` (H001). | Same. |

## Two ways a verifier faithful to the text is unsound

1. **Membership-only openings.** For each set bit, the prover supplies some leaf, a Merkle path
   to `setRoot`, and a Falcon signature by that leaf's key on `d`. Statement 1 holds (the key is a
   member), statement 3 holds (that key signed `d`), and statement 2 sums the leaf weight once per
   bit. A single honest-looking member sets all `n` bits and reuses its one signature. Then
   `w = n > 2n/3`.
2. **Positional openings with a per-opening tree size.** RFC 6962 audit paths need `(index, size)`
   (`merkle.rs:87`). If the circuit takes `size` as a per-opening witness, which is natural when
   it reuses an RFC 6962 gadget per signer, the last leaf of an unbalanced tree opens at several
   positions. The PoC shows member 4 of 5 opening as bit 4 and as bit 1. Its weight is counted
   twice. Larger and odd `n` give more aliases (any leaf that is the sole right child of a
   subtree). With one global `n`, the mapping index → leaf is injective (PoC: "aliases with
   n=5: []").

Neither problem exists on the Rust side, which never uses Merkle proofs for certificates. The
gap is only in what V2's interface promises and what it does not.

## Red-team (invalidation hypotheses walked)

1. *The `@param` already says "bit i = member i", so the statement is positional.* Partly true.
   That is why this finding is Low and not higher. But "member i" needs `n` to be meaningful for
   an RFC 6962 tree, `n` is not an input, and the three numbered statement items, which are
   what an implementer proves, are membership-only.
2. *Weight-1 members make `n = totalWeight`, so a verifier can derive `n`.* True at `7eb981b`
   (`validators.rs:132`, `genesis_file.rs:236`). But this is an implicit coupling that nothing in
   the interface states. A verifier that derives `n` from `totalWeight` breaks if weights ever
   differ from 1. The verifier should prove `n` and `Σweight == totalWeight` from the leaves
   instead.
3. *Can a second-preimage attack (leaf vs node) do the same?* No. Leaf and node hashes are
   prefixed `0x00` / `0x01` (`merkle.rs:19-32`). Leaves are 80 bytes and node preimages 65 bytes.
4. *Is the set itself free of duplicates?* Yes. `build_record` dedups by `consensus_key_hash`
   (`validator_sets.rs:41`), and validator records are stored keyed by `consensus_key_hash` (`shard0/validators.rs:209`, `members_at` `:126-137`). So positional
   openings with a fixed `n` imply distinct keys.
5. *Does the bridge check `signerBitmap` itself?* No. It is forwarded as is
   (`HypersnapBridgeV2.sol:465-467`). The bridge does not know `n`.
6. *Already covered by H001's verifier list?* H001 lists "membership of each signer in the
   sorted set", MSB-first order, and bitmap length / padding. It does not state positional
   binding, a single `n` bound to `setRoot`, or multiset vs set weight. Those are what make
   items 1–2 sound. This finding adds them and the PoC. It does not repeat H001.
7. *Overstated impact?* The Critical impact applies only to a hypothetical verifier built to the
   letter of the text. Severity reflects that.

## Fix (interface text, before the verifier is built)

Rewrite the `ICertificateVerifier` statement as:

1. There is a list `L = (leaf_0, …, leaf_{n-1})` of 80-byte member leaves
   (`consensus_key_hash ‖ u64 weight ‖ node_key_hash ‖ u64 fid`) with
   `merkle::root(L) == setRoot` for **one** `n` that the proof fixes.
2. `signerBitmap.length == ceil(n/8)`, and bits `≥ n` are zero. Bit `i` is
   `signerBitmap[i/8] & (0x80 >> (i%8))`.
3. For **each** set bit `i`, the proof uses `leaf_i` (that position), opens the Falcon key `pk_i`
   with `keccak256(pk_i) == leaf_i[0..32]`, and verifies a Falcon signature by `pk_i` on `d`
   (profile in F010).
4. `W = Σ_{i set} weight_i` (each position once), `T = Σ_{all i} weight_i`, `T == totalWeight`, and
   `3·W > 2·T` as integers (no wrap).

## Requirements for the CERT-STARK verifier

In addition to H001's list (bind `d` as given, CONSENSUS_VOTE domain, MSB-first bit order,
`setRoot`/`epoch` as public inputs, exact bitmap length and zero padding) and F004's (false for
`totalWeight == 0` / empty bitmap):

- **R-pos:** opening `i` must be the leaf at position `i` of the tree. No free leaf choice per bit.
- **R-n:** a single member count `n` is fixed for the whole proof and bound to `setRoot`. The
  cheapest sound way is to recompute `setRoot` from all `n` leaves in the circuit. This costs `n`
  leaf hashes, which is small for validator sets, and gives `T` for free. Do not take a tree size
  per opening, and do not infer `n` from `signerBitmap.length` or from `totalWeight`.
- **R-weight:** sum weights over set positions (multiset impossible by R-pos/R-n). Prove
  `Σ_all weight == totalWeight`, so the bridge's `totalWeight[e]` (from `next_total_weight`) and
  the leaves agree. Evaluate `3W > 2T` over integers with range-checked 64-bit weights. In
  Goldilocks, `3·W` or a sum of many u64 values can wrap.
- **R-sig-per-position:** one signature check per set bit. The same signature bytes may appear
  only if the same position appears, which R-pos excludes.
- **Failure behaviour:** for each violation, return `false` (the interface says it must not
  revert on a well-formed invalid proof). V2 turns `false` into `BadCertificate`.

## Addendum (2026-11-04)

This is the unsound-verifier route into the no-recovery state. Once a verifier faithful to the literal statement is installed, the honest set cannot pause or cancel an attacker upgrade (F004 path 3). See the F006 addendum, "the immutable verifier has no recovery path".
