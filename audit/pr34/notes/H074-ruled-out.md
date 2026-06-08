---
id: H074
specialist: rust-crypto-primitives
attack_class: signing-payload-encoding
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/dkls_sign_driver.rs
  - code/hypersnap/src/hyper/mod.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/importer.rs
  - code/hypersnap/src/hyper/chain.rs
---

# H074 — signing-payload encoding feeding the DKLS sign ceremony

## Scope and framing

Task scope is `src/hyper/dkls_sign_driver.rs`, the runtime shell wrapping a
`DklsSignCoordinator` during a block-signing ceremony. Hunt angle:
field-coverage / canonical encoding — does the digest the committee signs
cover every security-relevant field canonically, and could two distinct
logical payloads collide to one digest or a field be malleable so the signed
digest fails to bind what gets applied? Distinct from H024 (sender-spoofing)
and H026 (cross-digest replay), both previously ruled out.

## What I examined

`dkls_sign_driver.rs` performs no encoding — it forwards `start/submit/
try_advance/drain_outbound` to the coordinator and tracks an F045 recovery-id
retry budget. The digest is computed by the caller in `actor.rs` and bound
into the coordinator at construction (`DklsSignCoordinator::new(party,
committee, digest)`, actor.rs ~2688). For block signing the digest is
`keccak256(HyperBlockMetadata::signing_payload(epoch, &committee_indices))`
(actor.rs 2681-2685). That encoder (`src/hyper/mod.rs:403`) is therefore the
real subject of this hunt.

## Findings — encoding is canonical and complete

`signing_payload` (mod.rs:403-452):
- Domain-separated: prefix `b"hypersnap-hyperblock-v2:"`.
- Every variable-length field carries a u32 BE length prefix
  (`parent_hash`, `hyper_state_root`, `snapchain_anchor_hash`,
  `snapchain_range_root`, per-entry `missed_proposals.validator_key`,
  and the `signer_indices` vector). No unprefixed concatenation, so no
  boundary-ambiguity collision between two distinct field splits.
- All integers BE; `signer_indices` is sorted before encoding (canonical
  regardless of producer ordering — verified by the
  `signing_payload_is_deterministic` sort-invariance assertion).

Field-coverage vs the canonical block hash (`chain.rs:hyper_block_hash`,
lines 25-44): the block hash mixes canonical_block_id, parent_hash,
hyper_state_root, extra_rules_version, retained_message_count, epoch,
group_address, ecdsa_signature. `signing_payload` covers all of the
metadata-derived block-hash fields **and more** (missed_proposals, the four
snapchain anchor/range fields, snapchain_anchor_timestamp, signer_indices).
group_address/ecdsa_signature are the signature itself and correctly excluded
from the signed preimage. Every field of `HyperBlockMetadata` (mod.rs:292-329)
is present in the encoding.

Applied-state binding (importer.rs:238-305): import verifies the signature
over `signing_payload`, replays locks+transfers through the same builder,
recomputes the verkle root, and rejects unless it equals the signed
`hyper_state_root`. Locks/transfers are thus transitively bound. The
`envelope.payload: Vec<u8>` is not state-applied (only carried through gossip/
storage adapters), so its absence from the preimage is not exploitable.
Scoring credits use the bound `signer_indices` and a caller-supplied
`proposer_index` from consensus context (not a block field), so neither is a
payload-encoding gap.

## Historical gaps already closed
- F028: prior v1 layout omitted `extra_rules_version` +
  `retained_message_count` (both block-hash-mixed) — now bound (lines 417-418),
  closing the one-sig-authenticates-many-block-hashes gap.
- F153: `signer_indices` lives on the signature struct; now committed
  (lines 445-450) so a malleated index set breaks the digest. Covered by the
  `signing_payload_is_deterministic` test (different/permuted index sets).

## Conclusion
No field-coverage shortfall, canonical-encoding collision, or field
malleability in the signing payload feeding the DKLS sign ceremony at this
commit. The scope file itself does no encoding. Ruled out.
