---
id: F002
specialist: chain-economics
attack_class: false-slash-via-unverified-evidence
file_paths:
  - src/hyper/slashing.rs
  - src/hyper/runtime.rs
  - src/hyper/actor.rs
  - src/hyper/slashing_store.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
severity_initial: high
title: F026 cross-epoch evidence slashes innocent validators who signed only one of the two epochs
related_findings:
  - F009
  - F015
relationship: related-but-distinct
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.72
  hypotheses_walked: 8
  validated_at: 2026-06-08T00:00:00Z
---

## Summary

The F026 cross-epoch slashing path (PR #34) accepts two blocks at the same
`canonical_block_id` carrying *different* epoch tags (`epoch_a != epoch_b`)
as a single "equivocation" conflict, then at enforcement time slashes the
**union** of both blocks' signer sets — block_a's signers resolved against
epoch_a's active set AND block_b's signers resolved against epoch_b's active
set.

Because epoch_a and epoch_b are distinct committees (membership and key
ordering differ), a validator who legitimately participated in **only one**
of the two epochs is slashed for a conflicting block produced by the **other**
epoch's committee, which they never signed and could not have prevented. The
classic same-epoch slashing model ("the epoch's committee collectively
misbehaved") does not transfer to two disjoint committees, but the code
applies it as if it did.

The per-block signature verification (`verify_evidence_signatures`) is
*correct* — each block is genuinely committee-signed for its claimed epoch.
The bug is not unverified evidence; it is that a *validly signed* epoch-A
canonical block is treated as incriminating evidence against epoch-A's
signers merely because some epoch-B block shares its height.

## Affected code (file:line)

- Detection accepts any two same-height blocks with no signer-set-overlap or
  non-canonical guard: `src/hyper/slashing.rs:52-77`
  (`detect_conflicting_blocks`).
- Ingestion verifies each block per-epoch then records, no overlap guard:
  `src/hyper/actor.rs:1587-1620` (`InboundEvidence` handler).
- Enforcement slashes the **union** of both blocks' signers, each resolved
  against its own epoch's active set:
  `src/hyper/runtime.rs:4199-4226` (`slashed_validators_for_epoch`).
- Eviction applied to the active set for `epoch+1`:
  `src/hyper/runtime.rs:4074-4104` (`get_active_validators_enforced` →
  `slashed_validators_for_epoch(prev, ...)`).
- Persisted under `min(epoch_a, epoch_b)`:
  `src/hyper/slashing_store.rs:53-69, 153-168`.

## Attack scenario

1. At height `H`, epoch 5 produces its legitimate canonical block `block_a`,
   threshold-signed by epoch-5's committee. Innocent validator `V` is a
   member of epoch 5's committee and signs `block_a`. `V` is **not** a member
   of epoch 6.
2. An attacker who controls (or colludes with) one member of epoch 6's
   committee gets epoch 6's group key to threshold-sign a junk block
   `block_b` whose `canonical_block_id` is set to the same `H` but with a
   different `hyper_state_root` (and arbitrary `signer_indices`). Since the
   epoch-6 committee can sign anything it agrees to, `block_b` is a *valid*
   epoch-6 signature.
3. Attacker submits `InboundEvidence { block_a, block_b }`.
   - `detect_conflicting_blocks` passes: same `canonical_block_id`, different
     hashes (`slashing.rs:52-77`).
   - `verify_evidence_signatures` passes: `block_a` verifies under epoch-5's
     group key, `block_b` under epoch-6's (`slashing.rs:89-110`).
   - Evidence is persisted under epoch `min(5,6)=5`
     (`slashing_store.rs:163`).
4. At the epoch-6 boundary, `get_active_validators_enforced(6)` calls
   `slashed_validators_for_epoch(5, ...)`, which iterates `block_a`'s signers
   against epoch-5's set — slashing innocent `V` (and every other epoch-5
   signer of the legitimate canonical block) — and `block_b`'s signers
   against epoch-6's set (`runtime.rs:4199-4226`).
5. `V`, who only ever signed epoch 5's honest canonical block, is evicted
   from the active set.

## Impact

False slashing / griefing eviction of honest validators. An adversary needs
only a single validly-signed block in *any* one epoch at a chosen height to
manufacture "cross-epoch equivocation" evidence that evicts the entire
honest committee of the *other* epoch at that height. This:

- Evicts honest validators from the active set (lost rewards, lost
  participation), violating the protocol's slashing-correctness invariant.
- Lets an attacker who can sign one junk block in their own epoch knock out
  the canonical committee of an adjacent epoch, a path to active-set capture
  / liveness degradation.

Severity assessed High: no fund-loss, but direct false-slash of innocent
validators with a low attacker bar (one signed block in one epoch).

## Root cause

The same-epoch equivocation model — "two conflicting blocks signed by the
same group key prove that group misbehaved" (`slashing.rs:3-7`) — is
extended to `epoch_a != epoch_b` without recognizing that the two blocks are
signed by **different committees**. The cross-epoch path therefore lacks the
predicate that actually justifies slashing: that the *same* validators
signed two conflicting blocks. Concretely, there is no check that the
penalized validators appear in *both* blocks' signer sets, and the legitimate
canonical block at `H` is treated as incriminating evidence against its own
honest signers solely because a foreign-epoch block reused its height.

A signature being valid (the F001 fix) is necessary but not sufficient: the
mapping `signer_indices → penalized-validator` correctly resolves each block
against its own epoch, but the *set semantics* (union of two disjoint
committees) is the defect — innocent epoch-A-only signers are penalized for
epoch-B's block.

## Suggested fix

Restrict the penalized set on the cross-epoch path to validators who actually
equivocated, i.e. the **intersection** of the two blocks' resolved signer
sets (validators present and signing in *both* `block_a` and `block_b`).
A validator who signed only one of the two blocks did not equivocate and must
not be slashed.

Equivalently / additionally:
- Require the equivocator to hold shares in both epochs (the stated F026
  justification at `slashing.rs:47-51` is "a validator holding shares for two
  consecutive epochs"), and slash only the resolved validator-keys common to
  both committees.
- Reject cross-epoch evidence where `block_a` is the chain's known canonical
  block at `H` (a canonical block is not equivocation evidence against its
  own signers).
- Constrain `|epoch_a - epoch_b|` to adjacent epochs and re-derive the
  penalized identity by validator-key, not by raw index union, before
  inserting into `slashed`.
