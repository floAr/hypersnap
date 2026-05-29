---
id: F190
task: H210-fork
attack_class: consensus-divergence
severity: info
status: draft
---

# PR#32 fork-drift sweep — signing/serialization-determinism surface is PARITY (no consensus-divergence introduced)

## Summary

Focused fork-drift sweep of hypersnap @ PR#32 tip `4a6bca5` against the
authoritative v17 spec (snapchain v0.12.0 @ `da51554`), scoped to the
**consensus-deterministic** surface: the bytes that get SIGNED or HASHED,
the accept/reject decision for VALID consensus messages, and
CommitCertificate construction. The four requested surfaces were swept in
full (whole changed functions plus the helpers they call).

**Result: PARITY CONFIRMED on every fork-relevant path.** PR#32's only
change on this surface is the F151 fix — it adds *fallible* decode helpers
(`try_from_proto` / `try_to_commit_certificate` / `try_from_vec`) and rewires
the malachite `SnapchainCodec` decode arms to use them, converting prior
*panics on malformed input* into *decode errors*. For every VALID input the
reconstructed value and the produced wire bytes are bit-identical to
snapchain. No signed-byte layout changed, no certificate aggregation order
changed, no VALID message is accepted by one impl and rejected by the other.
The producer/encode side and all consensus wire-proto field numbers are
unchanged and remain wire-identical to snapchain. **PR#32 introduces no
fork/equivocation surface.**

The residual *panic-on-malformed* path that PR#32 did NOT route through the
new fallible helper is already captured as **F185** (`verify_signatures` →
`to_commit_certificate` on the read-node ingress) — that is a liveness/DoS
issue, not a fork, and is out of this sweep's scope.

## hypersnap-vs-snapchain divergence (file:line)

### Surface 1 — `src/core/types.rs` sign-bytes & proto round-trip

- `Vote::to_proto` — hypersnap `types.rs:410-426` vs snapchain `types.rs:401-417`:
  **IDENTICAL** (same field set, same `height: Some(..)`, `round.as_i64()`,
  `voter.to_vec()`, `r#type as i32`, `value` Nil→None mapping).
- `Vote::to_sign_bytes` — hypersnap `types.rs:468-470` vs snapchain
  `types.rs:438-440`: **IDENTICAL** (`self.to_proto().encode_to_vec()`).
  Signed byte layout unchanged.
- `Vote::from_proto` — hypersnap `types.rs:428-445` vs snapchain
  `types.rs:419-436`: **IDENTICAL** (unchanged by PR; still panics on
  type∉{0,1}, `height.unwrap()`, `voter` len≠32).
- `Vote::try_from_proto` (NEW, hypersnap `types.rs:447-466`): for every input
  that snapchain's `from_proto` accepts *without panicking* (type∈{0,1},
  `height` present, `voter` len==32) it produces the **byte-identical**
  `Vote`. It returns `Err` exactly where snapchain `from_proto` would `panic`.
  → **No VALID-input divergence.** (accept/reject set is identical for valid
  inputs; only panic→Err on malformed — out of scope per task.)
- `Proposal::to_proto` / `to_sign_bytes` — hypersnap `types.rs:483-491` /
  `515-518` vs snapchain `types.rs:452-461` / `472-475`: **IDENTICAL.**
- `Proposal::from_proto` — hypersnap `types.rs:493-501` vs snapchain
  `463-471`: **IDENTICAL** (unchanged).
- `Proposal::try_from_proto` (NEW, hypersnap `types.rs:502-513`): rejects
  `height==None`, `value==None`, `proposer` len≠32 — precisely the inputs
  snapchain panics on. For valid inputs the reconstructed `Proposal` is
  byte-identical. → **No VALID-input divergence.**
- `Address::try_from_vec` (NEW, hypersnap `types.rs:80-87`) vs
  `Address::from_vec` (hypersnap `74-78` == snapchain `74-78`): for `vec.len()
  == 32` both produce the **identical** `Self(bytes)`; `try_from_vec` errs
  where `from_vec`'s `copy_from_slice` panics (len≠32). → No valid divergence.

### Surface 2 — `src/consensus/malachite/snapchain_codec.rs`

- **encode** (all 6 impls) — hypersnap == snapchain, **textually identical**
  byte-for-byte: `SignedConsensusMsg` encode (hs `62-88` / sc `58-84`),
  `FullProposal` encode (hs `98-100` / sc `94-96`), `StreamMessage` encode
  (hs `124-131` / sc `117-124`), Status/Request/Response encode. → No
  producer-side drift. **F151's StreamMessage "drops stream metadata" behavior
  is present in BOTH** (both encode only the inner `FullProposal` via
  `self.encode(proposal)`); hypersnap did not drift here.
- **decode — `SignedConsensusMsg`** (hs `34-60` vs sc `34-56`): hypersnap
  swaps `Vote::from_proto`→`Vote::try_from_proto` and
  `Proposal::from_proto`→`Proposal::try_from_proto`, mapping `Err` to
  `InvalidField`. Decoded value for valid input is identical. → panic→Err only.
- **decode — ValueResponse** (hs `233-253` vs sc `226-243`):
  `to_commit_certificate()`→`try_to_commit_certificate()`. Same cert for valid
  input (see Surface 4). → panic→Err only.
- **decode — VoteSetResponse `.zip()`** (hs `254-277` vs sc `245-264`): both
  use `vote_set.votes.into_iter().zip(vote_set.signatures)`. `zip` truncates to
  `min(votes.len(), signatures.len())` in **both** impls → **identical
  membership** when the two repeated fields differ in length. hypersnap only
  made the per-element `Vote::from_proto` fallible; the zip-truncation
  semantics are unchanged. → **No truncation/membership drift.**

### Surface 3 — `proto/definitions/*.proto`

- `blocks.proto` (defines `Vote`, `Proposal`, `Commits`, `CommitSignature`,
  `ConsensusMessage`, `FullProposal`, `ShardHash`, `Height`, and all
  `Sync*Request/Response` consensus-wire messages): **byte-identical to
  snapchain v0.12.0 and unchanged from PR-base** (`ab945ec`). All consensus
  field numbers/types are wire-compatible. A hypersnap-encoded consensus
  message decodes identically on snapchain.
- PR#32 proto changes (`message.proto` `USER_DATA_TYPE_LIVE_AT = 14`;
  `request_response.proto` `+SignersByFidRequest`, `+SignersByFidResponse`
  fields 5/6; `rpc.proto` `GetSignersByFid(FidRequest)` →
  `GetSignersByFid(SignersByFidRequest)`): all on the **gRPC query / app
  surface**, NOT the consensus/gossip wire. No field-number REUSE, no type
  change on an existing consensus field. → **Not consensus-deterministic; no
  fork surface.** (Tracked separately as F165/F166 on the query surface.)

### Surface 4 — `Commits` / CommitCertificate construction

- `Commits::to_commit_certificate` — hypersnap `types.rs:758-780` vs snapchain
  `types.rs:709-731`: **IDENTICAL** (unchanged).
- `Commits::try_to_commit_certificate` (NEW, hypersnap `types.rs:782-809`):
  iterates `self.signatures.iter()` in the **same order** (no sort/reorder),
  builds `CommitSignature { address, signature }` in the same field order, and
  passes them to `AggregatedSignature::new(signatures)` — producing a
  CommitCertificate with **identical** `height` / `round` / `value_id` and an
  **identically-ordered** `aggregated_signature` to snapchain's
  `to_commit_certificate` for any VALID `Commits`. Errs (vs snapchain panic)
  only on `height==None`, `value==None`, or a signer len≠32. → **No
  aggregation-order drift → no cross-impl certificate-verification fork.**

## Fork / equivocation impact

**None introduced by PR#32.** A fork or cross-impl signature failure on this
surface would require one of: (a) a change to the SIGNED/HASHED byte layout
(`to_proto`/`to_sign_bytes`) — unchanged; (b) a VALID consensus message
accepted by one node and rejected by another — not the case, the accept set
for valid inputs is identical and only the malformed-input outcome changed
from panic to Err; (c) a different CommitCertificate aggregation order — not
the case, order is preserved; (d) a consensus wire-proto field-number/type
change — none. The only behavioral delta (malformed peer input → `Err` instead
of node panic) is strictly a liveness improvement and cannot cause two honest
nodes to disagree on a validly-signed message.

## PoC status

No fork-drift PoC is warranted: there is no divergence to demonstrate on the
consensus-deterministic surface. The differential reasoning is exhaustive and
source-anchored above. A confirmatory equality test (build a valid
`Vote`/`Proposal`/`Commits`, assert `try_from_proto`==`from_proto` and
`try_to_commit_certificate`==`to_commit_certificate` byte/field-for-byte) is
trivially true by construction — `try_*` differs from the original only in the
error branch, which is unreachable for valid input. Not run, since a green test
would only restate the source-level identity already established and would
require modifying tracked files.

## Severity

Info / negative result. This finding documents a clean negative across all
four requested surfaces; it is not a vulnerability. (The PR#32 codec/types
change is the F151 fix; the residual non-fork panic path is F185.)

## Remediation

None required for fork-drift. Unrelated tracking: F185 (residual
`to_commit_certificate` panic on read-node `verify_signatures` ingress) should
be routed through `try_to_commit_certificate` to complete the F151 fix, but
that is a DoS/liveness item, not a consensus-divergence item.
