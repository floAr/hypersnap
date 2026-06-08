# F028 validation — DKLS threshold hard-pinned to 1

Validator: validator (deliberate-disagreement). Commit `cab225f` (workspace HEAD).
Finding claims: `main.rs:1603 let dkls_threshold = 1u8;` flows unchecked into the
per-epoch DKG, yielding a 1-of-N group key, so any single committee-elected
validator unilaterally produces the group threshold signature over hyperblocks,
rewards, trust snapshots, and bridge authorizations. Severity: Critical.

## Evidence chain re-verified (read-only)

- `src/main.rs:1603` — `let dkls_threshold = 1u8;` — no nearby comment marking it
  phased/testnet/placeholder. Grep for `testnet|phase|placeholder|TODO` near line
  1603 found nothing on that line.
- `src/main.rs:1650` — `threshold: dkls_threshold` passed into
  `DklsSupervisorInputs`. Spawned only on signing validators (operator identity
  configured) — i.e. the production validator path, not a test stub.
- `src/hyper/dkls_supervisor.rs:192,203-205` — `share_count = active.len()` (real
  active set), `parameters = Parameters { threshold: inputs.threshold, share_count }`.
  No floor, no `threshold vs share_count` relationship check. Confirmed.
- `src/hyper/dkls_committee.rs:59` — `select_signing_committee` rejects only
  `threshold == 0 || threshold > share_count`; `take(threshold)` ⇒ returns exactly
  1 index for threshold=1. Confirmed.
- `crates/hypersnap-crypto/src/dkls_threshold.rs:115` — `run_honest_dkg` rejects
  only the same two cases. Confirmed.
- `src/hyper/actor.rs:2645-2666` — at sign time threshold is read back from the
  installed share and fed to `select_signing_committee`; only committee members
  sign. With threshold=1 a single lowest-rank party signs and broadcasts.
- `src/hyper/actor.rs:2711` — `signing_committee().len() == 1` is an explicitly
  supported fast path ("1-of-1 case completes within a single tick"). Confirms a
  size-1 committee is a first-class operating mode, not an error.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS
Is there a check upstream of `build_driver` that forces threshold ≥ 2? No. The
only field is the static `dkls_threshold = 1u8` in `main.rs`; it is the sole
producer of `inputs.threshold`. There is no config validation, env override, or
runtime clamp between `main.rs:1603` and `Parameters` construction. The supervisor
guards EmptyActiveSet / ActiveSetTooLarge / LocalNotActive only — none constrain
threshold. No upstream gate exists.

### 2. Consumer-side impact — STANDS (impact real, with one scoping nuance)
What consumes the group signature? `src/hyper/sig_verify.rs` verifies hyperblock,
reward-issuance, trust-snapshot, and DA-epoch-seed signatures. In every path the
verifier recovers ONE 65-byte ECDSA signature against the per-epoch group address
(`dispatch`, lines 74-77) and fails closed only on address mismatch. There is NO
check that `signer_indices.len() >= quorum` — grep for `signer_indices.len`,
`quorum`, `2f+1`, `two-thirds` across `src/` returned no DKLS-side quorum gate.
Therefore a signature produced by a 1-member committee recovers to the legitimate
group address and verifies. The corrupted "state" (a 1-of-N key) is directly
consumed by the authority verifier with no compensating count check. The bridge /
reward / hyperblock authority is genuinely exercised by a single party.
Nuance: the *on-chain L1 bridge* enforcement (EVM side) is outside this repo; the
finding's "mints arbitrary wrapped SNAP / seizes bridge owner" claim depends on the
L1 contract trusting the group address signature, which per `docs/00-OVERVIEW.md`
lines 28,47-48 it does ("threshold-signs root updates / owner rotations"). That is
the documented trust model, so the consumer is real. Impact not overstated.

### 3. Downstream enforcement — STANDS
Does a lower layer re-check for a real quorum? The only `quorum.is_met` in the
codebase is `src/core/util.rs:132`, which validates the **legacy Snapchain Ed25519
block certificate** (`certificate.aggregated_signature.signatures` against the shard
`validator_set.validators`). That is a different pipeline (two-pipeline-confusion
guard applied) — it does not touch the DKLS hyper threshold signature and provides
no floor on the DKLS committee size. No downstream layer re-enforces a t-of-n quorum
for the group signature. Confirmed not caught downstream.

### 4. PR HEAD currency — STANDS
`git rev-parse HEAD` = `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, identical to the
finding's pinned `commit`. Workspace is a detached checkout at the pinned SHA; the
cited lines are current. No drift.

### 5. Spec carve-out — STANDS (special-scrutiny target)
Hard search for documentation declaring threshold=1 intentional/phased/testnet:
- No comment at or near `main.rs:1603` says phased/placeholder; the adjacent
  comments describe block_time / supervisor_lead_blocks, not the threshold.
- `docs/00-OVERVIEW.md` describes the system as "**threshold ECDSA (DKLS23)**"
  (line 18) and lists the group signature as authority over hyperblocks, rewards,
  and "bridge merkle-root updates / owner rotations / pause / upgrade" (lines 28,
  42-48). It presents threshold signing as the *security model*, with no carve-out
  that t=1 is an accepted current-phase configuration.
- `crates/hypersnap-crypto/src/dkls_threshold.rs:104-106` mentions a "single-operator
  dummy ceremony" only for the bridge-ceremony *tool*, not the production node.
- No README / SECURITY.md / docs/hyper.md (no `threshold`/`dkls` matches) flags
  t=1 as known-incomplete.
Conclusion: this is NOT a documented phased config. The code presents a full N-party
DKG while silently fixing reconstruction at 1, and the docs assert real threshold
security. The carve-out hypothesis fails — finding stands.
Caveat noted: `dkls_threshold = 1u8` with the comment "Conservative defaults;
operators can re-tune via config fields if/when those land" (main.rs:1597-1598)
*could* be read as a not-yet-wired-config placeholder. But (a) no config plumbing
exists to override it, (b) the docs claim threshold security regardless, and (c) the
spawn is gated on production operator identity — so the live default is t=1 with no
operator escape hatch. This lowers neither reachability nor severity; it is at most
an "operator docs don't warn it's incomplete" framing on top of a real exposure.

### 6. Reachability of harm — STANDS
Can a single validator actually extract value? Path: a validator in the active set
wins the deterministic committee draw for some `(epoch, height, parent_hash)` →
`select_signing_committee` returns its index alone → it runs single-party DKLS sign
→ broadcasts a full `(r,s,v)` recovering to the group address → `sig_verify`
accepts it (no cosigner / count requirement). The committee selector is keyed on
non-grindable consensus-pinned fields (F036 fix), so the validator cannot freely
target a digest, BUT with threshold=1 *every* ceremony has a size-1 committee, so
across epochs a given validator is selected for many `(epoch,digest)` tuples and
needs only the ones it is selected for to forge authority for that payload. Bridge
owner-rotation / lock-root payloads are among the signed authorities
(docs/00-OVERVIEW.md:47-48). Harm is reachable for any payload the lone signer is
elected to sign. Not gated.

### 7. Test wiring — STANDS
Is the buggy path production or test-only? `main.rs:1603` is in the node bootstrap
(`HyperHttpHandler` construction), spawned under the real
`operator_validator_pubkey_hex` + `local_dkls_share_path` gate (lines 1572-1591) —
the production signing-validator path, not `#[cfg(test)]`. The supervisor, driver,
committee selector, and `sig_verify` are all production modules. Tests
(`pinned_vector_one_of_three`, `selection_size_equals_threshold`,
`dkls_integration_test.rs:150`) merely *confirm* size==threshold behavior. The bug
is in production wiring.

### 8. PoC mechanics — STANDS
The finding has no executable PoC, but cites unit tests as corroboration:
`pinned_vector_one_of_three` (committee of size 1 for a 3-party group) and
`selection_size_equals_threshold` prove `committee.len() == threshold`, and
`actor.rs:2711` proves a size-1 committee finalizes a full signature. These
assertions prove exactly the prose claim: threshold=1 ⇒ one signer produces a
valid group signature. The assertion cannot pass for an unrelated reason (it is a
direct size/threshold equality on the selection function actually used in prod via
actor.rs:2659). Mechanics sound.

## Overall verdict

WATERPROOF — confidence 0.9.

Every hypothesis STANDS. The two adversarial targets called out in the brief:
- Spec carve-out (#5): no doc/comment declares t=1 phased/testnet; the overview
  asserts real threshold security. The only mitigating reading ("config not yet
  wired") does not reduce the live exposure because no override path exists and the
  default ships t=1 on the production validator path.
- Consumer/reachability (#2/#6): the downstream verifier enforces only
  address-recovery, with NO `signer_indices`/quorum floor; the legacy Ed25519
  certificate quorum (util.rs:132) is a separate pipeline and does not apply. A
  single elected validator's signature verifies as the group authority.

Confidence held at 0.9 (not 1.0) for two honest residuals: (a) the EVM-side L1
bridge contract is out of this repo, so the literal "mint wrapped SNAP / seize
owner" L1 consequence is asserted from the docs' trust model rather than verified in
contract code here; (b) the "config may be intended to be operator-tunable later"
comment introduces a small framing ambiguity. Neither changes the core defect: in
the production node path the group threshold is fixed at 1 with no floor or operator
override, defeating the t-of-n premise. Critical severity is appropriate.

## Open follow-ups (NOT new findings)
- The on-chain L1 bridge contract (EVM, outside this repo) should be checked to
  confirm it trusts only the group address signature with no independent multisig;
  if it does, the bridge-takeover impact is fully concrete. Validator cannot create
  findings — flagging for hunt specialists.
- `main.rs:1597-1598` "operators can re-tune via config fields if/when those land"
  suggests intended-but-unwired threshold config; worth a hunt pass on whether any
  partial config plumbing exists elsewhere.
