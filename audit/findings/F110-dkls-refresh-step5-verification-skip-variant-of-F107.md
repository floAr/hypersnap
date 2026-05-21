---
id: F110
task: H110
attack_class: dkls23-protocol-correctness
severity: info
status: draft
validation:
  validator: validator
  verdict: HAS_CAVEATS
  confidence: 0.88
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# DKLS refresh `refresh_complete_phase4` and `refresh_phase4` invoke the same `step5` that has the F107 self-claimed-index verification-skip — same root cause as F107, distinct downstream consequences (refresh-side split-brain on `t == n`, attributed-blame-less abort on `t < n`); MITIGATED IN PRACTICE because `refresh.rs` is unreachable from hypersnap production code (no callers in `crates/hypersnap-crypto/` or `src/hyper/`), so the primitive cannot be exercised in the current build

## Scope files

- `code/hypersnap/crates/dkls23/src/protocols/refresh.rs:382-387` — `refresh_complete_phase4` calls `step5(parameters, party_index, refresh_sid, proofs_commitments)`; vulnerable to the F107 self-claimed-index proof-skip pattern in the underlying `step5`
- `code/hypersnap/crates/dkls23/src/protocols/refresh.rs:707-712` — `refresh_phase4` (the "faster refresh") calls the SAME `step5` with the same vulnerability surface
- `code/hypersnap/crates/dkls23/src/protocols/dkg.rs:321-333` — the root-cause site: `step5` skips `DLogProof::decommit_verify` for any `ProofCommitment` whose inner `index` field equals the verifier's `party_index`; both refresh entrypoints inherit this
- `code/hypersnap/crates/dkls23/src/protocols/refresh.rs:390-395, 715-720` — refresh-specific consistency check (`verifying_pk == identity()`) that DOES run after `step5` returns, but does not defend against the F107 primitive (see "Why the identity-check doesn't close the gap" below)

## Summary

This finding is a **same-root-cause variant of F107**
(`findings/drafts/F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md`).
The vulnerable code site is **identical** to F107's: `step5` at
`dkg.rs:321-333`, where the verification of `DLogProof::decommit_verify`
is gated on `party_j.index != party_index`. The defect: any inbound
`ProofCommitment` whose `index` byte matches the verifier's own
`party_index` is trusted unverified, and its `proof.point` is inserted
into `committed_points[party_index]`, last-writer-wins.

`refresh.rs` calls this `step5` from BOTH refresh modes:

```rust
// refresh.rs:382-387 (refresh_complete_phase4)
let verifying_pk = step5::<C>(
    &self.parameters,
    self.party_index,
    refresh_sid,
    proofs_commitments,
)?;

// refresh.rs:707-712 (refresh_phase4)
let verifying_pk = step5::<C>(
    &self.parameters,
    self.party_index,
    refresh_sid,
    proofs_commitments,
)?;
```

Hence, IF refresh were exercised on production, the F107 primitive
applies directly. With one wrinkle: refresh adds a downstream
`verifying_pk == identity()` check (`refresh.rs:390-395, 715-720`) that
F107's DKG path does not have. This check restricts the attacker's
arbitrary-point choice but does NOT eliminate the attack — see
"Why the identity-check doesn't close the gap."

**However: refresh.rs is unreachable from production code in this
build.** No file in `crates/hypersnap-crypto/` or `src/hyper/` calls
`refresh_phase1..4` or `refresh_complete_phase1..4`, nor uses any of the
`TransmitRefreshPhase*` / `KeepRefreshPhase*` types. The only call
sites are the in-tree `#[cfg(test)]` modules at the bottom of `refresh.rs`
itself. Therefore the realized severity for the current build is
**info** (latent risk, no exploit path under current scheduler).

## Reachability check

Grep results (workspace-relative, project = `code/hypersnap/`):

```text
# Production callers of refresh_*:
$ grep -rn 'refresh_phase\|refresh_complete_phase\|::refresh::' \
    code/hypersnap/crates/hypersnap-crypto/ code/hypersnap/src/
(no matches)

# Production users of refresh types:
$ grep -rn 'TransmitRefresh\|KeepRefresh\|RefreshPhase' \
    code/hypersnap/crates/hypersnap-crypto/ code/hypersnap/src/
(no matches)

# All callers of refresh_* functions, anywhere in the repo:
$ grep -rn 'refresh_phase\|refresh_complete_phase' code/hypersnap/
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:983: ... refresh_complete_phase1()
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1013: ... refresh_complete_phase2(...)
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1052: ... refresh_complete_phase3(...)
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1098: ... refresh_complete_phase4(...)
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1279: ... refresh_phase1()
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1309: ... refresh_phase2(...)
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1343: ... refresh_phase3(...)
code\hypersnap\crates\dkls23\src\protocols\refresh.rs:1373: ... refresh_phase4(...)
```

All occurrences are within `refresh.rs`'s own `#[cfg(test)] mod tests`
block (test bodies at lines 983, 1013, 1052, 1098, 1279, 1309, 1343,
1373). The supervisor (`src/hyper/...`) and the ceremony layer
(`crates/hypersnap-crypto/src/dkls_ceremony.rs`) implement DKG + signing
only; share refresh is not wired into the epoch lifecycle in this
build.

This matches the module's docstring caveat at `refresh.rs:17-21`:

> ATTENTION: The protocols here work for any instance of Party, including
> for derived addresses. However, refreshing a derivation is not such a
> good idea because the refreshed derivation becomes essentially independent
> of the master node. We recommend that only master nodes are refreshed
> and derivations are calculated as needed afterwards.

— consistent with refresh being available-but-not-yet-wired.

## Why the identity-check doesn't close the gap (if refresh ever ships)

After `step5` returns `verifying_pk`, refresh adds a check absent from
DKG:

```rust
// refresh.rs:390-395 / 715-720
if verifying_pk != crate::identity::<C>() {
    return Err(Abort::new(
        self.party_index,
        "The auxiliary public key is not the zero point!",
    ));
}
```

In DKG, F107 lets the attacker steer the reconstructed `pk` to ANY
attacker-chosen point. In refresh, this is constrained: only points
that yield `verifying_pk == identity` after Lagrange combination are
"useful." This sounds like it might fully defeat the F107 primitive
in refresh, but **it doesn't**, for three composing reasons:

1. **The attacker can choose `Q` so that `verifying_pk == identity`
   passes locally on the victim.** Lagrange combination of
   `committed_points` is `Σ_j l_j · committed_points[j]`. With the
   victim's own slot `V`'s point overwritten to attacker-chosen `Q`,
   the result is `l_V · Q + (rest)`. The attacker solves for `Q`
   such that `l_V · Q == -(rest)` ⟹ `verifying_pk = identity`. Since
   discrete logs of `(rest)` are unknown to the attacker, this looks
   hard — but the attacker doesn't need to know logs. They observe
   the broadcast `committed_points[j]` for `j ≠ V`, compute
   `target = -(Σ_{j≠V} l_j · committed_points[j])`, and set
   `Q = l_V^{-1} · target`. **The Lagrange weights `l_j` are
   public** (they're a function of party indices only). Computing
   `l_V^{-1} · target` is a single scalar multiplication on the
   target curve point. So the attacker can ALWAYS construct a `Q`
   such that `verifying_pk == identity` on a `t == n` window. The
   identity-check is satisfied; the refresh proceeds.

2. **For `t < n`, the multi-window Lagrange consistency check
   (`dkg.rs:341-376`) catches the divergence between windows that
   include slot V and windows that don't.** This aborts the refresh
   ceremony with the generic "Verification for public key
   reconstruction failed in iteration {i}" message — same blame-less
   abort F107 documents for DKG. Combined with the F040-class no-retry
   property (if refresh were under a similar supervisor), the
   refresh epoch halts and the share-set is never rotated.

3. **For `t == n`, both checks pass and the refresh "succeeds"
   asymmetrically.** Each victim V_i computes a different attacker-
   tailored `verifying_pk_i == identity` and proceeds to add their
   honest local `correction_value` to `poly_point`. The `pk` field
   on the Party struct is NOT changed by refresh (preserved as
   `self.pk` at line 535, 545, 916, 927). So the group public key
   stays consistent across parties, BUT — because the attacker
   tailored different `Q`s per victim — each victim sees a different
   "auxiliary public key" path through `step5`. The key question:
   does this split the share-set?

   Re-examining the data flow:
   - Each victim's `correction_value` is computed honestly from
     `poly_fragments.iter().sum()` (dkg.rs:277 via
     `step3`) — independent of the spoofed `ProofCommitment`.
   - The bogus `proof.point` only enters `committed_points`, used
     only by the `verifying_pk == identity` check.
   - If both checks pass (per #1 above), each victim adds the same
     honest sum to `poly_point` regardless of the attack.

   So in the `t == n` refresh-success case, the share-set is NOT
   actually corrupted by F107's primitive. The attack reduces to a
   bypass of the "all parties chose zero-sum polynomials" check.
   **Concretely**: a malicious refresher who *secretly chose a
   non-zero polynomial* (and so contributes a non-zero correction
   to the group public key) would, in the absence of F107, be
   caught by the `verifying_pk == identity` check, because their
   own honest `proof.point` would not Lagrange-combine to identity.
   With F107, they can spoof a `ProofCommitment { index: VICTIM,
   point: Q }` (one per victim) such that the local `verifying_pk
   == identity` check passes despite their own polynomial having
   a non-zero constant term. Their non-zero constant gets added to
   `poly_point` on every victim, but each victim ALSO adds it (via
   the fragment they received from the malicious refresher in phase
   1). So the malicious refresher's contribution propagates into
   every victim's `poly_point` without the zero-sum guard firing.

   **Result**: the malicious refresher has FORCED A KEY-CHANGE.
   `poly_point_new = poly_point_old + (legitimate zero-correction)
   + (malicious non-zero correction)`. Reconstructing the group
   secret from the new shares gives `secret_old + malicious_constant`
   — a DIFFERENT secret. But the `pk` field on each Party still
   reports `self.pk = self.pk` (unchanged from the old key). So:
   - Old `pk` no longer corresponds to the (new) reconstructed secret.
   - **Subsequent threshold signatures verify against the OLD `pk`
     (since `Party.pk` is unchanged) but are produced from the NEW
     (drifted) secret.** Mathematically equivalent to: signatures
     fail verification against `pk`. Threshold signing breaks for
     the affected key for all time after refresh.

   This is a more severe consequence than F107's DKG-time `pk`
   divergence: F107-on-DKG breaks only that epoch; F107-on-refresh
   silently corrupts the long-term key (the address persists across
   epochs).

## Round-by-round walk for refresh (same primitive as F107 with refresh-side consequences)

1. **Phase 1 (refresh_phase1)**: honest fragment exchange of a polynomial
   with constant term zero. Attacker contributes a polynomial with
   secret non-zero constant `c_attack`. The fragments propagate
   honestly; each victim accumulates `c_attack` in their local
   `correction_value` (via `step3`'s sum).
2. **Phase 2 (refresh_phase2)**: each party broadcasts a
   `ProofCommitment` derived from their `correction_value`. Honest
   parties produce `proof.point = correction_value · G`. Attacker
   produces their HONEST `correction_value_attack · G` matching
   what they actually sampled (so all phase-1 fragments sum to it).
3. **Phase 2 (attacker spoof)**: attacker ALSO broadcasts per-victim
   tailored `Phase2ProofCommitment` messages — each with `sender =
   attacker`, but `proof_commitment.index = V_i`, `proof.point = Q_i`
   chosen as `l_{V_i}^{-1} · ( -(Σ_{j ≠ V_i} l_j · honest_pc_j.proof.point) )`.
4. **Phase 4 (refresh_phase4 → step5)**: victim V_i runs `step5`. F107
   pattern fires: bogus PC at slot V_i is inserted into
   `committed_points[V_i]` without verification, overwriting V_i's
   own honest entry. Lagrange combination yields `verifying_pk_i =
   identity` (by construction). The `if verifying_pk != identity`
   check at refresh.rs:390-395 passes.
5. **Refresh "succeeds" locally**: V_i updates `poly_point_new =
   poly_point_old + correction_value_i`. Since
   `correction_value_i` includes `c_attack` (the attacker's non-zero
   polynomial constant, propagated through phase 1), the new share is
   drifted by `c_attack`.
6. **Across all victims**: each victim independently passes their
   own `verifying_pk == identity` check (because the attacker
   tailored `Q_i` per-victim). All victims drift by the same
   `c_attack` (because phase 1 fragments are honest and the
   attacker contributed a consistent non-zero polynomial).
7. **Outcome**: the group secret is rotated from `s` to `s +
   c_attack`. The group public key field `Party.pk` is unchanged
   (still `s · G`, NOT `(s + c_attack) · G`). All subsequent
   threshold signatures are produced from the new secret but
   verified against the old `pk` — they fail verification.

## Other refresh-specific cross-cuts walked

Per the H110 task, I walked the dkls23-protocol-correctness checklist
for proactive secret refresh. Findings, beyond the F107 variant:

- **refresh_sid binding**: the refresh `step5` call uses `refresh_sid`
  rather than the original DKG `session_id`, and the OT-extension
  Beaver-trick salts (`salt_r0`, `salt_r1`, `salt_b` at lines 794-816,
  836-860 of `refresh.rs`) bind `refresh_sid` into the per-pair
  randomness derivation. SID binding looks adequate for the faster
  refresh's OT-extension reuse. **No finding here.**
- **OT-extension reuse correctness**: the Beaver trick at
  `refresh.rs:782-905` looks superficially correct: each KAPPA OT
  instance has its `correlation[i]` XORed with a hash-derived
  `b_prime`, and the new `seeds[i]` is derived as
  `seeds[i] XOR r_prime_b_double_prime`. This matches the Battagliola
  et al. (2019/1328) Section 8 / Appendix E description as cited in
  the module docstring. **Light-touch review** — I'm not flagging this
  as a finding pending a deeper crypto review of the Beaver trick's
  forward-secrecy properties under partial corruption.
- **Committee-composition change (resharing)**: refresh `phase4` does
  NOT accept a new `parameters` argument. The new `Party` instance is
  constructed at line 539-555 (complete refresh) and 921-937 (faster
  refresh) with `parameters: self.parameters.clone()` — i.e., the
  share-count and threshold are preserved. **There is no
  resharing-to-a-new-committee path.** This is correct for proactive
  refresh; a resharing protocol would be a separate file. No finding,
  but worth noting that if hypersnap intends to support committee
  rotation, refresh alone is insufficient.
- **Share zeroization of old `poly_point`**: refresh's phase4 returns
  a NEW `Party` struct (line 539, 921). The CALLER is responsible for
  zeroing or dropping the old `Party`. Looking at the test harness
  (line 1098-1116, 1373-1389): it just overwrites the `parties` Vec
  with the new ones (`parties = refreshed_parties`), which causes the
  old `Party`s to be dropped without explicit zeroization. The
  `Party` struct (defined in `crates/dkls23/src/protocols.rs`) and
  `PolyPoint` (a `C::Scalar`) do not appear to implement `Drop` with
  zeroization. **Latent risk** — if and when refresh is wired into
  production, the old share secrets will remain in stale heap memory
  after the BTreeMap eviction. Not flagging here as F110's scope; tracking
  as part of cross-cut S001 (secret-material zeroization, if such a
  task exists). Reachability gate: not reachable today, hence info.
- **Abort safety**: if `step5` returns `Err`, the refresh function
  returns the abort and leaves `self` untouched. Good. If
  `verifying_pk != identity`, abort is returned BEFORE any zero-share
  or mul updates. Good. If the zero-share verification at line 752 /
  427 fails mid-loop, abort is returned BEFORE any new `Party` is
  constructed. Good. **No abort-safety finding.**
- **Phase ordering / sender authentication of refresh round messages**:
  refresh has no upper-layer codec or supervisor in this build (per
  the reachability check above). When/if it is wired, the same F018
  / F023 / F025 / inner-vs-wire-index issues will apply to the
  refresh round messages (since the message structs at refresh.rs:117-150
  contain a `PartiesMessage { sender, receiver }` that an upper-layer
  codec would have to authenticate the same way as DKG messages).
  **Pre-emptive note for the eventual wire-up**; no separate finding.

## Why this is filed as a separate finding from F107 (and not just a note)

- **Same root cause**: yes, F107 site is the only vulnerable code.
- **Different reachability scope**: F107 is reachable today via the
  active DKG ceremony pipeline. F110 (this finding) describes the
  same primitive applied to a **distinct downstream caller** that
  has different security consequences (key-drift across refresh
  rather than per-epoch `pk` divergence).
- **Recommended fix is the same as F107's #1** (verify all proofs,
  including own-index), which closes both. But the test matrix is
  different: a refresh-side regression test (not present in any
  scaffolding) is required to catch a future re-introduction of the
  defect on the refresh path, especially after refresh is wired up.
- The dedupe stage may link F110 to F107 as same-root-cause; that is
  expected and desired.

## Recommended fix

Same as F107's recommended fix #1 (the only sufficient fix for refresh):
verify EVERY `ProofCommitment`, including the verifier's own index,
in `step5` at `dkg.rs:321-333`. See F107 §"Recommended fix" for the
exact replacement code.

Additionally, when refresh is wired into the production ceremony layer,
add a **post-refresh `pk` re-verification step** outside of `step5`:
after refresh `phase4` returns, re-compute the group public key from
all parties' new `poly_point · G` via Lagrange and assert it equals
the previous `Party.pk`. This catches any silent key drift caused by
non-zero-constant attacker polynomials, even in the
F107-self-spoofing case. (Conceptually: this turns the
`verifying_pk == identity()` check from a per-victim local check
into a cross-party consensus check that is robust to one-spoofed-slot
attacks.)

## Tests to add (refresh-specific)

1. **Refresh-side self-spoofed `ProofCommitment` is rejected.** In
   `refresh.rs`'s test module, modify
   `test_refresh` (line 1257) to inject a synthesized
   `ProofCommitment { index: 1, proof: junk, commitment: junk }` into
   `proofs_commitments` before phase4. Today this is silently
   accepted by `step5` (it skips verification for `index ==
   party_index`); after F107 fix, this MUST cause `phase4` to abort
   with `"Proof from Party 1 failed!"`.
2. **Refresh under malicious non-zero polynomial.** Construct a test
   where one party samples a non-zero polynomial constant in
   `refresh_phase1` (artificially patched) and tailors a phase-2 spoof
   such that the local `verifying_pk == identity` check passes (per
   the algebra in §"Why the identity-check doesn't close the gap"
   #1). Then run `refresh_phase4` and assert:
   - Today: refresh succeeds with silent key drift; the new
     `poly_point` reconstructs to a different secret than `self.pk`.
   - After fix: refresh aborts at `step5` with
     `"Proof from Party {attacker} failed!"`.

## Reachability — bottom line

Per the H110 task's required reachability report:
- **No `crates/hypersnap-crypto/` file imports or calls
  `dkls23::protocols::refresh`.**
- **No `src/hyper/` file references refresh phases or types.**
- **All refresh function call sites in the repo are inside
  `refresh.rs`'s own `#[cfg(test)] mod tests`.**

Therefore, **severity is `info` for the current build**, downgraded
from what would otherwise be high/critical (if refresh were wired up,
the silent key-drift consequence in §"Why the identity-check
doesn't close the gap" #3 would make it a critical chain-halt
primitive). When the operator wires refresh into the epoch lifecycle,
this finding's severity should be re-evaluated and likely upgraded.

## Related

- **F107** (`findings/drafts/F107-dkls-step5-skips-verification-for-self-claimed-proof-commitment-index.md`):
  ROOT-CAUSE PARENT. F110 = same code defect, different caller, distinct downstream consequence.
- **F018** (`findings/drafts/F018-dkls-inner-sender-not-bound-to-libp2p-peer-id.md`):
  wire `sender` byte not bound; would apply equally to refresh round messages if/when refresh is wired up.
- **F023** (`findings/drafts/F023-dkls-round-messages-dropped-and-cross-routed.md`):
  network-layer drop/cross-route; would apply to refresh round messages.
- **F040** (`findings/drafts/F040-dkls-supervisor-no-retry-after-ceremony-abort.md`):
  if refresh is added under a similar supervisor with no-retry semantics, the
  `t < n` abort variant of this finding becomes a permanent epoch halt of refresh.
- **F045** (`findings/drafts/F045-dkls-recovery-id-2-or-3-bricks-signing-no-retry.md`):
  separate path; not directly related.
