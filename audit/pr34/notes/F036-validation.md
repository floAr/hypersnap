# F036 Validation — ConfidentialLockBody.range_proof defined-but-unwired

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f` (verified `git log -1` == cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9, 2026-06-08).

Finding claim: `ConfidentialLockBody.range_proof` (proto field 6) is carried on
the wire but `verify_value_range` is never called on the confidential-lock
admission path; finder rated **LOW** because impact is foreclosed by (1) public
`uint64 amount` and (2) Pedersen balance closure binding committed value to
`amount+fee`. RED-TEAM mandate: confirm impact really IS foreclosed, OR find a
path where the missing proof matters, OR show the issue isn't real (INVALIDATED).

## Verification of the factual core (the bug is REAL)

- `verify_value_range` has ZERO callers under `src/` (grep `verify_value_range src/`
  → empty). Its only non-test caller is `TransferTx::validate`
  (`crates/hypersnap-crypto/src/tokens.rs:332`). Confirmed unwired for locks.
- `validate_against_store` (`src/hyper/confidential_lock.rs:156-186`) calls
  `validate_structural` + `lookup_owner` + `is_spent` + Schnorr verify
  (`:170-173`) + Pedersen closure (`:177-184`). It NEVER references
  `body.range_proof`. `validate_structural` (`:100-152`) also never inspects it.
- `range_proof` refs in the lock path are all test fixtures setting `vec![]`
  (`confidential_lock.rs:212,232,253,274`). The runtime.rs:5310-5391 hits are the
  unrelated transfer-output codepath.
So the "defined-but-unwired" fact is correct. Question is impact magnitude.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS (no rescue)
`submit_message` (`runtime.rs:3699-3703`) intercepts `Body::ConfidentialLock` and
calls `apply_confidential_lock` directly. No upstream layer verifies a range
proof. (libp2p gossip signing authenticates the *peer*, not the lock contents.)
Nothing upstream re-introduces the missing check. Bug stands as a fact.

### 2. Consumer-side impact — INVALIDATES the "value overflow" harm (impact LOW is correct)
`apply_confidential_lock` (`runtime.rs:890-896`) records
`TokenLockState{ amount: body.amount, ... }` — the L1 bridge leaf carries the
**public** `body.amount`, not the committed value. The consumer never trusts the
hidden commitment value over the public amount. Combined with the closure (H6),
there is no value the attacker can inflate. Consumer-side confirms LOW.

### 3. Downstream enforcement — INVALIDATES the high-impact reading
The Pedersen balance closure at `confidential_lock.rs:177-184` is a downstream
crypto gate that already binds the committed input value to exactly
`amount+fee`. A correct range proof on `amount` would prove `amount ∈ [0,2^64)`,
which a `uint64` already guarantees structurally — so the missing proof enforces
nothing the closure + the type don't already enforce. Downstream catches what
the missing proof would have caught. This is the crux: impact is foreclosed.

### 4. PR HEAD currency — STANDS
Workspace HEAD == pinned `cab225f`; no drift. The unwired code is current.

### 5. Spec carve-out — PARTIALLY INVALIDATES (lowers severity, not the fact)
The codebase's own design documents that the range proof is unnecessary when
amount is public: the shield primitive reuses the same `range_proof` field as a
blinding scalar with the comment "the bulletproofs range proof is unnecessary —
`amount` is public" (`src/hyper/shield.rs:80-84`). So for the lock (also public
amount) the omission is consistent with stated design intent — not an oversight
that breaks a guarantee. The residual issue is purely a wire-format/doc integrity
gap (the proto comment still advertises an enforced range bound). Confirms LOW.

### 6. Reachability of the harm — INVALIDATED (no exploitable overflow)
Could a prover commit a near-group-order / negative value to overflow on the L1
side? No:
- `amount` and `fee_atoms` are `uint64` (proto fields 2 and 7), structurally
  `< 2^64`.
- `total_value = Scalar::from(amount.saturating_add(fee_atoms))`
  (`confidential_lock.rs:178`): `saturating_add` caps at `u64::MAX`, so
  `total_value < 2^64`. The Decaf448 scalar order L ≈ 2^446 ≫ 2^64, so
  `Scalar::from(total_value)` cannot wrap/alias. No modular escape.
- Closure `commitment.0 − total_value·B == blinding_diff·B_blinding`
  (`:180-182`) is an exact point equation binding the committed value to exactly
  `amount+fee mod L = amount+fee`. A prover cannot commit a large value while
  declaring a small public amount, nor a negative value (no value < the bound is
  reachable that the closure would accept while amount stays small). Harm to
  value conservation is unreachable.

### 7. Test wiring — STANDS (production path confirmed live)
`validate_against_store` is the SOLE gate: `apply_confidential_lock` →
`validate_against_store` (`runtime.rs:864`) then directly writes `TokenLockState`
and marks the nullifier spent (`:900-911`). The importer (`src/hyper/importer.rs`)
has no confidential-lock handling (grep empty) — no separate block-import
re-validation. So the unwired code runs in production; this is not a test-only
artifact. The bug is real and live (it's the IMPACT that's low, not the wiring).

### 8. PoC mechanics — N/A (no PoC asserted) → STANDS
The finding ships no executable PoC; its claim is a code-structure assertion
("field accepted, never verified"), which is directly confirmed by the grep +
read evidence above. The attack scenario ("garbage range_proof is admitted")
is trivially true since the field is never read. No over-claim in the prose:
the finding explicitly states the value-overflow impact is foreclosed.

## Overall verdict

**HAS_CAVEATS**, confidence 0.9.

The structural fact (range_proof carried on the wire, `verify_value_range` never
wired into the lock-admission path) is TRUE and verified at file:line. The
finding does NOT overstate impact: it self-rates LOW and correctly attributes
the foreclosure to (1) public `uint64` amount and (2) the Pedersen balance
closure — both of which I independently confirmed bind the value with no
overflow/aliasing/negative-value escape (H6), and whose consumer uses the public
amount (H2). The residual issue is a genuine but minor latent wire-format /
documentation integrity gap (proto comment advertises an enforced range bound
that admission does not enforce), consistent with the shield design rationale
(H5). LOW is the correct severity — neither INVALIDATED (the gap is real) nor
higher (no exploitable harm). "HAS_CAVEATS" reflects that the headline ("proof
defined but unwired") is true but the security consequence is essentially nil
given the closure; this is a hygiene/clarity finding, not a vulnerability.

## Open follow-ups (NOT new findings — for specialist consideration)
- None of security consequence. If the team chooses fix (b) (remove the proto
  field), confirm no off-chain tooling currently parses field 6 as load-bearing
  before removal, to avoid a wire-compat break.
