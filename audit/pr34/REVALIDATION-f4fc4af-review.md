# Revalidation — External Review Pass at tip `f4fc4af` (felirami, 2026-07-11)

**Trigger:** 5 inline `[P1]` review comments posted by `felirami` on
[farcasterorg/hypersnap#34](https://github.com/farcasterorg/hypersnap/pull/34)
("proof of work (restored)") on 2026-07-11, comment-only review against head
[`f4fc4af`](https://github.com/farcasterorg/hypersnap/commit/f4fc4af). This pass
takes each comment as a candidate finding and runs it through the audit's
validation process (adversarial confirm/refute against the exact `f4fc4af`
source, severity re-derivation, red-polarity PoC).

**Method:** one specialist validator per comment (rust-crypto-primitives,
general-purpose, rust-bulletproofs-pedersen, http-api-rocksdb), each reading a
detached worktree pinned at `f4fc4af`. F074 build-verified by actually running
`npm ci` + `tsc -b`. Rust PoCs built under WSL (`~/hs-f4fc4af`, `--cap-lints
allow`) per [[hypersnap-wsl-build]].

New finding IDs assigned: **F071–F075**.

---

## Verdict summary

| ID | Reviewer point | File | Verdict | Severity | Blocker? |
|----|----------------|------|---------|----------|----------|
| **F071** | Transfer validation uses bare `signing_payload()`, not envelope-bound → relay rewrites output `one_time_pubkey` | `runtime.rs:3957`/`4936` | **CONFIRMED** | High (output-burn / denial-of-funds; theft blocked by Pedersen closure) | Conditional — if confidential transfers ship |
| **F072** | Wire output omits `tx_pubkey` + encrypted note payload → notes undiscoverable/unspendable | `hyper.proto:220` | **CONFIRMED** | P1 liveness (feature-incomplete, not security) | Feature-ship blocker |
| **F073** | Wallet `confidential_lock` builder emits wrong `blinding_diff` + empty `range_proof` → always rejected | `confidential_lock.rs:45` | **CONFIRMED** | P1 broken-primitive (runtime correctly rejects) | Feature-ship blocker |
| **F074** | Deployer UI unbuildable — missing `src/lib/{merkle,leaf,recover}` + `@types/node` | `MerkleTreeBuilder.tsx:4` | **CONFIRMED** (built) | Peripheral tooling | Not core-scope |
| **F075** | Commit state batch after `stage_block` failure | `block_engine.rs:966` | **PARTIAL** | Low / defense-in-depth | No |

**4 confirmed, 1 partial. No claim was refuted outright** — the reviewer's
technical observations are accurate in every case; only F075's *severity*
(claimed state/header divergence) is overstated relative to the reachable
failure mode.

---

## The confidential-transfer feature cluster (F071 + F072 + F073)

These three are one coherent surface — the confidential transfer / stealth-note
/ confidential-lock suite — and together they say the feature is **both
incomplete and unsafe as shipped**:

- **F072** — a recipient cannot discover or spend a confidential output from
  on-chain data (missing `tx_pubkey` + encrypted payload on the wire). The
  crypto layer implements both; they are never wired to the proto or note
  store. → the feature does not work end-to-end for honest users.
- **F073** — the wallet's own `build_confidential_lock` produces messages that
  the live validator rejects (`BalanceClosureFailed`, then `MissingRangeProof`).
  → the honest lock path is non-functional from this builder.
- **F071** — the validation that *does* run on transfers verifies a digest that
  omits the recipient `one_time_pubkey`, so a gossip relay can rewrite the
  recorded output owner without invalidating the signer's signature. → the part
  that works is malleable (targeted denial-of-funds; theft foreclosed by
  Pedersen closure).

**Scope decision (parallel to the bridge B2–B4 framing):**
- If the confidential-transfer / stealth / confidential-lock capability is
  **in-scope and shipped** in this PR → **NOT merge-ready** for that feature;
  F071 (security) + F072/F073 (liveness) must be fixed first.
- If the capability is **experimental / feature-gated / not enabled** for this
  release → these are pre-ship blockers for that feature only, recorded as
  known-incomplete, and do not gate the PR's consensus/onboarding/bridge core.

This cluster is **new attack surface** relative to the prior revalidation
lineage, which covered consensus (F0xx), native onboarding (ONBD-1..15), and the
bridge (B2–B4). The confidential-transfer path was not previously
blocker-assessed.

---

## Revalidation observation: F036 is now CLOSED at `f4fc4af`

F036 (recorded at base `cab225f`) was "`ConfidentialLockBody.range_proof` is
carried on the wire but `verify_value_range` is never wired into lock
admission." At `f4fc4af` the range proof **is** now enforced —
`src/hyper/confidential_lock.rs:219-221` rejects an empty proof
(`MissingRangeProof`) and `:230` calls `verify_value_range(...)`. So **F036 →
CLOSED**. That fix is precisely what makes F073's always-empty `range_proof`
now hard-fail; F073 is F036's wallet-side mirror.

---

## F074 / F075 — outside the confidential cluster

- **F074** (deployer UI) — genuinely unbuildable (build-verified), but the
  off-chain Vite/React deploy helper is peripheral tooling, not the on-chain
  bridge contracts or the consensus core in the audit's scope. Record as a
  tooling defect to fix before the UI is usable; not a core-scope merge gate.
- **F075** (log-then-commit) — the anti-pattern is real in both
  `block_engine.rs:966` and `engine.rs:1844`, but adversarial tracing shows the
  only *reachable* `stage_block` failure (a RocksDB read error at the
  timestamp-index check) occurs after the block primary-key `put`, so
  block+header+state still commit atomically; only a secondary timestamp index
  is dropped. Low / defense-in-depth latent trap, not the claimed divergence.
  Worth the propagate-before-commit fix; not a blocker.

---

## Evidence base

- Full validation detail + quoted code per finding:
  [findings/F071](findings/F071-transfer-envelope-not-bound-output-pubkey-malleable.md),
  [F072](findings/F072-confidential-note-recovery-data-absent-from-wire.md),
  [F073](findings/F073-confidential-lock-wallet-builder-emits-non-validatable-messages.md),
  [F074](findings/F074-deployer-ui-unbuildable-missing-lib-modules-and-node-types.md),
  [F075](findings/F075-commit-after-stage-block-failure-log-then-commit.md).
- Per-finding synthesis: [materials/revalidation-f4fc4af-review/00-SUMMARY.md](materials/revalidation-f4fc4af-review/00-SUMMARY.md).
- Red-polarity PoCs: `poc/F071-transfer-envelope-malleable/`,
  `poc/F073-conf-lock-builder-rejected/`, `poc/F072-note-unrecoverable-from-wire/`
  (F074 reproduced by the build itself; F075 PoC specified, not built — Low +
  needs a test-only fault seam).
- Merge-gate impact folded into [MERGE-BLOCKERS-f4fc4af.md](MERGE-BLOCKERS-f4fc4af.md).
