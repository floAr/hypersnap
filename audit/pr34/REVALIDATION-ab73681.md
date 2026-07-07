# Hypersnap PR #34 — Fix Revalidation of commit `ab73681` ("audit pass")

**Fix commit:** [`ab7368134508390143ed0c4d0c04dbf2fb762e46`](https://github.com/farcasterorg/hypersnap/commit/ab73681) — *"audit pass"*, Cassandra Heart, 2026-07-07, on PR [#34](https://github.com/farcasterorg/hypersnap/pull/34) (branch `pow`).

**Parent (last revalidated):** [`573d671`](https://github.com/farcasterorg/hypersnap/commit/573d671) — see [REVALIDATION-573d671.md](REVALIDATION-573d671.md).
**Audited base (pre-fix):** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).

**Scope of the commit:** a single commit responding to the native-onboarding findings ONBD-1..7 filed against `573d671`. **11 files, +531 / −103.** Heaviest edits in `native_onboard.rs` (+224), `runtime.rs` (+181), `builder.rs` (+89), `mempool.rs` (+68). No Solidity touched.

**Method:** static call-site tracing against a worktree at `ab73681`; a **3-lane parallel adversarial revalidation** (storage/atomicity boundary, actor/consensus lifecycle, and an 8-hypothesis deliberate-disagreement validator red-teaming every "fixed" verdict); **WSL/Linux build (rustc 1.95)** of the whole crate plus **three build-verified PoCs** (two green fix-confirmations + one red regression). Multiple findings independently corroborated across ≥2 lanes.

---

## TL;DR

- **Six of seven prior ONBD findings are genuinely fixed** (ONBD-1 mechanism, ONBD-2, ONBD-3, ONBD-4 mechanism, ONBD-6, ONBD-7); **ONBD-5** is partial-by-design as previously characterized. ONBD-2 and ONBD-4 fix-confirmations are backed by **green PoCs**.
- **The ONBD-1 fix is architecturally sound and correct for _onboarding_**: FID assignment moved off per-node gossip ingestion into deterministic block-import order, folded into the threshold-signed verkle `hyper_state_root`; import recomputes the root and rejects on `StateRootMismatch`. Merge blockers **B6 (ONBD-1)** and **B7 (ONBD-2)** close.
- **But the fix left one half of identity off-root.** Custody _rotation_ still mutates only the off-root RocksDB mirror, never the on-root verkle binding. This single omission produces **two new High findings** — [ONBD-9](findings/native-onboard/ONBD-9-rotation-off-root-divergence.md) (rotation identity is off-root & per-node divergent — the exact ONBD-1 anti-pattern, reintroduced for rotation) and [ONBD-10](findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md) (an onboard replay resurrects a rotated-away custody→FID binding → **rotation-based key revocation can be undone**). ONBD-10 is **build-verified with a red PoC**.
- **A second new High is orthogonal:** [ONBD-11](findings/native-onboard/ONBD-11-speculative-produce-tree-pollution-selfhalt.md) — `produce` mutates `self.tree` before finalization with no rollback; ONBD-1's global sequence counter + permanent `ever` marker turn a would-be-transient losing-proposer divergence into an **unrecoverable identity fork + self-halt**. Plus [ONBD-12](findings/native-onboard/ONBD-12-aged-onboard-produce-import-asymmetry-stall.md) (Medium, proposer stall on an aged onboard).
- **Bridge merge blockers unchanged:** `HypersnapBridge.sol` byte-identical → **F049 (B2), F047 (B3), F048 (B4)** remain **OPEN**.

**Net merge-gate delta:** B6, B7 close; **B8 (ONBD-9+10)** and **B9 (ONBD-11)** open. Bridge B2/B3/B4 unchanged.

---

## Part A — Prior ONBD findings, status at `ab73681`

| # | Finding | Sev | At `573d671` | At `ab73681` |
|---|---------|-----|--------------|--------------|
| **ONBD-1** | onboarding applies identity + FID off the signed root at per-node gossip ingestion → divergence | Critical | OPEN (B6) | ✅ **FIXED (mechanism)** — identity assignment now on-root; but see ONBD-9/10 for the rotation half left off-root |
| **ONBD-2** | stake-release deletes+commits the lock before the fallible nonce check → staked atoms burned | High | OPEN (B7) | ✅ **FIXED** — green PoC |
| **ONBD-3** | stake-lock admit commits the lock before the debit → free-mint on crash | Med | OPEN | ✅ **FIXED** |
| **ONBD-4** | rotate-then-replay mints a 2nd FID from one PoW | Med | OPEN | ✅ **FIXED (2nd-FID mint blocked)** — green PoC; but replay resurrects the mirror binding → ONBD-10 |
| **ONBD-5** | weak/miscalibrated 22-bit SHA-256 PoW | Med | OPEN | ⚠️ **PARTIAL (by design)** — floor 22→30 bits; still a soft SHA-256 gate; "governance-tunable" is doc-only |
| **ONBD-6** | stake-arm ecrecover DoS + gate live despite "disabled" | Med | OPEN | ✅ **FIXED** — `STAKE_GATE_ENABLED=false` (prod), cheap reject before ecrecover |
| **ONBD-7** | fail-open decode → corrupt FID-counter reuse | Low | OPEN | ✅ **FIXED (core)** — 3 readers fail-closed; 2 minor fail-open readers remain (see §D) |
| **B2 / F049** | bridge watermark saturation bricks rotate/cancel/pause | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B3 / F047** | bridge owner-rotation front-run defeats recovery | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B4 / F048** | bridge pause does not gate `proposeUpgrade` | Med | OPEN | ⛔ **OPEN** (contract untouched) |

### ONBD-1 — onboarding identity now on-root · **FIXED (mechanism)** (0.9)

The fix is genuine and well-constructed for onboarding:
- `submit_message` (`runtime.rs:4076-4106`) no longer assigns a FID or mutates identity at gossip time. It only *validates* (anchor/PoW/stake/signature via `validate_onboarding`), does an **optimistic** duplicate reject against the mirror, and enqueues into the mempool (`submit_onboard`).
- FID assignment is deterministic and on-root: `builder::apply_onboard_to_tree` (`builder.rs:87-111`) assigns the FID from an **in-tree** sequence counter (verkle key domain `0x04`), writes custody→FID (`0x05`), a permanent `ever` marker (`0x06`), and the stake binding (`0x07`); onboards are applied **before** transfers, in block-canonical order, on both the produce and import sides (`runtime.rs:5083-5093`, `importer.rs:285-297`).
- Import **re-validates** every onboard (`runtime.rs:4826-4850`), re-applies via the same builder, recomputes the verkle root, and rejects on `StateRootMismatch` (`importer.rs:314-321`). Any custody→FID divergence between honest nodes now becomes a **root mismatch → block rejected → halt**, not a silent identity fork.
- Confirmed: the old per-node `apply_onboarding` FID-assigner has **no production caller** (tests only); no production path assigns a FID off-tree. No verkle key-domain collision (`0x04-0x07` disjoint from lock/nullifier/note `0x01-0x03`; refuted by two lanes).

**Why not a clean "FIXED":** the verdict's implicit claim that *custody→FID identity* is now root-covered is **false for custody rotation** — see ONBD-9. The onboarding assignment mechanism is fixed; the identity registry as a whole is not yet on-root.

### ONBD-2 — stake-release burn · **FIXED** (0.95) · green PoC

`admit_onboarding_stake_release` now only **stages** `batch.delete(lock)` into the caller's batch (`native_onboard.rs:1168`) and never commits. The runtime performs the nonce check **before** any commit (`runtime.rs:916-951`); on a stale nonce the batch is dropped uncommitted and the lock survives. Delete + credit-back + nonce bump land in a single `commit` (`runtime.rs:958-974`). The only early return is the `amount==0` idempotent no-op (batch dropped). Validator walked every branch: no burn-without-credit or credit-without-delete window.

**Green PoC** ([poc/onbd/ONBD-2-stake-release-burn/](poc/onbd/ONBD-2-stake-release-burn/), reused verbatim from the `573d671` round — the runtime API is unchanged): the value-conservation property that was **red on `573d671`** is now **green**:
```
test onbd2_rejected_stake_release_must_not_burn_staked_atoms ... ok
```

### ONBD-3 — stake-lock free-mint · **FIXED** (0.9)

`admit_onboarding_stake_lock` stages the lock write into the runtime's batch (`native_onboard.rs:1107-1110`); the runtime folds lock-write + balance debit + nonce bump into one batch, one commit (`runtime.rs:865-894`). No intermediate commit, no crash window.

### ONBD-4 — rotate-then-replay 2nd-FID mint · **FIXED (mint blocked)** (0.9) · green PoC

The permanent in-tree `ever` marker (`builder.rs:92-95`) makes `apply_onboard_to_tree` return `None` for any custody already onboarded, on the single assignment path — so a replay mints **no** second FID. The `573d671`-era PoC drove the now-dead `apply_onboarding` RocksDB path; this round's **rewritten green PoC** ([poc/onbd/ONBD-4-tree-rotate-replay-green/](poc/onbd/ONBD-4-tree-rotate-replay-green/)) exercises the real in-tree path and passes:
```
test onbd4_rotate_then_replay_via_tree_mints_no_second_fid ... ok
```
**Caveat:** the fix covers the FID *count*, not the custody-binding side effect — replay still resurrects the mirror binding (**ONBD-10**).

### ONBD-5 — weak PoW · **PARTIAL (by design)** (0.85)

`MIN_DIFFICULTY_BITS = 30` under `cfg(not(test))` (12 only under `cfg(test)` — a release build cannot be tricked to the test floor), enforced in `verify_pow` on both the submit and import paths. The commit is explicit that this is a *soft* SHA-256 gate (~2-4 s commodity SHA-NI, ms on GPU/ASIC) and that the durable fix (memory-hard function / stake gate) is deferred. **Caveat:** the doc-comment's "validator-set tunable via governance" is **not wired** — `MIN_DIFFICULTY_BITS` is a hard const (no override path, hence also no lower-bound-bypass). Accurately characterized as PARTIAL.

### ONBD-6 — stake-arm ecrecover DoS + live gate · **FIXED** (0.95)

`STAKE_GATE_ENABLED=false` under `cfg(not(test))`. The cheap `StakeGateNotYetEnabled` reject is the **first statement** in the Stake arm (`native_onboard.rs:544-546`), before the ecrecover at `native_onboard.rs:590`, on the shared `validate_onboarding` path used by both submit and import. The only pre-gate op is `verify_anchor` (O(1) DB get + 32-byte compare). No pre-auth expensive op left on the stake ingestion path.

### ONBD-7 — fail-open decode · **FIXED (core)** (0.85)

`next_hyper_fid`, `lookup_custody_fid`, and `read_rotation_nonce` now return `Err(Storage)` on present-but-wrong-length values (fail-closed). Two residual fail-open readers remain (§D) — low-risk, but the same pattern.

---

## Part B — New findings introduced / surfaced by the fix

All four are in the new native-onboarding subsystem; the first two share a single root cause.

### Root cause shared by ONBD-9 + ONBD-10

> **Custody rotation mutates only the off-root RocksDB custody→FID mirror (+ nonce), never the on-root verkle binding — and `sync_onboarding_mirror_from_tree` treats the frozen tree binding as authoritative for every re-onboarded custody.**

`apply_custody_rotation` (`native_onboard.rs:784-878`) does not even take a `VerkleTree` parameter; its only writes are `custody_to_fid_key` + `rotation_nonce_key` in RocksDB (line 867-877). It is invoked **inline from `submit_message`** (`runtime.rs:4109-4116`) — the gossip-ingestion path — is never included in a block, and is never persisted for replay. The tree binding `onboard_custody_verkle_key(custody)` is written once at onboarding and **never deleted or updated anywhere** (grep-confirmed across two lanes).

### ONBD-9 (High) — custody rotation is off-root & applied at gossip ingestion → per-node identity divergence

The exact anti-pattern ONBD-1 was filed against, relocated to the rotation path. Node A applies a rotation gossip frame (C1→C2); Node B drops it. There is no block, no root fold, no anti-entropy → the mirrors diverge **permanently**, and because rotation is off-root the divergence can **never** surface as `StateRootMismatch` (no fail-closed halt). Consumer-side walk: fund-authorization uses account-store signer keys (`require_active_signer`), not custody→FID, and on-root uniqueness uses the tree `ever` marker — so this is an **off-root identity-registry divergence** (rotation-chain state + HTTP identity queries), not a chain fork or direct fund loss. **[Full writeup →](findings/native-onboard/ONBD-9-rotation-off-root-divergence.md)**

### ONBD-10 (High) — onboard replay resurrects a rotated-away custody binding → rotation-revocation bypass · **build-verified red PoC**

Because the tree binding `custody[C1]=F` survives rotation, and `sync_onboarding_mirror_from_tree` (`native_onboard.rs:469-498`) **unconditionally** re-derives `mirror[custody] = tree[custody]` for *every* onboard body in an imported block (line 481-483) — regardless of whether `apply_onboard_to_tree` no-op'd it — a replayed onboard for C1 copies the stale `C1=F` straight back over the mirror. The original custody holder (who rotated F to C2 precisely to revoke C1, e.g. on key compromise) doesn't even need the stale body: they hold C1's key, so they can submit a **fresh, currently-anchored, freshly-PoW'd** C1 onboard (unbounded by the 1024-block anchor window). It passes the optimistic ingestion check (`lookup_custody_fid(C1)=None` after rotation), an honest proposer includes it, the `ever` marker no-ops the tree (no 2nd FID ✓), **and the mirror sync resurrects `mirror[C1]=F`**. The mirror now holds **both** C1=F and C2=F, and C1 can `apply_custody_rotation(C1→C3)` (passes `held_by_current`, nonce, signature) — **re-capturing a FID it had rotated away.** Deterministic, reachable through a normally-produced signed block; no malicious proposer required.

**Red PoC** ([poc/onbd/ONBD-10-mirror-resurrection/](poc/onbd/ONBD-10-mirror-resurrection/)) — the security property "after rotation, custody A stays revoked" **fails** on `ab73681`:
```
assertion `left == right` failed: REGRESSION: onboard replay resurrected rotated-away
custody A -> fid 9223372036854775808 (mirror sync copied the never-cleared verkle
binding back), defeating rotation-based revocation
  left: Some(9223372036854775808)   # 2^63 = HYPER_FID_BASE
 right: None
```
Correct red→green polarity: this test passes once rotation is folded into the tree (or sync skips rotated custodies). **[Full writeup →](findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md)**

**Fix direction (both):** make custody rotation an on-root, block-ordered state transition — update/delete `onboard_custody_verkle_key` in-tree under the signed root (add a rotation-nonce domain) — so the mirror-sync reflects rotations, cannot resurrect them, and rotation divergence halts via root-mismatch instead of forking silently.

### ONBD-11 (High) — speculative `produce` tree pollution → unrecoverable proposer divergence + self-halt

`produce_envelope_with_full_anchor` builds `HyperBlockBuilder::new(&mut self.tree)` (`runtime.rs:5094`) and applies drained messages **directly to `self.tree`** before the block is finalized — assigning FIDs, bumping the **global** in-tree `seq`, and setting permanent `ever` markers. The unsigned block is only stashed in `pending_dkls_blocks` (`actor.rs:2937`) and applied to the chain solely if the DKLS ceremony completes (`actor.rs:3001-3014`). **No rollback exists** (grep: the tree is only rebuilt at construction). If the ceremony stalls and — after an anchor-refresh proposer reassignment (`scheduler.rs:262-273`) — a different node finalizes the height with a different onboard set, the original proposer's tree stays polluted; its recomputed root will never match the canonical signed root → **permanent `StateRootMismatch` self-halt**, recoverable only by DB wipe + resync.

This is fundamentally a **pre-existing** speculative-mutation-without-rollback class (transfers already strand nullifier/commitment leaves). **ONBD-1 strictly worsens it:** transfer/lock leaves are content-addressed and re-agree if the same messages later commit, but an onboard's FID is history-derived (a global mutable `seq`) and the permanent `ever` marker cements the *first* speculative assignment — so the divergence becomes **non-self-healing** and an identity fork, not merely a transient root drift. (Restart *heals* it, since the tree is rebuilt only from committed blocks — the damage window is the in-memory, no-restart path.) **[Full writeup →](findings/native-onboard/ONBD-11-speculative-produce-tree-pollution-selfhalt.md)**

### ONBD-12 (Medium) — aged-onboard produce/import re-validation asymmetry → proposer stall

`produce` does **not** re-validate onboards; `import` does (`validate_onboarding`→`verify_anchor`, freshness `tip - anchor_block_height > 1024`). An onboard valid at submit but not included promptly (gossip lag / proposer churn) can age past the window by inclusion time; `produce` folds it and signs a root over it, then **every** importer (including the producer self-importing) deterministically rejects with `AnchorTooOld`. Because import errors out before `mempool.forget_onboard` (`importer.rs:333-338`), the poison onboard is never evicted (eviction is capacity-only) and is re-drained into the next block indefinitely → proposer stall. Deterministic, uniform (freshness measured against hyper-tip height, identical on all nodes at import of block H) — **not a fork**, but a liveness/self-halt feeder for ONBD-11. **[Full writeup →](findings/native-onboard/ONBD-12-aged-onboard-produce-import-asymmetry-stall.md)**

---

## Part C — Sound negatives (hypotheses tested and refuted)

Refuted across the three lanes (each with code citations):
- **Verkle key-space collision / truncation aliasing** among onboard domains `0x04-0x07` — refuted (distinct leading byte; fixed, ≤32-byte validated ids never truncate).
- **`next_hyper_fid` split-brain** — refuted; no production path reads the RocksDB sequence to assign (only the tree `read_onboard_seq`).
- **Double-apply seq divergence / producer self-halt on self-import** — refuted; the `ever`-marker idempotency prevents a second `seq` bump, recomputed root equals signed root.
- **Import-time re-validation nondeterminism → fork** — refuted; freshness inputs are hyper-tip height + committed block hashes, identical on all nodes importing block H.
- **Restart-replay ordering divergence** — refuted; replay applies onboards-first-then-transfers, matching produce/import order; verkle is order-independent across distinct key domains.

---

## Part D — Minor residuals (informational)

- **Two fail-open readers remain** (same pattern ONBD-7 set out to kill, both low-risk): `read_onboard_seq` (`builder.rs:65-77`) returns `HYPER_FID_BASE` on a wrong-length seq (justified as on-root → corruption halts via root-mismatch, but silently re-issues from base rather than erroring); `read_onboarding_stake_lock` (`native_onboard.rs:1050-1057`) decodes a corrupt lock to `None` ("not found") — low impact (stake gate disabled in prod).
- **Mirror-sync failure inconsistency:** if `sync_onboarding_mirror_from_tree` fails after the block + messages are durably recorded, `import_block` returns `Err` with the tree advanced but the mirror un-synced and no in-process retry. Bounded (tree is authoritative → no fork; self-heals on restart via idempotent re-sync), but the mirror lags and newly-onboarded custodies are temporarily invisible to `lookup_custody_fid`/HTTP/rotation. Consider committing the mirror in the same sequence as the block-index write, or halting hard on sync failure.
- **ONBD-5 "governance-tunable" doc claim** is not wired (informational).

---

## Build verification (this round)

WSL/Linux build (rustc 1.95, `--cap-lints allow`, malachite sibling staged) of the full crate: **clean** (`Finished dev [unoptimized + debuginfo] in 5m 25s`). The commit's own `native_onboard` suite: **17/17 pass**. Three authored PoCs, all build-verified:

| PoC | Polarity | Result on `ab73681` | Meaning |
|---|---|---|---|
| ONBD-2 rejected-release value-conservation | green (was red on `573d671`) | **PASS** | stake-release burn fixed |
| ONBD-4 rotate-then-replay (in-tree path) | green | **PASS** | 2nd-FID mint blocked |
| ONBD-10 rotation-revocation invariant | **red** | **FAIL** (`Some(2^63)` ≠ `None`) | mirror resurrection regression confirmed |

---

## Recommended re-report set

- **New merge blockers:** **B8** = ONBD-9 + ONBD-10 (fold custody rotation into the signed verkle root); **B9** = ONBD-11 (speculative produce-time tree mutation without rollback — apply to a scratch tree, or defer tree mutation to finalize/import).
- **Still open (bridge, untouched):** B2/F049, B3/F047, B4/F048.
- **Hardening:** ONBD-12 (re-validate onboards at produce + evict on import failure), ONBD-5 (memory-hard/stake gate as the durable barrier), the two fail-open readers, mirror-sync failure handling.

Per-finding bodies under [findings/native-onboard/](findings/native-onboard/) reflect the state at `ab73681`. Per-cluster detail and raw specialist notes: [materials/revalidation-ab73681/](materials/revalidation-ab73681/).
