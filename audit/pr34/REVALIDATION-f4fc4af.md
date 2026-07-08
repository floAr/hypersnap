# Hypersnap PR #34 — Fix Revalidation of commit `f4fc4af` ("Resolve last audit run")

**Fix commit:** [`f4fc4afccbd0419e04000dca0c6677fd6191afec`](https://github.com/farcasterorg/hypersnap/commit/f4fc4af) — *"Resolve last audit run"*, Cassandra Heart, 2026-07-07, on PR [#34](https://github.com/farcasterorg/hypersnap/pull/34) (branch `pow`).

**Parent (last revalidated):** [`ab73681`](https://github.com/farcasterorg/hypersnap/commit/ab73681) — see [REVALIDATION-ab73681.md](REVALIDATION-ab73681.md).
**Audited base (pre-fix):** [`cab225f`](https://github.com/farcasterorg/hypersnap/commit/cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9).

**Scope of the commit:** a single commit responding to the native-onboarding findings ONBD-9/10/11/12 filed against `ab73681` (merge blockers **B8**, **B9**). **12 files, +540 / −130.** Heaviest edits in `native_onboard.rs` (+315/−104), `runtime.rs` (+148/−20), `builder.rs` (+86), `mempool.rs` (+54). Threads a new `HyperCustodyRotationBody` list through the whole block/actor/importer/gossip/mempool plumbing. No Solidity touched.

**Method:** static call-site tracing against a worktree at `f4fc4af`; a **3-lane parallel adversarial revalidation** (storage/mirror-consistency, actor/consensus lifecycle & self-halt, and mempool/admission/DoS); **WSL/Linux build (rustc 1.95)** of the whole crate; **4 build-verified PoCs** (one green four-way-determinism confirmation + the fix commit's own ported red→green PoCs + two characterization PoCs backing the residual Lows). The non-atomic-mirror residual was independently surfaced by two lanes.

---

## TL;DR

- **All four prior findings are genuinely fixed.** ONBD-9, ONBD-10, ONBD-11, ONBD-12 are closed at the mechanism level, corroborated across lanes, and build-verified. The developer implemented **precisely the fix direction recommended in ONBD-9**: fold custody rotation into the on-root verkle tree as a block-ordered, threshold-signed transition.
- **Merge blockers B8 (ONBD-9+10) and B9 (ONBD-11) close.** With `573d671`'s B5/F070 and `ab73681`'s B6/B7 already closed, **there are no remaining native-onboarding merge blockers.**
- **Rotation is now consensus-covered.** A new `HyperWireBlock.rotations` list flows through mempool → block → import exactly like onboards; `apply_rotation_to_tree` tombstones the old custody (empty verkle leaf — a *committed* leaf, distinct from an absent slot), binds the new custody, sets its permanent `ever` marker, and advances an in-tree rotation nonce (key domain `0x08`), all under the signed root. Divergence now halts via `StateRootMismatch` instead of forking silently.
- **The ONBD-11 self-halt is structurally impossible now:** production builds candidate blocks against `scratch_tree = self.tree.clone()`, and `VerkleTree`'s derived `Clone` is a genuine deep copy — a produced-but-never-finalized block cannot strand FID/seq/ever/nonce state in the authoritative tree. The **only** authoritative mutation of `self.tree` is `import_block`.
- **Three new Low residuals, none blocking:** [ONBD-13](findings/native-onboard/ONBD-13-mirror-sync-nonatomic-restart-desync.md) (non-atomic query-mirror sync + restart-rebuilds-tree-only → self-healing query-index desync on a precisely-timed crash), [ONBD-14](findings/native-onboard/ONBD-14-noop-rotation-not-produce-filtered-reloop.md) (no-op rotations lack the ONBD-12 produce filter → re-loopable block-slot/ecrecover waste, PoW-FID-bounded), [ONBD-15](findings/native-onboard/ONBD-15-rotation-ecrecover-before-block-sig-check.md) (rotation ecrecover runs before the block signature check — a minor, PoW-free new instance of a pre-existing DoS-ordering class).
- **Bridge merge blockers unchanged:** `HypersnapBridge.sol` byte-identical → **F049 (B2), F047 (B3), F048 (B4)** remain **OPEN**.

**Net merge-gate delta:** B8, B9 close. No native-onboarding blockers remain. Bridge B2/B3/B4 unchanged.

---

## Part A — Prior findings, status at `f4fc4af`

| # | Finding | Sev | At `ab73681` | At `f4fc4af` |
|---|---------|-----|--------------|--------------|
| **ONBD-9** | custody rotation identity off-root, applied at gossip ingestion → per-node divergence | High | OPEN (B8) | ✅ **FIXED** — rotation folded on-root as a block-ordered transition; the exact recommended fix |
| **ONBD-10** | onboard replay resurrects a rotated-away custody→FID binding → revocation bypass | High | OPEN (B8) | ✅ **FIXED** — tombstone-aware read + mirror-reflects-tree; ported red PoC now green |
| **ONBD-11** | speculative `produce` mutates `self.tree` pre-finalization → self-halt / identity fork | High | OPEN (B9) | ✅ **FIXED** — builds against a deep-cloned scratch tree; only `import_block` mutates `self.tree` |
| **ONBD-12** | aged-onboard produce/import re-validation asymmetry → proposer stall | Med | OPEN | ✅ **FIXED** — produce-time re-validate-and-drop of aged onboards |
| **B8 / ONBD-9+10** | rotation-identity off-root | High | OPEN | ✅ **CLOSED** |
| **B9 / ONBD-11** | speculative-apply self-halt | High | OPEN | ✅ **CLOSED** |
| **B2 / F049** | bridge watermark saturation bricks rotate/cancel/pause | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B3 / F047** | bridge owner-rotation front-run defeats recovery | High | OPEN | ⛔ **OPEN** (contract untouched) |
| **B4 / F048** | bridge pause does not gate `proposeUpgrade` | Med | OPEN | ⛔ **OPEN** (contract untouched) |

### ONBD-9 — rotation identity now on-root · **FIXED** (0.95)

The fix follows the ONBD-9 "Fix direction" verbatim. `apply_custody_rotation` (RocksDB-only, gossip-time) is gone, split into three deterministic pieces:

- **`validate_custody_rotation`** (`native_onboard.rs:786-848`): structure + EIP-712 signature only, **state-independent**, so it is safe to run identically at submit (admission gate) and at import (malicious-proposer defense).
- **`builder::apply_rotation_to_tree`** (`builder.rs:103-137`): the state-dependent transition, applied **in block-canonical order under the signed root**. It tombstones `onboard_custody_verkle_key(current)` with an empty value, binds `new`, sets `ever(new)`, and advances the rotation nonce (new key domain `0x08`, `builder.rs:41`). Returns `false` as a deterministic no-op on stale nonce / current-not-holder / new-already-bound.
- **`sync_rotation_mirror_from_tree`** (`native_onboard.rs:850-879`): reflects the post-apply tree into the RocksDB query mirror (tombstone → `delete`).

Rotations are now a first-class block message: `HyperWireBlock.rotations` (field 5), `PendingMessage::Rotation`, drained from the mempool, persisted via `record_messages`, and replayed on restart. Import **re-validates** every rotation's signature (`runtime.rs:4862-4869`), re-applies via the same builder, recomputes the root, and rejects on `StateRootMismatch`. Any honest-node rotation divergence now halts fail-closed instead of forking. **Four-way determinism build-verified** (see PoC below).

### ONBD-10 — rotation-revocation bypass closed · **FIXED** (0.95) · ported red PoC now green

The resurrection vector was: rotation only touched the mirror, never tombstoned the tree, so a replayed onboard's `sync_onboarding_mirror_from_tree` copied the never-cleared verkle `custody[A]=X` back over the mirror. The fix closes both halves:

- Rotation **tombstones the tree binding** (`apply_rotation_to_tree`, empty leaf).
- `read_onboard_custody_fid` (`builder.rs:75-84`) is **tombstone-aware** — `len()==8` = bound; absent-or-empty = unbound.
- `sync_onboarding_mirror_from_tree` (`native_onboard.rs:478-495`) now reads through `read_onboard_custody_fid`, so a replay of a revoked custody reads `None` and **does not** re-put the binding. The permanent `ever` marker independently makes the replay a tree no-op (no 2nd FID).

The `ab73681`-round red PoC is unchanged in intent and now **passes**:
```
test onboard_replay_must_not_resurrect_rotated_away_custody_binding ... ok
test onbd4_rotate_then_replay_via_tree_mints_no_second_fid ... ok
```
Verified independently: no code path writes a non-8-byte custody value other than the empty tombstone, and an empty tombstone is never read as bound — so ONBD-10 cannot be reintroduced through a length collision.

### ONBD-11 — speculative-produce self-halt closed · **FIXED** (0.95)

`VerkleTree` now derives `Clone` (`verkle.rs:12`) and `produce_envelope_with_full_anchor` builds against `let mut scratch_tree = self.tree.clone();` (`runtime.rs:5187`), never `self.tree`. Confirmed at the type level: `VerkleNode` is an enum of `BTreeMap<u8, Box<VerkleNode>>` + `Vec<u8>` + `KzgCommitment` with **no** `Rc`/`Arc`/`RefCell` interior, so the clone is a genuine deep copy; only `srs: Arc<KzgSrs>` is shared, and it is immutable. Confirmed at the call-graph level: the lifecycle lane grepped every `self.tree` / `&mut self.tree` / `HyperBlockBuilder::new` in `runtime.rs` — the **only** authoritative logical mutation is `import_block → import_hyper_block_with_index(&mut self.tree, …)` (`runtime.rs:4953`); all others are read-only (submit optimistic checks, membership reads) or verkle proof-cache-only. A produced-but-never-finalized block (DKLS stall / losing proposer / ceremony reassignment) leaves `self.tree` untouched — the self-halt primitive is gone.

### ONBD-12 — aged-onboard proposer stall closed · **FIXED** (0.9)

`produce_envelope_with_full_anchor` re-validates each drained onboard against the current tip via `validate_onboarding` and **drops** any that no longer validate (`runtime.rs:5151-5160`), so an aged onboard is discarded rather than folded+signed into a block that every importer would reject. Refuted the obvious concern (a produce/import asymmetry that just relocates the stall): every `validate_onboarding` failure mode is **permanent** for a fixed body (anchor-too-old only worsens as the tip grows; hash/sig/PoW/structure are fixed), and `verify_anchor` is **chain-state-derived, not wall-clock** (`native_onboard.rs:425-457`) — so produce, self-import, peer-import and replay agree, and dropping an aged onboard discards nothing that could ever be validly included (ONBD-8 stays closed).

---

## Part B — New fix-induced findings (all Low, non-blocking)

| # | Finding | Sev | Consensus impact |
|---|---------|-----|------------------|
| [ONBD-13](findings/native-onboard/ONBD-13-mirror-sync-nonatomic-restart-desync.md) | query-mirror sync non-atomic with block persist + not rebuilt on restart | Low | none — self-healing query index; no fork/halt/double-mint |
| [ONBD-14](findings/native-onboard/ONBD-14-noop-rotation-not-produce-filtered-reloop.md) | no-op rotations lack the ONBD-12 produce filter → re-loopable slot/ecrecover waste | Low | none — deterministic no-op; PoW-FID-bounded resource waste |
| [ONBD-15](findings/native-onboard/ONBD-15-rotation-ecrecover-before-block-sig-check.md) | rotation ecrecover runs before block-sig verify, PoW-free | Low | none — CPU-only; minor new instance of a pre-existing class |

All three share a defense-in-depth / hardening character; none is a fork, halt, fund-loss, or double-mint. See the individual finding docs for mechanism, PoC, and fix direction. Recommended (in priority order): (a) verify the block threshold signature + a message-count cap **before** any per-message re-validation in `import_block` (closes ONBD-15 for rotations/onboards/transfers at once); (b) fold the mirror syncs into the block-persist write-batch or rebuild the mirror on restart (ONBD-13); (c) give rotations the ONBD-12 produce-time no-op drop (ONBD-14).

---

## Part C — Refuted hypotheses (adversarial negatives)

The lanes constructed and refuted, with mechanism:

- **Same-block mirror inconsistency** — consistent by construction: both mirror syncs read the *final, fully-applied* authoritative tree; every mirror-relevant key changed by a block corresponds to a custody/FID in that block's message list, so every change is re-read and reflected. Walked onboard+revoke-A, onboard-B+rotate-to-B, chained A→B→C, and stale/no-op combinations.
- **Tombstone/empty-value collision** — no path writes a non-8-byte custody value except the empty tombstone; `read_onboard_custody_fid` gates on `len()==8`; the `ever` marker is read via `is_some()` and is never tombstoned.
- **Rotation dedup censorship** — the one-per-FID mempool slot is reachable only after `validate_custody_rotation` (sig recovers to `current`) **and** the optimistic `current-holds-fid` tree check, so a third party cannot squat a victim's FID slot.
- **Submit-vs-import asymmetry fork** — submit uses optimistic tree checks (may differ across nodes' momentary tips); import uses the authoritative in-tree apply, deterministic because blocks import in order (every node at the identical parent tip when a block lands). Mempool divergence never reaches consensus.
- **`forget_rotation` stranding a competing rotation** — impossible: dedup is one-per-FID and the submit gate rejects any rotation whose `current` doesn't currently hold the FID, so a "next-nonce" rotation can't be queued before the prior one finalizes.
- **Cross-type eviction amplified by rotations** — eviction across the shared mempool cap is pre-existing and **not** rotation-amplified: bogus rotations are rejected before insertion, so admitted rotations are FID-bounded.
- **ONBD-7 fail-open readers driven to a wrong FID / stake bypass** — the two authoritative fail-open readers (`read_onboard_seq`, `read_onboard_rotation_nonce`) can only ever see 8-byte or *absent* values, and absent is the correct default; `read_onboarding_stake_lock` is behind the prod-disabled stake gate. Not exploitable (latent fragility only; ONBD-7 status unchanged — still partial-by-design).

---

## Part D — Build & test evidence

WSL/Linux build tree `~/hs-f4fc4af` (rustc 1.95, `--cap-lints allow`, malachite sibling staged). Whole crate compiles clean.

```
# native onboarding (incl. the ported red→green PoCs)
test result: ok. 19 passed; 0 failed; ... (native_onboard)

# four-way rotation determinism (the ONBD-9/11 confirmation)
test hyper::builder::tests::onbd_four_way_rotation_apply_order_determinism ... ok

# broad regression (runtime/importer/mempool/builder/block_index)
test result: ok. 170 passed; 0 failed; ... incl. verkle_tree_replays_from_block_index_on_restart

# residual-Low characterization PoCs (mempool + native_onboard)
test poc_q4_noop_rotation_can_reloop_through_mempool ... ok      # ONBD-14
test poc_q5_rotation_validate_is_not_fid_bounded ... ok          # ONBD-15
test poc_q1_junk_rotation_cannot_squat_victim_fid_slot ... ok    # refutes censorship
```

Green fix-confirmation PoC bundle: [poc/onbd/ONBD-9-10-11-rotation-in-tree-green/](poc/onbd/ONBD-9-10-11-rotation-in-tree-green/). Per-cluster detail: [materials/revalidation-f4fc4af/00-SUMMARY.md](materials/revalidation-f4fc4af/00-SUMMARY.md).
