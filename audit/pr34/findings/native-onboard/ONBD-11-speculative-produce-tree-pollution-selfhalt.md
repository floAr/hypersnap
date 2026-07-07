# ONBD-11 — Speculative `produce` mutates `self.tree` with no rollback → unrecoverable proposer divergence + self-halt

- **Severity:** High
- **Status:** OPEN (new/worsened at `ab73681`; merge blocker **B9**)
- **Component:** `src/hyper/runtime.rs`, `src/hyper/builder.rs`, `src/hyper/actor.rs`
- **Class:** pre-existing speculative-mutation-without-rollback, **strictly worsened** by the ONBD-1 fix.
- **Corroboration:** actor/consensus-lifecycle lane (Finding 1).

## Summary

`produce_envelope_with_full_anchor` applies drained messages **directly to `self.tree`** before the produced block is finalized by consensus, and there is no rollback. For onboards this assigns a FID, bumps the **global** in-tree sequence counter, and sets a **permanent** `ever` marker. If the produced block never becomes canonical (DKLS ceremony stall + proposer reassignment), the proposer's tree stays polluted and its recomputed root will never again match the canonical signed root → **permanent `StateRootMismatch` self-halt**.

## Mechanism (code-traced)

- `produce_envelope_with_full_anchor` builds `HyperBlockBuilder::new(&mut self.tree)` (`runtime.rs:5094`) and, via `build_envelope_with_full_anchor` (`builder.rs:333-335`), calls `apply_message` on every drained message against `self.tree`. For onboards this runs `apply_onboard_to_tree` (`builder.rs:87-111`): assigns a FID from the in-tree sequence, `tree.insert(onboard_seq, next)` (bumps the **global** counter), `tree.insert(ever_key, [1])` (permanent).
- `start_dkls_block_production` (`actor.rs:2871`) calls `produce_unsigned_block_dkls` **before** any guarantee the block finalizes; the unsigned block is only stashed in `pending_dkls_blocks` (`actor.rs:2937`) and applied to the chain solely if/when the DKLS ceremony completes and `dispatch_dkls_signature` (`actor.rs:3001-3014`) calls `import_block`.
- **No rollback exists.** The tree is only (re)built at construction (`runtime.rs:386-432`); `pending_dkls_blocks` is a `BTreeMap` with no timeout that reverts the tree.

## Failure scenario (reachable under a normal fault, not adversarial-only)

1. Height H: proposer P is selected (`scheduler.rs:141-168`). P's mempool holds an onboard for custody B. P produces → `self.tree` now holds `B→k`, `seq=k+1`, `ever[B]=1`. Block stashed; multi-party DKLS ceremony started.
2. The ceremony stalls (a committee member offline → P never gathers `t` partial sigs). The block is never finalized, imported, or broadcast. **P's tree stays polluted.**
3. The chain head does not advance (moves only on import). An anchor-refresh tick (`scheduler.rs:262-273`) updates the proposer context; `is_proposer(anchor', H)` now selects a different node P′ for the **same** height H. P′ (which never saw B) produces and finalizes block B\* for H with a different onboard set.
4. P receives B\* → `import_block`. Re-applying B\*'s onboards leaves P's tree still carrying `B→k, seq=k+1`, which B\*'s signed root does not. `import_hyper_block` returns `StateRootMismatch` (`importer.rs:314-321`). P rejects the canonical block and **halts at H permanently** — every future import re-derives from the polluted tree and fails the root check. Recovery requires wiping the DB and resyncing.

## Why this is a regression of the ONBD-1 fix

The underlying speculative-apply-without-rollback is **pre-existing** — transfers already strand nullifier/commitment leaves at `builder.rs:210-220` for a losing block. But those leaves are **content-addressed**: if the same messages later commit, they re-agree at fixed keys, so the divergence is transient/self-healing. An onboard's FID is **history-derived** (a global mutable `seq`), and the permanent `ever` marker cements the *first* speculative assignment — once P assigns `B→k`, `apply_onboard_to_tree` returns `None` forever, so P can never re-agree with the network's `B→k′`. ONBD-1 thus converts a would-be-transient root drift into a **non-self-healing identity fork + self-halt**.

(Restart *heals* the pollution — the tree is rebuilt only from committed blocks in the index — so the damage window is the in-memory, no-restart path.)

## Reachability caveat

The trigger depends on the consensus/proposer model: a stalled DKLS ceremony **plus** proposer reassignment for the same height via anchor refresh. If the deployment guarantees a produced block is always the finalized block at its height (no reassignment before ceremony completion/timeout), the window narrows. The **structural** defect — produce mutates authoritative state with no rollback — stands regardless.

## Fix direction

Apply produce-time messages to a **scratch/cloned** tree (or a staged overlay) and only fold into `self.tree` at finalize/import; or defer all tree mutation to `import_block` and have produce compute the candidate root without persisting. Either removes the speculative-pollution surface for onboards *and* transfers.

## Key locations

`runtime.rs:5094` (produce mutates `self.tree`) · `builder.rs:87-111` (global `seq` + permanent `ever`) · `actor.rs:2871,2937,3001-3014` (produce→stash→conditional import) · `importer.rs:314-321` (root check → self-halt) · `scheduler.rs:141-168,262-273` (proposer selection / anchor refresh).
