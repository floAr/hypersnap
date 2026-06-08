---
id: H008
specialist: chain-economics
attack_class: stale-trust-not-cleared
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/trust_store.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/scoring_driver.rs
  - code/hypersnap/crates/proof-of-quality/src/scoring.rs
---

# H008 — stale-trust-not-cleared — RULED OUT

## Scope
`TrustScoreStore` (`trust_store.rs`) and every trust-snapshot apply site:
the recurring epoch-rotation path and the one-time cutover bootstrap.

## Hypothesis
A PUT-only snapshot apply (`set_many`) leaves stale trust for FIDs that
dropped out of the active universe. Their stale score keeps feeding the
validator-trust gate, soft-evict filter, and fee-discount path long after
they go inactive — the classic stale-trust-not-cleared bug (prior F014).

## Method
1. Read both write APIs on the store. `set_many` (`trust_store.rs:59-64`)
   is PUT-only; `replace_with` (`trust_store.rs:79-115`) is the F014 fix —
   it walks the `HyperTrustScore` prefix, collects FIDs absent from the new
   set, and applies deletes + sets in one batch.
2. Enumerated every caller of both APIs across `src/`.
3. Identified which path is recurring (per-epoch rotation) vs. one-time.
4. Verified the snapshot semantics fed to `replace_with` are a *complete*
   recomputation, not a delta (else delete-absent would over-prune).
5. Confirmed the trust readers all go through `trust_store.get()`.

## Call-site map
- Recurring epoch rotation → `apply_trust_snapshot_update`
  (`runtime.rs:638-679`) → **`replace_with`** (`runtime.rs:674-675`).
  Reached from: `submit_message` gossip dispatch (`runtime.rs:3677`),
  BLS auto-scoring (`actor.rs:2138`), DKLS auto-scoring (`actor.rs:2271`),
  and multi-party DKLS sign-queue completion (`actor.rs:2817`). All four
  recurring paths use the delete-then-set semantic.
- One-time cutover bootstrap → `apply_cutover` (`runtime.rs:4258-4309`) →
  `set_many` (`runtime.rs:4292-4293`). Guarded by `genesis_applied`
  (`runtime.rs:4266-4268`); runs once into an empty store, so PUT-only is
  correct — there are no prior FIDs to clear.

## Snapshot is a complete recomputation (delete-absent is safe)
The snapshot entries come from `ScoringDriverOutput.trust_snapshot`
(`scoring_driver.rs:87-99,163-175`), built from
`EpochScoringOutput.trust_snapshot` =
`metrics.iter().map(trust_score)` (`scoring.rs:484-485`). `metrics` =
`build_metrics(reader, now_unix)` over `reader.all_active_fids()`
(`scoring.rs:379-382`) — the full active universe recomputed fresh each
epoch. Any FID that leaves `all_active_fids` is absent from the new set
and is therefore correctly DELETEd by `replace_with`. No stale entry can
survive a rotation, and the deletion is not over-broad.

## Readers are protected
- Validator-trust registration gate: `trust_store.get(event.fid)`
  (`runtime.rs:3858-3867`).
- Soft auto-deregister / active-set filter: `trust_store.get(fid)`
  (`runtime.rs:4096`).
- `validators_below_trust_floor`: `trust_store.get(fid)`
  (`runtime.rs:4132-4140`).
- Fee discount: `fee_charger.rs:96` via `trust_store`.
All read the same keyspace `replace_with` clears, so a dropped-out FID
reads `None` → treated as `0.0` after the first post-departure rotation.

## Replay / monotonicity
`apply_trust_snapshot_update` rejects epoch ≤ last applied
(`runtime.rs:646-653`) before writing, so an old snapshot can't clobber a
fresh store and resurrect stale scores.

## Conclusion
The stale-trust-not-cleared defect is fixed and correctly wired at this
commit. Every recurring trust-snapshot rotation uses the PUT+DELETE
`replace_with`; the snapshot is a complete recomputed set, making the
delete-absent semantic exactly right; the only PUT-only caller is the
guarded one-time bootstrap into an empty store. No stale trust persists
across epoch rotation. No finding.
