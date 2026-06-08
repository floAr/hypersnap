---
id: H043
specialist: http-api-rocksdb
attack_class: rocksdb-batch-write-partial
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
scope:
  - src/hyper/slashing_store.rs
  - src/hyper/validator_score.rs
  - src/hyper/importer.rs
---

# H043 — Slashing evidence record vs. validator score-decrement non-atomic put — RULED OUT

## Hunt

When slashing evidence is recorded and a validator score is updated, are both
writes in one atomic `RocksDbTransactionBatch`? If evidence is persisted but
the score-decrement (or vice versa) is a separate `db.put`, a crash between
them would leave evidence-without-penalty or penalty-without-evidence.

## Core finding: the two writes are never co-invoked

The premise of the hunt — an evidence write and a score-penalty write issued as
a pair — does not exist in this code. The two live on entirely separate paths
that never run together:

1. **Evidence record** (`src/hyper/slashing_store.rs:50-71`,
   `SlashingEvidenceStore::record`). A single `self.db.put(&key, &buf)` writing
   one `HyperWireEvidence` row under `RootPrefix::HyperSlashingEvidence`. It does
   **not** touch any validator score. Its only production caller is the actor's
   `InboundEvidence` handler via `HyperRuntime::record_evidence`
   (`runtime.rs:4156-4161`, called at `actor.rs:1608`). The handler persists
   evidence, pushes a dedupe key, and emits `EvidenceConfirmed` outbound — no
   score mutation anywhere in that arm (`actor.rs:1587-1620`).

2. **Score updates** (`src/hyper/validator_score.rs`,
   `src/hyper/importer.rs:86-111`). `update_scores_for_block` and
   `update_scores_for_missed_proposals` run on the block-import / epoch-boundary
   path (`importer.rs:184-227`, `runtime.rs:4569`). The slashing-specific
   penalty `ValidatorScoreTracker::record_invalid_proposal`
   (`validator_score.rs:198-208`) is **never called from any non-test code** —
   the only references are unit tests (`validator_score.rs:301`). So there is no
   wired "apply slashing penalty to score" operation at all, let alone one
   paired with the evidence write.

Because evidence-recording and score-mutation are not part of one logical
operation, a crash between them cannot produce "evidence-without-penalty /
penalty-without-evidence" — there is no penalty write to lose. Evidence is the
durable input the future epoch-boundary enforcement reads (per the module doc,
`slashing_store.rs:3-6`); enforcement is deliberately deferred and recomputed
from persisted evidence, not applied inline.

## Secondary observation (noted, not raised as F043)

`record_missed_proposal` / `record_successful_proposal`
(`validator_score.rs:179-196`, `161-177`) each issue **two** bare `db.put`
calls outside any batch:
- `persist(&record)` — the per-epoch `ValidatorScoreRecord` under
  `HyperValidatorScore` (`validator_score.rs:138-144`), and
- `write_consecutive_misses(...)` — the cross-epoch counter under
  `HyperValidatorConsecutiveMisses` (`validator_score.rs:107-115`).

A crash between the two leaves the per-epoch counter advanced while the
cross-epoch counter (the one `should_auto_deregister` actually reads,
`validator_score.rs:240-248`) lags by one. This is a real intra-method
non-atomicity, but it is **out of the F043 attack model** and low-impact:

- It is a divergence between two *derived score counters*, not the
  evidence-vs-penalty pairing this hunt targets.
- These counters are recomputable telemetry, and the surrounding import
  pipeline (verkle tree, block index, message store, scores) is already
  non-atomic across stores by design — score state is not committed in the
  same batch as block state, so it is reconciled by re-derivation, not crash
  atomicity. A single off-by-one on the consecutive-misses gate self-heals on
  the next miss or success.
- No fork-rollback state-corruption consequence: nothing keys committed chain
  state to these counters.

A batch API exists (`db.txn()` + `db.commit(batch)`,
`storage/db/rocksdb.rs:373-395`) and could tidy this pair, but the absence of an
atomicity invariant here means it is a code-hygiene nit, not the H043 bug.

## Conclusion

The H043 hypothesis (a non-atomic evidence-record + score-decrement pair) does
not hold: the slashing-evidence write and validator-score writes are never part
of one operation, and the slashing penalty (`record_invalid_proposal`) is not
wired to production at all. The only non-batched double-put found is the
score-tracker's two derived counters, which is outside this attack class and
carries no fork-rollback corruption impact. No confirmed finding.
