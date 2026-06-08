# F011 validation — shard read-validator protocol-version enforcement

Validator: validator (deliberate-disagreement). Commit `cab225f`.

Finding claim: shard read-validators skip protocol-version enforcement (only the
`Block` variant of `validate_protocol_version` enforces it), so a stale shard
read-node **silently** applies post-upgrade chunks under the wrong, locally
derived version and **silently diverges** with **no halt / no alert**.

## Key code facts confirmed

- `read_validator.rs:173-212` — `validate_protocol_version` only checks
  `Some(Value::Block(block))`; `Shard` falls into `_ =>` no-op and returns
  `true`. **CONFIRMED.**
- `blocks.proto:165-170` — `ShardHeader` has `height/timestamp/parent_hash/shard_root`,
  no `version`, no `chain_id`. `BlockHeader` (135-144) has `version` + `chain_id`.
  **CONFIRMED** — there is no producer-asserted version on the shard path.
- `engine.rs:2082` — `commit_shard_chunk` replay path derives `version` locally
  from `header.timestamp`. **CONFIRMED.**
- Production reachability: `read_validator.rs:58` (`commit_decided_value` →
  `ShardEngine::commit_shard_chunk`) is the real read-node ingest path.
  **CONFIRMED reachable.**

## The decisive counter-evidence (Hypothesis 3 / 6)

The finding's central claim — "silent divergence, no halt" — is **contradicted
by a downstream enforcement the finding does not address**:

- `engine.rs:593-605` (inside `replay_proposal`, the exact function the read-node
  replay path at 2093 calls): after applying the chunk's transactions, the engine
  recomputes `root1 = self.stores.trie.root_hash()` and compares it against the
  producer-supplied `shard_root` from the chunk header. On mismatch it logs
  `"Shard root mismatch"` and returns `Err(EngineError::HashMismatch)`.
- `engine.rs:2102-2104` — the read-node replay caller treats that `Err` as
  `panic!("State change commit failed: {}", err)`. A panic is a hard crash /
  halt, observable to the operator (process exits, restart loops, alerts fire).
- `version_for` (`version.rs:201-218`) on a stale binary returns the **highest
  schedule entry it knows** (`.filter(active_at<=t).last()`), i.e. an *older*
  version than the producer for a post-upgrade timestamp. A different
  `EngineVersion` that changes application semantics for the chunk's transactions
  produces a **different trie state**, hence a **different `shard_root`**, hence
  the `HashMismatch` panic at commit time.

Therefore the scenario the finding describes (stale node applies post-upgrade
chunk under wrong version) does **not** result in silent divergence: it results
in a panic at the shard-root self-check — a halt, just via crash rather than the
`ExitWithError("needs upgrade?")` message. The state-root self-check is a
version-agnostic integrity gate that catches exactly the divergence the missing
version check was supposed to catch.

Residual gap (genuine, but lower-impact than claimed): the operator signal is a
generic `"State change commit failed"` panic, not the actionable
`"Does your node need an upgrade?"` message the block path emits. So the real
defect is **poor operator diagnostics / wrong halt mechanism**, not "silent fork
serving divergent RPC." The node does NOT keep serving forked state across the
boundary — it crashes on the first divergent chunk.

The only way silent divergence survives is if a wrong-version replay produces a
state that differs from the producer yet collides to the *same* blake3 trie root
— cryptographically negligible. And if the wrong version produces an *identical*
root, no divergence occurred for that chunk in the first place.

## 8-hypothesis walk

1. **Upstream auth / gate** — STANDS (partial). `verify_signatures`
   (`read_validator.rs:228`, height-keyed validator set) does pass on a stale
   node across the boundary, so the chunk is admitted. No upstream version gate
   exists for shard chunks. The version no-op is real.

2. **Consumer-side impact** — PARTIALLY INVALIDATED. The claimed consumer ("RPC
   serves silently forked state to downstream consumers") does not materialize:
   the node panics on the first divergent chunk (engine.rs:2104) rather than
   committing and serving it. Consumers see an unavailable / crash-looping node,
   not a silent fork.

3. **Downstream enforcement** — INVALIDATED (the core). `replay_proposal`
   recomputes and enforces the shard state-root (engine.rs:593-605) version-
   agnostically; mismatch → `HashMismatch` → `panic!` (engine.rs:2104). This is
   the layer the finding says doesn't exist. It does.

4. **PR HEAD currency** — NEEDS_MORE_DATA. Validated against pinned `cab225f`;
   workspace is read-only / not a git repo, branch currency not checkable here.
   Does not affect the verdict (the counter-evidence is in pinned code).

5. **Spec carve-out** — STANDS. The `_ =>` arm comment ("Only blocks have
   protocol version") documents the design assumption but no spec declares shard
   version-divergence "intentionally deferred." Not a carve-out that rescues the
   finding; also not one that strengthens it.

6. **Reachability of harm** — INVALIDATED. The "harm" (persisted silent
   divergence + RPC serving) is gated by the shard-root self-check, which halts
   before persistence. Path to the claimed value/observability harm is blocked.

7. **Test wiring** — STANDS. The buggy no-op and the replay path are both
   genuine production paths (`read_validator.rs:58`, `:235`; `engine.rs:2042+`),
   not test-only.

8. **PoC mechanics** — NEEDS_MORE_DATA. No PoC is attached to the finding. The
   prose's "silent / no halt" assertion is not demonstrated and is contradicted
   by static analysis of the commit path; a PoC would need to show a wrong-
   version replay that yields a *matching* shard_root, which is implausible.

## Overall

The mechanical observation (shard variant has no protocol-version enforcement;
`ShardHeader` carries no version) is **true and confirmed**. But the impact as
written — "silent, undetected state divergence with no halt/alert, node keeps
serving forked state" — is **overstated and largely invalidated** by the
version-agnostic shard-root self-check + panic at commit (engine.rs:594-604,
2104). The genuine residual issue is a **diagnostics / wrong-halt-mechanism**
defect: the shard read-node crashes with a generic message instead of the
actionable "needs upgrade" `ExitWithError`. That is a real but Low-impact
defect, not the Medium-severity silent-fork described.

**Overall verdict: HAS_CAVEATS** (mechanical claim stands; impact materially
overstated — "silent divergence / no halt" is false because the shard-root
self-check panics). Confidence 0.8.

Suggested re-scoping: Low (operator-diagnostics / halt-quality), not Medium.

## Open follow-ups (NOT new findings)

- The generic `panic!("State change commit failed")` at engine.rs:2104 is the
  de-facto upgrade-needed halt for shard read-nodes. Worth confirming whether
  operators have alerting that distinguishes this crash from unrelated
  HashMismatch panics — a docs/runbook item, not a code bug.
