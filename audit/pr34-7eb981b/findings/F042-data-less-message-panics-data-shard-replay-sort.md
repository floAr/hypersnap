---
finding_id: F042
title: A proposed data-shard block whose transaction holds two `Message`s with `data = None` panics every node that executes it
severity: critical
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.8
poc:
  path: poc/F042
  kind: build-backed
  result: 6/6
related_findings:
- F023
- F022
- F033
---
# F042 — A proposed data-shard block whose transaction holds two `Message`s with `data = None` panics every node that executes it. `replay_snapchain_txn` sorts user messages with `a.data.as_ref().unwrap()` before any validation.

> **Status (2026-11-04):** Severity **Critical** (validated 0.8, HAS_CAVEATS). Preconditions: conditional: High if the consensus topic is validator-only. PoC: poc/F042 (build-backed, 6/6). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity **Critical** (validated 0.8; High if the consensus topic is validator-only). The panic stops the shard's Host actor, which has no supervisor; the process stays up and consensus for that shard is dead until a manual restart. Fixed upstream at snapchain f66b47c (`engine.rs:1589-1594`); cherry-pick. PoC: poc/F042 (6/6).


- **Category:** message-envelope robustness (X2: "every path that consumes `Message`")
- **Specialist:** falcon-pq-message-auth · task H033 (X2)
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **Attribution:** The sort is **inherited from snapchain v0.15** (identical at bdef7b7 `engine.rs:1602-1607`). The PR makes it reachable: the Hypersnap proposer set is open, and per F022/F023 proposals are not authenticated. Upstream snapchain proposals come from a permissioned, signed set.

## Code facts

1. `replay_snapchain_txn` clones `user_messages`, drops unknown fields only where `data` is `Some` (`src/storage/store/engine.rs:2313-2318`), then sorts (`:2321-2354`).
   - `get_message_priority` is safe for `data = None` because `msg_type()` returns `None`, which maps to priority 5.
   - On equal priority, `then_with(|| a.data.as_ref().unwrap().timestamp.cmp(&b.data.as_ref().unwrap().timestamp))` (`:2347-2353`) unwraps `None`.
2. The sort runs before `validate_user_message` (`:2358`), which is where a missing `data` would otherwise be rejected (`NoMessageData`, `:2956-2959`).
3. Nothing upstream of it rejects a data-less message.
   - `validate_body` checks sizes, hash and roots only (`src/chain/block.rs:155-180`).
   - `check_value` → `ShardBlockProducer::validate` → `hypersnap_validate` → `replay_proposal` → `replay_snapchain_txn` (`src/chain/proposer.rs:131-135`, `src/chain/shard_blocks.rs:436-466`, `engine.rs:754-773, 1308-1310`).
   - The same replay runs at commit for a decided block (`hypersnap_commit`, `engine.rs:807-848`) and during sync.
4. `Cargo.toml` sets no `panic = "abort"`. The panic unwinds the task that runs `check_value`. No `catch_unwind` exists in `src/`.

## Attack path

1. Build a `HypersnapBlock` for shard s at height `next`: copy the public parent certificate, and add one `Transaction` with two `Message{data: None, data_bytes: None}` (or `data_bytes` set to anything, since only `data` matters). Compute `messages_root` and the hash. `state_root` can be anything, because the panic comes before the root comparison.
2. Gossip it as a `FullProposal` (F023 route) or propose it in a validator slot.
3. Each validator's `check_value` executes it and panics. If the decided-value path also replays it (a Byzantine proposer who gets it decided, or a sync peer serving it), restarted nodes crash again on replay. Not traced further.

## Red-team

1. *Does prost decoding fill `data`?* No. `data` is an optional field, and its absence is `None`.
2. *Does `then_with` run for a lone message?* No. It needs at least two messages with equal priority, which the attacker controls.
3. *Is the panic contained?* **This is the strongest reason the severity might be lower.** If the Malachite host actor is supervised and restarted, the effect may be one failed round per crafted proposal, not a node exit. It is still a cheap, repeatable round-killer. Medium is the floor.
4. *Does F023 really let a non-validator reach `validate`?* F023 fact 4 says so. If not, this needs one validator.
5. *Pre-pivot?* Snapchain v0.15's own path had the same code (fixed upstream at `f66b47c`), but its proposals are signed by known validators.

## Recommendations

- Reject messages without `data` (after normalising `data_bytes`) in `validate_body` for every block type, and use a total, panic-free comparator, for example `data.map_or(0, |d| d.timestamp)`.
- Authenticate proposals (F022/F023 fix).
- Add a fuzz target over `replay_snapchain_txn` with arbitrary `Transaction`s.
- Note: the sort is inherited from snapchain v0.15 and is already fixed upstream at `f66b47c` (`engine.rs:1589-1594`); cherry-picking that comparator closes it.
