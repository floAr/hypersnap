---
finding_id: F074
title: When the relay deferred queue is full, deferrals become permanent drops and those messages are never relayed
severity: low
status: pending-validation
related_findings:
- F073
---
# F074 — Each relay shard worker has a deferred queue of 1024 entries. When the queue is full, a new state-dependent rejection ("unknown fid", "invalid signer", "fname is not registered") becomes a permanent `Rejected` in the seen set, and that message is never relayed. Entries leave only after 5 attempts over about 7.5 minutes. About 2.3 such messages per second per shard keep the queue full. During that time, legitimately early messages are dropped from the other network for good. Examples are a new user's first casts that arrive before their `KEY_ADD` is relayed by the shard-0 worker, and messages of an FID whose on-chain registration the target has not ingested yet.

- **Severity:** Low, source-only. The impact is permanent cross-network loss of individual messages (selective censorship of new or just-changed accounts), not a halt. Users can resubmit to the other network directly. The attacker needs messages that the *source* accepts and the *target* rejects with a state pattern. The cheapest way is an attacker FID that removes signer S directly on the target (gasless `KEY_REMOVE`, never rate-limited) while it keeps posting with S on the source. That costs one source-side message per entry. Source-side rate limits per FID bound this to the attacker's storage, so it needs several FIDs.
- **Confidence:** 0.6. The queue semantics are certain from source. The organic fill rate is not measured: migrated FIDs whose signers exist only on Hypersnap could also fill it organically.
- **Category:** relay liveness / bounded-queue overflow policy (deferred-queue growth)
- **Specialist:** http-api-rocksdb · task H054
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`crates/hypersnap-relay` is new since `bdef7b7`).
- **PoC:** None. Unit-test sketch: `DeferredQueue::open(path, 2)`, upsert two entries, and drive `Worker::apply_outcomes` with a third `Outcome::Deferred`. Expected: `SeenStatus::Rejected` is recorded for the third, and a later block that contains the same hash is skipped as `AlreadyHandled`.

## Code facts

1. `DeferredConfig::default()`: `capacity = 1024`, `max_attempts = 5`, `retry_ms = 30_000`, patterns `unknown fid` / `invalid signer` / `fname is not registered for fid` (`crates/hypersnap-relay/src/config.rs:157-188`).
2. `upsert` returns false when the queue is full and the hash is new (`store/deferred.rs:110-118`). The worker then records `SeenStatus::Rejected` ("deferred queue full; rejecting", `worker.rs:343-377`).
3. Delays double: 30 s, 60 s, 120 s, 240 s, and the 5th submission rejects (`worker.rs:345-361`). One entry therefore holds a slot for about 450 s, so 1024/450 s ≈ 2.3 entries per second per worker.
4. A `Rejected` hash is skipped forever, until the seen set evicts it (`worker.rs:279-298`, `store/seen.rs`).
5. Classification is a substring match on the target's error text (`classify.rs:150-153`).

## Red-team

1. *Is the overflow policy deliberate?* The doc says "When the queue is full, a new deferral is a rule rejection" (`config.rs:163-165`). It is deliberate, but it converts a transient condition into a permanent drop, and the trigger is attacker-fillable.
2. *Can an attacker produce state-dependent rejections cheaply?* Yes, via a signer that is valid on the source and removed on the target (above). Also, organically, via Hypersnap-only signers of migrated FIDs (Falcon-custody `KEY_ADD`s are filtered as `KeyAddNotEip712`, `filter.rs:193-200`, but those signers' casts are not).
3. *Is a lost message recoverable?* Only manually, by resubmitting to the target.

## Fix

- When the queue is full, either block (back-pressure) or evict the entry with the most attempts, rather than reject the newest.
- Size the queue by bytes, not entries, and alert when it is full.
- Rate-limit deferrals per FID so one FID cannot fill the queue.

## Files

- `crates/hypersnap-relay/src/config.rs:157-188`; `store/deferred.rs:1-12, 110-118`; `worker.rs:279-298, 343-377`; `classify.rs:110-153`; `filter.rs:171-206`
