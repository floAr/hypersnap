---
finding_id: F073
title: One rate-limited message stalls a relay shard worker for about 14 minutes, delaying signer removals on the other network
severity: medium
status: pending-validation
related_findings:
- F074
---
# F073 — The relay processes each shard strictly in order, and `Submitter::submit` does not return until every message in the batch has a final outcome. A per-message `bad_request.rate_limited` is retried up to 20 times with exponential backoff capped at 60 s, which is about 14 minutes per batch. The target's always-on 1-per-minute `KEY_ADD` limiter can be held empty by the message's own FID, by submitting `KEY_ADD`s directly to the target. So one cheap `KEY_ADD` per ~14 minutes freezes that shard's relay worker in that direction. Shard 0 carries `KEY_ADD`/`KEY_REMOVE`/`LEND_STORAGE`, so signer revocations stop crossing the bridge.

- **Severity:** Medium, source-only. The relay's liveness is attacker-controlled. The shard-0 worker in either direction can be kept ~100% stalled by one FID: each poisoned block costs the worker ~14 minutes while the source makes about 840 blocks. Lag grows without bound, and the cursor gauge shows it. The security-relevant consequence: a `KEY_REMOVE` of a compromised signer on snapchain does not reach Hypersnap (and vice versa) for as long as the attacker keeps going. The stolen key stays valid on the other network. Not High, because there is no consensus or funds impact, it is visible in metrics, and operators can restart with a skip.
- **Confidence:** 0.6. The relay control flow is certain from source. The race of the attacker's direct `KEY_ADD`s against the relay's retries is reasoned: the limiter refills at a fixed time, and the attacker re-fills it about once a second. That gives roughly a 20% chance per stall that a retry slips through, after which the worker moves on to the next poisoned block. Not built.
- **Category:** relay liveness / head-of-line blocking (rate-limit amplification)
- **Specialist:** http-api-rocksdb · task H054
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced**: `crates/hypersnap-relay` does not exist at `bdef7b7`. The 1/min `KeyAddRateLimits` it collides with is inherited from snapchain (`bdef7b7:src/mempool/mempool.rs:141`). Mainnet snapchain is the outbound target.
- **PoC:** None. Relay-test sketch (`crates/hypersnap-relay/tests/e2e.rs` harness): give the fake target a submit handler that returns `MessageError{err_code: "bad_request.rate_limited"}` for one hash, always. Push that message in block h and a normal message in block h+1. Expected: block h+1 is not submitted until 20 attempts have elapsed. Shrink `retry_*` to show the 20-attempt ceiling.

## Code facts

1. **Classification.** `"bad_request.rate_limited" => RateLimited` (`crates/hypersnap-relay/src/classify.rs:117`).
2. **Retry loop.** Each round charges a RateLimited message one attempt, gives up only at `max_attempts`, and sleeps `backoff.next_delay()` between rounds (`submit.rs:162-180, 208`). The defaults are `retry_initial_ms = 500`, `retry_max_ms = 60_000` and `max_message_attempts = 20` (`config.rs:269-271`), so 0.5+1+…+32 s plus 13 × 60 s ≈ 14 min. Messages in the batch that already succeeded wait too, because `submit` returns only when `pending` is empty (`submit.rs:1-11, 120-212`).
3. **Strictly sequential.** The worker `await`s `process_block` inside its `select!` loop before it advances the cursor (`worker.rs:235-246`). It runs batches for one block in order (`worker.rs:305-308`). The deferred-retry tick and the tip gauge are in the same loop, so they stall too.
4. **Target limiter.** `KEY_ADD` is limited to 1 per minute per FID, always on, at mempool admission, for both RPC and gossip arrivals (`src/mempool/mempool.rs:136-170, 797-816`). Rejected attempts don't consume a token. The bulk RPC returns that as a per-message `MessageError` (`src/network/server.rs:1704-1740`).
5. **Allowlisted.** `KEY_ADD` is in the outbound allowlist from snapchain 0.11.7 (`filter.rs` `SNAPCHAIN_ALLOWLIST_TABLE`). On inbound, Hypersnap runs the same limiter.

## Attack (outbound, shard 0)

1. Attacker FID F submits a valid gasless `KEY_ADD` K1 to Hypersnap. It is merged in shard-0 block h.
2. Right before the relay reaches h (the cursor-lag gauge is not needed; just keep step 3 running continuously), F submits fresh valid `KEY_ADD`s directly to snapchain, about once per second. One per minute is accepted, which keeps F's bucket empty. Each accepted one needs a fresh key and an EIP-712 custody signature, which costs nothing. `KEY_REMOVE` (never rate-limited) recycles key slots.
3. The relay submits K1 and gets `rate_limited`. It retries for about 14 minutes, then `GaveUp`. Then it processes block h+1 and onward until it hits F's next `KEY_ADD` (one per 14 minutes is enough).
4. Inbound is symmetric: F's `KEY_ADD` on snapchain, and F's direct `KEY_ADD`s to the Hypersnap node(s) that the relay submits to.

Even without the attacker's spam, two `KEY_ADD`s of one FID that land in different blocks within a minute (via two proposers) stall the worker for up to a minute.

## Red-team

1. *Does the relay fail over on rate limits?* Only when no per-message result came back (`submit.rs:183-201`). A per-message RateLimited does not fail over. And the limiter state is shared across target nodes via gossip anyway.
2. *Is "one poison message cannot stop a shard" (`submit.rs:10-11`) true?* It cannot stop it forever, but the cap is 14 minutes per message. With a fresh poison message every 14 minutes, it is effectively forever.
3. *Can the operator lower `max_message_attempts`?* Yes, and that is a mitigation, but the shipped defaults are as above and the docs don't warn about this.
4. *Is the relay trusted to be the only bridge?* FIP Appendix A makes it the message bridge between the two networks. A stalled relay means divergent signer sets.
5. *Does Hypersnap itself stop F's spam?* The spam goes to the *target* network, not to Hypersnap.

## Fix

- Do not block the cursor on per-message rate limits. Park the message in the deferred queue with its own schedule (as for `StateDependent`), and finish the batch.
- Or cap the total time per batch (for example 2 × `retry_max`) and move the remaining messages to the deferred queue.
- Process `KEY_REMOVE` on its own fast path, never behind a rate-limited `KEY_ADD`.

## Files

- `crates/hypersnap-relay/src/submit.rs:1-11, 98-212`; `classify.rs:110-125`; `config.rs:262-285`; `worker.rs:186-246, 254-310`
- `src/mempool/mempool.rs:136-170, 797-830`; `src/network/server.rs:1654-1750`
