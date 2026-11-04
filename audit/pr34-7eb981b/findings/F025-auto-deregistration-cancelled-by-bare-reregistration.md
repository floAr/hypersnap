---
finding_id: F025
title: A validator that never proposes can cancel its own auto-deregistration with nothing more than a signed re-registration
severity: medium
status: pending-validation
related_findings:
- F024
- F026
- F029
---
# F025 — A validator that never proposes can cancel its own auto-deregistration with nothing more than a signed re-registration. The miss counter resets each time, so an offline seat stays in the set forever and costs every one of its proposer slots a round timeout.

- **Severity:** Medium (lasting liveness/throughput loss. It defeats the protocol's only way to remove dead validators, and it costs nothing to repeat). It is not a halt on its own: the seats must stay below 1/3, and above that see F024.
- **Category:** epoch-set-handoff-gap / auto-deregistration bypass (spec-level weakness implemented as written)
- **Specialist:** pivot-genesis-epoch · attack class: epoch-set-handoff-gap · task H015
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** None (reasoned from source).

## Code facts

1. **Auto-deregistration.** After `auto_deregister_threshold` (100) consecutive missed proposals, `record_proposals` calls `auto_deregister`. That function sets `leave_epoch = epoch + 2` and `auto_deregistered = true`, or `inactive` if the set would fall below `MIN_VALIDATORS` (`src/chain/shard0/validators.rs:363-415`). Misses are counted on all three shards (`engine.rs:345,386`).
2. **Cancel path** (`validators.rs:210-223`). A `VALIDATOR_REGISTER` for the same consensus key and the same FID while `auto_deregistered && leave_epoch > ctx.epoch` sets `leave_epoch = 0`, `auto_deregistered = false`, and **`consecutive_missed = 0`**, then returns. The checks that run first are only signatures (PoPs), the `registration_epoch`, an attestation of *some* node key of the FID, and age/trust (`:151-201`). Nothing asks for evidence that the node is back: no recent proposal, no certificate signature, no liveness attestation. The body's `falcon_node_key` is not even compared with the stored `node_key_hash`.
3. FIP §4.7 says: "If the node recovers and registers again during the buffer, the protocol cancels the deregistration". The code follows this literally, using "registers again" as the proof of recovery.

## Attack

The attacker holds seat V, obtained as in F024 or as a former honest operator, and never proposes (or keeps the node offline).
1. V is proposer for about `1/n` of the (height, round-0) slots on each shard. Every one of those rounds times out (`propose_time` 6 s plus escalation) before round 1. With `n` = 20, V has about 5,400 slots per epoch across 3 shards, so it reaches 100 misses within about 2% of an epoch.
2. Auto-deregistration then sets `leave = e+2`. V sends one `VALIDATOR_REGISTER` in epoch `e` or `e+1`, and the deregistration is cancelled with the counter back at 0.
3. Repeat. V never leaves. Each cycle costs one signed message and no tokens: seats have no stake and nothing is slashed (FIP §12).

With `A` such seats out of `n`, a fraction of about `A/n` of heights on every shard pays at least one round timeout. Consecutive attacker slots in `order(e)` pay several. At `A/n` near 0.3 the average block time rises by a large fraction, and blocks per epoch fall. Epochs are counted in blocks, so wall-clock epochs get longer, and every per-epoch schedule (PoQ, DA, bridge handoffs) slows with them. Honest operators cannot remove V.

## Red-team

1. *Does it need a key the attacker doesn't have?* No. The registration is signed by V's own account key, consensus key and node key.
2. *Does age/trust re-check stop it?* Only if V's FID trust falls below 0.05. Nothing about missing proposals changes trust.
3. *Does `INACTIVE` change anything?* `INACTIVE` (set too small) is cleared the same way (`inactive && leave_epoch == 0`), so the same reset applies.
4. *Is it just the spec's intent?* The spec allows the cancel but assumes recovery. A cancel that resets the counter without proof makes §4.7 ineffective against an adversary. This is a spec weakness that the code faithfully implements, and both need the fix.
5. *Self-harm only?* No. Every honest validator and user pays the timeouts.

## Recommendations

- Require proof of liveness to cancel. For example, V must have proposed (as `round == decided`) or signed a certificate since `auto_deregistered` was set, or the cancel takes effect only after V's next successful proposal.
- Alternatively, do not reset `consecutive_missed` on cancel, and cap cancellations (for example once per N epochs), or make a second auto-deregistration within K epochs final.
- On the cancel path, require the body's node key to equal the stored `node_key_hash` and still be attested.
