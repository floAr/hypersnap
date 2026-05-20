---
id: F026
task: H026
specialist: node-lifecycle-actor
attack_class: lifecycle-state-leak
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# `produce_unsigned_block_dkls` selects the local DKLS share by `iter().next_back()` (max-epoch-installed) instead of by the resolver's current epoch — pre-installed future-epoch material leaks into current-epoch block production, decoupling `block.signature.epoch` from the canonical chain position and bypassing equivocation slashing

## Summary

`HyperRuntime::produce_unsigned_block_dkls` (`src/hyper/runtime.rs:4430-4478`) picks the signing epoch by reading the **highest-keyed entry** in the in-memory `dkls_signers: BTreeMap<u64, DklsEpochState>` (line 4459-4464):

```rust
// The "current epoch" at production time is the one the
// DKLS signer is keyed on — fall back to the most-recently
// installed if multiple are present.
let (epoch, group_address) = self
    .dkls_signers
    .iter()
    .next_back()
    .map(|(e, s)| (*e, s.group_address))
    .ok_or(RuntimeProduceError::NoDklsShare)?;
```

`next_back()` on a `BTreeMap` returns the entry with the **largest key** — the highest epoch ever installed. The runtime never reconciles this with `self.epoch_resolver.current_epoch()` (`runtime.rs:3895-3897`), never asserts that the picked epoch matches the canonical block id's epoch via `epoch_resolver`, and never prunes old shares. The map is insert-only (`dkls_signers.insert(...)` at line 4354 is the *only* mutating call; `grep dkls_signers\.(remove|clear|retain|pop)` returns zero matches across `src/hyper/`).

The downstream block stamps `block.signature.epoch = <max-installed-epoch>` and `block.signature.group_address = <that-epoch's-group-addr>`. The importer (`importer.rs:246-258`) and verify path (`runtime.rs:4127`) look up the group address by `block.signature.epoch` and accept the block, because the registry entry for that future epoch was also written by `install_local_dkls_share` (line 4367) and is hydrated on restart from the durable `dkls_address_store`. The verifier therefore cannot tell — from the wire — that the chain head position implies a *different* epoch.

The leak window opens the instant a future epoch's local share is installed (DKG ceremony for epoch N+1 finalizes early, before the epoch-N→N+1 boundary), and stays open until the chain advances into epoch N+1. During that window every block the local proposer builds is stamped `signature.epoch = N+1` even though `canonical_block_id` is in epoch N. Two consequences follow.

## Consequence 1: equivocation slashing is bypassed

`detect_conflicting_blocks` (`src/hyper/slashing.rs:51-81`) is the only path that converts double-signing into `ConflictingBlocksEvidence`. After the canonical_block_id check (lines 55-59) it gates on **equal epochs**:

```rust
let e_a = a.signature.epoch;
let e_b = b.signature.epoch;
if e_a != e_b {
    return Err(EvidenceError::DifferentEpochs { a: e_a, b: e_b });
}
```

A malicious proposer who is in the signing committee for both epoch N and (the pre-installed) epoch N+1 can therefore deliberately double-sign the same `canonical_block_id`:

1. Build block A at height H with the epoch-N share (force-select by ensuring no later share is installed). Sign with the epoch-N committee. `block_a.signature.epoch = N`.
2. Install the epoch-N+1 share early (or wait for it to arrive). Build block B at height H — `produce_unsigned_block_dkls` now picks epoch N+1 via `next_back()`. Sign with the epoch-N+1 committee. `block_b.signature.epoch = N+1`.
3. Gossip both blocks. Honest verifiers accept *either* — both signatures verify against their respective registry entries.

When honest validators run `detect_conflicting_blocks(block_a, block_b)`, the function returns `EvidenceError::DifferentEpochs` (line 64) and **drops the evidence**. The on-chain slashing path is gated on that evidence: `record_evidence` (`runtime.rs:3901-3909`) is only ever called with the *output* of `detect_conflicting_blocks`. The attacker double-signs the same height without being slashable.

Real-world trigger does not require malice: a buggy/auto-scheduling proposer that runs the production loop while a fresh epoch share has just been installed will *naturally* produce two competing blocks at the same height (one before, one after the install) — the post-install block carries the wrong epoch tag and silently shields the pre-install block from equivocation detection.

## Consequence 2: every block in the leak window has a wrong-epoch tag, breaking chain-position invariants

`block.signature.epoch` is mixed into the hyper block hash via `chain.rs:35`:

```rust
h.update(block.signature.epoch.to_be_bytes());
```

…and is the key used by:

- `update_scores_for_block` (`importer.rs:219-224`) — credits the **epoch-N+1** validator score for a block that actually appears in epoch N. Scores rotate with the active set, so the wrong validators' performance counters are bumped.
- `apply_validator_events` (`importer.rs:65-79`) — `block_epoch` is the epoch the registry validates registration events against. A block tagged N+1 carrying a register/deregister event for epoch N+1 will pass the registry's epoch check **even though the block is anchored to a snapchain block whose true epoch is N**. This is a one-epoch-early effect, not a multi-epoch leak, but it lets the proposer activate validators a full epoch before the resolver thinks the epoch has begun.
- `record_missed_proposal` (`importer.rs:102-111`) — counter at the wrong epoch.
- `block_index.rs:57` and `slashing_store.rs:184` — persist the wrong epoch alongside the block. Restart recovery of the score tracker now thinks epoch N+1 had blocks that were actually epoch N.

## How the future-epoch share gets installed before the boundary

`install_local_dkls_share` (`runtime.rs:4347-4380`) is the sole installer; its callers are the DKG finalization driver and `bootstrap_runtime` (`genesis.rs:88`). The DKG ceremony runs **ahead of** the epoch boundary by design — `dkls_supervisor.rs:59-110` (per H025's analysis) drives `StartDkls` at `start_lead_blocks` *before* `next_epoch_start`. The lead time is configurable, but the protocol-level contract is "the next epoch's group address must be known to all verifiers before the boundary so post-boundary signatures verify immediately." That means the registry write at line 4367 — `self.dkls_group_addresses.insert(epoch, group_address)` — happens before the resolver's `current_epoch()` advances. From then until the boundary, `dkls_signers` (the local-share map) contains both N and N+1, and `next_back()` returns N+1.

Test `runtime.rs:6208-6234` exercises exactly this layered installation:

```rust
rt.install_local_dkls_share(0, 1, dkg0.parties[0].clone(), dkg0.group_address);
rt.install_local_dkls_share(1, 1, dkg1.parties[0].clone(), dkg1.group_address);
rt.install_local_dkls_share(2, 1, dkg2.parties[0].clone(), dkg2.group_address);
```

After this sequence, regardless of the resolver state, every subsequent `produce_unsigned_block_dkls` call selects epoch 2.

## Why the cutover/genesis paths make the leak persistent across restart

- `bootstrap_runtime` (`genesis.rs:58-92`) installs the local epoch-0 share. The share's `group_address` is captured at line 88. Restart wipes `dkls_signers` (it is in-memory only — see test comment at `runtime.rs:5263-5266`: *"Local share is NOT persisted (per design — only the group address registry is durable). The dkls_signers map is empty after restart."*). But the **registry** `dkls_group_addresses` IS hydrated on restart from `dkls_address_store` (`runtime.rs:378`). So after restart with no in-flight DKG, signer state is `{epoch_0: share}` for a genesis node and `next_back()` correctly returns 0. Once the *next* epoch share is installed in the same process, the leak window opens and stays open.
- `apply_cutover` (`runtime.rs:3990-4041`) writes `install_dkls_group_address(0, genesis_group_address)` at line 4017 but does NOT touch `dkls_signers`. A node that ran `bootstrap_runtime` (which already installed a local epoch-0 share with the DKG-derived `group_address`) and later has `apply_cutover` called with a **different** `genesis_group_address` argument ends up with `dkls_signers[0].group_address ≠ dkls_group_addresses[0]`. The `next_back()` selection then emits a block whose `signature.group_address` (from `dkls_signers[0]`) doesn't match the verifier's registry lookup (`dkls_group_addresses[0]`) for the same epoch. Signature verification fails on every peer. This is a self-DoS that is hard to diagnose because the producing node sees no error — it built a valid-looking block, but every peer rejects it on import.

## What the safe selection would look like

The producer must derive the signing epoch from the *resolver*, not from the BTreeMap's max key:

```rust
let epoch = self.epoch_resolver.current_epoch();
let share = self.dkls_signers
    .get(&epoch)
    .ok_or(RuntimeProduceError::NoDklsShare)?;
```

…with a defensive assertion that `share.group_address == self.dkls_group_addresses[&epoch]` to catch the bootstrap-vs-cutover divergence. The committee selection in `actor.rs:2302-2308` already takes `epoch` as an explicit argument; the same value should flow into the producer.

## Affected file:line citations

- `src/hyper/runtime.rs:4459-4464` — `produce_unsigned_block_dkls` picks max-epoch share via `BTreeMap::iter().next_back()`. No resolver consultation.
- `src/hyper/runtime.rs:278` — `dkls_signers: BTreeMap<u64, DklsEpochState>` declaration. Persists every epoch's share ever installed in the running process.
- `src/hyper/runtime.rs:4347-4380` — `install_local_dkls_share` is insert-only; never prunes, never errors on out-of-order installs.
- `src/hyper/runtime.rs:4367` — write-through into `dkls_group_addresses`, the verifier's registry, completes the round-trip: the verifier accepts the future-epoch tag because it has the group address for it.
- `src/hyper/runtime.rs:3895-3897` — `current_epoch()` exists and returns the resolver's view, but is **not** consulted by the producer.
- `src/hyper/slashing.rs:61-65` — `detect_conflicting_blocks` returns `Err(DifferentEpochs)` and drops the evidence whenever `a.signature.epoch != b.signature.epoch`. This is the slashing-bypass primitive.
- `src/hyper/importer.rs:219-224` — `update_scores_for_block` uses `block.signature.epoch` directly. Wrong-epoch tag → wrong-epoch score credit.
- `src/hyper/importer.rs:65-79` — `apply_validator_events` validates registration events against `block_epoch = block.signature.epoch`. Wrong tag → registrations land in the wrong epoch.
- `src/hyper/chain.rs:35` — `block.signature.epoch` is mixed into the block hash. Different tags → different hashes for blocks at the same canonical_block_id.
- `src/hyper/actor.rs:2279-2287` — block production caller reads `block.signature.epoch` *back* from the runtime's returned block (line 2287) and uses that for digest + committee selection. The actor cannot detect the leak; it trusts the runtime's choice.
- `src/hyper/runtime.rs:5263-5266` — test comment confirming dkls_signers is in-memory-only; restart erases historical shares but not the leak window once a fresh share is installed mid-session.
- `src/hyper/runtime.rs:6208-6210, 6233-6234` — tests that build the exact multi-epoch installed state in which `next_back()` mis-selects.

## Attack/drift scenarios

**Scenario A — natural double-sign, no malice.** A single proposer node ticks through `start_dkls_block_production` (`actor.rs:2270`) at canonical_block_id H during epoch N. Meanwhile the DKG finalization driver completes epoch N+1's ceremony and calls `install_local_dkls_share(N+1, ...)`. Tokio schedules a *second* block production attempt (e.g., a retry from the BlockProductionScheduler tick, or a fork-choice reorg trigger) at the same height H; this second attempt's `produce_unsigned_block_dkls` now picks N+1. Both blocks are valid threshold signatures over the same `canonical_block_id` but with different epoch tags. `detect_conflicting_blocks` rejects the pair as `DifferentEpochs`. The node has equivocated and is not slashable.

**Scenario B — deliberate slashing-bypass.** A validator in both committee N and committee N+1 wants to support two forks of the chain (e.g., for an MEV-style bribe). They produce fork-A block tagged epoch N and fork-B block tagged epoch N+1 at the same height. The honest network observes both but cannot evict them. Combined with F018-style committee-selection deterministic-pseudorandomness (`dkls_committee.rs`), a validator who maximizes their reuse across consecutive committees gets a wide leak window for free.

**Scenario C — bootstrap-vs-cutover address drift.** Genesis runs `bootstrap_runtime` with `dkg.group_address = X`; the bootstrap signer's `dkls_signers[0].group_address = X`. Operator re-runs `apply_cutover` (post-restart, before any hyper block) with `genesis_group_address = Y` — perhaps because the original DKG was discarded and a fresh one was held. `apply_cutover` writes `dkls_group_addresses[0] = Y` but leaves `dkls_signers[0].group_address = X` (no clear, no overwrite of the local-share map). The producer emits blocks with `signature.group_address = X`; verifiers look up registry epoch 0 → Y; signature verification fails. Self-DoS, hard to diagnose because every peer's error message is "SignatureVerificationFailed" rather than a structured mismatch.

**Scenario D — wrong-epoch validator activation.** A validator submits a `HyperValidatorEventBody` with `registration_epoch = N+1` into a block produced during epoch N. Normally the registry would reject this on `block_epoch = N` (the registry enforces same-epoch registration). With the leak, the producer stamps `block.signature.epoch = N+1` and the registry happily accepts the registration **a full epoch early**. The new validator is now part of the active set at the *next* boundary's computation despite the chain having only just left epoch N-1.

## Severity rationale: high

- **Detection difficulty**: invisible to the producing node (no error path), partially visible to honest peers (they can observe that a block's `signature.epoch` is incoherent with the snapchain anchor's resolver-derived epoch, *if* they implement that cross-check — they currently do not).
- **Exploitability**: the leak window opens automatically every epoch by design — DKG finalization precedes the boundary by `start_lead_blocks`. Any node that produces a block in this window with the new share already installed exhibits the bug. Slashing-bypass (Scenario B) requires committee membership in two consecutive epochs, which is the norm not the exception under the validator-stability policy.
- **Direct impact**: equivocation slashing is the consensus layer's *only* deterrent against double-signing. Bypassing it lets an attacker double-sign without economic cost — the foundational integrity property of the protocol.
- **Severity-limiting factors**: only one block at the leak-window-affected height becomes "free to equivocate"; the attacker still needs a valid threshold committee for the future epoch (committees aren't fully under one party's control). But because the future committee membership is public *before* the boundary, an attacker can pre-coordinate.
- **Cost to fix**: low — replace `next_back()` with a resolver lookup, add the `group_address` consistency assertion, and tighten `detect_conflicting_blocks` to also accept evidence pairs where canonical_block_id matches even if signature.epoch differs.

## Cross-references

- F004 (epoch-boundary race) — distinct: F004 is about resolver desync across `observe_anchor`; F026 is about the producer not consulting the resolver at all when picking the share.
- F018 (DKLS inner-sender binding) — distinct surface; same family of "future-epoch signing material handled too leniently."
- H025 ruled-out — confirms there is no supervisor restart loop, so the bug is bounded to a single producing process's lifetime; this matters because the leak window does not get amplified by automatic restart.

## Suggested remediation (for triage; not part of this draft's scope)

1. **Resolver-driven epoch selection.** Replace lines 4459-4464 with `let epoch = self.epoch_resolver.current_epoch(); let share = self.dkls_signers.get(&epoch).ok_or(...)?;`. Future-epoch installs no longer affect current-epoch production.
2. **Consistency assertion.** In `produce_unsigned_block_dkls`, assert `self.dkls_group_addresses.get(&epoch) == Some(&share.group_address)`; return a structured `EpochGroupAddressMismatch` error if they diverge. Catches Scenario C immediately.
3. **Same-height equivocation evidence.** Loosen `detect_conflicting_blocks` to produce evidence when `canonical_block_id` matches even if `signature.epoch` differs. The signing committees for the two epochs are both slashable (each block's signers committed under their own group key); record evidence under *both* epochs and let the slashing pipeline punish the intersection.
4. **Prune `dkls_signers` past a horizon.** Once `chain.last_height` is well past the snapchain anchor that started epoch e, drop `dkls_signers[e-K]` to bound the forward-secrecy window. The registry `dkls_group_addresses` is the only thing verifiers need long-term; old local shares are pure liability.
5. **Producer→resolver→committee triple binding test.** Add a test that pre-installs epoch N+1's share, calls `produce_unsigned_block_dkls` while the resolver is still on epoch N, and asserts the produced block carries `signature.epoch = N`, not `N+1`.
