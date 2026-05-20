---
id: F096
task: H096
specialist: solidity-bridge
attack_class: inbound-burn-finality-or-replay
file_paths:
  - code/hypersnap/src/hyper/inbound_burn.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/http_handler.rs
commit: 6cff47c63791ce50255f64d4a5d3cd2ccf93a5ae
severity_initial: low
status: draft
---

# F096 — `apply_inbound_burn` short-circuits on the `(source_chain_id, burn_id)` nullifier BEFORE signature verification, accepting (and one-hop-broadcasting) unsigned/forged `HyperInboundBurn` messages

- **Attack class:** `inbound-burn-finality-or-replay` (signature-bypass at the apply gate, not at the encoder itself)
- **Scope file:** `C:\Projects\hypersnap-revalidation-v2\code\hypersnap\src\hyper\inbound_burn.rs` (the canonical encoder is correct; the bug is in the consumer in `runtime.rs::apply_inbound_burn`, which is the only entry that runs the verifier built on top of this encoder)
- **Severity (provisional):** **Low** (no fund-loss; no state mutation; bounded gossip impact)
- **Direct fund-loss to attacker?** No — the `Ok(false)` early-return path performs zero state mutation: balance is not credited, the `HyperInboundBurnProcessed` record is not overwritten, no batch is committed.
- **Direct grief / freeze for victim?** No.
- **What does break:** the protocol-layer guarantee that "`submit_message(HyperMessage::InboundBurn) -> Ok` implies the message carried a valid threshold-ECDSA signature over the canonical payload". An attacker with HTTP `POST /messages` access (or peer-relay access on the local node's `LocalSubmitMessage` flow) can have completely-unsigned, fully-attacker-chosen `HyperInboundBurn` protos accepted by the validator and one-hop-broadcast to all gossip peers as a "successfully applied" inbound burn. Peers accept too (same early-return logic) but don't re-broadcast (only `LocalSubmitMessage` broadcasts, `InboundMessage` does not — see `actor.rs:1131-1156`).

## Summary

The signing-payload encoder in `inbound_burn.rs` is itself well-formed: 29-byte unique DST `b"hypersnap-inbound-burn-v1\x00\x00\x00\x00"`, fixed-width fields with no concatenation ambiguity, and binds all five "value-relevant" fields (`epoch`, `source_chain_id`, `burn_id`, `recipient_fid`, `amount`) plus two audit fields (`source_block_number`, `source_tx_hash`). The DST is unique across all DKLS-signed payloads in the codebase (cross-checked against `app_usage_receipt.rs`, `lock_event.rs`, `validator_registry.rs`, etc — no collisions). Cross-chain replay is byte-bound by the `source_chain_id` field. Per-`(source_chain_id, burn_id)` replay is byte-bound by the nullifier set under `RootPrefix::HyperInboundBurnProcessed`.

The bug is **not** in the encoder. It is in `runtime.rs::apply_inbound_burn` — the only function that builds the signing payload from this encoder and calls the verifier. The function checks the replay-nullifier *before* invoking `inbound_burn_signing_payload` + `verify_hyperblock_signature`, with the explicit intent (per the in-source comment) of saving an ECDSA-recover op for already-processed burns. The consequence is that the verifier is **never called** on the `Ok(false)` (already-processed) path, so the attached `ecdsa_signature` bytes can be anything (empty, zeros, malformed, attacker-forged). All five validation predicates in the apply path (`burn_id.len() == 32`, `source_tx_hash.len() == 32`, `recipient_fid > 0`, `amount > 0`, `source_chain_id > 0`) are easy for an attacker to satisfy because they're structural, not cryptographic.

## Where the bug lives

`code/hypersnap/src/hyper/runtime.rs:1086-1098`:

```rust
// Replay-key check before sig verification (cheaper) — already-
// processed burns short-circuit without spending a recover op.
let key = Self::inbound_burn_key(burn.source_chain_id, &burn.burn_id);
if self
    .db
    .get(&key)
    .map_err(crate::core::error::HubError::from)
    .map_err(|e| RuntimeRewardError::Reward(RewardError::from(e)))?
    .is_some()
{
    return Ok(false);
}

let dkls_addr = self
    .dkls_group_address_for_epoch(burn.epoch)
    .ok_or(RuntimeRewardError::UnknownEpoch(burn.epoch))?;
let payload = crate::hyper::inbound_burn::inbound_burn_signing_payload(burn);
// … verify_hyperblock_signature(…)  ← never reached for already-processed burns
```

The encoder + verifier (lines 1100-1111) are reached only on the *first* `(source_chain_id, burn_id)` submission — every subsequent submission with that key skips the verifier entirely.

## End-to-end exploit trace

The `(source_chain_id, burn_id)` nullifier becomes "stale-known" the moment the first legitimate burn for that key has been threshold-signed and applied. The attacker then has a permanent window to submit junk.

1. **Setup.** A legitimate burn `(source_chain_id=10, burn_id=B)` is observed, threshold-signed, and applied. `db[HyperInboundBurnProcessed || 0x0000000A || B]` is now populated.

2. **Attacker constructs forgery.** Empty / garbage signature, attacker-chosen fields that satisfy the structural validators:
   ```rust
   let forged = proto::HyperInboundBurn {
       epoch: 999_999_999,                  // arbitrary
       source_chain_id: 10,                 // real chain
       burn_id: B,                          // real, processed burn_id
       recipient_fid: 7777,                 // any FID
       amount: u64::MAX,                    // anything > 0
       source_block_number: 0,              // arbitrary
       source_tx_hash: vec![0u8; 32],       // 32 bytes (only the length is checked)
       ecdsa_signature: vec![],             // <-- EMPTY
   };
   ```

3. **Submission path.** Attacker `POST /messages` with the prost-encoded forged proto. `http_handler.rs:157-171::submit_message` decodes and sends `HyperActorEvent::LocalSubmitMessage(msg)` to the actor.

4. **Actor handling.** `actor.rs:1141-1156` runs `runtime.submit_message(msg.clone())`. `runtime.rs:3504-3508` matches `Body::InboundBurn(ref burn)` and calls `apply_inbound_burn(burn).map(|_| ())`.

5. **The bypass.** `apply_inbound_burn` walks lines 1059-1085 (structural checks all pass because attacker chose conformant lengths and nonzero scalars), then reaches line 1086-1098 — the replay-key check finds `(10, B)` is already processed and `return Ok(false)`. The signature is never read. The encoder is never invoked.

6. **Submit-success.** `submit_message` returns `Ok(())`. The actor's `LocalSubmitMessage` handler proceeds to `outbound.send(HyperActorOutbound::BroadcastMessage(msg))` at `actor.rs:1151-1154`. The forged unsigned message is broadcast to every gossip peer.

7. **Peer acceptance (one hop).** Each peer receives the forged message as an `InboundMessage` (`actor.rs:1131-1140`). They run `runtime.submit_message`, hit the same nullifier short-circuit, return `Ok(())`. They do **not** re-broadcast (only `LocalSubmitMessage` triggers broadcast), so propagation is bounded to one hop. They do, however, run `observe_validator_event` + `observe_inbound_message_kind`, polluting per-peer metrics with a "successful inbound burn" event sourced from an unsigned forgery.

8. **Persistent state effect:** none. The `Ok(false)` path writes nothing.

## Why the no-state-mutation bound is fragile

Two reasons this is a real bug to fix rather than "harmless cleverness":

1. **The early-return condition is `db.get(&key).is_some()` with no validation that the stored bytes are a valid `HyperInboundBurn` proto.** If a future feature ever changes the value-shape under `RootPrefix::HyperInboundBurnProcessed` (e.g. adds a "challenge window" status enum, or makes the value a tombstone for slashed burns) and forgets to refactor this gate, the bypass could leak into a state-mutating code path.

2. **The bypass produces a false-positive submit-Ok at a protocol contract surface.** Other callers may reasonably treat `submit_message -> Ok` as "this message carried a valid threshold signature" — e.g. the metrics layer at `actor.rs:1132-1133` (`observe_validator_event`, `observe_inbound_message_kind`) and the gossip layer above. Any downstream consumer that audits inbound-burn rates, decides slashing/rewards based on participation, or trusts the rate of accepted messages, is now corruptable by anyone with HTTP access to one validator. With `BridgeBurnStore` already having unbounded-growth and watermark-poisoning gaps (see F095), an attacker can lay down a poisoned watermark + a flood of forged "already-processed" submissions and produce a per-validator metrics blackout.

The composition with F094/F095 isn't required for the bug to exist — but it widens the blast radius of any inbound-burn-related monitoring.

## Reverse-direction check: encoder completeness vs L2 verifier

For completeness of the H096 scope (the encoder), I walked every field the verifier reads:

| Field                  | In payload? | Apply-path uses | Width      | Comment |
|------------------------|-------------|-----------------|------------|---------|
| `epoch`                | yes (8B BE) | `dkls_group_address_for_epoch(burn.epoch)` | 8B fixed | OK |
| `source_chain_id`      | yes (4B BE) | nullifier key + `> 0` check | 4B fixed | OK |
| `burn_id`              | yes (32B)   | nullifier key + length check | 32B fixed | OK |
| `recipient_fid`        | yes (8B BE) | reward credit + `> 0` check | 8B fixed | OK |
| `amount`               | yes (8B BE) | reward credit + `> 0` check | 8B fixed | OK |
| `source_block_number`  | yes (8B BE) | (audit only — stored, not compared) | 8B fixed | OK |
| `source_tx_hash`       | yes (32B)   | length check, stored as audit | 32B fixed | OK |
| `ecdsa_signature`      | NO (correctly excluded — it's the output of signing) | sig-verify input | 65B | OK |

The encoder is **complete** for the verifier's needs. The DST is unique. Cross-chain binding is correct via `source_chain_id`. Cross-contract binding (multiple `HypersnapBridge` deployments on the same chain) is **not** in the payload — the watcher's RPC subscription is to a fixed `bridge_contract_address`, so cross-contract collisions are an operator-misconfig hazard rather than a protocol vulnerability. I am not flagging it.

The `epoch` field is set by the signing validator (`actor.rs:2801-2812`, `runtime.rs:1186-1196`) rather than by the on-chain emit, but the DKLS group address keyed by `burn.epoch` is the trust anchor — a forged epoch with a non-matching group key fails the sig-verify. Cross-validator agreement on `epoch` is required for DKLS to produce a sig at all, so this is correctly bound.

## Order-of-checks dilemma (the hunt task's explicit question)

The hunt task asks: "is the (source_chain_id, burn_id) nullifier checked BEFORE signature verification, or after? Either order has risks."

- **Current order (nullifier first):** saves an ECDSA-recover op on legitimate retries / fan-out, at the cost of accepting unsigned forgeries with a known-replayed key (this finding).
- **Alternative order (sig-verify first):** prevents unsigned forgeries from getting past `submit_message -> Ok`, at the cost of one `ecrecover`-equivalent per retry. ECDSA recover is ~7-15μs on modern hardware — well below the disk-read cost the current order is "saving". The cost argument for the current order is weak.

Recommended: verify the signature first, then check the nullifier. This restores the protocol-layer guarantee that submit-Ok implies sig-valid, and makes the gossip / metrics surfaces robust against the cheap-forgery vector. The legitimate-retry overhead is negligible.

If preserving the current order is strongly preferred (e.g. to harden against an ECDSA-recover DoS at the apply gate), an alternative fix is to keep the nullifier check first but **only return `Ok(false)` if the signature ALSO verifies** — i.e. run both checks and return `Ok(false)` only when both (a) nullifier exists, and (b) sig is valid for the canonical payload. This costs one ECDSA-recover per submission regardless and matches the cost of "sig-first" but preserves the "no-state-mutation on replay" semantics callers may depend on.

## Suggested fix

```rust
pub fn apply_inbound_burn(
    &mut self,
    burn: &proto::HyperInboundBurn,
) -> Result<bool, RuntimeRewardError> {
    // ... structural checks unchanged ...

    let dkls_addr = self
        .dkls_group_address_for_epoch(burn.epoch)
        .ok_or(RuntimeRewardError::UnknownEpoch(burn.epoch))?;
    let payload = crate::hyper::inbound_burn::inbound_burn_signing_payload(burn);
    let expected = crate::hyper::sig_verify::ExpectedGroupKey::ecdsa_only(&dkls_addr);
    crate::hyper::sig_verify::verify_hyperblock_signature(
        &payload,
        &burn.ecdsa_signature,
        &[],
        &expected,
    )
    .map_err(|_| RuntimeRewardError::Reward(RewardError::InvalidSignature))?;

    // Now check the nullifier — unsigned junk has already been rejected.
    let key = Self::inbound_burn_key(burn.source_chain_id, &burn.burn_id);
    if self.db.get(&key).map_err(...).is_some() {
        return Ok(false);
    }

    // ... credit + commit unchanged ...
}
```

This shape also matches `apply_lock_merkle_root_update` and `apply_reward_issuance` (sig-verify first, then per-record state check), so adopting it removes a single asymmetry in the codebase's apply-style.

## Test that would catch this

```rust
#[test]
fn apply_inbound_burn_rejects_unsigned_replay_of_known_key() {
    let (mut rt, _dir) = make_runtime();
    let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).unwrap();
    rt.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

    // Legitimate apply.
    let mut burn = proto::HyperInboundBurn { /* … */ };
    let payload = crate::hyper::inbound_burn::inbound_burn_signing_payload(&burn);
    burn.ecdsa_signature = hypersnap_crypto::dkls_sign::run_local_dkls_sign(
        &dkg.parties[0], alloy_primitives::keccak256(&payload)
    ).unwrap().to_bytes().to_vec();
    rt.apply_inbound_burn(&burn).unwrap();

    // Attacker submits an UNSIGNED message with same (source_chain_id, burn_id)
    // but different recipient_fid / amount.
    let forged = proto::HyperInboundBurn {
        epoch: burn.epoch,
        source_chain_id: burn.source_chain_id,
        burn_id: burn.burn_id.clone(),
        recipient_fid: 9999,
        amount: u64::MAX,
        source_block_number: 0,
        source_tx_hash: vec![0u8; 32],
        ecdsa_signature: vec![],  // empty
    };
    let r = rt.apply_inbound_burn(&forged);
    assert!(r.is_err(), "unsigned forgery with replayed key must be rejected, not silently no-op'd");
}
```

Today the assertion fires — the call returns `Ok(false)`.

## Affected source

- `code/hypersnap/src/hyper/runtime.rs:1086-1098` — the early-return-on-nullifier-before-sig.
- `code/hypersnap/src/hyper/runtime.rs:3503-3509` — the `submit_message` dispatch that maps `Ok(false)` to `Ok(())` for the broadcaster.
- `code/hypersnap/src/hyper/actor.rs:1141-1156` — the `LocalSubmitMessage` handler that broadcasts on submit-Ok.
- `code/hypersnap/src/hyper/http_handler.rs:157-171` — the HTTP entry that turns any external POST into a `LocalSubmitMessage`.
- `code/hypersnap/src/hyper/inbound_burn.rs` — the signing-payload encoder itself, which is **correct** but is bypassed by the consumer's early-return.

## Out-of-scope notes (also walked, no findings)

- DST uniqueness: confirmed against the full `b"hypersnap-"` prefix family across the repo. No collisions.
- Cross-chain replay: `source_chain_id` is byte-bound (4B BE) into the payload.
- Cross-contract replay (same source_chain_id, multiple bridge deployments): bridge contract address is **not** bound in the payload, but the watcher subscribes to a fixed `bridge_contract_address` — operator-misconfig hazard only, not a protocol vulnerability at this layer.
- `epoch` validator-chosen: bound via the DKLS group lookup, so byzantine-epoch values fail sig-verify on legitimate first-apply (the only path that reaches sig-verify under the current bug).
- u64 amount vs uint256 contract amount: watcher rejects `amount > u64::MAX` (silently — see F094/F095 for the watcher's audit gaps). The signing layer correctly uses 8B BE matching the post-watcher u64 representation.
