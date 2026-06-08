---
id: F070
specialist: chain-economics
attack_class: registration-custody-sig-gating
title: Validator-registration custody-signature gate is never wired into the production ingestion path — the router is built without a CustodyResolver, so the lenient validate_event branch runs and the EIP-712 custody cross-sign is never checked, letting an attacker register arbitrary validator keys under any FID
severity_initial: high
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/validator_registry.rs
  - code/hypersnap/src/hyper/router.rs
  - code/hypersnap/src/hyper/runtime.rs
  - code/hypersnap/src/hyper/actor.rs
  - code/hypersnap/src/hyper/importer.rs
  - code/hypersnap/src/hyper/config.rs
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.9
  hypotheses_walked: 8
  validated_at: 2026-06-08T13:37:04Z
---

## Summary

`validator_registry.rs` implements a correct, well-tested EIP-712 custody
cross-signature gate (`verify_custody_signature`, required by
`validate_and_check_quota` / `validate_register_with_trust`) intended to
ensure a validator slot can only be registered/rotated with the
authorization of the FID's on-chain custody key. **That gate is never
reached in production.** Every inbound validator event flows through
`HyperRuntime::submit_message`, which constructs the `HyperRouter`
**without** calling `with_custody_resolver(...)`. With `custody_resolver ==
None`, `HyperRouter::route_inbound` takes the lenient branch
`ValidatorRegistry::validate_event(&event, epoch, None)`, which skips
custody-signature verification entirely (it only verifies a custody sig when
a custody address is supplied). The strict `validate_and_check_quota` path —
the only one that resolves a custody address and enforces the cross-sign and
the per-FID 3-cap — is dead code in production.

Net effect: an attacker can register an arbitrary, self-generated
validator key bound to **any FID they choose** (including a victim's FID, or
many sybil FIDs) using only a self-signed Ed25519 signature and **no valid
custody signature at all**. The only remaining barrier is an optional trust
floor that is disabled (`0.0`) by default.

## Where the gate is, and why it never runs

### The gate exists and is correct

`validate_and_check_quota` (`validator_registry.rs:421`) resolves the FID's
custody address via the `CustodyResolver`, requires a custody signature on
Register (`MissingCustodySignature`, line 436-438), and verifies it through
`validate_event(event, epoch, Some(&custody))` → `verify_custody_signature`
(line 268). All the tests (`cross_signed_register_passes_strict_validation`,
`register_with_wrong_custody_address_rejected`,
`register_without_custody_signature_strict_rejected`, …) exercise this
strict path directly and pass.

### The lenient path skips the custody check

`validate_event` (`validator_registry.rs:367`) takes
`custody_address: Option<&[u8;20]>`. With `None`:

```rust
let has_ed25519 = !event.signature.is_empty();
let has_custody = !event.custody_signature.is_empty();
if !has_ed25519 && !has_custody { return Err(MissingSignature); }
if has_ed25519 { verify_event_signature(event)?; }
if has_custody {
    let addr = custody_address.ok_or(CustodyAddressUnknown{...})?;  // only if Some
    verify_custody_signature(event, addr)?;
}
```

When `custody_address` is `None`, the custody signature is only checked if
the attacker *chooses to include one* — and they simply omit it. A register
event with a valid self-signed Ed25519 sig and an empty `custody_signature`
passes `validate_event(.., None)` unconditionally. `fid` is an
attacker-controlled field on the event; no proof of control over that FID's
custody key is required.

### Production never supplies a resolver

`router.rs:165-168`:

```rust
match self.custody_resolver.as_deref() {
    Some(r) => registry.validate_and_check_quota(&event, self.current_epoch, r)?,
    None    => ValidatorRegistry::validate_event(&event, self.current_epoch, None)?,
}
registry.record_event(&event)?;
```

`with_custody_resolver` (`router.rs:115`) is **never called anywhere** in
the codebase (only defined). The single production router construction site,
`runtime.rs:3882`:

```rust
let mut router = HyperRouter::new(
    std::mem::take(&mut self.mempool),
    Some(self.validator_registry.clone()),
    self.epoch_resolver.current_epoch(),
);   // no .with_custody_resolver(...)
```

So `custody_resolver` is `None` → lenient branch → custody sig skipped →
`record_event` persists the registration and its
`HyperValidatorFidLookup[vk] → fid` binding.

### Both ingestion points are affected

- Gossip + local submit: `actor.rs:1218` / `actor.rs:1230`
  (`HyperActorEvent::InboundMessage` / `LocalSubmitMessage`) both call
  `self.runtime.submit_message(msg)` → the unwired router above.
- The alternative `importer::apply_validator_events` (`importer.rs:65`),
  which *also* supports a strict resolver, is **never called** anywhere in
  the tree (dead code), so it provides no compensating enforcement.

The only pre-router gate in `submit_message` (`runtime.rs:3855-3878`) is the
**trust-score floor**, and it is `if self.min_validator_trust_score > 0.0`.
The default is `0.0` (`config.rs:526`, and every non-test runtime config),
so by default even that gate is off; when enabled it only checks the claimed
FID's trust score, never custody authorization.

The metric label set in `observe_routing_rejection`
(`actor.rs:1953-1955`: `invalid_custody_sig`, `missing_custody_sig`,
`custody_address_unknown`) shows the design *intended* custody enforcement
on this path; those counters can never increment from registration because
the strict branch is never taken.

## Impact

Authorization for the entire validator set collapses to "holds a freshly
generated Ed25519 key + names an FID":

- **Validator-slot hijacking / impersonation.** Register a validator key
  under a *victim's* FID with no custody signature. The
  `HyperValidatorFidLookup[vk] → fid` binding (written by
  `record_event`) now attributes attacker-controlled validator activity to
  the victim's FID. Downstream consumers trust this binding as ground truth
  — e.g. DA-PoW response admission (`runtime.rs:3292-3307`) checks
  `fid_for_validator_key(validator_pubkey) == body.fid`, which the attacker
  forged.
- **Active-set dilution / capture.** `compute_active_set`
  (`validator_registry.rs:674`) replays every persisted Register/Deregister
  event regardless of how it was validated. An attacker registers unbounded
  cheap validator keys (the per-FID 3-cap lives only in the dead strict
  path, and the attacker can name arbitrary FIDs anyway) to flood the active
  set. This directly feeds DKLS committee selection, hyperblock proposer
  selection, and quorum math — the attacker can dilute or majority the
  active set.
- **Amplifies F025.** F025 (committee-index grinding) explicitly assumed the
  EIP-712 custody cross-sign was enforced and that sybils needed to control
  their own FIDs' custody keys. With this gap, no custody key is needed at
  all and the per-FID cap does not bind, making the grind strictly cheaper
  and registration under arbitrary FIDs unrestricted. This is nonetheless a
  distinct root cause (missing wiring vs. grindable index map).

## Severity: High

Registration authorization is the trust anchor for the whole validator
subsystem (committee selection, proposer set, DA-PoW attribution, quorum).
The custody gate that is supposed to enforce it is implemented but
unreachable on every production ingestion path, and the only fallback gate
is disabled by default. Exploitation requires only crafting a normal
validator-event gossip message with a self-signed Ed25519 sig and an empty
custody signature. Not direct fund-loss, but it is silent, total bypass of
validator-registration authorization — consistent with the high-severity
incentive/authorization-distortion class for this domain.

## Suggested direction (non-binding)

Wire a `StoreBackedCustodyResolver` into the production router at
`runtime.rs:3882` via `.with_custody_resolver(...)` (mirroring how
`apply_miniapp_register` already builds one at `runtime.rs:2597`), so
`route_inbound` takes the `validate_and_check_quota` /
`validate_register_with_trust` branch. Alternatively make the lenient
`None`-resolver branch unreachable in production by requiring a resolver at
router construction for any non-test runtime. Consider also asserting that
Register events with an empty `custody_signature` are rejected
unconditionally outside explicitly-flagged migration/test contexts.

## Notes / residual uncertainty

- `with_custody_resolver` and `importer::apply_validator_events` both exist
  and are correct; the defect is purely that neither is invoked on a live
  path. Confirmed by full-tree grep: the only callers of
  `with_custody_resolver` and `apply_validator_events` are their own
  definitions/tests.
- If a deployment sets `min_validator_trust_score > 0.0`, the trust floor
  raises the bar (attacker must name an FID whose trust ≥ floor) but still
  does not establish custody authorization — slot hijacking of any
  sufficiently-trusted FID, and sybil registration under any such FID,
  remain possible.
- `compute_active_set` / `record_event` themselves are sound; they faithfully
  apply whatever passed validation. The defect is upstream at the validation
  wiring.
