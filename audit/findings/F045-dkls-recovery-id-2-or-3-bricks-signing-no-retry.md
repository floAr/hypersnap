---
id: F045
task: H045
attack_class: ecdsa-recovery-id-handling
severity: low
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.90
  hypotheses_walked: 8
  validated_at: 2026-05-20T15:43:12Z
---

# F045 — DKLS `recovery_id ∈ {2,3}` aborts the ceremony with no re-run path; same `(digest, committee)` is permanently un-signable for that epoch

- **Task:** H045
- **Attack class:** ecdsa-recovery-id-handling
- **Severity (provisional):** Low (probability ~2^{-128} per ceremony per attempt is astronomical; recorded for completeness because the protocol design explicitly anticipated this case but the wiring is incomplete and adjacent paths give it teeth — see F040)
- **Status:** draft

## Scope files

- `code/hypersnap/crates/hypersnap-crypto/src/ecdsa.rs`
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_sign.rs`
- `code/hypersnap/crates/hypersnap-crypto/src/dkls_threshold.rs`
- `code/hypersnap/crates/dkls23/src/protocols/signing.rs` (vendored)
- `code/hypersnap/src/hyper/dkls_sign_driver.rs`
- `code/hypersnap/src/hyper/actor.rs` (`AdvanceDklsSign` handler)
- `code/hypersnap/src/hyper/dkls_supervisor.rs` (interaction with F040)

## Summary

DKLS23's `Party::sign_phase4` returns a recovery id in `{0, 1, 2, 3}`,
where values 2 and 3 indicate the signature point's x-coordinate
`R.x ≥ n` (the curve order). For secp256k1 this happens with
probability `≈ (p − n) / p ≈ 2^{-128}` per ceremony, but it is a
defined output of the protocol. The Hypersnap stack correctly **does
not** smuggle `recovery_id ∈ {2,3}` into an Ethereum `v` byte (which
would yield `v=29/30` and be rejected by the precompile / OZ
`ECDSA.recover`). Instead **both** production paths reject the case
with a `DklsError::Abort`:

- `dkls_threshold.rs:434-441` (`run_honest_sign`, used by the
  in-process 1-of-1 device path and tests).
- `dkls_sign.rs:379-386` (`DklsSignCoordinator::try_advance_phase3_to_complete`,
  used by the multi-party network ceremony).

That is the right floor. The gap is what happens **next**: there is
no re-run path. When the `(digest, committee, freshly-sampled nonces)`
triple lands in the "R.x ≥ n" gap, the actor's `AdvanceDklsSign`
handler propagates the `DklsError::Abort` upward, the active driver
is dropped, and no new ceremony for the same digest is queued. The
supervisor (per F040) does not re-fire ceremonies within an epoch on
abort. The deterministic outcome is: that specific `(digest, epoch
group key)` is **never signed**, even though resampling fresh phase-1
nonces would (with overwhelming probability) yield `recovery_id ∈ {0,1}`
on the next attempt.

Whether this matters in practice depends entirely on what the digest
is bound to. For one-shot bridge action signatures (`MERKLE_ROOT_UPDATE_V1`,
`ROTATE_OWNER_V1`, etc.) the producer can pick a different digest
(bump nonce / lockId / etc.) and try again, so the worst case is a
transient single-ceremony failure. For digests pinned to consensus
state (a specific hyperblock header at a specific height — see
`finalize_dkls_signature` in `actor.rs:1338`), the **digest is not
free to change**: that exact header at that exact height is the one
needing a signature. With no retry path, the hyperblock cannot be
finalized at all until a new epoch installs a new group key, by
which point F040's "no in-epoch retry" lock-in compounds the problem.

## Walkthrough

### Producer-side recovery_id derivation (vendored DKLS23)

`code/hypersnap/crates/dkls23/src/protocols/signing.rs:695-714`:

```rust
// Now the recovery id can be calculated using the following conditions:
// - If R.y is even and R.x is less than the curve order n: recovery_id = 0
// - If R.y is odd and R.x is less than the curve order n: recovery_id = 1
// - If R.y is even and R.x is greater than the curve order n: recovery_id = 2
// - If R.y is odd and R.x is greater than the curve order n: recovery_id = 3
//
// For 256-bit curves, x >= n is extremely rare (probability ~ 2^-128 for secp256k1).
// We compute it generically: compare the x-coordinate (as U256) against the scalar
// field order (derived from -1 in the scalar field + 1).
let neg_one = -C::Scalar::ONE;
let neg_one_bytes = neg_one.to_repr();
let order_minus_one = U256::from_be_slice(neg_one_bytes.as_ref());

let x_bytes = signature_point.x();
let x_as_u256 = U256::from_be_slice(x_bytes.as_slice());
let is_x_reduced = x_as_u256 > order_minus_one;
let is_y_odd: bool = signature_point.y_is_odd().into();
let recovery_id: u8 = u8::from(is_y_odd) | (u8::from(is_x_reduced) << 1);
```

The `is_x_reduced` bit feeds bit 1 of `recovery_id`, so values 2 and 3
correspond to `R.x ≥ n`.

### Both Hypersnap sign paths reject 2/3 with Abort

`dkls_threshold.rs:430-441` (`run_honest_sign`):

```rust
// Recovery id 2/3 only fires when R.x ≥ curve order, which has
// probability ~2^-128 on secp256k1 — we surface it as an error
// rather than silently mapping to 0/1, since the bridge contract
// (and our `EcdsaSignature::from_rsv`) only accept 0/1.
if recovery_id > 1 {
    return Err(DklsError::Abort {
        party: 0,
        reason: format!(
            "DKLS23 produced recovery_id={recovery_id} (R.x ≥ curve order); not Ethereum-compatible"
        ),
    });
}
```

`dkls_sign.rs:379-386` (`DklsSignCoordinator::try_advance_phase3_to_complete`):

```rust
if recovery_id > 1 {
    return Err(DklsError::Abort {
        party: 0,
        reason: format!(
            "DKLS23 produced recovery_id={recovery_id} (R.x ≥ curve order); not Ethereum-compatible"
        ),
    });
}
```

The wrapper `EcdsaSignature::from_rsv` (`ecdsa.rs:75-85`) only accepts
`v ∈ {0, 1, 27, 28}` and would reject anything outside, so the abort
correctly prevents `v=29/30` from being emitted on-wire. Good defensive
floor; no silent contract violation.

### Where the re-run is supposed to happen — and doesn't

The persona checklist for `ecdsa-recovery-id-handling` calls out two
forks: "does the Rust wrapper handle recovery_id ∈ {2,3} (re-run path
to MPC), or does it silently use `v + 27 = 29 or 30`?". Hypersnap is
on the third branch: aborts cleanly but **never re-runs**.

`actor.rs:1325-1343`:

```rust
HyperActorEvent::AdvanceDklsSign => {
    let Some(mut driver) = self.active_dkls_sign.take() else {
        return Ok(());
    };
    driver.try_advance()?;            // <-- recovery_id-2/3 abort bubbles here
    self.flush_dkls_sign_outbound(&mut driver).await;
    if driver.is_completed() {
        let signature = driver
            .signature()
            .expect("is_completed() ⇒ signature present")
            .clone();
        let digest = *driver.coordinator.digest();
        let epoch = driver.epoch();
        self.finalize_dkls_signature(epoch, digest, signature).await;
    } else {
        self.active_dkls_sign = Some(driver);
    }
    Ok(())
}
```

Two issues compound:

1. `take()` on line 1326 unconditionally pulls the driver out of
   `self.active_dkls_sign`. The `?` on line 1329 then propagates the
   `DklsError::Abort` upward via `From<DklsSignDriverError>` (declared
   `#[from]` at `actor.rs:615`). The driver is **gone** — no
   re-insertion, no error-state handling that would respawn a fresh
   coordinator for the same digest with new phase-1 randomness.
2. The coordinator state mutation in `try_advance_phase3_to_complete`
   has already consumed `own_unique_2to3` (via `.take()` on line 338
   in dkls_sign.rs's phase 2→3 transition) — so even if the driver
   were retained, the existing coordinator cannot replay the protocol.
   A fresh `DklsSignCoordinator::new(...)` over the same digest is
   the only valid recovery, and nothing constructs it.

### Phase-1 nonces are fresh per ceremony

`code/hypersnap/crates/dkls23/src/protocols/signing.rs:199-201`
(`sign_phase1`):

```rust
let instance_key = C::Scalar::random(rng::get_rng());
let inversion_mask = C::Scalar::random(rng::get_rng());
```

So a re-run **with a fresh `DklsSignCoordinator::new`** would
resample `k` and yield a different `R = k·G`, almost certainly with
`R.x < n` (probability `≈ 1 − 2^{-128}`). The re-run is exactly what
the protocol prescribes; the integration layer simply doesn't wire it.

### Interaction with F040 (supervisor never re-fires)

F040 documents that `dkls_supervisor.rs` latches `last_started_for_epoch`
on dispatch, not on completion, so it does not re-fire `StartDkls` /
`StartDklsSign` within an epoch on abort. The combination:

- Phase-4 returns `recovery_id ∈ {2,3}` → `try_advance` returns
  `Err(DklsError::Abort)`.
- Actor drops the driver, propagates the error to the actor's main
  loop (where it gets logged and the actor continues running but the
  driver is gone).
- No supervisor-side retry within the epoch.
- The digest in question is permanently unsignable until next epoch.

For hyperblock signing, where the digest binds `(epoch, height,
header_hash)` and the block must be finalized in-epoch to maintain
liveness, this is the hard failure mode F040 already warned about,
with an additional astronomically-rare trigger.

## Impact

- **Realistic likelihood:** Negligible. The ~2^{-128} per-attempt
  probability means that even at 10^6 ceremonies/year per validator
  set, the expected wait for a single 2/3 event is ~3×10^31 years.
  This is not a finding because the bug fires; it's a finding because
  the protocol's documented re-run path is missing and so adjacent
  hardening (F040) is one degree weaker than it should be.
- **Defensive completeness:** The persona checklist for this attack
  class lists "re-run path to MPC" as the canonical handling for
  `recovery_id ∈ {2,3}`. Hypersnap correctly rejects but does not
  re-run. The producer-side reject without retry is approximately a
  "fail-stop on a 2^{-128} event"; given that the abort message
  fires from the actor's main `handle_event`, it bubbles up alongside
  every other operational abort and there's no observability hook
  that would let operators distinguish "we hit the lottery" from "the
  ceremony failed for a normal reason".
- **Cross-side correctness:** Verifier (`HypersnapBridge.sol` OZ
  `ECDSA.recover`, `EcdsaSignature::recover_address`) is not at risk —
  no value of `v ∉ {27,28}` is ever produced by the Hypersnap signer.
  This is purely a producer-side liveness gap, not a soundness or
  cross-side asymmetry gap.

## Recommended fix

**Option A (minimal):** When `try_advance_phase3_to_complete` would
return `Err(DklsError::Abort{reason: "...recovery_id...not
Ethereum-compatible"})`, replace it with a dedicated
`DklsError::RecoveryIdOutOfRange { recovery_id }` variant. In
`actor.rs::AdvanceDklsSign`, special-case this variant: respawn a
fresh `DklsSignCoordinator` for the same `(digest, committee,
epoch_party)` and re-issue the phase-1 transmits. The committee will
likewise hit the abort and respawn; if everyone uses fresh randomness,
the second ceremony succeeds w.p. `1 − 2^{-128}`. Bound the retry
count at e.g. 3 (probability of three consecutive hits is `2^{-384}`,
i.e. zero in practice; if it does, alert hard).

**Option B (cheaper, accepts the rare outage):** Document the
behavior explicitly — note in `dkls_sign.rs` and the bridge-payload
docs that a `recovery_id ∈ {2,3}` event results in a one-ceremony
outage that the *application layer* must recover from by selecting a
new digest (where applicable) and re-submitting. For hyperblock
signing, which can't pick a new digest, document the dependency on
the supervisor / F040 fix to re-fire `StartDklsSign` within the same
epoch.

**Adjacent hygiene:**

- Add an integration test that synthetically forces `recovery_id ∈
  {2,3}` (e.g., by intercepting `sign_phase4` and returning a forged
  result) and asserts the system either respawns the ceremony (Option
  A) or surfaces a distinguishable, alertable error (Option B).
- Add a metric `hyper.dkls.sign.recovery_id_out_of_range_total` so an
  operator can detect the (vanishingly rare) event versus other
  aborts.

## Affected attack-class checklist items

- `ecdsa-recovery-id-handling`: producer rejects `recovery_id ∈ {2,3}`
  correctly (no silent v=29/30 emission), but lacks the protocol-
  prescribed re-run path; combined with F040 the system has no
  liveness recovery on this branch within the epoch. Probability of
  trigger ≈ 2^{-128} per ceremony — informational/defensive, not
  exploitable in practice.

## Cross-references

- **F040** — `dkls-supervisor-no-retry-after-ceremony-abort`: the
  supervisor-side latch that turns any in-epoch ceremony abort
  (including this one) into a permanent epoch-level outage.
- **F044** — `ecdsa-low-s-not-enforced-at-construction`: the sibling
  cross-side malleability finding. Together with F045 these document
  the full state of the `EcdsaSignature` wrapper boundary — F044 on
  the `(r,s)` side, F045 on the `v` side. Both involve the same
  `from_rsv` constructor and would benefit from a unified hardening
  pass.
