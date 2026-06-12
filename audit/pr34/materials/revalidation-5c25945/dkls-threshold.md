# Revalidation — DKLS / threshold-signing / DKG buffer subsystem

- Audited commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- Fix commit: `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child)
- Reviewer: rust-threshold-signing specialist
- Date: 2026-06-12

## Summary table

| ID   | Verdict          | Confidence | One-line reason |
|------|------------------|-----------|-----------------|
| F028 | FIXED            | 0.95      | Threshold now derived as `floor(2n/3)+1` in `build_driver`; static `inputs.threshold` ignored for `share_count>1`; written into `Parameters`/`session_id`/installed share. |
| F025 | FIXED            | 0.80      | Party-index map replaced with keccak permutation over `(epoch, set_hash, validator_key)`; applied consistently in supervisor + `peer_id_for_party` + transport lookup. Matches the finding's recommended fix (residual: no unpredictable beacon — still a hard grind, by design). |
| F024 | FIXED            | 0.95      | Buffer now stores `propagation_source`; drain runs `check_dkls_sender_against_propagation_source` before `driver.submit`, mirroring the live path. |
| F016 | FIXED            | 0.9       | Global `PENDING_DKLS_INBOUND_EPOCH_CAP = 16` with eldest-epoch eviction added; BTreeMap can no longer grow unboundedly. |
| F018 | PARTIALLY_FIXED  | 0.85      | Keystore now pruned each epoch via `prune_retired_dkls_shares` (core leak closed), but no Zeroize/Drop on `Party`/`DklsEpochState`, and bridge local-sign helpers + lock-root/owner-rotation apply paths still lack epoch-currency / monotonicity guards. |
| F021 | FIXED            | 0.92      | Registry-miss branch now returns `false` (fail-closed); `None` propagation_source (locally-synthesized) still accepted, which the finding explicitly deemed acceptable. |

---

## F028 — DKLS threshold hard-pinned to 1 (Critical) — FIXED (0.95)

The static `dkls_threshold = 1u8` still exists at `src/main.rs:1606`, but it is now
dead for production: a comment documents that it is consulted only on the
single-validator devnet path. `build_driver` no longer plugs it into the DKG
parameters. Instead a new `bft_safe_threshold(share_count)` derives the
reconstruction threshold from the real active-set size.

`src/hyper/dkls_supervisor.rs:77`:
```rust
pub fn bft_safe_threshold(share_count: u8) -> u8 {
    let n = share_count as u16;
    let t = ((2 * n) / 3) + 1;
    ...
    t as u8
}
```

`src/hyper/dkls_supervisor.rs:250-263`:
```rust
let threshold = bft_safe_threshold(share_count);
if share_count > 1 && threshold < 2 {
    return Err(BuildError::Ceremony(format!(
        "BFT invariant violated: share_count={} but threshold={}", ...)));
}
let parameters = Parameters { threshold, share_count };
```

I confirmed `inputs.threshold` is no longer referenced anywhere in `build_driver`
(grep over the new file: only the field def + doc comments remain). The computed
threshold flows into `Parameters`, is hashed into `canonical_session_id`
(`params.threshold` at line 275), and is persisted in the installed share — so the
sign-time read-back (`share.party.parameters.threshold`) and
`select_signing_committee` inherit the BFT value automatically. For n=4 -> t=3
(tolerates 1), n=7 -> t=5, n=10 -> t=7. A regression test asserts the floor and
the `t>=2` invariant for n in 2..=200.

Adversarial note: for n=2,3 the formula yields t==n (unanimity, 0 fault
tolerance), which still closes the "single validator controls the key" vuln. No
production path can produce a 1-of-N key for N>1. Verdict FIXED.

---

## F025 — Committee membership grindable via chosen validator_key (High) — FIXED (0.80)

The pre-fix index->validator map was lexicographic over the active-key BTreeMap,
letting an attacker grind an Ed25519 key into a target sort-slot. The fix replaces
that with `committee_party_order` (`src/hyper/dkls_committee.rs:139`), which sorts
validators by `keccak256("hypersnap-party-index-v1:" || epoch || set_hash ||
validator_key)`, where `set_hash` = keccak over all sorted active keys. This is
exactly the construction the finding recommended (hash-based order bound to the
full set, creating a fixed-point constraint).

Critically, the new ordering is wired into all three index<->validator mapping
sites, so the map is internally consistent:
- `src/hyper/dkls_supervisor.rs:229-237` — `own_idx` assignment uses
  `committee_party_order(target_epoch, active.keys())` instead of `active.keys().enumerate()`.
- `src/hyper/runtime.rs:1237` — transport-pubkey resolution uses the same order.
- `src/hyper/runtime.rs:1271` — `peer_id_for_party` uses the same order.

Residual (why 0.80, not higher): the permutation seed still depends only on
`epoch` and the active-set membership — both predictable far ahead; there is no
unpredictable per-epoch beacon (VRF/randao). An attacker can still brute-force
candidate keys K and recompute the full ordering per trial to try to land K on a
winning committee index. The finding's own suggested fix acknowledges this is
"materially harder" (keccak-preimage grind where every other validator's rank also
shifts per trial) rather than impossible. The implemented fix matches the
recommended remediation, so I rate it FIXED, but the residual grind surface should
be noted: a beacon-bound assignment would fully eliminate pre-computation.

---

## F024 — Buffered DKG drain skips sender authentication (High) — FIXED (0.95)

The buffer type changed from `Vec<Vec<u8>>` to `Vec<BufferedDklsFrame>`, where
`BufferedDklsFrame { encoded, propagation_source }` (`src/hyper/actor.rs:1062`)
now carries the authenticated libp2p originator alongside the bytes. The
`InboundDkls` buffering arm pushes `propagation_source` (`actor.rs:1389-1391`),
and the `StartDkls` drain loop now runs the F018 check before submit:

`src/hyper/actor.rs:1507-1514`:
```rust
if !self.check_dkls_sender_against_propagation_source(
    target, m.sender(), frame.propagation_source.as_deref(),
) { continue; }
if let Err(e) = driver.submit(m) { ... }
```

I enumerated all `driver.submit` call sites in the new actor.rs: live DKG (1441),
buffered drain (1514), sign path (1603) — each is now immediately preceded by
`check_dkls_sender_against_propagation_source` (1429, 1507, 1591). There is exactly
one buffer and one drain. The documented spoofing window (inject broadcast frames
with `sender = victim` before StartDkls) is closed end-to-end. Verdict FIXED.

---

## F016 — Unbounded pending_dkls_inbound epoch buffer (DoS) (High) — FIXED (0.9)

A global cap on distinct epoch keys was added:
`PENDING_DKLS_INBOUND_EPOCH_CAP = 16` (`src/hyper/actor.rs:1059`). When a frame
for a NEW epoch arrives and the map is already at the cap, the oldest epoch entry
is evicted (`pop_first`) before insertion:

`src/hyper/actor.rs:1376-1387`:
```rust
if !self.pending_dkls_inbound.contains_key(&target_epoch)
    && self.pending_dkls_inbound.len() >= PENDING_DKLS_INBOUND_EPOCH_CAP
{
    if let Some((stale_epoch, _)) = self.pending_dkls_inbound.pop_first() { warn!... }
}
```

Combined with the pre-existing per-epoch cap of 256, total buffered memory is now
bounded at 16 * 256 frames. The attacker can no longer grow the BTreeMap by
streaming strictly-increasing fake `target_epoch` values. Verdict FIXED.

Minor note (not a defect against the finding): the finding also suggested
range-validating `target_epoch` at ingress and bounding `|encoded|`; the fix
relies on the dual cap instead, which is sufficient to bound memory. Eviction is
lowest-epoch (the finding's recommended "stalest" policy).

---

## F018 — DKLS signer share keystore never pruned at epoch boundary (Medium) — PARTIALLY_FIXED (0.85)

Core leak CLOSED. A new `prune_retired_dkls_shares(retain_epoch_floor)`
(`src/hyper/runtime.rs:217`) removes every `dkls_signers` entry for epochs strictly
below the floor:
```rust
let stale: Vec<u64> = self.dkls_signers.range(..retain_epoch_floor).map(|(e,_)| *e).collect();
for epoch in &stale { self.dkls_signers.remove(epoch); }
```
It is invoked on the production epoch-transition handler `EvaluateEpochDkls`
(`src/hyper/actor.rs:1314-1315`) with `retain_floor = epoch.saturating_sub(1)`, so
the keystore is bounded to ~2 epochs (current + immediately prior grace window)
instead of accumulating for the process lifetime. The insert-only accumulation
that was the heart of the finding is fixed.

Residual gaps (why PARTIALLY_FIXED):

1. No zeroization. The prune comment claims "`Party<Secp256k1>` is responsible for
   zeroizing its own secret material on drop", but this is false: I checked the
   vendored type at `crates/dkls23/src/protocols.rs:32` — `struct Party` has no
   `Zeroize`/`ZeroizeOnDrop`/`Drop` impl, and `DklsEpochState`
   (`src/hyper/runtime.rs:323`) derives only `Clone` with no Drop. Removed shares
   are freed by the default allocator without scrubbing, so secret share bytes
   linger in freed heap pages. The finding's zeroization remediation is unaddressed.

2. Bridge local-sign helpers still take a caller-chosen epoch with no
   currency check: `produce_signed_lock_merkle_root_local` and
   `produce_signed_owner_rotation_local` were not modified (no diff in
   runtime.rs touches them). With the keystore now pruned to ~2 epochs the
   exposure window is much smaller, but within the retained window a non-current
   retained share can still be used.

3. Apply-path monotonicity guards still absent:
   `apply_lock_merkle_root_update` and `apply_owner_rotation` were not given the
   epoch-monotonicity watermark that the trust-snapshot path has (no diff). Again,
   the blast radius is reduced by pruning but the asymmetric guard remains.

Given the core lifecycle-state-leak (unbounded keystore retention) is closed and
the residual items are the secondary/hardening recommendations from a
medium-severity finding, this is PARTIALLY_FIXED rather than FIXED. The most
notable residual is the missing zeroization, made worse by the comment asserting
it happens when it does not.

---

## F021 — DKLS sender-binding fail-open when party has no registered peer-id (Medium) — FIXED (0.92)

The registry-miss branch of `check_dkls_sender_against_propagation_source` was
flipped from fail-open to fail-closed.

`src/hyper/actor.rs:2544-2562` (new):
```rust
let registered = match self.runtime.peer_id_for_party(epoch, claimed_sender) {
    Some(p) => p,
    None => {
        // F021 fix: ... Now fail-closed ...
        tracing::warn!(... "F021: DKLS frame from party with no registered peer-id; dropping ...");
        return false;
    }
};
```

The only remaining permissive branch is `propagation_source == None`
(`actor.rs:2539-2541`, returns `true`), which corresponds to locally-synthesized
frames — the finding explicitly stated this branch "is acceptable; the registry-miss
accept branch for an active party is the hole." That hole is now closed: an active
committee member that registered an empty `libp2p_peer_id` can no longer be spoofed,
because frames claiming it as sender are dropped rather than accepted.

This is applied uniformly on all three submit paths (live, drain, sign) per the
F024 wiring. Operators must now ensure committee members register a non-empty
peer-id or their own legitimate frames will be dropped (a liveness trade-off the
fix consciously accepts). The finding's alternative suggestion (reject empty
peer-id at registration) was not implemented, but fail-closing the check is the
equally-valid remediation the finding offered. Verdict FIXED.
