# ONBD-15 — rotation re-validation runs a PoW-free ecrecover per message before the block threshold-signature check

- **Severity:** Low (CPU-only DoS; a minor new instance of a pre-existing ordering class)
- **Status:** OPEN (new at `f4fc4af`; **not** a merge blocker)
- **Component:** `src/hyper/runtime.rs`, `src/hyper/importer.rs`, `src/hyper/native_onboard.rs`
- **Introduced by:** the `f4fc4af` rotation-in-tree fix adds a rotation re-validation loop to
  `import_block`; the underlying "re-validate messages before verifying the block signature"
  ordering is pre-existing (onboards and transfers already do it).
- **Corroboration:** mempool/DoS lane; build-verified; ordering independently re-confirmed against source.

## Summary

`import_block` re-validates every message before applying, as a malicious-proposer defense. The
order is: rotation loop (`runtime.rs:4862-4869`) → onboard loop (`runtime.rs:4880-4892`) → transfer
loop (`runtime.rs:4906-4948`) → `import_hyper_block_with_index` → `import_hyper_block`, where the
**block's threshold signature is finally verified** (`importer.rs:270`). So all per-message
re-validation, including the rotation ecrecover, runs **before** the block is authenticated. The
inbound-block path reaches this from any gossip peer: `gossip_adapter::wire_to_event` builds
`InboundBlock` verbatim from the wire, and the actor calls `runtime.import_block` directly
(`actor.rs:1400`) — no signature or size pre-check.

`validate_custody_rotation` (`native_onboard.rs:790-837`) is **state-independent**: it only requires
the EIP-712 signature to recover to `current_custody`, a value the attacker chooses and self-signs
with a fresh key that holds no FID. So an unauthenticated peer's bogus (unsigned) block packed with
rotations forces one secp256k1 recovery per rotation before it is rejected.

## Impact / why Low

- **CPU only.** The block is ultimately rejected on the signature check — no state change, no fork,
  no halt.
- **A minor new instance, not a new class.** The **transfer** re-validation loop already runs in the
  same pre-signature position (`runtime.rs:4906`) and is *more* expensive per message
  (Pedersen/range-proof verification ≫ one ecrecover) and equally PoW-free. The rotation ecrecover
  is cheaper than the DoS surface that already exists there.
- Amplification is capped by the gossip frame size and libp2p peer scoring.

**Where it is genuinely worse than ONBD-6:** onboarding verifies PoW *before* its ecrecover
(`native_onboard.rs:537`), so an onboard flood costs the attacker one PoW solution per message.
Rotation validation has no PoW and no cheap state gate before the recovery, so producing N valid-looking
rotations costs only N keygen+sign — free. The same ordering also affects the **submit** path:
`validate_custody_rotation` (ecrecover) at `runtime.rs:4117` runs before the cheap
`read_onboard_custody_fid(tree, current)` precheck at `runtime.rs:4124`.

## PoC (build-verified, green — characterizes the cost)

`poc_q5_rotation_validate_is_not_fid_bounded` (native_onboard.rs) mints 64 rotations from 64 distinct
fresh keys that hold no FID, all passing `validate_custody_rotation` (each = one recovery) — proving
the import-side cost is **not** bounded by attacker FID ownership.

## Fix direction

Verify the block threshold signature (and enforce a message-count ceiling) **before** any per-message
re-validation in `import_block` — this closes the whole pre-signature re-validation DoS class
(rotations, onboards, transfers) at once. On the submit path, do the cheap `current-holds-fid` tree
lookup before the ecrecover so the recovery is FID-bounded.

## Key locations

`runtime.rs:4862-4869` (rotation ecrecover loop) · `runtime.rs:4906` (pre-existing transfer loop,
same position) · `importer.rs:270` (block signature verified — after the loops) · `actor.rs:1400`
(peer block import, no pre-check) · `native_onboard.rs:790-837` (state-independent rotation validate) ·
`native_onboard.rs:537` (onboarding PoW-before-ecrecover, the ONBD-6 comparison).
