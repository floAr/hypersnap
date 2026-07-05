# PoC — ONBD-4: rotate-then-replay mints unbounded FIDs from one PoW

**Finding:** [ONBD-4](../../../findings/native-onboard/ONBD-4-rotate-then-replay-mints-unbounded-fids-one-pow.md) (Medium–High) · commit `573d671`.

**Polarity:** red property test — it asserts the *secure* property (a post-rotation replay is rejected) and therefore **FAILS on the buggy `573d671` code**, flipping green once a consumed-PoW / ever-onboarded marker is enforced.

## What it proves

Onboarding carries no per-message nonce and no consumed-PoW marker; its only
anti-replay guard is `lookup_custody_fid(custody) == None`
(`native_onboard.rs:535`). `apply_custody_rotation` **deletes** that entry
(`native_onboard.rs:777`). So a custody can: onboard once (one PoW) → rotate the
FID to a fresh address (freeing its own custody index) → replay the identical,
still-valid onboarding body for another FID — indefinitely, amortizing a single
PoW across unbounded FIDs within the 1024-block anchor window.

## Result (build-verified, RED)

```
ONBD-4: rotate-then-replay minted a second FID Ok(9223372036854775809)
from a single POW solve (custody freed by rotation; no consumed-POW marker)
```

`9223372036854775809 == HYPER_FID_BASE + 1` (1<<63 + 1) — the second FID minted
from the same PoW after one rotation. Full transcript:
[test-output.txt](test-output.txt). Test source:
[onbd4_rotate_replay_test.rs](onbd4_rotate_replay_test.rs) (drop into
`mod tests` in `src/hyper/native_onboard.rs`).

## How to run

```bash
cd ~/hs-573d671
RUSTFLAGS="--cap-lints allow" \
  cargo test -p hypersnap --lib -- \
  onbd4_rotate_then_replay_must_not_mint_second_fid --nocapture --test-threads=1
```
(`--cap-lints allow` dodges an unrelated `ed448-bulletproofs` lint-pass ICE in
rustc 1.95; the `malachite` path-dep sibling must be staged at `../../malachite`.)

## Expected after the fix

Add a permanent, rotation-immune marker on successful onboarding
(`HyperNativeCustodyEverOnboarded[custody]` or a spent-PoW key
`PowSpent[H(custody‖anchor_hash‖nonce)]`) to the atomic batch and check it in
`apply_onboarding`. The replay is then rejected and the test passes.
