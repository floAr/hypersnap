# ONBD-4 — rotate-then-replay mints no 2nd FID (in-tree path) · GREEN PoC

Build-verified green fix-confirmation for [ONBD-4](../../../findings/native-onboard/ONBD-4-rotate-then-replay-mints-unbounded-fids-one-pow.md) on fix commit `ab73681`.

## Why a rewrite

The `573d671`-era ONBD-4 PoC drove `apply_onboarding` — the RocksDB assignment path that, at `ab73681`, has **no production caller** (tests only) and never received the `ever` marker. Running the old PoC would exercise dead code and misrepresent the fix. This rewrite exercises the **real** production path `builder::apply_onboard_to_tree` (the in-tree sequence + permanent `ever` marker).

## Property

Rotate-then-replay must **not** mint a second FID from a single PoW solve. The permanent in-tree `ever` marker makes the replay a no-op → the property holds on `ab73681`.

## Placement / run

Same `onbd_native_pocs.rs` block as the ONBD-10 bundle (shared helper + two tests) added to `mod tests` in `src/hyper/native_onboard.rs`.

```
RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib \
  onbd4_rotate_then_replay_via_tree_mints_no_second_fid -- --nocapture
```

## Verbatim result on `ab73681` (see `test-output.txt`)

```
test onbd4_rotate_then_replay_via_tree_mints_no_second_fid ... ok
test result: ok. 1 passed; 0 failed; ...
```

Note: this confirms the FID-*count* fix only. The same replay still resurrects the custody→FID mirror binding — a distinct High regression, [ONBD-10](../../../findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md) (red PoC in the sibling bundle).
