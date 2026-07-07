# ONBD-10 — mirror-resurrection / rotation-revocation-bypass · RED PoC

Build-verified red property PoC for [ONBD-10](../../../findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md) (High), demonstrated on fix commit `ab73681`.

## What it proves

Property that *should* hold: **custody rotation is revocation** — after custody A rotates its FID to custody B, A must stay unbound (`lookup_custody_fid(A) == None`). On `ab73681` this **FAILS**: replaying A's onboard body drives `sync_onboarding_mirror_from_tree`, which copies the never-cleared verkle `custody[A]=X` binding straight back over the mirror (rotation only mutates the RocksDB mirror, never the tree). The `ever` marker correctly blocks a 2nd FID mint (ONBD-4), but does not stop the mirror resurrection — re-enabling revoked key A to pass the rotation `held_by_current` check and re-capture the FID.

## Placement / run

`onbd_native_pocs.rs` contains a shared `onbd_revalidation_setup()` helper plus **two** tests; add the whole block to `mod tests` in `src/hyper/native_onboard.rs` (it reuses that module's `make_db`, `solve_pow`, `build_typed_data`, `build_rotation`, `PrivateKeySigner`/`B256`/`SignerSync`). The red test here is `onboard_replay_must_not_resurrect_rotated_away_custody_binding`; the companion `onbd4_rotate_then_replay_via_tree_mints_no_second_fid` is the ONBD-4 green test (shared file — see the sibling ONBD-4 bundle).

```
cd <hypersnap>   # WSL, malachite sibling staged (see audit notes)
RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib \
  onboard_replay_must_not_resurrect_rotated_away_custody_binding -- --nocapture
```

## Verbatim result on `ab73681` (see `test-output.txt`)

```
assertion `left == right` failed: REGRESSION: onboard replay resurrected rotated-away
custody A -> fid 9223372036854775808 (mirror sync copied the never-cleared verkle
binding back), defeating rotation-based revocation
  left: Some(9223372036854775808)   # 2^63 = HYPER_FID_BASE
 right: None
test ... FAILED
```

Correct red→green polarity: the assertion passes once custody rotation is folded into the on-root verkle tree (or `sync_onboarding_mirror_from_tree` skips rotated custodies).
