# ONBD-9/10/11 — rotation-in-tree transition · GREEN fix-confirmation PoC

Build-verified confirmation that the `f4fc4af` fix folds custody rotation into the
on-root verkle tree deterministically, closing [ONBD-9](../../../findings/native-onboard/ONBD-9-rotation-off-root-divergence.md),
[ONBD-10](../../../findings/native-onboard/ONBD-10-onboard-replay-resurrects-rotated-custody.md)
and [ONBD-11](../../../findings/native-onboard/ONBD-11-speculative-produce-tree-pollution-selfhalt.md).

## What it proves

Property that *should* hold after the fix: rotation is a **deterministic, root-covered**
state transition applied in a fixed order at all four consensus paths (producer scratch
clone, proposer self-import, peer import, cold-restart replay).

`onbd_four_way_rotation_apply_order_determinism` asserts, on `f4fc4af`:
1. Identical ordered messages (onboard(A) then rotate A→B, one block) derive a **byte-identical
   root and rotation nonce** across two independent nodes.
2. Post-state: A is tombstoned/unbound (`read_onboard_custody_fid(A) == None`) and B holds the
   FID — i.e. rotation is a genuine on-root revocation (this is what closes ONBD-10; the mirror
   sync now reflects the tombstone instead of resurrecting the binding).
3. A **stale (no-op) rotation** folded into a follow-up block leaves the root unchanged and does
   so identically across nodes.
4. **Order-sensitivity witness:** applying rotations *before* onboards derives a *different* root
   (the rotation no-ops because A is not yet bound, then the onboard binds A and never revokes it).
   This proves the onboards→rotations→transfers order at every one of the four call sites is
   load-bearing, not cosmetic.

The companion `native_onboard` tests (shipped in the fix commit) confirm the ONBD-10 red PoC from
the `ab73681` round is now **green** (`onboard_replay_must_not_resurrect_rotated_away_custody_binding`),
and the ONBD-4 rotate-then-replay guard holds via the in-tree path.

ONBD-11 is confirmed by construction rather than a runtime test: the producer builds against
`scratch_tree = self.tree.clone()` (`runtime.rs:5187`) and `VerkleTree`'s derived `Clone` is a genuine
deep copy (`BTreeMap<u8, Box<VerkleNode>>`, no `Rc`/`Arc`/`RefCell` interior; `srs` is `Arc`-shared and
immutable), so a produced-but-never-finalized block cannot strand FID/seq/ever/nonce state in the
authoritative tree.

## Placement / run

Add `onbd_four_way_determinism.rs` to `mod tests` in `src/hyper/builder.rs` (reuses that module's
`VerkleTree`, `KzgSrs`, `VERKLE_DOMAIN`, `OsRng`, `PendingMessage`, `HyperBlockBuilder`,
`read_onboard_rotation_nonce`, `read_onboard_custody_fid`). The four-way test is already present in
the fix commit's test suite — this bundle is the audit copy.

```
cd <hypersnap>   # WSL, malachite sibling staged (see audit notes)
RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib -- \
  onbd_four_way_rotation_apply_order_determinism --nocapture
```

Verbatim result in `test-output.txt`.
