# ONBD-10 — Onboard replay resurrects a rotated-away custody→FID binding → rotation-revocation bypass

- **Severity:** High
- **Status:** OPEN (new at `ab73681`; merge blocker **B8**, shared root cause with [ONBD-9](ONBD-9-rotation-off-root-divergence.md))
- **Component:** `src/hyper/native_onboard.rs` (`sync_onboarding_mirror_from_tree`), `src/hyper/builder.rs`, `src/hyper/runtime.rs`
- **Introduced by:** the ONBD-1/ONBD-4 fixes in `ab73681`.
- **Corroboration:** storage-boundary lane (primary, rated Critical) + validator (ONBD-4 dispute) + **build-verified red PoC**.

## Summary

Custody rotation deletes the custody→FID binding from the RocksDB mirror but never from the verkle tree (the tree binding `onboard_custody_verkle_key(C1)=F` is written once at onboarding and **never deleted or updated anywhere**). `sync_onboarding_mirror_from_tree` unconditionally re-derives `mirror[custody] = tree[custody]` for every onboard body in an imported block. So **replaying an onboard for a rotated-away custody copies the stale tree binding straight back over the mirror**, resurrecting the binding that rotation deleted. The `ever` marker correctly blocks a second FID mint (ONBD-4), but does nothing to stop the mirror resurrection — which re-enables the revoked custody to pass the rotation `held_by_current` check and re-capture the FID. **Rotation-based key revocation can be undone.**

## Mechanism (code-traced, every link verified)

1. **Tree binding never cleared.** `apply_onboard_to_tree` writes `onboard_custody_verkle_key(C1)=F` (`builder.rs:99`); rotation never touches the tree (see [ONBD-9](ONBD-9-rotation-off-root-divergence.md)); grep confirms no delete of the custody/`ever` tree keys anywhere. After C1 rotates F to C2: mirror `{C2=F}`, `C1` deleted; **tree still `{C1=F, ever[C1]=1}`**.
2. **Mirror sync is unconditional.** `sync_onboarding_mirror_from_tree` (`native_onboard.rs:469-498`) loops every body in the imported block and does `tree.get(onboard_custody_verkle_key(custody))` → `batch.put(custody_to_fid_key(custody), fid)` (`:481-483`) — with no check that the body produced a fresh assignment and no check against the current mirror. `import_block` passes the **unfiltered** `onboards_in_block` to it (`runtime.rs:4926-4931`).
3. **Replay is admissible and unbounded.** The original holder owns C1's key, so they craft a **fresh, currently-anchored, freshly-PoW'd** C1 onboard (not the stale original → **not** bounded by the 1024-block anchor window). At ingestion `lookup_custody_fid(C1)=None` (rotation deleted it) → optimistic dup-check passes (`runtime.rs:4092-4101`) → enqueued. An honest proposer drains and includes it. At import, `apply_onboard_to_tree(C1)` sees `ever[C1]` → returns `None` (no 2nd FID ✓, tree unchanged → root matches → block imports), **but the mirror sync resurrects `mirror[C1]=F`**.
4. **Re-capture.** The mirror now holds **both** `C1=F` and `C2=F`. The revoked key C1 calls `apply_custody_rotation(current=C1, new=C3, fid=F, nonce=stored+1)`: `held_by_current` reads `lookup_custody_fid(C1)=F == body.fid` → passes (`native_onboard.rs:813-824`); nonce and C1-signature valid → C3 controls F. The FID the holder rotated away (e.g. after a C1 key compromise) is re-captured.

No malicious proposer is required (an honest one includes the mempool-admitted onboard). Deterministic; reachable through a normally-produced signed block.

## Build-verified red PoC

[poc/onbd/ONBD-10-mirror-resurrection/](../../poc/onbd/ONBD-10-mirror-resurrection/) — a `native_onboard` unit test asserting the security property *"after rotation, custody A stays revoked"*. It drives the real production primitives (`apply_onboard_to_tree` → `sync_onboarding_mirror_from_tree` → `apply_custody_rotation` → replay-`sync`) and **fails** on `ab73681`:

```
assertion `left == right` failed: REGRESSION: onboard replay resurrected rotated-away
custody A -> fid 9223372036854775808 (mirror sync copied the never-cleared verkle
binding back), defeating rotation-based revocation
  left: Some(9223372036854775808)   # 2^63 = HYPER_FID_BASE
 right: None
```

Correct red→green polarity: the test passes once rotation is on-root (or sync skips rotated custodies). A companion green test (`onbd4_rotate_then_replay_via_tree_mints_no_second_fid`) confirms the `ever` marker still blocks the 2nd-FID mint — i.e. ONBD-4 holds while ONBD-10 is a *distinct* side effect.

## Fix direction

Same as ONBD-9 — fold rotation into the signed tree so `sync` reflects (rather than resurrects) rotations. Alternatively/additionally: have `sync_onboarding_mirror_from_tree` skip a custody whose tree FID is already mirrored under a *different* custody, or gate the mirror write on the `ever`-vs-current-mirror state. The tree fold is the durable fix.

## Key locations

`native_onboard.rs:469-498` (unconditional mirror sync) · `builder.rs:87-111` (tree binding written, `ever` no-op) · `runtime.rs:4926-4931` (import passes unfiltered onboards) · `native_onboard.rs:813-824` (rotation `held_by_current` consumes the resurrected binding).
