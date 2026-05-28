# PoC — F004 cutover-offset broken-fix (PR #28 round 5, `4a7d9c6`)

Runnable behavioral witness for the R5 broken-fix described in
[`../../REVALIDATION-4a7d9c6.md`](../../REVALIDATION-4a7d9c6.md) and
[`../../REMAINING-AFTER-R5.md`](../../REMAINING-AFTER-R5.md).

## What it proves

R5 made the runtime's epoch math cutover-aware in the actor / supervisor / scheduler
loops but left the authoritative `epoch_resolver` built `EpochManager::new()` (cutover = 0)
at `src/hyper/runtime.rs:339`. Genesis DKLS material is keyed at **epoch 0**
(`apply_cutover` → `install_dkls_group_address(0, …)` at `runtime.rs:4277`; genesis shares
at `genesis.rs:88`), but after cutover the resolver reports `cutover / EPOCH_LENGTH`, not 0.
The signing path (`runtime.rs:4824-4829`) does `dkls_signers.get(&current_epoch)` → miss →
`RuntimeProduceError::NoDklsShare`. At any mainnet cutover ≥ `EPOCH_LENGTH` (432,000) the
chain cannot produce its first post-cutover block — a launch-day liveness halt.

## How it was run

`f004_cutover_poc.rs` is a `#[test]` inserted into `src/hyper/runtime.rs`'s `mod tests`
(it needs crate-internal access to `epoch_resolver` and `dkls_signers`) against the **R5
source** (`farcasterorg/hypersnap` PR #28 commit `4a7d9c6`), built on the nightly toolchain.
It exercises the **real** `apply_cutover` and `produce_signed_block_dkls_local` paths.

```
# from a checkout of hypersnap @ 4a7d9c6, with the test pasted into runtime.rs mod tests:
cargo +nightly test --lib f004_poc_cutover_epoch_resolver_divergence -- --nocapture
```

> Note: run with `--lib`, not `--bin hypersnap` — the test lives in the library crate
> (`runtime.rs`); the binary test target (`main.rs` unittests) contains 0 matching tests.
> Stable rustc 1.95.0 ICEs on the unchanged `ed448-bulletproofs` dependency, so nightly
> (1.98.0) was used — an environmental toolchain issue, not a property of the commit.

## Captured output (cutover = 5,000,000)

```
running 1 test
cutover=5000000 EPOCH_LENGTH=432000
epoch_for_with_offset(cutover, cutover) = 0   <- genesis keyed here
rt.epoch_resolver.current_epoch()       = 11  <- signer looks up here
produce_signed_block_dkls_local => Err(NoDklsShare)
test hyper::runtime::tests::f004_poc_cutover_epoch_resolver_divergence ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1654 filtered out; finished in 1.72s
```

The test **passes**, i.e. the broken behavior is present in R5: the resolver epoch is 11
(= 5,000,000 / 432,000) while genesis material lives at epoch 0, and block production fails.

## Fix

One line, using the constructor R5 already added but never wired into `HyperRuntime::new`:

```rust
// src/hyper/runtime.rs:339
let manager = EpochManager::with_cutover(config.cutover_snapchain_block);
```

The maintainer's regression test should assert the **correct** post-cutover behavior
(`current_epoch() == 0` immediately after `apply_cutover`, and the genesis proposer can
produce) — i.e. the inverse of this PoC's assertions — so it goes red against R5 and green
once the one-liner lands.
