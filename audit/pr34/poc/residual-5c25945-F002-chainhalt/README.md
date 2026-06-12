# F002 residual chain-halt PoC — PRESENT at commit `5c25945`

**Result: REPRODUCED (structural model) / UNVERIFIED-BY-BUILD (in-crate test).**

- Target: hypersnap commit `5c2594563df84c374fdce7cdeae06d3444da3b72`
  (the "audit fixes" commit). The F002 UNION→INTERSECTION fix is present in
  this commit; the recursion / chain-halt sub-issue is **not** fixed.
- Source of the residual claim: `findings/revalidation/slashing-consensus.md`
  (F002 = PARTIALLY_FIXED) and
  `findings/F002-cross-epoch-evidence-slashes-innocent-single-epoch-signers.md`.

---

## The bug

In `src/hyper/runtime.rs` at `5c25945`:

- `get_active_validators_enforced(E)` (runtime.rs:4102) computes `prev = E-1`
  and calls `slashed_validators_for_epoch(E-1, …)` (runtime.rs:4122).
- `slashed_validators_for_epoch(epoch)` (runtime.rs:4238) loads stored
  evidence for `epoch`. Its `resolve_signers` closure reads each block's own
  `sig.epoch` (`block_epoch`) and calls
  `self.get_active_validators_enforced(block_epoch, …)` (runtime.rs:4264).
- Evidence is persisted under `min(epoch_a, epoch_b)`
  (`slashing_store.rs::make_key`, line 163).

So a stored **adjacent cross-epoch** evidence row
`(epoch_a = E-1, epoch_b = E)` — where `block_b` is validly signed for
epoch `E` — is keyed under `E-1` and produces:

```
get_active_validators_enforced(E)
  -> slashed_validators_for_epoch(E-1)              [runtime.rs:4122]
  -> reads the row at E-1; block_b.sig.epoch == E
  -> resolve_signers(block_b) calls
     get_active_validators_enforced(E)              [runtime.rs:4264]
  -> slashed_validators_for_epoch(E-1)              [back to the top]
  -> ... unbounded ...
```

There is **no depth guard, no memoization**, and the `_active_set_at_epoch`
parameter that could have broken the cycle is ignored (underscore-prefixed,
runtime.rs:4241). `compute_active_set(E)` for a future epoch returns `Ok`
(validator_registry.rs:686-689 → `Ok(active)` over the bootstrap set), so the
`Err -> continue` arm never fires to break the loop. Net: stack overflow →
node abort → **epoch-boundary chain halt**, triggerable by one
attacker-submitted adjacent cross-epoch evidence row.

This is reachable from unauthenticated gossip evidence ingest
(`detect_conflicting_blocks` never requires `epoch_a == epoch_b`); the only
real gate is per-block threshold-signature verification, which by design
passes for two genuinely committee-signed blocks.

---

## Test design

Two deliverables, both included here:

### 1. `F002_chainhalt_test.rs` — the FAITHFUL in-crate `#[test]`

Authored into `src/hyper/runtime.rs`'s `#[cfg(test)] mod tests` module,
reusing that module's existing `make_runtime()` helper and the **production**
APIs:

- `rt.record_evidence(&ev)` — the same store-write the production ingestion
  path (`InboundEvidence` → `runtime.record_evidence` →
  `SlashingEvidenceStore::record`) uses. Persists under `min(epoch_a, epoch_b)`.
- `rt.evidence_for_epoch(E-1)` — sanity-checks the row landed under `E-1`.
- `rt.get_active_validators_enforced(E, &bootstrap)` — the call that recurses.

It builds a real `ConflictingBlocksEvidence` with `block_a @ epoch E-1` and
`block_b @ epoch E` (same `canonical_block_id`), records it, then invokes
`get_active_validators_enforced(E)` on a **256 KiB-stack thread** so the
overflow is contained. A **benign control** (same-epoch evidence,
`epoch_a == epoch_b == E-1`) runs first on the same small stack and returns
`Ok` — proving the difference is the cross-epoch recursion, not setup error
or the small stack size.

Because a stack overflow on Windows aborts the **whole process**
(STATUS_STACK_OVERFLOW), `join()` does not cleanly return `Err` on this
platform — the malicious case manifests as a process abort *after* the benign
case has already returned `Ok`. On platforms that convert the overflow into a
thread panic via a guard page, `join()` returns `Err` and the assertion holds
literally. Either way the observable signal is: **benign returns, malicious
does not.**

### 2. `f002_model_standalone.rs` — runnable STRUCTURAL MODEL (the OBSERVED run)

The hypersnap crate could not be compiled in this environment (see Build
status), so to actually *observe* the recursion this standalone, dependency-
free binary mirrors the exact same control flow and keying:
`Store::get_for_epoch`, `record()` keyed under `min(ea,eb)`,
`get_active_validators_enforced(E) → slashed_validators_for_epoch(E-1) →
resolve_signers(block) reads block.sig.epoch → get_active_validators_enforced`,
with no depth guard and the `_active_set_at_epoch` parameter omitted (matching
that it is ignored in production). It runs the same benign-vs-malicious split
on a 256 KiB stack.

---

## Exact cargo commands

In-crate faithful test (the intended command — **build blocked here**):

```
git -C <repo> worktree add <wt> 5c2594563df84c374fdce7cdeae06d3444da3b72
# (this env also needs a sibling malachite checkout at ../malachite — see caveat)
cd <wt>
cargo test -p hypersnap --lib \
  f002_cross_epoch_evidence_recurses_unbounded_on_epoch_boundary -- --nocapture
```

Runnable structural model (the **observed** result):

```
cd scratch/f002-model
cargo run --release
```

---

## OBSERVED result

In-crate faithful test: **UNVERIFIED-BY-BUILD.** `cargo test`/`cargo build`
fail before rustc type-checks the test, in the transitive native dependency
`tikv-jemalloc-sys`:

```
running: "sh" ".../tikv-jemalloc-sys-.../out/build/configure" ...
checking for x86_64-pc-win32-gcc... .../MSVC/.../cl.exe
checking whether the C compiler works... no
configure: error: C compiler cannot create executables
thread 'main' panicked at .../tikv-jemalloc-sys-0.6.1.../build.rs:407:19:
failed to execute command: program not found
```

jemalloc's autotools `configure` feeds the MSVC `cl.exe` into a GNU-style
compile test and fails; there is no GNU/mingw `cc` in this environment. This
was retried with `vcvars64.bat` loaded (`cargo-build-vcvars.txt`) — identical
failure. The same blocker prevents the sibling `hypersnap-audit` checkout of
this code from building (no completed test binary there either). The blocker
is **entirely in a transitive allocator dependency and unrelated to the F002
logic**, which is pure safe-Rust recursion.

Structural model: **REPRODUCED.**

```
BENIGN (same-epoch evidence) get_active_validators_enforced(2): Ok(())

thread '<unknown>' (...) has overflowed its stack
error: process didn't exit successfully: `target\release\f002_model.exe`
       (exit code: 0xc00000fd, STATUS_STACK_OVERFLOW)
LASTEXITCODE = -1073741571   (= 0xC00000FD = STATUS_STACK_OVERFLOW)
```

The benign same-epoch row returns `Ok(())`; the malicious adjacent
cross-epoch row recurses without bound until the worker thread overflows its
256 KiB stack, aborting with `STATUS_STACK_OVERFLOW`. This is the observable
chain-halt: one attacker-submitted cross-epoch evidence row crashes the node
at the epoch boundary.

---

## Caveats / honesty notes

- The **in-crate test is UNVERIFIED-BY-BUILD**: it was never compiled by
  rustc, so a typo-level compile error cannot be fully ruled out by the
  toolchain. It was, however, written directly against the verified source
  signatures (`make_runtime`, `record_evidence`, `evidence_for_epoch`,
  `get_active_validators_enforced`, `ConflictingBlocksEvidence`, and the
  `HyperBlock`/`HyperBlockMetadata`/`HyperBlockSignature`/`HyperEnvelope`
  field layouts all read from the `5c25945` tree), and mirrors the existing
  `active_set_excludes_validator_with_trust_below_floor` test's construction.
- The **structural model is a model, not the production binary.** It proves
  the recursion *structure* is genuinely unbounded and that the benign vs.
  malicious distinction is real; it does not exercise the production RocksDB
  store or signature paths (the in-crate test does, but could not be run).
- The build needed a sibling `malachite` source tree at `../malachite`
  relative to the worktree (a workspace path-dependency). For the build
  attempt a directory junction was created at
  `scratch/malachite -> hypersnap-audit/code/malachite`; this is build
  scaffolding only and does not touch the target logic. It does not affect the
  jemalloc blocker.
- On Windows the malicious in-crate case aborts the whole test process rather
  than returning `Err` from `join()` (the model confirms this); the
  `res.is_err()` assertion is the correct outcome only on guard-page
  platforms. The benign-then-abort sequence is still a sound demonstration.
