# `tests/c1_poc.rs` — false slashing via unauthenticated `InboundEvidence` gossip

PoC for an audit finding on PR #28 (the full writeup is in the PR conversation thread). **Verified end-to-end** on Ubuntu/WSL2 (`cargo test --test c1_poc` → 2 passed, 0 failed) against `64493318130f1ebf03a787790c59f6d4a354d414`.

## What this PoC proves

A single peer-supplied `HyperWireEvidence` gossip frame causes `HyperRuntime::slashed_validators_for_epoch(epoch)` to return arbitrary, attacker-chosen validator keys. Neither of the two `HyperBlock`s in the frame carries any signature material at all (both `group_address` and `ecdsa_signature` are empty byte vectors).

Trace through the source at commit `6449331`:

1. `gossip_adapter::wire_to_event` (`gossip_adapter.rs:82-88`) translates the `Body::Evidence` proto into `HyperActorEvent::InboundEvidence` with no signature check.
2. `HyperActor::dispatch` for `InboundEvidence` (`actor.rs:1288-1300`) calls `detect_conflicting_blocks` then `runtime.record_evidence` — still no signature check.
3. `slashing::detect_conflicting_blocks` (`slashing.rs:43-73`) only asserts heights match, epochs match, and hashes differ. It does NOT re-verify the threshold signatures, despite the comment at `slashing.rs:22-24` claiming verifiers do.
4. `slashing_store::record` (`slashing_store.rs:40-51`) writes the evidence to RocksDB keyed by `(prefix, epoch, height, sorted_hash_pair)`.
5. `runtime::slashed_validators_for_epoch` (`runtime.rs:3825-3856`) reads the persisted evidence and walks `signer_indices` from either block as ground truth — they are 1-based indices into the sorted active set.

## Variants demonstrated

- **Primary (unsigned-evidence-slashes):** two blocks with empty `group_address` and empty `ecdsa_signature` and `signer_indices = [1]` / `[2, 4]`. After one gossip frame, the runtime returns `{vk(1), vk(2), vk(4)}` as slashed for epoch 0.
- **Stretch (storage amplification):** 64 frames at the same `(height, epoch)`, varying only `parent_hash` on `block_b`. The store grows linearly (64 rows) because the RocksDB key includes the full hash pair.

## How to reproduce

This is a pure-additive integration test under the standard Cargo `tests/` directory. No production-code modification; every symbol it touches is already `pub` and reachable through the crate's public API.

### Prerequisites

The hypersnap workspace requires the standard sibling-clone of `informalsystems/malachite` (per the repo's main README):

```bash
# Adjacent to ./hypersnap/, NOT inside it.
git clone https://github.com/informalsystems/malachite.git
cd malachite && git checkout 13bca14cd209d985c3adf101a02924acde8723a5 && cd ..
```

`eth-signature-verifier @ 8deb4a0` is fetched transitively as a git dep — no separate clone needed.

### Run

From `code/hypersnap/`:

```bash
cargo test --test c1_poc                                                                # build + run
cargo test --no-run --test c1_poc                                                       # build only
cargo test --test c1_poc -- c1_unsigned_evidence_slashes_attacker_chosen_validators     # single test
cargo test --test c1_poc -- c1_storage_amplification_one_row_per_metadata_variant       # single test
```

### Verified output (2026-05-19, against `64493318130f1ebf03a787790c59f6d4a354d414`)

```
$ cargo test --test c1_poc
   Compiling hypersnap v0.11.6 (/mnt/c/.../hypersnap)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 10.80s
     Running tests/c1_poc.rs

running 2 tests
test c1_storage_amplification_one_row_per_metadata_variant ... ok
test c1_unsigned_evidence_slashes_attacker_chosen_validators ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.43s
```

**2 of 2 pass** = the bug is live exactly as the finding describes. After the recommended fix lands, test 1 will FAIL at the `assert_eq!(confirmed, 1, ...)` line (no `EvidenceConfirmed` will be emitted) and the test flips into a regression guard. The negative shape of the suite is intentional: passing today, failing post-fix.

## What each test asserts

### `c1_unsigned_evidence_slashes_attacker_chosen_validators`

- Builds a runtime with 4 bootstrap validators (`vk(1)..vk(4)`).
- Forges two `HyperBlock`s at `(height=42, epoch=0)` with empty `group_address` and empty `ecdsa_signature`.
- Sets `block_a.signature.signer_indices = [1]` and `block_b.signature.signer_indices = [2, 4]` — the attacker's hit list.
- Encodes the two blocks into a `proto::HyperWireMessage` with `Body::Evidence` — the exact wire frame a hostile peer would publish.
- Runs the frame through `gossip_adapter::wire_to_event` (production adapter); asserts the result is `HyperActorEvent::InboundEvidence`.
- Drives that event through `HyperActor::drive_events`; asserts the outbound contains exactly one `EvidenceConfirmed` and zero `EventError`s — i.e. the actor accepted unsigned evidence.
- Re-opens the same RocksDB, builds the active set, queries `slashed_validators_for_epoch(0, &active_set)`. Asserts the returned `BTreeSet` contains exactly `vk(1)`, `vk(2)`, and `vk(4)` — every attacker-named victim and nobody else.

### `c1_storage_amplification_one_row_per_metadata_variant` (stretch)

- Same setup, but sends 64 distinct `InboundEvidence` frames at `(height=99, epoch=7)`, varying only `parent_hash` on `block_b` (using `0xFF` for `block_a`'s `parent_hash_byte`, outside the `0..64` loop range, so `block_b` never collides with `block_a`).
- Asserts all 64 are confirmed.
- Asserts `evidence_for_epoch(7).len() == 64` — the `slashing_store.rs` key shape gives each distinct hash pair its own RocksDB row, so the store grows linearly under spam.

## Build-environment notes (incidental to the finding)

Two unrelated workarounds the auditor needed on fresh Ubuntu/WSL2 — flagged here so you don't get surprised if you hit them:

- `RUSTFLAGS="--cap-lints allow"` — rustc 1.95.0 (2026-04-14) hits an ICE in the `lifetime_syntax` lint renderer while compiling `informalsystems-malachitebft-wal`. Capping lints bypasses the renderer. Pinning rustc 1.94.0 also works. Not specific to this PoC or to hypersnap.
- `CARGO_TARGET_DIR` outside the workspace — fine, except for the `pre-commit` crate's build script which walks up looking for the workspace root and panics if it can't find it. Use the default in-workspace `target/` to avoid.

## Per-symbol verification (audit detail)

Every symbol the PoC touches was cross-checked against its declaration site during the audit — all are already `pub` and reachable through the crate's public API. Highlights:

- `HyperActor::drive_events` → `pub async fn` at `src/hyper/actor.rs:1020` (NOT `pub(crate)`; the doc comment at `:1015-1019` explicitly flags it as a test helper).
- `HyperActor`, `HyperActorEvent`, `HyperActorOutbound` → `pub` at `src/hyper/actor.rs:889`, `:29`, `:535`.
- `wire_to_event` → `pub fn` at `src/hyper/gossip_adapter.rs:56`.
- `HyperRuntime`, `HyperRuntimeConfig` → `pub struct` at `src/hyper/runtime.rs:201` and `:119` (every field of `HyperRuntimeConfig` is `pub`).
- `HyperRuntime::slashed_validators_for_epoch` → `pub fn` at `src/hyper/runtime.rs:3825`.
- `HyperRuntime::evidence_for_epoch` → `pub fn` at `src/hyper/runtime.rs:3804`.
- `HyperBlock`, `HyperBlockMetadata`, `HyperBlockSignature`, `HyperEnvelope` → `pub struct` at `src/hyper/mod.rs:388`, `:293`, `:371`, `:358`. `signer_indices` is `Vec<u64>` (verified at `mod.rs:376` and `proto/definitions/hyper.proto:87 repeated uint64`).
- `RocksDB` → `pub` at `src/storage/db/rocksdb.rs:80`.

No production-code visibility changes needed; the PoC compiles against the public crate API as-is.

## Full finding writeup and recommended fix

See the PR #28 conversation thread for the full writeup, severity rationale, attacker-framed impact analysis, and recommended fix sketch.
