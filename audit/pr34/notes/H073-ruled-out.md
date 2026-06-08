---
hunt_id: H073
attack_class: group-address-fallback
specialist: rust-threshold-signing
file_paths:
  - src/hyper/dkls_address_store.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H073 — group-address-fallback — ruled out

## Scope
`src/hyper/dkls_address_store.rs` (PR-authored per-epoch DKLS23 group-address
store). Hunt: does a missing per-epoch group address cause a fall-back to a
BLS address / a default / a neighboring epoch (letting a signature verify
under the wrong key)? Can the store be written with an attacker-influenced
address?

## What the store does
Key layout `[HyperDklsGroupAddress][epoch BE u64]` (9 bytes), value = 20-byte
address.

- `get(epoch)` (lines 42-48) is an **exact-key point lookup**. It returns
  `Some(addr)` only when a 20-byte value exists for that exact epoch key, and
  `Ok(None)` for a missing key or any value whose length != 20. Fails closed;
  no prefix/range seek that could overshoot into an adjacent epoch.
- `make_key` (lines 19-24) is collision-free across epochs (full 8-byte BE
  epoch), so no cross-epoch key aliasing.
- `load_all` (lines 53-75) rejects any record with `key.len() != 9 ||
  value.len() != 20` and keys the in-memory `BTreeMap` on the exact decoded
  epoch — no neighbor coalescing.

## Lookup path fails closed at every consumer
The resolver `HyperRuntime::dkls_group_address_for_epoch` (runtime.rs
4783-4785) is `dkls_group_addresses.get(&epoch).copied()` — returns `Option`,
no fallback. Every production verification call site treats `None` as a hard
rejection, never substituting a default/neighbor/BLS key:

- `import_block` (runtime.rs 4467-4469) → `.ok_or(ImportError::SignatureVerificationFailed)`
- `apply_reward_issuance` (565-567) → `.ok_or(UnknownEpoch)`
- `apply_trust_snapshot_update` (655-657) → `.ok_or(UnknownEpoch)`
- merkle-root update (1025-1027) → `.ok_or(UnknownEpoch)`
- owner rotation, both epochs (1145-1150) → `.ok_or(UnknownEpoch)` each
- inbound burn (1332-1334) → `.ok_or(UnknownEpoch)`
- DA epoch-seed (3239-3246) → `.ok_or(Custom("no group address known..."))`

`sig_verify::dispatch` (sig_verify.rs 46-78) itself fails closed: empty/wrong-
length sig rejected, a non-empty declared `group_address` must equal the
expected address (no trusting attacker bytes), and the recovered address must
match `expected.ecdsa`. There is no BLS branch reachable from a missing ECDSA
key — the "falls back to BLS" wording in the module docstrings
(dkls_address_store.rs 6-8, runtime.rs 4776-4782) describes a hypothetical the
persistence layer is meant to *avoid*; no such fallback branch exists in the
verification code at this commit.

## Writes are not attacker-influenced
Non-test writers of the store (via `install_local_dkls_share` /
`install_dkls_group_address`, runtime.rs 4715-4766, both write-through to
`dkls_address_store.set`):

- Genesis bootstrap — `genesis.rs:84` and runtime.rs:4285 — trusted config
  `genesis_group_address`.
- DKG driver finalization — `dkls_driver.rs:92-103
  finalize_into_runtime` installs `output.group_address`, the address derived
  from this node's own locally-computed threshold-DKG ceremony output, not a
  value read off the wire.

The only `install_dkls_group_address` call that takes an externally-observed
address (`actor.rs:4056`) is inside a `#[tokio::test]`. There is no production
gossip handler that installs an attacker-supplied address for an epoch; a
persistence failure in `set` is logged and non-fatal but cannot inject a wrong
address.

## Conclusion
The store fails closed on missing/malformed entries, no consumer falls back to
a BLS/default/neighbor-epoch key, and addresses originate only from trusted
genesis config or local DKG ceremony output. No issue.
