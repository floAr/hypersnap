---
id: H027
specialist: rust-threshold-signing
attack_class: share-refresh-race
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
outcome: ruled-out
---

# H027 — share-refresh / epoch-rollover race vs in-flight signing is RULED OUT

Scope: `src/hyper/dkls_supervisor.rs`, `src/hyper/dkls_address_store.rs`
(traced through `actor.rs`, `runtime.rs`, `dkls_driver.rs`,
`dkls_sign_driver.rs`, `importer.rs`, `sig_verify.rs`).

## Threat hypotheses tested

1. A share refresh / new-epoch group-key install races an in-flight signing
   ceremony and produces a signature under a mixed / half-installed key.
2. A signing ceremony finalizes under a key the consumer no longer trusts.
3. The address store persists the wrong group address for an epoch.

All three are ruled out. Root cause of safety: the design is **full per-epoch
key rotation keyed strictly by epoch number, with an append-only / overwrite-
by-epoch address registry**, and all install + sign + verify steps run on the
**single-threaded actor event loop** — there is no in-flight "refresh that
keeps the same group key while rotating shares", which is the precondition for
the classic share-refresh-race.

## Why a mixed / half-installed key cannot be signed or verified

- This is not FROST-style in-place share refresh. Each epoch E gets its own
  independent DKG (`dkls_supervisor::run` dispatches one ceremony per target
  epoch; `DklsDriver::finalize_into_runtime` →
  `runtime.install_local_dkls_share(epoch, …)`). The group address for epoch E
  is therefore set exactly once and indexed by E.
- `install_local_dkls_share` (runtime.rs:4715) writes `dkls_signers[E]`,
  `dkls_group_addresses[E]`, and `dkls_address_store.set(E, …)` in a **single
  synchronous call** — there is no observable "half-installed" intermediate
  state for a given epoch (no separate share-then-address window another event
  could interleave into).
- Production (`produce_unsigned_block_dkls`, runtime.rs:4798) binds
  `epoch = epoch_resolver.current_epoch()` and reads the group address from
  `dkls_signers[current_epoch]` (F028 fix: no longer `next_back()`/max-installed,
  so pre-staged epoch-E+1 material cannot leak into epoch-E production). The
  signing digest is over `signing_payload(epoch, committee)` and the chosen
  `signature.epoch = epoch`.
- Verification (`import_block`, runtime.rs:4461 → `import_hyper_block`,
  importer.rs:238 → `sig_verify::dispatch`) recovers the ECDSA signature against
  `dkls_group_address_for_epoch(block.signature.epoch)` — i.e. against the
  registry value for the *epoch the block declares*, never the verifier's
  current epoch. The block's self-declared `signature.group_address` must also
  equal that expected address (`GroupAddressMismatch` fail-closed,
  sig_verify.rs:59-77). A signature that recovered to any other (half/mixed/old)
  key fails closed.

## Why epoch rollover during a ceremony is safe

- The actor processes `StartDkls`/`AdvanceDkls`/`StartDklsSign`/`AdvanceDklsSign`/
  `InboundDkls*` one at a time; the supervisor only *sends* events. No
  cross-thread mutation of `dkls_signers` / `dkls_group_addresses` exists, so
  "race" reduces to event interleaving, not a data race.
- `current_epoch` advances only inside `import_block` (runtime.rs:4581) at the
  end of a fully-serialized produce→sign→import sequence for one block. A block
  produced under epoch E is always verified against E's address regardless of
  any later rollover.
- The per-epoch address registry and `DklsAddressStore` are **never pruned or
  re-keyed** (no `dkls_signers.remove` / `dkls_group_addresses.remove` / retain
  in runtime.rs). Once epoch E's address is installed it remains stable for the
  process lifetime and across restarts (`load_all` rehydrates). An in-flight or
  late-finalizing ceremony for E therefore can never find E's entry mutated to a
  different key mid-flight. (Non-pruning is the separately-tracked F018; it is
  not a refresh-race and if anything closes this race.)
- Re-running a DKG for an already-installed epoch is prevented: the supervisor's
  `dispatched` watchdog only clears/retries an epoch while
  `has_dkls_share_for_epoch(epoch)` is false (dkls_supervisor.rs:83-103); once
  installed it is never re-dispatched, so E's address is never overwritten with
  a second, different DKG output.

## Why the wrong group address cannot be stored

- The only writers of `DklsAddressStore` for a given epoch are local DKG
  finalization (`install_local_dkls_share`) and genesis config
  (`install_dkls_group_address`, genesis.rs:84). `DkgFinalized` /
  `DklsSignFinalized` outbounds are log/notification-only (network_loop.rs:52)
  — there is **no gossip-driven, attacker-influenced address install** for an
  arbitrary epoch. Honest DKG yields one canonical address per epoch, so
  overwrite-by-epoch is last-writer-wins over identical values; no conflicting
  writes occur.
- `make_key`/`load_all` are length-gated (key len 9, value len 20) and the
  prefix scan upper bound (`RootPrefix::HyperDklsGroupAddress + 1` = 52) cannot
  pull foreign rows into the epoch→address map.

## Residual / adjacent (not this hunt)

- Availability-only: a non-signing verifier never auto-installs epoch-E's
  address from gossip, so it can only import an epoch-E block if the address was
  installed out of band; failure is fail-closed (`SignatureVerificationFailed`),
  not a wrong-key acceptance — out of scope for share-refresh-race.
- Unbounded growth of the never-pruned registry/store is F016/F018, already
  tracked; it strengthens rather than weakens H027.

Conclusion: no share-refresh / epoch-rollover race can yield a signature under a
mixed or untrusted key, nor cause the wrong group address to be stored.
