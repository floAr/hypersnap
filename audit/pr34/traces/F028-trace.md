# F028 trace — DKLS threshold hard-pinned to 1 (t=1-of-N group key)

Finding: `findings/F028-dkls-threshold-hardpinned-to-one-single-validator-controls-group-key.md`
Validation: WATERPROOF (0.9). Commit `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`.
Code (read-only): `code/hypersnap`.

This trace documents two linked paths:
- (A) **Production-of-illegitimate-authority** — how the hard-pinned `threshold = 1`
  flows from node bootstrap into the per-epoch DKG and then lets a single
  committee-elected validator emit a full `(r,s,v)` group signature.
- (B) **Acceptance** — how any peer importing that hyperblock (or reward / trust /
  bridge payload) verifies the 1-member signature as the group authority, with no
  quorum / signer-count floor.

---

## Entry point(s)

- **(A) Node bootstrap config (LOCAL-CONFIG, operator-controlled):**
  `code/hypersnap/src/main.rs:1603` — `let dkls_threshold = 1u8;` inside the
  signing-validator bootstrap block (gated at `main.rs:1572` on
  `operator_validator_pubkey_hex` + `local_dkls_share_path`). Passed into the
  supervisor at `main.rs:1650` (`threshold: dkls_threshold` →
  `DklsSupervisorInputs`). This is the sole producer of `inputs.threshold`; there is
  no env override, config-file field, or runtime clamp.
- **(B) Gossip ingress for finished hyperblocks (REMOTE-AUTHED-PEER):** a hyperblock
  (carrying the threshold ECDSA signature) arrives over the hyper gossip topic from a
  peer and is fed into `import_hyper_block` (`code/hypersnap/src/hyper/importer.rs:238`).
  The block's `signature.ecdsa_signature` / `signer_indices` are attacker-influenced
  payload bytes; only libp2p peer-id authenticates the *sender*, not the
  threshold-membership of the signature.

## Trust boundary crossed

- **(A)** Operator config value (`dkls_threshold = 1u8`) crosses into the DKG
  parameter set unchecked: the static `1` becomes `Parameters.threshold` for an
  active set of arbitrary size N, defining a 1-of-N reconstruction policy. The
  boundary that *should* exist — "threshold must be BFT-safe relative to
  share_count" — is absent, so a misconfiguration (or the shipped default) silently
  becomes a security-critical key policy.
- **(B)** An untrusted, network-delivered byte blob (a single 65-byte ECDSA
  signature + self-declared `group_address` + `signer_indices`) crosses into the
  authority verifier (`sig_verify::dispatch`). The verifier trusts the *recovered
  address*, not any notion of "≥ quorum distinct cosigners signed." Because the
  group key is 1-of-N, a signature legitimately producible by one party recovers to
  the group address and is honored.

## Call path

### (A) Production path: t=1 config → DKG → single-party signature

1. `code/hypersnap/src/main.rs:1603` — bootstrap — `dkls_threshold = 1u8` set as a
   "conservative default" (comment at `main.rs:1597-1598`); no override plumbing.
2. `code/hypersnap/src/main.rs:1647-1655` — bootstrap — spawns
   `dkls_supervisor::run(DklsSupervisorInputs { threshold: dkls_threshold=1, .. })`.
3. `code/hypersnap/src/hyper/dkls_supervisor.rs:55` — `run` — epoch-boundary ticker;
   on imminent boundary calls `build_driver` then fires
   `HyperActorEvent::StartDkls`/`AdvanceDkls` at the actor.
4. `code/hypersnap/src/hyper/dkls_supervisor.rs:175` — `build_driver` — reads the
   **real** active set: `share_count = active.len()` (`:192`), e.g. N = 5/10/32.
5. `code/hypersnap/src/hyper/dkls_supervisor.rs:203-206` — `build_driver` —
   **vulnerable sink (production side):**
   `Parameters { threshold: inputs.threshold /* = 1 */, share_count /* = N */ }`.
   No floor, no `threshold` vs `share_count` relationship check. Builds the DKG
   coordinator (`:208`) with a 1-of-N policy.
6. `code/hypersnap/crates/hypersnap-crypto/src/dkls_threshold.rs:110` — `run_honest_dkg`
   (and the live ceremony coordinator equivalently) — gate at `:115` rejects only
   `threshold == 0 || threshold > share_count`; `(1, N)` passes. Every validator
   receives a share of a 1-of-N group key.
7. At sign time — `code/hypersnap/src/hyper/actor.rs:2614+` (`ProduceBlockDkls`
   dispatch) — reads the threshold back from the installed share:
   `threshold = share.party.parameters.threshold` (`:2645`),
   `share_count = ...share_count` (`:2646`).
8. `code/hypersnap/src/hyper/actor.rs:2657-2665` — committee selection —
   `select_signing_committee(epoch, committee_seed, share_count, threshold=1)`.
9. `code/hypersnap/src/hyper/dkls_committee.rs:53` — `select_signing_committee` —
   gate at `:59` rejects only `threshold == 0 || threshold > share_count`;
   `take(threshold)` at `:75` returns **exactly one** index (lowest-rank party for
   the `(epoch, digest)` seed).
10. `code/hypersnap/src/hyper/actor.rs:2666` — gate
    `if !committee.contains(&local_party_index) { return }` — only the single elected
    party proceeds; it builds the `DklsSignCoordinator` (`:2687`) and runs the sign.
11. `code/hypersnap/src/hyper/actor.rs:2711-2714` — single-member fast path —
    `signing_committee().len() == 1` ⇒ advance immediately; the lone party's share
    alone completes phases 1→4 and yields a full ECDSA signature.
12. `code/hypersnap/src/hyper/actor.rs:2715-2723` → `finalize_dkls_signature`
    (`actor.rs:2925`) → `dispatch_dkls_signature` — the completed `(r,s,v)` group
    signature is attached to the block and broadcast to peers. **A single validator
    has now produced group authority with no cosigner.**

### (B) Acceptance path: peer imports the 1-of-N signature as group authority

1. `code/hypersnap/src/hyper/importer.rs:238` — `import_hyper_block` — entry for a
   gossip-received hyperblock; resolves the expected per-epoch group address
   (`dkls_group_address_for_epoch`).
2. `code/hypersnap/src/hyper/importer.rs:246-249` — rebuilds the canonical
   `signing_payload(epoch, signer_indices)` from the block.
3. `code/hypersnap/src/hyper/importer.rs:252-258` — calls
   `verify_hyperblock_signature(payload, block.signature.ecdsa_signature,
   block.signature.group_address, expected)`.
4. `code/hypersnap/src/hyper/sig_verify.rs:84` — `verify_hyperblock_signature` →
   `dispatch` (`sig_verify.rs:46`).
5. `code/hypersnap/src/hyper/sig_verify.rs:46-77` — `dispatch` —
   **vulnerable sink (acceptance side):** checks (a) sig is exactly 65 bytes, (b) if a
   `group_address` is self-declared it must equal the expected address, then (c)
   `sig.verify_against_address(keccak256(payload), expected_addr)` (`:74-76`). There
   is **no** `signer_indices.len() >= quorum` / `2f+1` / cosigner-count check. A
   signature from the 1-member committee recovers to the legitimate group address and
   returns `Ok(())`. The block (or reward / trust-snapshot / bridge payload via the
   sibling `verify_*` helpers at `sig_verify.rs:100/109/119`) is applied as group
   authority.

Same single-ECDSA-recover-no-quorum acceptance is reused by the runtime verifiers
(`runtime.rs:1034/1166/1179/1338/5549`) and slashing (`slashing.rs:102`) — all route
through the same `dispatch`, so the missing floor is systemic across consumers.

## Attacker capability / preconditions

- **Production (A):** the elected signer must be a **committee member**, i.e. a
  **validator in the active set** who wins the deterministic `(epoch, height,
  parent_hash)` committee draw. With `threshold = 1`, *every* ceremony's committee has
  size 1, so each epoch some single validator is the sole signer; over epochs any
  given validator is the lone signer for many `(epoch, digest)` tuples. Compromise or
  malice of **one** active validator suffices to forge authority for the payloads it
  is elected to sign. The committee seed is non-grindable (F036 fix), so the attacker
  cannot freely target a specific digest, but does not need to — it only needs the
  draws it already wins.
- **Acceptance (B):** any peer (honest or not) that imports the block honors the
  1-member signature; the *forging* capability is what matters and lives in (A).
- **Precondition:** the live, shipped default `dkls_threshold = 1u8` on the production
  signing-validator path (gated on operator identity at `main.rs:1572`). No operator
  action is required to reach the vulnerable state — it is the default — and no config
  escape hatch exists to raise it.

## Guards on the path

- `main.rs:1572` operator-identity gate — only scopes *who runs the supervisor*; does
  not constrain the threshold. Does not stop traversal.
- `build_driver` guards `EmptyActiveSet` (`:186`), `ActiveSetTooLarge` (`:189`),
  `LocalNotActive` (`:201`) — none constrain `threshold`. Do not stop traversal.
- `dkls_threshold.rs:115` and `dkls_committee.rs:59` both reject only
  `threshold == 0 || threshold > share_count`. `(threshold=1, share_count=N)` passes
  both. These are the only validity gates and they explicitly permit t=1; the
  `pinned_vector_one_of_three` / `selection_size_equals_threshold` tests confirm a
  size-1 committee is first-class.
- `actor.rs:2666` `committee.contains(local_party_index)` — restricts *who* signs to
  the one elected party; it does not require a quorum — it enforces the opposite
  (single signer suffices).
- `sig_verify.rs:59-72` declared-`group_address` match + `:74-76` address recovery —
  fail closed only on address mismatch; **no** signer-count / quorum guard. Does not
  stop traversal.
- Separate-pipeline guard: the only `quorum.is_met` in the tree
  (`core/util.rs:132`) validates the legacy Snapchain Ed25519 block certificate, a
  different pipeline; it does not touch the DKLS group signature and provides no floor
  here.

## Reachability verdict

**LOCAL-CONFIG (default-ON) → COMMITTEE-MEMBER for exploitation.**

The illegitimate-authority *capability* is created by the shipped default config
(`dkls_threshold = 1u8`) on the production validator path with no override and no
BFT floor — so the dangerous state is reached with zero operator action
(LOCAL-CONFIG, default-on). *Exercising* the resulting forgery requires being a
single active validator that wins a committee draw (COMMITTEE-MEMBER / VALIDATOR);
the acceptance side is honored by any importing peer with no quorum check.
