# F035 validation — HyperLockEvent mints into the verkle root with no balance closure

Validator: validator (deliberate-disagreement). Commit `cab225f` (workspace HEAD, clean tree).
Finding claims: the transparent `HyperLockEvent` lock pipeline writes a caller-supplied
plaintext `amount` into a verkle leaf with no Pedersen balance closure, no range proof, and
no `lock_signature` check; the verkle root is threshold-signed and posted as the cross-chain
`hyper_state_root`. A malicious proposer can include arbitrary-amount locks in a wire block;
every importer applies them with structural-only validation. Confirms prior **F002** is, on
the balance/authenticity dimension, still vulnerable. Severity initial: High.

This is the **prior-F002 revalidation** and the central red-team concern is the
two-pipeline-confusion lesson (and the prior C3 invalidation): the L1 bridge consumes a
DIFFERENT, balance-validated pipeline than the one the finding traces. That tension is the
crux of the verdict below.

## Evidence chain re-verified (read-only)

WEAK path (the one the finding traces):
- `src/hyper/lock_event.rs:141` `validate_lock_event` — only checks `amount != 0`,
  `lock_id.len()==32`, non-empty dest/spend, EVM length conventions. Never reads
  `lock_signature`, enforces no balance relation. Confirmed.
- `src/hyper/lock_event.rs:1-14` module doc explicitly states source-side balance
  constraints are "a known gap" (Phase B-3). Confirmed.
- `src/hyper/builder.rs:113-118` `apply_message(PendingMessage::Lock)` → `insert_lock_into_tree`
  → `validate_lock_event` only, then `tree.insert(key, leaf)`. No commitment/range proof. Confirmed.
- `src/hyper/importer.rs:238-305` `import_hyper_block` — verifies block-level threshold ECDSA
  sig (252-258) and recomputed-root == stated root (285-292), then loops every `lock` in
  `locks_in_block` into `PendingMessage::Lock` (263-265). No per-lock authenticity/balance check. Confirmed.
- `src/hyper/runtime.rs:4461-4524` `import_block` — re-validates every TRANSFER off-mempool
  (`validate_against_store` + `verify_balance_with_blinding_diff`, 4482-4524) "to defend against
  a malicious proposer". **No equivalent loop for `locks_in_block`** — they pass straight to
  `import_hyper_block_with_index` (4526-4535). Confirmed asymmetry.
- `src/hyper/gossip_adapter.rs:70-77` `wire_to_event` — `InboundBlock { locks: b.locks, ... }`:
  locks are pulled VERBATIM from the proposer's `HyperWireBlock`, NOT cross-checked against the
  local mempool. → `actor.rs:1241-1248` `InboundBlock` → `runtime.import_block(&block, &locks, ...)`.
  Reachability of attacker-chosen leaves into the signed verkle root confirmed end-to-end.

STRONG path (the one the L1 bridge actually consumes):
- `src/hyper/confidential_lock.rs:156-186` `validate_against_store` — Pedersen closure
  (`residual != expected`, 182), Schnorr verify (171), nullifier-not-spent (166). Confirmed.
- `src/hyper/runtime.rs:860-913` `apply_confidential_lock` — the ONLY non-test writer of
  `TokenLockState` into `reward_store` (890-902), gated on `validate_against_store`. Confirmed.
- `src/hyper/runtime.rs:921-932` `build_lock_merkle_tree` — sources `reward_store.iter_all_locks()`
  (i.e. only `TokenLockState`s from the confidential path), builds the keccak256 merkle tree.
- `src/hyper/lock_tree.rs:1-46` — module doc + `encode_token_lock_leaf`: this merkle root is the
  one threshold-signed and posted to `HypersnapBridge.claim` as `latestRoot`; the claimant proves
  inclusion against THIS tree. The verkle root is a separate `hyper_state_root`. Confirmed.

Ingress sealing (F058):
- `src/hyper/router.rs:133-142` — gossip/RPC `Body::Lock` is rejected ("transparent lock path
  removed; use ConfidentialLockBody").
- `src/hyper/http_handler.rs:1706-1743` — HTTP POST of a Lock is rejected; mempool stays empty.
- BUT neither seals the block-application path: `b.locks` from a remote `HyperWireBlock` bypasses
  the router entirely (gossip_adapter → InboundBlock → import_block). The proposer-inserted weak
  lock path is genuinely live.

`lock_signature` usage: grep across `src/` — every occurrence is `vec![0u8; 64]` (test fixtures
in builder/actor/gossip_adapter/http_handler/mempool/router/runtime/lock_event/network_sim) or
the unrelated block-level `verify_hyperblock_signature`. The field is read NOWHERE in production. Confirmed.

## 8-hypothesis walk

### 1. Upstream auth / gate — STANDS
Is there a check upstream of `apply_message(Lock)` that re-validates proposer-supplied locks?
The transfer path has one (`runtime.rs:4482-4524`); the lock path does not. The router seals
*gossip/HTTP* ingress (router.rs:133, http_handler.rs:1706) but the wire-block path
(`gossip_adapter.rs:75` → `InboundBlock.locks` → `import_block`) carries locks directly from the
proposer's frame with no mempool cross-check and no balance/auth gate. No upstream gate on the
exploited path. STANDS.

### 2. Consumer-side impact — PARTIALLY INVALIDATED (this is the key caveat)
What consumes the corrupted verkle leaf? The in-scope L1-facing consumer is
`HypersnapBridge.claim`, which recomputes the **keccak256 merkle** lock-tree root
(`lock_tree.rs:1-46`, `runtime.rs:921-932`), built ONLY from `TokenLockState`s written by the
balance-validated `apply_confidential_lock` (`runtime.rs:890-902`). The `HyperLockEvent` verkle
leaf is NOT in that merkle tree. So the attacker's forged leaf is committed under the
threshold-signed `hyper_state_root` (verkle) but is NOT claimable through the merkle root the
deployed bridge consumes. This is precisely the two-pipeline-confusion / prior-C3 scenario.
The finding's own "Note on exploit live-ness" (body lines 122-132) already concedes this and
explicitly downgrades to "latent in-protocol primitive". The corrupted state is real and
threshold-signed, but no IN-SCOPE consumer turns it into L1 fund-loss today. Impact is therefore
an in-protocol invariant break, not a live drain. PARTIALLY INVALIDATED (impact, not existence).

### 3. Downstream enforcement — STANDS
Does any layer below `apply_message(Lock)` re-verify balance/authenticity before the leaf is
sealed? No. `import_hyper_block` only checks (a) block threshold sig and (b) verkle-root equality
(importer.rs:252-292). The root-equality check is satisfied because the leaf is deterministic, so
it cannot catch a balanced-vs-unbalanced distinction. No downstream balance enforcement on the
verkle lock path. STANDS.

### 4. PR HEAD currency — STANDS
Workspace HEAD is `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` (git log), clean working tree,
matching the pinned commit. No drift; all cited lines are current. STANDS.

### 5. Spec carve-out — PARTIALLY INVALIDATED (mitigates severity framing)
`lock_event.rs:11-14` explicitly documents the missing source-side balance enforcement as "a
known gap" pending Phase B-3 UTXO+Pedersen+range-proof primitives. The confidential pipeline
(`confidential_lock.rs`, `apply_confidential_lock`) IS that Phase-B replacement and is wired as
the production bridge path; the router/HTTP seals (F058) show the team is actively retiring the
transparent path. So the transparent verkle-lock primitive reads as a documented, partially-decommissioned
placeholder rather than a silently-broken production money path. This does not erase the
invariant break (the application path is still live for proposer-inserted locks) but it weakens
the "production block-application path still applies the weak path unconditionally" framing toward
"a not-fully-removed legacy primitive". PARTIALLY INVALIDATED (framing/severity).

### 6. Reachability of the harm — PARTIALLY INVALIDATED
Verkle-leaf insertion IS reachable (hyp. 1: malicious proposer → `b.locks` → import_block →
verkle root, no gate). But reachability of *value extraction* requires an L1 contract that honors
verkle-inclusion claims. The in-scope L1 claim path consumes the merkle root (hyp. 2), and the
deployed verkle-inclusion bridge contract is out of scope / not in this repo, so it is not
determinable that a value-bearing consumer exists today. The `lock_event.rs` module doc and the
`bridge_proof_pipeline_end_to_end` test (lines 318-371) assert a verkle-inclusion L1 mint flow,
but that is a hypersnap-side proof exercise, not proof a live L1 contract honors it. Harm to
in-protocol state STANDS; harm to L1 funds is NEEDS-MORE-DATA/out-of-scope. PARTIALLY INVALIDATED.

### 7. Test wiring — STANDS (production-reachable; no production producer)
`import_block` / `apply_message(Lock)` / `insert_lock_into_tree` are production functions on the
live import path (actor.rs:1248, 2775). The locks are supplied from the wire frame, so a remote
proposer reaches them in production regardless of whether any honest node ever *produces* a
transparent lock (all in-repo `locks` populations outside tests are `vec![]`). The exploit relies
on a malicious proposer hand-crafting `b.locks`, which `gossip_adapter` feeds unconditionally —
so the buggy code is genuinely invoked in production by adversarial input. STANDS.

### 8. PoC mechanics — NEEDS-MORE-DATA (no executable PoC in the finding)
The finding cites the existing `bridge_proof_pipeline_end_to_end` test (lock_event.rs:318-371) as
evidence the verkle-inclusion path is exercised. That test proves the hypersnap-side flow
(insert → root → inclusion proof → verify → decode round-trip) but asserts nothing about an L1
contract honoring it, nor about a *missing* balance check — it uses a well-formed sample event.
It does not itself demonstrate the unbacked-mint claim end-to-end. The structural-only behavior of
`validate_lock_event` is directly evidenced by reading lines 141-171 (no balance/signature logic),
which is solid. The "L1 mints `amount` to attacker" step rests on assertion, not a PoC. The
in-protocol-invariant-break portion is well-evidenced by code; the L1-fund-loss portion is not
demonstrated. NEEDS-MORE-DATA on the L1 leg.

## Overall verdict — HAS_CAVEATS (confidence 0.7)

The underlying CODE FACTS are correct and verified:
- The transparent `HyperLockEvent` path applies attacker-controllable, plaintext-amount leaves
  into the threshold-signed verkle root with structural-only validation (no Pedersen closure, no
  range proof, no `lock_signature` check).
- The asymmetry is real: transfers are re-validated off-mempool in `import_block`; locks are not.
- The path is genuinely reachable by a malicious proposer via the wire-block `locks` field, which
  bypasses the F058 router/HTTP seals.
- `lock_signature` is dead in production; `mod.rs`'s "Schnorr-signed authorization" claim is false.

This substantiates that F002's balance/authenticity dimension is **still vulnerable** as an
in-protocol invariant break on the verkle lock primitive.

The CAVEAT (and reason this is not WATERPROOF High fund-loss) is the consumer-side / reachability
walk: the in-scope L1 `claim` consumes the MERKLE root built from balance-validated
`TokenLockState`s, NOT the verkle root the forged leaf lands in. So the live, in-scope impact is a
threshold-signed-state-corruption / latent-mint primitive, not a demonstrated L1 drain. Whether it
becomes true fund-loss depends on an out-of-scope L1 contract honoring verkle inclusion. The
finding's body already states this honestly (lines 122-132) and frames severity accordingly, which
is why this is HAS_CAVEATS rather than INVALIDATED. The prior C3/two-pipeline lesson would
INVALIDATE a finding that claimed *live L1 fund-loss via HyperLockEvent*; F035 does not overclaim
that — it claims an in-protocol balance-closure violation + latent primitive, which holds.

f002_status: **still-vulnerable** (balance-closure invariant on the transparent lock path is
unenforced and the application path is live; impact is in-protocol / latent-L1 rather than
confirmed live L1 fund-loss).

## Open follow-ups (NOT new findings — validator cannot create findings)
- Severity calibration: under an Immunefi-style rubric the demonstrated in-scope impact is
  "threshold-signed cross-chain state-root corruption requiring a hardfork to unwind" (High by
  state-corruption, not Critical fund-loss). The finding's `severity_initial: high` is consistent
  with the caveated reading; no downgrade warranted, but a Critical upgrade would NOT be justified
  without the out-of-scope L1 verkle-claim contract in evidence.
- Documentation gap worth noting to the team: `mod.rs:14` / `lock_event.rs:6` advertise lock
  signature validation that does not exist — independent of fund-loss, this is a false safety claim.
