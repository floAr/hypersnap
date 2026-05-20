---
id: F058
task: H058
specialist: rust-bulletproofs-pedersen
attack_class: validator-defined-but-unwired
severity: critical
status: draft
validation:
  validator: validator
  verdict: INVALIDATED
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
  decisive_hypotheses: [H2, H6]
  rationale: >-
    HyperLockEvent / Body::Lock writes to the verkle tree, but the
    L1 HypersnapBridge.sol consumer reads a keccak256 merkle root
    built from TokenLockBody-sourced TokenLockState entries
    (apply_token_lock in runtime.rs:720 — Ed25519-authenticated).
    No L1 contract reads the verkle tree, has a verkle verifier, or
    expects the verkle leaf encoding. Two-pipeline-confusion: the
    unwired verify_lock_signature is real, but it belongs to a
    dead/aspirational Phase-B3 verkle-bridge pipeline, not the live
    L1 bridge. The "arbitrary wrapped-HYPER mint" impact is
    refuted. Residual technical observation downgradeable to
    Low/Info (verkle-tree DoS / dead-code) but the Critical claim
    is invalidated.
---

# F058: `verify_lock_signature` is never called in production — gossip-fed `HyperLockEvent`s with arbitrary `lock_signature` are admitted into the verkle bridge tree, forging L1 wrapped-token mints

## Summary

`code/hypersnap/src/hyper/lock_event.rs:180` defines
`verify_lock_signature(event, locker_pubkey_bytes)`, which Schnorr-verifies
`event.lock_signature` against a domain-separated payload
(`lock_signing_payload`, line 149, DST `b"hypersnap-lock-event-v1"`). The
function is correct, domain-separated, and exhaustively unit-tested
(lines 346-418).

It has **zero non-test callers** in the entire repository. A repo-wide grep
for `verify_lock_signature` returns only the function definition + six
in-module test invocations.

The production ingress for a `HyperLockEvent` is:

```
gossip → HyperRuntime::submit_message
            (runtime.rs:3416, no Body::Lock arm — falls through)
       → router.route_inbound
            (router.rs:127)
       → Body::Lock(event) =>
            self.mempool.submit_lock(event)        ── router.rs:130
       → HyperMempool::submit_lock(event)         ── mempool.rs:119
            validate_lock_event(&event)            ── structural only
            // NO signature check
```

The block-apply path is no better:

```
import_hyper_block_with_index → import_hyper_block
       → HyperBlockBuilder::apply_message(Lock(event))   ── builder.rs:115
       → insert_lock_into_tree(tree, event)              ── lock_event.rs:258
            validate_lock_event(event)                   ── structural only
            tree.insert(&event.lock_id, encode_lock_leaf(event));
```

`validate_lock_event` (lock_event.rs:210) only enforces non-zero amount,
32-byte `lock_id`, non-empty `dest_address`/`spend_pubkey`, and EVM-shape
checks for known chain IDs. It does **not** verify any signature, does
**not** read `event.lock_signature`, and does **not** consult any locker
pubkey.

`HyperMessage::Body::Lock` is also **not** intercepted in
`HyperRuntime::submit_message` (runtime.rs:3416-3580) — every other
state-mutating body (`TokenTransfer`, `Transfer`, `TokenLock`,
`LockMerkleRootUpdate`, `OwnerRotation`, `InboundBurn`,
`TokenEscrowClaim`, `TokenEscrowBridge`, `TokenStake`, `TokenUnstake`,
`NodeAttestation`, `AppUsageReceipt`, `Miniapp*`, etc.) gets an
intercept arm that performs cryptographic validation; `Body::Lock`
falls through to the router and is admitted into the mempool with
structural-only checks.

## Why this is critical

Per the file's own doc-comment (lock_event.rs:1-14):

> Locks are user-initiated events that move HYPER from the source-side
> balance into a verkle-tree leaf, **which the L1 bridge contract proves
> inclusion of before minting wrapped tokens**.

The verkle leaf bytes are exactly the bridge-claim payload (`encode_lock_leaf`,
line 27):

```
amount (8B BE) || dest_chain_id (8B BE) ||
dest_address_len (2B BE) || dest_address ||
spend_pubkey_len (2B BE) || spend_pubkey
```

There is no on-chain "this leaf is endorsed by the burner" check. Inclusion
in the signed verkle root **is** the endorsement. Without
`verify_lock_signature`, an attacker who can put a `HyperLockEvent` on the
gossip wire can:

1. Pick any `lock_id` (32 bytes; collision-only constraint is mempool
   dedupe + `tree.insert` overwrite).
2. Pick any `amount` (>= 1), any `dest_chain_id`, any `dest_address`,
   any `spend_pubkey`.
3. Set `lock_signature` to arbitrary 0..=N bytes (no length or shape check
   in `validate_lock_event`; the codec-level
   `BadSignatureLength` / `InvalidLockSignature` branches in
   `verify_lock_signature` are unreachable because the validator is
   never invoked).
4. Gossip the `HyperMessage { body: Body::Lock(event) }`.
5. Router accepts via `mempool.submit_lock`. Proposer drains, builds a
   block, gets the threshold sig over the new verkle root.
6. `import_hyper_block` accepts the block (verkle root recomputes from
   the inserted leaf; signature verifies) and the attacker's leaf is now
   in the canonical state at the path `event.lock_id`.
7. Attacker presents a verkle inclusion proof for `lock_id` to the L1
   bridge contract on the `dest_chain_id`. The L1 contract mints
   `amount` wrapped HYPER to `dest_address`.

The attacker did not burn anything source-side — the H054 ruled-out note
already documents that source-side balance is decoupled from lock-event
acceptance (lock_event.rs:11-14: *"the handler accepts the lock event but
does not enforce source-side balance constraints"*). The intended brake is
the lock signature: only someone who can sign with the spend-key of an
existing burnable note should be able to mint that note as a bridge claim.
Without `verify_lock_signature` running, that brake is absent.

Result: **unbounded forge-mint** of wrapped HYPER on every L1 chain the
bridge supports (mainnet, Base, Optimism, Arbitrum, Polygon, Sepolia per
`is_evm_chain`, lock_event.rs:244-253). The cap is whatever the L1 bridge
contract itself caps — which, per the verkle-inclusion claim model
described in the file header, is nothing beyond "this leaf is in the
signed root."

## Evidence

```
$ rg -n verify_lock_signature code/hypersnap/src code/hypersnap/crates
src/hyper/lock_event.rs:180:pub fn verify_lock_signature(
src/hyper/lock_event.rs:346:    verify_lock_signature(&e, &pk_bytes).unwrap();    # in #[cfg(test)]
src/hyper/lock_event.rs:371:    verify_lock_signature(&e, &other_pk_bytes),       # in #[cfg(test)]
src/hyper/lock_event.rs:399:    verify_lock_signature(&e, &pk_bytes),             # in #[cfg(test)]
src/hyper/lock_event.rs:408:    verify_lock_signature(&e, &[0u8; 32]),            # in #[cfg(test)]
src/hyper/lock_event.rs:418:    verify_lock_signature(&e, &[0u8; 56]),            # in #[cfg(test)]
```

All six non-definition call sites are inside `mod tests` (line 268
`#[cfg(test)] mod tests`). Zero production callers.

```
$ rg -n submit_lock code/hypersnap/src --type rust
src/hyper/mempool.rs:119:    pub fn submit_lock(&mut self, event: ...)
src/hyper/router.rs:130:    self.mempool.submit_lock(event)?;
```

The only non-test caller of `submit_lock` is `router.rs:130`, which does
not pass a pubkey and could not call `verify_lock_signature` even if it
wanted to — the locker pubkey to verify against would have to be looked
up by `event.lock_id` against the source-side burn record, but no such
lookup exists at this site.

## Distinction from H054

H054 confirmed `verify_balance_with_blinding_diff` is wired into both
`submit_message` and `import_block` for the confidential `Transfer` rail.
That ruled-out is correct and orthogonal. H058 generalized the sweep to
every `verify_*` / `validate_*` in `src/hyper/**` and found that the lock
event Schnorr-signature validator falls through both the mempool admission
path and the block import path with no gate.

## Fix sketch

Two non-mutually-exclusive options:

1. **Router-side intercept (mempool gate):** in `router.route_inbound`'s
   `Body::Lock(event)` arm (router.rs:129), look up the locker pubkey
   for `event.lock_id` (or use `event.spend_pubkey` directly — see note
   below) and call `verify_lock_signature(&event, &locker_pubkey_bytes)`
   before `submit_lock`. Reject `RoutingError::Lock(...)` on failure.
   Mirrors the pattern used for `Body::Transfer` in
   `runtime.rs:3459-3482`, which the same file already cites as the
   template (router.rs:134-145).

2. **Block-import re-verification (defends against off-mempool inclusion):**
   in `import_hyper_block`'s lock loop (importer.rs:263-265), call
   `verify_lock_signature` against each lock event before
   `builder.apply_message(Lock(...))`. Mirrors the pattern in
   `HyperRuntime::import_block`'s transfer loop (runtime.rs:4139-4165)
   where every transfer is re-validated before any state change.

Both options need the protocol to fix *which* pubkey is canonical for
binding. The lock event already carries `event.spend_pubkey`, but
signing with it would be circular (the attacker chooses both). The
intended binding is presumably to a pre-existing note (UTXO) whose
`one_time_pubkey` the locker is claiming to burn — i.e. the lookup
needs the note store, the same path the confidential-transfer rail
already uses (`note_store.lookup_owner(&commitment)`,
`tokens.rs:354`). Until that binding is decided in protocol, even
wiring `verify_lock_signature` against `event.spend_pubkey` is *worse
than nothing* — it would key the bridge-mint authority to a field the
attacker chooses, which is the same auth gap dressed differently. The
file at lock_event.rs:11-14 acknowledges this is gapped on the
*balance* side; the *signature* side has the same gap.

For the immediate scope of this finding: `verify_lock_signature` is
defined, tested, security-load-bearing, and **never called from
production code**. Wiring it correctly is the necessary first step
even if its semantics need protocol-level work to fully close the
forge-mint surface.

## Severity rationale

Critical: arbitrary mint on every supported L1 wrapped-token deployment,
no privileged access required (gossip-reachable), no cost to the
attacker beyond network access. The file-header comment that locks
"depend on the UTXO + Pedersen + range-proof token primitives planned
for Phase B-3" suggests the team is aware this rail is undergated; the
mainnet docker-compose file (`docker-compose.mainnet.yml` in the repo
root) indicates a production deployment exists, so the gap ships.

## Other validators surveyed in this task (all wired)

See `findings/notes/H058-ruled-out.md` for the per-validator wiring
table. Of the ~30 `validate_*` / `verify_*` functions in `src/hyper/**`
+ `crates/hypersnap-crypto/**`, only **one** is unwired in production:
`verify_lock_signature`. `validate_with_input_pubkeys` (tokens.rs:326)
is also only test-called, but it is the unused branch of a two-branch
validator pattern whose other branch (`validate_against_store`,
tokens.rs:347) is fully wired and provides the same predicates against
chain state — not a finding.
