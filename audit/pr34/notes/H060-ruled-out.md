# H060 — eip712-signer-recovery-replay — RULED OUT (with hardening notes)

- hunt_id: H060
- specialist: rust-crypto-primitives
- attack_class: eip712-signer-recovery-replay
- commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
- file: code/hypersnap/src/hyper/token_escrow_claim.rs
- supporting: code/hypersnap/src/hyper/runtime.rs (apply_token_escrow_claim L1624,
  escrow_nonce_for L1583, submit_message dispatch L3766), token_escrow_bridge.rs,
  proto/definitions/hyper.proto L465-494
- outcome: no confirmed vulnerability

## Question

Is the EIP-712 domain bound to chainId + contract/deployment? Is the nonce
strictly monotonic / single-use so a claim signature cannot be replayed? Can
signer-recovery be confused so the wrong address claims another custodian's
escrow?

## What the code does

`validate_token_escrow_claim` (L103) builds the canonical typed-data
(`token_escrow_claim_typed_data`, L83), computes `eip712_signing_hash`, then
**recovers** the signer from the 65-byte `(r||s||v)` signature and compares the
recovered address to the *signed* `custody_address` (recover-and-compare). The
apply path `apply_token_escrow_claim` (runtime.rs L1624) is a three-stage gate:
(1) `validate_token_escrow_claim`, (2) nonce monotonicity vs.
`escrow_nonce_for(custody)` requiring `nonce == current+1`, (3) move the entire
escrow balance to `destination_fid` — all in one atomic RocksDB batch that also
bumps the nonce. It is invoked directly and synchronously from `submit_message`
(L3766), so there is no structural-only admission path that bypasses the gate.

## Why each sub-question is negative

1. **Nonce replay — SOUND.** The escrow nonce is a per-custody-address monotonic
   watermark under `RootPrefix::HyperEscrowNonce`, enforced as strictly
   `current+1`, written in the same atomic batch as the balance move (L1667-1688).
   Replay of an older signature fails the monotonicity check; the apply is
   idempotent. Single apply path, no separate mempool structural admission.
   Covered by tests (runtime.rs replay rejection at L8069).

2. **Signer-recovery confusion — NOT EXPLOITABLE.** Recover-and-compare binds the
   recovered address to the signed `custody_address`. The attacker controls the
   `v`/parity byte (L130-132), but flipping parity only changes *which* address is
   recovered — it cannot coerce recovery to equal a victim's address from a
   signature the attacker did not produce. Field tampering changes the EIP-712
   hash so recovery diverges; a wrong-key signature recovers a different address.
   All three cases are tested (rejects_custody_address_mismatch,
   rejects_field_tampering_after_signing, signature_from_wrong_key_rejected).

3. **Cross-context (claim vs bridge) replay — BLOCKED.** Claim and bridge share
   the `HypersnapEscrow` domain but use distinct `primaryType` and field sets, so
   the EIP-712 hashes differ; a claim signature cannot be replayed as a bridge
   (token_escrow_bridge.rs test claim_and_bridge_have_distinct_signature_domains).

4. **Domain chainId/contract binding — gap, but not a live vuln here.** The domain
   binds name/version/chainId(10) but NOT `verifyingContract`/deployment identity,
   and chainId is a fixed constant unrelated to where the node runs (comment L36-38:
   "no on-chain contract involved; we just want a stable domain"). Unlike the
   bridge control plane (F045), the escrow claim authorizes a state transition in
   the *single* logical hyper-chain reward ledger consumed exactly once via the
   per-custody nonce. There is no second deployment/context to replay the same
   signed message into, so the missing verifyingContract is hardening, not an
   exploitable cross-deployment replay.

## Robustness notes (recorded, none fund-loss)

- **No canonical low-S enforcement.** ECDSA malleability lets a third party who
  observes a claim in gossip mint a second distinct valid signature over the same
  body, but it is harmless: recover-and-compare still binds to custody_address and
  the action is idempotent under the single-use nonce. Worth normalizing to low-S
  for hygiene, not a vulnerability.
- **Loose `v` parity derivation.** `parity = v_byte != 0x1b && v_byte != 0x00`
  maps anything other than 27/0 to parity=true (so 28/1 and all junk → true).
  Accepts non-canonical `v` bytes but cannot cause signer confusion (wrong parity
  recovers a wrong address → mismatch → reject).
- **Proto/Rust domain mismatch.** hyper.proto L477 documents the claim domain as
  `{ name, version }` (no chainId) while the Rust domain (L73-79) includes
  `chainId: 10`. The Rust signer-side and verifier-side agree with each other, so
  it is internally consistent; but a wallet that follows the proto comment would
  produce a non-matching hash. Fails closed (rejected), not a security hole, but a
  wallet-interop trap worth fixing.
- **No independent cross-side EIP-712 test vector.** All tests sign with alloy
  itself, so a self-consistent-but-nonstandard typed-data encoding bug would not be
  caught. Recommend pinning a vector produced by an external wallet/EIP-712 impl.

## Verdict

No confirmed eip712-signer-recovery-replay vulnerability. Nonce replay and
signer-confusion are correctly defended. The missing verifyingContract binding and
the four robustness notes above are hardening recommendations, not findings.
