---
id: H030
specialist: rust-crypto-primitives
attack_class: low-s-ecdsa-divergence
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - crates/hypersnap-crypto/src/ecdsa.rs
  - contracts/src/HypersnapBridge.sol
  - crates/hypersnap-crypto/src/dkls_threshold.rs
  - crates/hypersnap-crypto/src/dkls_sign.rs
  - crates/hypersnap-bridge-ceremony/src/main.rs
  - src/hyper/sig_verify.rs
  - contracts/test/CrossSideDigests.t.sol
---

# H030 — low-S / malleability enforcement asymmetry (Rust ecdsa.rs vs Solidity ecrecover)

## Question

Does the Rust ECDSA wrapper enforce low-S while the Solidity verifier
accepts high-S (or vice versa), so that a signature accepted on one side
is rejected/replayable on the other — breaking a uniqueness / anti-replay
assumption that keys off signature bytes?

## Conclusion: ruled out

Both sides enforce canonical low-S, symmetrically, at the same boundary,
on every in-tree producer and verifier path. There is no accepted-here /
rejected-there divergence. Separately, the Solidity anti-replay design does
not key off signature bytes at all, so even residual malleability would not
break a uniqueness assumption on that side.

## Evidence walked end-to-end

### 1. Rust verify side enforces low-S (and rejects s == 0)
`EcdsaSignature::from_bytes` (`ecdsa.rs:79-102`) parses via
`PrimitiveSignature::try_from` (which alone does NOT enforce low-S — alloy
accepts any `s < N`) and then applies an explicit check at line 92:
`if s > SECP256K1_HALF_N || s == 0 { reject }`. `SECP256K1_HALF_N`
(`ecdsa.rs:69-72`) is the exact secp256k1 `N/2` constant
(`0x7FFF…5D576E7357A4501DDFE92F46681B20A0`). The check uses strict `>`, so
the `s == N/2` boundary is accepted — identical to OZ. Every threshold
verification routes through this constructor: `sig_verify.rs:75`
(`dispatch`) feeds all four hyperblock/reward/trust/da-seed verifiers,
and the `runtime.rs` owner-rotation reads (6302, 6412, 6503, 6512, 8264,
8268) all call `EcdsaSignature::from_bytes`. No verify path bypasses the
low-S gate.

### 2. Rust sign side produces low-S
- DKLS23 threshold signing: both finalizers call
  `sign_phase4(..., normalize = true)` (`dkls_threshold.rs:429`,
  `dkls_sign.rs:411`), which canonicalizes to low-S, then re-wrap through
  `EcdsaSignature::from_rsv` → `from_bytes`, which re-rejects any non-low-S
  result. recovery_id ∈ {2,3} is surfaced as an error / re-run, not coerced
  (dkls_threshold.rs:442-449, dkls_sign.rs:417-422).
- Bridge-ceremony CLI signer: `signer.sign_hash_sync` over alloy's k256
  `PrivateKeySigner` (`main.rs:465`), which produces low-S `(r,s,v)` by
  default. Its `cmd_recover` helper (main.rs:507-536) is verify-only
  display and carries no dedup/uniqueness semantics.

### 3. Solidity verify side enforces low-S
`HypersnapBridge.sol` imports OZ
`@openzeppelin/contracts/utils/cryptography/ECDSA.sol` (line 7,
`using ECDSA for bytes32` line 51) and verifies every signed payload via
`digest.recover(sig)` (claim/rotateOwner/proposeUpgrade/cancelUpgrade/
pause/recoverERC20). With `pragma solidity ^0.8.24` and `solc = 0.8.24`
pinned in `contracts/foundry.toml`, the only OZ line that compiles is
v5.x, whose `ECDSA.recover` reverts `ECDSAInvalidSignatureS` for
`s > N/2`. Same enforcement, same boundary as the Rust side. (Note: the
`lib/` submodules are not checked out in this snapshot, so the exact OZ
source could not be read in-tree; the solc pin + import path constrain it
to a low-S-enforcing OZ v5 release.)

### 4. Solidity anti-replay does not key off signature bytes
Even if a malleated high-S sig somehow reached the contract, replay
protection there is structural, not signature-bytes-based:
- universal payloads gate on the strictly-monotonic `latestBlock`
  watermark (`StaleBlock` / `blockNumber > latestBlock`), and
- claims gate on `claimed[lockId]`.
A second (malleated) signature over the same `(blockNumber, …)` payload is
rejected by the watermark, and a second claim of the same `lockId` is
rejected by the `claimed` map. The malleability primitive the hunt worries
about (two accepted sigs for one digest used as a dedup key) does not exist
on the Solidity side because the dedup key is never the sig.

### 5. The Rust "dedup key" concern is also closed
The `ecdsa.rs` doc comments (lines 85-89) note that signature bytes feed
slashing-evidence dedup keys and that high-S would create a malleability
primitive there. Because `from_bytes` rejects high-S, the only accepted
encoding of any `(r, s)` pair is its low-S form — so the bytes are
canonical before they can ever be hashed into a dedup key. The producer
paths (point 2) already emit low-S, so this is closed on both ends.

### 6. Cross-side encoding is pinned
`contracts/test/CrossSideDigests.t.sol` pins keccak256 digests for all
seven signed-payload domains plus the lock leaf, asserting byte-equality
against the Rust encoder in `crates/hypersnap-crypto/src/bridge_payload.rs`
and against the live contract constants (`test_constants_matchContract`).
The signed-value encoding cannot silently drift between sides.

## Residual / nits (not findings)

- OZ ECDSA source is not vendored in this snapshot (`contracts/lib/` empty,
  no `.gitmodules`); low-S enforcement on the Solidity side is inferred from
  the solc 0.8.24 pin forcing OZ v5. If a future build were repinned to a
  pre-4.7.3 OZ line (which does not enforce low-S), the symmetry would
  break — but that is not reachable under the current `^0.8.24` pragma.
- The malleability fix is the one the comments attribute to F044; the code
  matches the comments and the constants are correct.
