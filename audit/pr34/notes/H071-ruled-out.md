---
id: H071
specialist: rust-crypto-primitives
attack_class: eip191-custody-domain-proof
outcome: ruled-out
file_paths:
  - code/hypersnap/src/hyper/account_association.rs
  - code/hypersnap/src/hyper/runtime.rs
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
---

# H071 — EIP-191 custody-domain proof: replay / domain confusion (ruled out)

## Scope

`src/hyper/account_association.rs::verify_account_association` — the sync
apply-path verifier for Farcaster account-association proofs. A JFS-style
envelope (`BASE64URL_NOPAD(header) || "." || BASE64URL_NOPAD(payload)`)
signed via EIP-191 `personal_sign` by an FID's custody secp256k1 key,
proving the FID controls a domain. Reached from
`runtime.rs::apply_miniapp_register` (stage 2 of a four-stage gate).

## Hunt question

Is the EIP-191 signed message bound to chainId + FID + a nonce/timestamp so
it can't be (a) replayed to associate an account to an attacker, (b) reused
across FIDs, or (c) replayed cross-chain? Can the `personal_sign` payload
collide with another signed structure (domain confusion)?

## What the verifier binds (walked signer-side and verifier-side)

The signed bytes are `BASE64URL(header) . BASE64URL(payload)` where:
- `header = {"fid":<u64>,"type":"custody","key":"0x<20B>"}`
- `payload = {"domain":<str>,"chain_id":<u64>}`

Both `fid` (header) and `chain_id` (payload) are inside the signed input.
The verifier enforces, in order:
1. `header.type == "custody"` (line 172) — segregates this flow from the
   Ed25519 app-key flow.
2. signature recovers to `header.key` over `eip191_hash(signing_input)`
   (lines 183-204).
3. `header.key == on-chain custody address for header.fid` (lines 207-218).
4. `header.fid == expected_fid` (lines 220-225).
5. `payload.domain == expected_domain` (lines 226-231).
6. `payload.chain_id == expected_chain_id` (lines 232-237), where
   `expected_chain_id = self.protocol_chain_id` (runtime.rs:2602), a
   non-zero protocol constant (default 10, OP Mainnet) all validators agree
   on.

## Why each sub-vector is closed

- **Cross-FID replay**: `fid` is part of the signed header and is checked
  three ways — against `expected_fid`, and the recovered signer must equal
  the on-chain custody address looked up *for that specific fid*
  (`custody_address_for_fid(header.fid)`). A proof signed for FID A cannot
  be replayed for FID B: the header.fid bytes are signed and must equal
  the caller's expected_fid. Even a custody key controlling multiple FIDs
  cannot cross-associate, because the signed header pins one fid.

- **Attacker self-association**: an attacker signing with their own key
  produces a proof whose recovered signer == header.key (their address),
  but the on-chain custody lookup for the victim fid returns the real
  owner's address, firing `CustodyMismatch` (covered by the
  `wrong_signer_rejected` test).

- **Cross-chain replay**: `payload.chain_id` is signed and matched against
  `protocol_chain_id` (the F101 regression already fixed this; the
  `cross_chain_replay_rejected` test guards it). `chain_id` is a required
  serde field (no `#[serde(default)]`), so a chain_id-less payload fails to
  parse rather than verifying with a vacuous 0.

- **Domain confusion / payload collision**: EIP-191 `personal_sign` is used
  in exactly one place in the codebase (a grep for "Ethereum Signed
  Message" / `sign_message` finds only this module and its tests). There is
  no second EIP-191-signed structure for the base64url signing input to
  collide with. The signing input is restricted to the base64url alphabet
  plus a `.` separator, and is verified only by this dedicated function
  after a `type == "custody"` gate. The EIP-191 prefix
  (`\x19Ethereum Signed Message:\n<decimal-len>`) is itself a domain
  separator from any raw-keccak / EIP-712 structured data.

- **No nonce/timestamp — acceptable here**: the proof authorizes a *stable*
  `(fid, domain, chain_id)` association, not a one-time action. Re-submitting
  an identical proof is idempotent: stage-3 domain-uniqueness
  (runtime.rs:2612-2622) rejects duplicate live registrations, and a
  re-registration after unregister legitimately re-asserts the same binding
  the custody owner already authorized. There is no replayable
  state-changing nonce semantic that a timestamp would protect, so its
  absence is not a vulnerability.

## EIP-191 digest correctness

`eip191_hash` (lines 112-118) computes
`keccak256(b"\x19Ethereum Signed Message:\n" || decimal_len(msg) || msg)`
and recovery uses `recover_address_from_prehash(&digest)`. This matches
alloy's `sign_message_sync` (exercised by `happy_path_verifies`). The `v`
normalization accepts both raw parity {0,1} and legacy {27,28} and rejects
anything else.

## Conclusion

No replay, cross-FID reuse, cross-chain replay, or domain-confusion gap.
The verifier binds fid, custody address, domain, and chain_id into a
checked, signed envelope, with on-chain custody as the trust anchor. Ruled
out.
