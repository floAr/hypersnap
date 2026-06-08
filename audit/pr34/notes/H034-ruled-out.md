---
id: H034
specialist: rust-crypto-primitives
attack_class: aead-nonce-reuse
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/crates/hypersnap-crypto/src/transport_encrypt.rs
  - code/hypersnap/src/hyper/dkls_wire_codec.rs
  - code/hypersnap/src/hyper/actor.rs
---

# H034 — AEAD nonce-reuse / AAD discipline in DKLS transport (ruled out)

## Scope

`crates/hypersnap-crypto/src/transport_encrypt.rs` (X25519 + ChaCha20-Poly1305
sealed box) as consumed by `src/hyper/dkls_wire_codec.rs`, with real call sites
in `src/hyper/actor.rs`.

## Question

Is the AEAD nonce unique per (key, message)? Is it random with sufficient width,
or a counter that can reset/collide across reconnects/epochs? Does the AAD bind
the right protocol context?

## Findings — construction is canonical-correct

### Nonce source (transport_encrypt.rs:162-164)

`seal` draws a fresh 12-byte nonce per call via `rng.fill_bytes(&mut nonce_bytes)`.
There is no counter, no stored/persisted nonce, no reset path, and no
deterministic-nonce constructor anywhere in the module (grep for
`counter`/`Nonce::from` confirms only the per-call random path and the
decrypt-side `from_slice` of the received nonce).

### Key uniqueness makes nonce collision non-catastrophic (defense in depth)

Even if two messages ever drew the same 12-byte nonce, the AEAD *key* is also
unique per message: the key is
`HKDF-SHA256(X25519(fresh_ephemeral_secret, recipient_pub),
salt = ephemeral_pub || recipient_pub, info = "hypersnap-dkls-transport-v1")`
(lines 152-160, 183-196). The ephemeral X25519 keypair is freshly random per
`seal` (line 153, `rng.fill_bytes`). So the (key, nonce) pair is unique per
message by two independent CSPRNG draws. Classic AEAD nonce-reuse-under-fixed-key
cannot occur. The in-module test `repeated_seal_produces_distinct_ciphertexts`
pins this.

### RNG at real call sites is a CSPRNG

`seal` is generic over `RngCore + CryptoRng`. Both production call sites in
`actor.rs` pass `rand::rngs::OsRng`:
- line 2501-2509 (`seal_dkls_round_message`, DKG frames)
- line 2589-2595 (`seal_dkls_sign_round_message`, sign frames)

No seeded `StdRng`, no `thread_rng` reseeding concern, no per-session counter.
Reconnects/epoch rotations do not reset any nonce state because there is no
nonce state to reset.

### AAD binds the right context

DKG frames (`build_aad`, dkls_wire_codec.rs:122-130):
`"hypersnap-dkls-wire-v1" || epoch(8B BE) || round_tag(1B) || sender(1B) || receiver(1B)`.

Sign frames (`build_sign_aad`, lines 138-147) additionally append the 32B target
digest, binding each ciphertext to its signing ceremony.

`round_tag` (`ROUND_TAG_DKG=0xd1` / `ROUND_TAG_SIGN=0x51`) domain-separates DKG
from sign at the same epoch. The receiver reconstructs identical AAD at open time
(lines 309, 385); epoch/round/digest/sender/receiver mismatches fail the Poly1305
tag. Tests `aad_binds_to_epoch`, `opening_with_wrong_aad_fails`, and
`sign_broadcast_cross_digest_rejected` confirm this. The module docstring is
honest that cross-round *replay* binding is the caller's responsibility, and the
codec does supply that context (epoch + round_tag + digest).

## Residual / out of scope

- `crates/hypersnap-crypto/src/tokens.rs` (lines 574-677) also uses
  ChaCha20-Poly1305 with a `nonce` field carried in a struct. That is a
  token-confidentiality path, not the DKLS transport in scope here; its nonce
  derivation was not audited under H034. If not already covered, it is a
  candidate for a separate hunt task.

## Conclusion

No AEAD nonce-reuse and no AAD-discipline defect in the DKLS transport path.
The construction (fresh ephemeral key + fresh random nonce per message, context-
binding AAD) is the canonical correct pattern. Ruled out.
