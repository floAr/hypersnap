---
id: H019
specialist: p2p-gossip
attack_class: untrusted-input-ingress
outcome: ruled-out
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
file_paths:
  - code/hypersnap/src/hyper/gossip_adapter.rs
  - code/hypersnap/src/hyper/mod.rs
---

# H019 — untrusted-input-ingress in `wire_to_event_with_source` — RULED OUT

## Scope
`wire_to_event_with_source` (`gossip_adapter.rs:65-104`) and its helper
`decode_hyper_block` (`gossip_adapter.rs:190-201`). Question: do all four
wire bodies decode into actor events safely, with no unwrap/expect/index/
u64-cast/alloc on attacker-controlled bytes and no default-on-missing that
bypasses a check?

## Method
1. Enumerated the four `proto::hyper_wire_message::Body` variants and traced
   each decode arm.
2. Inspected every fallible step for panic primitives (`unwrap`/`expect`/
   slice index/`as`-cast/`with_capacity`-style alloc on length fields).
3. Followed the two `.into()` conversions invoked during block decode into
   their `From` impls.

## Variant-by-variant decode path

- **`Body::Block(b)`** (`:70-78`): `b.block.ok_or(MissingBlock)?` then
  `decode_hyper_block`. Inside the helper every nested `Option` is gated with
  `ok_or` (`MissingEnvelope` `:191`, `MissingMetadata` `:192`,
  `MissingSignature` `:193`). No unwrap. `b.locks` / `b.transfers` are moved
  verbatim into the event as `Vec<proto::...>` — no per-element decode, no
  indexing, no cast in the adapter. (Downstream validation of locks/transfers
  is the actor's concern, out of this hunt's scope.)
- **`Body::Message(m)`** (`:79`): passed through verbatim as
  `proto::HyperMessage`. No field access, no decode — nothing to panic on.
- **`Body::Dkg(d)`** (`:80-95`): only `d.round` (a `u32`) is matched against
  the two discriminator constants `WIRE_ROUND_DKLS`/`WIRE_ROUND_DKLS_SIGN`;
  any other value returns `Err(InvalidDkgRound(n))` — no silent default. The
  `d.target_epoch` (u64) and `d.encoded` (`Vec<u8>`) are forwarded verbatim
  to the actor without cast, index, or length-driven allocation. The adapter
  is deliberately opaque to the codec bytes.
- **`Body::Evidence(e)`** (`:96-102`): `e.block_a` / `e.block_b` each gated
  with `ok_or` (`EvidenceMissingBlockA` `:97`, `EvidenceMissingBlockB` `:98`),
  then both run through the same total `decode_hyper_block`.

## `.into()` conversions are total
`metadata_proto.into()` resolves to `From<proto::HyperBlockMetadata> for
HyperBlockMetadata` (`mod.rs:552-575`) and `signature_proto.into()` to
`From<proto::HyperBlockSignature> for HyperBlockSignature`
(`mod.rs:905-914`). Both are plain field moves: every scalar copied as-is,
every `Vec` (`parent_hash`, `hyper_state_root`, `group_address`,
`ecdsa_signature`, `snapchain_*`) moved without length validation or
fixed-array conversion, and `missed_proposals` mapped element-wise
(`validator_key: Vec<u8>`, `round: i64`) with no fallible step. There is no
`TryInto`/`try_into`, no `[..N]` slice, no `as` truncation, and no
length-prefix-driven `with_capacity` on attacker input. No panic surface.

## Top-level body
`wire.body.ok_or(MissingBody)?` (`:69`) handles the absent-oneof case
explicitly; a `None` body cannot reach any match arm.

## Default-on-missing analysis
proto3 scalar defaults (e.g. `target_epoch == 0`, `round == 0`,
`canonical_block_id == 0`, empty `Vec`s) are produced when a field is absent,
but the adapter performs **no check** that a default would bypass: the round
discriminator is the only branch, and `round == 0` (or any non-11/12 value)
falls into the explicit `InvalidDkgRound` error arm rather than silently
selecting a ceremony. Numeric epochs are forwarded, not authorized, here.
Block/evidence decode never substitutes a default for a missing *message*
field — those are hard `ok_or` errors.

## Conclusion
All four wire bodies decode through `ok_or`-gated `Option` extraction, an
exhaustively-matched `round` discriminator with an explicit reject arm, and
two panic-free `From` impls. No unwrap/expect/index/u64-cast/length-driven
alloc on attacker-controlled bytes, and no default-on-missing that bypasses a
guard. The adapter is pure, total translation. No finding for this hunt.

(Adjacent, out-of-scope: the actor's downstream consumption of the forwarded
`locks`/`transfers`/`encoded`/`target_epoch` fields is covered by other
tasks; F013 and F016 already track panic/unbounded-key concerns in different
ingress paths.)
