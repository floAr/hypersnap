---
id: F185
task: H151-residual
attack_class: serialization-boundary
severity: high
status: draft
---

# `verify_signatures` panics on peer-gossiped `Commits` before signature check (F151-residual, read-node path)

## Summary

PR#32 (commit `b464cfb`) fixed F151 by adding fallible codec helpers
(`Vote::try_from_proto`, `Proposal::try_from_proto`,
`Commits::try_to_commit_certificate`, `Address::try_from_vec`) and rewiring the
`SnapchainCodec` decode arms to use them, so malformed protos crossing the
malachite network codec are now rejected instead of panicking. That part is
confirmed fixed.

However the original **panicking** `Commits::to_commit_certificate()`
(`src/core/types.rs:758`) is still called by `verify_signatures()`
(`src/core/util.rs:103`) — and `verify_signatures` builds the certificate
*before* any signature or length validation. On the read-node path, the
`proto::Commits` it consumes is fully peer-controlled and arrives via the raw
`proto::GossipMessage::decode` ingress, **never** crossing the now-fixed
`SnapchainCodec` / `try_to_commit_certificate`. A single malicious peer can
gossip a `DecidedValue` whose embedded block/shard-chunk `Commits` is malformed
and panic every read-node subscribed to the topic, before any signature is
checked.

`to_commit_certificate()` panics on any of:
- `self.height.unwrap()` — `Commits.height` absent (`types.rs:761`)
- `self.value.clone().unwrap()` — `Commits.value` absent (`types.rs:763`)
- `Address::from_vec(commit.signer.clone())` where `signer.len() != 32` —
  `copy_from_slice` length-mismatch panic (`types.rs:769` -> `types.rs:74-77`)

The cheapest weaponization is a single `CommitSignature` with a `signer` of
length != 32 (e.g. empty or 1 byte): trivially constructed, no valid signatures
or quorum required, panic fires at the very first line of `verify_signatures`.

## Affected files

Panic surface:
- `src/core/types.rs:758-780` — `Commits::to_commit_certificate()` (the
  non-`try_` variant), `unwrap()` on height/value, `Address::from_vec` on signer
- `src/core/types.rs:74-78` — `Address::from_vec` -> `copy_from_slice` panics if
  `vec.len() != 32`
- `src/core/util.rs:103` — `verify_signatures` calls
  `commits.to_commit_certificate()` as its first statement, before the quorum
  check (util.rs:112) and per-signature verification (util.rs:120-139)

Peer-reachable call chain (read-node, gossip ingress):
1. `src/network/gossip.rs:862` — `proto::GossipMessage::decode(...)` (raw prost,
   NOT SnapchainCodec)
2. `src/network/gossip.rs:874-875` —
   `read_node_message::ReadNodeMessage::DecidedValue(decided_value)` ->
   `SystemMessage::DecidedValueForReadNode(decided_value)`
3. `src/main.rs:852-853` — `node.dispatch_decided_value(decided_value)`
4. `src/node/snapchain_read_node.rs:205` — `actors.cast_decided_value(decided_value)`
5. `src/consensus/malachite/spawn_read_node.rs:139` —
   `ReadHostMsg::ProcessDecidedValue { value, .. }`
6. `src/consensus/malachite/read_host.rs:79-80` —
   `state.validator.process_decided_value(value)`
7. `src/consensus/read_validator.rs:154` -> `:118` — `verify_signatures(&commits, ..)`
   where `commits = block.commits` / `shard_chunk.commits` (read_validator.rs:110-116)
8. `src/core/util.rs:103` -> `src/core/types.rs:758` — **panic**

Second peer-reachable ingress (read-node, value-sync), independent of the codec:
- `src/consensus/malachite/read_sync.rs:344-359` — on `Response::ValueResponse`,
  the `proto::DecidedValue` cast to `ProcessDecidedValue` is **reconstructed** by
  re-decoding `value_bytes` (the `full_value` blob) into `proto::Block` /
  `proto::ShardChunk` (read_sync.rs:350/354). That decoded block carries its own
  embedded `commits: proto::Commits`. The codec's `try_to_commit_certificate`
  (snapchain_codec.rs:240) validated only the *top-level*
  `SyncValueResponse.commits` into the separate `certificate` field — it never
  touches the `commits` embedded inside `value_bytes`. So the `Commits` that
  reaches `verify_signatures` here is also unvalidated and peer-controlled.

## Reachability trace (answering the backcheck question)

**Is `commits` at `read_validator.rs:118` peer-controlled and does it reach
`to_commit_certificate()` without passing through the fixed codec?**

YES, on the read-node path.

- The gossip path (chain above) decodes the `DecidedValue` with bare
  `proto::GossipMessage::decode` at gossip.rs:862. There is no
  `try_to_commit_certificate`, no `try_from_vec`, and no optional/length
  validation anywhere between that decode and `to_commit_certificate()`. The
  block's `commits` is taken straight out of the decoded proto
  (read_validator.rs:110-116) and handed to `verify_signatures`.
- The value-sync path re-decodes `value_bytes` into a block whose embedded
  `commits` was never seen by the codec's validation (which only checked the
  sibling top-level `commits`). So even the one path that *does* touch the codec
  does not gate the field that actually panics.
- `verify_signatures` calls `to_commit_certificate()` as line 1 (util.rs:103),
  strictly before the quorum check and signature verification — so an invalid /
  unsigned `Commits` reaches the panic regardless of signature validity.

**Block-receiver path (`block_receiver.rs:86`): RULED OUT as peer-reachable.**
`BlockReceiver.block_rx` is fed only by the local proposer's
`publish_new_block` -> `block_tx.send(block)` (`src/consensus/proposer.rs:479-483`;
channel created at `main.rs:870` and wired into the proposer at `main.rs:887`).
The blocks are locally produced/decided, not peer protos. So this callsite is
locally-sourced and not the residual concern. (It would still panic on a
locally-corrupt block, but that is not attacker-controlled.)

## Relationship to F151 / F005

- **F151** fixed the malachite-codec decode arms only
  (`snapchain_codec.rs`, via `try_from_proto` / `try_to_commit_certificate` /
  `try_from_vec`). It did **not** migrate `verify_signatures` /
  `to_commit_certificate()` to the fallible variant. F185 is the residual: the
  exact same malformed-`Commits` class still panics, just via the read-node
  ingress that bypasses the codec. The fix is incomplete on the
  read-node-crash path.
- **F005** covers the `DecidedValue.value == None` (unknown-oneof) unwrap at the
  *front* of the same read-node pipeline (`get_decided_value_height` /
  `verify_signatures` wrapper). F185 is distinct and reached *after* F005's
  guard would pass: it fires when `value` is a valid known `Block`/`Shard`
  variant but the *inner* `Commits` (height / value / signer-length) is
  malformed. Same ingress, different and deeper panic surface. Fixing F005
  (handling `value: None`) does not fix F185.

## Snapchain-parity note

Inherited, not introduced. snapchain v0.12.0:
- `src/core/util.rs:102-103` — identical `verify_signatures` ->
  `commits.to_commit_certificate()` ordering.
- `src/core/types.rs:709-720` — identical `to_commit_certificate()` with
  `Address::from_vec` (types.rs:74) length-panic; **no** `try_` variant exists
  upstream.
- `src/consensus/read_validator.rs:118` / `:154` and
  `src/network/gossip.rs:999-1012` — identical raw-decode-then-verify read-node
  ingress.

PR#32 added the `try_` helpers (a hypersnap divergence from upstream) and used
them in the codec, but left the `verify_signatures` read-node consumer on the
panicking path. So hypersnap is one rewire away from closing the class it
already built the tools for; upstream is fully exposed.

## Severity rationale

High. Remote, unauthenticated, pre-signature-verification panic that is
fleet-wide: a single peer gossips one `DecidedValue` with a malformed inner
`Commits` (e.g. a `CommitSignature.signer` of length != 32) into the read-node
topic; every read-node subscribed to that topic decodes it via
`proto::GossipMessage::decode` and panics inside `to_commit_certificate()`
before any signature, quorum, or protocol-version check. No valid signatures,
quorum, or even a well-formed block body are required. The crash is a hard
`panic!`/`copy_from_slice` abort of the read-node process (DoS / halt of the
read-node fleet). Matches the F005 severity (high) for the same ingress and is
arguably easier to trigger (no protocol-drift coordination needed).

## Suggested remediation

Migrate `verify_signatures` and its callers to the fallible certificate
builder:

1. Change `verify_signatures` (`src/core/util.rs:102`) to use
   `commits.try_to_commit_certificate()` (already exists, `types.rs:782`) and
   return `false` (drop the block) on `Err`, e.g.:
   ```rust
   let certificate = match commits.try_to_commit_certificate() {
       Ok(c) => c,
       Err(e) => { error!("invalid commits: {e}"); return false; }
   };
   ```
   This rejects missing height/value and `signer.len() != 32` exactly as the
   codec arms already do, and folds cleanly into the existing
   `verify_signatures -> false -> "Dropping decided block"` flow at
   read_validator.rs:155-157.
2. Optionally deprecate / remove the non-`try_` `to_commit_certificate()` so no
   future caller reintroduces the panic, or keep it only for genuinely
   local-source data (block_receiver/proposer) with a comment noting it must
   never see peer protos.
3. (Defense in depth, overlaps F005) `process_decided_value` /
   `get_decided_value_height` (read_validator.rs:97-118) should also stop
   `.unwrap()`-ing `value.value` and the header/height options on the
   peer-decoded `DecidedValue`.
