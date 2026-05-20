---
id: F005
task: H005
specialist: consensus-malachite-tendermint
attack_class: read-validator-protocol-version
severity: high
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.95
  hypotheses_walked: 8
  validated_at: 2026-05-20T00:00:00Z
---

# Read-validator panics on unknown `DecidedValue` oneof variants (forward-incompat protocol drift)

## Summary

The read-validator decoding pipeline assumes the `DecidedValue.value` oneof
field is `Some(known_variant)` and uses `.unwrap()` at the very first hop
(`get_decided_value_height`, `verify_signatures`). Prost decodes unknown
oneof variants as `value: None`. Therefore, the moment the on-wire
`DecidedValue` proto reserves a new variant in a future protocol version
(variant tag 5, 6, …) and a peer running the new code gossips such a
message into the read-node topic, every read-validator running the *old*
binary panics on the very first decoded value. The new variant does not
need to be valid, signed, or even well-formed for the OLD node: `prost`'s
oneof decoding simply discards unknown variants and yields `value: None`,
which directly hits the unwrap.

This is the exact read-validator-protocol-version footgun: a forward-only
protocol upgrade (adding a new `DecidedValue` arm) is **not** backwards
compatible — old read-nodes crash instead of skipping the unknown message.

Severity rationale: a single attacker (or a single mainnet operator who
ships ahead of the fleet) can produce a `DecidedValue` proto whose oneof
tag is any unknown value; the gossip layer relays it to all subscribers of
the `DecidedValues` topic; every read-validator running an older binary
panics. The crash is fleet-wide and remote-triggerable. There is no
authentication on read-node gossip beyond gossipsub admission, and the
panic happens *before* any signature check — see Evidence.

## Description

### 1. The decode contract

`proto/definitions/blocks.proto:83-89`:

```proto
message DecidedValue {
  oneof value {
    Block block = 2;
    ShardChunk shard = 3;
    HyperBlock hyper_block = 4;
  }
}
```

prost-generated Rust:

```rust
pub struct DecidedValue {
    pub value: Option<decided_value::Value>,  // None for unknown variants
}
```

When a peer encodes a `DecidedValue` with a future oneof variant (e.g.
`block_v2 = 5`), prost on the old node decodes it as
`DecidedValue { value: None }`. This is the standard, documented
behaviour of protobuf oneof forward-incompatibility: unknown tags are
preserved as raw bytes but the strongly-typed enum field is `None`.

### 2. The panic surface inside `read_validator.rs`

After `ReadHostMsg::ProcessDecidedValue` is delivered
(`src/consensus/malachite/read_host.rs:79`), the host immediately calls
`state.validator.process_decided_value(value).await`
(`src/consensus/malachite/read_host.rs:80`), which executes:

`src/consensus/read_validator.rs:176-188`

```rust
pub async fn process_decided_value(&mut self, value: DecidedValue) -> u64 {
    let height = Self::get_decided_value_height(&value);   // <-- panic
    let verified = self.verify_signatures(&value);          // <-- also panic
    ...
}
```

#### 2a. `get_decided_value_height` — unwrap on the oneof

`src/consensus/read_validator.rs:97-123`

```rust
fn get_decided_value_height(value: &proto::DecidedValue) -> Height {
    match value.value.as_ref().unwrap() {     //  <-- line 98: panic on None
        proto::decided_value::Value::Shard(shard_chunk) => { ... }
        proto::decided_value::Value::Block(block)       => { ... }
        proto::decided_value::Value::HyperBlock(hb)     => { ... }
    }
}
```

An attacker-controlled `DecidedValue` whose oneof tag is *anything except
2, 3, or 4* (i.e. any future-reserved variant) decodes to `value: None`
on an old node and crashes the process at this `.unwrap()`. No signature
check has run; no validity check has run.

#### 2b. `verify_signatures` — same unwrap

`src/consensus/read_validator.rs:125-143`

```rust
fn verify_signatures(&self, value: &proto::DecidedValue) -> bool {
    let commits = match value.value.as_ref().unwrap() {  // <-- line 126
        proto::decided_value::Value::Shard(shard_chunk) => shard_chunk.commits.as_ref().unwrap(),
        proto::decided_value::Value::Block(block)       => block.commits.as_ref().unwrap(),
        proto::decided_value::Value::HyperBlock(_)      => return false,
    };
    ...
}
```

Even if `get_decided_value_height` had been hardened, `verify_signatures`
re-`.unwrap()`s the same oneof on line 126 — so the panic just moves one
line down.

#### 2c. `commit_decided_value` — panic on cross-variant routing

`src/consensus/read_validator.rs:49-79`

```rust
match &mut self.engine {
    Engine::ShardEngine(shard_engine) => match &value.value {
        Some(proto::decided_value::Value::Shard(shard_chunk)) => { ... }
        _ => { panic!("Invalid decided value") }   // <-- line 61
    },
    Engine::BlockEngine(block_engine) => match &value.value {
        Some(proto::decided_value::Value::Block(block)) => { ... }
        _ => { panic!("Invalid decided value") }   // <-- line 74
    },
};
```

The `_` arms collapse *three* cases into a panic:

1. `Some(other_known_variant)` (e.g. a `Block` arriving at a `ShardEngine`
   read-validator, or a `HyperBlock` reaching either engine if it ever
   slipped past `verify_signatures`).
2. `Some(future_unknown_variant)` — same forward-incompat surface as
   above; would matter if 2a/2b were fixed but 2c not.
3. `None` — same `value.value = None` decode of an unknown variant.

In other words, every layer of the read-validator pipeline that *touches*
the oneof panics on `None` / unknown / wrong-engine variants. There is no
defence-in-depth.

### 3. The reachability proof: gossip path, not just sync

Two ingress paths reach `ReadHostMsg::ProcessDecidedValue`:

**(a) Sync (request/response) path** — `src/consensus/malachite/read_sync.rs:343-362`:

```rust
Response::ValueResponse(value_response) => {
    let value_bytes = value_response.value.as_ref().unwrap().value_bytes.as_ref();
    let value = if decided_value.certificate.value_id.shard_index == 0 {
        proto::decided_value::Value::Block(proto::Block::decode(value_bytes).unwrap())
    } else {
        proto::decided_value::Value::Shard(proto::ShardChunk::decode(value_bytes).unwrap())
    };
    self.host.cast(ReadHostMsg::ProcessDecidedValue {
        value: proto::DecidedValue { value: Some(value) },
        ...
    })?;
}
```

This path *constructs* the variant locally, so it's not the attack
surface for unknown variants — but it *is* a panic surface for malformed
`value_bytes` via the two `.unwrap()`s on `proto::Block::decode` /
`proto::ShardChunk::decode`. (Out of scope; mentioned for completeness.)

**(b) Gossip path** — this is the protocol-version-drift surface.

`src/network/gossip.rs:815-823`:

```rust
match read_node_message {
    None => None,
    Some(read_node_message) => match read_node_message {
        read_node_message::ReadNodeMessage::DecidedValue(decided_value) => {
            Some(SystemMessage::DecidedValueForReadNode(decided_value))
        }
    },
}
```

`src/main.rs:878`:

```rust
SystemMessage::DecidedValueForReadNode(decided_value) => {
    node.dispatch_decided_value(decided_value);
}
```

`src/node/snapchain_read_node.rs:189-209`:

```rust
pub fn dispatch_decided_value(&self, decided_value: proto::DecidedValue) {
    let shard_id = match decided_value.value.as_ref().unwrap() {   // <-- line 190: panic on None
        proto::decided_value::Value::Shard(...)      => { ... }
        proto::decided_value::Value::Block(...)      => { ... }
        proto::decided_value::Value::HyperBlock(_)   => { warn!(...); return; }
    };
    ...
}
```

`dispatch_decided_value` panics *before* even forwarding to the
read-host: `decided_value.value.as_ref().unwrap()` on line 190. So a
single gossiped `DecidedValue` with an unknown oneof variant kills the
read-node main loop directly. (This file is outside the stated scope but
sits on the same call chain and is part of the same attack class; the
read-validator inside `read_validator.rs` is the second backstop and it
*also* panics, which is what the H005 scope is about.)

### 4. Why the existing `validate_protocol_version` does not save us

`src/consensus/read_validator.rs:145-174` *does* implement a graceful
protocol-version check: it compares `header.version` against
`EngineVersion::version_for(...).protocol_version()` and on mismatch
sends `SystemMessage::ExitWithError` and returns `false` — clean exit, no
panic. Good.

But that function is only called *after* `get_decided_value_height` and
`verify_signatures` (line 177–185). Both of those already panic on the
unknown-variant case, so `validate_protocol_version` is dead code along
the unknown-variant path. The graceful exit only covers *known-variant
but wrong header.version* — not *unknown variant entirely*.

Furthermore, `validate_protocol_version` only inspects the `Block`
variant (line 147) — the `_` arm at line 169 silently accepts everything
else (ShardChunk, HyperBlock, any future variant). So even *with* the
unwraps removed, the protocol-version drift check would let an unknown
variant through to `commit_decided_value`, where it would hit the
`panic!("Invalid decided value")` on line 61/74.

## Impact

- **Remote panic of every read-validator on the network**, triggered by a
  single gossiped `DecidedValue` with a future-reserved oneof variant.
- The attacker needs only to be a peer that the read-node has accepted
  into its gossipsub mesh on the `DecidedValues` topic — there is no
  signature check that runs *before* the panic; signature verification is
  on the same `value.value.as_ref().unwrap()` that panics.
- This is the canonical foot-gun for forward protocol upgrades: the moment
  the upstream proto adds a new `DecidedValue.value` arm (and the wire
  format permits exactly this — that's why the field is a `oneof`), every
  not-yet-upgraded read-node on the network crashes when the first
  upgraded peer broadcasts a `DecidedValue` of the new variant.
- A malicious or buggy peer can also forge a `DecidedValue` with an
  *arbitrary* unknown tag today (no upgrade required) by hand-crafting
  the bytes; gossipsub will relay it; old nodes panic.
- Hyperblock dispatch logic at
  `src/node/snapchain_read_node.rs:203-208` deliberately drops
  `HyperBlock` variants via a typed match arm — but that defence is
  *positioned after* the unwrap on line 190, so it only protects against
  the case where the oneof was already-`Some`. It does not protect
  against `None` (unknown variant).

## Evidence

- Panic on unknown oneof in height extractor: `src/consensus/read_validator.rs:98`
  `match value.value.as_ref().unwrap()`
- Panic on unknown oneof in signature verifier: `src/consensus/read_validator.rs:126`
  `match value.value.as_ref().unwrap()`
- Panic on wrong/unknown variant in commit path (ShardEngine arm):
  `src/consensus/read_validator.rs:61` `_ => { panic!("Invalid decided value") }`
- Panic on wrong/unknown variant in commit path (BlockEngine arm):
  `src/consensus/read_validator.rs:74` `_ => { panic!("Invalid decided value") }`
- Caller hop that delivers attacker-controlled `DecidedValue` to the
  panicking function: `src/consensus/malachite/read_host.rs:79-80`
  `ReadHostMsg::ProcessDecidedValue { value, sync } => { let num_values_processed = state.validator.process_decided_value(value).await; ... }`
- Gossip ingress that yields unauthenticated `DecidedValue`:
  `src/network/gossip.rs:820-822` and `src/main.rs:878-880`
- Upstream panic before the read-validator is even reached:
  `src/node/snapchain_read_node.rs:190` `match decided_value.value.as_ref().unwrap()`
- Wire-format definition that *permits* unknown variants:
  `proto/definitions/blocks.proto:83-89`
- Protocol-version drift checker that is dead code on the unknown-variant
  path: `src/consensus/read_validator.rs:145-174`

## Remediation

1. **Replace every `value.value.as_ref().unwrap()` on the read-validator
   path with an explicit `Option` match that returns / logs / drops on
   `None`.** Specifically:

   - `src/consensus/read_validator.rs:97-123` (`get_decided_value_height`):
     change the signature to `Option<Height>` and return `None` when the
     oneof is `None`. Have `process_decided_value` early-return `0` with
     a `warn!` in that case.
   - `src/consensus/read_validator.rs:125-143` (`verify_signatures`):
     return `false` when `value.value` is `None`.
   - `src/consensus/read_validator.rs:49-79` (`commit_decided_value`):
     downgrade `panic!("Invalid decided value")` to a `error!` + early
     return, so a future / wrong-engine variant cannot crash a live
     read-node.

2. **Move `validate_protocol_version` (or an equivalent unknown-variant
   guard) to be the *first* check in `process_decided_value`**, before
   any unwrap on the oneof, so that a header-version mismatch *or* an
   unknown-variant value triggers the graceful `ExitWithError` /
   silently-drop path instead of a `.unwrap()` panic.

3. **Extend `validate_protocol_version` to explicitly handle the unknown
   / `None` variant case**, e.g.:

   ```rust
   match &value.value {
       Some(proto::decided_value::Value::Block(b))      => { /* existing check */ }
       Some(proto::decided_value::Value::Shard(_))      => { /* existing no-op */ }
       Some(proto::decided_value::Value::HyperBlock(_)) => { /* existing no-op */ }
       None => {
           // Unknown future variant: warn, drop, optionally trigger a
           // controlled upgrade-needed exit. NEVER panic.
           warn!("Unknown DecidedValue oneof variant — node may need upgrade");
           return false;
       }
   }
   ```

4. **Audit the entire codebase for `decided_value.value.as_ref().unwrap()`
   / `.value.unwrap()`**; specifically fix
   `src/node/snapchain_read_node.rs:190` along the same pattern, since
   that panic is hit *before* the read-validator even sees the message.

5. **Add a regression test** that constructs a `DecidedValue` with raw
   bytes whose oneof tag is unrecognised (e.g. tag 99), encodes it,
   feeds it through the gossip-to-read-validator path, and asserts that
   the read-node logs a warning and continues running.

6. Consider tagging the `DecidedValue` proto with a top-level
   `protocol_version` field that an old node can inspect *before* trying
   to interpret the oneof, so forward upgrades have a clean negotiation
   point instead of relying on prost's silent-`None`-on-unknown-variant
   behaviour.
