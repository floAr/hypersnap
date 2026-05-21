---
id: F135
task: H135
attack_class: fee-trust-uniqueness-flow
severity: high
status: draft
---

# F135 — DA-PoW driver zero-pads the natural-length trie key to a 32-byte `served_key` whose exact bytes are not present in the hyper merkle trie; in production wiring this guarantees `BlockEngineDaTrieLookup::contains_key` rejects every DA challenge response, collapsing the FIP §5 DA-PoW reward signal to zero for every validator

- **Task:** H135
- **Attack class:** `fee-trust-uniqueness-flow` (driver-side encoding asymmetry between producer and apply-time existence gate)
- **Severity (provisional):** High. The FIP §5 DA-PoW reward formula consumes the per-(epoch, fid) `da_answered_count` and `da_response_block_sum` to apportion a portion of the per-epoch issuance budget to validators who demonstrably store hyper trie data. With this defect, in any deployment that wires `BlockEngineDaTrieLookup` (the standard production path; `main.rs:1273-1278`), every honest validator's DA challenge responses are rejected at apply time with `"DA response served_key not in hyper trie"`. The DA-PoW reward share for the entire validator set collapses to zero. The pure-DA part of issuance is silently misallocated (or lost, depending on the §5 budget split — out of H135's narrow scope to enumerate), and validators have no economic gradient incentivising them to actually store data. The trie-existence gate that DA-PoW is supposed to enforce is, in production, a no-op — every accepted response (when the lookup is unwired) lands without proving data possession, and every response (when the lookup IS wired) is rejected even for an honest, fully-data-present validator. The two failure modes are symmetric: lookup-on → no rewards; lookup-off → no proof.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/da_pow_driver.rs:52-99` — `produce_da_response_for_index_via`: derives the 16-byte challenge prefix, calls `lookup(&prefix)` which returns the FULL natural-length trie key (e.g. 26 bytes for messages, 22 bytes for fnames, 46 bytes for onchain events), then zero-pads OR truncates that key to a fixed 32 bytes (`let mut served_key = [0u8; 32]; let copy_len = served.len().min(32); served_key[..copy_len].copy_from_slice(&served[..copy_len]);`). The 32-byte `served_key` is then signed and shipped on the wire.
- `code/hypersnap/src/hyper/da_pow_driver.rs:101-157` — `produce_da_responses` / `produce_da_responses_via`: the batch wrapper, invoked once per epoch by the actor at `actor.rs:2127-2186`. No mitigation for the served-key width mismatch.
- `code/hypersnap/src/hyper/da_response_producer_prod.rs:38-62` — `BlockEngineDaResponseProducer::produce_for_epoch`: production `DaResponseProducer` impl. Looks up trie keys via `engine.trie_values_with_prefix(&ctx, prefix).into_iter().next()` — confirms the lookup returns the natural-length trie key, not a padded 32-byte one.
- `code/hypersnap/src/hyper/runtime.rs:3022-3142` — `apply_da_challenge_response`: the consensus apply path. At `runtime.rs:3090-3097` it invokes `lookup.contains_key(&body.served_key)` with the FULL 32-byte `served_key` field. `BlockEngineDaTrieLookup::contains_key` is an exact-byte-match check (does not strip trailing zeros, does not accept prefixes), so the 32-byte padded key never matches the trie's natural-length entry.
- `code/hypersnap/src/hyper/da_trie_lookup_prod.rs:34-49` — `BlockEngineDaTrieLookup::contains_key`: delegates to `engine.trie_key_exists(&ctx, &key_vec)` with the 32-byte vec.
- `code/hypersnap/src/storage/store/block_engine.rs:239-247` — `BlockEngine::trie_key_exists`: delegates to `self.stores.trie.exists(ctx, &self.db, sync_id)`.
- `code/hypersnap/src/storage/trie/merkle_trie.rs:359-367` — `MerkleTrie::exists`: expands the input key to nibbles, walks the trie, leaf-comparison is `bytes_compare(self.key, key) == 0` (`trie_node.rs:528`). Exact match. A 26-byte natural key stored as 52 nibbles never matches a 32-byte padded query expanded to 64 nibbles.
- `code/hypersnap/src/storage/trie/trie_node.rs:520-542` — `TrieNode::exists`: confirms the leaf comparison is exact-byte-length-match.
- `code/hypersnap/src/main.rs:1273-1278` — production wiring: the `BlockEngineDaTrieLookup` is installed unconditionally whenever the hyper block engine is present. So in any production hyper-mode deployment, the broken `contains_key` gate is active.
- `code/hypersnap/src/storage/trie/merkle_trie.rs:30-105` — `TrieKey::for_message` / `for_message_type` / `for_fid` / `for_fname` / `for_onchain_event`: confirms natural trie key shapes. `for_message`: `1 + 4 + 1 + HASH_LENGTH (20) = 26 bytes`. `for_fname`: `1 + 4 + 1 + USERNAME_MAX_LENGTH (20) = 26 bytes`. `for_fid`: `1 + 4 = 5 bytes`. `for_onchain_event`: `1 + 4 + 1 + 32 + 8 = 46 bytes` (truncated to 32 by the driver).
- `code/hypersnap/src/storage/store/account/message.rs:15-16` — `HASH_LENGTH = 20`, `TS_HASH_LENGTH = 24`. Confirms the 20-byte hash that drives message trie keys to 26 bytes total.

## Summary

The DA-PoW driver and the DA-PoW apply path disagree on the bit-width of the
`served_key` field in `DaChallengeResponseBody`. The driver pads the
natural-length trie key (26 bytes for typical message entries, 5 bytes for
fid-shard entries, 46 bytes for onchain events) to a fixed 32-byte width with
trailing zeros (or truncates from the right, for onchain events). The apply
path's `DaTrieLookup::contains_key` performs an exact-bytes lookup of the
FULL 32-byte `served_key` against the hyper merkle trie, which holds only
the natural-length keys.

Consequence: in production, every DA challenge response — even one that an
honest validator produces from a trie key it actually holds — is rejected
with `"DA response served_key not in hyper trie"` (`runtime.rs:3092-3096`).
The `(epoch, fid, challenge_index)` marker is never written, the
`da_answered_count` counter for that validator stays at zero, the
`da_response_block_sum` stays at zero, and the §5 DA-PoW reward share for
that validator becomes zero.

Since the same encoding asymmetry affects every validator identically, the
total DA-PoW credit pool across the validator set is zero. The pure-DA
portion of the epoch issuance budget is either misallocated to the
non-DA-PoW reward components (if §5 normalises by participating share) or
left unminted (if §5 has a fixed-amount DA-PoW envelope). Either way, the
"validators must store hyper trie data to earn this reward" incentive
gradient collapses to a flat-zero signal.

Worse, if a deployment unwires the `BlockEngineDaTrieLookup` (the
`if let Some(engine) = ...` branch at `main.rs:1273` evaluates `false`), the
apply path's existence gate at `runtime.rs:3090-3097` short-circuits with
`if let Some(lookup) = ... { ... }` falling through — and DA responses are
accepted purely on the strength of the prefix + signature + binding gates,
WITHOUT proving the validator holds any data. The driver's padded
`served_key` doesn't actually need to exist in any trie — it just needs to
begin with the derived prefix, which the driver itself generates from the
prefix. A malicious validator can build a "served_key" of the form
`prefix || 16 zero bytes`, sign it, and earn full DA-PoW credit without
serving a single byte of trie data.

So:

- **Lookup wired (default production):** all honest responses rejected; DA-PoW reward signal == 0.
- **Lookup unwired (test/dev or partial deployment):** trie-existence gate is a no-op; any validator can forge "I served data" responses by simply zero-padding the derived prefix; DA-PoW reward becomes a free 100/100 mint for any validator that runs `produce_da_responses` against a known prefix.

The defect is not a one-side bug — it's a fundamental wire-format
disagreement between producer and verifier that the test suite did not
catch because the driver's unit test
(`da_pow_driver.rs:198-239: matching_trie_key_produces_signed_response`)
inserts artificial 32-byte keys into a fresh trie, then validates that the
driver round-trips its own 32-byte format — not that the apply path
accepts the result against a real-shaped trie key.

## Root-cause analysis

`produce_da_response_for_index_via` (`da_pow_driver.rs:52-99`) does two
things that, taken together, break the cross-side encoding:

1. **Lookup callback returns the natural-length trie key.** Production
   wiring is `engine.trie_values_with_prefix(&ctx, prefix).into_iter().next()`
   (`da_response_producer_prod.rs:55-58`). `trie_values_with_prefix`
   delegates to `MerkleTrie::get_all_values` (`block_engine.rs:250-259`,
   `merkle_trie.rs:443-466`) which returns full leaf keys after
   `combine_nibbles`. Leaf keys are the natural shapes built by
   `TrieKey::for_message` / `for_fid` / `for_fname` / `for_onchain_event`.

2. **Driver pads or truncates to exactly 32 bytes before signing.**
   `da_pow_driver.rs:77-79`:
   ```rust
   let mut served_key = [0u8; 32];
   let copy_len = served.len().min(32);
   served_key[..copy_len].copy_from_slice(&served[..copy_len]);
   ```
   - For a 5-byte fid-only key (rare but possible — these don't actually
     appear in user-message tries but exist in some metadata branches),
     `served_key` becomes 5 real bytes + 27 trailing zeros.
   - For a 26-byte message-or-fname key (the common case), `served_key`
     becomes 26 real bytes + 6 trailing zeros.
   - For a 46-byte onchain-event key, `served_key` becomes the first 32
     bytes of the natural key — the trailing `log_index.to_be_bytes()` (8
     bytes) plus the last few bytes of the 32-byte tx_hash are SILENTLY
     CHOPPED OFF.

   None of these forms exist in the trie. The trie has:
   - the 26-byte form (not the 32-byte zero-padded form),
   - the 46-byte form (not the 32-byte truncated form),
   - etc.

3. **Apply-path `contains_key` does exact-byte matching at the leaf.**
   `MerkleTrie::exists` (`merkle_trie.rs:359-367`) expands the 32-byte
   query to 64 nibbles, walks the trie, and `TrieNode::exists`
   (`trie_node.rs:520-542`) compares the leaf's stored key (52 nibbles
   for the 26-byte case) against the 64-nibble query at line 528:
   `bytes_compare(self.key.as_ref().unwrap_or(&vec![]), key) == 0`.
   Different lengths → not equal → returns `false`.

There is no length-tolerant matching, no zero-trailing strip, no
prefix-only mode. The check is `key == leaf`. Always false in production.

## Secondary observation — challenge-prefix vs. trie keyspace

Even before the padding/truncation issue, the 16-byte SHA-256-truncated
challenge prefix has near-zero probability of matching the START of any
real trie key. Trie keys follow a deterministic structured prefix:

- Byte 0: shard byte (`fid_shard(fid) = sha256(fid_be4)[..4] % 256`) —
  uniformly random per FID over 0-255.
- Bytes 1-4: `make_fid_key(fid)` — the FID as 4 BE bytes. Active FID
  range is on the order of 10^6 over a 2^32 keyspace, so a random
  4-byte query matches an active FID with probability ~10^6 / 2^32 ≈
  2.3 × 10^-4.
- Byte 5: message type byte (`msg_type << 3` for messages, or 1-6 for
  onchain event types, or 7 for fname). Roughly 10 valid values out of
  256 → 4 × 10^-2.

Joint probability per challenge of even the first six bytes of the random
16-byte SHA prefix matching any natural-shape trie key: `~1 * 2.3e-4 *
4e-2 = 9.2 × 10^-6`. Over 100 challenges per validator per epoch: `9.2 ×
10^-4` — i.e. each validator successfully produces a response in roughly
1 in 1000 epochs. And even when it does, the apply path rejects it for
the padding reason above.

This secondary observation explains why the bug went undetected: the
driver itself returns `None` from `lookup(&prefix)` overwhelmingly often
(`da_pow_driver.rs:75: let served = lookup(&prefix)?`), so the producer
silently emits zero responses per epoch, and the operator sees "no
metrics" rather than "responses rejected". The metric
`hyper.da.responses_submitted` (`actor.rs:2185`) stays at 0 in steady
state without raising any alarm. The "DA driver: submit_message rejected
response" debug log (`actor.rs:2170-2175`) only fires for the rare path
where a response IS produced but the apply path rejects it — and at
debug level it's invisible to most operators.

This is arguably a separate finding (challenge-derivation does not match
the trie keyspace's structured prefix; FIP §5 contract is violated even
absent the padding bug), but it shares the same root cause as the
padding mismatch: nobody verified that `derive_challenge_prefix` and the
hyper merkle trie agree on key shape. We bundle it here as an aggravating
factor; a separate H-task could trace its independent fix surface (e.g.
require the prefix to be conditioned on the shard byte, or to be derived
from a known FID and only the suffix randomised) without invalidating
this H135 padding-side report.

## Proof of vulnerability

End-to-end, in production wiring (`main.rs:1273-1278`):

1. Validator A with FID 42 reaches a new epoch boundary; `actor.rs:1170`
   calls `maybe_trigger_da_responses(anchor_block)`.
2. `da_response_producer_prod.rs:48-58` calls `produce_da_responses_via`,
   which iterates `0..CHALLENGES_PER_EPOCH = 100`.
3. For each `challenge_index`, the driver derives a 16-byte prefix from
   `(boundary_hash, validator_pubkey, epoch, challenge_index, chain_id)`.
4. The lookup callback walks the trie for keys starting with `prefix`. In
   the (rare) case it finds one, it returns the natural-length key —
   typically 26 bytes for `for_message`, 22 bytes for `for_fname`, etc.
5. The driver pads to 32 bytes: `served_key = key || [0u8; 32 - key.len()]`.
6. The driver signs `(epoch, fid, challenge_index, served_key,
   signer_pubkey)` and ships the response.
7. `apply_da_challenge_response` (`runtime.rs:3022`) walks every gate:
   - `validate_da_response` — passes (signature was made by the driver
     itself over this exact `served_key`).
   - signer-fid binding — passes (FID 42, key is on-chain).
   - validator-fid binding — passes.
   - epoch / seed availability / deadline — pass.
   - `check_served_key_prefix(body, &boundary_hash, chain_id)` — passes:
     `served_key[..16] == derived_prefix` is true by construction in the
     driver (`da_pow_driver.rs:80-82`).
   - `lookup.contains_key(&body.served_key)` (`runtime.rs:3090-3097`) —
     **FAILS**: the trie has the 26-byte natural key, the query is the
     32-byte zero-padded version. Returns `false`. Apply rejects with
     `"DA response served_key not in hyper trie: <hex>"`.
8. No marker written. `da_answered_count(42, epoch) = 0`. §5 reward
   formula awards FID 42 zero DA-PoW credit for the epoch.

This sequence repeats for EVERY validator for EVERY epoch.

## Suggested fix (sketch — not normative)

Two minimal options:

**Option A — change the apply path's existence query.** Instead of
`lookup.contains_key(&body.served_key)`, strip the trailing zero bytes
from `served_key` before the lookup (or use a length-typed served_key
field on `DaChallengeResponseBody` so the consumer knows where the
natural key ends). This requires a wire-format expansion: add a
`served_key_len: u32` field, OR introduce a TLV / length-prefixed
encoding. Note that for the onchain-event 46-byte case the driver is
currently TRUNCATING, which is unrecoverable from a 32-byte value alone
— the served_key field width itself needs to grow.

**Option B — change the driver to skip non-fitting keys.** If the
natural trie key is not exactly 32 bytes (or whatever fixed width the
apply path expects), the driver should return `None` for that
`challenge_index` rather than producing a response that can never be
verified. This collapses to "no challenge responses" but doesn't pretend
to credit ungrounded ones.

**Option C — fix the challenge keyspace to match the trie key shape.**
Derive challenges over the 26-byte (or whatever the canonical message
key length is) namespace explicitly. Pair this with making `served_key`
match the natural trie-key width on the wire (variable-length encoded).

In any case, both sides of the wire MUST agree on the natural width and
the test suite MUST exercise an end-to-end produce → apply round-trip
against a real-shaped trie key (e.g. an actual `for_message` key in the
trie via `merge_message`, not an artificial 32-byte one).

## Variant-class checks

- **F132 read-after-write:** N/A here. The driver and apply path don't
  share a `RocksDbTransactionBatch`; each apply is a single-call commit.
  H134 already cleared this for the apply side.
- **F133 direct DB writes during simulate:** N/A. The driver doesn't
  write to the DB; it only reads (via `trie_values_with_prefix`) and
  emits responses through `runtime.submit_message → actor outbound`.
- **Validator divergence on the challenge derivation:** Negative. All
  validators with the same boundary seed compute the same 16-byte
  prefix. Disagreement on the produced response across validators
  reduces to disagreement on the trie state at boundary time, which is
  consensus's job to keep coherent. The bug here is identical across
  all validators (everyone fails to credit), so it's not a fork-causing
  defect — just a uniform incentive collapse.
- **Restart safety / double-credit:** The driver's
  `last_da_responded_epoch` is in-memory only (`actor.rs:966`). On
  restart, the actor re-submits responses for the current epoch.
  Apply-path duplicate detection (`runtime.rs:3110-3120`) gates the
  marker, so re-submits are silently rejected (logged at debug,
  `actor.rs:2170-2175`). No double-credit. (And no SINGLE credit
  either — see above.)
- **Cross-shard / cross-chain replay:** Closed by chain_id binding in
  both `derive_challenge_prefix` and `da_response_signing_payload`
  (cleared in H134 ruling).
- **Eligibility bypass:** The validator-fid binding gate (`runtime.rs
  :3049-3064`) is solid (cleared in H134 ruling), so a non-validator
  cannot earn DA credit. But the eligibility gate is moot when
  contains_key rejects every legitimate response anyway.

## Cross-references

- **H134 (ruled out)** — protocol-encoding side of DA-PoW. H134's
  conclusion explicitly noted: "Driver-side concerns (e.g. the
  zero-padded 32-byte `served_key` not matching a short-key trie entry
  at apply-time `DaTrieLookup` → silent miss + unanswered challenge)
  are deferred to H135's scope on `da_pow_driver.rs`." This finding
  realises that deferral as a HIGH driver-side bug.
- **F132** (HIGH, fee-trust-uniqueness-flow on `RewardStore::stage_charge_message_fee`) — different root cause (read-after-write in a shared txn batch). Not implicated here.
- **F133** (CRITICAL, fingerprint-store direct DB writes during simulate) — different root cause (RPC-driven side effects bypassing consensus). Not implicated here.
- **F012** (HIGH, retro-vesting bypasses budget cap) — related family (reward-issuance silent misallocation), but separate channel.
