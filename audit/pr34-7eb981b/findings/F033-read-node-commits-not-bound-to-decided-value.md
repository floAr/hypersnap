---
finding_id: F033
title: The read-node path checks that a decided value's `Commits` carry a valid quorum, but never checks that those commits are for that value
severity: high
status: validated
validation:
  verdict: HAS_CAVEATS
  confidence: 0.8
poc:
  path: poc/F033
  kind: build-backed
  result: 4/4
related_findings:
- F022
- F027
- F040
---
# F033 — The read-node path checks that a decided value's `Commits` carry a valid quorum, but never checks that those commits are for that value. `commits.value.hash` is never compared with `block.hash`/`chunk.hash`, and `commits.height` is never compared with the header height. Any gossip peer can wrap a genuine `Commits` from any past block around a header and body it chose itself. That lets it (a) make every pre-pivot Hypersnap node exit with one message (a bad `header.version`, or a chunk timestamp 60 days past the schedule horizon), (b) kill a shard's ReadHost actor (a root mismatch panics in `commit_shard_chunk`), or (c) commit a self-consistent forged chunk or block, for example with fabricated on-chain events, which the pre-pivot engine merges without any check.

> **Status (2026-11-04):** Severity **High** (validated 0.8, HAS_CAVEATS). PoC: poc/F033 (build-backed, 4/4). State: validated. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity High (validated). PoC: poc/F033 (4/4). **Correction:** the chunk-timestamp staleness exit (`read_validator.rs:276-322`) is dormant at 7eb981b **for attackers as well as honest time**: its guard needs `version_for(ts) == latest()` (V23), and no mainnet or testnet timestamp maps to V23. Attack (a) rests on the block `header.version` exit (`validate_protocol_version`), which works. The duplicate-signer counting was introduced by the PR (now F040), not inherited from snapchain.


- **Severity:** High. No keys or stake are needed: one gossip frame on the `decided-values` topic, or a sync response, with `Commits` copied from any block. Before the epoch-1 pivot every Hypersnap node, the future bootstrap validators included, runs this read path (`node/snapchain_read_node.rs`). (a) stops every such node on demand and again after each restart, so the network cannot reach the pivot while the attack lasts. (c) puts forged history into the state that the node later uses for its genesis (PivotRecord, Keccak roots, PoQ social graph). That fails loud at the pivot vote, but poisoning more than 1/3 of the bootstrap validators halts the pivot. The forged state is also served by the node's API.
- **Category:** missing-validation / authentication bypass (signature over X accepted for Y)
- **Specialist:** consensus-malachite-tendermint · attack class: read-validator-protocol-version · task H020
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). The missing binding in `core/util.rs::verify_signatures` and in the commit/buffer flow already exists at the merge-base `bdef7b7`, so this is snapchain heritage (since fixed upstream by snapchain #1089, `7ee2f53`, which this fork does not carry). In-diff code makes it worse and claims to fix it. The diff adds `validate_block_hash_matches_header` (`read_validator.rs:203-227`), whose comment ("once we've verified the quorum signed `commits.value.hash`, this check binds it to the actual header") assumes a comparison that does not exist. The diff also adds the shard-chunk `ExitWithError` heuristic (`read_validator.rs:258-318`) and the pivot guard, which makes this read path the producer of genesis input.
- **Trigger:** gossip `ReadNodeMessage::DecidedValue` (`gossip.rs:1774-1787` → `main.rs:705` → `snapchain_read_node.rs:226-243` → `read_host.rs:79-80` → `ReadValidator::process_decided_value`), or a read-sync `ValueResponse` (`read_sync.rs:368-384`). Neither path authenticates the sender beyond libp2p peer signing.

## Code facts

1. **`verify_signatures` checks only that the `Commits` are internally consistent.** It builds the certificate from `commits` (`util.rs:112`). It picks the set by `certificate.height` (`:123`), checks the quorum on `signatures.len()` (`:133-139`), and verifies each signature over `Vote::new_precommit(certificate.height, certificate.round, certificate.value_id, ..)` (`:141-167`). It never receives the block or chunk, so it cannot compare `certificate.value_id.hash` with the value's hash, or `certificate.height` with the header height.
2. **The caller does not compare them either.** `ReadValidator::verify_signatures` passes only `shard_chunk.commits` / `block.commits` (`read_validator.rs:182-195`). `process_decided_value` (`:336-380`) then runs: height from the header (`:337`); shard/engine match (`:341`); `verify_signatures` (`:345`); `blake3(header) == value.hash` (`:360`, which the attacker satisfies by recomputing `hash`); `validate_protocol_version` (`:369`); and the commit or buffer by header height (`:374-409`). No step relates `commits.value` or `commits.height` to the value. A repo-wide grep for `commits.value`/`value_id.hash` finds no such comparison on the read path.
3. **Forged headers reach two `ExitWithError` calls before any height check.** Block: `header.version != version_for(timestamp)` → `SystemMessage::ExitWithError` (`read_validator.rs:230-255`). Chunk: `timestamp > horizon + 60 d` → `ExitWithError` (`:258-318`, new in this diff). `main.rs:708-714` turns `ExitWithError` into a process exit. Both run for a value at any height, including one that is already committed, because the height comparison comes later (`:374`).
4. **A forged chunk at `last_height + 1` is committed.** `commit_shard_chunk` (`storage/store/engine.rs:3629-3708`) replays the attacker's transactions. On a root mismatch it panics (`:3703`). Its own comment says this "stops the ReadHost actor … the shard stays dead". If the attacker sets `shard_root`/`account_root` to the values it computed over the public pre-state, the replay succeeds. Pre-pivot (`hypersnap_mode == false`), on-chain events in `system_messages` are merged with no view check (`engine.rs:2035-2090`; `hypersnap_onchain_check` runs only in Hypersnap mode). So an attacker can fabricate `IdRegister`/`SignerAdd` events, giving any FID a new custody address or signer. When the genuine value arrives later, it is dropped as "height is too low" (`read_validator.rs:404-412`).
5. **The buffer is overwritable.** `buffered_blocks.insert(height, value)` (`:376`) replaces an honest buffered future value with a forged one for the same height.
6. **Secondary flaw:** the quorum counts `signatures.len()` and allows duplicate signers (`util.rs:133-167`). One validator's precommit repeated n times meets the threshold. With fact 1 this is not needed, but it should be fixed in the same change.

## Attack

1. The attacker joins gossip as an ordinary peer (any libp2p identity) and subscribes to `decided-values/<shard>`.
2. **Kill switch:** for shard 0 it publishes `Block` B' (fact 3) built from any historical block. Every pre-pivot Hypersnap/snapchain read node on the topic exits. The attacker repeats this whenever a node restarts. Applied in the weeks before `PIVOT_HEIGHT`, this stops the bootstrap validators from ever writing the pivot marker (`after_commit`, `read_validator.rs:107-128`).
3. **Forgery:** when a target node is at `last_height = H-1` (from `ReadNodePeerStatuses` or timing), the attacker takes the genuine `Commits` of any block and sends a chunk at height H. That chunk drops chosen user messages and adds fabricated on-chain events, with roots computed on its own replica. The target commits it and diverges for good. The divergence shows only at the pivot (PivotRecord mismatch → prevote nil) or to API users.

## Red-team (invalidation hypotheses walked)

1. *Is the hash checked against `commits.value` somewhere upstream of `process_decided_value`?* No. `dispatch_decided_value` only drops `HypersnapBlock` and routes by header shard (`snapchain_read_node.rs:226-243`). `read_sync` decodes `value_bytes` and casts it without looking at `value_response.certificate` (`read_sync.rs:368-384`).
2. *Does `commits.height` → validator-set lookup save it?* No. It selects the set for the *commit's* height, and genuine commits pass for their own height.
3. *Does gossip restrict who can publish decided values?* No. Only libp2p message signing applies (`ValidationMode::Strict`), and there is a size cap (`gossip.rs:1777-1786`).
4. *Is the exit really reachable before the height check?* Yes. `validate_protocol_version` runs at `:369` and the height branching at `:374`.
5. *Is (c) blocked by the state-root check?* Only when the attacker sends wrong roots, and then the actor panics instead (still a DoS). The attacker can compute the right roots because the pre-state is public chain state.
6. *Post-pivot nodes?* Not affected. Hypersnap blocks are rejected on this path (`read_validator.rs:188-190`, `snapchain_read_node.rs:228-231`), and post-pivot certificates are bound to the block (`shard_blocks.rs:500-511`, `shard0/engine.rs:1052-1061`). The issue is pre-pivot only.
7. *Is it out of scope because it predates the PR?* The root cause does predate it. But the PR adds an incomplete "fix" that documents the binding as present, adds a new exit path, and makes this path the source of genesis input. It is reported with that scope note.
8. *Duplicate of F021/F027/F028?* No. Those cover the DA checkpoint dependency and genesis snapshot/validator-hash verification, not the read-node decided-value ingress.

## Recommendations

- In `ReadValidator::process_decided_value` (or in `verify_signatures`, by passing the value), require `commits.value == ShardHash{shard_index: self.shard_id, hash: value.hash}` and `commits.height == header.height` before anything else, and do it before `validate_protocol_version`.
- Count distinct signers for the quorum (dedupe by address, or reject duplicates). Use voting power, not the count.
- Never call `ExitWithError` based on data that is not bound to a verified certificate. Even when it is bound, consider a halt-and-alert instead of an exit triggered by peer data.
- Do not overwrite an existing `buffered_blocks` entry with a different value. Keep the first verified one.
- Add a regression test: genuine `Commits` from height H wrapped around a different header must be rejected.

## Addendum (2026-11-04): the staleness exit is dormant today and re-arms when V23 is scheduled

- At `read_validator.rs:276-322` the pre-pivot read node exits (`ExitWithError`) once a chunk timestamp is more than 60 days past the binary's latest schedule `active_at`. The guard at `:284` also requires `version_for(ts) == EngineVersion::latest()`.
- `latest()` is the largest enum value, V23. The mainnet and testnet schedules end at V22 (`version.rs`, mainnet 2026-10-23 12:00 UTC). **At `7eb981b` the honest-time exit can never fire on mainnet or testnet.** The same guard makes the chunk-timestamp exit unreachable for an attacker too (no mainnet or testnet timestamp maps to V23). The attacker exit that still works is the block `header.version` check (`validate_protocol_version`) reached through the unbound `Commits`.
- **It re-arms the moment a V23 mainnet entry is added.** Every binary that carries that entry exits on pre-pivot read nodes at that entry's date + 60 days, unless it has been replaced first. Nothing here needs an attacker. The dormant guard also means the PR's "F011 fix" gives no protection today.
- Recommendation: tie the horizon check to the schedule entry, not to `latest()`. Replace the exit with halt-and-alert. Document the 60-day upgrade deadline in the release notes for any release that schedules V23.
- Source: the internal validation notes, verified by the coordinator at `7eb981b`.
