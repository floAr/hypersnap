---
finding_id: F020
title: The proposal size budget does not reserve room for the block's own commit certificate
severity: medium
status: pending-validation
related_findings:
- F018
- F019
---
# F020 — The proposal size budget does not reserve room for the block's own commit certificate. A byte-full shard-0 block is decided normally, but its stored form (block plus `certificate`) can be over `MAX_BLOCK_BYTES`, and sync rejects it. New or lagging nodes cannot pass that height.

- **Severity:** Medium (permanent sync failure at one height for every node that has to fetch it; live validators are not affected). It needs a byte-full block, meaning the size budget is the binding limit, and a certificate bigger than the remaining slack. With bundled Falcon signatures that is about 6 or more signers. A full block happens under load, at the `ScoringResult` height (F019, even when that block is under the limit itself), or when an attacker pads messages (F018's padding technique, ≤ 256 KiB each so that it gossips).
- **Category:** proposer-validator-divergence (resource limit) / sync-liveness
- **Specialist:** shard0-ledger-state · attack class: proposer-validator-divergence · task H016
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** None. This is reasoned from source. A harness test would `propose` with `max_block_bytes` filled, attach a certificate with s signers, and call `check_structure` on it.

## Code facts

1. **Propose budget.** `room = max_block_bytes − (BLOCK_RESERVE_BYTES (4096) + field_len(parent_certificate) + Σ field_len(system))` (`engine.rs:747-757`). Items are added while `field_len(item) <= room`. The comment on `BLOCK_RESERVE_BYTES` says it covers "the header, the hash and the field tags" (`engine.rs:129-131`). It does not mention the block's own `certificate` (field 5).
2. **Decide attaches the certificate.** `Shard0Proposer::decide` sets `block.certificate = Some(cert)` and commits. The store keeps that form (`shard0/proposer.rs:253-256`; `engine.rs:1132`).
3. **Sync serves and checks that form.** `get_decided_value` returns `block.encode_to_vec()` of the stored block, certificate included (`shard0/proposer.rs:268-279`). The receiver runs `add_synced_value` → `check_value(_, synced = true)` → `check_structure` → `validate_body`, and `validate_body` rejects `block.encoded_len() > MAX_BLOCK_BYTES` (`chain/proposer.rs:388-393`; `shard0/proposer.rs:72-74`; `block.rs:155-159`).

## Slack versus certificate size

- Header ≈ 420 B (15 fields, 2 shard links of ~78 B), plus header wrapper and `hash` ≈ 40 B. Slack from the reserve ≈ **3.6 KB**. Add +1 B per item, because `field_len` counts a 2-byte tag where fields 3 and 4 use 1 byte, and add the packing gap.
- Own certificate: ~60 B of fixed fields and bitmap, plus **669 B per signer** (`BundledSignatures`, Falcon-512 `SIGNATURE_LEN = 666`, `hypersnap-falcon/src/keys.rs:20`). With ≥ 2/3 of the set signing, s = 6 already gives ~4.07 KB.

So a full block made of a few large items (a big `ScoringResult`, padded or large messages, many watcher items) exceeds 16 MiB once the certificate is attached, for any set with about 7 or more members. A full block of thousands of small messages gains about 1 B per message of extra slack and usually fits. Shard-0 message pulls are capped at `PULL_BYTES` = 15 MiB (`hypersnap_node.rs:306`, `block.rs:35`), so a full block needs ≥ ~1 MiB of system or watcher content, or the scoring block. That is why this finding is Medium and not High.

## Impact

Live validators commit from `pending` or re-execute in `Mode::Commit` and never re-check the size, so the chain keeps going. Every node that later has to sync that height gets `Validity::Invalid` from every peer and stops there for good. That includes new nodes, read nodes, and validators that restart behind the tip. Validators that cannot rejoin wear down the active set over time. If enough of them go down, the result is a shard-0 halt.

## Red-team walk

1. *Is the certificate excluded from `validate_body`'s size?* No. It measures `block.encoded_len()`, and `certificate` is field 5 of `HypersnapBlock`.
2. *Does sync strip the certificate before checking?* No. `hypersnap_block()` decodes the bytes as served.
3. *Is `parent_certificate` the same thing?* It is reserved, but it belongs to the parent. The block's own certificate comes on top of it, at about the same size.
4. *Does the transport cap reject it first?* No. `HYPERSNAP_MAX_VALUE_BYTES = MAX + 1 MiB` lets it through, so `validate_body` is what rejects it.
5. *Aggregate (R2) certificates?* With a small aggregate the overflow goes away. The code at this commit uses `bundled`, which is F010's subject.

## Recommendation

Reserve the worst-case own-certificate size (`669 × |set| + 64`) in `room`. Alternatively, have `validate_body` measure the block without `certificate` and `aggregate_certificates`, and bound the certificate separately.

## Evidence

- `src/chain/shard0/engine.rs:129-136, 747-757`
- `src/chain/shard0/proposer.rs:72-88, 243-279`; `src/chain/proposer.rs:386-393`
- `src/chain/block.rs:11, 35, 155-159`; `proto/definitions/hypersnap.proto:62-96`
- `crates/hypersnap-falcon/src/keys.rs:20`; `src/node/hypersnap_node.rs:303-307`
