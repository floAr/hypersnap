---
id: H001
specialist: chain-economics
attack_class: false-slash-via-unverified-evidence
commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
f001_status: resolved
outcome: ruled-out
---

# H001 — F001 (false-slash via unverified evidence) is RESOLVED

PR #34 fully closes F001. The original Critical (slashing-evidence ingestion
accepting unsigned blocks) is fixed, and the classic incomplete-fix variant
(ingest verifies but enforcement trusts persisted data writable through a
second path) does **not** apply here, because the store has exactly one
verified write path.

## Trace: ingestion → persistence → epoch-boundary read → penalty

### 1. Ingestion is gated (single production write path)
`src/hyper/actor.rs:1587-1620` — `HyperActorEvent::InboundEvidence`:
- `detect_conflicting_blocks` (1588) confirms a real conflict.
- `verify_evidence_signatures(&evidence, |epoch| dkls_group_address_for_epoch(epoch))?`
  (1605-1607). The `?` propagates on failure, so `record_evidence` (1608) is
  unreachable for evidence that fails sig-verify. Unknown epoch group key →
  `UnknownEpochGroupKey` error → also aborts before persistence.
- All inbound evidence (incl. gossip, `gossip_adapter.rs:96-102`) funnels
  through this one handler; the wire `Evidence` body only ever becomes an
  `InboundEvidence` event, never a direct store write.

### 2. verify_evidence_signatures cryptographically binds signer_indices + epoch
`src/hyper/slashing.rs:89-111` verifies each block's threshold ECDSA sig
against its own epoch's group address. The signed payload
(`src/hyper/mod.rs:403-452`, `signing_payload`) commits BOTH:
- `epoch` (line 407), and
- `signer_indices` (F153 fix, lines 439-450, sorted+length-prefixed).

So an attacker cannot malleate `signer_indices` or `epoch` on captured
evidence without invalidating the group signature. `sig_verify.rs:46-78`
fails closed on missing/short sigs and on declared-vs-expected group-address
mismatch.

### 3. Persistence — only verified evidence reaches the store
`src/hyper/runtime.rs:4156-4161` `record_evidence` → `slashing_store.record`
(`src/hyper/slashing_store.rs:50-71`). The sole DB writer to
`RootPrefix::HyperSlashingEvidence` is `slashing_store.rs:69`. No snapshot
restore / bulk-import / raw-put path writes that prefix (verified by grep over
`src/hyper` for `db.put`/restore/snapshot writers). Therefore the store cannot
contain a row whose `signer_indices` were not group-signed.

### 4. Epoch-boundary read + penalty
`src/hyper/runtime.rs:4055-4105` `get_active_validators_enforced` →
`slashed_validators_for_epoch(prev, ...)` (4074-4076) → evicts those keys from
the active set (4090). `slashed_validators_for_epoch`
(`src/hyper/runtime.rs:4191-4229`) reads persisted `HyperWireEvidence` and
walks `sig.signer_indices` (4217) **without re-verifying** the signature.

This read-side trust is the textbook incomplete-fix shape, BUT it is **not
exploitable here**: the only data it trusts (`signer_indices`, `epoch`) was
cryptographically committed at the single gated ingestion point, and there is
no alternate path to plant a forged row. An attacker has no primitive to write
attacker-chosen `signer_indices` into the store.

## Residual (non-exploitable) observations — defense-in-depth only
- The enforcement reader does not re-verify persisted evidence
  (runtime.rs:4191-4229). Harmless given the single verified writer, but a
  belt-and-suspenders re-verification (resolve group key per block-epoch, re-run
  `verify_evidence_signatures` on decode) would harden against any *future*
  second write path (e.g., a state-sync importer of `HyperSlashingEvidence`).
- `encode_block` (slashing_store.rs:171-196) zeroes `missed_proposals` and the
  snapchain anchor/range fields on persist, so the persisted block is NOT
  re-verifiable as-is. This is fine today (enforcement reads only
  `signer_indices`), but it means a future re-verification at read time could
  not use the stored bytes directly — relevant if anyone later adds that
  hardening.

## Verdict
F001 resolved. No false-slash primitive exists: unsigned/forged evidence is
rejected at the sole ingestion point, `signer_indices`+`epoch` are sig-bound,
and the store has a single verified writer feeding the enforcement reader.
