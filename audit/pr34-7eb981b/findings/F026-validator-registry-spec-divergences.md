---
finding_id: F026
title: 'Validator registry rules differ from FIP §4.1/§4.5/§4.6/§4.8 in several places: who may deregister, multiple seats per FID, `INACTIVE`'
severity: low
status: pending-validation
related_findings:
- F010
- F024
- F025
---
# F026 — Validator registry rules differ from FIP §4.1/§4.5/§4.6/§4.8 in several places: who may deregister, multiple seats per FID, `INACTIVE` reactivation, the extra transition type, and the set recurrence.

- **Severity:** Low (spec-divergence bundle. None of these breaks safety alone. Items 2 and 4 feed F024/F025.)
- **Category:** spec-divergence
- **Specialist:** pivot-genesis-epoch · task H015
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). Spec: `docs/spec/FIP-proof-of-work-tokenization.md`.

| # | Spec | Code | Side that looks wrong |
|---|------|------|-----------------------|
| 1 | §4.5: "For a deregistration … A signature by the LWE key or by the custody key is sufficient." | `deregister` accepts `Role::AccountKey` or `Role::NodeKey` whose hash equals the record's `node_key_hash`. It does **not** accept the consensus key (`src/chain/shard0/validators.rs:270-278`). | Spec, or else the code. The node key is the hotter key (DA responses, attestations). If it leaks, an attacker can deregister the validator. Decide which key should be allowed and align the two. |
| 2 | §4.9: "Each validator has a weight of 1". The credibility gate (§4.5) applies per FID. Nothing says how many validators one FID may run. | One FID may register up to `MAX_NODES_PER_FID` = 3 validators, one per attested node key, each with weight 1 (`validators.rs:62-64, 204-208, 126-137`). | Spec silent. Code triples FID-level weight (see F024). |
| 3 | §4.8: an auto-deregistration that would break `MIN_VALIDATORS` marks the validator `INACTIVE`, and it stays. The spec says nothing about reactivation. | A `VALIDATOR_REGISTER` of an `INACTIVE` key clears `inactive` and `consecutive_missed` at once (`validators.rs:213-222`). The comment cites §4.8, but §4.8 has no such rule. | Spec incomplete. Code adds an unspecified state transition (same reset problem as F025). |
| 4 | §4.1: `set(N) = set(N-1) + registrations(N-2) - deregistrations(N-2)`. | `set(e+1)` is rebuilt from the registry (`write_set_record`, `boundary.rs:33`). It also reflects auto-deregistrations, their cancellation (§4.7), and `INACTIVE` members that stay. | Spec formula is incomplete. The code is the more accurate model. |
| 5 | §4.6 `TransitionType` = NONE/DEPARTING/JOINING/DELAYED. | Proto adds `TRANSITION_INACTIVE = 4` (`proto/definitions/hypersnap.proto:126`), and `transitions.rs:31-32` emits it. | Spec missing the value (§4.8 "a gossip alert asks new validators to register"). |
| 6 | §4.5: age/trust are registration conditions. | They are checked only at registration. A seat stays after the FID's trust falls below `min_validator_trust_score`, because `apply_scoring_result` rewrites trust but never touches validators. | Spec silent. State whether credibility is a continuing condition. |
| 7 | §4.5/§4.9 field names `lwe_consensus_key`, `lwe_key_hash`. | Code uses `consensus_key` / `consensus_key_hash` (Falcon-512, not LWE). Already noted by H009 for the `set_root` leaf. | Spec stale (see F010). |

Minor code note (self-harm only): `node_attestation_revoke` blocks revocation only for validators with `leave_epoch == 0` (`validators.rs:95-97`). A deregistering validator, which is still a member for one more epoch, can therefore lose its node attestation. A later cancel (F025) keeps the stale `node_key_hash` without checking that it is still attested.
