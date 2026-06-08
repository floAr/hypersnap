# F025 trace — committee-index grinding via attacker-chosen validator_key

Commit pinned: `cab225f`. Code is READ-ONLY; verdict from `findings/notes/F025-validation.md` (HAS_CAVEATS, 0.78) is not re-judged here.

This trace covers two reachability legs that compose:
- **Leg A (registration ingress → persisted index slot):** how an attacker gets an attacker-chosen 32-byte `validator_key` into the active set at a chosen lexicographic position.
- **Leg B (per-epoch seed → committee selection → index→validator map):** how that position deterministically wins a committee slot for a predictable target epoch/ceremony.

## Entry point(s)

- **Registration ingress (Leg A entry):** gossip wire decode
  `code/hypersnap/src/hyper/gossip_adapter.rs:79`
  (`hyper_wire_message::Body::Message(m) => HyperActorEvent::InboundMessage(m)`)
  → actor dispatch `code/hypersnap/src/hyper/actor.rs:1215` (`InboundMessage`) and the
  local-submit twin `code/hypersnap/src/hyper/actor.rs:1225` (`LocalSubmitMessage`).
  The carried `proto::HyperMessage` body is a `ValidatorEvent` whose `validator_key`,
  `fid`, and `event_type` are all attacker-chosen fields on the wire.
- **Ceremony seed/selection (Leg B entry, internal/consensus-driven):** each epoch-boundary
  ceremony and the block path call `select_signing_committee` with a public, predictable
  seed — block path `code/hypersnap/src/hyper/actor.rs:2657-2665`; epoch-tag ceremonies
  `actor.rs:3055`, `:3080`, `:3216`, `:3284`, `:3357`. These are not attacker-invoked;
  they are the sink the attacker pre-positions for.

## Trust boundary crossed

Untrusted gossip peer → validator-registration authorization layer. The boundary that is
*supposed* to gate this (EIP-712 custody cross-sign + per-FID cap in
`validate_and_check_quota`) is bypassed: the production router is built with no custody
resolver, so `route_inbound` takes the lenient `validate_event(.., None)` branch
(`code/hypersnap/src/hyper/router.rs:165-167`), which skips custody verification entirely
(the `has_custody` block at `validator_registry.rs:406-409` only runs if the attacker
*chooses* to attach a custody sig and a resolver supplied an address). This is exactly the
F070 gap; F025 rides on it. The only remaining check is `verify_event_signature`
(`validator_registry.rs:403-404`), which merely proves possession of the (ground) Ed25519
private key, plus a default-off trust floor.

## Call path (ordered file:line hops)

Leg A — get the chosen key into the active set at a chosen sort position:
1. `code/hypersnap/src/hyper/gossip_adapter.rs:79` — decode inbound `ValidatorEvent` from gossip.
2. `code/hypersnap/src/hyper/actor.rs:1218` — `dispatch(InboundMessage)` → `runtime.submit_message(msg)`.
3. `code/hypersnap/src/hyper/runtime.rs:3882` — production router constructed **without** `.with_custody_resolver(...)` (F070); `custody_resolver == None`.
4. `code/hypersnap/src/hyper/router.rs:165-167` — `custody_resolver` is `None` ⇒ lenient `ValidatorRegistry::validate_event(&event, epoch, None)`.
5. `code/hypersnap/src/hyper/validator_registry.rs:375` — only enforces `validator_key.len()==32`; `:403-404` verifies self-sig (possession only); custody check at `:406-409` skipped.
6. `code/hypersnap/src/hyper/router.rs:169` — `registry.record_event(&event)` persists the Register event and the `validator_key → fid` binding.
7. `code/hypersnap/src/hyper/validator_registry.rs:674` — `compute_active_set` (replayed at epoch boundary, cutoff at `:686`) admits the persisted key into the active `BTreeMap<Vec<u8>,_>` keyed on raw `validator_key` bytes.

Leg B — chosen sort position deterministically wins a committee slot:
8. `code/hypersnap/src/hyper/dkls_committee.rs:110-117` — `committee_seed_for_epoch(epoch, tag)` (or `committee_seed_for_block`, `:119-127`): seed depends only on consensus-pinned public values; attacker computes it offline.
9. `code/hypersnap/src/hyper/dkls_committee.rs:53-89` — `select_signing_committee` ranks abstract indices `1..=share_count` via `rank_for(epoch,digest,i)=keccak256("hypersnap-dkls-committee-v1\0"||epoch||digest||i)`; **no validator identity input**. Lowest-`threshold` indices win. Winning index set is a pure function of public values.
10. `code/hypersnap/src/hyper/dkls_supervisor.rs:194-201` — `for (i, vk) in active.keys().enumerate() { if vk==local … own_idx=Some((i+1)) }`: `party_index` = 1-based lexicographic position of the raw key bytes. Attacker's ground key lands on the precomputed winning index `w`.
11. Sink: `code/hypersnap/src/hyper/actor.rs:2666` (`committee.contains(&local_party_index)`) and the epoch-tag equivalents — the winning index is the authoritative signer; the bound `signing_payload(epoch,&committee_indices)` (F153) recomputes to the same digest, so occupying the index *is* the authorization.

## Attacker capability / preconditions

- Network access to gossip a `ValidatorEvent` (or local submit) — no peer authentication of the inner registration fields required for Leg A given the F070 wiring gap.
- Ability to grind Ed25519 keypairs offline (one keygen per attempt) and read the public registry to know the other active keys (so the target sort position is computable, not blind brute force). Joint placement of multiple sybils must account for self-shifts in the sort order (validation H8).
- Sybil FIDs: per-FID cap is 3 (`validator_registry.rs:24`) but is enforced only on the dead strict path; attacker names arbitrary FIDs. A non-default `min_validator_trust_score > 0.0` would require naming FIDs meeting the floor but never establishes custody authorization.
- Long lead time: `EPOCH_LENGTH=432_000`, `EPOCH_BUFFER=1` (`epoch.rs`); active set at epoch N reflects events ≤ N−2, so epoch-tag ceremonies are predictable arbitrarily far ahead.

## Guards on the path

- `validate_event` (`validator_registry.rs:367-411`): enforces 32-byte key, epoch match, present signature, and Ed25519 possession — **none constrains the key bytes** against an unpredictable beacon. Custody/quota guard (`validate_and_check_quota`) is unreachable in production (F070).
- `committee_seed_for_epoch/_for_block`: F036 made the seed non-grindable, but the index→key map (`dkls_supervisor.rs:194-201`) has **no shuffle/VRF/commit-reveal** mixing the seed into the assignment — the guard F036 added does not cover this leg.
- `select_signing_committee` parameter guard (`dkls_committee.rs:59`): only rejects `threshold==0 || threshold>share_count`; no identity binding.

## Reachability verdict

**REMOTE-UNAUTH** (Leg A registration ingress), composing into deterministic committee capture.

Justification: the registration entry point is reachable by any gossip peer; under the shipped production wiring the custody/quota authorization gate is never invoked (F070), so an attacker submits a Register event with a ground 32-byte `validator_key` under an arbitrary FID using only a self-signed Ed25519 sig. No committee membership, validator key custody, or operator credential is needed to *enter*. The grind then deterministically places the sybil on a predictable winning index. The downstream signer-authority sink (`actor.rs:2666` et al.) is consensus-driven, not attacker-invoked, so the attacker's role is pre-positioning, not triggering — the leg that crosses the trust boundary is REMOTE-UNAUTH.

**Validator caveat (per finding + F028):** production hard-pins `dkls_threshold = 1u8` (`main.rs:1603`, F028). With threshold=1 each committee is size 1, so the threshold-security assumption is already void independent of grinding; F025's *marginal* value in the shipped config is **deterministic targeting of the lone winner** (the attacker guarantees its own sybil is that single signer for a chosen epoch/ceremony) rather than holding a 1/N chance. The strong, independent "assemble a full threshold-of-N quorum" impact is realized only in the intended t>1 regime.

---
Return: `F025 | entry=gossip_adapter.rs:79 → actor.rs:1218 (ValidatorEvent registration ingress) | reachability=REMOTE-UNAUTH | unauth gossip registers ground validator_key (F070 gate bypass); grind lands sybil on predictable winning index; under shipped t=1 (F028) buys deterministic targeting of the lone signer.`
