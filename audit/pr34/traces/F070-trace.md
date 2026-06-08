# F070 trace — custody-sig gate unwired in production router

Commit `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9` (verified `git rev-parse HEAD`).
Trace only; verdict unchanged (WATERPROOF, High).

## Entry point(s)

- `code/hypersnap/src/hyper/actor.rs:1218` — `HyperActor::dispatch`,
  `HyperActorEvent::InboundMessage(msg)` arm → `self.runtime.submit_message(msg)`.
  This is the gossip ingress: a `HyperMessage` deserialized off the wire from any
  network peer.
- `code/hypersnap/src/hyper/actor.rs:1230` — same dispatch,
  `HyperActorEvent::LocalSubmitMessage(msg)` arm → `self.runtime.submit_message(msg.clone())`
  (local RPC submit; also re-broadcast).

Both deliver an attacker-crafted `proto::HyperMessage` whose body is
`Body::ValidatorEvent(HyperValidatorEventBody)` with `event_type = Register`.

## Trust boundary crossed

Untrusted network/RPC input → persistent validator-registry authority state in
RocksDB (`HyperValidatorFidLookup[vk] → fid`, `HyperValidatorByFid[fid][vk]`).
The crossing point is `route_inbound`'s ValidatorEvent arm, where the only
authorization decision for "may this key be registered under this FID" is made.
The intended authorization proof is the EIP-712 custody cross-signature; it is
not enforced on this path.

## Call path (ordered hops)

1. `actor.rs:1218` — `HyperActor::dispatch` (InboundMessage) — forwards the gossip
   message verbatim to `runtime.submit_message`. No auth here (only metric
   observers `observe_validator_event` / `observe_inbound_message_kind`).
2. `runtime.rs:3664` — `HyperRuntime::submit_message` — ValidatorEvent is NOT
   early-intercepted (unlike RewardIssuance/Transfer/Miniapp*, which return early),
   so control falls through to the router-construction tail.
3. `runtime.rs:3855` — `submit_message` trust-floor pre-gate —
   `if self.min_validator_trust_score > 0.0 { … }`. Default `0.0`
   (`config.rs:526`), so the entire block is skipped. Even when enabled it only
   compares the *claimed* FID's trust score against the floor — it never checks
   custody authorization.
4. `runtime.rs:3882` — `submit_message` builds the router:
   `HyperRouter::new(take(mempool), Some(validator_registry.clone()), current_epoch)`.
   No `.with_custody_resolver(...)` is chained ⇒ `custody_resolver = None`
   (set in `router.rs:111`).
5. `runtime.rs:3887` — `router.route_inbound(msg)`.
6. `router.rs:157` — `HyperRouter::route_inbound`, `Body::ValidatorEvent(event)`
   arm — fetches `self.registry` (present), then at `router.rs:165` matches
   `self.custody_resolver.as_deref()`. `None` ⇒ takes the lenient branch
   `router.rs:167`: `ValidatorRegistry::validate_event(&event, current_epoch, None)`.
   (The strict `Some(r) => validate_and_check_quota(...)` at `router.rs:166` is
   never taken — see dead-code note.)
7. `validator_registry.rs:367` — `ValidatorRegistry::validate_event(event, epoch, None)`
   — checks event_type ≠ None, validator_key len 32, registration_epoch == epoch,
   and (Register) validator_address len 20 / transport_pubkey len 32. Signature
   logic at `validator_registry.rs:397-410`: requires at least one of ed25519 /
   custody sig present; verifies ed25519 if present (`verify_event_signature`);
   verifies custody sig ONLY `if has_custody` (non-empty) AND `custody_address`
   is `Some`. With resolver `None` the custody address is `None`, and the
   attacker simply leaves `custody_signature` empty, so the `has_custody` block
   is skipped. Only `verify_event_signature` runs.
8. `validator_registry.rs:172` — `verify_event_signature(event)` — verifies the
   Ed25519 signature over the canonical event bytes using
   `event.validator_key` as the public key. This is a self-signature: it proves
   the attacker holds the validator key they themselves generated; it binds
   nothing about `event.fid`. `fid` is an attacker-controlled field.
9. `router.rs:169` — back in `route_inbound`: `registry.record_event(&event)`.
10. `validator_registry.rs:541` — `ValidatorRegistry::record_event` — writes
    directly to `self.db` (RocksDB) at ingestion: the event blob
    (`make_event_key`), and for Register `HyperValidatorByFid[fid][vk] = []`
    (`validator_registry.rs:551`) and `HyperValidatorFidLookup[vk] = fid.to_be_bytes()`
    (`validator_registry.rs:554`). Sink reached: an arbitrary validator key is
    now bound to an arbitrary, attacker-chosen FID with no custody proof.

## Dead-code gate (why the strict path never runs)

- `HyperRouter::with_custody_resolver` (`router.rs:115`) — the only way to set
  `custody_resolver = Some(_)`. Full-tree grep for `.with_custody_resolver(` →
  zero call sites (only the definition + doc comments at `router.rs:100,164`).
- `validate_and_check_quota` (`validator_registry.rs:421`) and
  `validate_register_with_trust` (`validator_registry.rs:466`) — the strict
  functions that resolve the custody address, require the custody sig on Register
  (`MissingCustodySignature`), and enforce the per-FID `MAX_VALIDATORS_PER_FID`
  3-cap. Non-test callers: only the unreached `Some(r)` arms in `router.rs:166`
  and `importer.rs:73`. All direct callers are tests (`validator_registry.rs:1280-1469`).
- `importer::apply_validator_events` (`importer.rs:65`), the other resolver-aware
  entry, has zero callers in the tree (grep `apply_validator_events(` → only its
  own definition). Block import does not re-apply / re-validate validator events,
  so there is no compensating downstream re-check.

## Attacker capability / preconditions

- Network peer able to gossip a `HyperMessage` (or any client that can issue a
  local submit). No validator membership, no committee seat, no key custody.
- Generates a fresh Ed25519 keypair (the "validator key"), self-signs the event,
  picks any `fid` (a victim's FID or arbitrarily many sybil FIDs), sets
  `registration_epoch = current_epoch`, leaves `custody_signature` empty.
- No EIP-712 custody key, no on-chain custody control, no per-FID quota budget
  required.

## Guards on the path

- `runtime.rs:3855` trust-floor gate — OFF by default (`min_validator_trust_score
  == 0.0`, `config.rs:526`; same `0.0` in all non-test configs). When enabled it
  only requires the *named* FID's trust ≥ floor — it does not establish custody
  authorization, so slot-hijack of any sufficiently-trusted FID and sybil
  registration under any such FID remain possible.
- `validate_event` structural checks (key/address lengths, epoch match,
  ≥1 signature) — passable by construction.
- `verify_event_signature` — passes (attacker self-signs with their own key);
  proves nothing about FID ownership.
- Intended custody cross-sign guard (`verify_custody_signature` via
  `validate_and_check_quota`) — NOT on the live path (dead code).
- Per-FID 3-cap — lives only in the dead strict path; does not bind, and FID is
  attacker-chosen anyway.

## Downstream authority granted

- DA-PoW response admission (`runtime.rs:3292-3307`) trusts
  `fid_for_validator_key(validator_pubkey) == body.fid` as ground truth; the
  attacker forged this binding, enabling FID-misattributed reward responses.
- Active-set / committee authority: `compute_active_set`
  (`validator_registry.rs:674`) replays every persisted Register/Deregister
  regardless of how validated, feeding DKLS committee selection, proposer
  selection, and quorum math. Unbounded cheap registrations ⇒ active-set
  dilution / capture.

## Interaction with related findings

- F025 (grindable committee index): F025 assumed the custody cross-sign was
  enforced and sybils needed their own FIDs' custody keys. F070 removes that
  premise entirely — no custody key, no per-FID cap binding, arbitrary FIDs —
  making the grind strictly cheaper. Distinct root cause (missing wiring vs.
  grindable index map).
- F028 (threshold = 1): with single-signer admission and unbounded forged
  validator registrations, the cost to reach a controlling/participating set is
  further reduced. F070 lowers the registration-authorization floor that both
  F025 and F028 build on. Distinct root cause.

## Reachability verdict

REMOTE-UNAUTH. The sink is reached from a single crafted gossip ValidatorEvent
(`actor.rs:1218`) by any network peer with no prior trust, no custody key, and no
validator/committee membership. The only on-path guard (trust floor) is disabled
by default and, even when enabled, does not check custody authorization. The
intended custody-signature gate is unreachable dead code on every production
ingestion path.
