# F016 validation — pending_dkls_inbound unbounded epoch keys (memory DoS)

Validator: validator (deliberate-disagreement role)
Finding: F016 — F023a pre-StartDkls buffer keyed by attacker-controlled `target_epoch`
Audited commit: cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (== current `origin/pow` HEAD)
Validated: 2026-06-08

## Core code re-verified at cab225f

- Buffer field: `pending_dkls_inbound: BTreeMap<u64, Vec<Vec<u8>>>`
  — `src/hyper/actor.rs:1004`.
- Per-epoch cap only: `PENDING_DKLS_INBOUND_CAP_PER_EPOCH = 256`
  — `src/hyper/actor.rs:1045`.
- Pre-auth buffering branch: `src/hyper/actor.rs:1334-1346`.
  `if !is_active { entry(target_epoch).or_default(); push(encoded); return Ok(()) }`.
  Returns BEFORE codec-open / F018 sender check.
- F018 sender↔peer-id cross-check runs ONLY on the `is_active` path
  (`src/hyper/actor.rs:1373`), i.e. AFTER the buffer branch has already
  returned. So the buffer path is genuinely pre-authentication.
- Sole drain: `remove(&target)` on StartDkls — `src/hyper/actor.rs:1430`.
- Whole-codebase grep: `pending_dkls_inbound` is mutated in exactly two
  places — insert (1335) and remove-on-StartDkls (1430). No `.clear()`,
  `.retain()`, `.split_off()`, no DkgFinalized/epoch-advance pruning,
  no global epoch-key cap. Confirmed.
- `target_epoch` provenance: `gossip_adapter.rs:84-88` maps
  `proto::HyperWireDkg.target_epoch` straight into the event with no
  range/committee check. Full u64 reachable from the wire.
- Ingress path: `network/gossip.rs:1099-1144` decodes HyperWire frames
  from gossipsub and `tx.try_send`s the event to the actor. Reachable
  from untrusted gossip on topic `hyper/dkg/v1` (`topics.rs:18`).
- Supervisor StartDkls window is bounded: only
  `first_undispatched..=next_epoch`, `break` once
  `blocks_until_target > start_lead_blocks`; `build_driver` may also skip
  — `dkls_supervisor.rs:119-150`. Far-future / non-member epochs never
  get a matching StartDkls → never drained. Confirmed.

## 8-hypothesis walk

### H1 — Upstream auth / gate — STANDS
RED-TEAM target. Gossipsub runs `ValidationMode::Strict` + `MessageAuthenticity::Signed`
(`gossip.rs:314,324`), so the publishing peer-id is *authenticated*, and
F017 enabled peer scoring + greylist (`gossip.rs:328-343`). BUT:
(a) Strict signing authenticates the peer-id, it does NOT restrict WHO
may publish — `hyper/dkg/v1` is a normal public gossipsub topic; any
libp2p peer that connects + subscribes joins the mesh and can publish.
The "validators-only / peer-restricted" notes in `topics.rs:16,36` are
aspirational — only describe which topics *this* node subscribes to; no
publish-side allow-list / committee gate is implemented.
(b) The buffer path returns `Ok(())` and there is NO
`report_message_validation_result(...Reject)` anywhere in `gossip.rs`
(grep: zero matches). So junk DKG frames are accepted by default at the
gossipsub layer and are NOT counted as invalid-message-rate against the
sender's score. Default `PeerScoreParams`/`Thresholds` give only generic
rate protection, not bug-specific. No upstream gate bounds the map.
`target_epoch` is attacker-controlled and unvalidated as claimed.

### H2 — Consumer-side impact — STANDS
The "consumer" of the corrupted state is the allocator: each distinct
attacker epoch allocates a fresh `Vec` (up to 256 × |encoded|). The
harmful consumer is process memory itself — no value-transfer consumer
needed for a memory-exhaustion DoS. Impact is availability, not fund
loss (consistent with High, not Critical).

### H3 — Downstream enforcement — STANDS
The drain path (StartDkls, 1430) re-runs codec-open + would discard junk,
but it is NEVER reached for attacker-chosen epochs that get no StartDkls.
The 256/epoch cap is the only enforced bound and it does nothing to bound
the *number of epoch keys*. No downstream layer prunes the map.

### H4 — PR HEAD currency — STANDS (notable)
`git fetch origin pow` → `origin/pow` HEAD == cab225f (the audited
commit). `git log cab225f..origin/pow` is empty: nothing newer fixes it.
(Stale local `origin/pow`@6cff47c, dated 2026-05-19, predates the F023a
buffer entirely and lacks `pending_dkls_inbound` — that is an OLDER
ancestor, not a fix.) The unbounded buffer is present on the live branch
HEAD. Branches `fix-memory` / `additional-memory-fix` / `main` do not
contain the buffer (it lives only on the `pow` line). No fix upstream.

### H5 — Spec carve-out — PARTIALLY (does not invalidate)
`topics.rs:16-17` comment says the DKG topic is separate "so they can be
rate-limited or peer-restricted independently" — an acknowledgment that
restriction is desired but explicitly NOT yet implemented. No SECURITY.md
/ doc says the unbounded buffer is intentional. No carve-out that excuses
the leak; if anything the comment confirms the gap is known-aspirational.

### H6 — Reachability of harm — STANDS
Path fully reachable: untrusted peer → `hyper/dkg/v1` → `gossip.rs:1099`
→ `wire_to_event_with_source` (`gossip_adapter.rs:84`) → channel →
actor `InboundDkls` arm → buffer insert. Each frame is bounded to 512KB
by `MAX_HYPER_WIRE_BYTES` (`gossip.rs:52,1100`), but the epoch-key
dimension is unbounded, so growth is unbounded regardless of per-frame
size. The bounded `hyper_actor_tx` channel only rate-limits ingestion;
it does not bound the actor-resident map (entries persist after dequeue).

### H7 — Test wiring — STANDS
The buffering branch is in the production `dispatch` arm reached from the
real gossip ingest (`gossip.rs:1120` → `wire_to_event_with_source`), not
test-only. `wire_to_event_with_source` is called from production gossip
(`gossip.rs:1120`); the other call sites are tests. Production-reachable.

### H8 — PoC mechanics — N/A
No PoC accompanies F016 (code-walk finding). Nothing to over-claim.

## Minor inaccuracy in the finding body (not invalidating)
- "No size limit on `encoded` was found at the adapter layer" (point 4)
  is imprecise: `network/gossip.rs:52,1100` caps the whole HyperWire frame
  at `MAX_HYPER_WIRE_BYTES = 512 KB`, so each buffered `encoded` is
  bounded ~512 KB. This caps per-entry size but NOT the number of epoch
  keys, so the unbounded-growth conclusion is unaffected. The amplification
  framing ("each entry can be sizable") is bounded at 512 KB/frame.

## Overall verdict
WATERPROOF (with one minor body imprecision noted above). The central
claim — unauthenticated, attacker-controlled `target_epoch` keying a
`BTreeMap` with a per-epoch cap but NO global epoch-key cap / TTL /
eviction, reachable from untrusted gossip, drained only by an honest
StartDkls that never fires for attacker-chosen epochs — is verified at
file:line. Gossipsub Strict signing + F017 peer scoring are real but
weak/generic mitigations that do not bound the map and do not gate the
pre-auth buffer path. Confidence 0.9.

Severity assessment: High is appropriate (remote, low-cost, unauthenticated
availability DoS on the DKG/threshold-signing subsystem; not fund loss).
Peer-scoring partial mitigation is the only reason this isn't 0.95+.

## Open follow-ups (NOT new findings — for specialist owners)
- F024 in this set ("buffered DKLS DKG drain skips sender authentication")
  targets the SAME buffer from the drain/auth angle. Dedupe-curator should
  decide same-root-cause vs related (both stem from the F023a buffer +
  pre-auth handling). Not a validation issue for F016.
- Consider whether peer-scoring could be strengthened by calling
  `report_message_validation_result(...Reject/Ignore)` for out-of-window
  `target_epoch` DKG frames so the flood costs the attacker score — but
  that is a remediation suggestion, already implied by F016's fixes.
