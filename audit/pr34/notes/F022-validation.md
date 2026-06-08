# F022 validation — per-variant size cap gap on FullProposal / DecidedValue gossip arms

Validator: validator (deliberate-disagreement). Commit `cab225f`.

## Code-level confirmation of the core claim

`src/network/gossip.rs`:

- `ReadNodeMessage` / `DecidedValue` arm — lines 1007-1017: constructs
  `SystemMessage::DecidedValueForReadNode(decided_value)` with NO
  `encoded_len()` check.
- `FullProposal` arm — lines 1019-1039: `full_proposal.encode_to_vec()`
  (line 1026) and dispatch with NO `encoded_len()` check.
- Every other application arm IS capped: ContactInfo (994 / 4 KB),
  Consensus (1041 / 64 KB), Status (1066 / 4 KB), HyperWire (1100 /
  512 KB), Mempool (1146 / 256 KB). Caps defined gossip.rs:52-56.
- F019 intent comment (gossip.rs:46-51) explicitly states the
  per-variant caps exist so "anything larger is a Sybil-flood /
  amplification vector and is dropped at ingress." The two arms above
  are genuinely missed.
- Transport ceiling `MAX_GOSSIP_MESSAGE_SIZE = 10 MB` (line 44), applied
  via `.max_transmit_size(...)` (line 316).

So the factual claim — these two arms are bounded only by the 10 MB
transport ceiling, unlike all other arms — is TRUE at file:line.

## 8-hypothesis walk

### H1 — Upstream auth / gate. PARTIALLY INVALIDATES (severity, not existence)
ValidationMode::Strict + MessageAuthenticity::Signed (lines 314, 324):
every gossipsub frame must carry a valid libp2p signature from a mesh
peer, and the 10 MB transport cap is enforced by libp2p BEFORE the
handler runs. So the attacker is not anonymous — they need a peer with a
valid key already in the mesh (the finding acknowledges this, line 105).
This is a genuine upstream gate that bounds *who* can do this, but it
does not bound the per-frame amplification once a peer is in the mesh.
The arm-level gap stands; the precondition lowers it from a remote
unauthenticated DoS to a mesh-member DoS.

### H2 — Consumer-side impact. STANDS (with nuance)
FullProposal → `SystemMessage::MalachiteNetwork` on Channel::ProposalParts;
re-encoded via `encode_to_vec()` at line 1026 (a second full buffer)
before dispatch. DecidedValue → `SystemMessage::DecidedValueForReadNode`,
handed downstream whole. Both consumers exist and are live. The
re-encode for FullProposal is real and is the strongest part of the
amplification claim (raw `message.data.clone()` at line 774 + decoded
tree + re-encoded vec = ~3x wire size transiently). Claim of ">=2x" is
conservative and correct.

### H3 — Downstream enforcement. PARTIALLY INVALIDATES (impact ceiling)
The heavy cost the finding describes (decode + re-encode) happens at the
gossip handler BEFORE any downstream block-validation. Downstream
`validate_block_size` (builder.rs:238/275, MAX_MESSAGES_PER_BLOCK) would
reject an over-large block, but only AFTER the allocate+re-encode has
already occurred. So downstream enforcement does NOT prevent the
transient memory cost — the finding's harm is pre-validation, so this
does not invalidate. It does confirm the harm is transient
(per-frame heap, freed after the message is dropped), not a persistent
leak — consistent with Medium, not High.

### H4 — PR HEAD currency. NEEDS_MORE_DATA (no impact on verdict)
Workspace pinned at `cab225f`; this is a read-only revalidation against
that commit. No fetch performed (no network mandate for revalidation).
The cited lines match the pinned tree exactly. If upstream later added
caps to these arms the finding would be fixed-forward, but at the pinned
commit it stands.

### H5 — Spec carve-out. STANDS
The F019 comment (lines 46-51) is the relevant doc, and it states the
OPPOSITE of a carve-out: it claims oversized frames are "dropped at
ingress." There is no comment marking FullProposal/DecidedValue as
intentionally exempt. The gap is an omission, not a documented deferral.

### H6 — Reachability of harm. STANDS (bounded)
A mesh peer can publish FullProposal frames on the consensus topic
(published there, line 848; validators subscribe, lines 395-401) and
DecidedValue on decided-values (line 849; read nodes subscribe, lines
378-385) up to ~10 MB each. Gossipsub duplicate-suppression
(content-addressed message IDs) means re-sending the IDENTICAL frame is
de-duped, but a malicious peer can trivially vary the payload (round,
proposer bytes, padding) to defeat dedup and force a fresh
decode+re-encode each time. So sustained amplification is reachable.
Harm is real but capped per-frame at 10 MB and per-peer by mesh
membership.

### H7 — Test wiring. STANDS
`map_gossip_bytes_to_system_message` is the production handler, called
from the live `gossipsub::Event::Message` arm (line 780). Not
test-only. The FullProposal/DecidedValue arms are production decode
paths.

### H8 — PoC mechanics. NEEDS_MORE_DATA
No PoC is included in the finding. The claim rests on static code
reading, which I confirmed at file:line. Absence of a PoC is acceptable
for a Medium memory-amplification finding but means the *magnitude* of
real-world amplification (GC pressure, OOM threshold) is asserted, not
measured. This caps confidence rather than invalidating.

## Severity judgement: Medium vs lower

Arguments to DOWNGRADE toward Low:
- 10 MB transport ceiling already bounds each frame; the gap is the
  delta between "10 MB allocate+re-encode" and "drop at a tighter cap,"
  not unbounded memory.
- Requires a valid signed mesh peer (Strict + Signed) — not a remote
  anonymous attacker.
- Peer scoring (F017, lines 328-343) provides eventual eviction of
  invalid-message-rate abusers, capping sustained abuse.
- Harm is transient per-frame heap, freed after drop — no persistent
  corruption or fund loss.

Arguments to HOLD at Medium:
- The consensus topic is subscribed by EVERY validator; a single
  malicious mesh peer amplifies onto all of them simultaneously, and
  gossipsub forwards the frame across the mesh before local drop.
- FullProposal re-encodes (line 1026), giving genuine >=2x (≈3x with the
  raw clone) amplification per frame — the highest-value target.
- The F019 hardening's stated purpose is precisely to prevent this; the
  gap defeats the control's intent on its two heaviest payloads
  (full blocks up to 50k messages each).
- Peer scoring is reactive/eventual, not preventive — a peer can burst
  many oversized frames before greylisting.

Net: Medium is defensible and not overstated. It is bounded (10 MB +
auth gate + eventual eviction), which correctly keeps it out of High.
The finding itself already articulates these bounds (lines 99-107),
so the impact is NOT overstated.

## Overall verdict
WATERPROOF (with the caveat that severity rests on the gap-vs-intent
argument and the per-frame transient cost, both confirmed; no PoC).
Confidence 0.82. The factual claim is exact at file:line; the only soft
spots are the un-quantified amplification magnitude (no PoC) and the
mitigating auth/peer-scoring gates, both of which the finding already
acknowledges and which justify Medium rather than High.

## Open follow-ups (NOT new findings)
- The finding's side-note (lines 50-57): MAX_HYPER_WIRE_BYTES = 512 KB
  may UNDER-size a legitimate two-block evidence frame (each block up to
  MAX_MESSAGES_PER_BLOCK = 50_000 msgs, builder.rs:67), silently dropping
  real slashing evidence. Confirmed the constant (512 KB) and the
  per-block message ceiling. This is an availability/functional concern
  on the slashing path distinct from the DoS gap; flagging for the
  specialist to consider as a separate finding if in scope. I did not
  create a finding per role constraints.
