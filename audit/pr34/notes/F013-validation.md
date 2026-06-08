# F013 validation — red-team walk

Finding: The inbound-gossip decode path's `FullProposal` arm calls
`full_proposal.height()` (= `self.height.clone().unwrap()`) BEFORE the
fallible `shard_id()` guard. A peer can publish a `GossipMessage::FullProposal`
frame with the message-typed `height` field omitted → `unwrap()` on `None` →
panic → remote unauthenticated single-frame node crash / DoS.

Validator role: deliberate disagreement. Pinned commit `cab225f`
(HEAD verified `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`, detached, clean tree).

## Core mechanic — CONFIRMED at file:line

- `src/network/gossip.rs:1019-1039` FullProposal arm. Line **1020**
  `let height = full_proposal.height();` runs FIRST. The `shard_id()` guard
  (`is_err() -> return None`) is at lines **1032-1036**, i.e. STRICTLY AFTER
  the panicking `.height()`. The guard is dead-on-arrival for the missing-height
  case exactly as the finding states. Call order confirmed.
- `proto/src/lib.rs:185-187` `pub fn height(&self) -> proto::Height {
  self.height.clone().unwrap() }` — panics on `None`. Confirmed.
- `proto/src/lib.rs:139-142` `shard_id()` does `if let Some(height) = &self.height`
  → returns `Err` on `None` — so the author KNEW height can be absent, yet the arm
  reaches `.height()` first. Confirmed.
- `proto/definitions/blocks.proto:73-80`: `message FullProposal { Height height = 1; ... }`.
  `Height` is a message type → prost generates `Option<Height>` (proto3 has no
  required fields; message-typed singular fields are always `Option<T>`). A peer
  can omit it on the wire and decode succeeds with `height = None`.
- Same-file corroboration: `StatusMessage { Height height = 2; }`
  (blocks.proto:42). The Status arm at gossip.rs:**1076** does
  `let Some(height) = status.height else { ...return None; }` — the codebase
  itself treats an identical `Height` message field as a `None`-able `Option`
  and GUARDS it. FullProposal uses the panicking `.height()` instead. This is the
  same family as F185/F151 residual unwraps; F022 covers the *size-cap* gap on the
  same arm (distinct root cause — no dedup conflict).

## 8-hypothesis walk

**H1 — Upstream auth / gate. STANDS (the crux; investigated hardest).**
Gossipsub is configured `ValidationMode::Strict` (gossip.rs:314) +
`MessageAuthenticity::Signed(key)` (gossip.rs:324). Strict+Signed authenticates
the libp2p *transport envelope*: it proves the frame was signed by SOME peer's
libp2p keypair and rejects unsigned/badly-signed envelopes. It does NOT validate
the application proto payload, required fields, or that `height` is present.
The single application gate before the arm is `proto::GossipMessage::decode`
(gossip.rs:989), which only fails on malformed wire bytes — a `FullProposal` with
`height` omitted is well-formed proto3 and decodes to `Some(FullProposal{height:None,..})`.
No signature/authority check exists between decode and the FullProposal arm
(dispatch at gossip.rs:780 calls the mapper directly on `message.data`). The proto
even carries `// TODO: This probably needs a signature?` (blocks.proto:72)
confirming these frames are NOT app-authenticated. Upstream gate does NOT save the
node. STANDS.

**H2 — Consumer-side impact. STANDS.**
The "consumer" is the panic itself — the unwrap aborts the gossip/event thread
inside the swarm loop. No corrupted-state-consumer analysis needed; the harm is
the crash, which is immediate and self-contained. STANDS.

**H3 — Downstream enforcement. STANDS.**
There is no layer "below" `.height()` that re-checks height before it executes —
`.height()` is the very first statement in the arm. The `shard_id()` Result guard
that WOULD have caught `None` sits after the panic and never runs. No downstream
re-verification rescues it. STANDS.

**H4 — PR HEAD currency. STANDS.**
Workspace HEAD == pinned `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`; no drift to
re-check against. (Cannot fetch a moving branch from this read-only snapshot; the
finding is anchored to the pinned commit, which is what we validate.) STANDS.

**H5 — Spec carve-out. STANDS.**
No spec/README/doc-comment says missing-height frames are intentionally tolerated.
The only nearby comment (`// TODO: This probably needs a signature?`) cuts AGAINST
safety — it acknowledges the frame is unauthenticated. No carve-out. STANDS.

**H6 — Reachability of harm. STANDS (one honest caveat, non-defeating).**
The arm is reached for any decoded `GossipMessage::FullProposal` on ANY subscribed
topic (dispatch matches on the proto variant, not the topic). Validators subscribe
to the consensus/proposal mesh. Caveat: Strict+Signed means the attacker must be a
*mesh peer with a valid libp2p identity* — i.e. "any peer in the mesh", not literally
"any unauthenticated internet host". There is no validator-only admission shown that
would narrow this to honest validators, and gossipsub meshes admit arbitrary peers,
so "any peer" still equals a remote, non-privileged attacker. This slightly refines
the wording ("any mesh peer" vs "any unauthenticated node") but does not lower the
severity: a single crafted frame crashes any subscribed node, repeatable network-wide.
STANDS.

**H7 — Test wiring. STANDS.**
`map_gossip_bytes_to_system_message` is a `pub fn` on the gossip read actor invoked
from the real swarm event handler (gossip.rs:780) on live `message.data`. Production
path, not test-only. STANDS.

**H8 — PoC mechanics. NEEDS_MORE_DATA (no PoC supplied) → does not weaken the static proof.**
No PoC file accompanies F013. The claim rests on static call-order + type analysis,
all of which is independently verified above (line numbers, `Option<Height>` codegen
confirmed via the parallel Status guard). A PoC would strengthen the submission but
the mechanic is proven by code reading; no PoC assertion can be mis-attributed
because none exists. Recommend the specialist add a unit test encoding a
`FullProposal` with `height: None` and asserting the mapper panics (or, post-fix,
returns `None`).

## Open follow-ups (NOT new findings — for the specialist)
- `proto/src/lib.rs:189-191` `round()` does `self.round.try_into().unwrap()` on a
  peer-controlled `int64 round` — negative round → `try_into::<u..>` Err → panic on
  the same untrusted FullProposal. Same family; if/when the height guard is added,
  `round()` is the next reachable unwrap on this struct. The finding body already
  flags this in "Variant context"; leaving to the specialist.
- Worth confirming whether `MalachitePeerId::from_libp2p` / `encode_to_vec` between
  lines 1025-1031 can also fault, but those are infallible; height/round are the
  live ones.

## Overall verdict
**WATERPROOF**, confidence **0.92**.
Call order (`height()` before the `shard_id` guard), the panicking `.unwrap()`,
the `Option<Height>` peer-controllability, and the absence of any app-layer auth
upstream are all confirmed at file:line. The single caveat (H6: "any mesh peer"
rather than "any internet host") refines wording without reducing severity.
Deduct 0.08 only for the absent PoC (H8) and the standard residual that a moving
branch could add a guard above `cab225f` (out of scope for the pinned commit).
