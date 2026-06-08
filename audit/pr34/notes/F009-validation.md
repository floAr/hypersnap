# F009 validation — slashing predicate keys conflict on signature-inclusive block hash

Validator: validator (deliberate-disagreement role)
Finding: F009 (consensus-malachite-tendermint, attack_class double-sign-evidence-gating)
Commit: cab225f (HEAD matches pin)
Date: 2026-06-08

## Core mechanism — CONFIRMED

The structural defect the finding names is real and verified line-by-line:

- `hyper_block_hash` mixes the threshold-signature bytes into the digest:
  `signature.group_address` and `signature.ecdsa_signature`
  (`code/hypersnap/src/hyper/chain.rs:35-39`).
- `signing_payload` (the signed content) excludes the signature
  (`code/hypersnap/src/hyper/mod.rs:403-452`).
- `detect_conflicting_blocks` keys "distinct block" purely on
  `hyper_block_hash` inequality with `canonical_block_id` equality; there is
  **no signed-payload comparison** (`slashing.rs:56-66`).
- The downstream gates do not rescue it: `verify_evidence_signatures` only
  checks each block's signature is valid over its own `signing_payload`
  (`slashing.rs:98-108`) — two benign blocks both pass. Enforcement
  `slashed_validators_for_epoch` slashes purely on `signer_indices` of both
  evidence blocks with no payload/state-root/height re-check
  (`runtime.rs:4191-4229`).

So IF two distinct valid threshold signatures over an identical
`signing_payload` at one `canonical_block_id` can be produced and packaged
into an `InboundEvidence` frame, they survive detect → verify → record →
enforce and slash the honest committee. The over-broad-predicate logic is
sound. The dispute is entirely about **reachability** of the benign
collision.

## 8-hypothesis walk

### H1. Upstream auth / gate — STANDS (no rescue)
`InboundEvidence` (`actor.rs:1587-1620`) calls `detect_conflicting_blocks`
directly on two caller-supplied `HyperBlock`s. There is no upstream gate
comparing signed payloads. The only upstream filters are the dedupe set and
`verify_evidence_signatures` — neither dedupes by payload, both pass a benign
pair. STANDS.

### H2. Consumer-side impact — STANDS (no rescue)
The consumer is `slashed_validators_for_epoch` (runtime.rs:4191). It reads
`signer_indices` from both evidence blocks and adds the resolved validator
keys to the slashed set. It does NOT re-derive or compare `signing_payload`,
`hyper_state_root`, or height beyond what `detect_conflicting_blocks` already
admitted. So a benign-but-admitted pair does cause a real penalty. STANDS.

### H3. Downstream enforcement — STANDS (no rescue)
Walked the epoch-boundary path explicitly. No layer below
`detect_conflicting_blocks` re-checks that the two blocks committed to
different content. Enforcement is index-driven, not content-driven. STANDS.

### H4. PR HEAD currency — STANDS
`git log -1` = cab225f, matches the pinned commit. Branch is detached at the
pin. No drift. STANDS.

### H5. Spec carve-out — NEEDS_MORE_DATA → effectively STANDS
The slashing module doc-comment (`slashing.rs:1-11`) describes evidence as
"two blocks ... with **different state roots**" — i.e., the *intent* is to
catch divergent content. The code keys on signature-inclusive hash, which is
broader than the documented intent. No doc says "benign re-sign is
intentionally slashable," so no carve-out protects the code; if anything the
doc-comment supports the finding (code is broader than documented intent).

### H6. Reachability of the harm — PARTIALLY INVALIDATED (this is the load-bearing hypothesis)
The finding offers two reachability stories for "two valid sigs over the same
payload." Both are weaker than claimed:

(a) **DKLS recovery-id restart (F045).** The finding asserts
    "recovery_id ∈ {2,3} occurs ~50% of the time, see dkls_sign.rs:211."
    This is a **material misreading**. The code states the probability of
    recovery_id ∈ {2,3} (R.x ≥ curve order) is **~2⁻¹²⁸ per attempt**
    (`dkls_sign.rs:464`, `dkls_threshold.rs:439`) — cryptographically
    negligible, essentially never observed. (The ~50% figure plausibly
    conflates with low-s EIP-2 normalization `s' = n-s; recovery_id ^= 1`,
    which is a *deterministic in-place fixup* — `bridge_payload.rs:30-32` —
    NOT a ceremony re-run, and does not yield a second independent
    signature.) Moreover, even on the negligible {2,3} event, the rejected
    attempt returns `Err(RecoveryIdOutOfRange)` *before* `from_rsv` /
    `output = Some(sig)` (`dkls_sign.rs:417-426`); it never materializes an
    `EcdsaSignature`. Only the final accepted signature is finalized into a
    block (`actor.rs:1574-1581`, `2715-2723`). So the attacker cannot
    "retain sig1" — there is no sig1 object. Scenario (a) is INVALIDATED.

(b) **Consensus round-retry / re-proposal.** The finding assumes a
    Malachite round-retry re-runs block production for the same
    `(epoch, height, parent_hash)` and broadcasts two distinct finalized
    blocks. In this codebase the block producer is a **fixed-cadence
    single-proposer scheduler** (`scheduler.rs:179-211`), not a Malachite
    round loop. `is_proposer(...)` is called with **round hardcoded to 0**
    (`scheduler.rs:167`); height is `snapshot.next_height()` which only
    advances on an observed `BroadcastBlock` (`scheduler.rs:222-228`). There
    is no wired re-proposal path that emits two finalized, differently-signed
    blocks for one height. A second `ProduceBlockDkls` for an un-finalized
    height recomputes the *same* digest and overwrites
    `pending_dkls_blocks[digest]` (`actor.rs:2698`); only the *finalized*
    signature is ever attached + broadcast (`actor.rs:2761-2790`). The
    round-aware seed exists only in the proposer-selection abstraction
    (`proposer.rs:26`) and is not exercised by the producer with round != 0.
    Scenario (b) is NOT demonstrated reachable in this code; it is imported
    from a generic Malachite mental model.

(c) **Insider harvesting (attack steps 1-4).** A single byzantine committee
    member cannot unilaterally produce a t-of-n threshold signature; it needs
    t-1 honest co-signers. Honest nodes run one ceremony per height (driven
    by scheduler → finalize) and have no code path that voluntarily
    co-signs a *second* ceremony for the same already-decided payload. So
    even an insider cannot trivially harvest two valid signatures over one
    payload through the wired protocol.

Net: the *predicate is genuinely over-broad and would mis-slash IF a
benign collision occurred*, but no concretely-wired path in this codebase
produces two distinct valid signatures over an identical `signing_payload`
at one height. The harm is latent/defensive (the predicate is wrong and
fragile) rather than presently-triggerable with the stated frequency.
PARTIALLY INVALIDATED — the high-frequency "~50% recovery-id" trigger is
false; remaining triggers are not shown reachable in-tree.

### H7. Test wiring — STANDS (predicate is production code)
`detect_conflicting_blocks` and `slashed_validators_for_epoch` are
production paths reached from `HyperActorEvent::InboundEvidence`
(`actor.rs:1587`) and the epoch boundary. The predicate is genuinely live.
STANDS (the *defect* is in production; only its *trigger* is in question,
covered under H6).

### H8. PoC mechanics — N/A / NEEDS_MORE_DATA
No executable PoC is attached to the finding. The prose attack relies on the
~50% recovery-id claim (H6a), which the code contradicts. Without a PoC that
actually obtains two valid signatures over one payload, the "honest committee
gets slashed" assertion is not demonstrated end-to-end.

## Overall verdict

HAS_CAVEATS (confidence 0.6).

The structural finding is correct and worth fixing: `detect_conflicting_blocks`
should define "conflict" on signed content (`signing_payload`), not on the
signature-inclusive `hyper_block_hash`. The recommended fix is sound, and the
defect is real defense-in-depth/correctness debt — a future change that does
produce two valid signatures over one payload (legit re-sign, alternate
client, protocol evolution) would silently weaponize this predicate against
honest signers.

BUT the finding's impact and exploitability are overstated:
- The "~50% recovery-id restart" trigger is factually wrong (actual ~2⁻¹²⁸);
  the rejected attempt never even yields a signature object.
- The "Malachite round-retry" trigger is not wired in this fixed-cadence,
  round-0 single-proposer producer.
- A single insider cannot harvest two threshold signatures unilaterally.

So this is a real **latent correctness/robustness bug in the slashing
predicate** (the two notions of "distinct block" diverge), not a presently
high-frequency griefing vector. Severity should be reconsidered downward from
"high griefing/halt with no key compromise" toward "medium latent
mis-slashing risk / defense-in-depth" pending a concrete demonstration that
two valid signatures over one payload are reachable in-tree.

## Open follow-ups (NOT new findings)
- Worth confirming whether any *future* or *off-path* component (e.g. an
  alternate signing client, a re-sign-on-restart recovery flow, or a
  multi-region producer) could legitimately generate a second signature over
  an already-decided payload. If such a path is added, F009 becomes directly
  exploitable. This is forward-looking and belongs to the specialists, not a
  new finding here.
