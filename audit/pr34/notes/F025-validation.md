# F025 validation — committee-index grinding via attacker-chosen validator_key

Validator: validator (deliberate-disagreement). Commit pinned: `cab225f`. HEAD verified == workspace pin (read-only, no git repo to fetch; PR-HEAD currency assessed below).

Finding under test: F036 made the committee *seed* non-grindable, but `select_signing_committee` ranks abstract **party indices** `1..=share_count`, and the index→validator binding is the 1-based lexicographic (BTreeMap) sort position of the active validators' raw 32-byte Ed25519 `validator_key`s. Since the per-epoch seed is fully predictable far ahead, an attacker grinds key bytes so their sybil validators land on the winning index slot(s) for a target epoch.

## Code claims re-verified (file:line)

- Index-ranking selection (no identity input): `dkls_committee.rs:53-89`. `rank(i)=keccak256("hypersnap-dkls-committee-v1\0"||epoch||digest||i)`; inputs are epoch + seed only. CONFIRMED verbatim.
- Non-grindable epoch seed: `committee_seed_for_epoch(epoch, message_tag)` depends only on `epoch` + static tag (`dkls_committee.rs:110-117`). Block seed adds `(height,parent_hash)` (`:119-127`). CONFIRMED.
- Index→validator = lexicographic key order: `dkls_supervisor.rs:194-201` — `for (i, vk) in active.keys().enumerate() { if vk==local … own_idx=Some((i+1)) }`. `active` is `BTreeMap<Vec<u8>,_>` keyed on `validator_key` (`actor.rs:819`, `runtime.rs:3993`). CONFIRMED — party_index is a pure function of raw key bytes; no shuffle/VRF/commit-reveal.
- Winning index ⇒ that validator signs, bound into payload: block path `actor.rs:2657-2705` (`committee.contains(&local_party_index)` gate + `signing_payload(epoch,&committee_indices)` F153 bind). Same shape for all epoch-tag ceremonies: `actor.rs:3055-3087`, `:3216`, `:3284`, `:3357`. CONFIRMED — only the selected index's signature recomputes to the same digest, so committee membership IS the authorization.
- `validator_key` freely chosen, only 32-byte length enforced: `validator_registry.rs:375`. CONFIRMED.
- Registration binding does NOT constrain key bytes: ed25519 self-sig only proves possession (`verify_event_signature`, `validate_event` :403-405); EIP-712 custody sig commits to whatever key the attacker supplies (`:406-409`); trust floor gates the FID score not key bytes (`validate_register_with_trust` :466-489). CONFIRMED.
- Per-FID cap = 3 (`MAX_VALIDATORS_PER_FID`, `validator_registry.rs:24`), but sybil controls many FIDs. CONFIRMED — cap is per-FID, not global.
- Timing window: `EPOCH_LENGTH=432_000`, `EPOCH_BUFFER=1` (`epoch.rs:14,19`); active set at epoch N reflects events ≤ N−2 (`compute_active_set` cutoff `:686`). CONFIRMED — epoch-tag ceremonies predictable arbitrarily far ahead.

## CRITICAL CONTEXT discovered: production threshold is hardcoded to 1 (F028 overlap)

`main.rs:1603` — `let dkls_threshold = 1u8;` is the only production wiring of `DklsSupervisorInputs.threshold` (`main.rs:1647-1658`). So in production **every committee is size 1**: `select_signing_committee` returns exactly one winning index per ceremony. This materially reshapes the impact framing (see H2/overlap).

## 8-hypothesis walk

### H1 Upstream auth / gate — STANDS
Is there a gate upstream that prevents an attacker from registering a key with attacker-chosen bytes, or that re-randomizes the index? No. Registration (`validate_register_with_trust`) enforces signature possession, custody cross-sign, trust floor and per-FID cap — none constrains the 32 key bytes. The index assignment in `build_driver` is a raw `BTreeMap` enumerate with no beacon mixed in. The finding's mechanism is not masked by any upstream control. STANDS.

### H2 Consumer-side impact — PARTIALLY INVALIDATED (marginal value over F028 is conditional)
What does winning the index actually buy, *given the rest of the system*? Two regimes:
- **Production today (threshold=1):** the threshold-security assumption is already void — whichever single validator wins each ceremony has unilateral signing power (this is the separate F028 problem). F025's *marginal* contribution here is that grinding lets the attacker **deterministically be that winner** for a target epoch/ceremony, rather than holding a 1/N chance. That is a real, distinct capability (selection control), but the catastrophic "threshold broken" outcome is already delivered by t=1 regardless of grinding. So in the *current* config, F025 is best described as "deterministic-targeting amplifier on top of an already-broken t=1 committee," not an independent root cause of signature capture.
- **Intended t>1 config:** grinding lets a sybil land on *multiple* winning slots and assemble a full `threshold`-of-N quorum it controls — this is the strong, independent impact the finding claims. The finding's High rating is sound for this regime.
The finding's prose asserts the strong impact generally; it does not flag that the *shipped* threshold is 1, which makes part of the claimed novelty redundant with F028 today. Impact is real but **overstated for the current production config** and **understated-context** (doesn't note t=1). Hence PARTIALLY INVALIDATED on impact-framing, not on mechanism.

### H3 Downstream enforcement — STANDS
Does a layer below re-verify the signer's identity in a way that defeats grinding? No. The verifier recomputes the *same* deterministic committee from the same public seed and accepts the bound signature (`signing_payload(epoch,&committee_indices)`, F153). The whole point of determinism is that all nodes agree on which index signs — so an attacker who legitimately holds the winning index produces a fully valid signature. There is no separate stake-weight or identity re-check downstream that would reject a grinder-occupied index. STANDS.

### H4 PR HEAD currency — NEEDS_MORE_DATA (no drift detectable in workspace)
Workspace is a read-only snapshot at `cab225f` with no `.git`. I cannot `git fetch` to confirm the branch hasn't moved. The structural facts (BTreeMap key-order index, hardcoded t=1) are unlikely to have changed silently, but I flag this as the one hypothesis I cannot fully close. NEEDS_MORE_DATA.

### H5 Spec carve-out — STANDS (no carve-out found)
`dkls_committee.rs` module docs tout uniformity/determinism but say nothing about index assignment being randomized against the key — and explicitly note "output is sorted by index" and "correctness relies on every party seeing the same canonical ordering." No README/doc-comment says "index→key mapping is intentionally raw-sort / grindability deferred." The F036 fix comment (`:91-109`) addresses *seed* grindability only and does not acknowledge the index-map vector. No carve-out. STANDS.

### H6 Reachability of harm — STANDS (with cost caveat)
Can the grind be realized end-to-end? Yes: (a) seed is public/predictable (epoch-tag path, far ahead); (b) winning index set computable offline; (c) attacker computes the target sort position knowing other registered keys (or targets a byte-prefix bucket) and grinds Ed25519 keypairs cheaply (one keygen/attempt); (d) registers before `epoch−2`. The cost gates are real but surmountable for a sybil adversary: trust floor per FID + 3-cap per FID, so the attacker needs enough sufficiently-trusted FIDs. Reachable. STANDS (the attack is not free, which the finding already states).

### H7 Test wiring — STANDS
Is the code actually in production? Yes. `dkls_supervisor::run` is spawned in `main.rs:1647` for any node with operator identity; `build_driver` (the index-assignment site) runs each epoch; `select_signing_committee` is called on every real ceremony path (`actor.rs:2659,3055,3080,3216,3284,3357`) plus block production (`:2657`). Not test-only. STANDS.

### H8 PoC mechanics — NEEDS_MORE_DATA
The finding ships no executable PoC, only an attack procedure. The procedure is internally consistent and the load-bearing primitives are verified above, but there is no assertion artifact to scrutinize for "passes for the wrong reason." The one mechanical nuance worth stating: the attacker must grind a *sort position*, and inserting a new key shifts the positions of all keys that sort after it — so to land sybils on multiple specific indices simultaneously the attacker must solve the joint placement (register in sorted order, accounting for self-shifts). This is tractable (the attacker controls all sybil keys and knows the honest set) but is more involved than "grind each key independently." Does not invalidate; flagged for accuracy. NEEDS_MORE_DATA (no PoC to test).

## Overall verdict: HAS_CAVEATS (confidence 0.78)

The mechanism is real and verified at every step: committee selection ranks indices, the index→validator map is raw lexicographic key order, validator_key is attacker-chosen with no beacon/PoP binding the bytes, and the winning index is the authoritative signer. The grindability claim is correct.

Caveats that prevent WATERPROOF:
1. **F028 overlap / threshold=1 (H2).** Production ships `dkls_threshold = 1u8` (`main.rs:1603`). In the shipped config the threshold assumption is already broken by F028, so F025's incremental value today is "deterministic targeting of the single winner," not "first break of threshold security." The finding's High severity is fully justified only in the intended t>1 regime; for the current config it should be read as composing with / amplifying F028. The finding does not note the hardcoded t=1, which is a material framing gap.
2. **Joint sort-position placement (H8).** Landing multiple sybils on multiple specific winning indices requires solving the joint placement (self-shifts), slightly harder than the prose's per-key framing — tractable, not invalidating.
3. **PR-HEAD currency (H4) and absence of executable PoC (H8)** could not be closed from the workspace.

None of these invalidate the core finding; they bound and contextualize its severity. Recommend the originating specialist add a one-line note on the shipped `threshold=1` and the F028 relationship, and (for the joint-placement nuance) tighten the "direct sort-position computation, not even a brute force" wording.

## Open follow-ups (NOT new findings — for specialist triage)
- The hardcoded `dkls_threshold = 1u8` at `main.rs:1603` is the substance of F028; F025 and F028 should be cross-linked at dedupe (related, not duplicate — different root cause: F028 = no threshold security; F025 = grindable selection map). Validator cannot create findings; flagging for dedupe-curator.
