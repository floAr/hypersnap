# F018 Validation — DKLS signer share keystore never pruned at epoch boundary

Validator: validator (deliberate-disagreement). Commit `cab225f`. Read-only.

Finding claims: `dkls_signers: BTreeMap<u64, DklsEpochState>` (per-epoch secret
share + mult shares) is insert-only — no prune/zeroize/retire — so retired shares
stay live and signing-capable for process lifetime. Two consequences asserted:
(1) bridge local-sign helpers take a caller-chosen epoch with no currency check;
(2) verify-side resolves group key from a never-pruned registry; lock-merkle-root
/ owner-rotation apply paths lack the epoch-monotonicity guard the trust-snapshot
path has. Rated **medium** (hygiene / blast-radius), explicitly conceding (a) block
path is pinned to current_epoch and (b) on-chain bridge rejects retired group keys.

## Code confirmation (whole-repo)

- `dkls_signers` mutations: insert only at `runtime.rs:4722` (`install_local_dkls_share`).
  Reads: `4773` (`dkls_share_for_epoch`), `4834`/`4903` (block path), query helper
  `actor.rs:1732`. Init `434`. **No `.remove/.retain/.clear/.split_off`** anywhere
  (grep confirmed). Registry `dkls_group_addresses` ALSO never pruned (grep: empty).
- No `Zeroize`/`impl Drop for DklsEpochState` (grep: empty). Struct derives Clone only.
- Block path pinned to `epoch_resolver.current_epoch()` at `runtime.rs:4832-4838`
  (F028/F026 fix) — CONFIRMED. Finder's concession is accurate.
- Bridge helpers take caller-chosen epoch, no currency check: `produce_signed_lock_
  merkle_root_local` `940-987` (only checks threshold==share_count==1, not epoch
  currency); `produce_signed_owner_rotation_local` `1066-1122` (same). CONFIRMED.
- Verify/apply paths resolve key from `dkls_group_address_for_epoch(update.epoch)`
  (caller field): `1025-1027` (merkle) / `1145-1150` (rotation). Only `block_number`
  monotonicity guard (`1020-1023`, `1140-1144`); NO epoch watermark. Contrast
  trust-snapshot `last_trust_snapshot_epoch` guard at `646-653`/`677`. CONFIRMED.
- On-chain bridge: `claim` `ownerSig.recover != ownerAddress -> BadOwnerSignature`
  (`HypersnapBridge.sol:194`); `rotateOwner` `243/251`; recover/pause `286/...`.
  A retired group address does NOT recover to current `ownerAddress` -> L1 reverts.
  CONFIRMED — concession (b) is accurate.

## 8-hypothesis walk

**H1 Upstream auth / gate — PARTIALLY INVALIDATES the verify-side impact.**
The bridge helpers and the gossip ingest of `LockMerkleRootUpdate`/`OwnerRotation`
(`runtime.rs:3744-3756`, `submit_message`) both reach apply with a caller-supplied
epoch and no currency gate. BUT to produce a HONORED signature the actor must hold,
or the network peer must possess, the retired epoch's secret share. A non-share-holder
cannot forge the ECDSA sig. So the only actor that can exercise the stale-epoch path
is one already holding the leaked share (rotated-out / compromised node) — i.e. the
exact threat the finding scopes. No upstream gate invalidates the *root cause* (no
prune/zeroize), but it bounds the attacker set to share-holders. STANDS as scoped.

**H2 Consumer-side impact — PARTIALLY INVALIDATED (impact correctly downgraded).**
Cached `latest_signed_lock_merkle_root`/`latest_owner_rotation` are consumed by
relayers via HTTP (`http_handler.rs:634`/`599`) and posted to L1. On-chain bridge
rejects a retired-key signature (Sol:194/243). So a poisoned protocol-side cache is
a LOCAL divergence / relayer-confusion (liveness/consistency), not an on-chain fund
move. The finding states exactly this. No overstatement: medium, not high.

**H3 Downstream enforcement — STANDS for root cause; bounds impact.**
The L1 contract IS the downstream re-verifier and catches the retired-key forgery.
That is precisely why the finding is hygiene/blast-radius, not fund-loss. The
protocol-side apply path does NOT re-verify epoch currency (only block_number), so
the local cache-poisoning sub-claim survives downstream enforcement.

**H4 PR HEAD currency — STANDS.** Workspace HEAD == pinned `cab225f1f63...` (git
rev-parse matches). No drift.

**H5 Spec carve-out — STANDS (and strengthens finding).** Doc-comment `runtime.rs:
282-287` says BLS signer is "retired" once DKLS authoritative; no analogous DKLS
retirement exists. Helper doc-comments frame local-sign as "1-of-1 devnet" path
(`1057-1065`) but do NOT mark the missing prune/zeroize as intentionally deferred.
No SECURITY.md / FIP carve-out found that says "shares intentionally kept resident."

**H6 Reachability of harm — PARTIALLY INVALIDATED.** The acute harm (forged L1 move)
is unreachable — on-chain owner check blocks it. The reachable harm is: (a) indefinite
resident secret material (a node compromised at T leaks the whole BTreeMap = every
historical epoch's share, no zeroize on freed pages); (b) protocol-side relay-cache
poisoning by a share-holder. Both are real but bounded to share-holders / local state.
Matches the finding's medium framing.

**H7 Test wiring — STANDS (production-wired).** `produce_signed_lock_merkle_root_local`
called in production at `actor.rs:2176` (epoch-boundary refresh, EvaluateEpochDkls);
apply at `actor.rs:2188`/`2837` and gossip ingest `runtime.rs:3746`. Not test-only.
NOTE: in production the *honest* caller passes the protocol-driven scoring epoch from
`EvaluateEpochDkls`, not an attacker-chosen one — so the helper's missing currency
check is only abusable by a misbehaving share-holder, consistent with H1.

**H8 PoC mechanics — N/A / STANDS.** No executable PoC asserted; finding rests on
static grep + path tracing, all independently reproduced above. The replay tests at
`runtime.rs:6333-6341`/`6532-6538` exercise only `block_number` monotonicity — they
do NOT cover epoch monotonicity, corroborating the missing-guard claim rather than
refuting it.

## Overall

The root-cause claim (insert-only, never-pruned, never-zeroized per-epoch secret
keystore + parallel never-pruned address registry; missing epoch-currency check on
bridge helpers; missing epoch-monotonicity guard on lock-root/owner-rotation apply
vs. the present trust-snapshot guard) is fully verified at the cited lines. The
finding does NOT overstate: it explicitly concedes the two mitigations (current_epoch
block binding; on-chain owner enforcement) that I independently confirmed, and lands
on medium = secret-material hygiene / blast-radius expansion + local relay-cache
poisoning. The exploit set is bounded to share-holders (insider/compromised), which
the finding's own threat model assumes.

VERDICT: WATERPROOF (impact already correctly bounded to medium). Confidence 0.9.

## Open follow-ups (NOT new findings — for specialist consideration)
- The gossip ingest path `submit_message` (`runtime.rs:3744-3756`) applies
  network-received `LockMerkleRootUpdate`/`OwnerRotation` with a caller-supplied
  epoch and only block_number monotonicity. If a *current* share is ever multi-held
  this widens the relay-cache poisoning surface beyond local self-sign; worth the
  specialist confirming whether the epoch-monotonicity guard should live in apply_*
  regardless of share residency. Folds under F018's remediation #4.
