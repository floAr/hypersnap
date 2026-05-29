# F151 fix backcheck — commit b464cfb ("pulling in a fix from the audit")

**Scope:** PR #32 commit `b464cfb`, files `src/consensus/malachite/snapchain_codec.rs` + `src/core/types.rs`.
**Finding under review:** F151 — `SnapchainCodec` decode panics on peer-controlled Vote/Proposal/sync-Commits (read-node + validator DoS). 9 panic triggers (a–i) + 5 remediation items.
**Target tree:** hypersnap @ `4a6bca5`. **Oracle:** snapchain v0.12.0 (`C:\Projects\snapchain`).

## Verdict: PRIMARY CLAIM FIXED ✅ — with one residual to adjudicate ⚠️ and one minor gap

### ✅ Network-edge codec path fully closed (all 9 triggers a–i)
The fix adds `Vote::try_from_proto`, `Proposal::try_from_proto`, `Commits::try_to_commit_certificate`, `Address::try_from_vec`, and rewires every network-edge codec decode arm to call them and `?`-propagate `SnapchainCodecError::InvalidField`:
- (a) Vote.type out-of-range → `try_from_proto` returns Err (was `panic!`). ✅
- (b) Vote.height None → `ok_or("Vote::height missing")`. ✅
- (c) Vote.voter len≠32 → `try_from_vec` length check. ✅
- (d) Proposal.height None, (e) Proposal.value None, (f) Proposal.proposer len≠32 → all `try_*`. ✅
- (g) Commits.height None, (h) Commits.value None, (i) signer len≠32 → `try_to_commit_certificate`. ✅
- BONUS: `Codec<StreamMessage<FullProposal>>::decode` `proposal.height.unwrap()` (snapchain_codec.rs:106 — the site F002's open-follow-up #1 recommended folding in) is now `ok_or_else(... "FullProposal::height missing")`. ✅

Confirmed by grep: **no `Vote::from_proto` / `Proposal::from_proto` callers remain anywhere in `src/`.** The network-edge codec (Channel::Consensus gossip, Channel::Sync ValueResponse + VoteSetResponse) — F151's entire primary attack surface — no longer panics on peer input.

### ⚠️ RESIDUAL — 5 un-migrated callers of the still-panicking `to_commit_certificate`
The fix **added** `try_to_commit_certificate` but left the original panicking `to_commit_certificate` in place, still called from:
- `host.rs:332`, `host.rs:336` — `GetDecidedValue` handler. Operates on **local store** data (`get_decided_value`). Not peer-reachable. ✅ safe.
- `read_validator.rs:207`, `read_validator.rs:220` — `get_decided_value`. Reads **local** `shard_engine.get_shard_chunk_by_height` / `block_engine.get_block_by_height`. Not peer-reachable. ✅ safe (though `chunk.commits.clone().unwrap()` is a local-integrity panic).
- `util.rs:103` — `verify_signatures(commits, validator_sets)` calls `commits.to_commit_certificate()` **before** verifying signatures. Callers:
  - `read_validator.rs:118`, `read_validator.rs:154` — **read-node** decided-value processing.
  - `block_receiver.rs:86` — block ingestion.

  **OPEN QUESTION for validate stage:** if `commits` at `read_validator.rs:118` / `block_receiver.rs:86` is peer-controlled (e.g. a gossiped/synced `DecidedValue` whose `proto::Commits` reaches `verify_signatures` WITHOUT first passing through the now-fixed codec `try_to_commit_certificate`), then a malformed `Commits` (missing height/value, or signer len≠32) still panics the read-node before signature verification — i.e. the F151 fix would be **incomplete on exactly the read-node-crash path the PR set out to fix.** This intersects F005 (read_validator DecidedValue panics on peer gossip). Provenance trace required before rating.

### ⚠️ MINOR — remediation #5 not done
`VoteSetResponse` decode still uses `.zip(vote_set.signatures)` (snapchain_codec.rs:258) — silent truncation on `votes.len() != signatures.len()` remains. F151 judged this non-exploitable for forgery (downstream sig verify rejects mismatches); cosmetic serialization-boundary defect.

### ✅✅ Snapchain cross-verification — hypersnap is AHEAD of upstream
snapchain v0.12.0 has **no** `try_from_proto` / `try_to_commit_certificate` / `try_from_vec`, and its codec **still** calls `Vote::from_proto` (snapchain `snapchain_codec.rs:42,251`), `Proposal::from_proto` (:48), `proposal.height.unwrap()` (:106), `to_commit_certificate()` (:232). **Upstream snapchain remains vulnerable to the full F002/F005/F151 codec-panic class.** This hypersnap fix is hypersnap-specific and not yet upstreamed.
→ **Recommendation: report the F151/F002/F151 codec-panic class to snapchain (farcasterxyz/snapchain) — they have not fixed it.**
