# Revalidation — bridge-watermark cluster (F045, F047, F048, F049)

- AUDITED commit: `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
- NEW "fixes" commit: `5c2594563df84c374fdce7cdeae06d3444da3b72` (direct child)
- Revalidated: 2026-06-12

## Decisive cross-cutting fact

The NEW commit's changed-file set does **not** include
`contracts/src/HypersnapBridge.sol`. Confirmed by `git diff --stat`: the only
bridge-side file touched is `crates/hypersnap-crypto/src/bridge_payload.rs`
(plus `src/hyper/runtime.rs` wiring). I exported and read the contract at the
NEW commit
(`git show 5c25945:contracts/src/HypersnapBridge.sol`) and it is **byte-identical**
at every entry point referenced by these four findings:

- Universal digests still bind only `(domain, bytes8(blockNumber), payloadFields)`:
  `claim` root-update L189-193, `rotateOwner` auth L238-242, `OWNER_ACCEPTANCE`
  L247-250, `proposeUpgrade` L281-285, `cancelUpgrade` L325-329, `pause` L363-366.
  No `block.chainid`, no `address(this)`, no `deploymentId` in any universal preimage.
- Single shared watermark `uint64 latestBlock` (L90); every universal gate is
  `if (blockNumber <= latestBlock) revert StaleBlock` then `latestBlock = blockNumber`
  (L235/255, L276/306, L321/331, L362/368, L188/195), and `recoverERC20` consumes
  the same counter (L399/411). No dedicated rotation counter, no upper bound.
- `proposeUpgrade` (L271-274 signature) still has **no** `whenNotPaused` modifier;
  only `claim` (L182), `burn` (L380), and `executeUpgrade` (L346) carry it.
- `executeUpgrade` (L346-355) still reads only `pendingImplementation`,
  `pendingUpgradeEffectiveAt`, `pauseExpiry` — no `latestBlock` read, no signature,
  permissionless.

The contract is the true verification sink for every one of these findings. Since
it was not modified, **no contract-enforced defense was added** for any of them.

## What the NEW commit actually changed (bridge-relevant)

`crates/hypersnap-crypto/src/bridge_payload.rs` adds an honest-signer block-number
cap (only relevant to F049):

```rust
// bridge_payload.rs (NEW)
pub const MAX_SANE_BRIDGE_BLOCK_NUMBER: u64 = (1u64 << 48) - 1;

pub fn validate_bridge_block_number(block_number: u64) -> Result<(), BridgeBlockNumberError> {
    if block_number > MAX_SANE_BRIDGE_BLOCK_NUMBER {
        return Err(BridgeBlockNumberError::TooLarge { block_number, cap: MAX_SANE_BRIDGE_BLOCK_NUMBER });
    }
    Ok(())
}
```

Wired into the two existing producers in `src/hyper/runtime.rs`:
- `produce_signed_lock_merkle_root_local` (L949) — call at L956.
- `produce_signed_owner_rotation_local` (L1079) — call at L1086.

There is **no** producer for pause / proposeUpgrade / cancelUpgrade in runtime.rs,
so those universal payloads are not even routed through the cap on the honest side.
The cap's own doc-comment concedes it does not bind a Byzantine signer ("they sign
outside this code path"). No `block.chainid` / `address(this)` binding, no
namespace separation, no contract change was made.

---

## F045 — Universal control-plane sigs replay across deployments

**Verdict: NOT_FIXED — confidence 0.95**

The recommended fix was contract-side: include `block.chainid` AND `address(this)`
(or a `deploymentId`) in the preimage of `UPGRADE`, `UPGRADE_CANCEL`,
`OWNER_UPDATE`, `OWNER_ACCEPTANCE`, `PAUSE` on both the Solidity and Rust sides,
and add a watermark to `OWNER_ACCEPTANCE`. None of this was done. The contract is
unchanged: every universal digest still omits chain/address binding (e.g.
`proposeUpgrade` L281-285, `cancelUpgrade` L325-329, `pause` L363-366,
`OWNER_ACCEPTANCE` L247-250 which still has no watermark at all). The Rust change
is a block-number magnitude cap only — it does **not** introduce deployment
binding into any digest. The cross-deployment replay window for a
superseded/old-key universal signature onto a watermark-stale deployment is
exactly as described in the audit. Residual gap: the entire documented attack
path is open, including the `OWNER_ACCEPTANCE` "replayable forever/everywhere"
sub-gap and the `recoverERC20` shared-watermark coupling aggravator.

## F047 — Owner-rotation front-run defeats key-compromise recovery

**Verdict: NOT_FIXED — confidence 0.95**

The recommended fix was contract-side: decouple `rotateOwner` onto a dedicated
rotation-only monotonic counter; bind the authorization digest to the current
`ownerAddress` + deployment identity; bind the acceptance digest to `blockNumber`.
None of this was done. `rotateOwner` (L229-258) still shares the single
`latestBlock` watermark with `pause`/`proposeUpgrade`/`cancelUpgrade`/`recoverERC20`/
`claim` root-update; the auth digest still binds only
`(DOMAIN_OWNER_UPDATE, bytes8(blockNumber), bytes20(newOwner))` (L238-242) — not
the outgoing owner — and the acceptance digest still binds only
`(DOMAIN_OWNER_ACCEPTANCE, bytes20(newOwner))` (L247-250) with no block. The
mempool front-run / starvation primitive and the "attacker rotates to
`O_attacker` permanently" seizure variant are both fully intact. The Rust
block-number cap does not touch the race model. The `validate_bridge_block_number`
call added to `produce_signed_owner_rotation_local` (L1086) only rejects absurdly
large block numbers from honest signers; it provides no priority and no anti-front-run
property. Residual gap: complete attack path open.

## F048 — Pause does not gate proposeUpgrade

**Verdict: NOT_FIXED — confidence 0.97**

Purely contract-side finding (the writeup lists only `HypersnapBridge.sol`). The
recommended fix — add `whenNotPaused` to `proposeUpgrade`, and/or push
`pendingUpgradeEffectiveAt` out to `pauseExpiry` on pause — was not applied.
`proposeUpgrade` (L271-274) still carries no `whenNotPaused` modifier; only
`claim`, `burn`, `executeUpgrade` do. The attacker can still call `proposeUpgrade`
during an active pause and set `effectiveAt = T_prop + 48h >= pauseExpiry`,
collapsing the documented "24h guaranteed lockout" to zero. The L64-71 / L341-345
comments asserting the guarantee are also unchanged (still wrong). The Rust commit
has zero bearing on this finding. Residual gap: complete attack path open;
documented defense-in-depth guarantee still violated.

## F049 — Max-block watermark saturation bricks rotate/cancel; executeUpgrade survives

**Verdict: PARTIALLY_FIXED — confidence 0.85**

This is the only finding the NEW commit meaningfully touches. The audit's primary
recommendation was contract-side ("Bound the accepted `blockNumber` on every
universal entry point ... `blockNumber <= latestBlock + MAX_BLOCK_ADVANCE`")
**and** a secondary Rust mirror ("Apply the same bound in `bridge_payload.rs` so
honest signers never produce out-of-range block numbers"). Only the secondary
half was implemented: `MAX_SANE_BRIDGE_BLOCK_NUMBER = 2^48 - 1` plus
`validate_bridge_block_number`, wired into the two runtime producers
(`produce_signed_lock_merkle_root_local` L956, `produce_signed_owner_rotation_local`
L1086).

The contract — the actual sink — has **no** upper bound. `latestBlock` is still a
raw `uint64` (L90) with no cap on the supplied value at any gate (L235, L276, L321,
L362, L188, L399), and `executeUpgrade` is still watermark-independent and
permissionless (L346-355). So:

- Against an **honest** producer, a saturating block number can no longer be
  emitted accidentally (closes the misconfiguration / single-corrupted-validator
  tail). This is a real, if narrow, improvement and matches the finding's own
  "accidental tail" framing.
- Against the finding's **actual threat model** — the key-compromise / Byzantine
  signer who "holds the threshold key and can sign any universal payload at any
  block number" — the cap is irrelevant. A compromised signer signs outside the
  honest code path (the new comment explicitly admits this). Such a signer can
  still submit `pause(2^64-1, sig)`, permanently saturate `latestBlock`, brick
  `rotateOwner`/`cancelUpgrade`/`pause`/root-advancement, and then let the
  permissionless `executeUpgrade` fire a pending malicious implementation. The
  custody-theft path and the unconditional permanent-DoS variant both remain.

Two further residual gaps untouched: (a) the recommended decoupling of
`cancelUpgrade`/`rotateOwner` onto a separate non-saturable counter; (b) the
recommended `executeUpgrade` owner-snapshot check. Net: the lower-severity
accidental tail is mitigated honest-side; the high-severity adversarial core
(the reason the finding is High) is unaddressed because the contract was not
bounded. PARTIALLY_FIXED.

---

## Summary table

| ID   | Verdict          | Confidence | One-line reason |
|------|------------------|-----------|-----------------|
| F045 | NOT_FIXED        | 0.95 | Contract untouched; no chainId/address binding added to any universal digest; OWNER_ACCEPTANCE still watermark-less. |
| F047 | NOT_FIXED        | 0.95 | `rotateOwner` still on shared watermark; auth digest not bound to outgoing owner; acceptance still block-less; race primitive intact. |
| F048 | NOT_FIXED        | 0.97 | `proposeUpgrade` still lacks `whenNotPaused`; pure-Solidity fix never applied; Rust commit irrelevant. |
| F049 | PARTIALLY_FIXED  | 0.85 | Rust honest-signer cap (2^48-1) closes accidental tail only; contract has no bound, so Byzantine-signer saturation + `executeUpgrade` custody-theft core remains open. |
