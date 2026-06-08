# F048 validation — pause does not gate proposeUpgrade (late-propose erases lockout window)

Validator: validator (deliberate-disagreement). Code @ cab225f (read-only).
Finding severity_initial: medium.

## Core claim verification (file:line)

- `whenNotPaused` modifier — `HypersnapBridge.sol:165-168`: `if (block.timestamp < pauseExpiry) revert BridgePaused(pauseExpiry);` — STRICT `<`. Pause is INACTIVE at `block.timestamp == pauseExpiry`. Confirmed.
- `proposeUpgrade` — `:271-311`: signature `external` with NO `whenNotPaused`. Confirmed missing. Only gates: watermark `blockNumber <= latestBlock` (:276), zero-addr (:277), single-pending-slot `pendingImplementation != address(0)` (:278), owner sig (:286), UUPS-compat staticcall (:298). Sets `effectiveAt = uint64(block.timestamp) + UPGRADE_DELAY` (:307). Confirmed callable while paused.
- `executeUpgrade` — `:346`: `external whenNotPaused`; `:350` `block.timestamp < effectiveAt` strict `<`. Confirmed.
- `pause` — `:361-372`: `pauseExpiry = block.timestamp + PAUSE_DURATION` (:369). One-shot, auto-expiring. Confirmed.
- Documented guarantee — `:64-71` storage comment ("24h guaranteed lockout window … even in the adversarial same-block-timestamp scenario") and `:341-345` executeUpgrade doc ("block all execute attempts for 48h, giving cancel ample time to land"). Both present verbatim. Confirmed.
- `PAUSE_DURATION = 72h` (:70), `UPGRADE_DELAY = 48h` (:71). Confirmed.

## Arithmetic re-derivation (independent)

Defender pause at T=0 ⇒ pauseExpiry=72h. Attacker proposes at T_prop=24h (pause still active, propose not gated) ⇒ effectiveAt=24h+48h=72h.
At block.timestamp == 72h:
- whenNotPaused: `72 < 72` == false ⇒ passes (strict `<`, pause inactive exactly at expiry).
- executeUpgrade timer: `72 < 72` == false ⇒ passes.
Both gates clear in the SAME block ⇒ defender cushion collapses from documented 24h to 0h. Arithmetic SOUND. The comment's "same-timestamp" worst case is NOT the genuine worst case because T_prop is attacker-controlled and unconstrained by pause.

## 8-hypothesis walk

1. **Upstream auth / gate** — STANDS. No upstream pause check on proposeUpgrade exists. proposeUpgrade requires owner sig — but in the threat model the owner key is compromised (this is the key-compromise recovery scenario the comments address), so the attacker holds a valid owner sig. The watermark gate (:276) only enforces monotonic blockNumber, not pause state. Nothing upstream halts propose during pause.

2. **Consumer-side impact** — PARTIALLY INVALIDATED (impact bounded, as finding already states). The "corrupted state" is the pending upgrade landing executable with zero pause-overlap. The consumer is `executeUpgrade` → `ERC1967Utils.upgradeToAndCall` (:354) = real implementation swap = total custody loss IF it lands. BUT the finding itself caps impact: `cancelUpgrade` (:316-335) remains available with no pause gate, so a freshly-rotated owner can still clear the pending impl. Net: this is degradation of a documented defense-in-depth window, not standalone unconditional theft. The Medium rating already reflects this. No overstatement beyond what the body concedes.

3. **Downstream enforcement** — STANDS. Does any layer below re-block execute? executeUpgrade's only two gates are whenNotPaused and the effectiveAt timer; both are shown to clear simultaneously. cancelUpgrade is a *parallel* remedy (race), not a downstream enforcement that automatically catches the bug. No automatic backstop.

4. **PR HEAD currency** — STANDS. Workspace pinned at cab225f; `git log -1` HEAD == cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9 (2026-06-08). Lines cited match current file. No drift.

5. **Spec carve-out** — STANDS / strengthens finding. The doc-comments at :64-71 and :341-345 do NOT say "deferred/known-incomplete"; they affirmatively CLAIM the 24h guarantee and "block all execute attempts for 48h." So this is a code-vs-documented-guarantee contradiction (the worst kind for a security comment), not an acknowledged limitation. No carve-out exists.

6. **Reachability of harm** — STANDS (conditional, as bodied). Attacker needs a valid owner sig for proposeUpgrade — i.e. this only bites in the key-compromise scenario, which is precisely the scenario the pause guarantee was written for. Reachable within that model. The harm (execute landing with 0h cushion) is reachable; the *remedy* (cancel) is also reachable, so harm = "guaranteed defensive window reduced to a tight race," reachable and real, bounded as the finding states.

7. **Test wiring** — STANDS. proposeUpgrade/executeUpgrade/pause are production external functions on the deployed bridge contract (UUPS proxy target), not test-only. They are the live upgrade pipeline.

8. **PoC mechanics** — NEEDS_MORE_DATA (no executable PoC supplied), but the analytical proof is self-contained and the arithmetic is independently re-derived above and checks out. The two strict-`<` comparisons clearing in the same block is verifiable by inspection; no PoC needed to establish the timing collapse. The prose claim ("cushion = 0") is exactly what the arithmetic proves — no assertion-vs-claim mismatch.

## Severity judgment

Medium is appropriate. Standalone, this is a defense-in-depth degradation: the pause backstop is not the fire-and-forget guarantee documented, but cancelUpgrade still offers recovery on a current-watermark deployment. It is NOT standalone fund loss. Agree with finder's Medium.

## Shared-root-cause / dedupe note

- F048 root cause: missing `whenNotPaused` on proposeUpgrade + strict-`<` boundary alignment defeating the documented 72h>48h timing cushion. This is a PAUSE-vs-UPGRADE-TIMING bug.
- F045 (high): universal sig cross-deployment replay — different root cause (signature scoping / watermark not deployment-bound). F048 explicitly notes it *compounds* with F045 (on a lagging deployment the cancel remedy is void). Related-by-compounding, NOT same root cause.
- F047 (high): rotateOwner has no priority over other watermark consumers (front-run race). Different root cause (watermark ordering / no rotate priority).
- F049 (high): single max-block sig saturates shared watermark, bricking rotate/cancel while watermark-independent executeUpgrade survives. Different root cause (watermark saturation), though it ALSO concerns the cancel-vs-execute race from a different angle.
- Recommend: link F048 as RELATED to F045/F047/F049 (shared upgrade/pause/watermark control-plane theme + compounding interactions) but DO NOT merge — each has a distinct mechanism and fix. F048's fix (gate proposeUpgrade with whenNotPaused, or push effectiveAt past pauseExpiry on pause) is independent of the watermark fixes.

## Open follow-ups (not new findings)

- Even WITH the recommended fix (1) [gate proposeUpgrade], an upgrade proposed just before a pause (effectiveAt already set) is unaffected by a later pause unless fix (2) [push effectiveAt to >= pauseExpiry on pause] is also applied. The finder lists both; worth ensuring any patch adopts (2) or the timer-reset, not just (1). Noted for the specialist, not a separate finding.

## Overall

Verdict: WATERPROOF (core mechanism + arithmetic confirmed at file:line; impact correctly self-bounded to Medium; comment-vs-code contradiction is real and not carved out).
Confidence: 0.9 (deduction: no executable PoC, but analytical proof is complete and re-derived).
