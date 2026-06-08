# F070 validation — custody-sig gate unwired in production router

Validator: validator (deliberate-disagreement). Commit `cab225f`. Date 2026-06-08.

Finding claim: the EIP-712 custody cross-sign gate for validator registration is
implemented (`validate_and_check_quota`/`validate_register_with_trust`) but never
wired into the live ingestion path. The production router is built without a
`CustodyResolver`, so `route_inbound` takes the lenient `validate_event(.., None)`
branch, which skips the custody check. An attacker can register an arbitrary
self-generated validator key bound to any FID.

## Pipeline traced (entry → mutate)

- `actor.rs:1218` (gossip `InboundMessage`) and `actor.rs:1230` (`LocalSubmitMessage`)
  → `runtime.submit_message(msg)`.
- `runtime.submit_message` (`runtime.rs:3664`): ValidatorEvent is NOT intercepted
  earlier (unlike RewardIssuance/TokenTransfer/Miniapp* which return early). The only
  pre-router gate is the trust floor (`runtime.rs:3855`, `if min_validator_trust_score > 0.0`).
- Router constructed at `runtime.rs:3882` via `HyperRouter::new(...)` with NO
  `.with_custody_resolver(...)` → `custody_resolver = None` (`router.rs:111`).
- `route_inbound` ValidatorEvent branch `router.rs:165-169`: `None` → lenient
  `ValidatorRegistry::validate_event(&event, epoch, None)` then `registry.record_event`.
- `validate_event` (`validator_registry.rs:367-412`): with `custody_address == None`,
  custody sig is only checked `if has_custody` (non-empty) AND `Some(addr)`. Attacker
  omits `custody_signature` → empty → custody check skipped entirely. Only the
  attacker-controlled, self-signed Ed25519 over `validator_key` is verified
  (`verify_event_signature` `validator_registry.rs:172-187`), which proves nothing
  about FID ownership.
- `record_event` (`validator_registry.rs:541-581`) writes directly to `self.db`
  (RocksDB) — persists `[HyperValidatorEvent]`, `[HyperValidatorByFid][fid][vk]`,
  and `[HyperValidatorFidLookup][vk]→fid` immediately at ingestion. No separate
  consensus-admission re-validation.

## 8-hypothesis walk

1. Upstream auth/gate — STANDS. The only upstream gate in `submit_message` is the
   trust floor (`runtime.rs:3855`), gated on `min_validator_trust_score > 0.0`. Every
   non-test config sets it to `0.0` (config.rs:526, genesis.rs:121, devnet.rs:41,
   dkls_driver.rs:136, scheduler.rs:596). So by default no upstream gate runs at all,
   and even when set (>0) it only checks the *claimed* FID's trust score — never
   custody authorization. ValidatorEvent is not early-intercepted, so the router is
   genuinely the live handler.

2. Consumer-side impact — STANDS. The `[HyperValidatorFidLookup][vk]→fid` binding is
   consumed by DA-PoW response admission (`runtime.rs:3292-3307`,
   `fid_for_validator_key == body.fid`) and the per-FID active index drives
   `count_active_validators_for_fid` / `compute_active_set`. Persisted state is read
   by real authorization logic, not just "writes garbage to disk."

3. Downstream enforcement — STANDS. No lower layer re-validates. `record_event` mutates
   the DB at ingestion. The block importer does NOT re-apply validator events:
   `apply_validator_events` (`importer.rs:65`) has zero production callers (grep
   confirms only its own definition + doc references; `import_hyper_block*` never call
   it), and the builder never references validator events. So there is no
   block-import/consensus re-check that supplies a resolver.

4. PR HEAD currency — STANDS. Pinned commit `cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9`
   matches finding frontmatter; working tree clean; HEAD detached at the pinned SHA.
   No drift.

5. Spec carve-out — PARTIALLY. The lenient branch is documented as
   "tests + migration" (`router.rs:163`) and the importer doc says "Production callers
   should always pass a resolver" (`importer.rs:64`). This is the inverse of a
   carve-out: the code comments assert production SHOULD wire a resolver, and it does
   not — strengthening, not excusing, the finding. No doc says the gate is intentionally
   deferred in production. STANDS as a defect; impact framing unchanged.

6. Reachability of harm — STANDS. Exploit is a single crafted gossip ValidatorEvent
   (Register) with a valid self-signed Ed25519 sig over the attacker's own
   `validator_key` and an empty `custody_signature`, naming any `fid`. It passes
   `validate_event(.., None)` unconditionally and is persisted. No additional gate on
   the path (trust floor off by default).

7. Test wiring — STANDS (this is the crux, and it confirms the finding). The strict
   functions are exercised ONLY in tests: `validate_and_check_quota` and
   `validate_register_with_trust` callers are all in `validator_registry.rs` tests
   (lines 1280-1469). `with_custody_resolver` (`router.rs:115`) is never called outside
   its definition/doc. `apply_validator_events` (`importer.rs:65`) is never called at
   all. So the implemented gate is dead code in production; the lenient path is the one
   actually wired.

8. PoC mechanics — N/A / STANDS. No PoC artifact attached; the claim rests on static
   dispatch tracing, which I reproduced end-to-end above. The prose's mechanism
   (None-resolver → lenient → empty custody sig skipped) matches the code exactly.
   `verify_event_signature` binds only `validator_key`, not `fid`, confirming the FID
   is attacker-chosen.

## Severity judgement

High is appropriate. Registration authorization is the trust anchor for committee
selection (DKLS), proposer set, quorum math, and DA-PoW FID attribution. The gate is
unreachable on every live path and the fallback (trust floor) is disabled by default.
Not direct fund loss, but a silent, total bypass of validator-registration
authorization — consistent with high-severity authorization/incentive-distortion for
this domain. Interaction with F028 (threshold=1) and F025 (committee grinding) is real
but those are distinct root causes; F070 makes them strictly cheaper (no custody key
needed, per-FID 3-cap does not bind since it lives only in the dead strict path).

## Overall verdict

WATERPROOF. Confidence 0.9. Every hypothesis either STANDS or strengthens the finding.
The only residual is that a deployment could set `min_validator_trust_score > 0.0`,
which raises (but does not establish custody authorization for) the bar — the finding
already states this caveat accurately, so it is not an invalidation. Cross-checks with
H075's router-gap observation: consistent (ValidatorEvent dispatch is the live gap).

## Open follow-ups (NOT new findings)

- The trust floor (`runtime.rs:3855`) being disabled by default in genesis/config could
  warrant operator-doc hardening; out of scope for this finding's body.
