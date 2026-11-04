---
finding_id: F006
title: The universal V1 upgrade signature binds only a CREATE3 address, which does not commit to V2's verifier or epoch-1 set; the same signature
severity: medium
status: pending-validation
related_findings:
- F005
---
# F006 — The universal V1 upgrade signature binds only a CREATE3 address, which does not commit to V2's verifier or epoch-1 set; the same signature installs a V2 with a different `CERTIFICATE_VERIFIER` on any chain where the implementation is deployed later

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation. Notes: v0.3 upgrade: supersede stale body status lines

> **Status 2026-11-04 (post-validation):** Severity **Medium** (recalibrated 2026-11-04 from Low). See the addendum at the end: the immutable verifier has no recovery path.


- **Category:** upgrade-race / deterministic-deploy; documentation / spec divergence (the NatSpec claim).
- **Specialist:** solidity-bridge · task H004
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** `poc/H004/test/H004.t.sol::test_F006_sameImplAddress_differentVerifier_sameSignature` passes (`poc/H004/H004-forge-output.txt`). It uses a minimal CREATE3 factory with the CreateX address semantics (address = f(factory, salt), independent of init code) and `vm.snapshotState`/`revertToState` to model two chains. The owner signs once. On "chain A", V2 is deployed with the intended verifier. On "chain B", V2 is deployed at the same address with a verifier that accepts everything. The same signature passes `proposeUpgrade` on B, `initializeV2` passes, and an anonymous caller anchors a forged root and mints `1e30`.

## Summary

The V2 NatSpec says (`contracts/src/HypersnapBridgeV2.sol:26-32`):

> `initializeV2` … is safe to front-run: the epoch-1 values are immutables of this implementation, so the owner's signature over the implementation address already commits to them …

The script repeats this (`contracts/script/UpgradeToV2.s.sol:16-18`, `:144-146`). That holds only if the address determines the code. Here it does not:

- The V1 upgrade digest is `keccak256(DOMAIN_UPGRADE || u64(blockNumber) || bytes20(impl))` (`HypersnapBridge.sol:281-285`). It is universal (no chain ID), and it contains no code hash.
- The implementation is deployed with CreateX **CREATE3** with a cross-chain salt (`UpgradeToV2.s.sol:61-73`, salt byte 20 = `0x00`, `:177-183`). For CREATE3 the README itself says: *"Constructor arguments: **don't affect the address**"* (`README.md:248`). `CERTIFICATE_VERIFIER`, `SET_ROOT_EPOCH1` and `TOTAL_WEIGHT_EPOCH1` are constructor arguments (`HypersnapBridgeV2.sol:206-213`).
- The salt is sender-protected (bytes 0..19 = deployer). So no third party can take the address, but the deployer key can deploy **any** init code at that address on each chain, independently.
- V1 `proposeUpgrade` checks only that the address has code and returns the ERC-1967 `proxiableUUID` (`HypersnapBridge.sol:298-304`).

So the owner's signature commits to "whatever the deployer puts at address X on each chain". On a chain where X already has code when the owner signs, the code is fixed (V2 has no `selfdestruct`). On any chain where X is still empty, the deployer can choose the verifier and genesis set after the signature exists.

## The script does not close the gap

- `deployImplementation` checks the immutables only on a fresh deploy (`UpgradeToV2.s.sol:77-80`). If X already has code, it logs "Already deployed" and returns without any check (`:64-67`). A re-run with the correct arguments on a chain where a wrong deploy already exists reports success.
- `_checkImplementation` (`:169-175`), used by `upgradeDigest`, `propose` and `execute`, checks only `CERTIFICATE_VERIFIER().code.length > 0` and `SET_ROOT_EPOCH1 != 0`. It does not check equality with the expected values, the implementation's codehash, or the verifier's codehash.
- `execute` reads the values that it passes to `initializeV2` from the implementation itself (`:133-134`, `:147`), so the post-checks (`:155`) are always true.
- The operator check "compare `SET_ROOT_EPOCH1()` … before anyone signs" (`:25-27`) is per chain, before signing. It cannot cover a chain where the deploy happens after the signature.

## Attack / failure scenario

1. The deployer deploys V2 at X on Ethereum with verifier `V` and `PivotRecord` values. Reviewers check it. The owner signs `HYPERSNAP_UPGRADE_V1(bn, X)`.
2. On Optimism (or any later chain), the deployer key deploys `HypersnapBridgeV2(V', root', w')` at X. The cause can be compromise, malice, or a mistaken run with a testnet or mock verifier.
3. Anyone relays the same signature to Optimism V1 `proposeUpgrade`. It passes.
4. 48h later, `executeUpgrade` and `initializeV2(root', w')` pass. With `V'` accepting any proof (or `root'` naming an attacker set), anyone calls `advanceRoot` with a forged header and `claim` mints without limit. All later governance on that chain also goes through `V'`.

Defence today: during the 48h window, someone must read the immutables on every chain. The V1 owner can then `cancelUpgrade`. That cancel signature is also universal and binds only X, so anyone can replay it on the good chains too and cancel the legitimate upgrade there as well. The operators then have to redo the whole ceremony at a new address.

## Related: verifier mutability

The bridge also checks only `verifier.code.length > 0`: in the V2 constructor (`HypersnapBridgeV2.sol:207`) and in the script (`:60`, `:173`). If the deployed CERT-STARK verifier is a proxy, or has an owner or any mutable state, its admin silently controls every anchor and governance action of V2. The 48h upgrade delay and the CERT-STARK trust model then do not apply to it. `ICertificateVerifier` says "The verifier is stateless" (`interfaces/ICertificateVerifier.sol:18`). Nothing enforces it.

## Requirements V2 places on the future CERT-STARK verifier (for the R3 implementer)

- It must be **non-upgradeable** and **admin-free**: no proxy, no `delegatecall` to mutable targets, no `selfdestruct`, no owner-settable parameters (for example, FRI parameters or a vk hash in storage). Its runtime code hash should be published and pinned.
- It must be deployed on every target chain with the **same codehash**, and the V2 implementation must be deployed with the same verifier address. Otherwise the cross-chain address equality that the universal signature relies on hides a difference.
- It must be a `view` that returns `false` (not `true`) on any parse or edge-case failure that it cannot positively verify. A permissive default is equivalent to the `RubberStampVerifier` in this PoC.

## Spec vs code

- §13.4: *"The deployment of the bridge contract sets `setRoot[1]` and `totalWeight[1]`. Anyone can compare these values with the `PivotRecord`."* In the code these values come from implementation immutables that are approved by address only. Anyone can still compare them, but must do it on every chain and after the last deployment. The NatSpec claim that the signature commits to them is **wrong** (code/doc side).

## Red-team walk

1. *Can a third party deploy at X?* No. CreateX sender protection ties the salt to the deployer. So the precondition is the deployer key, not anyone. That is why this is Low.
2. *Deployer == owner in practice?* `Deploy.s.sol` defaults the genesis owner to the deployer, but the README intends the owner to become a threshold address and the deployer key to be retired (`README.md:268-270`). `UpgradeToV2.deployImplementation` uses whoever broadcasts (`:61`). If they are the same key, the owner could also sign a malicious implementation directly (F005), so the issue reduces to the false NatSpec claim and the missing script checks.
3. *Does `proposeUpgrade` on an empty address revert?* Yes (`try … proxiableUUID` fails). So the signature can only be used where X has code. That is why the danger is "deploy later, then relay".
4. *Does `initializeV2` catch it?* No. It only compares its arguments with the implementation's own immutables (`:222-224`).
5. *Detectable?* Yes, within 48h, if someone checks every chain. Without that, the failure is silent.

## Recommended fix

- Bind code, not only the address. Add `impl.codehash` (and ideally the chain ID, or keep it universal but codehash-bound) to the V1 upgrade digest, and check `newImplementation.codehash == signedHash` in `proposeUpgrade`. The immutables are part of the runtime code, so the codehash commits to the verifier and the genesis set.
- In the script: verify the immutables against the expected values on the "Already deployed" branch, and in `_checkImplementation`. Check the verifier's codehash against a pinned value, and reject a verifier that has an ERC-1967 implementation slot or admin.
- Correct the NatSpec in `HypersnapBridgeV2.sol:26-32` and `UpgradeToV2.s.sol:16-18`, `:144-146`.

## Leads

- H006 (`initializeV2` replay / front-run): the front-run is harmless (the arguments must equal the immutables, `:222-224`). The only effect is that the script's own `initializeV2` reverts with `InvalidInitialization` after a front-run, and the script then aborts before its post-checks (`UpgradeToV2.s.sol:147-163`). That is cosmetic. Also check what version a future V3 uses: `reinitializer(2)` is spent by V2.
- H005: no layout issue found while reading. V1 has slots 0–5 plus `__gap[44]`, and V2 has slots 0–5, four new slots and `__gap[40]`, both 50 in total. V2 clears slot 0 and leaves slot 1 (the V1 retro root) stale but unused.

## Addendum (2026-11-04): the immutable verifier has no recovery path

Source: the internal validation notes, "Dependency review". The facts were checked at `7eb981b`.

- `CERTIFICATE_VERIFIER` is a constructor `immutable` (`HypersnapBridgeV2.sol:98`, `:209`). Every V2 path that moves state goes through it: `advanceEpoch` (`:262`), `advanceRoot` (`:280`), and `_applyAction` (`:496`), which backs `proposeUpgrade`, `cancelUpgrade` and `pause` (`:337-377`).
- No path bypasses it. `upgradeToAndCall` and `_authorizeUpgrade` both revert (`:392-398`). `executeUpgrade` only runs an implementation that was proposed under a certificate. `initializeV2` clears the V1 owner, so no admin key remains. On Hypersnap, an outbound `lock` debits the balance, and the ledger has no unlock.
- **If the verifier is unsound,** anyone can mint, and the honest set cannot stop a takeover. A forged certificate proposes an upgrade at height 2^64−1 (the F004 path-3 mechanism), so `pause` and `cancelUpgrade` revert with `StaleAction`. This finding (a wrong or permissive verifier installed) and F011 (gaps in the statement) are routes into this state.
- **If the verifier is too strict,** the bridge is bricked for good. Anchors, handoffs, pause and upgrade all revert, and nothing can replace the verifier, because a replacement needs an upgrade, and the upgrade needs that verifier. Hypersnap→L1 locks made after the last good anchor are stranded. F010 (a verifier built to FIP §16.6) is a route into this state.
- **Partial strictness is the worst case.** The bridge keeps working until it reaches a certificate the verifier rejects, for example a required `advanceEpoch` handoff. That only shows up in production.
- **Fix directions:**
  - (a) A liveness fallback. After N days without an anchor, a pre-committed recovery authority, frozen into V2 as an immutable, can propose an upgrade under a long delay.
  - (b) A separate verifier for governance actions only (pause and upgrade).
  - (c) A ceremony gate: before the V1→V2 upgrade is signed, run the verifier end to end on real mainnet-shaped certificates, including edge-case bitmaps.
- **Severity of the dependency** as a design issue: High (impact if shipped: Critical and permanent in either direction; the precondition is a defect in a STARK circuit that hasn't been written yet).
