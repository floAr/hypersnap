---
id: ONBD-7
specialist: http-api-rocksdb
attack_class: fail-open-decode
title: Onboarding counter/index readers treat a present-but-wrong-length stored value as the default instead of erroring, so a corrupt HyperNativeFidSequence silently resets FID issuance to HYPER_FID_BASE and re-issues already-used hyper-native FIDs
severity_initial: low
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/native_onboard.rs
validation:
  validator: storage lane
  verdict: PLAUSIBLE
  confidence: 0.5
  hypotheses_walked: 1
---

## Summary

`next_hyper_fid` (`native_onboard.rs:171-183`), `lookup_custody_fid`
(`186-202`), and `read_rotation_nonce` (`644-658`) each treat a *present-but-
wrong-length* stored value as the default: `next_hyper_fid` → `HYPER_FID_BASE`,
`lookup_custody_fid` → `None`, `read_rotation_nonce` → `0`. A corrupt or
truncated `HyperNativeFidSequence` therefore silently **resets issuance to
`HYPER_FID_BASE`** (→ FID reuse / collision with the first hyper-native FID); a
corrupt custody entry reads as "never onboarded" (→ duplicate onboarding +
index overwrite); a corrupt nonce reads as 0 (→ rotation replay).

## Impact / Severity

**Not attacker-reachable** — the only writers (`apply_onboarding` `582-583`,
`apply_custody_rotation` `778-781`) always write exactly 8 bytes, so a
wrong-length value implies disk corruption or a future encoding change, not
adversarial input. Called out because the fail-*open* default masks corruption
instead of surfacing it, and the FID-reuse consequence is severe if it ever
triggers. **Low / informational.**

## Fix

Return an explicit `Storage`/decode error on a present-but-wrong-length value
(fail closed), matching `OnboardingStakeLock::decode`'s strict 32-byte check
(`native_onboard.rs:855-865`).
