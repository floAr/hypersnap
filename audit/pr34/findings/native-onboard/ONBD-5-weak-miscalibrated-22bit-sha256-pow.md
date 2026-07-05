---
id: ONBD-5
specialist: chain-economics
attack_class: weak-sybil-gate-parameter
title: The onboarding hashcash gate is 22-bit SHA-256, which is ASIC/SHA-NI-trivial (milliseconds, not the "~30s single-core" the code comment claims), providing negligible sybil resistance as the sole Phase-1 onboarding gate
severity_initial: medium
commit: 573d67112cf5702349767ce0f682250195830ce1
file_paths:
  - src/hyper/native_onboard.rs
validation:
  validator: economics lane
  verdict: PLAUSIBLE
  confidence: 0.85
  hypotheses_walked: 1
---

## Summary

`MIN_DIFFICULTY_BITS = 22` (`native_onboard.rs:52`) with a SHA-256 pre-image
(`pow_hash`, `native_onboard.rs:315-322`) means an expected `2^22 ≈ 4.19M`
hash evaluations per FID. The in-code comment (`native_onboard.rs:46-51`)
calibrates this as "~30s of single-core CPU work on a contemporary x86 core."
That estimate is wrong by 1.5–3.5 orders of magnitude:

- Modern x86 core with SHA-NI (~300–600 MH/s): **~7–14 ms/FID**.
- Without SHA-NI (~5 MH/s): ~0.8 s/FID.
- Commodity GPU (tens of GH/s) or a SHA-256 ASIC: microseconds/FID.

SHA-256 is the single most hardware-optimized hash in existence, so the gate is
ASIC-dominated. Effective minting rate is hundreds of FIDs/sec/core and
millions/hour on one GPU. Since it is one-FID-per-custody and custody addresses
are free to generate, the cost to mint N hyper-native FIDs is ≈ N × (7 ms … 0.8
s) single-core, trivially parallelizable.

## Impact / Severity

The gate provides negligible sybil resistance, and — worse — the in-code cost
estimate that governance and reviewers would anchor on is off by ~35× (SHA-NI)
to ~3600× (ASIC). The floor is documented as governance-tunable but "not
adaptive in Phase 1" and fixed at 22 at launch, so the launch posture is the
one rated. Amplified by ONBD-4 (one solve → unbounded FIDs), which nullifies
the gate regardless of difficulty. **Medium.**

## Fix

Either raise `MIN_DIFFICULTY_BITS` substantially (and correct the comment to a
defensible estimate) or — since SHA-256 POW is ASIC-dominated — switch to a
memory-hard function (Argon2 / scrypt) for onboarding POW. At minimum, delete
the misleading "~30s" claim. Note that fixing ONBD-4 is a prerequisite for any
POW difficulty to matter at all.
