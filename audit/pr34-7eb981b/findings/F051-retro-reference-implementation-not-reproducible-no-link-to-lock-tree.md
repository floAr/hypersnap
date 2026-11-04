---
finding_id: F051
title: The retroactive "reference implementation" named by FIP §10.5 (`src/bin/retro_rewards_finalize.rs`) breaks every determinism rule that
severity: low
status: pending-validation
related_findings:
- F050
- F007
- F003
---
# F051 — The retroactive "reference implementation" named by FIP §10.5 (`src/bin/retro_rewards_finalize.rs`) breaks every determinism rule that section states. It uses `f64` throughout and sums over `HashMap` iteration order. It reads its input live from a third-party hub URL. Its output is float whole-token CSVs, one per CLI-selectable mutuality mode. Nothing turns that output into the integer lock snapshot that `bridge-ceremony build-tree` signs, and `build-tree` checks no total against `RETROACTIVE_POOL`. So no one can reproduce or verify the on-chain allocations as §10.5 promises.

- **Severity:** Low, source-only. FIP §10.1 says the distribution already happened, so no live funds depend on this code. The impact is on verifiability and audit claims. A mis-built snapshot (over-pool total, wrong FID→address mapping, duplicate FID under two lock ids) would go undetected by the tooling, and only the owner signature (F005) guards the V1 root.
- **Confidence:** 0.8.
- **Category:** retro-rewards-replay / mutuality-asymmetry (offline vs online computation)
- **Specialist:** chain-economics · task H052
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34). **PR-introduced** (`src/bin/retro_rewards*.rs`, `crates/hypersnap-bridge-ceremony/` are new at merge-base `bdef7b7`).
- **PoC:** None, reasoned from source.

## Code facts

1. **Floating point and hash order.** `RETROACTIVE_POOL: f64 = 200_000_000.0` (`retro_rewards_finalize.rs:148`). Metrics are `HashMap<u64, FidMetrics>` (`:927`). EigenTrust runs over `HashMap`/`HashSet` with `f64` accumulation in hash-iteration order (`:1978-2050`). The pool normaliser is `metrics.values()...sum::<f64>()` (`:1271-1276`). `HashMap` uses a per-process random seed, so the summation order, and with it the low bits of every `f64`, can differ between two runs on the same input. Thresholds compared against these values (trust floor, percentile filters) can then flip for boundary FIDs.
2. **External live input.** The data source is `--hub-url` with default `https://haatz.quilibrium.com` (`:227`). Recoveries come from Optimism RPC log scans (`:1430-1520`). The tool takes no fixed snapshot height and no content hash of the input.
3. **Selectable algorithm.** `--mutuality-modes` (default `harmonic`, but `min,geom,avg,sum` accepted) writes one `final.<mode>.csv` per mode (`:233-240, 877-910, 1293-1297`). The live PoQ uses harmonic only (`crates/proof-of-quality/src/scoring.rs:163-230`). Most exponents and floors are CLI flags with defaults (`:253-330`).
4. **Output format.** `write_final_csv` writes `fid, format!("{:.6}", tokens)` as float whole tokens, sorted by amount (`:2130-2170`). It writes no integer micro-units, no address, no lock id, and no total check.
5. **Ceremony input is unrelated.** `build-tree` reads `{lock_id, destination_chain_id, recipient, amount}` (`crates/hypersnap-bridge-ceremony/src/types.rs:8-26`). It rejects duplicate `(lock_id, chain)` pairs and sorts by leaf hash (`main.rs:281-358`). It does not check Σ `amount` against `RETROACTIVE_POOL`, a FID→recipient binding, the lock-id derivation or domain (see F003), or that each FID appears once. No code in the repo produces this JSON from the finalize CSV.

## Spec (FIP §10.5, spec lines 921-971)

> 1. Fixed snapshot. 2. **Integer arithmetic.** All intermediate values used fixed-point integer arithmetic. 3. **Ordered iteration.** … FIDs in the order of FID number … 4. **No external state.** … No external chain query …
> The reference implementation is `src/bin/retro_rewards_finalize.rs`. Anyone can run it on the same snapshot and compare the result with the allocations of the Ethereum contract.

The code meets none of points 1-4.

## Failure / abuse path

- A third party re-runs the reference tool to check the V1 root. They get a different float result: a different hub state, different hash order, or different flags. They have no defined way to map it to the leaves (lock id, address, integer amount). The claim "anyone can verify" cannot be exercised.
- An operator assembling the snapshot by hand can include a FID twice under two lock ids, round floats up, or exceed 200M. `build-tree` accepts all of it.

## Red-team

1. *Retro is complete per §10.1, so does any of this matter?* Only for verifiability and the spec's audit claim. That is why this is Low, not Medium.
2. *Maybe a different, deterministic tool produced the real allocations.* Possibly, but the FIP names this file. If another tool was used, the FIP is wrong instead. Either way, it is a divergence.
3. *Does hash-order nondeterminism actually change results?* The effect on amounts is about 1e-16 relative, mostly hidden by the 6-decimal output. Thresholds can still flip at exact ties. I did not run it. The main point stands without this: `f64` plus a live remote source cannot be bit-reproduced.
4. *Replay of retro into live emission (persona class)?* Ruled out. Hypersnap genesis has no retro records (§10.1), and live emission only offsets by `RETRO_MINTED` (see F050). No path credits a retro FID on Hypersnap.
5. *Do duplicate retro lock ids collide with V2 lock ids?* V2 ids are `keccak("…lock…" || fid || nonce)` (`src/chain/shard0/ledger.rs:527-543`). A collision would need the snapshot author to pick such a preimage. That is already covered under F003/F005 trust. Not refiled.

## Fix

- Either update §10.5 to describe the actual process, or make the tool match it. That means integer fixed point (reuse `crates/proof-of-quality`), `BTreeMap` ordering, input from a pinned snapshot file with a published hash, a single algorithm, and output of integer micro-units.
- Add a `retro → lock snapshot` step with a documented lock-id derivation (domain-separated, see F003) and FID→address source. Make `build-tree` check `Σ amount ≤ RETROACTIVE_POOL` and one leaf per FID.
- Publish the snapshot hash, the CSV hash and the tree root together.

## Files

- `src/bin/retro_rewards_finalize.rs:148, 227-330, 877-927, 1255-1297, 1978-2050, 2130-2170`
- `crates/hypersnap-bridge-ceremony/src/main.rs:281-358`, `src/types.rs:8-40`
- `docs/spec/FIP-proof-of-work-tokenization.md` lines 921-971
