# F024 PoC: unbounded validator inflow halts or captures shard 0's next set

Target: farcasterorg/hypersnap @ `7eb981b`. Uses the WSL build tree `<build-tree>` (malachite at `<malachite>`). Validated scope is shard 0 only. Bridge capture is not reachable at 7eb981b (see the internal validation notes), so this PoC does not touch the bridge.

## Environment and commands

- WSL2 Ubuntu, `rustc 1.95.0`, `RUSTFLAGS="--cap-lints allow"`.
- Source copy: `<build-tree>` (from `git archive 7eb981b`). The audit checkout was not modified.
- Test file: `<build-tree>/src/chain/shard0/f024_poc_test.rs`, wired as `#[cfg(test)] mod f024_poc_test;` at the end of `src/chain/shard0/mod.rs`. A copy is here as `f024_poc_test.rs`.
- Run (via a local helper script, not included): `cd <build-tree> && RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib f024 -- --nocapture --test-threads=1`
- The incremental build took 36 s and the 6 tests ran in 19 s.
- Output: `F024-test-output.txt`.

## Fixture

- The real shard-0 `Net` harness from `src/chain/shard0/test_support.rs`: 3 nodes on one genesis, with the 4-member bootstrap set (`Genesis::new(4)`, `n_h = 4`). Every block is proposed on node 0, validated on nodes 1-2 and committed on all three, and the state roots must agree.
- `params()` from the harness, but with **`min_validator_trust_fp = 50_000`**, the mainnet 0.05 value (`mod.rs:130-134`). The devnet default is 0, so the trust gate is switched on explicitly here.
- The attacker FIDs (5001..) are registered by on-chain `IdRegister` events, funded by an inbound burn and migrated to Falcon custody with a real `CustodyMigration`.
- Trust comes in through the production path. A `ScoringResult` for epoch 1 that gives each attacker FID `trust_fp = 50_000` is supplied as the node input. The proposer carries it at `boundary(2) + SCORING_DELAY`, and `apply_scoring_result` writes `trust_score(fid)`. The test asserts the stored value. This is the minimum value that passes the gate.
- Each FID posts real `NODE_ATTESTATION`s (up to 3) in epoch 1. In epoch 2 it posts all of its `VALIDATOR_REGISTER`s **in one block**, with real Falcon PoPs, and each registration passes `validators::register`. The registered seats join at epoch 4.
- The chain runs to the last block of epoch 3. The boundary of epoch 3 (`on_boundary` -> `write_set_record(4)`) has written `set(4)`. Then the first block of epoch 4 is proposed and validated. Its parent certificate comes from the honest `set(3)`, so that succeeds.
- The newcomer seats never sign. Honest certificates are signed by all 4 genesis keys over the real precommit bytes (`certificate::precommit_sign_bytes`) and built with `certificate::build`. In the capture test, the newcomer certificate is signed by the 9 newcomer Falcon consensus keys.
- The checks are the real `certificate::verify(&epoch_set(4), cert)`, plus the child-block check: after the epoch-4 block is committed with that certificate, its child is proposed and `Shard0Engine::validate` runs on node 1, which checks the parent certificate against `set(4)` (`check_structure`).

## Tests and results

| Test | Inflow (FIDs x seats) | `set(4)` | What it asserts | Result |
|---|---|---|---|---|
| `f024_one_fid_three_silent_seats_halts_shard0` | 1 x 3 | 7 (4 honest + 3 new) | All 4 honest signers give `verify` = `NoQuorum { weight: 4, total: 7 }`. The child of an honest-only epoch-4 block is rejected by `validate`: "signers have weight 4 of 7; more than 2/3 is needed". | **RED** (pass, halt reproduced) |
| `f024_threshold_two_seats_halts_shard0` | 1 x 2 | 6 | `A = n_h/2` is already enough: `NoQuorum { weight: 4, total: 6 }` (3·4 > 2·6 is false). | **RED** (pass) |
| `f024_three_fids_nine_seats_dominate_next_set` | 3 x 3 | 13 | Honest signers give `NoQuorum { 4, 13 }`. **The 9 newcomers alone pass `verify`** (27 > 26), and a block certified only by newcomers passes the real child validation. | **RED** (pass, capture of shard 0 reproduced) |
| `f024_control_one_seat_chain_continues` | 1 x 1 | 5 | Normal inflow: the honest 4 keep quorum (12 > 10). `verify` and the child validation pass, and the chain keeps committing epoch-4 blocks (tip at height 163, epoch 4). | pass (control) |
| `f024_control_trust_gate_rejects_unscored_fid` | 1 x 1, no `ScoringResult` | - | The gate is live: with trust 0, `register` returns "trust score is below min_validator_trust_score". | pass (control) |
| `f024_control_fourth_attestation_rejected` | 1 x 4 attestations | - | The per-FID cap: the 4th attestation returns "the FID has MAX_NODES_PER_FID attestations". So 3 seats per FID is the maximum, and it is reached in the RED tests. | pass (control) |

**All 6 tests pass, and the claim reproduces for shard 0.** Every registration passes the trust gate at the mainnet threshold, and the inflow in one block of one epoch is unbounded. `set(E+2)` takes every seat at weight 1. One FID with 3 silent seats takes the 4-member bootstrap set below quorum. Three FIDs (9 seats) give the newcomers a quorum by themselves.

## What was exercised vs source-only

Exercised with real code:
- `node_attestation` (including the 3-per-FID cap)
- `validators::register` (role, epoch, both Falcon PoPs, attestation FID, trust gate)
- `apply_scoring_result` (writes the trust value)
- `on_boundary` -> `write_set_record` -> `members_at` (weight 1, no cap)
- `Shard0Engine::epoch_set`
- `certificate::build` / `certificate::verify` / `EpochSet::is_quorum`
- the parent-certificate check in `Shard0Engine::validate`

All of these run on a multi-node engine with agreeing state roots.

Source-only (not driven here):
- **Malachite liveness.** The PoC shows that no certificate over `set(4)` can be valid without the newcomers. It does not run Malachite rounds, timeouts or proposer rotation. The silent seats also own proposer slots in `set(4)`, which is not exercised.
- **No fallback set.** There is no code path that falls back to `set(3)` when `set(4)` cannot reach quorum (`consensus/validator.rs:165-175`). Grep evidence only.
- **No in-protocol recovery.** Auto-deregistration only counts misses from the parent certificates of committed blocks, so it cannot fire during a halt (`validators.rs:345-393`), and it would take effect at `epoch + 2` anyway. Not exercised. F025 and F029(b) remove this slow path even for sub-threshold inflow.
- **FID age gate.** The harness sets `min_validator_fid_age_secs = 0`, so the 90-day `effective_age` check (`validators.rs:191-193`) is not exercised, and neither is the age reset on transfer. The trust *value* is exercised. How hard it is to reach 0.05 of the top-100 EigenTrust average is not.
- **Data shards.** Not touched. Per H014/F029 they continue under `set(N+1)`.

## Caveats

- `n_h = 4` (the harness's bootstrap set) is the smallest realistic case. The arithmetic scales: a halt needs `A >= n_h/2` seats (`ceil(n_h/6)` FIDs), and capture needs `A > 2·n_h`. The tests check both inequalities against the real `is_quorum`, at both edges (A = 2 halts, A = 1 does not).
- The seats are silent because their keys never sign, which is all the finding needs. No equivocation or malicious behaviour is modelled.
- In the capture test, the newcomer-only certificate is accepted at the shard-0 certificate and validation layer. What capture would mean for the bridge (V2 minting) stays out of scope, per the validation note.
