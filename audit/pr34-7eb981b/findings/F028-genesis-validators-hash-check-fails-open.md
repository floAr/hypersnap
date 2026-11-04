---
finding_id: F028
title: When the release has no `GENESIS_VALIDATORS_HASH`, the check of the genesis validator file only logs a warning, and in this PR the constant
severity: low
status: pending-validation
related_findings:
- F027
---
# F028 — When the release has no `GENESIS_VALIDATORS_HASH`, the check of the genesis validator file only logs a warning, and in this PR the constant is absent on every network. The operator-supplied file is the only trust root for the snapshot path's certificate check, so whoever supplies the file and the snapshot RPC can certify any genesis

- **Severity:** Low (pre-release, and it needs the operator to take the file from an untrusted channel. However, the fail-open is the default, and the spec makes the check mandatory).
- **Category:** genesis-state-forgery / spec-divergence (FIP §17.5 step 6)
- **Specialist:** pivot-genesis-epoch · attack class: genesis-state-forgery · task H017
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)
- **PoC:** None (reasoned from source).

## Code facts

1. `pivot_guard::params::genesis_validators_hash` returns `None` for Mainnet, Testnet, Devnet and None (`src/consensus/pivot_guard.rs:77-84`). The doc comment says "`None` until a release fixes it". `pivot_height` is also `None` everywhere (`:66-73`), and the pivot is armed through the config override (`effective_pivot_height`, `cfg.pivot_height`).
2. The local path (`pivot_boot::build_in`, `src/node/pivot_boot.rs:401-415`) handles `None` with `warn!("No GENESIS_VALIDATORS_HASH in this release; the file is not checked")` and continues.
3. The snapshot path (`genesis_snapshot::fetch_certified_record`, `src/node/genesis_snapshot.rs:191-195`) skips the comparison when the constant is `None`. `verify_certified_pivot` then checks only that the record's `genesis_validators_hash` equals the hash of *the same file*, and verifies the certificate against `epoch1_set(file, …)` (`:116-151`). The file is read from the operator config path `hypersnap.genesis_validators_file` (`hypersnap_main.rs:815-819`).
4. FIP §17.5 steps 5-6 say: "Read the genesis validator file. Compare the hash of the file with `GENESIS_VALIDATORS_HASH`." It is not optional.

## Impact

- **Snapshot path:** the certificate on the shard-0 pivot block is checked against a set that the attacker's file defines. If an attacker can get the operator to use its genesis file (for example, the file and the snapshot URL/RPC are published together on a compromised download page or bucket), then the attacker's own keys sign a "pivot block" whose `PivotRecord` has arbitrary `genesis_state_roots`. The snapshot built to those roots passes `check_staged`. The victim boots into a forged genesis: forged messages and on-chain events in shards 1/2, and a forged set(1). The marker fields (fork block hash, `shard_forks`) still have to match the victim's local snapchain DB, but the attacker knows them because they are public.
- **Local path:** the node builds its genesis with whatever set the file names. It then disagrees with the network's pivot block, which fails loudly, so this is mostly an operational risk.
- Nothing ties a release's `pivot_height` to a `genesis_validators_hash`. A release could set the first and forget the second, and the nodes would still run, with only a warning.

## Red-team

1. *Is it just "pre-release placeholders"?* Partly. The issue is that the check fails open. Once `pivot_height(network)` is `Some`, a missing hash should be a hard error, and devnets can opt out explicitly.
2. *Does the certified-record check still protect the node?* Only relative to the file. The file is the trust root.
3. *Needs the operator to take an attacker's file:* yes. That is why this is Low.

## Recommendations

- If `params::pivot_height(network).is_some()` (or `network != Devnet`) and the hash is `None`, return an error and do not warn. Allow skipping the check only on devnets or with an explicit `--unsafe-skip-genesis-hash`.
- Add a unit test that fails if the release sets `pivot_height` without `genesis_validators_hash` for a network.
