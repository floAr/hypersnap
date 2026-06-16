# PoC — slashing signer-index mis-attribution (fix-induced regression)

**Commit:** `58fa604` (PR #34, branch `pow`). **Provenance:** introduced by the F025 remediation in `5c25945`, carried through `58fa604`.
**Severity:** High — incorrect slashing of honest validators + active-set eviction; real equivocators escape.
**Status:** build-verified (WSL, rustc 1.95). See [REVALIDATION-58fa604.md](../../REVALIDATION-58fa604.md).

## The bug

`signer_indices` in a `HyperBlock` are DKLS **party indices**. The two index→key mappings disagree:

| Path | Mapping | Source |
|---|---|---|
| **Signing** | party index `i` → `committee_party_order(epoch, active.keys())[i-1]` (keccak-rank permutation) | `actor.rs` (`select_signing_committee` → `attach_dkls_signature`), supervisor `build_driver`, `transport_pubkey_for_party` |
| **Slashing** | signer index `i` → `active_set.keys()[i-1]` (lexicographic BTreeMap order) | `runtime.rs::slashed_validators_for_epoch` (the function `58fa604` edited for F002) |

`committee_party_order` is explicitly a permutation (*"Sorting is purely for the hash; it does NOT determine the output order"*). So when the keccak order diverges from lexicographic order, slashing attributes equivocation to the validator at the **lexicographic** slot — an innocent party — and the real equivocator at the **party-order** slot is never slashed. Slashed validators are then excluded via `get_active_validators_enforced`.

At baseline `cab225f` both sides used lexicographic order, so they matched. `5c25945` changed only the signing side to the permutation; the slashing side was missed.

## Reproduce

Paste [`slashing_index_mismatch_test.rs`](slashing_index_mismatch_test.rs) (two tests) into `mod tests` in `src/hyper/runtime.rs` (uses the existing `make_runtime` / `f002_evidence` helpers), then:

```sh
RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib -- \
  slashing_must_slash_true_party_order_signer \
  slashing_resolves_signer_index_in_lexicographic_not_party_order
```

`--cap-lints allow` dodges an unrelated rustc 1.95 ICE in the vendored `ed448-bulletproofs` crate (`check_unused_traits` lint pass). The crate does not build under Windows/MSVC (`tikv-jemalloc-sys`); build under Linux/WSL.

Both tests build a 5-key active set, find the first index where `committee_party_order` diverges from lexicographic order, and record a same-epoch equivocation by that party index. **They have opposite polarity — read this before interpreting the result:**

| Test | Asserts | Result on `58fa604` | Meaning |
|---|---|---|---|
| `slashing_must_slash_true_party_order_signer` | the **correct** behavior — the real party-order signer must be slashed | ❌ **FAILS** | **primary proof** — the security property is violated |
| `slashing_resolves_signer_index_in_lexicographic_not_party_order` | the **buggy** behavior — the lexicographic key is slashed, true signer escapes | ✅ passes | characterization / regression pin |

The **failing** test is the unambiguous demonstration; the passing one pins the buggy behavior (and flips to red when fixed). Verbatim output (red + green) in [`test-output.txt`](test-output.txt):

```
test ...slashing_resolves_signer_index_in_lexicographic_not_party_order ... ok
test ...slashing_must_slash_true_party_order_signer ... FAILED
  B5 SECURITY PROPERTY VIOLATED: the equivocator that held party index 1
  was NOT slashed; slashing resolved the index in lexicographic order instead
```

When the fix lands (resolve via `committee_party_order`), the property test goes green and the characterization test goes red.

## Fix

Resolve indices in `slashed_validators_for_epoch` through `committee_party_order(epoch, active_set.keys())` — the same permuted ordering the `signer_indices` were assigned in — instead of raw `.keys()`. Apply the same correction to the `importer.rs` scoring path (`active_validator_keys_by_index`) if/when it goes live. When fixed, the test's final two assertions flip.
