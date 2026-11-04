---
finding_id: F010
title: Consensus keys and commit certificates use Falcon-512 (bundled), not LWE-FSA / LWE-MS2 as FIP §16.2–§16.6 specify, so the CERT-STARK
severity: medium
status: pending-validation
related_findings:
- F026
- F039
---
# F010 — Consensus keys and commit certificates use Falcon-512 (bundled), not LWE-FSA / LWE-MS2 as FIP §16.2–§16.6 specify, so the CERT-STARK statement, cost model and security assumption in the spec no longer describe what the bridge must verify

> **Status (2026-11-04):** Severity **Medium** (unvalidated). PoC: none. State: pending-validation.

> **Status 2026-11-04 (post-validation):** Severity **Medium** (recalibrated 2026-11-04 from Low). Over-strict route to the no-recovery state; see the F006 addendum.


- **Category:** spec-divergence; cross-side-cert-statement-mismatch.
- **Specialist:** falcon-pq-message-auth · task H009
- **Target:** farcasterorg/hypersnap @ `7eb981b` (PR #34)

## Summary

| Aspect | FIP (THE spec) | Code @ `7eb981b` |
|---|---|---|
| Validator consensus key | LWE-FSA, unstructured LWE/SIS (§16.4, §16.2 table row 1). §16.2: Falcon-512 is accepted "for user keys only". | Falcon-512 / FN-DSA via `fn-dsa =0.4.0` (`src/core/consensus_keys.rs:1-11`, `:158-200`; `proto/definitions/hypersnap_bodies.proto:21`, `hypersnap_state.proto:59` "Falcon-512 consensus public key (§16.4)") |
| Proof of possession | LWE-FSA, to make the plain-sum `T_P` rogue-key safe (§16.4, §4.5 l.310) | Falcon-512 PoP under `hypersnap-validator-consensus-pop-v1` (`domains.rs:177`). No aggregation, so a PoP is not needed for rogue-key safety. |
| Certificate forms | `bundled` (LWE-FSA sigs) for finality, then compacted to an `aggregate` LWE-MS2 signature (§16.5 steps 1–12, `MS2_AGG_WINDOW`, `MS2_MAX_RESTARTS`) | Bundled Falcon only. `certificate::verify` returns `NotBundled` for `aggregate` (`src/chain/certificate.rs:147-150`). The proto comment reads "One aggregate signature (R2)" (`hypersnap.proto:90`). No MS2 session, no `certificate` gossip topic. |
| `set_root` leaf | "Each member record commits the full LWE public key and the weight" (§16.6) | `keccak256(falcon_pk) ‖ u64 weight ‖ node_key_hash ‖ u64 fid` (`validator_sets.rs:15-25`). This commits the key only through a hash. |
| CERT-STARK statement | (1) members of `set_root`; (2) weight > 2/3; (3) `T_P = Σ T_i`; (4) the LWE-MS2 aggregate verifies under `T_P` on `d` (§16.6) | `ICertificateVerifier.sol:10-16`: (1) members; (2) weight > 2/3; (3) **one Falcon-512 signature per signer** on `"hypersnap-consensus-vote-v1" ‖ d` |
| Prover work / cost | "one LWE verification, `|P|` key additions, `|P|` Merkle openings". The Goldilocks field is chosen so that `A·z` inner products fit (§16.6). | `|P|` FN-DSA verifications: per signer, Keccak over the 897-byte pk, SHAKE256 for `hpk`, `mu` and hash-to-point, a mod-12289 NTT/product, and an ℓ2 norm bound. Plus `|P|` openings. None of the §16.6 field and cost reasoning applies. |
| §18 open items | LWE-FSA parameters (#1), LWE-MS2 proof (#2) | Moot for the code. The research crate `crates/hypersnap-lattice` is not linked into the node (`Cargo.toml:11`). |

Code comments cite §16.4/§16.5 as if the FIP said Falcon. For example, `consensus_keys.rs:2` says
"Falcon-512 (Hypersnap, from the epoch-1 pivot; FIP-proof-of-work-tokenization §16.4)", and
`domains.rs:209` cites "16.4, 16.5". The FIP does not say this.

## Which side looks wrong

The code looks like a deliberate interim design. The interface NatSpec, the proto comments and
the "(R2)" aggregate placeholder all agree. The spec is stale. But the spec's security argument
does not carry over: §16.2 justifies unstructured LWE for consensus keys because "a break of
these keys gives control of consensus" and the bridge. With the code, a cryptanalytic break of
Falcon-512 / NTRU lattices (or an fn-dsa verification bug) forges both user keys **and** the
bridge's commit certificates. The FIP had kept those two failure domains separate. The FIP
must be updated (or the code changed) so that reviewers of the future verifier work from the
real statement.

## Red-team (invalidation hypotheses walked)

1. *Is Falcon only a pre-pivot stand-in that switches to LWE at some epoch?* No. The Ed25519 →
   Falcon switch is at the pivot (`consensus_keys.rs:1-7`). No code path selects LWE, and the
   lattice crate is not a node dependency.
2. *Does the FIP mention Falcon consensus keys anywhere?* No. FIP l.148 ("A validator also has an
   LWE consensus key"), §16.2, §16.3 inventory (l.1574-1578) and §17.3 (`lwe_possession_signature`)
   all say LWE.
3. *Is this a safety bug in the node?* No. Bundled Falcon verification is sound (see
   the internal validation notes). This finding is about the spec and the future verifier.
4. *Does the bridge rely on the aggregate form?* No. `Certificate` carries only
   `round, signerBitmap, proof` (`HypersnapBridgeV2.sol:74-78`). The form is invisible to V2,
   so either design fits the interface signature. Only the statement text differs.
5. *Severity inflation?* Kept at Low: no attacker gains anything at `7eb981b`. The liveness
   impact needs a verifier built from the FIP text, and the interface NatSpec already says Falcon.

## Fix

- Update FIP §16.2–§16.6, §4.5 and §17.3 to Falcon-512 consensus keys and bundled certificates,
  or state the interim status and the migration plan. Move "the bridge trust anchor depends on
  NTRU lattices" into the §16.2 assumptions table.
- Replace §16.6 with the Falcon statement and the exact FN-DSA verification profile below. Re-do
  §18 #3 (proof size, gas) for `|P|` Falcon verifications.
- Fix the code comments that cite §16.4/§16.5 for Falcon consensus keys.

## Requirements for the CERT-STARK verifier (from this divergence)

V2 forwards `(epoch, setRoot, totalWeight, d, signerBitmap, proof)` and trusts the `bool`. For
the node's real certificates to pass, and only those, the verifier must implement **exactly** the
node's verification (`crates/hypersnap-falcon/src/lib.rs:141-163`, `:184-194`):

1. **Scheme profile = fn-dsa 0.4.0 FN-DSA-512, HASH_ID_EXTMU over a pre-computed `mu`.** Not
   round-3 Falcon (which hashes `nonce ‖ msg` directly). Per signer:
   `hpk = hashed_vrfykey_from_vrfykey(pk)` (64 bytes, SHAKE256 of the 897-byte pk);
   `mu = SHAKE256-stream(compute_mu_start(hpk, DOMAIN_NONE) ‖ "hypersnap-consensus-vote-v1" ‖ d)` (64 bytes);
   then FN-DSA verification of the 666-byte signature over `mu` with `DOMAIN_NONE`, `HASH_ID_EXTMU`
   (hash-to-point over `nonce(40) ‖ mu`, the ℓ2 norm bound of FN-DSA-512). The message is the
   27-byte domain followed by the 32-byte `d`, with no length prefix. Cross-check with test vectors
   produced by `hypersnap_falcon::sign`. A mismatch here is a total bridge liveness failure, not a
   soundness failure.
2. **Key binding:** open the full 897-byte pk from the leaf and prove
   `keccak256(pk) == consensus_key_hash` (leaf bytes 0..32). Also prove the pk decodes (header byte
   `0x09`, each coefficient < 12289), as `FalconPublicKey::from_bytes` does
   (`keys.rs:50-63`). Accepting a non-decodable pk would make "the key in the leaf" ill-defined.
3. **Encoding strictness:** the node rejects non-canonical compressed `s2` (`keys.rs:199-213`).
   A verifier may be *laxer* on encoding without losing soundness: the norm check still needs a
   real short preimage. It must not be *stricter* (liveness). Signatures are randomized (fresh
   40-byte nonce per signing, `consensus_keys.rs:193-198`), so the verifier must not assume one
   signature per (key, `d`).
4. **No reliance on aggregation:** the FIP's `T_P` sum, "one LWE verification" and Goldilocks
   range argument (§16.6) do not apply. If the verifier works over Goldilocks, the FN-DSA
   arithmetic mod 12289 and the norm bound (sums of squares of 1024 coefficients) must be
   range-checked so that they cannot wrap mod `p`.
5. **If an aggregate form is added later (R2):** the statement changes. `ICertificateVerifier`
   must then carry the form, or a new verifier/version, and the bridge must not accept both forms
   under one verifier key unless both are sound for the same `(setRoot, bitmap, d)`.

## Addendum (2026-11-04)

The over-strict-verifier route (a verifier built to FIP §16.6 rejecting real certificates) ends in a permanent brick with no recovery path, and it strands outbound locks. See the F006 addendum, "the immutable verifier has no recovery path".
