// ============================================================================
// F025 — Committee membership is grindable via attacker-chosen validator_key
//        because party indices are assigned by lexicographic key order against
//        a fully predictable per-epoch committee seed.
//
// Finding:    findings/F025-committee-index-grinding-via-attacker-chosen-validator-key.md
// Trace:      findings/traces/F025-trace.md
// Commit:     cab225f1f63aea650201a4c0dfbb06a8cbbbb7b9
// Class:      committee-selection-grinding
//
// WHERE THIS BELONGS IN THE REPO
// ------------------------------
// This file is authored as a single self-contained module so it can be dropped
// in as-is, but the test is intended to be merged into the existing in-tree
// `#[cfg(test)] mod tests` block of:
//
//   * `committee_index_not_grindable_by_key_bytes`
//       -> belongs alongside the index->validator assignment in
//          code/hypersnap/src/hyper/dkls_supervisor.rs::build_driver
//          (lines ~194-201, the `for (i, vk) in active.keys().enumerate()`
//          loop that sets `own_idx = Some((i + 1))`). That loop is the
//          unguarded second layer the finding targets: it maps a validator
//          key to a `party_index` purely by its lexicographic position in the
//          `BTreeMap<Vec<u8>, _>` active set, with NO mixing of the
//          (non-grindable, F036) committee seed. It drives the REAL selector
//          `dkls_committee::select_signing_committee` and seed builder
//          `dkls_committee::committee_seed_for_epoch` that prod calls at the
//          epoch-tag ceremony sites (actor.rs:3055/:3080/:3216/:3284/:3357).
//
// PER-TEST ASSERTION & EXPECTED RESULT
// ------------------------------------
//   1. committee_index_not_grindable_by_key_bytes
//        For a fixed, publicly-predictable epoch seed, the winning committee
//        index set W is a pure function of (epoch, seed, share_count,
//        threshold) — the attacker computes it offline. The attack: the
//        attacker chooses the BYTES of its 32-byte validator_key so that the
//        key's 1-based position in the lexicographically-sorted active set
//        (== the supervisor's `party_index`) equals a winning index w ∈ W.
//
//        SECURE PROPERTY ASSERTED: the index/slot assigned to a key must be a
//        non-grindable function of (seed, key) — i.e. an attacker who only
//        controls its own key bytes must NOT be able to steer its slot onto a
//        chosen winning index. Concretely: under a secure assignment, mixing
//        the per-epoch seed into the key->slot map (e.g. ordering by
//        keccak256(seed || key)) breaks the monotone "raw key bytes determine
//        slot" relationship, so the attacker's chosen-byte placement no longer
//        lands deterministically on the precomputed winner.
//
//        On cab225f the assignment is RAW lexicographic key order
//        (dkls_supervisor.rs:194-201, `active.keys().enumerate()` over a
//        `BTreeMap<Vec<u8>,_>`), so the attacker's chosen-byte key DOES land
//        on the winning slot -> ASSERTION FAILS. After the fix (seed-mixed,
//        non-grindable index assignment) the chosen bytes no longer control
//        the slot -> PASSES.
//
// CAVEAT (shipped config): production hard-pins `dkls_threshold = 1u8`
// (main.rs:1603, finding F028), so each committee is size 1. Under that config
// this finding's marginal value is *deterministic targeting of the lone
// signer* — the attacker guarantees its sybil is the single winning index for
// a chosen epoch/ceremony — rather than assembling a full t-of-N quorum. The
// test is written for the lone-signer (threshold = 1) regime to match shipped
// behavior; the property generalizes to t > 1.
//
// STATUS: UNVERIFIED — authored from source, not compiled.
// ============================================================================

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, B256};

use hypersnap::hyper::dkls_committee::{committee_seed_for_epoch, select_signing_committee};

/// Faithful reproduction of the supervisor's index->validator map under test
/// (code/hypersnap/src/hyper/dkls_supervisor.rs:194-201).
///
/// `active` is a `BTreeMap<Vec<u8>, _>` keyed on the raw 32-byte
/// `validator_key`, so iterating `active.keys()` yields keys in ascending
/// lexicographic byte order. The supervisor assigns `party_index = i + 1` for
/// the `i`-th key. Returns the 1-based party index for `target_key`, or `None`
/// if it is not in the set (mirrors `BuildError::LocalNotActive`).
///
/// This mirrors the EXACT logic the system runs today (cab225f). When the fix
/// lands, this loop in `build_driver` is replaced by a seed-mixed assignment
/// (see `seed_param`/`assign_party_index` note below); updating this mirror to
/// the fixed map is what flips the regression assertion from FAIL to PASS.
///
/// To make the mirror track the fix automatically, the assignment takes the
/// per-epoch `seed`: on cab225f the seed is IGNORED (raw lexicographic order);
/// after the fix the seed is mixed in so the slot is non-grindable. The
/// `cfg(not(feature = "f025_fixed"))` arm reproduces the shipped (buggy) order;
/// the `f025_fixed` arm reproduces the suggested fix (order by
/// keccak256(seed || key), per the finding's "Suggested direction").
fn assign_party_index(active: &BTreeMap<Vec<u8>, ()>, seed: &B256, target_key: &[u8]) -> Option<u8> {
    #[cfg(not(feature = "f025_fixed"))]
    {
        // SHIPPED (cab225f): raw lexicographic key order; `seed` unused — this
        // is precisely why the slot is grindable from chosen key bytes.
        let _ = seed;
        for (i, vk) in active.keys().enumerate() {
            if vk.as_slice() == target_key {
                return Some((i + 1) as u8);
            }
        }
        None
    }
    #[cfg(feature = "f025_fixed")]
    {
        // FIXED: order keys by keccak256(seed || key) so a validator's slot
        // depends on the non-grindable per-epoch seed and cannot be
        // pre-computed from raw key bytes alone (finding's suggested direction).
        let mut ranked: Vec<(B256, &[u8])> = active
            .keys()
            .map(|vk| {
                let mut buf = Vec::with_capacity(32 + vk.len());
                buf.extend_from_slice(seed.as_slice());
                buf.extend_from_slice(vk);
                (keccak256(&buf), vk.as_slice())
            })
            .collect();
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(b.1)));
        ranked
            .iter()
            .position(|(_, vk)| *vk == target_key)
            .map(|p| (p + 1) as u8)
    }
}

/// Build a 32-byte validator_key whose leading byte is `lead` and the rest
/// zero. Lexicographic order over such keys is exactly the order of `lead`,
/// which lets an attacker deterministically choose its sort position relative
/// to a known set of honest keys — the "byte-prefix bucket" grind from the
/// finding (Leg A / attack procedure step 3).
fn key_with_lead(lead: u8) -> Vec<u8> {
    let mut k = vec![0u8; 32];
    k[0] = lead;
    k
}

/// Test 1 — the party index a key is assigned must NOT be grindable from the
/// attacker's chosen key bytes.
///
/// Belongs in: code/hypersnap/src/hyper/dkls_supervisor.rs `mod tests`
/// (next to the `build_driver` index-map logic at lines 194-201).
#[test]
fn committee_index_not_grindable_by_key_bytes() {
    // --- Public, predictable inputs the attacker computes offline. -----------
    // A future epoch-tag ceremony (e.g. reward issuance). The seed depends only
    // on (epoch, tag) — F036 made it non-grindable, but it is fully PREDICTABLE
    // far in advance (EPOCH_LENGTH = 432_000). This is the real prod seed API.
    let target_epoch: u64 = 9_000;
    let seed = committee_seed_for_epoch(target_epoch, b"reward-issuance");

    // The active-set size at the target epoch (derivable one epoch ahead via
    // EPOCH_BUFFER). Use a small set for clarity. Under the shipped F028 config
    // the committee is size 1 (the lone signer); this finding lets the attacker
    // deterministically BE that lone signer.
    let share_count: u8 = 5;
    let threshold: u8 = 1; // shipped hard-pinned threshold (F028 caveat).

    // Step 2 of the attack procedure: precompute the winning index set W with
    // the REAL selector the actor calls (actor.rs:3055 et al.).
    let winning = select_signing_committee(target_epoch, &seed, share_count, threshold)
        .expect("valid (threshold, share_count)");
    assert_eq!(
        winning.len(),
        threshold as usize,
        "selector must return exactly `threshold` winners"
    );
    let target_winner: u8 = winning[0]; // the lone winning party_index w ∈ W.

    // --- The honest validators already registered (raw keys, known on-chain). -
    // Their leading bytes are spread out so the attacker can slot a chosen key
    // BETWEEN them at any lexicographic position. There are `share_count - 1`
    // honest keys; the attacker adds one sybil to reach `share_count` total.
    let honest_leads: [u8; 4] = [0x10, 0x40, 0x80, 0xC0];
    assert_eq!(honest_leads.len() as u8, share_count - 1);

    // --- Step 3: the attacker GRINDS its key bytes to land on slot `w`. -------
    // The attacker reasons about the SHIPPED assignment: raw lexicographic key
    // order means picking a leading byte places its key at a chosen sorted
    // position among all `share_count` keys. It searches the chosen-byte space
    // the registrant fully controls (one Ed25519 keygen per candidate; modeled
    // here as choosing the leading byte) for a key that occupies winning slot
    // `target_winner`. We compute this against RAW lexicographic order — the
    // attacker's model of cab225f — independent of the map under test, so the
    // grind always yields a concrete chosen-byte key to probe with.
    let mut attacker_key_that_wins: Option<Vec<u8>> = None;
    for lead in 0u16..=255 {
        let lead = lead as u8;
        // Skip collisions with honest leading bytes (the sybil key must be
        // distinct in the BTreeMap).
        if honest_leads.contains(&lead) {
            continue;
        }
        let attacker_key = key_with_lead(lead);

        // Assemble the active set exactly as compute_active_set would:
        // a BTreeMap keyed on raw validator_key bytes.
        let mut active: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        for &h in &honest_leads {
            active.insert(key_with_lead(h), ());
        }
        active.insert(attacker_key.clone(), ());
        assert_eq!(active.len() as u8, share_count);

        // Attacker's model: 1-based lexicographic position (raw key order).
        let modeled_idx = active
            .keys()
            .position(|vk| vk.as_slice() == attacker_key.as_slice())
            .map(|p| (p + 1) as u8)
            .expect("attacker key is in the active set");
        if modeled_idx == target_winner {
            attacker_key_that_wins = Some(attacker_key);
            break;
        }
    }

    // The grind is feasible: there exists a chosen-byte key that, under raw
    // lexicographic order, occupies the precomputed winning slot. (This is the
    // attacker computing its target key; not yet the regression assertion.)
    let attacker_key = attacker_key_that_wins.expect(
        "attacker could not find a chosen-byte key for winning slot — fixture malformed",
    );

    // --- THE SECURE PROPERTY (regression assertion). -------------------------
    // Reassemble the real active set with the attacker's grind-chosen key.
    let mut active: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
    for &h in &honest_leads {
        active.insert(key_with_lead(h), ());
    }
    active.insert(attacker_key.clone(), ());

    // The slot the attacker actually gets from the assignment the SYSTEM uses
    // (`assign_party_index` mirrors dkls_supervisor.rs:194-201). On cab225f the
    // seed is ignored and this is raw lexicographic order -> equals
    // `target_winner` (grind succeeds, assertion FAILS). After the fix the seed
    // is mixed in -> the chosen bytes no longer steer the slot (PASSES).
    let assigned_index = assign_party_index(&active, &seed, &attacker_key)
        .expect("attacker key is in the active set");

    // SECURE behavior: attacker-chosen key bytes must NOT deterministically
    // occupy the precomputed winning index. Index assignment must be a
    // non-grindable function of (seed, key).
    assert_ne!(
        assigned_index, target_winner,
        "GRINDABLE: attacker-chosen key bytes landed on the precomputed winning committee \
         index {target_winner}. Index assignment must be a non-grindable function of \
         (seed, key) so chosen-key bytes do NOT control the slot. On cab225f the supervisor \
         uses raw lexicographic key order (dkls_supervisor.rs:194-201), so this FAILS; after \
         mixing the per-epoch seed into the key->slot map it PASSES."
    );
}
