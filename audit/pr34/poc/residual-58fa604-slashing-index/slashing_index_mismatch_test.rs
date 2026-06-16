// PoC — fix-induced regression confirmed during revalidation of 58fa604.
//
// Paste both tests into `mod tests` in `src/hyper/runtime.rs` (they rely on
// the crate-internal `make_runtime` and `f002_evidence` test helpers that
// already live there). Build/run under Linux/WSL:
//
//   RUSTFLAGS="--cap-lints allow" cargo test -p hypersnap --lib -- \
//     slashing_must_slash_true_party_order_signer \
//     slashing_resolves_signer_index_in_lexicographic_not_party_order
//
// (cap-lints dodges an unrelated rustc 1.95 ICE in the vendored
//  ed448-bulletproofs crate's check_unused_traits lint pass.)
//
// TWO TESTS, OPPOSITE POLARITY — read this before interpreting results.
//   * slashing_must_slash_true_party_order_signer  — asserts the SECURITY
//     PROPERTY. FAILS on 58fa604 (red). This is the unambiguous proof of
//     the bug. Goes green when the resolver is fixed.
//   * slashing_resolves_signer_index_in_lexicographic_not_party_order —
//     CHARACTERIZATION test. PASSES on 58fa604 (green) because its
//     assertions encode the *buggy* behavior; it flips to red when fixed.
//     Useful as a regression pin, but on its own a green result is easy to
//     misread — that's why the red property test above is the primary PoC.
//
// THE BUG
// -------
// `signer_indices` in a HyperBlock are DKLS *party indices*. At signing
// time, party index i maps to a validator key via
// `dkls_committee::committee_party_order(epoch, active.keys())` — a
// keccak-rank permutation of the active set (see also supervisor
// `build_driver` and `transport_pubkey_for_party`, which use the same
// permuted mapping). But `slashed_validators_for_epoch` resolves index i
// via `active_set.keys()[i-1]` — plain lexicographic BTreeMap order.
//
// The two orderings differ by design, so slashing attributes the slash to
// the WRONG validator: the innocent key at the lexicographic slot is
// slashed (and then excluded from the active set), while the real
// equivocator at the party-order slot escapes.
//
// Provenance: introduced by the F025 remediation in 5c25945 (which changed
// only the signing side to the permutation) and carried through 58fa604
// (which edited slashed_validators_for_epoch for F002 but kept `.keys()`).
//
// FIX: resolve indices in slashed_validators_for_epoch via
// committee_party_order(epoch, active_set.keys()) instead of raw `.keys()`.

// ---- PRIMARY PoC: security property, FAILS on 58fa604 (red) ----
#[test]
fn slashing_must_slash_true_party_order_signer() {
    use crate::hyper::dkls_committee::committee_party_order;
    let epoch: u64 = 7;
    let mut active_set: std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)> =
        std::collections::BTreeMap::new();
    for b in 1u8..=5 {
        active_set.insert(vec![b; 32], (vec![0u8; 48], vec![0u8; 32]));
    }
    let lex_keys: Vec<Vec<u8>> = active_set.keys().cloned().collect();
    let party_order = committee_party_order(epoch, active_set.keys());
    let idx = (1..=lex_keys.len())
        .find(|&i| lex_keys[i - 1] != party_order[i - 1])
        .expect("keccak party-order must permute a 5-key set vs lexicographic");

    let (rt, _dir) = make_runtime();
    let ev = f002_evidence(epoch, epoch, 100, 0xaa, 0xbb, vec![idx as u64], vec![idx as u64]);
    rt.record_evidence(&ev).expect("record same-epoch evidence");
    let slashed = rt
        .slashed_validators_for_epoch(epoch, &active_set)
        .expect("resolve slashed set");

    let true_signer = party_order[idx - 1].clone();
    assert!(
        slashed.contains(&true_signer),
        "B5 SECURITY PROPERTY VIOLATED: the equivocator that held party index {idx} \
         was NOT slashed; slashing resolved the index in lexicographic order instead"
    );
}

// ---- CHARACTERIZATION: pins the buggy behavior, PASSES on 58fa604 (green) ----
#[test]
fn slashing_resolves_signer_index_in_lexicographic_not_party_order() {
    use crate::hyper::dkls_committee::committee_party_order;
    let epoch: u64 = 7;
    let mut active_set: std::collections::BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)> =
        std::collections::BTreeMap::new();
    for b in 1u8..=5 {
        active_set.insert(vec![b; 32], (vec![0u8; 48], vec![0u8; 32]));
    }
    let lex_keys: Vec<Vec<u8>> = active_set.keys().cloned().collect();
    let party_order = committee_party_order(epoch, active_set.keys());
    let idx = (1..=lex_keys.len())
        .find(|&i| lex_keys[i - 1] != party_order[i - 1])
        .expect("keccak party-order must permute a 5-key set vs lexicographic");

    let (rt, _dir) = make_runtime();
    let ev = f002_evidence(epoch, epoch, 100, 0xaa, 0xbb, vec![idx as u64], vec![idx as u64]);
    rt.record_evidence(&ev).expect("record same-epoch evidence");
    let slashed = rt
        .slashed_validators_for_epoch(epoch, &active_set)
        .expect("resolve slashed set");

    let lex_key = lex_keys[idx - 1].clone();
    let true_signer = party_order[idx - 1].clone();
    assert_ne!(lex_key, true_signer, "precondition: orderings differ at idx");
    // BUG: slash attributed to the lexicographic key, not the true signer.
    assert!(slashed.contains(&lex_key), "resolver uses lexicographic .keys() ordering");
    assert!(
        !slashed.contains(&true_signer),
        "MIS-ATTRIBUTION: real party-order signer escaped; lexicographic key slashed instead"
    );
}
