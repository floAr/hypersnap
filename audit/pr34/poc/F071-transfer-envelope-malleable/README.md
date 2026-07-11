# F071 PoC — transfer output `one_time_pubkey` is malleable (envelope not bound)

**Finding:** [F071](../../findings/F071-transfer-envelope-not-bound-output-pubkey-malleable.md)
**Commit:** `f4fc4af` · **Polarity:** RED (asserts the security property; FAILS on current code)

## What it proves

A gossip relay rewrites `outputs[0].one_time_pubkey` on a validly-signed
transfer *after* the sender signed. Because admission verifies the bare
`signing_payload()` (which does not cover the output pubkey), the Schnorr
signature still verifies and `submit_message` **accepts** the tampered transfer.
The test asserts the property that *should* hold — a transfer whose output owner
was rewritten after signing must be rejected — so it fails today (red) and would
pass once `validate_against_store` verifies `signing_payload_with_envelope`.

## Location

`src/hyper/runtime.rs`, `#[cfg(test)] mod tests`,
`fn f071_relay_rewrite_output_pubkey_must_be_rejected` (see
[`f071_test.rs`](f071_test.rs) — the exact inserted test).

## Reproduce (WSL, per hypersnap-wsl-build)

```
cd ~/hs-f4fc4af
RUSTFLAGS='--cap-lints allow' cargo test -p hypersnap --lib \
  f071_relay_rewrite_output_pubkey_must_be_rejected -- --nocapture
```

## Verbatim RED output (f4fc4af)

```
thread 'hyper::runtime::tests::f071_relay_rewrite_output_pubkey_must_be_rejected' panicked at src/hyper/runtime.rs:6036:9:
F071: envelope not bound -- relay rewrote output one_time_pubkey without invalidating the spend signature; admission accepted it (pending=1)
test hyper::runtime::tests::f071_relay_rewrite_output_pubkey_must_be_rejected ... FAILED
```

`pending=1` is the smoking gun: the mutated transfer entered the mempool.

## Green condition (after fix)

`validate_against_store` (admission) and the `import_block` re-validation verify
`signing_payload_with_envelope(extract_output_pubkeys(..), blinding_diff)`, and
the producer signs that same digest. The mutated pubkey then changes the
verified digest → `schnorr_verify` fails → `submit_message` returns
`Err(RoutingError::Transfer(...))` → assertion passes (green).
