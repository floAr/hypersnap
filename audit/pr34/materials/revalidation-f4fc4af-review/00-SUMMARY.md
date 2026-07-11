# Materials — External Review Revalidation Pass (felirami, f4fc4af)

Per-finding synthesis of the validation of 5 `[P1]` review comments on
farcasterorg/hypersnap#34 (head `f4fc4af`), posted by `felirami` 2026-07-11.
Parent: [../../REVALIDATION-f4fc4af-review.md](../../REVALIDATION-f4fc4af-review.md).

Source read against detached worktree at `f4fc4af`
(`C:\Projects\hypersnap-audit\code\wt-f4fc4af`). Rust PoCs built under WSL
`~/hs-f4fc4af` (`--cap-lints allow`); crate compiled clean, tests ran.

---

## F071 — transfer envelope not bound (CONFIRMED, High)

- **Claim:** admission + import verify bare `signing_payload()`, not
  `signing_payload_with_envelope`; relay can rewrite output `one_time_pubkey`.
- **Verified:** `signing_payload_with_envelope` (tokens.rs:276-308, hashes
  output pubkeys + blinding_diff) has **zero call sites**. Admission
  (runtime.rs:3956-3958) and import (runtime.rs:4935-4942) both call bare
  `validate_against_store` → `signing_payload()` (tokens.rs:414). `one_time_pubkey`
  is not a field of the signed `TransferTx`; it rides a separate wire field read
  by `extract_output_pubkeys` and persisted via `record_note` (runtime.rs:5006-5017).
- **Attack:** relay overwrites `outputs[0].one_time_pubkey` with a canonical
  attacker point; bare digest unchanged → schnorr + Pedersen closure still pass;
  nullifier-keyed mempool front-run strands the honest copy. Import persists the
  attacker pubkey → recipient's scan can't resolve ownership. Bounded to
  denial-of-funds (theft needs the output blinding, per tokens.rs:266-273).
- **PoC:** `poc/F071-transfer-envelope-malleable/` — RED. `submit_message`
  returned Ok, `pending=1` (mutated transfer admitted).

## F072 — confidential note recovery data absent from wire (CONFIRMED, P1 liveness)

- **Claim:** wire output lacks `tx_pubkey` + encrypted note payload; recipient
  can't discover/spend.
- **Verified:** `HyperTransferOutput` (hyper.proto:215-226) = {commitment,
  range_proof, one_time_pubkey}; no `tx_pubkey`, no ciphertext (grep across
  proto/ empty). `scan_stealth_note` (tokens.rs:842-857) needs the sender
  ephemeral `tx_pubkey = R` for the ECDH; not derivable from wire. `encrypt_note_payload`
  / `decrypt_note_payload` exist (tokens.rs:504-701) but have zero callers in
  `src/`. Wallet builders generate `tx_pubkey` and drop it
  (shield.rs:23-32, confidential_transfer.rs:53-54). Runtime note store keeps
  `[commitment]->one_time_pubkey` only (note_store.rs:4).
- **Consequence:** confidential outputs undiscoverable + unspendable from
  on-chain data; no other channel. Feature-incomplete, not a security hole.
- **PoC:** `poc/F072-note-unrecoverable-from-wire/` — RED. `scan_notes` returns
  empty because `ChainOutput.tx_pubkey` has no wire source.

## F073 — confidential_lock wallet builder emits non-validatable messages (CONFIRMED, P1 broken-primitive)

- **Claim:** builder subtracts a random `output_blinding` for an
  `output_commitment` never attached (balance mismatch) + always-empty
  `range_proof`.
- **Verified:** builder (confidential_lock.rs:30-32,44-45) sends
  `blinding_diff = input_blinding - output_blinding` and `range_proof:
  Vec::new()`. Runtime closure (src/hyper/confidential_lock.rs:194-205) requires
  `blinding_diff == input_blinding` → residual off by `output_blinding·B_blinding`
  → `BalanceClosureFailed` (fails first). Empty proof separately rejected at :219.
- **F036 linkage:** F036 (range proof unwired at cab225f) is **now FIXED** at
  f4fc4af (verify_value_range wired at :230); that fix is why the empty proof
  hard-fails. F073 is the wallet-side mirror.
- **PoC:** `poc/F073-conf-lock-builder-rejected/` — RED. `validate_against_store`
  returned `Err(BalanceClosureFailed)`.

## F074 — deployer UI unbuildable (CONFIRMED by build, peripheral tooling)

- **Claim:** missing `src/lib/{merkle,leaf,recover}` + missing Node typings.
- **Verified by actually running** `npm ci` (546 pkgs) + `npx tsc -b`:
  TS2307 on `../lib/merkle`, `../lib/leaf` (x2), `../lib/recover`; `src/lib`
  directory does not exist. `@types/node` absent from devDependencies →
  TS2307/TS2339/TS2580 on `node:fs`/`node:path`/`node:url`/`import.meta.url`/`process`/`console`
  in `scripts/*.ts`. (`../abis`/`./bytecode` are generated post-`forge build` —
  correctly excluded by the reviewer.)
- **Scope:** off-chain deployer UI, not consensus/bridge core. Not a core-scope
  merge gate. Reproduction = the build itself.

## F075 — commit after stage_block failure (PARTIAL, Low / defense-in-depth)

- **Claim:** logs `stage_block` error then commits state batch → state/header
  divergence; same in engine.rs shard path.
- **Verified pattern present:** block_engine.rs:959-969 and engine.rs:1844-1851
  both log-then-`commit`. **But** the only reachable `stage_block` failure is a
  RocksDB read error at the timestamp-index check (block.rs:190), which runs
  *after* the block primary-key `put` (block.rs:186); the header/height failure
  arms are dead (callers pre-unwrap at block_engine.rs:922 / engine.rs:1809-1810).
  So on the reachable failure, block+header+state still commit atomically — only
  a secondary timestamp index is dropped; chain height stays consistent, no fork.
- **Severity corrected:** Low / latent trap (a future refactor removing the
  caller unwraps would make the real divergence reachable). Not a blocker.
  PoC specified but not built (needs a `#[cfg(test)]` fault seam; Low priority).

---

## Cross-cutting

- F071+F072+F073 = the confidential-transfer feature surface, new relative to
  the prior lineage. Together: incomplete (F072/F073) **and** malleable (F071).
  Merge-gate treatment is conditional on whether that feature is shipped this
  release — see MERGE-BLOCKERS-f4fc4af.md overlay.
- F036 closed at f4fc4af (bonus revalidation observation surfaced by F073).
