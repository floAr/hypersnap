---
id: F101
task: H101
attack_class: eip712-domain-or-replay-binding
severity: medium
status: draft
validation:
  validator: validator
  verdict: WATERPROOF
  confidence: 0.92
  hypotheses_walked: 8
  validated_at: 2026-05-21T19:00:00Z
---

# F101 — Custody-key JFS account-association proof is a publicly-served, replayable bearer token: no chain-id, no nonce, no consumption — every other miniapp operation binds chain-id+nonce; Register stands alone

- **Task:** H101
- **Attack class:** eip712-domain-or-replay-binding (EIP-191 variant)
- **Severity (provisional):** Medium. The JFS account-association proof is published by design at `/.well-known/farcaster.json` on the registering FID's own domain (that is its sole intended verification flow at the Farcaster spec level). The hypersnap layer ingests the same proof as authorization for a state-changing on-chain action (`MiniappRegister`) with no additional binding. Anyone who fetches the FID's well-known file (or observes a gossip-broadcast `HyperMessage::MiniappRegister`) can replay the proof to (a) re-register on a sibling hyper chain, (b) re-register after the FID unregisters once Phase B turns on, and (c) front-run the legitimate FID's submission on chains where it has not yet registered. The Register message envelope is anyone-can-gossip — there is no separate ingress authentication — and the runtime does not consume / nullify the proof.
- **Status:** draft

## Scope files

- `code/hypersnap/src/hyper/account_association.rs` (verifier — primary)
- `code/hypersnap/src/hyper/miniapp.rs:155-173` (`validate_register_structure` — no nonce; contrast with `unregister_signing_payload`/`update_signing_payload`/etc. at `:184-258` which DO bind chain_id + nonce)
- `code/hypersnap/src/hyper/runtime.rs:2338-2412` (`apply_miniapp_register` — no nonce check; contrast with `apply_miniapp_unregister` `:2530-2583` which calls `miniapp_check_signer_and_nonce`)
- `code/hypersnap/src/hyper/router.rs:267-274` (router falls through; runtime is sole gate)
- `code/hypersnap/src/hyper/mod.rs:106-111` (doc-comment that contradicts the actual Register behavior)
- `code/hypersnap/proto/definitions/hyper.proto:740-771` (`AccountAssociationProof` + `MiniappRegisterBody` — no nonce/chain_id/timestamp fields)

## Summary

`verify_account_association` consumes the standard Farcaster JFS custody-key proof verbatim:

```text
header  JSON:   { "fid": <u64>, "type": "custody", "key": "0x<20B addr>" }
payload JSON:   { "domain": "<host>" }
signing input:  base64url(header) || "." || base64url(payload)
signature:      EIP-191 personal_sign over signing input (65B r||s||v)
```

(`account_association.rs:17-22`, verifier at `:130-221`)

Three properties make this verifier safe **as a domain-control attestation** in the Farcaster spec context: the proof binds `header.fid` (so cross-FID confusion is blocked at `:203-207`), it binds `payload.domain` (cross-domain confusion blocked at `:209-214`), and the verifier reloads the current on-chain custody address at every check (`:189-201`) so a rotated-away custody address cannot re-prove ownership.

But the proof has zero binding to:

- **Chain-id.** The signing input contains nothing identifying which hyper chain the proof is being submitted to. `code/hypersnap/src/hyper/mod.rs:106-111` documents the protocol-wide invariant — "Embedded in every Ed25519-signed canonical payload (v2 DSTs) so a message signed for chain A cannot replay on chain B. EIP-712 paths already bind chain_id via their typed-data domain" — and `unregister_signing_payload` / `update_signing_payload` / `add_signing_payload` / `remove_signing_payload` in `miniapp.rs:194-258` all extend their DST with `chain_id.to_be_bytes()`. **Register is the sole miniapp operation that ignores this invariant.**

- **Nonce / replay nullifier.** `MiniappRegisterBody` has no `nonce` field (`hyper.proto:762-771`); contrast `MiniappUnregisterBody` at `:775-781` which carries `uint64 nonce = 3` and is gated by `runtime.rs:2537 miniapp_check_signer_and_nonce`. `apply_miniapp_register` (`runtime.rs:2338-2412`) does NO check that the JFS proof has not been seen before — the proof bytes are never persisted, never nullifier-consumed.

- **Network ingress authentication.** `HyperMessage::MiniappRegister` is gossip-broadcast over the hyper p2p topic and the router at `router.rs:267-274` forwards it untouched to the runtime; there is no outer-envelope signature, no claimed-sender authentication, and no IP/peer-id binding. Anyone on the network can publish a `MiniappRegisterBody` with whatever proof bytes they like.

The JFS proof is also, by design, **publicly retrievable**: the Farcaster mini-app spec stores it on the FID's domain at `/.well-known/farcaster.json` precisely so anyone can fetch and verify the domain↔FID binding. So the threat model "attacker possesses a copy of FID-X's JFS proof for domain-Y" is the default state, not an exotic compromise.

## Concrete attack scenarios

### Scenario 1 — front-running registration on a parallel hyper chain

Hypersnap supports configurable `protocol_chain_id` (`hyper/config.rs:447`; default `10` at `hyper/mod.rs:111`). Testnet / staging / future shards run distinct chain ids. Alice (FID 42) publishes her JFS proof at `https://alice.com/.well-known/farcaster.json` and registers `alice.com` on mainnet hyper (chain_id = 10). Bob:

1. Curls `alice.com/.well-known/farcaster.json`.
2. Constructs a `MiniappRegisterBody` with Alice's exact proof bytes, Bob-chosen `metadata` (Bob's own home_url, icon_url, name, description — none of which are covered by the JFS sig, per `hyper.proto:757-761`).
3. Gossips it on the testnet hyper topic before Alice gets around to registering there.

The verifier passes — the proof is valid for `(FID 42, "alice.com")` on any chain because chain_id is not bound. `apply_miniapp_register` writes Bob's metadata under the canonical `miniapp_id_from_domain("alice.com")` key, claims one of Alice's `MAX_REGISTRATIONS_PER_FID = 10` slots, AND latches that domain to point at Bob's home_url forever via the `miniapps_by_author` index. Subsequent legitimate registrations from Alice's mempool are rejected with "miniapp already registered for domain alice.com" (`runtime.rs:2374-2378`).

Alice can recover only by signing an Unregister (which she can; she still controls her FID's authorized Ed25519 signers) and re-registering. But:
- Bob's home_url has been the canonical mini-app entry on that chain for however long it took Alice to notice.
- Per FIP §7 App-PoW credit, the `miniapp_id → author_fid` mapping accrues rewards in the meantime; Bob does not get the reward (it goes to Alice's FID) — but Alice has been spoofed at the entry-point level. Any downstream consumer of `MiniappState.metadata` (notification routers, search indexes, frontends) has been pointed at Bob's icon/url.
- Re-registration only becomes possible after Unregister (which marks `state.active = false`) AND only in Phase B (currently blocked unconditionally at `runtime.rs:2369-2378`).

### Scenario 2 — Phase B re-registration replay (forward-dated)

`runtime.rs:2367-2368` reads:

```
// Domain uniqueness: rejects if any existing record for the
// domain. (Re-registration after Unregister is handled in
// Phase B by also checking `active`.)
```

When Phase B turns on, the gate becomes `state.is_some() && state.active`. At that point:

1. Alice registers `alice.com`. Her JFS proof is stored at her well-known endpoint.
2. Alice unregisters (`apply_miniapp_unregister` at `runtime.rs:2530`). `state.active = false`.
3. Anyone — including someone whose own custody key has nothing to do with FID 42 — fetches the JFS proof Alice publishes (or replays the original `MiniappRegister` they captured from gossip) and re-registers with their own metadata. Verifier still passes: header.fid matches, header.key matches Alice's still-current custody (she didn't rotate), domain matches, signature recovers correctly. No nonce check exists.

Alice is now permanently spoofable as a Phase B feature: the only way she can keep her own domain pointed at her own metadata is to rotate custody to a new address (severing the JFS proof) AND keep her well-known endpoint scrubbed of the old proof. That is not a defensible operational posture; it inverts the threat model of a domain-control attestation.

### Scenario 3 — metadata grinding via re-registration churn

Even without Phase B, Scenario 1 generalizes: any chain on which Alice has not yet registered is a free target. Once hypersnap promotes additional shards or runs validator-internal forks for testing, the proof is replayable on each one. The defense at `:189-201` (live on-chain custody lookup) requires that each chain's on-chain custody store for FID 42 returns the same address — which it does as long as the L1 IdRegistry indexer is shared / mirrored, which is the production setup.

## Compounding factor — low-S not enforced (creates a second replayable copy)

`account_association.rs:171-180` parses the signature via `PrimitiveSignature::from_bytes_and_parity` and calls `recover_address_from_prehash`, which silently normalizes high-S. The verifier accepts **both** `(r, s, v)` and the malleated `(r, n-s, v^1)`. So even a defensive future fix that nullifier-consumes "the proof bytes" by content-hashing them would still admit a second variant per JFS proof unless the bytes are canonicalized at consumption time. (This is the same Rust-side leniency flagged in F044; it bites here because the proof bytes themselves are the de facto bearer token.)

## Why the existing checks do not close the gap

| Check | What it gates | Replay window it leaves open |
|---|---|---|
| `header.fid == expected_fid` (line 203) | Cross-FID swap | Same FID, any chain |
| `payload.domain == expected_domain` (line 209) | Cross-domain swap | Same domain, any chain or re-registration |
| `recovered == header.key` (line 182) | Forged signature | Replay of legitimately-signed proof |
| `header.key == on-chain custody for FID` (line 195) | Stale post-rotation key | Pre-rotation window; chains that share the same custody mirror |
| `state already exists for miniapp_id` (`runtime.rs:2369`) | Same-chain re-registration today | Phase B (per code comment) AND parallel chains where state does NOT yet exist |
| Per-FID cap of 10 (`miniapp.rs:22`) | Quota only | An attacker's spoof still costs Alice 1 of her 10 slots on each chain |

There is no `personal_sign`-replay-prevention layer anywhere in the path.

## Why the spec rationale at `hyper.proto:757-761` is wrong here

The proto comment says metadata is unsigned because "only the registering FID can submit." That premise relies on an unstated assumption that nobody else can construct a valid Register message. For Unregister/Update/Add/Remove that holds — those bodies are gated by an Ed25519 signature over a chain-id+nonce-bound canonical payload from an authorized signer, AND the runtime nullifies the nonce. For **Register, that premise is false**: the JFS bearer proof is publicly served, doesn't bind chain or nonce, and the runtime never consumes it.

The implicit assumption only holds in the Farcaster app-domain-verification flow (where the verifier is a third party reading `.well-known/farcaster.json` to confirm domain control). It does NOT hold in an on-chain authorization flow.

## Recommended fix

Bind the proof to a chain-id + nonce + (optionally) a deadline, and consume the nonce.

**Option A (minimal — closes cross-chain and Phase B replay):**

1. Extend `MiniappRegisterBody` with `uint64 nonce` and `uint64 chain_id`.
2. Mandate that the JFS payload include both. The Farcaster JFS schema allows arbitrary additional JSON fields in the `payload` JSON, so this is forward-compatible:

   ```json
   { "domain": "alice.com", "chain_id": 10, "nonce": 42 }
   ```

3. In `verify_account_association`, parse `chain_id` and `nonce` from the payload, require them to equal the runtime's `protocol_chain_id` and the message-body fields respectively.
4. In `apply_miniapp_register`, call `miniapp_check_signer_and_nonce(body.fid, &custody_addr_bytes, body.nonce)` (or analogous keyed on the custody addr instead of an Ed25519 pubkey, to give custody a dedicated nonce namespace) and persist the consumed nonce in the same write batch as the state.

**Option B (full chain-of-trust — preferred):**

Drop the JFS proof for the register path entirely and use an EIP-712 typed signature with `domain.chainId` and a `Register(uint256 fid,string domain,bytes32 metadataHash,uint256 nonce,uint256 deadline)` typed message — symmetric with the rest of the EIP-712 surface in this codebase (token_escrow_claim, token_escrow_bridge, custody_escrow). The well-known JFS proof remains for off-chain domain verification but the on-chain registration is authorized by a single-use EIP-712 sig the FID's custody address explicitly produces for that purpose. This also covers metadata (currently entirely unsigned).

**Independent of A/B:** reject high-S in `account_association.rs` by either checking `s ≤ (n-1)/2` at line 172 or canonicalizing before storing the proof bytes, so the proof has at most one valid wire form.

## Affected attack-class checklist items

- `eip712-domain-or-replay-binding` — present-in-spirit for EIP-191 too; no chain_id binding, no domain separator, no nonce, no deadline.
- `low-s-ecdsa-divergence` — verifier silently accepts both S forms (compounds replay surface).

## Tests to add

- **Cross-chain replay rejected.** Build a proof valid for chain A; submit on chain B with `protocol_chain_id = B`; assert rejection.
- **Same-chain replay rejected.** Apply `MiniappRegister`, Unregister, then attempt to re-apply the **exact same** `MiniappRegisterBody` bytes; assert rejection (after Phase B is enabled this is the load-bearing case).
- **High-S sig rejected.** Negate `s` and flip parity on a valid proof; assert rejection at the `from_bytes` layer (currently passes).
- **Nonce double-spend rejected.** Submit same proof twice with the same `(fid, custody, nonce)` triple; assert second rejection from the nullifier store.
