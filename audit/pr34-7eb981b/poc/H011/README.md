# H011 PoC (used by F014): watcher recipient decoding vs the encoding the repo's tests use

Target: farcasterorg/hypersnap @ `7eb981b`. Solidity only, Foundry.

This harness was written during the hunt (task H011) and is the PoC for F014. It needs only
the repo's own contracts: the original harness used byte-identical copies of `contracts/src`,
`contracts/test/utils` and `contracts/foundry.toml` at `7eb981b`, so only the new test file is
published here.

## Run

```
git archive 7eb981b contracts | tar -x -C <scratch>
cd <scratch>/contracts
# libs: OpenZeppelin contracts + contracts-upgradeable v5.1.0, forge-std (as in remappings)
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0 OpenZeppelin/openzeppelin-contracts-upgradeable@v5.1.0 foundry-rs/forge-std --no-git
cp <this dir>/H011RecipientEncoding.t.sol test/
forge test --match-contract H011 -vv
```

Expected output: `H011-forge-output.txt` (2/2 pass).

- `test_rightAlignedFid_isBurnedButSkippedByWatcher`: a burn with `hypersnapRecipient = bytes32(uint256(fid))`
  (the encoding the repo's own Solidity tests use) succeeds on-chain, but the node watcher's decoder
  (`decode_hypersnap_recipient`, `src/chain/bridge_burn_watcher.rs:300-313`, ported in the test) rejects it.
- `test_leftAlignedFid_isCredited`: the left-aligned encoding the watcher expects is accepted (control).
