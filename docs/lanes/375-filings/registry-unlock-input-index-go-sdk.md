keeper's word first

# RegistryClient revokes and updates a definition by signing the token's output index as the input index, so the spend is signed for the wrong input whenever the two differ

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The registry's revoke and update unlocking script (#548)" ("Go at `2ca481c` unlocks with the same unlocker but signs and keys the spend at the token's output index"; "Theirs: go-sdk, filing pending"). Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk app revoking (or updating) a registry definition whose token is output 0 of its transaction, in a signable transaction where the wallet put the token at input 1 (after a funding input), signs input 0 and hands signAction a spend for input 0: the token's input is left unsigned and another input gets the token's unlocking script, so the wallet refuses the action, or the revoke never confirms. The index the spend needs is the token's position among the signable transaction's inputs; go-sdk uses `record.OutputIndex`, its position among its source transaction's outputs.

```go
finalUnlockScript, err := unlocker.Sign(partialTx, int(record.OutputIndex))
...
Spends: map[uint32]wallet.SignActionSpend{
	record.OutputIndex: { UnlockingScript: finalUnlockScript.Bytes() },
},
```

The reference unlocks with `pushdrop.unlock(protocol, '1', 'anyone', 'all', false, satoshis, lockingScript)` (`RegistryClient.ts:539-548`) under `completeBoundAction`, which finds the input spending the token's outpoint in the signable transaction and signs and keys that input.

Steps to reproduce (the reference recorded under Node 22.18.0 by the linked recorder, wallet the scalar 9; go-sdk read from the code at 2ca481c, not run):

1. Case 0 of the vector: revoke the basket token `9552c0cb…b6d8cd.0`; the wallet's signable transaction spends it at input 1.
2. The reference signs input 1 and sends `spends: { 1: { unlockingScript: 4830450221…0841 } }` (`spend_index: 1`), valid under the token's lock.
3. go-sdk signs input 0 (`record.OutputIndex` is 0) and sends the spend keyed 0.

Expected: the token's input located in the signable transaction by its outpoint, signed there and keyed by that index.

Actual: the output index used for both.

bsv-rs signs and keys the token's input index (#548).

Witness:

- [tests/registry_unlocking_548.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/registry_unlocking_548.rs) (`a_revoke_and_an_update_unlock_the_definition_token_as_the_reference_does_548`, `the_spend_this_crate_signs_unlocks_the_token_548`)
- [tests/vectors/registry_unlocking_548.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/registry_unlocking_548.json) (six cases, revoke and update for the three types, each with `spend_index` and the reference's unlocking script)

Pinned reference reading:

- [go-sdk@2ca481c59 registry/methods.go:405-441](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/registry/methods.go#L405-L441)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/registry/RegistryClient.ts:536-552](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/registry/RegistryClient.ts#L536-L552).

Existing related filing(s): the registry-token-fields draft (this lane's, unfiled) is the token's format. No upstream issue found (`--search "registry"`, 2026-11-10).

Requested maintainer action: sign and key the registry spend at the input index of the token's outpoint in the signable transaction, not at the token's output index.

Evidence status: the reference's spends are the recorded vector (Node 22.18.0); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal (the wallet key is the scalar 9, named).
