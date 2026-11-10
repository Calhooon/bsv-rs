keeper's word first

# LocalKVStore writes an unsigned one-field token that the TypeScript LocalKVStore refuses, and reads or spends any basket output as a token without authenticating it

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The contacts manager and the key-value stores send signAction the reference as the wallet answered it" (#326, with #341/#342 and #454; "go-sdk@2ca481c's `LocalKVStore` sends the bytes and no options"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `local-kvstore-wallet-contract.md`; the signAction options it also named are dropped here, since go-sdk's store has no configured options to carry. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk `LocalKVStore.Set` writes its token as a PushDrop with the value alone and no signature field, where the reference writes the value and the wallet's signature over it and refuses, at every lookup, a token of any other field count; so a key set from a go-sdk app is invisible to a TypeScript app on the same wallet and basket, whose `get`, `set` and `remove` fail on it. In the other direction go-sdk's `Get` returns field 0 of the most recent output listed under the key's tag whether or not this store wrote it, and `Set` and `Remove` sign it away as an input: no locking key, signature or BEEF check runs.

```go
lockingScript, err := pushDrop.Lock(
	ctx,
	[][]byte{valueBytes},
	kv.getProtocol(key),
	key,
	wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
	true,  // forSelf
	false, // includeSignature
	pushdrop.LockBefore,
)
```

The reference locks with `pushdrop.lock([valueAsArray], protocol.protocolID, protocol.keyID, 'self')`, so `includeSignature` takes its default `true` (`LocalKVStore.ts:486-492`, `PushDrop.ts:130-150`). With counterparty self the two `forSelf` values derive the same key, so the locking key agrees and only the signature field differs.

```go
mostRecentOutput := outputsResult.Outputs[len(outputsResult.Outputs)-1]
...
pushDropData := pushdrop.Decode(txOutput.LockingScript)
if pushDropData == nil || len(pushDropData.Fields) < 1 {
	return nil, fmt.Errorf("invalid pushdrop token format found for key %s in output %s", key, mostRecentOutput.Outpoint)
}
valueBytes := pushDropData.Fields[0]
```

The reference's reader (`LocalKVStore.ts:231-306`): the BEEF read strictly, each outpoint unique and found in it with the listed satoshis and script, the token a canonical PushDrop of exactly two fields, its locking key the wallet's `getPublicKey` for the protocol with counterparty self (`KVStore token locking key does not belong to the wallet`), and `verifySignature` over the value field (`KVStore token signature is invalid`); only then is it read or spent.

Steps to reproduce (go-sdk read from the code at 2ca481c, not run; the reference's two-field token and its refusals recorded in the linked vector):

1. go-sdk `Set("alpha", "1")`: the token is `<key> OP_CHECKSIG <"1"> OP_DROP`, one field.
2. The reference's `get("alpha")` on the same wallet lists it and refuses it at `decodeCanonicalPushDrop(..., { fieldCount: 2 })`, the lookup failing in the local store's wrapper.
3. Place in the basket, tagged `alpha`, a PushDrop output locked by another key: go-sdk's `Get` returns its field 0; the reference refuses `KVStore token locking key does not belong to the wallet`.

Expected: the token written with the signature field, and a listed output authenticated (the BEEF's output, the wallet's locking key, the field signature) before it is read or spent, as the reference does.

Actual: an unsigned one-field token written; the last listed output decoded and trusted.

bsv-rs authenticates every local output before `get`, `set` and `remove` (#454) and binds the signable transaction before signing (#341).

Witness:

- [tests/kvstore_local_454.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/kvstore_local_454.rs) (`every_local_output_is_authenticated_before_set_and_remove_454`, `local_get_rejects_a_hidden_second_output_454`)
- [tests/vectors/kvstore_local_454.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/kvstore_local_454.json) (recorded from the reference)
- [tests/kvstore_bound_action_341_342.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/kvstore_bound_action_341_342.rs) (`the_local_output_is_bound_before_signing_341`)

Pinned reference reading:

- [go-sdk@2ca481c59 kvstore/local_kv_store.go:269-278](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/kvstore/local_kv_store.go#L269-L278) (the lock, `includeSignature` false)
- [go-sdk@2ca481c59 kvstore/local_kv_store.go:66-140](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/kvstore/local_kv_store.go#L66-L140) (`lookupValue`) and [:336-345](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/kvstore/local_kv_store.go#L336-L345) (the spend signed from it)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/kvstore/LocalKVStore.ts:231-306](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/kvstore/LocalKVStore.ts#L231-L306) (the reader) and [:486-492](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/kvstore/LocalKVStore.ts#L486-L492) (the lock).

Existing related filing(s): none found (`--search "kvstore"`, 2026-11-10).

Requested maintainer action: write the token with its signature field (`includeSignature` true) and authenticate each listed output (the BEEF's output, the wallet's locking key, the field signature) before `LocalKVStore` reads or spends it, as the reference does.

Evidence status: go-sdk source-read at 2ca481c, not run; the reference's behaviour is the recorded vector and its lines at edf6e03. This draft contains no private-key literal.
