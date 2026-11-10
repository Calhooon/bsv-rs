keeper's word first

# RegistryClient locks a definition token with forSelf false and reads 6/6/7 fields, so it refuses the reference's tokens and its own, and the reference refuses go-sdk's

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The registry definition token (#543)" ("Go at `2ca481c` locks with `forSelf` false (`registry/methods.go:45-55`) and reads 6/6/7 unverified (`registry/client.go:246,267,293`)"; "Theirs: go-sdk, filing pending"). Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk app that registers a basket, protocol or certificate definition writes a token the TypeScript registry skips: its locking key is derived for counterparty anyone with `forSelf` false, where the reference's validator expects the operator's anyone-derived key (`Registry token locking key is not linked to its operator`). Reading, go-sdk's `parseLockingScript` requires 6, 6 or 7 decoded fields, but `pushdrop.Decode` returns the signature field too, so every signed token (the reference's 7/7/8, and go-sdk's own, also signed) is refused as an unexpected field count, and no signature is verified on any path.

```go
// registry/methods.go:44-55, the lock
lockingScript, err := pushDrop.Lock(ctx, fields, protocol, "1",
	wallet.Counterparty{ Type: wallet.CounterpartyTypeAnyone },
	false, // forSelf
	true,  // includeSignature
	pushdrop.LockBefore,
)
// registry/client.go:246, the read (basket; protocol at :267, certificate 7 at :293)
if len(decoded.Fields) != 6 {
	return nil, errors.New("unexpected field count for basket type")
}
```

`buildPushDropFields` (`client.go:150-196`) gives a basket 5 fields plus the operator, 6, and `Lock` appends the signature (`pushdrop.go:144-160`), 7 on the chain. The reference locks with `pushdrop.lock(fields, protocol, '1', 'anyone', true)` (`RegistryClient.ts:320`) and reads through `decodeAndVerifySignedPushDropToken` (`registryTokenValidation.ts:13-41`): `dataFields + 1` fields, the lock `new KeyDeriver('anyone').derivePublicKey(protocolID, '1', operator)`, the operator's signature over the data fields.

Steps to reproduce (the reference's tokens recorded under Node 22.18.0 by the linked recorder, wallet the scalar 9, operator `03acd484…27ccbe`; go-sdk read from the code at 2ca481c, not run):

1. The reference's basket token (vector `tokens[0]`) is locked by `03a8e23c8d3fbcfda8ee345368bc8bdb2ec630f1d6d5eef0e1a8cf22d3fcb2b91e` and carries 7 fields, the last the signature `3045022100f9e1c054…12a7b`.
2. go-sdk's `parseLockingScript` decodes 7 fields and returns `unexpected field count for basket type`.
3. go-sdk's own basket token for the same definition is locked by the anyone key's child (`forSelf` false), not `03a8e23c…`, so the reference's resolver skips it.

Expected: locked with `forSelf` true for counterparty anyone, read as `dataFields + 1` fields with the signature verified against the operator, as the reference does.

Actual: `forSelf` false; 6/6/7 fields counted with the signature among them; nothing verified.

bsv-rs writes the reference's bytes and reads through the reference's validator (#543).

Witness:

- [tests/registry_token_fields_543.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/registry_token_fields_543.rs) (`the_registry_client_writes_the_reference_definition_token_543`, `the_reference_definition_tokens_are_read_by_the_resolvers_and_the_listing_543`, `a_token_changed_in_one_respect_is_skipped_as_the_reference_skips_it_543`)
- [tests/vectors/registry_token_fields_543.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/registry_token_fields_543.json) (the three definition types' tokens, wallet calls and verdicts, 30 one-change refusals; recorded from the reference)

Pinned reference reading:

- [go-sdk@2ca481c59 registry/methods.go:40-58](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/registry/methods.go#L40-L58) (the lock)
- [go-sdk@2ca481c59 registry/client.go:150-196](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/registry/client.go#L150-L196) (the fields) and [:236-300](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/registry/client.go#L236-L300) (the read)
- [go-sdk@2ca481c59 transaction/template/pushdrop/pushdrop.go:20-50](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/template/pushdrop/pushdrop.go#L20-L50) (`Decode` returning every field, the signature included)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/registry/RegistryClient.ts:320](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/registry/RegistryClient.ts#L320) and [registryTokenValidation.ts:13-64](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/registry/registryTokenValidation.ts#L13-L64).

Existing related filing(s): none found (`--search "registry"`, 2026-11-10; #120, closed, is the original port). The registry-unlock-input-index draft (this lane's, unfiled) is the revoke and update spend, another function.

Requested maintainer action: lock definition tokens with counterparty anyone and `forSelf` true, and read them as the reference does (the data fields plus the signature, the lock and the signature verified against the operator).

Evidence status: the reference's tokens and verdicts are the recorded vector (Node 22.18.0); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal (the wallet key is the scalar 9, named).
