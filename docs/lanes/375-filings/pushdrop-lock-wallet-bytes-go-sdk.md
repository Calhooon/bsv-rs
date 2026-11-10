keeper's word first

# PushDrop.Lock re-encodes the wallet's public key as compressed and re-serializes its signature, so a token's bytes differ from the TypeScript lock for the same wallet answer

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "PushDrop's wallet-aware lock (#782)" ("Go ... pushes the key re-encoded compressed and the signature re-serialised"; "Theirs: go-sdk, filing pending"). Drafted by the filings-1109 lane on 2026-11-09.

A go-sdk user locking a PushDrop token through a wallet that answers `getPublicKey` with an uncompressed key, or `createSignature` with a valid high-S signature, gets a locking script with other bytes than the TypeScript reference writes from the same answers: a 33-byte compressed key push where the reference pushes the 65 bytes returned, and a low-S signature field where the reference pushes the signature as the wallet produced it. The token is a different output script, so a service that finds or compares tokens by their script, or by the signature field the wallet returned, does not find go-sdk's token.

```go
pubKeyBytes := pub.PublicKey.Compressed()
lockChunks = append(lockChunks, &script.ScriptChunk{
	Op:   byte(len(pubKeyBytes)),
	Data: pubKeyBytes,
})
...
fields = append(fields, sig.Signature.Serialize())
```

`Signature.Serialize` writes the strict DER form with S at or below half the order (`primitives/ec/signature.go:77-80`, `if sigS.Cmp(S256().halfOrder) == 1`), so a high-S signature is rewritten. The reference pushes both as the wallet returned them (`PushDrop.ts:166-172`, `{ op: publicKey.length / 2, data: toArray(publicKey, 'hex') }`; `:184`, `fields.push(signature)`).

Steps to reproduce (the reference run by the #782 recorder; go-sdk read from the code at 2ca481c, not run):

1. A wallet answering `getPublicKey` with the uncompressed form of `027f04d8ef56518c7940ebd25a81856164557964651175ff969406182c8f338329` (`047f04d8...`, 65 bytes), fields `6869`, `05`, `` (empty), signature included, lock before.
2. The reference's locking script starts `41047f04d8ef56518c7940eb...` (case `uncompressed_answer_signed_before`); go-sdk's starts `21027f04d8ef56518c7940eb...`.
3. A wallet whose `createSignature` answers a high-S DER signature: the reference pushes those bytes; go-sdk pushes the low-S re-encoding (read from the code).

Expected: the key and the signature pushed as the wallet returned them, so the same wallet answers give the same token in both SDKs.

Actual: both re-encoded.

bsv-rs pushes both as returned (`PushDrop::lock_with_wallet`, `src/script/templates/pushdrop_wallet.rs`, since #782; the key bytes since #545).

Witness:

- [tests/script_pushdrop_wallet_lock_782.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/script_pushdrop_wallet_lock_782.rs) (`the_wallet_lock_writes_the_references_bytes_782`, `a_wallet_key_in_an_uncompressed_form_is_pushed_as_returned_782`)
- [tests/vectors/pushdrop_wallet_lock_782.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/pushdrop_wallet_lock_782.json) (cases `uncompressed_answer_signed_before`, `uncompressed_answer_signed_after`, recorded from the reference under Node 22.18.0)

Pinned reference reading:

- [go-sdk@2ca481c59 transaction/template/pushdrop/pushdrop.go:124-161](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/template/pushdrop/pushdrop.go#L124-L161) (the key at `:136`, the signature at `:160`)
- [go-sdk@2ca481c59 primitives/ec/signature.go:70-80](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/primitives/ec/signature.go#L70-L80) (`Serialize`, low S)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/script/templates/PushDrop.ts:155-185](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/templates/PushDrop.ts#L155-L185).

Existing related filing(s): go-sdk #401 (row 9 of the queue: the certificate adapter rewriting a valid high-S signature, the same `Serialize` normalization at another site). Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: push the key and the signature bytes the wallet returned (keep the encoding the wallet's answer carried) rather than re-encoding them.

Evidence status: the reference's bytes are the recorded vector (Node 22.18.0); go-sdk source-read at 2ca481c, not run. The go-sdk wallet interface returns a parsed `*ec.PublicKey` and `*ec.Signature`, so the fix may need the original bytes carried through the wallet result types; this draft names the difference, not the shape of the fix. This draft contains no private-key literal.
