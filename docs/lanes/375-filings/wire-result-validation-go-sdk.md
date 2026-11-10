keeper's word first

# WalletWireTransceiver returns a wallet's answer without checking it against the request, so a result the reference's client refuses reaches the caller

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The wire client validates returned wallet facts at nine sites (#487)" ("Go at `2ca481c` returns its deserialized answers without a result-validation pass ..., leaving request bindings and BEEF commitments/conservation unchecked"; "Theirs: go-sdk, filing pending"). The binary wire's counterpart of go-sdk #406 (the HTTP JSON substrate). Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk app calling a wallet through `WalletWireTransceiver` receives whatever the wallet frame decodes to: a signAction result with a txid and no transaction when the app did not ask for `returnTXIDOnly`, a createAction result carrying both a txid and a signable transaction, an empty or non-DER createSignature signature, a listOutputs page whose BEEF does not hold the outputs listed. The reference's own wire client checks each of these against the request before it returns (`validateWalletResult(call, response, bindingRequest)` at nine sites) and refuses them in named words; go-sdk's transceiver hands them to the caller, which then signs, broadcasts or trusts a malformed answer.

```go
resp, err := t.transmit(ctx, CallSignAction, originator, data)
if err != nil {
	return nil, fmt.Errorf("failed to transmit sign action call: %w", err)
}
return serializer.DeserializeSignActionResult(resp)
```

Steps to reproduce (the frames written and judged by the reference's transceiver under Node 22.18.0 by the #487 recorder, 209 frames; go-sdk read from the code at 2ca481c, not run):

1. signAction with `options: { returnTXIDOnly: false, sendWith: [5555…55] }`, the wallet answering `0001b65f51a9f71df43292636303d910597bdd1c9a4a8ae8dd5f18c2140cf05e6b8b0001555555555555555555555555555555555555555555555555555555555555555501` (a txid, no tx; frame `signAction_tx_null`). The reference refuses `Invalid signAction result tx: expected transaction evidence unless returnTXIDOnly was explicitly requested`; go-sdk returns the result with a nil `Tx`.
2. createAction answered with both a txid and a signable transaction (frame `createAction_exclusive_signable`): the reference refuses `Invalid createAction result signableTransaction: expected exclusive of txid and tx`; go-sdk returns both.
3. createSignature answered with an empty signature (`00`, frame `createSignature_empty`): the reference refuses `Invalid createSignature result signature: expected a canonical DER-encoded ECDSA signature`.

Expected: each returned result checked against the request it answers (the request's options and outputs, the BEEF's commitments, the scalar and certificate shapes), as the reference's transceiver does at createAction, signAction, listOutputs, createSignature, acquireCertificate, listCertificates and proveCertificate (the two linkage calls are go-sdk #405).

Actual: the decoded result returned unchecked.

bsv-rs's transceiver runs the reference's result validation at the nine sites and replays all 209 recorded frames to the reference's verdicts (#487).

Witness:

- [tests/wallet_wire_result_validation_487.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/wallet_wire_result_validation_487.rs) (the 209 frames recorded from the reference, with its verdict and words for each)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/substrates/wallet_wire_transceiver.go:38-63](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/wallet_wire_transceiver.go#L38-L63) (createAction and signAction; the same at `:119`, `:155`, `:167`, `:227`, `:251`, `:263`, `:275`)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:227](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L227) (createAction), [:320](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L320) (signAction), [:665](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L665) (listOutputs), [:1093](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1093) (createSignature), [:1438](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1438) (acquireCertificate), [:1551](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1551) (listCertificates), [:1618](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1618) (proveCertificate).

Existing related filing(s): go-sdk #406 (ours, open) asks the same pass of the HTTP JSON substrate; go-sdk #400 (ours, open) bounds the wire's widths and collection counts; go-sdk #405 (ours, open) validates the two linkage results. None covers these seven wire results' request bindings. Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: run a result-validation pass, bound to the request, in `WalletWireTransceiver` before returning each result, as the reference's transceiver does.

Evidence status: the reference was run by the linked recorder (Node 22.18.0) and its frames and verdicts are embedded in the Rust test; go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
