keeper's word first

# The wallet wire turns a refusal into success: a false verifyHmac, verifySignature or waitForAuthentication verdict and a refused abortAction are written as the success frame and read back as true

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence rows "A false verdict on the wallet wire" (#197) and "A refused abort on the wallet wire" (#206), both "Theirs: go-sdk, filing pending". Supersedes the short batch-1 drafts `wire-false-verdicts.md` and `wire-abort-refusal.md` (one serializer pattern, one fix). Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk client calling a wallet through the wire (`WalletWireTransceiver`) is told that an HMAC or a signature is valid, that the user is authenticated, or that an action was aborted, whatever the wallet answered: the readers return `true` without reading the frame. Behind go-sdk's own processor a wallet's `Valid: false` is written as the success frame. go-sdk's own `ProtoWallet` does not answer `Valid: false`: it returns `ErrInvalidSignature` and `ErrInvalidHMAC` for a failed check, as the reference's `ProtoWallet` throws (`proto_wallet.go:269-274`, `:357-362`), and the processor hands that error to its transport with no frame (the wire-error-frames draft). The success frame therefore reaches the client from any other wallet implementation that answers `{Valid: false}`, which go-sdk's result type permits (`Valid bool`, `wallet/wallet.go:182-189`) where the reference types the result `valid: true` (`Wallet.interfaces.ts:789,819`); the readers' constant `true` is the defect whatever the wallet answers.

```go
func SerializeVerifyHMACResult(_ *wallet.VerifyHMACResult) ([]byte, error) { return nil, nil }
func DeserializeVerifyHMACResult(_ []byte) (*wallet.VerifyHMACResult, error) {
	return &wallet.VerifyHMACResult{Valid: true}, nil
}
func SerializeAbortActionResult(*wallet.AbortActionResult) ([]byte, error) { return nil, nil }
func DeserializeAbortActionResult([]byte) (*wallet.AbortActionResult, error) {
	return &wallet.AbortActionResult{ Aborted: true }, nil
}
```

`verify_signature.go:102-110` and `authenticated.go:36-44` (`waitForAuthentication`) are the same. The reference's processor throws on a false verdict, so the frame is an error frame (`if (verifyHmacResult.valid !== true) throw new Error('HMAC is not valid')`, `WalletWireProcessor.ts:1520`; the signature at `:1597`, `Wallet did not affirmatively authenticate` at `:1636-1638`), and a wallet's `aborted: false` is framed code 8, `abortRefused` (`:797-804`), which the reference's transceiver reads back as `{ aborted: false }` (`WalletWireTransceiver.ts:334-340`).

Steps to reproduce (go-sdk read from the code at 2ca481c, not run; the reference's frames are pinned by the Rust tests below against the reference's words):

1. A wallet behind `WalletWireProcessor` answers `VerifySignature` with `{Valid: false}`. The processor writes the success frame `00`; `DeserializeVerifySignatureResult` reads `{Valid: true}`.
2. A wallet answers `AbortAction` with `{Aborted: false}` (the action is already broadcast). The processor writes `00`; the client reads `{Aborted: true}`.
3. A TypeScript processor answers both with error frames; go-sdk's transceiver reads those as errors, so only go-sdk's processor turns them into success, and only go-sdk's reader returns true for any success frame.

Expected: a false verdict framed as an error and a refused abort framed code 8, as the reference frames them; the readers returning what the frame says.

Actual: every one of the four is success, and read as true.

bsv-rs frames them in the reference's words and reads code 8 as `aborted: false` (#197, #206).

Witness:

- [tests/wire_error_frames.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/wire_error_frames.rs) (`the_three_false_verdicts_are_framed_in_the_references_words`, `a_wallets_refused_abort_is_framed_code_8_in_the_references_words`, `the_transceiver_reads_code_8_as_aborted_false`)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/serializer/verify_hmac.go:71-77](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/verify_hmac.go#L71-L77), [verify_signature.go:102-110](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/verify_signature.go#L102-L110), [authenticated.go:36-44](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/authenticated.go#L36-L44), [abort_action.go:33-43](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/abort_action.go#L33-L43); [wallet/substrates/wallet_wire_processor.go:256-266](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/wallet_wire_processor.go#L256-L266) (the wallet's result handed to the serializer); [wallet/proto_wallet.go:269-274](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/proto_wallet.go#L269-L274) (`ErrInvalidSignature` for a failed check, so go-sdk's own wallet never answers `Valid: false`) and [wallet/wallet.go:182-189](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/wallet.go#L182-L189) (`Valid bool`, which another wallet may answer false)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:797-804](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L797-L804), [:1518-1526](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L1518-L1526), [:1634-1644](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L1634-L1644); [WalletWireTransceiver.ts:334-340](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L334-L340).

Existing related filing(s): go-sdk #410 (the createAction result's extra success byte) and #409 (`sendWithResults`'s marker) are other frames of the same serializer package; neither touches these four results. No upstream issue found (`--search "VerifyHMAC result"`, `"verify signature wire"`, `"abort action"`, 2026-11-10).

Requested maintainer action: frame a false verdict as an error and a refused abort as code 8, and have the four readers return the verdict the frame carries, never a constant true.

Evidence status: go-sdk source-read at 2ca481c, not run; the reference's frames and words are pinned by the linked Rust tests, written from the reference's lines. This draft contains no private-key literal.
