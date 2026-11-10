keeper's word first

# WalletWireProcessor returns a wallet's refusal as a Go error instead of an error frame, so a wire client never learns the refusal's code

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The processor's error frame is the reference's" (#202; "go-sdk's processor writes no error frame"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `wire-error-frames.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A wallet served by go-sdk's `WalletWireProcessor` that refuses a call (an invalid parameter, code 6; insufficient funds, code 7; a refused abort, code 8) produces no BRC-100 error frame: `TransmitToWallet` returns a Go error to its transport, so the client on the other side (a TypeScript `WalletWireTransceiver`, or go-sdk's own) receives a transport failure in place of the frame and cannot tell a parameter refusal from an outage. go-sdk's `WriteResultFrame`, when a caller does use it with an error, writes the message uncut and the stack as given.

```go
if err != nil {
	return nil, fmt.Errorf("error calling %d: %w", requestFrame.Call, err)
}
return serializer.WriteResultFrame(response, nil), nil
```

The reference's processor catches every wallet error (`#invokeWallet`, `WalletWireProcessor.ts:2402-2418`): an explicit wallet error with a code from 2 to 8 keeps its code and words, any other error is `Wallet operation failed`, code 1, and the frame carries the message cut at 4096 bytes and an empty stack (`:2385-2399`: "Stack traces disclose source paths and implementation details to remote callers.").

Steps to reproduce (go-sdk read from the code at 2ca481c, not run; the reference's frames pinned by the Rust tests below):

1. A wallet behind `WalletWireProcessor` returns a `wallet.Error` with code 6 from `CreateAction`.
2. `TransmitToWallet` returns `(nil, "error calling 1: failed to process create action: ...")`; no frame is written.
3. The reference's processor writes `06` followed by the message's length and bytes and a zero-length stack, which a client reads back as the code-6 refusal.

Expected: every wallet failure framed (its code when it is an explicit wallet error from 2 to 8, else code 1 with a generic message), the message bounded, the stack empty.

Actual: no frame; the error reaches the transport.

bsv-rs frames every wallet call through the reference's `#invokeWallet` rule (#202, #137).

Witness:

- [tests/wire_error_frames.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/wire_error_frames.rs) (`an_uncoded_wallet_error_is_framed_as_wallet_operation_failed`, `every_wallet_error_variant_is_framed_as_the_same_constant`, `the_processors_own_refusal_is_framed_with_code_one`)
- [tests/wire_wallet_refusal_class.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/wire_wallet_refusal_class.rs) (codes 2 to 8 framed with their words)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/substrates/wallet_wire_processor.go:24-97](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/wallet_wire_processor.go#L24-L97) (the error returned at `:94-96`)
- [go-sdk@2ca481c59 wallet/serializer/frame.go:70-87](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/frame.go#L70-L87) (`WriteResultFrame`: the message and the stack written whole)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:2380-2418](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L2380-L2418).

BRC reading: [BRCs@5119a9b51 wallet/0100.md:1553,1613-1616](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L1553) ("If an error occurred, it contains the serialized error message and optional stack trace"; the error frame's message and stack fields).

Existing related filing(s): the wire-false-verdicts draft (this lane's, unfiled) is the success-frame half of the same processor; go-sdk #410 is the createAction result's extra success byte. No upstream issue found (`--search "error frame"`, 2026-11-10).

Requested maintainer action: have `TransmitToWallet` write an error frame for every wallet failure (the code for an explicit wallet error from 2 to 8, else code 1), with the message bounded and no stack, as the reference's processor does.

Evidence status: go-sdk source-read at 2ca481c, not run; the reference's frames are pinned by the linked Rust tests from the reference's lines. This draft contains no private-key literal.
