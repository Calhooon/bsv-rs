HOLD — a stated row on [the keeper's 2026-10-30 08:1xZ word](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6518218558): a frame cap is the reference's own resource safeguard and not a BRC number, Go's choice to make; the row names the difference; this crate's processor cap (bsv-rs#505) runs as hardening. Not filed.

# Bound a complete wallet wire request before transmitting it

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created.
Census row 10, #496: the client refuses a complete request frame above
256 MiB before calling either transport. Wire shapes are the charter's;
this draft needs the keeper's word before the owner's filing cadence applies.

At the Go pin, WriteRequestFrame builds the complete request and the
transceiver passes it directly to TransmitToWallet without a size check.
The TypeScript WalletWire contract requires requests and responses no larger
than MAX_WALLET_WIRE_FRAME_BYTES, and its client checks the completed frame
before choosing the legacy or compact transport. Go can therefore transmit
a frame the reference client refuses. Add the same strict greater-than check
after serialization and before transmission, using the reference's uncoded
error: `Wallet Wire request exceeds the maximum permitted size`.
A frame exactly at 268,435,456 bytes must still be sent.

Witness:

- [tests/wallet_wire_request_frame_cap_496.rs](https://github.com/Calhooon/bsv-rs/blob/2feb00dca1b34699cbf2aa712bde654b4d311c72/tests/wallet_wire_request_frame_cap_496.rs)
- [tests/vectors/wallet_wire/request_frame_cap_496.json](https://github.com/Calhooon/bsv-rs/blob/2feb00dca1b34699cbf2aa712bde654b4d311c72/tests/vectors/wallet_wire/request_frame_cap_496.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWire.ts:4-9](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWire.ts#L4)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:95-107](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L95)
- [go-sdk@2ca481c59 wallet/serializer/frame.go:19-36](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/frame.go#L19)
- [go-sdk@2ca481c59 wallet/substrates/wallet_wire_transceiver.go:23-35](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/wallet_wire_transceiver.go#L23)

BRC reading: the 256 MiB cap is the reference's explicit WalletWire transport
contract, not a claimed BRC-100 numeric limit. WalletWire.ts:4-9 says requests
and responses must fit; this is a reference-contract defect at the Go pin.

Evidence status: source-read at the pins in this docs lane; the linked Rust
test and recorded frame recipes are the reproducible witness, not a claim
that Go or TypeScript was rerun here. The test checks zero transport/wallet
calls above the cap and one at the cap. Its at-cap wallet answer uses a stub:
the reference processor reaches V8's array limit on this payload, as #496's
parity note records. This filing names the client only. Go's processor has
no cap either: `TransmitToWallet` refuses an empty message alone before
`ReadRequestFrame` (`wallet/substrates/wallet_wire_processor.go:24-29` at the
pin), where the reference's processor refuses a request above the cap before
decoding (`WalletWireProcessor.ts:248-269`); that side is not argued here
because this crate's own processor lacks the same cap,
[bsv-rs#505](https://github.com/Calhooon/bsv-rs/issues/505).

Existing related filing(s): [bsv-rs#496](https://github.com/Calhooon/bsv-rs/issues/496),
landed in [PR #503](https://github.com/Calhooon/bsv-rs/pull/503).
