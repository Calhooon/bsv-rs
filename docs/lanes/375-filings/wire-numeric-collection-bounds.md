FILE — second in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); filed as bsv-blockchain/go-sdk#400 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending.

# Check wallet response widths and collection counts before reading or allocating

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Filed as bsv-blockchain/go-sdk#400 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending. Census row 10: The wallet wire's client-side bounds (#473) are the reference's (WalletWireTransceiver.ts…

The recorded getHeight case above u32 wraps through ReadVarInt32. The corpus also covers satoshis above 2100000000000000, over-cap collections, impossible counts versus remaining bytes, and pages beyond their limit/total. Enforce the declared widths and pre-allocation bounds; do not narrow a successfully read u64 silently.

Witness:

- [tests/wallet_wire_bounds_473.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_wire_bounds_473.rs)
- [tests/vectors/wallet_wire/bounds_473.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_wire/bounds_473.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1940-1953](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1940)
- [go-sdk@2ca481c59 wallet/serializer/get_height.go:14-21](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/get_height.go#L14)
- [go-sdk@2ca481c59 util/reader.go:123-125,263-280](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/util/reader.go#L123)
- [go-sdk@2ca481c59 wallet/serializer/list_actions.go:239-292](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/list_actions.go#L239)
- [go-sdk@2ca481c59 wallet/serializer/list_outputs.go:144-163](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/list_outputs.go#L144)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:274-278](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L274).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
