FILE — eleventh in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6521258019), moved one place by the keeper's 11:1xZ word; filed as bsv-blockchain/ts-stack#1463 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending.

# Reject certificate outpoint indexes that the writer cannot serialize

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Filed as bsv-blockchain/ts-stack#1463 on 2026-11-01 under the owner's name (cadence (b), the owner's word of 2026-10-31 16:2xZ through the keeper); answer pending. Census row 47: A certificate's revocation outpoint index above u32::MAX is refused (Unreleased,…

Read a binary certificate whose revocation output index is 4294967296. Certificate.fromBinary accepts it up to the JS safe-integer ceiling, whereas toBinary refuses the outpoint. Apply the u32 bound on input and preserve the explicit bound refusal. The analogous Go narrowing is already covered by go-sdk #387.

Witness:

- [tests/auth_reader_bounds.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_reader_bounds.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/certificates/Certificate.ts:263-270,353](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/Certificate.ts#L263)
- [go-sdk@2ca481c59 wallet/serializer/serializer.go:82-96](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/serializer.go#L82)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0052.md:85-103](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0052.md#L85).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Existing related filing(s): go-sdk #387, fixed on master at 9f4c4a658 (PR #392, merged 2026-10-30), in no release through v1.7.3. Keep these numbers; confirm their scope before opening a duplicate.
