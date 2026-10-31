FILE — sixth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); filed as bsv-blockchain/go-sdk#397 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending.

# Reject contradictory repeated BUMP offsets

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Filed as bsv-blockchain/go-sdk#397 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending. Census row 36: One reader for both paths (Unreleased, bsv-rs#86): Beef::from_binary is the…

Repeat a BUMP offset with a different hash; Go's last-wins lookup discards the contradiction. TypeScript and the Rust witness refuse the duplicate offset. The linked tests construct these bytes with the crate writer. Preserve the contradictory entries long enough to reject the proof, rather than silently accepting the later hash.

Witness:

- [tests/beef_two_readers_agree.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/beef_two_readers_agree.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:133-140,221](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L133)
- [go-sdk@2ca481c59 transaction/merklepath.go:87-110](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L87)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:59-79](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L59). This asks the keeper to settle duplicate-offset handling under the charter's BEEF rules; the TypeScript reader is the implementation comparison.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
