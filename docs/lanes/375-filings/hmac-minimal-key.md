HOLD — [the keeper's 2026-10-30 07:14Z word](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425):
go-sdk PR #389 is the maintainers' own change, described as in flight; a new
filing would duplicate it. Reviews 2 and 3 read this as outside the charter.
The live PR state below differs from that recorded reason; keep the HOLD.
The keeper's word of 2026-10-30 08:1xZ ([recorded](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6518218558)): the hold holds, a filing would ask go-sdk for what its master already carries; the row reads fixed on master at `a8159c77` after the pin, in no release through v1.7.3, re-read at the monthly recon and closed when a release names it.

# Use the amended BRC-56 minimal-length ECDH X coordinate for HMAC

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 20: BRC-56 HMAC (#379, #375): issuance and strict HmacVerifyPolicy::MinimalLengthOnly conform to…

The self k95 and k91538 witnesses omit one and two leading zero octets; counterparty k497 and k29510 do likewise. Go passes key.ToBytes() to HMAC and pads short keys in NewSymmetricKey, producing the legacy tag and rejecting the minimal-key tag. Implement the amended convention and explicitly plan migration of persisted identifiers. No private key or derived HMAC key literal is needed: use the linked published fixture.

Witness:

- [tests/vectors/wallet_hmac_key_379.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_hmac_key_379.json)
- [tests/wallet_hmac_issuance_379.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_hmac_issuance_379.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/proto_wallet.go:295-313,335-357](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/proto_wallet.go#L295)
- [go-sdk@2ca481c59 primitives/ec/symmetric.go:82-90](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/primitives/ec/symmetric.go#L82)
- [ts-stack@9a2787b8c packages/sdk/src/wallet/ProtoWallet.ts:295-365](https://github.com/bsv-blockchain/ts-stack/blob/9a2787b8c/packages/sdk/src/wallet/ProtoWallet.ts#L295)

BRC reading: [BRCs@d4ce8119f wallet/0056.md:56-89](https://github.com/bsv-blockchain/BRCs/blob/d4ce8119fbdc5964aed5913cf41d0089df08f833/wallet/0056.md#L56). This amendment mandates minimal-length keys; legacy compatibility here remains a named owner-authorized Rust policy.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Existing related filing(s): [go-sdk PR #389](https://github.com/bsv-blockchain/go-sdk/pull/389),
“fix(wallet): key HMAC with minimal-length X coordinate per BRC-56”,
by **deggen (@sirdeggen)**, state **MERGED** (2026-10-28 20:39:45Z).
This is GitHub's state when checked for this record; the keeper's later word
calls it “in flight”. The verdict preserves that word as the historical HOLD
reason, pending reconciliation; the source reading above remains at `2ca481c`.
The merge commit `a8159c77` is not an ancestor of `2ca481c` (v1.7.2) and no
go-sdk tag contains it (the latest release is v1.7.3, 2026-10-20): go-sdk
diverges at the pin and in every release, and conforms on `master` only.
