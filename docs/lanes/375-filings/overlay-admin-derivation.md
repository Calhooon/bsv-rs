# Match canonical overlay advertisement key derivation

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 26: Go signs overlay admin tokens with counterparty = Self (a…

Produce a SHIP or SLAP advertisement with the same fixture wallet and decode/verify it using the TypeScript validator. Go selects self and forSelf false at admin-token.go:107-110, while canonical TypeScript lock uses anyone and forSelf true. BRC-42 symmetry preserves the locking public key, but the signature derives from a different signing key, so the token fails the canonical validator. Keep any intended legacy title-case/self compatibility explicit.

Witness:

- [tests/overlay_admin_token_ts_parity_tests.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/overlay_admin_token_ts_parity_tests.rs)
- [tests/vectors/overlay_admin_token_ts_parity.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/overlay_admin_token_ts_parity.json)

Pinned reference reading:

- [go-sdk@2ca481c59 overlay/admin-token/admin-token.go:97-113](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/overlay/admin-token/admin-token.go#L97)
- [ts-stack@edf6e03da packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts:290-308,340-348](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts#L290)

BRC reading: [BRCs@5119a9b51 overlays/0088.md:45-70](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/overlays/0088.md#L45).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
