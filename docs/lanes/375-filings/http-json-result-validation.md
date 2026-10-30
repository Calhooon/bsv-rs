FILE — seventeenth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6521258019), moved one place by the keeper's 11:1xZ word; pending the owner's cadence word.

# Validate HTTP wallet results against their requests and BRC-100 shapes

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 18: the HTTP JSON result-check inventory was closed by #432; Go still lacks the reference result-validator pass.

The JSON substrate unmarshals successful responses but does not run the reference result validator. Replay the linked R01-R88 inventory cases: out-of-range totals, mismatched action outputs/values, invalid BEEF bindings, malformed scalar/container fields and unsafe records. Typed JSON decoding alone cannot bind the returned transaction to the request. The Rust inventory was closed by #432; the Go gap remains at the pin.

Witness:

- [tests/wallet_http_json_pending_432.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_http_json_pending_432.rs)
- [tests/wallet_http_json_result_values_408.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_http_json_result_values_408.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/substrates/http_wallet_json.go:37-79](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_json.go#L37)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:322-341](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts#L322)
- [ts-stack@edf6e03da packages/sdk/src/wallet/WalletResultValidation.ts:1919-1938](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/WalletResultValidation.ts#L1919)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:274-278,302-309](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L274).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Census row 18 now records #432 (landed at `d81def2f`, PR #461): 85 fully Done rows and three stated residues, R02/R03 for native JSON representation and R47 for the public u32 totals kept by the keeper's #467 word (the wider JSON-validator total is ts-stack #1449). The earlier assignment to a second lane is resolved; this draft concerns Go at the pinned source only.
