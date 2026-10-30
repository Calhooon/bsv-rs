# Carry local KVStore action options and authenticate selected outputs before signing

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 70: The contacts manager and the key-value stores send signAction the…

Compare the linked two-token wallet-call traces with LocalKVStore.ts and completeBoundAction.ts. Go sends only Reference and Spends to SignAction, and its older lookup decodes the last output without the exact BEEF/key/signature checks. The reference forces bound-action options, authenticates each selected token, and refuses an invalid template before signing. Rust ownership and absent Go global-store/contact helpers are not defects requested here.

Witness:

- [tests/kvstore_bound_action_341_342.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/kvstore_bound_action_341_342.rs)
- [tests/kvstore_signaction_326.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/kvstore_signaction_326.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/kvstore/LocalKVStore.ts:231-305,413-425](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/kvstore/LocalKVStore.ts#L231)
- [ts-stack@edf6e03da packages/sdk/src/wallet/completeBoundAction.ts:1022-1070,1111-1151](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/completeBoundAction.ts#L1022)
- [go-sdk@2ca481c59 kvstore/local_kv_store.go:66-171,342-345,494-497](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/kvstore/local_kv_store.go#L66)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:302-309](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L302). The requested BEEF must correspond to the requested inputs before signing.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Filing route: The request concerns local wallet-call behavior, not BRC-100 integer widths or the charter's BEEF validity rules; it follows the captain's filing path.
