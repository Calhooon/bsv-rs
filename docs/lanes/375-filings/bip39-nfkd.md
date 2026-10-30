# Normalize BIP-39 phrase and passphrase with NFKD

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 37: A BIP-39 phrase is read in NFKD (Unreleased, bsv-rs#163): from_phrase_with_language…

Read the NFC French/Spanish/Korean phrase emitted by the Rust writer and compare its decomposed equivalent. Also compare NFC and NFD passphrases for one mnemonic, and the published Japanese vectors. Go hashes raw phrase/password bytes at bip39.go:256-257 and compares raw word bytes; BIP-39 requires NFKD before lookup/seed derivation.

Witness:

- [tests/compat_bip39_nfkd.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/compat_bip39_nfkd.rs)
- [tests/vectors/bip39_japanese.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/bip39_japanese.json)

Pinned reference reading:

- [go-sdk@2ca481c59 compat/bip39/bip39.go:256-257](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/bip39/bip39.go#L256)
- [ts-stack@edf6e03da packages/sdk/src/compat/Mnemonic.ts:425,426](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/Mnemonic.ts#L425)

BRC reading: No BRC defines this compatibility format or its limits; this is an SDK parity request.

Additional standard: [BIP-39, NFKD wordlist and phrase/passphrase normalization](https://github.com/bitcoin/bips/blob/100ba872/bip-0039.mediawiki), lines 86-87 and 94-96 at the recorded pin; the Rust tests carry the published vectors.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
