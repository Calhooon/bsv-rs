# Bound inbound and outbound authentication certificate lists

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 25: The Peer's intake and certificate paths (#445): all required nonces…

A 101-certificate response must be refused before validating/decrypting entries; 100 remains permitted. The linked fixture records sender and receiver bounds and the empty/missing-policy cases. Go maps/loops through the list without the reference maximum; its lower-case diagnostics are not the requested fix.

Witness:

- [tests/auth_peer_certificate_paths_445.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_peer_certificate_paths_445.rs)
- [tests/vectors/auth_peer_certificate_paths_445.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_peer_certificate_paths_445.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/AuthMessageValidation.ts:348-389](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/AuthMessageValidation.ts#L348)
- [ts-stack@edf6e03da packages/sdk/src/auth/utils/validateCertificates.ts:80-136](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/utils/validateCertificates.ts#L80)
- [go-sdk@2ca481c59 auth/peer.go:689-720,935-966](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L689)
- [go-sdk@2ca481c59 auth/utils/validate_certificates.go:143-145](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/utils/validate_certificates.go#L143)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:145-172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L145). The certificate message schema is specified here; 100 is the SDK reference limit, not a number imposed by this BRC.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
