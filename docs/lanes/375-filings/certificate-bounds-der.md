# Certificate wallet conversion rewrites valid high-S signature bytes

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created.
Census row 60's DER-preservation claim only.

A signed certificate's valid high-S DER signature changes to low-S DER
through go-sdk's certificate adapter, where the pinned TypeScript reference
and bsv-rs preserve those signature bytes. The signature still verifies;
the interoperability defect is that the round trip changes the certificate's
serialized representation.

The witness uses one certificate signed by bsv-rs with deterministic test
keys. Case (a) is canonical low-S DER. Case (b) replaces S with n − S and
re-encodes DER over the same signed digest. Go verifies both inputs and
both adapter outputs, but writes case (a)'s signature for both:

| Case | Input signature hex (ends abbreviated) | Go output | TypeScript / bsv-rs |
|---|---|---|---|
| (a) low S | `30440220…b8d76d91` | unchanged | unchanged, verifies |
| (b) high S | `30450220…175ed3b0` | `30440220…b8d76d91` | unchanged, verifies |

Case (c), a non-minimal BER outer sequence length (`30 81 …`), is a refusal
control. Go rejects it at `signature.go:199-207`; the reference rejects it
at `Signature.ts:45-51`. It is not evidence of an accepted encoding that
must be preserved.

Witness:

- [Rust test](../../../tests/auth_certificate_der_roundtrip_375.rs): rebuilds
  all inputs with the crate's writer, pins JSON and accepted wire byte
  preservation, both SDKs' verdicts, and Go's measured outputs.
- [Recorded vector](../../../tests/vectors/auth_certificate_der_roundtrip_375.json):
  complete certificate JSON, binary input, both signature hex strings and verdicts.
- [Go recorder](../../../tests/support/certificate_der_roundtrip_375/main.go)
  and [run instructions](../../../tests/support/certificate_der_roundtrip_375/README.md):
  Go 1.27.0, go-sdk v1.7.2; two byte-identical runs, SHA-256
  `22e88c0e9c9141c2cc684e38e98062d0310b53a71d047b8bf076a1458f29474d`.

Pinned reference reading, also executed on these inputs under Node v22.18.0:

- [ts-stack@edf6e03 Certificate.ts:309-311](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/Certificate.ts#L309)
  parses DER and writes the given bytes. At 395-397 `fromBinary`
  re-encodes through `Signature.toString`, preserving these canonical
  high-S and low-S encodings. At 425-439 `verify` checks the parsed
  signature and returns false on parsing failure.
- [Signature.ts:201-247](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/Signature.ts#L201)
  encodes the held R and S without low-S normalization;
  [ECDSA.ts:236-239](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/ECDSA.ts#L236)
  accepts either S form within 1 ≤ S < n.

Pinned Go reading at `2ca481c5931b987a0c8f48bb341c70b7477b6b07`:

- [auth/certificates/certificate.go:255-290](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/certificates/certificate.go#L255):
  `ToWalletCertificate` parses at 274-280 with `ec.ParseSignature`.
- [certificate.go:293-333](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/certificates/certificate.go#L293):
  `FromWalletCertificate` serializes at 319-322 with `Signature.Serialize`.
  `ToBinary` at 114-125 also passes through the parsed wallet representation.
- [primitives/ec/signature.go:77-102](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/primitives/ec/signature.go#L77):
  `Serialize` replaces high S with n − S at 78-82 and emits canonical DER.
  `ParseSignature` at 297-299 uses the BER parser;
  `ParseDERSignature` at 301-305 enables stricter integer padding checks.
  `ToDER` at 37-39 uses ASN.1 encoding without that low-S normalization,
  but is not the adapter's write path.

BRC reading: [BRCs@5119a9b BRC-52:93,103](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0052.md#L93)
specifies DER signature bytes and recommends retaining the original
unsigned prefix and signature bytes while refusing malformed inputs.
It does not require low S. [BRC-53:13-15](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0053.md#L13)
defers current certificate behavior to BRC-52/100; it adds no low-S rule.

Requested maintainer action: preserve an accepted certificate's original
DER signature bytes across wallet conversion and binary serialization.
Keep parsed scalars available for verification without substituting
`Serialize()`'s normalized bytes. Add the valid high-S round-trip regression
above while retaining malformed-signature rejection.
