keeper's word first

# A certificate whose revocationOutpoint is a bare txid, the TypeScript issuer's default, cannot be read from JSON by go-sdk

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "A certificate's field value is its base64 text" (#261, #268; "A `revocationOutpoint` of the txid alone, the reference's default issuance's (`MasterCertificate.ts:442`), reads as index 0 as the reference reads it, where Go refuses it"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `certificate-txid-only-outpoint.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A certificate issued by the TypeScript `MasterCertificate.issueCertificateForSubject` without a revocation callback carries `revocationOutpoint: "00…00"` (64 hex digits, no `.index`), which the reference writes and verifies as index 0. go-sdk's `Outpoint.UnmarshalJSON` refuses any string shorter than 66 characters, so a go-sdk peer or overlay receiving that certificate in a Peer certificateResponse or a token's JSON fails to parse it, and the certificate is lost to the exchange.

```go
func OutpointFromString(s string) (*Outpoint, error) {
	if len(s) < 66 {
		return nil, fmt.Errorf("invalid-string")
	}
```

```ts
getRevocationOutpoint = async (_serial: string): Promise<string> => '00'.repeat(32),
...
// MasterCertificate historically uses a txid-only zero outpoint placeholder.
const [txid, outputIndex = '0'] = outpointParts
```

Steps to reproduce (go-sdk read from the code at 2ca481c, not run): unmarshal a certificate JSON whose `revocationOutpoint` is `"0000000000000000000000000000000000000000000000000000000000000000"` into `certificates.Certificate`; `json.Unmarshal` returns `invalid-string`. The reference's `Certificate.toBinary` writes it as txid zero, index 0, and `verify` checks the signature over those bytes.

Expected: a bare 64-hex txid read as index 0, as the reference's writer reads it (or, if go-sdk prefers to refuse it, the reference's issuer asked to write `.0`; the two SDKs should read the default certificate the same way).

Actual: refused.

bsv-rs reads the bare txid as index 0 (#268).

Witness:

- [tests/auth_certificate_json_268.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/auth_certificate_json_268.rs) (`the_reference_default_txid_alone_revocation_outpoint_reads_as_index_zero`, `an_auth_message_carrying_the_reference_default_revocation_outpoint_is_read`, `a_wallet_certificate_with_a_txid_alone_revocation_outpoint_verifies`)

Pinned reference reading:

- [go-sdk@2ca481c59 transaction/outpoint.go:48-66](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/outpoint.go#L48-L66) (`OutpointFromString`) and [:84-95](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/outpoint.go#L84-L95) (`UnmarshalJSON` through it); [auth/certificates/certificate.go:46](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/certificates/certificate.go#L46) (the certificate's field)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/auth/certificates/MasterCertificate.ts:437-444](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/MasterCertificate.ts#L437-L444) (the default) and [Certificate.ts:255-270](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/Certificate.ts#L255-L270) (the txid alone read as index 0).

Existing related filing(s): go-sdk #317 (E-Jacko's, open: TS-signed certificates failing Go's `Verify`, cause not identified there) and #368 (codenlighten's, open: mixed-case field names) are other cross-SDK certificate failures; #388 (ours, open) is the field order. None names the outpoint text. Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: read a revocation outpoint of a bare 64-hex txid as index 0, as the reference's certificate writer does.

Evidence status: go-sdk and the reference source-read at the pins, not run here; the Rust tests pin the reference's reading. This draft contains no private-key literal.
