# Certificate DER round-trip witness (#375)

Run with Go 1.27.0 (`/opt/homebrew/bin/go`) and the local go-sdk clone at
`2ca481c5931b987a0c8f48bb341c70b7477b6b07` (v1.7.2). The committed
module has no machine-specific replacement. From the repository root:

```sh
repo="$PWD"
scratch=$(mktemp -d "$TMPDIR/certificate-der-375.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
test "$(git -C "$HOME/bsv/go-sdk" rev-parse HEAD)" = 2ca481c5931b987a0c8f48bb341c70b7477b6b07
printf 'go 1.27.0\n\nuse %s\n\nreplace github.com/bsv-blockchain/go-sdk v1.7.2 => %s\n' "$repo/tests/support/certificate_der_roundtrip_375" "$HOME/bsv/go-sdk" > "$scratch/go.work"
export GOWORK="$scratch/go.work"
cd "$repo/tests/support/certificate_der_roundtrip_375"
# If dependencies are absent from the module cache, run once:
# /opt/homebrew/bin/go mod download
/opt/homebrew/bin/go run . < ../../vectors/auth_certificate_der_roundtrip_375.json > "$scratch/run-1.json"
/opt/homebrew/bin/go run . < ../../vectors/auth_certificate_der_roundtrip_375.json > "$scratch/run-2.json"
cmp "$scratch/run-1.json" "$scratch/run-2.json"
cmp "$scratch/run-1.json" ../../vectors/auth_certificate_der_roundtrip_375.json
shasum -a 256 "$scratch/run-1.json" "$scratch/run-2.json"
```

Dependencies were already cached for this recording; `go mod download`
was not needed. Both runs and the vector have SHA-256
`22e88c0e9c9141c2cc684e38e98062d0310b53a71d047b8bf076a1458f29474d`.
The workspace's sums and temporary output stay under `$TMPDIR`. Keep
project evidence under `/Volumes/Lanes/out/bsv-rs/` when available.

The recorder reads one JSON object with a `cases` array. Each case contains
`name`, `certificate` in bsv-rs's JSON form (`type`, `serialNumber`,
`subject`, `certifier`, `revocationOutpoint`, `fields`, hex `signature`),
`unsignedBinaryHex`, and `binaryHex`. It checks Go's unsigned writer against
Rust's bytes, calls `ToWalletCertificate` then `FromWalletCertificate`,
and records both signature hex strings, verification before and after
conversion, and output binary. It checks the binary writer and adapter
agree. Optional `reference` observations pass through unchanged; the Go
recorder does not compute TypeScript verdicts.

To regenerate raw inputs, run from the repository root with
`CARGO_TARGET_DIR` outside the checkout:

```sh
cargo test --features auth --test auth_certificate_der_roundtrip_375 print_certificate_der_roundtrip_inputs_375 -- --ignored --nocapture
```

Capture the line starting `CERTIFICATE_DER_ROUNDTRIP_375_INPUT=` under
`$TMPDIR` or the evidence directory and remove the marker before passing
it to `go run .`. The test uses deterministic test scalars 42 and 69,
`Certificate::sign`, `to_binary(false)`, and the crate's JSON writer.
Case (a) is its canonical signature. Case (b) replaces S with n − S and
uses k256's DER writer, which preserves that scalar. Case (c) inserts the
BER long-form length marker before the canonical signature's computed
outer length. The malformed frame appends that generated signature to the
crate-written unsigned prefix; the normal signed writer refuses it.
No certificate or signature fixture is hand-written.

The vector's `reference` members were measured separately against an
unmodified archive of `ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9`,
bundled from `packages/sdk/mod.ts` with Bun and run on Node v22.18.0.
The reference `Certificate` constructor receives each input's JSON
members; `JSON.stringify`, `verify`, `toBinary(true)`, and
`fromBinary(binaryHex)` record the held signature, verdict, output or
error, and decoded certificate's verdict. Its unsigned writer was checked
against `unsignedBinaryHex`. The Go recorder accepts either raw generated
inputs or the complete vector with those reference observations.

Pinned adapter sites in `auth/certificates/certificate.go`:
`ToWalletCertificate` (255-290) parses at 274-280 through `ec.ParseSignature`;
`FromWalletCertificate` (293-333) writes at 319-322 through `Serialize`.
In `primitives/ec/signature.go`, `ParseSignature` (297-299) selects BER,
`ParseDERSignature` (301-305) enables stricter integer padding checks,
and `Serialize` (77-102) emits canonical DER and normalizes high S (78-82).
The adapter does not call `ToDER` (37-39), which ASN.1-encodes held scalars.

TypeScript `Certificate.ts:309-311,395-397` validates and writes/re-encodes
DER; `:425-439` verifies parsed scalars. `Signature.ts:201-247` preserves S;
`ECDSA.ts:236-239` requires 1 ≤ S < n without requiring low S.
Low-S and high-S inputs verify in both SDKs. Go returns the same low-S
bytes for both; TypeScript and bsv-rs retain the high-S bytes.
Both parsers reject case (c): Go at `signature.go:199-207` reports
`malformed signature: bad length`; TypeScript at `Signature.ts:45-51`
reports `Invalid DER entity length`. Go's adapter drops that signature,
and its unsigned output verifies false. Case (c) is a refusal control,
not the preservation claim.
