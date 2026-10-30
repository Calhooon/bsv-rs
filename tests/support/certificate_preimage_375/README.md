# Certificate-response preimage witness (#375)

The input certificate, encrypted fields/keyring and response come from
`tests/auth_certificate_preimage_375.rs`: `Certificate::sign`,
`SymmetricKey::encrypt_with_iv` and the real `Peer::send_certificate_response`.
Private scalars 42 (sender), 69 (receiver), 23 (certifier), field keys and IVs
are **deterministic test keys/data**, never production secrets. Peer nonces
are generated normally; re-running the Rust input generator makes fresh
response signatures. Replaying one saved input is byte-stable.

Use Node 22.18.0 from nvm and Go 1.27.0 on the PATH; `TS_STACK` and `GO_SDK` name the reference clones (default: siblings of this repository), archived at their pins, never their moving checkouts. The Node recorder runs the
`JSON.stringify(message.certificates)` / `ProtoWallet.verifySignature`
steps of `Peer.processCertificateResponse` at `Peer.ts:1203-1213`.
The Go recorder uses the actual `auth.AuthMessage` and certificate types,
`json.Marshal(message.Certificates)` and `ProtoWallet.VerifySignature`
from `Peer.handleCertificateResponse` at `auth/peer.go:898-926`;
the wallet implementation is `wallet/proto_wallet.go:224-280`.
Neither recorder runs a handshake or the SDKs' differing nonce checks.
Rust's test additionally accepts each recorded message through the full
receiving Peer, and Node checks certificate verification and field decryption.
Go independently checks each certificate's signature. No network or port.

Build the unmodified reference from a git archive, never its moving checkout:

```sh
repo="$PWD"
scratch=$(mktemp -d "$TMPDIR/certificate-preimage-375.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/reference" "$scratch/go-recorder" "$scratch/go-cache" "$scratch/go-build"
git -C "${TS_STACK:-../ts-stack}" archive edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk | tar -x -C "$scratch/reference"
bun build "$scratch/reference/packages/sdk/mod.ts" --target node --format esm --outfile "$scratch/sdk.mjs"
. "$HOME/.nvm/nvm.sh"
nvm use 22.18.0
cp tests/support/certificate_preimage_375/go.mod tests/support/certificate_preimage_375/main.go "$scratch/go-recorder/"
mkdir -p "$scratch/go-sdk" && git -C "${GO_SDK:-../go-sdk}" archive 2ca481c5931b987a0c8f48bb341c70b7477b6b07 | tar -x -C "$scratch/go-sdk"
printf 'go 1.27.0\n\nuse %s\n\nreplace github.com/bsv-blockchain/go-sdk v1.7.2 => %s\n' "$scratch/go-recorder" "$scratch/go-sdk" > "$scratch/go.work"
export GOWORK="$scratch/go.work"
export GOCACHE="$scratch/go-cache" GOTMPDIR="$scratch/go-build"
# Only if a dependency is missing from the module cache, run once in
# "$scratch/go-recorder": go mod download
for run in 1 2; do
  node "$repo/tests/support/certificate_preimage_375.mjs" "$scratch/sdk.mjs" "$repo/tests/vectors/auth_certificate_preimage_375.json" "$scratch/node-$run.json"
  (cd "$scratch/go-recorder" && go run . < "$scratch/node-$run.json" > "$scratch/go-$run.json")
done
cmp "$scratch/node-1.json" "$scratch/node-2.json"
cmp "$scratch/go-1.json" "$scratch/go-2.json"
cmp "$scratch/go-1.json" tests/vectors/auth_certificate_preimage_375.json
shasum -a 256 "$scratch/node-1.json" "$scratch/node-2.json" "$scratch/go-1.json" "$scratch/go-2.json"
```

To generate fresh input, archive this commit into a directory under
`$TMPDIR`, give that copy its own external `CARGO_TARGET_DIR`, and run
`cargo test --features full,http --test auth_certificate_preimage_375
print_certificate_preimage_inputs_375 -- --ignored --nocapture`.
Extract the JSON after `CERTIFICATE_PREIMAGE_375_INPUT=` and supply that file
to the Node recorder, then the Node output to Go. The final Go output is
the vector; never hand-edit its certificate, signed text or observations.
