# #305: the certificate signature's DER, parsed and re-encoded on the type as the reference does

Branch `lane/fix-305-der-reencode` from beta's tip, after #299 and #301 have landed (both touch `Certificate::verify`, `to_binary` and `from_binary`; read their changelog entries). Read `CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #305, from the #301 lane)

The reference's `Certificate.toBinary` and `fromBinary` round the signature through `Signature.fromDER` / `toDER` (`ts-stack@edf6e03` `Certificate.ts`: name the lines), so a malformed DER is refused at parse and a non-canonical encoding does not survive a round trip; this crate carries the signature bytes as given on the type (the BRC-100 wire checks the DER form, `certificate_signature_der`, #189). `received_unsigned` (#249) binds the unsigned prefix, not the signature.

## What to do

1. Read the reference's sites in full (`Certificate.ts`: the constructor, `fromBinary`, `toBinary`, `sign`, `verify`; `Signature.fromDER`/`toDER` in `primitives`) and Go's (`go-sdk@2ca481c` `auth/certificates/certificate.go`, `primitives/ec/signature.go`; name the lines): where the DER is parsed, what a malformed one does (thrown where, with which words), what a non-canonical one becomes (re-encoded on write? kept?), and whether `verify` on a non-canonical DER answers `false` or verifies the re-encoded form. Conform at the same sites, in the same words, in the error class #297 and #301 use; the wire's `certificate_signature_der` stays (say whether the two now share one function).
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): a canonical DER signature round-trips unchanged; a non-canonical DER (a leading zero on `r` the reference strips, or an over-long length) does what the reference does on `from_binary`, `to_binary` and `verify`; a malformed DER is refused at the reference's site in its words; the reference's verdicts on the same recorded by a Node script at `edf6e03` (bun build, Node 22) into a vector and compared; the older vectors unchanged (#249's "received bytes kept" witnesses in particular: say why each still holds).
3. The changelog entry under `[Unreleased]` with the parity note (Go's reading); the rows in `src/auth/certificates/CLAUDE.md` and `tests/CLAUDE.md`; the divergence list if a difference remains; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_certificate_*`, `wire_*`, `identity_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet; `cargo fuzz run fuzz_auth_messages -- -max_total_time=60` on a corpus copy.

## Report

A REPORT: base and tip, each commit, the reference's and Go's sites and words, RED counts then green, the gate's results, anything unverified.
