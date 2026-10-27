# #301: Certificate::to_binary and from_binary carry the reference's 16 MiB frame and 72-byte signature bounds

Branch `lane/fix-301-frame-signature-bounds` from beta's tip, after #297 has landed (read #275's and #297's changelog entries: the 1 MiB field value bound through one function at four sites, the constructor's checks, the keyring and plaintext bounds, the decrypt wrappers). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #301, from the #297 lane's parity note)

The reference's `Certificate.toBinary` refuses a frame over 16 MiB (`ts-stack@edf6e03` `Certificate.ts:315-319`, "Certificate binary exceeds the maximum of 16777216 bytes") and its reader refuses one (`snapshotCertificateBinary`, `:87-91`, "Certificate binary must be a byte array of at most 16777216 bytes"); the reference also bounds the DER signature at 72 bytes (find the site in `Certificate.ts` and name it). The BRC-100 wire writer and reader carry both (#189, #246, `src/wallet/wire/`); `Certificate::to_binary` and `from_binary` do not.

## What to do

1. Read the reference's sites in full and Go's (`go-sdk@2ca481c` `auth/certificates/certificate.go`; name the lines), and conform on the type: `to_binary` refuses the frame bound after it has the bytes' length and before it returns (the reference's point), `from_binary` refuses a frame over the bound before it reads (the reader's words), the signature bound at the reference's site on write and on read, each in the reference's words, in the error class #275 and #297 use; the wire's writer and reader keep their own checks (say whether the texts are now one function's).
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): a frame at exactly 16 MiB accepted on write and read, one byte over refused on both, in the words; a 72-byte DER signature accepted, a 73-byte one refused on write and read; the reference's verdicts on the same recorded by a Node script at `edf6e03` (bun build, Node 22) into a vector and compared; the #249, #251, #261, #262, #268, #275, #297 vectors unchanged. A 16 MiB frame in a test is built once and reused; keep the test under the suite's time (say its wall time).
3. The changelog entry under `[Unreleased]`; the parity note of #297 updated (the two bounds no longer unported); the divergence line of #275 updated the same way; the rows in `src/auth/certificates/CLAUDE.md` and `tests/CLAUDE.md`; the ratchet (a real move if a file crosses its bound).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_certificate_*`, `wire_*`, `identity_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet; `cargo fuzz run fuzz_auth_messages -- -max_total_time=60` on a corpus copy.

## Report

A REPORT: base and tip, each commit, the reference's and Go's sites and words, RED counts then green, the gate's results and the big test's wall time, anything unverified.
