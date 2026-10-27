# #294: validate_requested_certificate_set refuses a certificate type ID that is not 32-byte base64

Branch `lane/fix-294-type-id-form` from beta's tip, after #288 has landed (`RequestedCertificateSet.types` an insertion-ordered map; read its changelog entry and parity note). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #294, from the #288 lane)

The reference's `validateRequestedCertificateSet` refuses a certificate type ID that is not 32 bytes of base64 (`ts-stack@edf6e03` `packages/sdk/src/auth/utils/AuthMessageValidation.ts:144`; read the whole function and the message it throws); this crate's `validate_requested_certificate_set` (`src/auth/utils/validation.rs`) accepts any string as a type key. A reference peer refuses a certificateRequest this crate would send with a malformed type ID; this crate accepts the same request from a peer. The #288 parity note's one remaining divergence (a JavaScript object moves an integer-like key ahead of the others) rests on this: the reference never signs such a policy because `:144` refuses the ID first.

## What to do

1. Read the reference's function in full and Go's equivalent (`~/bsv/go-sdk`, `auth/utils/...`: name the file and lines) and conform: the same check (32 bytes after base64 decoding; say whether the reference also refuses padding or whitespace variants and do the same), the reference's words in the refusal, in the error class the crate's other `validate_requested_certificate_set` refusals use.
2. Where else the same ID enters: `add_type`, the wire's `requestedCertificates` reader (`src/wallet/wire/`), the identity and certificate paths that take a type ID. Refuse at the validator the reference refuses at; do not add refusals where the reference has none; list what you read in the REPORT.
3. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): a 31-byte ID, a 33-byte ID, a non-base64 string, an integer-like key (`"42"`), each refused in the reference's words; a 32-byte ID accepted; the reference's verdict on the same four recorded by a Node script at `edf6e03` (bun build, Node 22) into a vector and compared. Name the finding in each test's name.
4. The #288 parity note: the divergence closes (neither side signs an integer-like key); say so there and in the changelog entry under `[Unreleased]`; the rows in `src/auth/CLAUDE.md` and `tests/CLAUDE.md`.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_*`, `socketio_*`, `wire_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo fuzz run fuzz_auth_messages -- -max_total_time=120` on a corpus copy.

## Report

A REPORT: base and tip, each commit, the reference's and Go's sites and words, RED counts then green, the gate's results, anything unverified.
