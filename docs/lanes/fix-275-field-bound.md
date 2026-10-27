# #275: the certificate's 1 MiB field value bound on write and read

Branch `lane/fix-275-field-bound` from beta's tip (after #274, which made `Certificate.fields` a `HashMap<String, String>` of base64 text, and after the #262 fold that moved `certificate.rs`'s tests to `certificate_tests.rs`). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #275, from the cold review of #261's type fold)

The reference bounds a certificate field value at 1 MiB: `ts-stack@edf6e03` `packages/sdk/src/auth/certificates/Certificate.ts:27` (`MAX_ENCRYPTED_CERTIFICATE_FIELD_BYTES`), `:76-79` (the snapshot of the fields for writing refuses a longer value), `:377-381` (the reader refuses one). This crate's `Certificate::set_field`, `to_binary` and `from_binary` (`src/auth/certificates/certificate.rs`) bound nothing beyond the reader's remaining bytes. The BRC-100 wire writer's bound landed separately (#246, `src/wallet/wire/encoding.rs`, "Certificate field <name> exceeds the maximum of 1048576 bytes"); the wire reader's (#189) is in `src/wallet/wire/`. Read all three sites before you write, so the four refusals carry one text where the reference has one.

The toolbox's captain filed its own reading of the same sites as bsv-wallet-toolbox-rs #223 (the reference's field caps and canonical base64): read it (`gh issue view 223 -R Calhooon/bsv-wallet-toolbox-rs`) before you write, and if the reference also refuses a field value that is not canonical base64 (a value that decodes and re-encodes to different text), say at which site and conform in the same lane, stated in the changelog; if it does not, say so in the REPORT.

## What to do

1. Read the reference's three sites and say in the commit message what each measures (the base64 text's length, or the decoded bytes') and which word it uses. Conform: the same measure, the same words (rule 1). If the reference measures the text and the wire measures the bytes, that is two bounds, each at its own site, stated.
2. The write side: `to_binary` (through whatever snapshot `sign` takes) refuses a field value over the bound with the reference's words, before any allocation it would need (rule 5). Decide, by the reference, whether `set_field` refuses at insertion or the writer refuses at write; the reference's site decides.
3. The read side: `from_binary` refuses a field value length over the bound before allocating it (`primitives::bounded_capacity` is the pattern), with the reader's words; `verify` of a received certificate never sees an unbounded field.
4. Tests, RED before green (rule 2; a scratch copy with the fix removed, its own `CARGO_TARGET_DIR`): a value of exactly the bound accepted on both sides; one byte over refused on both with the words pinned; the frame built by this crate's writer with the bound bypassed (a test-only path or a hand-built frame) refused by the reader; the existing #249 and #261 vectors unchanged (`git diff -- tests/vectors` empty). Name the finding in each test's name.
5. `tests/arch_no_unwrap.rs` and the ratchet (`docs/ratchets.json`, certificate.rs under 800 lines, never re-recorded) stay green; if the file is over, move code to a sibling file as a real move, never a reshape.
6. The changelog entry under `[Unreleased]` (what changed, why it was wrong, which test pins it, the parity note), the rows in `src/auth/certificates/CLAUDE.md` and `tests/CLAUDE.md`.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_certificate_*`, `wire_*`, `identity_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo fuzz run fuzz_auth_messages -- -max_total_time=120` on a copy of the corpus (the certificate reader is reached through it; say the run count and crashes).

## Report

A REPORT: base and tip shas, each commit, the reference's three measures and words, RED counts then green, the gate's results, anything unverified.
