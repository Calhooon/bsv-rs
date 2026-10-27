# Fold on `lane/fix-268-certificate-json` (PR #292): the #280 witness in the certificate JSON #268 writes

Branch `lane/fix-268-certificate-json`, rebased onto beta's 70799f4 (#286 landed: `AuthMessage` carries `certificates_text` and `requested_certificates_text`, signs over them; `tests/auth_signed_text_280.rs` and `tests/vectors/auth_signed_text_280.json` with it). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, the branch's own changelog entry (#268) and `tests/support/auth_signed_text_280.mjs` with the #280 changelog entry on beta. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## Why

This branch makes the three certificate types' JSON the reference's: the keyrings maps of base64 strings (`VerifiableCertificate::new` takes `HashMap<String, String>`), the signature hex, `type` for the certificate type. #286 landed first with its witness written for the JSON before this branch: `tests/auth_signed_text_280.rs:154-158` builds the verifier keyring as `Vec<u8>` values (the test target no longer compiles on this branch: CI's clippy and test suite are red on 28d4356), and the vector's `this_crate_messages` texts carry `"keyring":{"country":[66,66,...]}` and the signature as numbers, which this branch's reader refuses. Rule 3: the vector is written by this crate's own writer and judged by the reference, never edited by hand.

## What to do

1. The test's `certificate()` helper builds the keyring values as base64 text (`to_base64(&[i as u8 + 0x40; 48])`, the same bytes), nothing else in the test changed except what the shape forces.
2. Re-record the vector's this-crate side exactly as the lane `fix-280-rerecord` did on 2e4b477 (read beta's changelog entry for #280 and the script's header): the Rust recorder emits this crate's texts in this branch's JSON, the Node script at `ts-stack@edf6e03` (bun build, Node 22; the memory: `serde_json` sorts a `Value`'s keys, so the Node script writes the vector) re-runs the reference `Peer`'s verify step on them and writes the JSON. Only `text`, `member_text` and `reference_verified_bytes` of the `this_crate_messages` entries should move; the reference's own `record` step is not re-run (its nonces are random; its recorded exchange stands). Say in the REPORT which members moved and that the verdicts are unchanged; if a verdict changed, stop and say why (that would be a finding against this branch's JSON, not the vector's).
3. The two `*_280.rs` test files and `tests/auth_certificate_json_268.rs` green; the RED claim of the #280 lane still holds on a scratch copy without `src/auth/types.rs`'s signed-text change (its own `CARGO_TARGET_DIR`).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_*`, `socketio_*`, `identity_*`, `wire_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`. One commit: "tests: the #280 witness and vector in the certificate JSON #268 writes (#268)".

## Report

A REPORT: base and tip, the vector diff's summary, the gate's results, anything unverified.
