# Fold on `lane/fix-268-certificate-json` (PR #292): certificate.rs's JSON serde into its own file

Branch `lane/fix-268-certificate-json`, rebased past #274 onto beta. Read `CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## Why

The ratchet (`docs/ratchets.json`, `files_over_800`) holds `src/auth/certificates/certificate.rs` under 800 lines and does not record it; the branch's JSON work (the reference's `type`, the hex signature, the outpoint always a string, the txid-alone reading, the serde `impl`s and their helpers) has it at 940. A reshape that dodges a counter is a finding (never re-record the baseline); a real move passes. The #262 fold (PR #281, landing soon) moves the inline `mod tests` of the same file to `certificate_tests.rs`; this fold must not touch the test module (so the rebase over #281 stays clean) and must bring the file under 800 on its own.

## The move

Move the certificate's JSON serde out of `certificate.rs` into `src/auth/certificates/certificate_json.rs`: the `Serialize` and `Deserialize` impls (or the serde helper types and `with`/`serialize_with` functions the derive names), the outpoint's string reading and writing, the signature's hex, the sentinel, and every private helper only the JSON uses. A trait impl lives in any module of the crate, so the move is `mod certificate_json;` in `mod.rs` (private; `pub(super)` or `pub(crate)` only where the derive or the tests need it) and the bytes moved verbatim: no reading changes, no name changes, no test changes. The module's `//!` line says what it holds and cites the reference sites the entry cites. If a test under `mod tests` in `certificate.rs` reaches a moved private item through `super::`, give that item `pub(super)` rather than moving the test. `wc -l` before and after in the commit message; the file under 800 with headroom for #281's rebase, and `docs/ratchets.json` untouched.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib auth::certificates`; every test file matching `auth_certificate_*`, `identity_*`, `wire_*`, `wallet_http_*`, `arch_*` (not the `arch_support` module); the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet `tools/ratchet/run --check --against origin/beta` passes. One commit: "auth: certificate.rs's JSON serde in its own file (#268)".

## Report

A REPORT: the two line counts, what moved (the items by name), the gate's results, anything the move could not keep verbatim.
