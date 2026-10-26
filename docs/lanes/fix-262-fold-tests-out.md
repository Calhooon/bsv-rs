# Fold on `lane/fix-262-sign-refusal` (PR #281): certificate.rs's inline test module into its own file

Branch `lane/fix-262-sign-refusal`, rebased onto beta's tip. Read `CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## Why

The ratchet (`docs/ratchets.json`, `files_over_800`) holds `src/auth/certificates/certificate.rs` at 800 lines. The branch's one commit (the `sign` refusal of a signed certificate, `Certificate.ts:450-453`) and the landed #261 put it over. A reshape that dodges a counter is a finding (never re-record the baseline); a real move passes.

## The move

Move the inline `#[cfg(test)] mod tests { ... }` at the end of `src/auth/certificates/certificate.rs` into `src/auth/certificates/certificate_tests.rs`, opening with `#![cfg(test)]` on line 1 (the arch scanner `tests/arch_support/mod.rs` reads the file-wide gate, not the `mod` line: `tests/arch_no_unwrap.rs` counts an ungated file's unwraps as production), then a `//!` line naming what it holds, then `use super::*;` as the inline module had. Include it from certificate.rs with

```
#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
```

so every `super::` path and every test name stays as it was. Move the bytes; change no test, no assertion, no name. If a test needed an item that was `pub(super)` or private, the inline module reached it through `super::*` and the `#[path]` module does the same.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib auth::certificates`; every test file matching `auth_certificate_*` and `arch_*` (not the `arch_support` module); the ratchet passes with certificate.rs under 800 lines and `docs/ratchets.json` untouched; `wc -l` before and after in the commit message. One commit: "auth: certificate.rs's inline tests in their own file (#262)".

## Report

A REPORT: the two line counts, the gate's results, anything the move could not keep verbatim.
