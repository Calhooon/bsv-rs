# #367: the ARC default arch test reads a CRLF checkout as it reads LF

Branch `lane/fix-367-arch-crlf` from beta's tip. Read `tests/CLAUDE.md` (the arch tests' rows), `tests/arch_arc_deprecated.rs`, `tests/arch_support/mod.rs` (the shared reader, if the arch tests share one), and issue #367. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding

`no_live_policy_default_chooses_the_arc_policy_url` (`tests/arch_arc_deprecated.rs:91`) finds each `impl Default` block's end with `find("\\n}\\n")`; on the Windows cells (a CRLF checkout) the file holds `\\r\\n}\\r\\n`, so the `expect` panics: run 40513515368's two Windows cells. The Linux cell passes.

## What to do

1. The test normalizes what it reads (`\\r\\n` to `\\n`) before any search, through the arch tests' shared reader if there is one (then every arch test gains it; say which tests searched raw before); a unit of the test feeds a CRLF string through the same search and passes, RED before the fix (the search on a CRLF string fails) and green after.
2. Grep every test under `tests/` for other LF-only searches of source text (`"\\n}\\n"`, `"\\n\\n"`, `ends_with("\\n")` on a file read) and fix the same way, naming each in the REPORT.
3. The row in `tests/CLAUDE.md`; a changelog line under `[Unreleased]` naming the Windows cells.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `arch_*` (not the `arch_support` module), `fixtures_replay`; the doc tests; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, the commit, the searches normalized, RED then green on the CRLF string, the gate's results, anything unverified.
