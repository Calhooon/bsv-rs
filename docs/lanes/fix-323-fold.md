# #323 fold: the cold review's three items on `lane/fix-323-http-substrate-originator` (at e14838a5)

Work in this worktree on the branch as it stands (one commit on beta's 5f3fa1ab; beta has moved since: do not rebase, the sequencer does). Read `CLAUDE.md`, `src/wallet/substrates/CLAUDE.md`, `tests/CLAUDE.md`, the branch's changelog entry, and the review's findings below. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The review's findings (Fable, verdict FIX, three items; the code otherwise merge-ready)

1. `src/wallet/validation/originator.rs:33` trims with Rust's white-space set where the reference's `validateOriginator` uses JavaScript's `trim` (`validationHelpers.ts:1005` at `edf6e03`): use `trim_js` from `src/wallet/substrates/origin.rs:56` (one helper for both), and pin the two edges where the sets differ, U+FEFF and U+0085 (JavaScript trims U+FEFF and not U+0085; Rust's `trim` the other way round: verify both against the reference's `String.prototype.trim` under Node 22 and pin what you measured).
2. `src/wallet/substrates/http_wire.rs:130`'s 256 MiB frame bound has no test: add one with a mock server, a frame of 256 MiB + 1 zeroed bytes refused before any request (the review measured 6 µs: the bound is checked on the length, not by building the frame; keep it so, and say in the test's name that it refuses before allocation, rule 5).
3. The changelog's migration line: `WalletClient`'s auto-detection (`src/wallet/client.rs:186-208`) with a `None` originator now lands on the wire substrate, not the JSON one, since the JSON call is refused with none configured: say so in the migration line.

Hermetic rule (rule 4, from the review): a MetaNet Client listens on 3301, 3321 and 2121 on this host, so any test that uses a default base URL hits a live wallet; every test in this branch binds its own wiremock server and names its URL.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `wallet_*`, `transport_fault_*`; `--lib wallet`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit (one per item or one for all three), the trim edges measured under Node 22 and pinned, the frame-bound test's timing, the migration line's new sentence, the gate's results, anything unverified.
