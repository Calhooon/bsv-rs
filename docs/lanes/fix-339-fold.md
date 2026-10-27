# #339 fold: the cold review's finding and note on `lane/fix-339-review-actions-body` (at 16061a0 on 6707363)

Work in this worktree on the branch as it stands (three commits; reviewed on Opus: FIX, one code finding, one changelog note; the review's REPORT is in `cca runs --show review-339` on this box). Read `src/wallet/substrates/CLAUDE.md`, `tests/CLAUDE.md`, the branch's changelog entry. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL; every HTTP test binds its own wiremock server.

## The review's findings

1. `src/wallet/substrates/http_json/review_actions.rs:182` (`byte_array`, used at `:294` and `:496`) refuses the reference's old object form of `tx` and `competingBeef` (an object of index keys to byte numbers), which `HTTPWalletJSON` accepts, normalized in `BRC100ByteEncoding.ts` (`ts-stack@edf6e03`: read the function and its rule for the object form, the key order, the bounds); the review confirmed it by running the reference on two probe bodies. Read the object form as the reference does; add the two probe bodies (the review's: an object-form `tx`, an object-form `competingBeef`) to the recorder `tests/support/wallet_http_json_review_actions_339.mjs` and re-record the vector (39 cases, byte for byte on a rerun; the recorder never hand-edited), with the test reading them.
2. `review_actions.rs:93`: a 400 body with no code, with `"5"` or with `5.5` gets the class refusal here where the reference's words say "envelope": name the difference in the parity paragraph (`CHANGELOG.md:80`) as a stated divergence, or conform the words if the reference's text is one sentence to take (read `HTTPWalletJSON.ts:199-241`'s words for each and say which).
3. Rebase onto `origin/beta` (1cdd149 or later: #326 and #350 landed since; the review found five docs conflicts that resolve cleanly: keep both sides, no heading split, no line lost; diff the result against beta's CHANGELOG and show only #339's own sections added), then re-gate.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `wallet_*`, `wire_*`, `identity_*`, `transport_fault_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib wallet`; `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <origin/beta's sha>` (the unreleased struct's fields named, as before; CI's check against the tag the record); the ratchet against `origin/beta`.

## Report

A REPORT: the base rebased onto, the tip, each commit, the object form's rule as read, the two probe bodies and the reference's verdicts, the envelope decision, RED then green for the new cases, the gate's results, anything unverified.
