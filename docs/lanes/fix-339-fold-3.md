# #339 fold three: the second re-review's finding and notes on `lane/fix-339-review-actions-body` (at 7faba87 on 1cdd149)

Work in this worktree on the branch as it stands (seven commits; the second fold re-reviewed on Opus: FIX, one finding, four notes; the REPORT is in `cca runs --show review-339-fold-2` on this box). Read `src/wallet/substrates/CLAUDE.md`, `tests/CLAUDE.md`, the branch's changelog entry. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL; every HTTP test binds its own wiremock server.

## The re-review's finding

- F1 `src/wallet/substrates/http_json.rs:239-245`: the success path now builds a `serde_json::Value` tree for every createAction and signAction answer to normalize `tx`: 48 MB peak for a 1 MiB `tx` (native, measured) where it was 1 MB. Try `serde_json::from_slice::<R>` on the bytes first and normalize through the `Value` reading only when that fails (the object form, a `1.0` byte), so the common answer costs what it cost; pin the cost with a test that measures the allocation on a 1 MiB `tx` in the array form (the crate's memory tests' form, `tests/memory_*` or a `dhat` witness if the crate keeps one: read `tests/CLAUDE.md`) or, failing a cheap measurement, a test that the array form never enters the normalizing path (a counter or a tracing sink the crate already has).

## The re-review's notes

- N1 `CHANGELOG.md:350-351`: "no `code`" holds for the base `toJson` only; codes 5 to 8 are set at `WERR_errors.ts:110`, `:136`, `:229`, `:282` (`ts-stack@edf6e03`): say it as it is.
- N2 `CHANGELOG.md:369-373`: cite #365 for the other byte fields.
- N3 `http_json.rs:245`: the malformed-answer words changed by the second fold; state the new words in the entry (and the parity note if the reference's differ).
- N4 `src/wallet/review_actions.rs:31-37`: the semver note (a major from the branch's earlier commits, the migration at `CHANGELOG.md:274`): the two sentences agree.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `wallet_*`, `wire_*`, `identity_*`, `transport_fault_*`, `memory_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib wallet`; `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1cdd149`; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit, the fast path and the measured cost before and after on the 1 MiB `tx`, the notes applied, RED then green, the gate's results, anything unverified.
