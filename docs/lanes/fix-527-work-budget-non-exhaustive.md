Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #527: `transaction::WorkBudget` is `#[non_exhaustive]` with a constructor and the two field setters (the keeper's word, 2026-10-30 20:1xZ; milestone 0.9.0-beta.5; label api-break)

Branch `lane/fix-527-work-budget-non-exhaustive` from `origin/beta` (`77cccd70`, where #519 landed). One commit. Never push.

## The finding

`src/transaction/work_budget.rs:11-17`: `WorkBudget { per_input: Option<u64>, per_transaction: Option<u64> }` derives `Default` and has two `pub` fields, so a downstream builds it with a literal (`tests/transaction_work_budget_519.rs:433` does; the toolbox has one). A third bound later would cost every consumer a major. The struct is in no published prerelease (v0.9.0-beta.4 is `56d12075`, below #519), so the break is free now.

## The shape (the keeper's; do not widen it)

1. `#[non_exhaustive]` on `pub struct WorkBudget`; the two fields stay `pub` (reading and `..` destructuring keep working outside the crate; a literal no longer builds there).
2. `pub const fn new() -> Self` (both bounds `None`); `Default` stays derived and equals `new()`. The internal `pub(super) const NONE` becomes `Self::new()` or stays, your call, one definition.
3. The two field setters, `const`, `#[must_use]`: `pub const fn with_per_input(self, limit: Option<u64>) -> Self` and `pub const fn with_per_transaction(self, limit: Option<u64>) -> Self`. They REPLACE the struct's `with_work_budget` and `with_transaction_work_budget` (`work_budget.rs:22,28`): remove those two from `WorkBudget`, no aliases. The verifier builders of those names (on the stream verifier's builders and `Transaction::verify_*`, #519) are NOT touched: grep `with_work_budget\|with_transaction_work_budget` under `src`, `tests`, `examples`, `README.md`, `docs` and leave every site that is a verifier builder; change every site that calls them on a `WorkBudget` value.
4. Nothing else changes: no new bound, no behaviour change in `charge`/`input_limit`, no change to `NotJudgedCause`, to the verifiers or to the stream.

## Pins (every one RED before the fix, watched on a scratch copy of the base with its own target dir, never a `git checkout` of a dirty tree)

- A `compile_fail` doc test on the struct's docs: `let _ = bsv_rs::transaction::WorkBudget { per_input: None, per_transaction: None };` under ```` ```compile_fail ```` (RED on `77cccd70`: it compiles there, so the doc test fails). Say in the REPORT the doc test's name as `cargo test --doc` prints it and its result on the base and the tip.
- In `tests/transaction_work_budget_519.rs` (or a new `tests/transaction_work_budget_527.rs` if the 519 file would cross a ratchet bound): `WorkBudget::new()` equals `WorkBudget::default()`; `new().with_per_input(Some(68)).with_per_transaction(Some(70))` reads `per_input == Some(68)` and `per_transaction == Some(70)`; the setters are usable in a `const` (a `const B: WorkBudget = WorkBudget::new().with_per_input(Some(1));`). The literal at `:433` moves to the constructor (it would not compile otherwise: an integration test is outside the crate).
- The existing #519 tests all green, unchanged in what they assert.

## Docs

- `CHANGELOG.md`, under `## [Unreleased]`, a `### Changed: \`WorkBudget\` is \`#[non_exhaustive]\` with a constructor and field setters (#527)` entry: the finding, the shape, the keeper's word, the one-line migration (`WorkBudget { per_input: a, per_transaction: b }` becomes `WorkBudget::new().with_per_input(a).with_per_transaction(b)`; a destructure outside the crate takes `..`; the struct's `with_work_budget`/`with_transaction_work_budget` are `with_per_input`/`with_per_transaction`, the verifier builders unchanged), the semver line (a major on the beta line under api-break; in no published prerelease), the pins named. Every entry of the file is a `### Kind: title (#N)` section; write one, not a bare bullet.
- `README.md:99-105` (the transaction-wide work bound paragraph): the constructor and setters if it shows the shape; a ```rust block that opens with `// examples/<name>.rs` equals that file (rule 8): if an example builds a `WorkBudget`, change the example, run it, paste it, and `cargo test --test readme_examples` pins the bytes.
- `src/transaction/CLAUDE.md:40` (the `work_budget.rs` row) and `src/script/CLAUDE.md:13`: the shape as it is now (`#[non_exhaustive]`, `new()`, the two setters, the fields readable).

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib transaction` and `--lib script` (one filter per run); one `--test` per integration file matching `transaction_*`, `script_*`, `beef_*`, `arch_*`, `fixtures_replay*` and `readme_examples` (the files, not the `arch_support` directory); `cargo test --doc --all-features`; `cargo build --examples --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (set `CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev 77cccd70 --release-type major` (name every break it lists: expected `struct_marked_non_exhaustive` and the two removed methods on `WorkBudget`; anything else is a finding), and read how `.github/workflows/ci.yml`'s `semver` job classifies the tip (say whether it passes a major on `beta`); `tools/ratchet/run --check --against 77cccd70` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the files changed with the line ranges; the RED evidence (the doc test's result on the base and the tip, the moved literal); the gate's results in a table; the semver breaks named and the CI job's reading; every verifier-builder site left as it was, counted; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
