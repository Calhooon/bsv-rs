Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #347: an unused arch allowlist entry reads red, so a stale allowance cannot outlive the line it named

Branch `lane/fix-347-stale-allowlist-entry` from `origin/beta` (name the base sha in your REPORT). One commit. Never push.

## The finding (the #323 CI fold's re-review, Opus, 2026-10-27; `gh issue view 347`)

`tests/arch_no_string_errors.rs`'s allowlist (its rule in `docs/ARCH-RULES.md` §3) carried two stale entries covering four sites (`http_json.rs:912`, `http_wire.rs:209` at 953d9c00, both lines gone) until the #323 fold removed them. Nothing refuses a stale entry today.

## The shape

1. Read `tests/arch_no_string_errors.rs` whole: how an entry names its site (a file and the text it allows, or a file and a line) and how the test walks `src`. The test refuses an allowlist entry that matches no line: for each entry, the named file exists and at least one line of it carries the allowed text (or the entry's exact shape, if entries are keyed another way: say how); the failure message names the entry, so the fix is to delete it. An allowance dies with its line.
2. The same rule for every other arch test under `tests/arch_*.rs` that carries an allowlist of sites (`arch_no_unwrap`, `arch_no_env`, `arch_no_system_time`, `arch_network_sites`, `arch_secrets_scan_scope`, `arch_arc_deprecated`: read each; say which carry one). Apply the check through the shared support module (`tests/arch_support/`) once, used by each, if the lists share a shape; else each test its own check with the same words. Every allowlist entry on the tip must still match (a stale one you find today is removed, named in the REPORT and the changelog).
3. `docs/ARCH-RULES.md` §3 (and any section for the other lists) says the rule: an entry that matches no line is red.

## Pin (RED before the fix, on a scratch copy of the base with its own target dir)

A test (unit, inside the arch test file or the support module) that builds an allowlist with one entry naming a file and text that does not exist and asserts the check refuses it with the entry in its message; and the real allowlists on the tip pass. On the base, add a stale entry to the real list in the scratch copy and show the arch test stays green there (the finding), red on the tip with the same entry.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; one `--test` per `tests/arch_*.rs` file and `fixtures_replay`; `cargo test --doc --all-features`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout (test files have bounds too); `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Changed: an unused arch allowlist entry reads red (#347)` section (never a bare bullet): the finding, the lists covered, any stale entry removed, the pin; `docs/ARCH-RULES.md`; `tests/CLAUDE.md`'s row for the arch tests.

## REPORT

Tip sha and message; the base; the lists covered (a table: test, entry shape, check added); stale entries found; the RED evidence; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
