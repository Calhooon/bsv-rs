Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #545 fold: `lock_with_key_bytes` crate-visible (a port helper, not the reference's shape), the template tests a unit test, the rows and counts true

You are on the lane's worktree `lane/fix-545-pushdrop-key-bytes` at `08bfaadc` (two commits on `69d315fc`: the lane's ce0bb25c and the cold review's tests commit 08bfaadc, the reveal site's own witness). PR #557. Never push. Nothing is filed on any tracker. Your logs, scratch copies and evidence live under `/Volumes/Lanes/out/bsv-rs/fix-545-fold/`, never the shared `$TMPDIR`.

## The review's FIX (Opus; `gh pr view 557 --comments`)

1. `PushDrop::lock_with_key_bytes` (`src/script/templates/pushdrop_key_bytes.rs:23`) is `pub`: the reference has one `lock` taking the key as text, so a second public constructor is a port invention; make it `pub(crate)` (the five wallet sites are in the crate); move the vector's template tests that call it from the integration test (`tests/script_pushdrop_key_bytes_545.rs`) to a unit test beside the helper (the vector read from `tests/vectors/pushdrop_key_bytes_545.json` by path from the unit test, as other unit tests read vectors: read how); the integration test keeps the five sites' witnesses (through the public wallet paths).
2. The rows that call it public (`CHANGELOG.md`'s #545 entry, `src/script/CLAUDE.md`, `src/script/templates/CLAUDE.md`, `tests/CLAUDE.md`) rewritten; the doc nits: the entry's "the reveal site has no site test" sentence (now false: the review's commit added it); `tests/CLAUDE.md:24`'s counts (7 tests / four site tests become 8 / five).
3. Nothing else changes; the vector unchanged.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib script`, `--lib kvstore`, `--lib identity`, `--lib registry` (one filter per run); one `--test` per file matching `script_*`, `kvstore_*`, `identity_*`, `registry_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev 69d315fc --release-type patch` (no public change now: say what it reports); `tools/ratchet/run --check --against 69d315fc` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. Three commits at the end (the two you were given and the fold); the captain squashes.

## REPORT

The tip; the visibility change and the test move; the rows and counts; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).
