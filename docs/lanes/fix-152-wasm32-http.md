# Lane: fix-152-wasm32-http. wasm32 with `http`: the transaction slice does not build; rule 6's slice list hides it (#152)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rule 6 above all), `src/transaction/CLAUDE.md`, `src/overlay/CLAUDE.md`, `docs/DEPENDENTS.md`, `.github/workflows/ci.yml` (the `wasm32` consumer matrix) and issue #152 (`gh issue view 152 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes. wasm32 C dependencies need LLVM clang locally: if `ring` fails to build for wasm32, set `CC_wasm32_unknown_unknown` to Homebrew's `clang` (`$(brew --prefix llvm)/bin/clang`) and say so.

## The finding

`cargo build --target wasm32-unknown-unknown --no-default-features --features "transaction,http,wasm"` fails on beta: `async_trait` methods of the HTTP chain trackers (`src/transaction/chain_trackers/`) await a reqwest future that is `!Send` on wasm32 (eight errors); with `http` added to rule 6's slice, 69 errors, among them `ClientBuilder::timeout` (reqwest's wasm backend has no timeout on the builder). Reproduce both counts on your base commit and quote them.

## The work, in the issue's order

1. **Does a consumer ask for `http` on wasm32?** grep the workers' `Cargo.toml`s (`~/bsv/bsv-overlay-cloudflare`, `~/bsv/rust-message-box`, `~/bsv/bsv-low/workers/*` is OFF LIMITS to you: read `docs/DEPENDENTS.md`'s record of those slices instead; `~/bsv/rust-chaintracks`, `~/bsv/bsv-middleware-cloudflare-public`) for `bsv-rs` features including `http`, and read the `wasm32` job's matrix. Report what each asks.
2. **If none asks:** the finding is a stated bound: README and `Cargo.toml`'s feature docs say `http` is native-only on wasm32 at those sites, and a `#[cfg]` guard (`compile_error!` at one named site under `all(target_arch = "wasm32", feature = "http")`, or the narrowest honest form) makes the wasm32 build with `http` fail at one named site with one message instead of eight or 69. Rule 6's slice sentence in `CLAUDE.md` says why `http` is absent.
3. **If one asks:** the fix: the trackers' futures `Send`-free on wasm32 (`#[async_trait(?Send)]` under `cfg(target_arch = "wasm32")`, the pattern `src/overlay/` uses if it builds there: read it), the builder's `timeout` behind `cfg(not(target_arch = "wasm32"))` with the wasm path's timing by `crate::util`'s helpers or `futures-timer` as rule 6 asks of the time driver; rule 6's slice list gains `http`; the `wasm32` CI job gains the slice; the transport fault (#87) still typed on that path (its tests).
Either way: RED before (the build's error count on the base), green after (the build's result line), every native test untouched. The changelog entry says which way and why.

Public shape: `#[async_trait(?Send)]` changes the trait's future bounds on wasm32 only; say so in the changelog if you take branch 3; if a native bound would move, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; the `http` wasm32 build (branch 2: fails at one named site, quote it; branch 3: builds); `cargo test --features "full,http" --test chain_tracker_tests` (or the trackers' test files by name: `grep -l -i chaintracker tests/*.rs`); `cargo test --doc --features full`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-152-wasm32-http` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#152)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; what each consumer asks (the grep lines); which branch you took and why; the RED counts and the green build lines; every gate command with its result line; anything you could not do and why.
