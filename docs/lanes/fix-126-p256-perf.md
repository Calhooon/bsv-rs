# Lane: fix-126-p256-perf. P-256 verification about twice as slow after the move to p256 0.14 (#126)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 2, 7, 9), `src/primitives/CLAUDE.md`, `benches/CLAUDE.md`, `docs/RATCHETS.md` ("When a dependency changes"), `docs/DEPENDENTS.md` and issue #126 (`gh issue view 126 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (Criterion runs with `--warm-up-time 1 --measurement-time 3`, one bench group at a time).

## The finding

With p256 0.14.0 (elliptic-curve 0.14.1, primeorder 0.14, crypto-bigint 0.7) P-256 signature verification measured about twice as slow as with p256 0.13.2, in two A/B rounds (the #125 advisory lane). `Cargo.toml` today: `p256 = { version = "0.14", default-features = false, features = ["alloc", "ecdsa", "precomputed-tables"] }`, `k256` the same with `sha256`. The advisory (RUSTSEC, #125) forbids going back to 0.13.

## The work (an investigation that ends in a measured change or a stated bound)

1. **Measure on this tree.** The scoreboard's sign-and-verify line (#92) and `benches/primitives_bench` (find the P-256 and secp256k1 verify groups): run them on `origin/beta` as the baseline, release, and record the medians; the box may be loaded (other lanes run), so interleave two runs and read the spread before you read the difference.
2. **Find the cause**, in the issue's order: (a) the arithmetic (crypto-bigint 0.7 vs 0.5: read p256 0.14's changelog and `elliptic-curve`'s; is there an upstream issue? search `RustCrypto/elliptic-curves` issues for "0.14 slower" / "performance" and cite what you find); (b) a feature the 0.13 line had on by default and 0.14 does not (`arithmetic`, `hazmat`, `precomputed-tables`, `std`): read both versions' `Cargo.toml` feature lists (`~/.cargo/registry/src/*/p256-0.13.2/Cargo.toml` and `p256-0.14.0/`), diff them, and try each candidate feature in a scratch copy with its own target dir, measuring; (c) a debug-assertion or overflow-check path (`[profile.bench]`/`[profile.release]` settings; `debug-assertions` in a dependency); (d) p256's own benches at 0.13.2 and 0.14.0 (`cargo bench` in the registry source, if they run under ten minutes), to say whether the slowdown is the crate's or this crate's use of it.
3. **Then one of:** (i) a feature or profile change in `Cargo.toml` that recovers the speed, measured (the ratchet library lock refreshed per `docs/RATCHETS.md` since the dependency set moved; `cargo deny check` green; the wasm32 build green: a feature that pulls `std` breaks it); or (ii) a stated bound: the changelog's `### Notes` paragraph with the cause, the upstream issue, the numbers, and that the scoreboard measures it from now on; `docs/PERFORMANCE.md` (or where the scoreboard's numbers live) carries the line. A change to k256's features is out of scope unless the same cause and measurement cover it: say so.
4. Rule 2 in its measured form: the before and after numbers in the commit body and the changelog, the bench command exact.

Public shape: nothing moves. A dependency version move is not yours (the advisory fixed it; a newer p256 than 0.14.0, if one exists and fixes it, is a finding to REPORT with its number, not to take).

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features full --lib primitives` and the EC test files (`ls tests/ | grep -i -E "ec_|p256|ecdsa|signature"`, each `--test`); `cargo deny check` if `Cargo.toml` moved; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (LLVM clang for `ring`: `CC_wasm32_unknown_unknown=$(brew --prefix llvm)/bin/clang`); `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-126-p256-perf` (fresh; never re-record a baseline; refresh the library lock if a dependency moved).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#126)`; bodies say what and why with the numbers; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the baseline and after numbers (the table, the command, the box load); the cause with its evidence (the feature diff, the upstream issue's link, the profile reading); which of (i)/(ii) you took and why; the gate (every command with its result line); anything you could not do and why.
