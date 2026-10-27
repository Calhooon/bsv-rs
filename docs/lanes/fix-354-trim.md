# #354 trim: `src/auth/transports/http.rs` one line over its ratchet bound after the rebase over #329

Work in this worktree on `lane/fix-354-unsigned-response-refused` as the sequencer rebased it (14f788ef on 6c7596a; `git fetch origin lane/fix-354-unsigned-response-refused && git reset --hard origin/lane/fix-354-unsigned-response-refused` first). CI's `ratchet` job refuses the tip: `src/auth/transports/http.rs: 1253 lines > 1252 (+1)` (run 40523707731); the fold's re-review had warned the file sat one line under its bound. Read `docs/RATCHETS.md` (never re-record the baseline for growth), `src/auth/transports/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL (a MetaNet Client listens on 3301, 3321 and 2121 on this host). Use your own `CARGO_TARGET_DIR` under `~/bsv/targets/bsv-rs-lanes/<lane>`.

## What to do

Bring `http.rs` under its bound by moving code, not by compacting it: the unauthenticated-answer handling or the fault classification the #354 branch added, into `src/auth/transports/http/unauthenticated.rs` (or a sibling under `http/`), with no behaviour change (the transport's tests and the vector unchanged); say in the commit what moved and that `http.rs` sits at how many lines of 1252 after. One commit.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transport_*`, `auth_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib auth::transports`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `tools/ratchet/run --check --against origin/beta` (the counter that failed, green).

## Report

A REPORT: the tip, the commit, what moved and the line counts before and after, the gate's results, anything unverified.
