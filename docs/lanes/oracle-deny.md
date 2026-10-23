# Lane oracle-deny: deny.toml and the supply-chain gate (#79)

**Repository.** `bsv-rs`, your worktree on a branch from `origin/beta`. `docs/lanes/README.md` binds you. Two hours.

**Read in this order.** #79 and the epic #101. `Cargo.toml` (the 21 features and every optional dependency: reqwest, tokio, tokio-tungstenite, js-sys, dhat, getrandom), `Cargo.lock`. The stack's template: `~/bsv/bsv-stack-lean/template/` (its `deny.toml` if present) and `docs/lanes/l2-deny-template.md`, `l2-deny-template-2.md` (the paved road's words: advisories with unsound and unmaintained on, yanked denied, licenses allowlisted, sources crates.io only). The CLI's `deny.toml` at `git -C ~/bsv/bsv-wallet-cli show origin/beta:deny.toml` (adopted at 0.13.x). `ci.yml`'s `machete`, `msrv` and `secrets` jobs for the pinned-tool shape (a tool built from its pinned source by version, under `$RUNNER_TEMP/tools`).

**The work.**
1. `deny.toml` from the stack's template, adapted: the license allowlist is what the tree actually carries (list each license and the crates under it in the report); `sources` pins crates.io and nothing else; `bans` with `multiple-versions = "warn"` and the duplicates named in the report (a duplicate is an issue, not an ignore).
2. `cargo deny --locked check` green with an empty `ignore` list under `--all-features`, under `--no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (the Cloudflare slice; wasm's dependency graph differs), and under the default features. A finding that cannot be green today is filed as an issue on Calhooon/bsv-rs with the advisory id, and the report names it; the lane never writes an `ignore`.
3. The CI job `deny` in `ci.yml` (cargo-deny by version, built from source into `$RUNNER_TEMP/tools` as `machete` is), running the three feature sets.
4. One paragraph in `RELEASING.md` under the gate: `deny` is a required check from this wave on (the captain adds the protection).

**Bounds.** No dependency moves (a bump to clear an advisory is its own PR, named in the report with the advisory). No edit under `src/`. `Cargo.toml` untouched.

**Report.** `REPORT: STATUS done|blocked`, the base and tip commits, the three `cargo deny` tails, the license table, every duplicate version and every advisory found, the issues filed, the six tests each choice passes.
