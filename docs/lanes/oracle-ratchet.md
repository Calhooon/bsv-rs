# Lane oracle-ratchet: the numbers that may only fall (#78)

**Repository.** `bsv-rs`, your worktree on a branch from `origin/beta`. `docs/lanes/README.md` binds you. Two hours.

**Read in this order.** #78 and the epic #101 (the code-health line). The measurements of 2026-10-23 that seed the baseline: 101,422 lines in 152 files; over 800 lines: `src/script/spend.rs` 4,419, `src/transaction/beef_stream.rs` 3,652, `src/transaction/beef.rs` 3,214, `src/transaction/transaction.rs` 3,000, `src/wallet/wire/encoding.rs` 2,560 (the eight `src/compat/bip39/wordlists/*.rs` at 2,061 each are data: exempt by path until #89 makes them text); 276 unwrap/expect outside tests (`primitives/encoding.rs` 25, `beef_stream.rs` 24, `compat/bip32.rs` 22, `compat/ecies.rs` 18, `auth/transports/websocket_transport.rs` 15, `primitives/hash.rs` 12). The CLI's shape at `git -C ~/bsv/bsv-wallet-cli show origin/beta:docs/lanes/oracle-ratchets.md` and its `tools/ratchet` if landed (`origin/beta:tools/`); `~/bsv/bsv-stack-lean/docs/GATE-LINT.md` for the gate-leg shape.

**The work.**
1. `tools/ratchet` (a Rust bin under `tools/ratchet/` with its own manifest, outside the workspace): measures files over 800 lines (count and list, the wordlists exempt by path), unwrap/expect outside `#[cfg(test)]` modules and `tests/`, functions over 60 lines, clippy's cognitive complexity over 25, `cargo doc` `missing_docs` warnings, duplicated blocks (a 40-token window hash; say the method), `clippy::pedantic` warnings. One JSON object, deterministic (two runs, same bytes).
2. `docs/ratchets.json`: the baseline from `origin/beta` at your base commit, the commit named inside.
3. `tools/ratchet --check`: fails when any number is above the baseline, naming which and by how much; `--record` rewrites it, used only by a PR that says so (a PR that lowers a number re-records in its own commit).
4. The CI job `ratchet` in `ci.yml`.
5. `docs/RATCHETS.md`: each number, how it is measured, why it only falls, how a lane moves one, which issue empties each list (#85, #86 for the files; #80's allowlist for the unwraps).

**Bounds.** Measure only; fix nothing. No edit under `src/`. `Cargo.toml` untouched (the tool's crate lives in `tools/ratchet/Cargo.toml`).

**Report.** `REPORT: STATUS done|blocked`, the base and tip commits, the baseline JSON in full, the commands and their tails, the six tests each choice passes.
