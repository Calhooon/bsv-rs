# Lane oracle-nightly: mutation testing on a schedule with a floor (#81)

**Repository.** `bsv-rs`, your worktree on a branch from `origin/beta`. `docs/lanes/README.md` binds you. Three hours.

**Read in this order.** #81 and the epic #101 (the mutation floor is a scoreboard line). `src/script/spend.rs` and `src/script/flags.rs`, `src/transaction/beef.rs`, `beef_stream.rs`, `merkle_path.rs`, `src/wallet/wire/`, `src/wallet/substrates/` (the surfaces under the floor). The CLI's `oracle-nightly` brief and its `nightly.yml` if landed (`git -C ~/bsv/bsv-wallet-cli show origin/beta:.github/workflows/nightly.yml`); `ci.yml`'s pinned-tool shape. `tests/CLAUDE.md` for which test files exercise each surface (a mutant is caught only by a test that runs; name the test command the mutants job uses).

**The work.**
1. `.github/workflows/nightly.yml`: a schedule (03:00Z) and `workflow_dispatch`; a `mutants` job running `cargo-mutants` (by version, built from source) over the five surfaces with `--in-place` off, a timeout per mutant, the test command `cargo test --features "full,http" --locked` scoped by `--test` where a surface's tests are known so the run fits the night; the score per file as a job summary and as a JSON artifact; failing below 80 percent on each file, or, where today's score is lower, at that file's score rounded down, named in the workflow beside the issue to raise it. The fuzz jobs are `oracle-fuzz`'s (#82); leave a job stub with a comment naming it, or coordinate by reading `lane/oracle-fuzz` if it exists.
2. An initial run locally on `src/transaction/merkle_path.rs` and `src/wallet/wire/encoding.rs` in full, and on the other three for as long as the lane's hours allow; every score in the report; a surviving mutant in `script/` or `transaction/beef*.rs` filed as an issue with the mutant's diff.
3. `docs/NIGHTLY.md`: what runs, where the results land, what a surviving mutant becomes, what a crash input becomes (shared with #82).

**Bounds.** No edit under `src/`, `Cargo.toml` untouched, `ci.yml` untouched (the nightly is its own file). Builds under `CARGO_TARGET_DIR` on the lane volume; a full local run is not required, the night is the schedule's.

**Report.** `REPORT: STATUS done|blocked`, the base and tip commits, the score per file with the mutant counts (caught, missed, timeout, unviable), the issues filed, the commands and their tails, the six tests each choice passes.
