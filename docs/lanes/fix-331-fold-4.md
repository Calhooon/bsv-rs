# #331 fold 4: the re-review's notes, and a result past the reference's read figure as the keeper words it (`lane/fix-331-verify-budget` at 87bcb193 on ccf5b8e6; PR #370)

Work in this worktree on the branch as it stands (thirteen commits; the last three are the third fold's: f92e2b4a the step's peak probed and the copies shrunk, 78fefe90 its docs, 87bcb193 the default mode's read limit at 536,870,888 bits with `Invalid string length`). The third fold's cold re-review (Opus, `review-331-fold-3`; its REPORT in `cca runs --show review-331-fold-3` on this host and on PR #370) is FIX on one point and carries notes. Read `CLAUDE.md`, `src/script/CLAUDE.md`, `src/script/spend/reference_read.rs`, `src/script/spend/{arithmetic,arithmetic_room,limits,splice}.rs`, `tests/script_reference_read_limit_331.rs`, the branch's changelog entry, the reference at `edf6e03` (`packages/sdk/src/primitives/BigNumber.ts:771-779`, `packages/sdk/src/script/Spend.ts:1066`, and `#readScriptNumber`), issues #374 and #331. Do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL. `CARGO_TARGET_DIR=~/bsv/targets/bsv-rs-lanes/fix-331-fold` (warm); the nightly toolchain, cargo-fuzz 0.13.2 and Node 22 under nvm are on this host; the reviews' harnesses are under `/Volumes/Lanes/out/bsv-rs/review-331-fold-2/` and `/Volumes/Lanes/out/bsv-rs/fix-331-fold3/`.

## The FIX point (the keeper's word follows by message from the captain; do not decide it yourself)

The reference throws `RangeError: Invalid string length` when a result past 536,870,888 bits is pushed (`BigNumber.ts:771-779`, `Spend.ts:1066`): `OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB` and `OP_LSHIFTNUM` of operands just under the figure give a result the reference cannot encode, where this branch computes and pushes it; `tests/script_reference_read_limit_331.rs:68` pins `Ok(true)` on such a script; the entry says nothing of it. The keeper's word names the class: (1) a verdict, invalid with the reference's words; (2) a decline, a resource limit; (3) computed and stated as a divergence. Until the word arrives, do the notes below; when it arrives (the captain sends it to this lane), one more commit: the behaviour at the push for every opcode whose result can cross the figure (say which, from the code: the arithmetic and the numeric shifts), the test at `:68` re-pinned to it RED before green, the entry and `CLAUDE.md`'s lines stating it with the reference's sites.

## The notes

1. `CHANGELOG.md:119` names the wrong commit: read the entry's line and name the commit it means.
2. `tests/script_reference_read_limit_331.rs:8-11`: the RSS figure holds only under `--test-threads=1`; say so where the figure is stated, or state the figure the way it was measured.
3. `src/script/spend/limits.rs:178`: a decline says "exceeded 0 bytes" (the figure is the limit's, not zero): fix the text to the real figure and pin it.
4. `src/script/spend/arithmetic.rs:57`: the operand order (read the review's note in its REPORT: which operand is named first in the decline's text or taken first, and the reference's order); fix and pin.
5. Not yours: `splice.rs:362-363` (the reference reads 8 bytes of a splice operand) is the captain's follow-up issue.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transaction_*`, `beef_*`, `script_*`, `identity_spend_witness`, `conformance_*` (with `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance`), `arch_*` (not the `arch_support` module), `fixtures_replay`; `cargo test --features "full,http,dhat-profiling" --test memory_profiling`; `--lib transaction`; `--lib script`; `--lib primitives`; the doc tests; `cargo build --examples --all-features`; `cargo test --test readme_examples`; the wasm32 build of the CLAUDE.md feature set; the corpus replay; `cargo semver-checks --release-type minor --baseline-rev ccf5b8e6` (`method_parameter_count_changed` alone); `tools/ratchet/run --check --against origin/beta` (beta is at bb80a525 now, a CI and docs landing; rebase onto it first: the CHANGELOG conflict keeps this entry above #380's, nothing lost).

## Report

A REPORT: the tip, each commit, the notes' fixes (file:line), the FIX point's commit as the keeper worded it (the opcodes, the class, the words, the test), RED then green, the gate's results, anything unverified.
