# #242: docs hygiene, three docs items and one cfg attribute

Branch `lane/fix-242-docs-hygiene` from beta's tip. Read `CLAUDE.md` ("Where the numbers come from"), `tests/CLAUDE.md`, `src/transaction/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No code change beyond item 4: if another item needs one, stop and say so in the REPORT.

## The three items (issue #242)

1. **"through 0.9.0" where 0.8 is meant.** The tree writes "through 0.9.0 X did Y" for a reading that 0.9.0 itself changed, so a 0.9.0 reader takes the sentence as current. `grep -rn "through 0.9.0" src tests docs README.md CHANGELOG.md CLAUDE.md`: for each site, read the changelog entry that changed the reading and write the version that last held it ("through 0.8.3", "until 0.9.0"), the changelog's own wording being the reference. Sites named by the review: `src/transaction/merkle_path.rs:707`, `tests/conformance_beef.rs:211`, others under `src/transaction/`. A sentence about 0.9.0 doing something is left alone.
2. **A stale `MismatchedNode`.** `tests/CLAUDE.md`'s row for `beef_two_readers_agree.rs` names the repeated-leaf kind `MismatchedNode`; since #86/#167 (`ef1a6c6`) it is `DuplicateOffset` (`src/transaction/beef/in_memory.rs`, `tests/beef_two_readers_agree.rs:526-533`). Fix the row; grep the tree for other `MismatchedNode` mentions that describe the repeated-leaf case and fix those the same way (a `MismatchedNode` that still exists as its own kind stays).
3. **The integration-file count.** Root `CLAUDE.md`'s layout table says "63 integration files" under `tests/`; re-measure with `ls tests/*.rs | wc -l` on the tip and write the number with its date and sha, as "Where the numbers come from" asks. Re-measure the other counts in that paragraph the same way only if the command is written beside them; never write a number you did not run for.

4. **A dead helper under one feature.** `tests/wallet_wire_cross_sdk_tests.rs:23` `vector_exists` is dead under `--features wallet` alone (`cargo clippy --tests --features wallet -- -D warnings` refuses the target). Gate it with one `#[cfg(feature = "...")]` naming the feature its callers sit under; `cargo clippy --tests --features wallet -- -D warnings` and `--all-features` both clean afterwards.

5. **Beta's own duplicate rows and paragraphs, left by keep-both rebases.** `tests/CLAUDE.md` holds three `wire_reader_strictness.rs` rows (one is right: the file's current count and sentence); `src/wallet/wire/CLAUDE.md` holds the "Certificate binary format in transceiver response parsing" paragraph twice; `src/auth/CLAUDE.md` may hold a duplicated `certificate.rs` bullet. For each docs file under the tree, list exact duplicate table rows (`grep -E '^\| `' | sort | uniq -d`) and near-duplicates (the same first cell with different tails), keep the one that matches the file or the current reading, and name every drop in the commit message.

## Gate

`cargo fmt --check`; `cargo test --features "full,http" --test readme_examples` and every test file matching `arch_*` (not the `arch_support` module; `arch_ci_lines` and the docs guards read these files); `cargo doc --no-deps --all-features` with no warnings; the ratchet.

## Report

A REPORT: every site changed with its old and new sentence, the measured count with its command and sha, the gate's results. One commit per item.
