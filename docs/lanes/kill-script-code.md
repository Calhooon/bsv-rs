# Kill lane: `src/script/spend/script_code.rs` (#681)

Base: `origin/beta` at `55424846` (the worktree opened at `efe12e63`, main's tip; reset to
`origin/beta` before any edit). The node is read at `879fc8b` (`git show 879fc8b:<path>`):
`src/script/script.h` (`CScript(const std::vector<uint8_t>&)` at 71, `operator<<` at 102-130,
`GetOp2` at 163-198, `FindAndDelete` at 200-224) and `src/script/interpreter.cpp`
(`CleanupScriptCode` at 255-263: the push of a signature without `SIGHASH_FORKID` deleted, a FORKID
signature's push kept, the rule of 0.3.27). The TypeScript clone is absent on this host, so its
citation is left out.

## The measure

`cargo mutants --jobs 1 --no-config --timeout 120 --build-timeout 300` with the nightly's
script-surface selection (`nightly_mutants.py`'s `mutation_args("script", ...)`, `--file
src/script/spend/script_code.rs`), in a scratch copy with its own target dir (the ratchet's
`library.Cargo.lock` as its `Cargo.lock`, for `--locked`). The baseline ran as shard 0/8 and the
round-robin 16-shards 1-7 and 9-15 (8-shard 0 is exactly 16-shards 0 and 8); the final as the
sixteen 16-shards; each shard under eight minutes.

| Run | Caught | Missed | Timeout | Score |
| --- | ---: | ---: | ---: | ---: |
| Issue #681 (the complete run) | 29 | 16 | 6 | 56.86% |
| Baseline at the base | 27 | 16 | 8 | 52.94% |
| Final at the tip | 50 | 1 | 0 | 98.04% |

The baseline's 16 missed are the issue's 16. Two of the issue's caught mutants time out here:
`123:16` `+=` to `-=` in `find_and_delete` and `86:21` `+` to `*` in `next_op`. Both are walks
that do not advance, so they hang on this host where the runner's memory ceiling or overflow
caught them on the nightly. The bound answers both.

## The bound (the timeouts)

`find_and_delete`'s `loop` became `for _ in 0..=script.len()` and its inner `while` became
`for _ in 0..script.len()` with a `break` on a mismatch. On the tip the change is neutral.
Each outer step either breaks or advances `pc` by a byte at least, and `next_op` answers `None`
at `pc == len`, so the walk breaks within `len + 1` steps. Each inner match advances by
`b.len() >= 1` within the script, so at most `len` matches fit, and after `len` the next check
fails anyway. The ranges add no mutant (cargo-mutants lists 51 before and after), whereas a
guard such as `next > pc` would be an unreachable branch, a new equivalent mutant. Every timeout
mutant now ends inside the bound and answers another script:

| Mutant (base line, tip line) | Without the bound | With the bound |
| --- | --- | --- |
| `85:5` `next_op` to `Some(0)` | hangs (30 s alarm) | FAILED in 0.01 s |
| `85:5` `next_op` to `Some(1)` | hangs | FAILED |
| `86:21` `+` to `*` | hangs | FAILED |
| `86:21` `+` to `-` | panics on this test (overflow at `pc = 0`); timed out in the run (a walk oscillating between two positions) | FAILED |
| `107:13` `+` to `*` | hangs | FAILED |
| `122:44` / `127:45` `==` to `!=` (`!=` to `==` on the tip's form) | hangs | FAILED |
| `123:16` / `130:16` `+=` to `-=` | hangs | FAILED |
| `123:16` / `130:16` `+=` to `*=` | hangs | FAILED |

The "without" column is `a_copy_after_two_instructions_is_deleted_by_a_walk_that_advances_681`
alone on the base file with the mutant applied. The "with" column is the same test, among the
others, on the tip with the mutant applied. `the_bound_never_cuts_short_a_walk_of_one_byte_steps_681`
pins that the bound is not too tight: 64 copies, 64 instructions then a copy, and 9 `OP_0`s.

## The kills

Every test is in `src/script/spend/script_code_tests.rs`, the file's own `#[cfg(test)]` module
(84 lines before, 204 after; `script_code.rs` is 148). Each was RED with its mutant applied by
hand in the scratch copy and GREEN on the tip. Every test cites the node.

| Mutant (tip line) | Killed by |
| --- | --- |
| `67:12` `<` to `<=` (`push_of`, direct below 76) | `a_push_of_75_bytes_is_direct_and_of_76_takes_pushdata1_681`, `the_walk_steps_over_a_direct_push_at_75_bytes_and_a_pushdata1_at_76_681` |
| `69:19` `<=` to `>` (`push_of`, PUSHDATA1 to 0xff) | `a_push_of_255_bytes_takes_pushdata1_and_of_256_pushdata2_681` and four more |
| `71:19` `<=` to `>` (`push_of`, PUSHDATA2 to 0xffff) | `a_push_of_65535_bytes_takes_pushdata2_and_of_65536_pushdata4_681`, `..._255_...`, `the_walk_steps_over_a_pushdata4_at_65536_bytes_681` |
| `87:22` `<` to `<=` (`next_op`, `OP_PUSHDATA1` read as a direct push of 76) | `the_walk_steps_over_a_direct_push_at_75_bytes_and_a_pushdata1_at_76_681` |
| `91:12` `+=` to `-=`, `*=` (PUSHDATA1's length byte) | `the_walk_steps_over_a_direct_push_at_75_bytes_and_a_pushdata1_at_76_681` |
| `94:54` `+` to `-`, `*`; `95:12` `+=` to `-=`, `*=` (PUSHDATA2) | `the_walk_steps_over_a_pushdata2_at_256_and_65535_bytes_681`, `a_pushdata2_of_0x0100_is_256_bytes_not_1_681` |
| `98:54` `+` to `-`, `*`; `99:12` `+=` to `-=`, `*=` (PUSHDATA4) | `the_walk_steps_over_a_pushdata4_at_65536_bytes_681`, `a_pushdata2_of_0x0100_is_256_bytes_not_1_681` (its PUSHDATA4 case) |
| `104:21` `-` to `/` (the cut-push check) | `a_one_byte_push_cut_short_at_the_last_byte_is_kept_681` and four more |
| the eight timeouts | `a_copy_after_two_instructions_is_deleted_by_a_walk_that_advances_681` (and the unit cases) |

The walk tests build each push with `push_of`, the crate's own writer, at the boundary sizes
(1, 2, 75; 76, 77, 255; 256, 65535; 65536), plus a non-minimal two-byte PUSHDATA1, PUSHDATA2 and
PUSHDATA4, which `GetOp2` reads as any other push. The data is all `0x51`, the pattern `[0x51]`,
followed by `0x51 0x52`. The node keeps the data and deletes the copy after it, and a walker that
misreads a length lands in the data or stops before the copy.

## The candidate

`104:26`, `<` to `<=` in `next_op` (`script.len() - pc < size`). With `<=`, `next_op` also
answers `None` when the instruction ends exactly at the script's end. Size 0 qualifies too, so
this covers a non-push opcode in the last byte. The difference is only at the last instruction.
On the tip the walk steps to `len`, appends `script[pc2..len]` and breaks at the next read. On
the mutant it breaks with `pc2` at the same instruction and appends `script[pc2..]`, the same
bytes. `found` is unchanged, because nothing past the last instruction can match. `next_op` has
no other caller. The two forms return the same `Vec` on every input. Its share of the floor is 1
of 51 viable, 1.96 points (98.04% with it standing, 100% if declared). No `exclude_re` entry is
written by this lane.

## Verification

In the scratch copy at the tip: `cargo test --features full,http --lib script::` 263 passed;
`--test sighash_scriptcode_654` 7 passed, 1 ignored; `--test sighash_tests` 12; `--test
script_if_depth_consequences_634` 4; `--test script_mutators_keep_parsed_chunks` 6; `--test
conformance_scripts` 3 (the corpus absent on this host: it skips). Before that run the shared
target held cargo-mutants' last mutated build under the same fingerprint, and the tests read red
until the sources were touched. Every final shard's unmutated baseline was `ok`, so the measure
was unaffected. In the worktree: `cargo fmt --check`, `cargo clippy --all-targets --all-features
-- -D warnings`, the wasm32 build of rule 6, and `tools/ratchet/run --check --against 55424846`
(all counters, oversized-file limits and mutation floors pass).
