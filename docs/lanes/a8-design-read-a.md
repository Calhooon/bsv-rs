Do every read yourself, in the foreground, in your turn: no subagent, no background job; the REPORT is the last thing you write. Your logs and evidence live under `/Volumes/Lanes/out/bsv-rs/a8-design-read-a/`, never the shared `$TMPDIR` or `/tmp`. You commit nothing and push nothing: this is a design read.

# Design read A (simplicity-focused) of bsv-rs#601: the A8 allocation cycle behind `a8-alloc`

You are one of three independent readers of the same design row; you do not see the others. Your lens is simplicity: the smallest change that removes the measured allocations, the fewest new types and `cfg` sites, buffers reused before abstractions added, nothing a host can see moved.

## Read, in this order

`gh issue view 601 --comments` (the design row and its two comments: the census rows cited, the sibling `~/bsv/bsv-script-lean` as the third oracle, the ensemble step); `docs/a8/census-2026-10-31.md` (the rows named in #601: 1, 11, 13, 16, 17, 19, 22, 25, 29, 32, 33, 34, 35, 36, 37, 45); `CLAUDE.md` (rules 5, 6, 7, 9; the contracts); the readers: `src/transaction/beef_stream.rs` (`BeefDecoder::next`, `BeefIndex::fold_checked_from`, `display_hex`, `Cursor`, `BeefStream<R>`), `src/transaction/beef.rs` (`sort_txs`), `src/transaction/beef_tx.rs` (`update_input_txids`), `src/transaction/transaction.rs` (`from_reader`, `clone_without_sources`), `src/transaction/merkle_path.rs`; the interpreter: `src/script/spend/mod.rs` (`Spend`, `execute_opcode`, `error`), `src/script/spend/stack.rs`, `src/script/spend/limits.rs` (the memory budget: the node's 32 bytes per element), `src/script/script.rs` (`Script`, its `Clone`, `parse_chunks`), `src/script/chunk.rs`; `benches/memory_bench.rs`, `benches/script_bench.rs`; `Cargo.toml` (the features; `full`); the wasm32 build line in `CLAUDE.md` rule 6.

## Answer

A one-page sketch (at most sixty lines) of the simplest design that removes the rows' allocations behind `a8-alloc`: for each of the two paths (the readers, the interpreter) the types or functions that change, how the oracle path and the flag's path share every public type, the `cfg` sites you count, what the differential target compares, and the bench plan (before and after, which benches). Name what you would NOT do and why. Then the bounded block.

## REPORT

The sketch; then the bounded block: the decision in one line (`arena`, `allocation-free parse`, `buffer reuse`, or a named third, per path if they differ); a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0]. Nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.
