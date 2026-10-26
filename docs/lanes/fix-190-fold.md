# Fold lane: fix-190-fold. PR #254 is red on two platforms: two u32-bound tests the gate did not run (#190)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), continuing in the worktree of `lane/fix-190-transceiver-frame-end` (tip `e87aa33`, PR #254 into beta). Read the lane's own commits (`git log --oneline origin/beta..HEAD`, `git show` each), `CLAUDE.md` (rules 1, 2, 3, 5), `src/wallet/wire/CLAUDE.md` and issue #122 (`gh issue view 122 --repo Calhooon/bsv-rs`: nine u32 fields of the wire refused above `u32::MAX`, never cast). You never push, tag or open a PR; you commit on this branch and end with the REPORT. Every command is foreground and under ten minutes.

## The red

CI's `Test Suite (windows-latest, stable)` and `Test Suite (macos-latest, beta)` on PR #254 fail two tests the lane's gate did not run: `tests/wire_u32_field_bounds_tests.rs` `a_list_certificates_total_above_u32_max_is_refused_not_truncated` (panics at `:378:69`) and `a_discovered_certificates_total_above_u32_max_is_refused_not_truncated` (`:401:76`); 7 of 9 pass. They fail on every platform (run them: `cargo test --features "full,http,tracing" --test wire_u32_field_bounds_tests` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-190-transceiver-frame-end`). The lane changed how the two certificate-page readers read the declared total (`#assertPageCount`, `#requirePageCapacity`, to the end of the frame), and the #122 tests pin that a total above `u32::MAX` is refused with the #122 reading's words, never cast or truncated; the new order of checks answers something else at that point.

## The work

1. Read the two tests: what bytes they build (a total above `u32::MAX`) and what they expect (the exact error and words). Read what the reference does with such a total, in order, at `ts-stack@edf6e03`: `WalletWireTransceiver.ts:1501-1550` and `:1652-1764` (the total's read: `readVarIntNumStrict`? `#requireInteger`? which refusal comes before the page checks), and cite the lines. The reference's order decides (rule 1).
2. Make the readers refuse in the reference's order with the reference's words at each point. If the reference's words for a total above `u32::MAX` are the #122 reading's words the tests expect, the tests stand and the code moves; if the reference's words at that point differ from what the #122 tests expect, say so in the REPORT with the two sentences side by side and STOP before changing a #122 test (the keeper's reading on #122 is of record; the captain decides), unless the difference is only the order of two refusals both of which the tests already accept.
3. The gate, in full this time: `cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_u32_field_bounds_tests --test wire_reader_strictness --test wire_identity_certificate_roundtrip --test wire_processor_validation --test wire_error_frames --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests --test wire_signed_varint_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` (fresh dir `$HOME/bsv/targets/bsv-rs-lanes/fix-190-fold`; never re-record a baseline). One commit: "the fold: ...", its body naming the two tests and the reference's order; the changelog entry adjusted if the order it describes moved.

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#190)`; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: the tip sha and the fold commit; the reference's order and words at the total's read, cited; what moved (code, or a test's expectation, and why the reference allows it); the green run (every gate command with its result line, the nine test files named); anything you could not do and why.
