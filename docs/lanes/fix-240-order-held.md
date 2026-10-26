# Lane: fix-240-order-held. The order held is the reading: a child ahead of its parent is refused where the reference sorts before judging; stated, pinned (#240)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rule 1 and the BEEF contract; the "Known cross-SDK divergences" list), `src/transaction/CLAUDE.md`, `tests/CLAUDE.md`, `CHANGELOG.md`'s `[Unreleased]` and #86's entry, and issue #240 with its comments (`gh issue view 240 --repo Calhooon/bsv-rs --comments`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The reading (the keeper's, 2026-10-26, on #240): state it; no behavior moves

0.9.0 judges a BEEF's transactions in the order held (the stream by its nature; `Beef::verify_structure` and `Beef::verify_valid` following it since #86, `beef.rs:721-731`), so a child ahead of its parent is `Kind::InputNamesNoElement` at the input. The reference at `ts-stack@edf6e03` sorts ahead of judging (`Beef.ts:1054-1065`, `verifyValid` calls `sortTxs`) and accepts a children-first BEEF; its writer sorts before serializing (`#ensureSortedForSerialization`, `:354-358`), so every BEEF the reference writes is in BRC-62 order and the read-side sort is a leniency beside its own writer. BRC-62 at `5119a9b` (`~/bsv/brcs`, `transactions/0062.md:43`, `:72-74`, `:172-191`) has the order in mind for streaming validation. 0.8's `verify_valid` sorted (the leniency); 0.9.0 reads the wire as BRC-62 writes it. Read every cited line yourself and cite them.

## The work (docs and one test; NO behavior changes: if a reader accepts a children-first BEEF today, that is a finding to REPORT, not to fix)

1. **The test** (rule 2's spirit: the pin must fail if the reading ever moves): a new file `tests/beef_order_held.rs`: build a two-transaction BEEF with this crate's writer in BRC-62 order (parent then child, the parent proven by a BUMP built by this crate, as the fixtures do), prove it passes the three readers; then the same entries children-first (assemble the bytes by hand or through `Beef` with the order swapped before `to_binary` if the writer does not sort; if the writer sorts, say so and hand-assemble), and prove each of the three readers (`verify_stream`, `Beef::from_binary` + `verify_structure`, `Beef::verify_valid`) refuses it as `InputNamesNoElement` naming the child's input, one reading. Say in the test's doc comment that the reference accepts the second BEEF (`Beef.ts:1065`) and why this crate does not. RED-before is the test absent; show it fails when the assertion is inverted on a scratch copy, or explain why that is the honest RED here.
2. **The changelog**: under `## [Unreleased]`, a `### Notes: cross-SDK parity (#240)` paragraph: the reading, the citations (BRC-62, the reference's two sites, the charter line the keeper named: `docs/charters/beef-of-any-size.md:14` in `~/bsv/bsv-stack-lean` if it is on disk, else as cited), and that 0.8's `verify_valid` sorted before judging and 0.9.0 does not: a consumer that wrote children-first BEEFs (the toolbox did, and corrected to BRC-62 order) sees `InputNamesNoElement` and writes parents first.
3. **`CLAUDE.md`**: one line in the "Known cross-SDK divergences" list beside the 0.4.2/0.8.1 BEEF lines, in their voice; `src/transaction/CLAUDE.md`'s note where the order rule is described; `tests/CLAUDE.md`'s row for the new file.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --test beef_order_held --test beef_stream --test beef_two_readers_agree`; `cargo test --features full --test arch_ci_runs_every_test` (the new file must be in CI's run); `cargo test --doc --features full`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-240-order-held` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal (write "parents before children", "ahead of"); never "conformant" without a run. Commit subjects name `(#240)`; bodies say what and why; end with the Co-Authored-By line the session gives you. Two commits: the test; the docs.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; the two commits; the three readers' verdicts on both BEEFs (the exact `Reason`); the citations read; the green run (every gate command with its result line); anything you could not do and why.
