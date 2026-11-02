Do every edit and every check yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write. Your logs live under `/Volumes/Lanes/out/bsv-rs/docs-filings-1102-b/`, never the shared `$TMPDIR` or `/tmp`.

# Docs, the second pass: the four 11-02 filings carried onto `CHANGELOG.md`'s census-row copies (row 57, row 60 in its four copies, row 61, row 18), every copy

You are in the worktree of `lane/docs-filings-1102` at its commit `39ae5f65` (on beta `699b7a35`), whose first pass carried the filings onto `docs/lanes/375-filings/QUEUE.md`, the four drafts' headers and `CLAUDE.md`, and reported the `CHANGELOG.md` census copies as untouched because its grep scope left CHANGELOG out. Never push. Docs only: `CHANGELOG.md` alone this pass.

## The facts

Filed on 2026-11-02 at 00:00Z under the owner's name by the keeper's detached script, from the drafts as they stood on beta (cadence (b)); the numbers checked against the issues' titles through the API by the captain:

- `certificate-bounds-der.md` (QUEUE row 9): bsv-blockchain/go-sdk#401
- `certificate-response-preimage-go-sdk.md` (QUEUE row 10): bsv-blockchain/go-sdk#402
- `create-action-positive-script-length-ts-stack.md` (QUEUE row 13): bsv-blockchain/ts-stack#1466
- `public-key-unreduced-coordinate-serialization.md` (QUEUE row 18): bsv-blockchain/ts-stack#1467

## What to do

1. Find every `CHANGELOG.md` site that names one of the four drafts, or its census row's filing, as pending or unfiled: the first pass named lines 12012 (census row 57), 11061, 11445, 11589 and 11657 (census row 60, four copies), 1535 (census row 61) and 2411 (census row 18's "a FILE draft"); re-find them yourself with a case-insensitive grep for each draft's file name, for `filing pending`, `to be filed`, `FILE draft`, `pending the owner's cadence` and the row numbers, and across line breaks (a clause wraps). A census row has several copies in the file (one per release entry that restated it): rewrite every copy the same way, and put the copy count per row in the REPORT (`grep -c` the row's opening words before and after).
2. The clause takes the shape the file's already-filed rows carry (row 10's "Theirs: go-sdk #400 for the wire bounds (filed 2026-11-01; answer pending; the witness: ...)" is the model): the repository and number, `filed 2026-11-02`, `answer pending`, the witness kept as it stands; the sentence that said pending goes; no other word of the row changes. A site you are unsure of is listed in the REPORT, not changed.
3. The check: `cargo test --test 'arch_*'` (`export CARGO_BUILD_JOBS=4`; one cargo at a time; `CARGO_TARGET_DIR` outside the checkout) green; `tools/ratchet/run --check --against origin/beta` green; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit on top of `39ae5f65`: `docs(filings): the 11-02 filings on the CHANGELOG census copies of rows 57, 60, 61 and 18 (#375)`.

## REPORT

The base and the commit; each row's copy count before and after; every changed line as line number with before and after; the sites left unchanged and why; the check's results; anything unverified; nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.

The per-host rule (the captains' channel line 1093, the keeper's 20:5xZ word): `export CARGO_BUILD_JOBS=4` at the start of every shell you open and before every `cargo` command (a build, a test, clippy, the ratchet, cargo-mutants); never two `cargo` invocations at once; `cargo mutants` only with `--jobs 1`; no `--all-targets` build you do not need. A lane that holds hundreds of `rustc` processes is stopped.
