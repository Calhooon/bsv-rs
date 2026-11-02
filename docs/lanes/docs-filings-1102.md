Do every edit and every check yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write. Your logs live under `/Volumes/Lanes/out/bsv-rs/docs-filings-1102/`, never the shared `$TMPDIR` or `/tmp`.

# Docs: the four upstream filings of 2026-11-02 00:00Z carried onto `docs/lanes/375-filings/QUEUE.md` (rows 9, 10, 13, 18) and every other site that names those drafts as unfiled

Branch `lane/docs-filings-1102` from `origin/beta` (name its sha in your REPORT). Never push. Docs only: no file under `src/`, `tests/`, `benches/`, `fuzz/`, no vector, no `Cargo.*`.

## The facts (the keeper's word of 2026-11-02 00:0xZ; the captain checked each title against its issue through the API)

Filed on 2026-11-02 at 00:00Z under the owner's name by the keeper's detached script, from the drafts as they stood on beta (cadence (b)):

- row 9, `docs/lanes/375-filings/certificate-bounds-der.md`: bsv-blockchain/go-sdk#401, "Certificate wallet conversion rewrites valid high-S signature bytes"
- row 10, `docs/lanes/375-filings/certificate-response-preimage-go-sdk.md`: bsv-blockchain/go-sdk#402, "Preserve certificate-response property order when signing and verifying"
- row 13, `docs/lanes/375-filings/create-action-positive-script-length-ts-stack.md`: bsv-blockchain/ts-stack#1466, "Refuse zero unlockingScriptLength as BRC-100 specifies"
- row 18, `docs/lanes/375-filings/public-key-unreduced-coordinate-serialization.md`: bsv-blockchain/ts-stack#1467, "Reduce or refuse an unreduced public key coordinate at parse, and serialize the point computed with rather than the coordinates given"

The next pair (go-sdk rows 14 and 15) files at 00:00Z on 2026-11-03 from the drafts as they stand on beta at that hour. The numbers are on bsv-rs#375 already (the captain's comment).

## What to do

1. Read `docs/lanes/375-filings/QUEUE.md` in full: the table, the rule above it ("After filing, put the filed number on bsv-rs#375 and in the row's verdict clause"), and the prose below it that counts and names the filed rows and the pending ones. Give each of the four rows the filed clause in the shape the filed rows already carry (row 7's cell is the model: the title, then `(filed as <repo>#<n> on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending)`), word for word in that shape, the number and date exact. Rewrite the prose so it is true after the four: which rows are filed (with their numbers), which stand pending and when the next pair files; keep every sentence that is still true byte for byte.
2. Grep (case-insensitively, across line breaks) `docs/`, `HANDOFF.md`, `README.md` and `CLAUDE.md` for the four drafts' file names, their titles and the words "unfiled", "to be filed", "not yet filed", "pending filing" near them; every site that says one of the four is unfiled is corrected to name its number; a count of filed or pending drafts anywhere is re-counted from the table and corrected. A site you are unsure of is listed in the REPORT, not changed.
3. The check: `cargo test --test 'arch_*'` (`export CARGO_BUILD_JOBS=4`; one cargo at a time; `CARGO_TARGET_DIR` outside the checkout) green; `tools/ratchet/run --check --against origin/beta` green; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit: `docs(filings): the 11-02 filings on QUEUE.md rows 9, 10, 13 and 18 (#375)`.

## REPORT

The base sha and the commit; the four cells after the edit, quoted; every other site changed as file:line with before and after; the sites left unchanged and why; the check's results; anything unverified; nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.

The per-host rule (the captains' channel line 1093, the keeper's 20:5xZ word): `export CARGO_BUILD_JOBS=4` at the start of every shell you open and before every `cargo` command (a build, a test, clippy, the ratchet, cargo-mutants); never two `cargo` invocations at once; `cargo mutants` only with `--jobs 1`; no `--all-targets` build you do not need. A lane that holds hundreds of `rustc` processes is stopped.
