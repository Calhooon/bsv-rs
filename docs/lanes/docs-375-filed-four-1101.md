Do every edit and every gate yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane. Your logs and evidence live under `/Volumes/Lanes/out/bsv-rs/docs-375-filed-four-1101/`, never the shared `$TMPDIR` or `/tmp`.

# The cadence's first day: four upstream filings of 2026-11-01 carried onto the census rows and the queue (docs only)

Branch `lane/docs-375-filed-four-1101` from `origin/beta`'s tip (name the base sha in your REPORT). Docs only: `CHANGELOG.md` (census lines), `CLAUDE.md` (divergence rows, where a row of these four has one), `docs/lanes/375-filings/QUEUE.md` and the four draft files under `docs/lanes/375-filings/`. Nothing is filed on any tracker by you; nothing else changes. Never push.

## The word (the keeper, captain-bsv-stack-lean, 2026-11-01 00:0xZ; the owner's cadence (b))

The keeper filed the cadence's first day at 00:00:42Z under the owner's name from the drafts as they stand on beta (the internal lines dropped, the census pointer added, nothing else changed):

| queue row | repository | draft | filed as | created |
|---|---|---|---|---|
| 1 | bsv-blockchain/go-sdk | `wire-originator.md` | bsv-blockchain/go-sdk#399 | 2026-11-01T00:00:43Z |
| 2 | bsv-blockchain/go-sdk | `wire-numeric-collection-bounds.md` | bsv-blockchain/go-sdk#400 | 2026-11-01T00:00:47Z |
| 11 | bsv-blockchain/ts-stack | `certificate-outpoint-bound.md` | bsv-blockchain/ts-stack#1463 | 2026-11-01T00:00:51Z |
| 12 | bsv-blockchain/ts-stack | `wire-input-index-width.md` | bsv-blockchain/ts-stack#1464 | 2026-11-01T00:00:55Z |

Fifteen filed in all after these four; eight remain (rows 9, 10 and 13 to 18), the next pairs on 2026-11-02. Verify each number yourself: `gh issue view <n> --repo <repository> --json number,title,author,createdAt` (the title equals the queue row's; the author is the owner's login). The port re-pins both ways, as the six of 2026-10-31 do (`099d5d98`): the upstream issue carries the census pointer (the keeper's side, done); the census row and the queue carry the upstream number (this lane).

## What to do

1. Read `git show 099d5d98` whole: it is the precedent, the six filings carried in the same four places. Match its form exactly, with the date 2026-11-01: in `docs/lanes/375-filings/QUEUE.md` the row's title cell gains "(filed as <repository>#<n> on 2026-11-01 ...)" as rows 3 to 8 have it; in each draft, the `FILE` line at the top and the "Prepared for filing by Calhooon (owner). Draft only; no issue was created." sentence become the filed form the six carry ("Filed as <repository>#<n> on 2026-11-01 under the owner's name (cadence (b) ...); answer pending."), the census pointer that follows kept as it is.
2. The census rows: `wire-originator` is census row 9, `wire-numeric-collection-bounds` row 10, `certificate-outpoint-bound` row 47, `wire-input-index-width` row 44 (each draft's line 7 names its row; read it, and read the row's text to be sure the draft is the row's). For each row, every copy in `CHANGELOG.md` (`grep -n '^- Row <N>:'`; the entry's copy and the census paragraphs' copies; count them before and after) and the row's line in `CLAUDE.md`'s divergence list if the row has one (`grep -n` the row's words) turn "Theirs: <repository>, filing pending" (or the equivalent wording the row carries) into "Theirs: <repository> #<n> (filed 2026-11-01; answer pending; the witness: <the row's witness files, as the six name theirs>)", in the precedent's form, with the draft link as the six carry it. Every copy, the same text; a row with no "Theirs" clause gets one in the precedent's form; a row whose text the precedent did not touch is a finding to report, not a guess.
3. Nothing else: no entry under `[Unreleased]` (the precedent carried none: check `git show 099d5d98 -- CHANGELOG.md` and say what you read), no code, no other row, no other draft.
4. The gate, in the foreground: `cargo test --features "full,http"` with one `--test` per file matching `arch_*` and `fixtures_replay*` (the `.rs` files); `cargo test --doc --all-features`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout (the census counters read the rows: a count that moves is a finding, not something to fix by reshaping); `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; `git diff --name-only <base> HEAD` names only `CHANGELOG.md`, `CLAUDE.md` (if a row of these four is there), `docs/lanes/375-filings/QUEUE.md` and the four drafts. One commit: `docs(375): the cadence's first day carried onto the census rows and the queue (go-sdk #399 #400, ts-stack #1463 #1464)`.

## Report

The base sha and the tip; the four drafts mapped to their rows (draft, repository, number, the row number, the copies per row before and after, the CLAUDE.md row if any); the queue's and the drafts' lines changed; any finding; the gate table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).
