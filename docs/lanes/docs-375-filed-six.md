Do every edit and every gate yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane. Your logs and evidence live under `/Volumes/Lanes/out/bsv-rs/docs-375-filed-six/`, never the shared `$TMPDIR` or `/tmp`.

# The first six upstream filings carried onto the census rows and the queue (docs only)

Branch `lane/docs-375-filed-six` from `origin/beta`'s tip (name the base sha in your REPORT). Docs only: `CHANGELOG.md` (census lines), `CLAUDE.md` (divergence rows), `docs/lanes/375-filings/QUEUE.md` and the six draft files under `docs/lanes/375-filings/`. Nothing is filed on any tracker by you; nothing else changes. Never push.

## The word (the keeper, captain-bsv-stack-lean, 2026-10-31 16:3xZ, relaying the owner's ruling of 16:2xZ)

The owner ruled the filings cadence (b). The first six drafts are filed under the owner's name by the keeper, from the drafts as they stand on beta (the internal provenance lines dropped, a census pointer added, nothing else changed):

| queue row | repository | draft | filed as |
|---|---|---|---|
| 3 | bsv-blockchain/ts-stack | `merkle-lone-leaf-offset.md` | bsv-blockchain/ts-stack#1460 |
| 4 | bsv-blockchain/ts-stack | `beef-empty-transactions.md` | bsv-blockchain/ts-stack#1461 |
| 7 | bsv-blockchain/ts-stack | `beef-reserved-flags-ts-stack.md` | bsv-blockchain/ts-stack#1462 |
| 5 | bsv-blockchain/go-sdk | `atomic-unrelated-data.md` | bsv-blockchain/go-sdk#396 |
| 6 | bsv-blockchain/go-sdk | `beef-duplicate-offsets-go-sdk.md` | bsv-blockchain/go-sdk#397 |
| 8 | bsv-blockchain/go-sdk | `canonical-varint-reader.md` | bsv-blockchain/go-sdk#398 |

The remaining twelve go two a day per repository in the queue's order from 2026-11-01; the keeper files them from the drafts as they stand, so a draft to be changed is changed on beta before its day. The port re-pins both ways, as ts-stack #1451 does: the upstream issue carries the census pointer (the keeper's side, done); the census row and the queue carry the upstream number (this lane).

## What to do

1. Read `docs/lanes/375-filings/QUEUE.md` whole and the six draft files: how a filed draft is marked (the `FILE` line or status cell: read how #1451, #1449, #1446, #1437, #1436 are carried in `QUEUE.md`, `CHANGELOG.md` and `CLAUDE.md`: `grep -n '1451\|1449\|1446\|1437\|1436'` on all three; match that form exactly). For each of the six: the queue row's status and the draft's `FILE` line become "filed as <repo>#<n> on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending", in the form the precedent uses.
2. The census rows: each draft names the divergence row(s) it covers (its census pointer); for each such row, every copy in `CHANGELOG.md` (`grep -n '^- Row <N>:'`: the entry's copy and the census paragraphs' copies) and the row in `CLAUDE.md` turn "Theirs: <repo>, filing pending" (or the equivalent wording) into "Theirs: <repo>#<n> (filed 2026-10-31; answer pending)", in the precedent's form, with the same words in every copy (`grep -c` the count before and after: the number of copies is unchanged; no other row's text moves). A row a draft covers that says something other than "filing pending" (an earlier number, a different status) is a finding: say so, change nothing there.
3. Nothing else: no entry under `[Unreleased]` (a docs change to the census and the queue is not a crate change; if the precedent's landings carried an entry, say so and follow it), no code, no other row.
4. The gate, in the foreground: `cargo test --features "full,http"` with one `--test` per file matching `arch_*` and `fixtures_replay*` (the `.rs` files); `cargo test --doc --all-features`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout (the census counters read the rows: a count that moves is a finding, not something to fix by reshaping); `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit: `docs(375): the first six filings carried onto the census rows and the queue (ts-stack #1460 #1461 #1462, go-sdk #396 #397 #398)`.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

## Report

The base sha and the tip; the six drafts mapped to their rows (draft, repository, number, the row numbers, the copies per row before and after); the queue's and the drafts' lines changed; any finding; the gate table; anything unverified; nothing else.
