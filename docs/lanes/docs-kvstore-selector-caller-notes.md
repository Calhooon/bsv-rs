Do every edit and every check yourself, in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write. Your logs live under your own folder on the lane volume, never the shared `$TMPDIR` or `/tmp`.

# Docs: the GlobalKVStore selector read doors state what the caller still checks after a selector read (documents only; the advisory GHSA-j4w5-4g84-q3f4)

Branch `lane/docs-kvstore-selector-caller-notes` from `origin/beta`'s tip, which carries the GlobalKVStore selector-filter fix (name the base sha in the REPORT). Never push to GitHub. Documents only: four rustdoc notes, one `## [Unreleased]` CHANGELOG entry and this record. No item, test, fixture or workflow changes; the non-comment code lines changed are 0.

## The four rows (what each read door checks and what it leaves to the caller)

The selector-filter fix (the security entry under `## [0.9.0-beta.10]`, the advisory GHSA-j4w5-4g84-q3f4) makes the returned set satisfy the query's controller, protocol and tags. These four notes record what the doors do not express, so a caller of each door reads what it still handles for itself:

1. `GlobalKVStore::get` matches the key under the store's configured protocol, takes no controller and returns the first entry for it; a key may be written by more than one controller, so a caller reads `entry.controller` when it expects a particular writer (corrected by the rule read of PR #1057: "the key alone" missed the protocol context).
2. `KVStoreQuery`'s `limit`, `skip` and `sort_order` are hints the overlay lookup service applies on its side, so the returned entries are unordered and a caller applies its own ordering or cap when it depends on one.
3. `KVStoreEntry`'s `value` is authenticated as its controller's own content rather than validated as safe input, so a caller parses and bounds it like any external input.
4. `GlobalKVStore::query` (and the `get_by_tags` wrapper) keeps every controller, tag set or protocol a member left unset admits (with a key, the configured protocol stands in for an unset protocol), keeps in the `any` mode an entry carrying one of the tags, and keeps every entry on an empty tag list in the `all` mode and none in the `any` mode, so a caller narrows the query or filters the returned `Vec` for a subset (corrected by the rule read of PR #1057: the `any` mode and the empty list in it do not match every entry).

## What was done

1. Row 1 in the `GlobalKVStore::get` rustdoc and row 4 in the `GlobalKVStore::query` rustdoc (`src/kvstore/global.rs`); row 2 in the `KVStoreQuery` type rustdoc and row 3 in the `KVStoreEntry` type rustdoc (`src/kvstore/types.rs`): the door a caller reads for each note. The README carries no caller-check list for this module and no row rises to a root-`CLAUDE.md` contract, so neither is touched.
2. A `### Docs:` entry at the top of the other entries under `## [Unreleased]`, naming what was added and where.
3. This record.
4. The gate in the foreground: the lint job's Rustfmt step; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`; `cargo test --doc` for the touched modules; `cargo test --test 'arch_*'`; `rows_from_sources.py --check` and its unittest; the ratchet against `origin/beta` with an outside `CARGO_TARGET_DIR`; gitleaks in git mode from the root over the one commit. One commit.

## REPORT

The base sha and the tip; the four rows and their rustdoc homes; the CHANGELOG entry; the gate table; anything unverified; nothing else.

Rules: no VM and no container on this machine (a Linux witness is CI's, a dispatch after the landing); never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).

The bounded block (the owner's form, 2026-11-01): every REPORT ends with four lines: the decision or verdict in one line; a confidence in [0.0, 1.0]; a rationale of at most three lines; the residual risks, each named and scored in [0.0, 1.0] (none is written "none, 0.0"). A read's verdict without the block is not a verdict; a lane's REPORT without it is not done.

The per-host rule (the captains' channel line 1093, the keeper's 20:5xZ word): `export CARGO_BUILD_JOBS=4` at the start of every shell you open and before every `cargo` command (a build, a test, clippy, the ratchet, cargo-mutants); never two `cargo` invocations at once; `cargo mutants` only with `--jobs 1`; no `--all-targets` build you do not need. A lane that holds hundreds of `rustc` processes is stopped.
