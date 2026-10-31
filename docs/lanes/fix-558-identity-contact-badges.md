Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #558: `from_identity` carries an identity's badges into the contact and `to_displayable_identity` returns the stored ones, as the reference does (`IdentityClient.ts` at ts-stack edf6e03): read first

You are on a fresh worktree of `lane/fix-558-identity-contact-badges` at beta's tip (`git rev-parse --short HEAD`: record it as the base in the REPORT; it carries #554's closed `Contact`: `Contact::new(name, identity_key)` and the `with_` setters, no literal from outside the type's module). Never push. Nothing is filed on any tracker. Your logs, scratch copies and evidence live under `/Volumes/Lanes/out/bsv-rs/fix-558-identity-contact-badges/`, never the shared `$TMPDIR` or `/tmp`.

## The finding (issue #558; the keeper's reading of 2026-10-31 13:1xZ: two rows of one record)

This crate's `Contact::from_identity` (or where the identity-to-contact conversion lives: `src/identity/`, grep `from_identity`, `to_displayable_identity`, `DisplayableIdentity`) does not copy an identity's badge fields (`badgeIconURL`, `badgeLabel`, `badgeClickURL`) into the contact, and `to_displayable_identity` returns fixed badges rather than the ones the contact stores. #554 (#552) gave `Contact` the three badge fields; these two conversions are the residue.

## Read first, then decide

The reference, read whole before a line is written: `IdentityClient.ts`'s `DisplayableIdentity` and `parseIdentity` (`:1044` and what follows: which badge values an identity carries, from which certificate types, with which defaults), and the contacts manager (`ContactsManager.ts`): whether the reference converts an identity into a contact anywhere (grep the packages for a function building a contact from a `DisplayableIdentity`, and for the reverse); the reference's own UI or wallet code if the SDK has none (the ts-stack packages only; nothing under `~/bsv/bsv-low/`, nothing under `~/vault/`, no grep across `~/bsv/` as a whole). Three outcomes, say which with lines:

- (a) the reference converts in both directions and carries the badges: the port does the same; the work below.
- (b) the reference has the conversion in one direction only (say which): the port's other direction is a port convenience, left as is but documented as one (its doc comment and the row), and the direction the reference has is fixed; the work below for that direction.
- (c) the reference has neither: both conversions are port conveniences; no code changes; the deliverable is the reading on the root `CLAUDE.md` row (rewritten to say what the reference has and what the port adds, open, pointing at #558) and in `src/identity/CLAUDE.md`; the captain closes or re-files from your REPORT.

## The work (for the direction(s) the reference has)

1. The conversion carries the badge fields as the reference's does (the same defaults where unset); nothing else changes.
2. The witness, recorded, never by hand: `tests/support/identity_contact_badges_558.mjs` under Node 22 against the edf6e03 bundle (the harness of `tests/support/contact_badges_552.mjs`): an identity with badges converted by the reference and the result the port must equal (and the reverse where the reference has it), into `tests/vectors/identity_contact_badges_558.json`; `tests/identity_contact_badges_558.rs` runs the vector: RED on the base (a scratch copy at the base with its own target dir; report the count), green on the tip.
3. The entry under `[Unreleased]` as a `### Fixed:` section carrying old and new; the root `CLAUDE.md` row for #558 (one copy, at the END of the list) closed by this landing (the captain adds the sha); `src/identity/CLAUDE.md`, `tests/CLAUDE.md`.
4. Semver: `cargo semver-checks check-release --baseline-rev <base> --release-type patch`; a changed return value of a public function has no lint, so say in the entry what moved.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib identity`; one `--test` per file matching `identity_*`, `contacts_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); the semver run; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit at the end.

## REPORT

The base sha and the tip; the reading with lines and the outcome (a, b or c); the port's sites and the change, if any; the vector's cases; the RED count on the base and the tip's; the entry and the rows; semver; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first; your logs, scratch copies and evidence live under your own folder on the lane volume, `/Volumes/Lanes/out/bsv-rs/<lane name>/`, never the shared `$TMPDIR` or `/tmp`, and no command of yours globs or lists a shared folder (the captains' channel line 1082, 2026-10-31).
