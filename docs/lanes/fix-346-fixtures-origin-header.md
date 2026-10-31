Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #346: the public-surface fixtures capture the `Origin` header beside `Originator`, so both headers the JSON substrate sends are pinned by the fixtures

Branch `lane/fix-346-fixtures-origin-header` from `origin/beta` (name the base sha in your REPORT). One commit. Never push.

## The finding (the #323 CI fold's re-review, Opus, 2026-10-27; `gh issue view 346`)

The fixtures' recorder (`tests/support/fixtures/`, read its `CLAUDE.md` or README first, and `.github/workflows/ci.yml`'s `fixtures` job for how CI checks them) captures the HTTP JSON substrate's `originator` header only; since #323 the substrate sends `Origin` and `Originator` both in the origin form (the reference's `HTTPWalletJSON.ts:311-314` at `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/`), and `Origin` is pinned by `tests/wallet_http_originator_323.rs` alone.

## The shape

1. The recorder's format grows one member for the `Origin` header (named as the recorder names headers; read how `originator` is captured and mirror it); the replay (`tests/fixtures_replay.rs` and whatever reads the fixtures) asserts it like the others.
2. The fixture files under `tests/fixtures/http_json/` (the issue counts 30; count them) are re-recorded by the recorder, never hand-edited: run the recorder as its docs say (hermetic: a wiremock or the recorder's own fake server on an ephemeral port; never a default URL or port, a MetaNet Client listens on 3301, 3321 and 2121 on this machine); then `git diff` every file and show that every other member is unchanged (the diff adds the one member per request and nothing else; if the recorder's run moves another member, that is a finding to report, not to hand-fix).
3. RED before the fix on a scratch copy of the base: the replay against a fixture carrying the `Origin` member fails (the member unknown or unasserted); on the tip it passes; and on the tip, a substrate that stopped sending `Origin` fails the replay (mutate the header's send site in a scratch copy and show the replay red).
4. `tests/wallet_http_originator_323.rs` stays (the fixtures pin the header beside it).

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib wallet`; one `--test` per file matching `wallet_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; the `fixtures` CI job's command as `ci.yml` runs it; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Changed: the fixtures capture the Origin header beside Originator (#346)` section (never a bare bullet): the finding, the member added, the count of files re-recorded with every other member unchanged, the pins; the fixtures' `CLAUDE.md`/README row for the format; `tests/CLAUDE.md`'s row if it describes the fixtures' members.

## REPORT

Tip sha and message; the base; the recorder's command and the file count; the diff's reading (the one member per request, nothing else); the RED evidence (both directions); the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
