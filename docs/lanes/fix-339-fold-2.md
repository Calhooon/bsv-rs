# #339 fold two: the re-review's two findings on `lane/fix-339-review-actions-body` (at dd0020d on 1cdd149)

Work in this worktree on the branch as it stands (five commits; the fold of 2914355 and dd0020d re-reviewed on Opus: FIX, two findings, two notes; the REPORT is in `cca runs --show review-339-fold` on this box). Read `src/wallet/substrates/CLAUDE.md`, `tests/CLAUDE.md`, the branch's changelog entry. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL; every HTTP test binds its own wiremock server.

## The re-review's findings

1. `src/wallet/types.rs:707` and `:1095` (read at `src/wallet/substrates/http_json.rs:226-229`): a 200 createAction or signAction body whose `tx` is in the object form, or an array holding `1.0`, is refused here and accepted by the reference (`HTTPWalletJSON`'s success path normalizes it through `normalizeBRC100ByteArray` too). Read the success `tx` through `byte_array` (the one reader for both paths), with the two bodies recorded by the recorder against the reference and pinned (the vector grows by two; a rerun byte for byte), RED before green.
2. `CHANGELOG.md:335`: the envelope divergence's reason names the `asStatus` bodies, which carry no `isError` and never reach the envelope words; it is the toolbox's `toJson` bodies (`isError`, `name`, `message`, no `code`) the words would refuse. Say so; the divergence and its pin stand.

## The re-review's notes (state, do not widen)

- `http_json.rs:191`: a byte written `1e400` fails the whole JSON parse, so this crate answers `HTTP 400 …` where the reference answers `Invalid createAction result tx: expected an array of bytes`; both refuse, the words differ: a sentence in the parity note.
- The other success-path byte fields (`signature`, `ciphertext`, `hmac`, and the rest the reference cleans) are read as plain arrays here: the captain files it; name it in the parity note as a stated difference, unchanged in this fold.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `wallet_*`, `wire_*`, `identity_*`, `transport_fault_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib wallet`; `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1cdd149`; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit, the success path's reading and its two pins, the envelope sentence as it now reads, the notes stated, RED then green, the gate's results, anything unverified.
