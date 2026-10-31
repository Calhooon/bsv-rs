Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #552: `Contact` carries the reference's three badge fields through read and write, so a reference contact's badges survive a round trip through the port's update

Branch `lane/fix-552-contact-badge-fields` from `origin/beta` (name the base sha in your REPORT; #544 has landed as PR #551 before you start: read its contacts commit, `git log origin/beta -10` and `git show <the contacts commit> -- src/identity`). One commit. Never push. Nothing is filed on any tracker. A parity row at the pin, 0.9.0, before #545, #548 and #550 (`gh issue view 552`: the keeper's reading of 2026-10-31 12:1xZ).

## The finding (the keeper's reading at ts-stack edf6e03)

`validateContact` (`~/bsv/ts-stack/packages/sdk/src/identity/ContactsManager.ts:171-192`) takes every one of the seven display fields (`name`, `avatarURL`, `abbreviatedKey`, `identityKey`, `badgeIconURL`, `badgeLabel`, `badgeClickURL`, `:35-43`) through `ownData` (`:47-53`: a missing key throws "must be an own data property") and then its validator (`:75` refuses a non-string), so a record the reference reads carries all seven keys as strings, the badge fields empty where unset. This crate's `Contact` (`src/identity/`, after #544) has no badge fields: it writes them empty, drops a reference contact's badges on read, and a round trip through the port (read, update another field, save) erases the reference's badge data.

## The shape (additive)

1. `Contact` carries `badgeIconURL`, `badgeLabel` and `badgeClickURL` through read and write: the record written with the reference's spellings and the values the port holds (empty strings where unset, as the reference writes them); the record read into the port's type with the three fields kept; the port's own field names as its other fields are named (read the type and its serde attributes; a public struct gaining three fields is an addition: say how a downstream literal of `Contact` is affected, if the struct is built by a literal outside the crate, and whether `#[non_exhaustive]` or a constructor already covers it; a shape that the keeper did not word is a finding to state, not to invent: keep to the additive fields).
2. The witness, recorded, never by hand: extend `tests/support/token_envelope_544.mjs` or add `tests/support/contact_badges_552.mjs` (Node 22 against the edf6e03 bundle, a `ProtoWallet` on a fixed key): the reference saves a contact with the three badges set; the port reads it, updates another field (the name), saves; the reference's `ContactsManager` reads the port's saved token back and the record equals the original with the badges intact (recorded as the reference's verdict and the read-back record in `tests/vectors/contact_badges_552.json`); RED on the base (the badges erased). The reverse: a contact saved by the port with badges read by the reference with the badges present.
3. Hermetic (rule 4): a `ProtoWallet` in process; no network, no default port.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: Contact carries the reference's badge fields through read and write (#552)` section (never a bare bullet) carrying old and new (a reference contact's badges erased by an update before; the toolbox has no contacts path and the CLI none, said plainly), the keeper's reading, the recorder and vector; the root `CLAUDE.md` divergence row closed by this landing (at the END of the list) with its census line under the entry; `src/identity/CLAUDE.md`'s rows.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib identity`; one `--test` per file matching `identity_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type minor` (say what it reports; the added fields named); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the base; the type's change and the serde shape with the reference's lines; the downstream-literal reading; the recorder's command and the vector's cases; the RED evidence both ways; the rows; semver's reading; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
