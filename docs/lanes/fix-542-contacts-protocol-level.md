Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #542: the contacts manager encrypts, locks and signs under the reference's protocol `[2, 'contact']`, not security level 1; each side's contact records readable by the other

Branch `lane/fix-542-contacts-protocol-level` from `origin/beta` (name the base sha in your REPORT; #541 landed at b51cbea7). One commit. Never push. Nothing is filed on any tracker. The keeper's reading (2026-10-31 07:1xZ, recorded in issue #542: `gh issue view 542`): a cross-implementation incompatibility, the god-tier bar's kind of row, a parity row at the pin.

## The finding (PR #541's review, verified against ts-stack edf6e03)

The reference's `ContactsManager.ts:30` (`~/bsv/ts-stack/packages/sdk/src/identity/ContactsManager.ts`) uses the protocol `[2, 'contact']` for every contact operation (read the whole file: the encrypt/decrypt calls, the locking key derivation of the contact token, the signature, the key ID). This crate's `src/identity/types.rs:527` holds the config `(2, "contact")`, but `src/identity/contacts_cache.rs:86`, `src/identity/contacts_actions.rs:39,330` and `src/identity/contacts.rs:203` hard-code `SecurityLevel::App` (level 1), so the derived keys differ: a contact ciphertext written by one side cannot be decrypted by the other, and the token's locking key and signature differ too.

## The shape

1. Every contact site uses the protocol the reference uses (`[2, 'contact']`: security level 2, protocol name `contact`, the key ID as the reference passes it, the counterparty as the reference passes it), read from the config at `types.rs:527` rather than hard-coded; nothing else about the contacts manager changes.
2. The witness, recorded, never by hand: a recorder `tests/support/contacts_protocol_542.mjs` (the pattern of `tests/support/kvstore_local_parser_words_489.mjs`: Node 22 against the bundle of edf6e03, the captain's memory `run-ts-reference-at-a-commit`: a git archive built with bun) that, with a `ProtoWallet` on a fixed private key, runs the reference's `ContactsManager` to encrypt a contact record (and build its token: the locking script and the signature field) and records the inputs and outputs into `tests/vectors/contacts_protocol_542.json`; the test decrypts the reference's ciphertext with this crate's contacts manager on the same key (RED on the base: the wrong derived key), and encrypts the same record here and checks the reference's `ContactsManager` decrypts it (recorded in the vector as the reference's verdict on this crate's base output and on the expected output: the recorder takes this crate's ciphertext as an input if the shape allows; else the witness is the derived key bytes compared, said plainly). The locking key and the signature of the token compared the same way (the reference's bytes in the vector; the port's equal on the tip, RED on the base).
3. Tests are hermetic (rule 4): a `ProtoWallet` in process; no network, no default port.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: the contacts manager uses the reference's contact protocol (#542)` section (never a bare bullet) carrying old and new (the level and protocol before and after; the consequence: records readable across implementations; the toolbox has no contacts path, the CLI's tables unchanged), the keeper's reading, the recorder and vector; the root `CLAUDE.md` divergence list: a row for the difference closed by this landing (at the END of the list), its census line under the entry; `src/identity/CLAUDE.md`'s rows for the four files.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib identity`; one `--test` per file matching `identity_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch` (no public change expected: say what it reports); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the base; the four sites' change with the reference's lines; the recorder's command and the vector's cases; the RED evidence (the base's wrong key, the tip's match; the locking key and signature); the rows; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
