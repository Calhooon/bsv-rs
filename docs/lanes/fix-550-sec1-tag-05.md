Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #550: `PublicKey::from_bytes` and `from_hex` refuse a SEC 1 tag `05` as the reference does (`Point.ts:303-325`); the sites that read through `from_bytes` pinned

Branch `lane/fix-550-sec1-tag-05` from `origin/beta` (name the base sha in your REPORT; #544 and, if landed, #545 and #548 before you start: `git log origin/beta -12`). One commit. Never push. Nothing is filed on any tracker. A parity row at the pin, 0.9.0 (`gh issue view 550`, the site list in its body).

## The finding (PR #547's fold and its scoped read)

k256 / sec1 0.8.1 (`src/point.rs:521-533` in the sec1 crate) reads a SEC 1 tag `05` as a compact point, so `PublicKey::from_bytes(05 || Gx)` yields the key `02 || Gx` on beta, where the reference refuses the tag at `Point.ts:303-325` (edf6e03; read `fromDER` whole: the prefixes it accepts are `02`, `03`, `04`, `06`, `07`; anything else is `Unknown point format`). `from_hex` (the lenient parser of #498, `src/primitives/ec/public_key_forms.rs`) accepts `05` on beta too. The sites that read a key through `from_bytes` with no prefix check, from the read's list: `src/kvstore/interpreter.rs:170`, `src/messages/signed.rs:170,205`, `src/script/templates/pushdrop.rs:289,335` (where a `05` locking key passes `decode_before` and the token is then refused as `PushDrop token must use the canonical PushDrop envelope`, the reference saying `Unknown point format`), and the others the issue lists; guarded already: the script interpreter (`src/script/spend/crypto.rs:397-407`, in every mode).

## The shape

1. `from_bytes` refuses a `05` tag before k256 reads it (the SEC 1 tags the reference reads and no other: `02`, `03`, `04`; `06`/`07` only where the lenient path handles them, as #498 landed it: read `public_key_forms.rs` and keep its contract); `from_hex` refuses `05` the same way; the refusal's error class the one the strict path uses (`InvalidPublicKey` or its named variant); the words the reference's where a site forwards them to a caller.
2. Pins RED on the base: `from_bytes(05 || Gx)` refused (today it returns `02 || Gx`); `from_hex("05" + Gx)` refused; at each listed site a token or message carrying a `05` key takes the reference's outcome (the reference's words recorded where the site's refusal reaches a caller: extend the recorder pattern, `tests/support/sec1_tag_05_550.mjs` against the edf6e03 bundle, the vector `tests/vectors/sec1_tag_05_550.json`, never by hand; where the reference swallows, the silent outcome).
3. The script interpreter's guard untouched; `tests/vectors/public_key_forms_498.json` unchanged (if the vector carries a `05` case, say what it recorded).

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: a SEC 1 tag 05 is refused as the reference refuses it (#550)` section (never a bare bullet) with old and new (the compact form read as a key before, the sites' outcomes), the recorder and vector; the root `CLAUDE.md` divergence row closed by this landing (at the END of the list) with its census line; `src/primitives/CLAUDE.md`'s row for the key parser; `src/primitives/ec/CLAUDE.md`.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib primitives`, `--lib kvstore`, `--lib messages`, `--lib script` (one filter per run); one `--test` per file matching `ec_*`, `primitives_*`, `kvstore_*`, `messages_*`, `script_*`, `registry_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; `cargo fuzz` is not required, but say whether a parser fuzz target covers `from_bytes`.

## REPORT

Tip sha and message; the base; the parser's change with the reference's lines; the sites' outcomes (a table: site, before, after, the reference's); the recorder's command and the vector's cases; the RED evidence; the rows; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
