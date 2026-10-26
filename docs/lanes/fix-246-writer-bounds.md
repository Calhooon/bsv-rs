# Lane: fix-246-writer-bounds. The wallet wire's certificate writer refuses what the reference's writer refuses (three bounds) and writes the fields in the signed order (#246)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in the worktree cca gives you on a branch from `origin/beta`. Read issue #246 with every comment (the #189 lane's finding; the #248 review's sharpening: three bounds, and the wire order), `CLAUDE.md` (rules 1, 2, 3, 5, 6, 7), `src/wallet/wire/CLAUDE.md`, `src/auth/CLAUDE.md` (the #249 entry: the collation order), `docs/FIXTURES.md`, `docs/lanes/README.md` (the lane rules; everything foreground, under ten minutes; never `~/bsv/bsv-low/` or `~/vault/`). You never push, tag or open a PR; you commit on your branch and end with the REPORT. `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-246` (`mkdir -p` it before the run).

## 1. The three bounds (the keeper's rule on #183: the writer never makes a frame the reference's reader refuses)

`Certificate.ts` at `ts-stack@edf6e03` refuses more than 100,000 fields (`:57-58`), a field value over 1 MiB (`:76-79`) and a frame over 16 MiB (`:316-320`); this crate's reader refuses all three (`src/wallet/wire/mod.rs:234-244`, `:260-264`), `WireWriter::write_wallet_certificate` (`src/wallet/wire/encoding.rs`, `certificate_bytes`) none. Add the three checks to the writer (the count ahead of the loop, the value length inside it, the total ahead of the return) with the readers' words; one RED-before test per bound; no recording or vector moves (`git diff -- tests/vectors tests/fixtures` empty).

## 2. The field order: the signed order, not byte order

The #248 review read the wire order as a stated divergence (the reference's and Go's readers insert into a map, requiring no order). That reading predates #249's landing on beta (`0266ba2`): this crate's `Certificate::from_binary` now keeps the received unsigned prefix and `verify` checks the signature over those bytes as received (BRC-52 `0052.md:103`'s retained bytes), and `Certificate::sign` serializes the fields in the reference's `localeCompare` order from the collation table (`src/auth/certificates/collation.rs`, `collation_latin1.txt`). So a wire frame this writer emits in byte order for a certificate signed in the collation order does not verify when read back by this crate's own reader, while the reference's reader re-sorts and does. Read `certificate_bytes`'s sort and the reference's writer (`Certificate.ts:282`, the sort before writing); make the wire writer sort with the same collation the signature uses (one function, shared with `serialize_unsigned`: read how it is exposed and reuse it, never a second table), so this crate's frame equals the reference's writer's bytes for the same certificate and verifies on both readers. Rule 2: a test red on the tip: a certificate with the mixed names of #249's witness (`a_b, a0, age, éa, f, Name`) signed here, written to the wire by `write_wallet_certificate`, read back by `read_wallet_certificate` into a `Certificate` whose `verify` passes (red today: the byte order mismatches the signed order), and the frame's bytes equal to the reference's `toBinary(true)` for the same certificate (the Node bundle at `edf6e03`: the recipe `git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C $TMPDIR/x`, `bun build mod.ts --target node --format esm --outfile ...`, run under `~/.nvm/versions/node/v22.18.0/bin/node`; extend `tests/support/certificate_field_order_249.mjs` or write a sibling for #246, the vector under `tests/vectors/`). The divergence line the issue proposed is not written; `CLAUDE.md`'s list gains nothing; the changelog says the writer's order is the signed order and why.

## Docs

The changelog entry (the three bounds with the reference lines and the readers' words; the order; the tests); `src/wallet/wire/CLAUDE.md` rows; `tests/CLAUDE.md`. `cargo semver-checks check-release --baseline-rev origin/beta --features full --release-type minor` (no shape change: the line).

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `for f in $(ls tests | grep -E '^(wire_|wallet_|auth_|http_|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib --features "full,http" -- wallet auth`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; the fuzz crate's `cargo check`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` (never re-record a baseline).

## Rules

No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#246)`; bodies say what and why; end with the Co-Authored-By line the session gives you. One concern per commit: the bounds, the order, the docs.

## REPORT (the last thing you print)

`REPORT` then: the base sha, the tip sha and each commit; the three bounds' words beside the readers'; the order function reused; the RED runs then green; the reference's bytes beside this crate's; the green run (every gate command with its result line); anything you could not do and why.
