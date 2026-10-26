# Lane: fix-105-json-substrate-shapes. The HTTP JSON substrate's certificate `type` and flat key-linkage results, as BRC-100 and the TypeScript JSON substrate have them (#105)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 1, 2, 3; "Downstreams to keep in mind"), `src/wallet/CLAUDE.md`, `src/wallet/substrates/CLAUDE.md` if one exists, `tests/CLAUDE.md`, `docs/FIXTURES.md` (the http_json recordings), `docs/DEPENDENTS.md`, and issue #105 with its comments (the owner's word of 2026-10-26) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The finding (read from the issue, re-read at the pin)

BRC-100 at `5119a9b` (`~/bsv/brcs/wallet/0100.md`; the issue cites the `ed1b015` lines, the same text: find the lines at `5119a9b` and cite them) and the TypeScript JSON substrate at `ts-stack@edf6e03` (`~/bsv/ts-stack/packages/sdk/src/wallet/Wallet.interfaces.ts:775, 790, 869`; `substrates/HTTPWalletJSON.ts:81`) name the certificate's type field `type`; this crate's `HttpWalletJson` serializes `WalletCertificate`, `AcquireCertificateArgs`, `RelinquishCertificateArgs` and the certificate inside `ProveCertificateArgs` with `certificate_type` under `rename_all = "camelCase"` and no rename, so the JSON field is `certificateType` (`src/wallet/types.rs`, `src/wallet/substrates/http_json.rs`). The key-linkage results (`reveal_counterparty_key_linkage`, `reveal_specific_key_linkage`) deserialize a body nested under `linkage` with hex strings where BRC-100 and TS are flat with byte arrays (`RevealCounterpartyKeyLinkageResult`, `RevealSpecificKeyLinkageResult`, `KeyLinkageResult`, `hex_bytes` in `types.rs`). Read every cited line yourself at the pin and in the reference, and cite them.

## The work

1. **The certificate's `type`.** A serde rename (`#[serde(rename = "type")]`) on every certificate shape the JSON substrate carries, so the JSON field is `type` on the wire in both directions; the Rust field `certificate_type` stays (no Rust shape moves). Every shape the substrate serializes or parses that BRC-100 names differently is listed (grep the JSON substrate's types against the BRC's field tables for the certificate calls; say what else differs, fix it the same way or file it).
2. **The key-linkage results.** The JSON shape flat with byte arrays as BRC-100 and the reference have it (the exact field names and encodings from `Wallet.interfaces.ts` and the BRC); the Rust result types keep their fields if a serde shape (`#[serde(flatten)]`, a byte-array serializer) can carry it without a public type change; if the Rust type must change shape, STOP and report the exact change (the owner's 0.9.0 word covers a break, but say it before taking it).
3. **`spendable`**: no change; a stated line in the changelog and `CLAUDE.md`'s divergence list (the wire writes `1` for a module inventory record where BRC-207 at the pin permits `0`; nothing this crate serves is a module inventory).
4. **Rule 2.** RED-before: the JSON bodies this crate sends and accepts for the four certificate calls and the two linkage calls, pinned against the reference's JSON (build the reference's bodies with a Node script against `~/bsv/ts-stack` at `edf6e03`: `HTTPWalletJSON` serializing the same args and results; record them under `tests/vectors/` named for #105 with the commit and Node version; the script under `tests/support/`); the http_json recordings (`tests/fixtures/http_json/`) re-recorded in their own commit with the diff explained (`docs/FIXTURES.md`: every changed byte named); no vector edited. A TypeScript client's body parsed here and this crate's body parsed by the reference's substrate both round-trip (the script does both directions).
5. **Docs**: the changelog's `### Fixed` entry with the citations and the consumer note (the toolbox's and the CLI's JSON wire: the two field shapes move with them in the next prerelease; both told); `src/wallet/CLAUDE.md`; `CLAUDE.md`'s divergence list (the #105 items leave it if they were there; `spendable` joins it).

Public shape: serde attributes only; if a Rust public field or type must move, STOP and report.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every wallet and wire test file: `for f in $(ls tests | grep -E '^(wallet_|wire_|http_|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib wallet --features "full,http"`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-105-json-substrate-shapes` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#105)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the BRC and reference lines read; every JSON field that moved (old name, new name, the shape); whether a Rust shape had to move (STOPPED or not); the reference's bodies and this crate's side by side (the script's output); the recordings changed and why; the green run (every gate command with its result line); anything you could not do and why.
