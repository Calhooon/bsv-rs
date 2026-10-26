# Fold lane: fix-268-fold. The reference's default txid-only revocation outpoint read as index 0; one changelog sentence (#268)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), continuing in the worktree of `lane/fix-268-certificate-json` (tip `ffc810e`, your own four commits over `0f1514c`, `origin/lane/fix-261-field-value-bytes`; `git status` clean, else say so). Read the cold review's REPORT (`cca runs --show review-fix-268`; never its transcript), issue #268, `CLAUDE.md` (rules 1, 2, 3, 5, 7), `src/auth/CLAUDE.md`, `src/identity/CLAUDE.md`. You never push, tag or open a PR; you commit on this branch and end with the REPORT. Every command foreground and under ten minutes; `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-268-certificate-json`. Never `~/bsv/bsv-low/` or `~/vault/`; grep the dependents by their explicit paths.

## Fold 1, the reader (code)

The reference's default issuance writes `revocationOutpoint` as 64 hex characters with no index (`~/bsv/ts-stack` at `edf6e03`, `MasterCertificate.ts:442`, `'00'.repeat(32)`), accepted by `assertRevocationOutpoint` (`:112-123`, `outputIndex = '0'`) and by `toBinary` (`Certificate.ts:261-262`); the review ran the bundle: a default-issued certificate's `verify()` is true and its JSON carries the txid-only string. This crate's `revocation_outpoint_json::deserialize` (`src/auth/certificates/certificate.rs:552`) goes through `Outpoint::from_string`, which needs two parts, so that JSON is refused here as a `Certificate` and inside an `AuthMessage` (`Invalid outpoint format: expected 'txid.vout'`); the same reading sits at `src/identity/client.rs:1246` (refuses the whole output with `?`), `:1421` and `src/auth/utils/validation.rs:226` (both silently `None`). Read a 64-hex string with no dot as index 0 at every site, as the reference does (one helper, used by all four). Go refuses the form (`go-sdk@2ca481c` `transaction/outpoint.go:50`): the parity note names TypeScript alone as the writer of it and Go as refusing it. Rule 2: a third reference-issued entry in the #268 vector with the default outpoint (the Node script extended; regenerate), and tests red on the tip at each of the four sites (the certificate's JSON, an `AuthMessage` carrying it, the identity client's two parsers, `validation.rs`'s intake), green after.

## Fold 2, the changelog (docs)

`CHANGELOG.md:35-36` says the HTTP JSON substrate's `WalletCertificate` already wrote the reference's shape; on this branch's base it writes `certificateType` (`src/wallet/types.rs:1357-1361`, `rename_all = "camelCase"`), and #105's PR #271 (queued ahead on beta) moves it to `type`. Reword: the substrate's certificate JSON is #105's (PR #271), outside this lane; the identity publish writes `type` by hand (`src/identity/client.rs:452`) and is right. The review's cite nits, if you touch those lines: `Certificate.ts:154` for `type`, `:504-525` for `fromObject`, `VerifiableCertificate.ts:81-119`.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `for f in $(ls tests | grep -E '^(auth_|identity_|wallet_|wire_|http_|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib --features "full,http" -- auth identity`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/lane/fix-261-field-value-bytes` (never re-record a baseline).

## Rules

No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#268)`; bodies say what and why; end with the Co-Authored-By line the session gives you. One commit per fold.

## REPORT (the last thing you print)

`REPORT` then: the tip sha and each new commit; the helper and the four sites; the RED runs then green; the vector's third entry and the reference's verdicts on it; the changelog sentence as rewritten; the green run (every gate command with its result line); anything you could not do and why.
