# #327: the identity revocation authenticates the lookup output, spends the matching one, aborts a failed action and retries a double spend as the reference's does

Branch `lane/fix-327-revocation-checks` from beta's tip, after #318 has landed (the revocation's createAction and signAction arguments the reference's; read #318's changelog entry, `tests/identity_wallet_calls_318.rs` and `tests/support/identity_reveal_wallet.rs`, the recording wallet). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #327, from the #318 lane's parity note, confirmed and extended by its review)

`revoke_certificate_revelation` (`src/identity/client.rs`; the lookup answer's BEEF's first transaction taken rather than its subject at `:589-592`, the configured `output_index` spent at `:604`, input 0 always) does none of the reference's checks around the spend. The reference's `revokeCertificateRevelation` (`ts-stack@edf6e03` `IdentityClient.ts:705-950`):

- `:718-729`: two `getPublicKey` calls, the identity key and the revelation token's locking key.
- `:745-756`: the lookup answer bounded by `MAX_IDENTITY_RESULTS` (`Identity revelation lookup exceeded N results`); `Failed to get lookup result` when absent.
- `:760-830`: each output's token decoded and authenticated (the locking key, the subject and the serial number against the requested certificate; `Certificate.verify()` at `:799`; `verifySignature` over the token at `:804-815`); the one matching output spent at its own `outputIndex`; none: `No authenticated revelation output matches the requested certificate.`
- `:830-911`: the createAction and signAction of #318.
- `:942`: the action aborted (`abortAction`) when signing or broadcasting fails; the spend wrapped in `withDoubleSpendRetry`.

Go (`go-sdk@2ca481c`) has no revocation: the parity note says so.

## What to do

1. Read `:705-950` whole and conform step by step, in the reference's words and order: the two keys, the result bound, the token checks, the matching output at its index, the abort on failure, the double-spend retry (read `withDoubleSpendRetry` and what it retries on; this crate's overlay module has `double-spend retry` of its own: use it if it is the same rule, say so either way). What the reference does with the BEEF's subject against the lookup's `txid` and `outputIndex`: the same here.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): `tests/identity_revocation_checks_327.rs` with the recording wallet and a lookup answered by the test: a token for another certificate (refused in the reference's words), two outputs where the second matches (spent at its index, the first untouched), more than `MAX_IDENTITY_RESULTS` outputs (refused), a signAction failure (the action aborted, the abort's reference pinned), a double spend answered once then accepted (retried as the reference retries), the lookup absent (`Failed to get lookup result`); the reference's verdicts and wallet calls recorded by `tests/support/identity_wallet_calls_318.mjs` extended (byte fields as hex text, witnesses not repeated; `edf6e03`, Node v22.18.0, the randomness #310's SHA-256 counter stream); the #307, #310, #315 and #318 witnesses unchanged.
3. The changelog entry under `[Unreleased]` with the parity note (#318's remaining items closed; Go's absence) and the migration line (a revocation that spent a wrong output before now refuses in the reference's words); the rows in `src/identity/CLAUDE.md` and `tests/CLAUDE.md`; the divergence line updated; the ratchet (the client file is near its bound: a new file for the checks if the counter asks).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `arch_*` (not the `arch_support` module); `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <base sha>`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's steps beside this crate's before and after, the retry rule's reading, RED counts then green, the gate's results, anything unverified.
