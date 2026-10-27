# #326: the contacts manager and the key-value stores send signAction the reference as the wallet answered it, with the reference's options

Branch `lane/fix-326-signaction-reference-text` from beta's tip, after #318 has landed (the identity revocation's signAction the reference's; read #318's changelog entry and `tests/support/identity_reveal_wallet.rs`, the recording wallet). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `src/kvstore/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #326, from the #318 lane, confirmed by its review)

Six `signAction` calls send the reference as the hex of its bytes: `src/identity/contacts.rs:447`, `:732`; `src/kvstore/global.rs:281`, `:409`; `src/kvstore/local.rs:331`, `:438`. The wallet answers `createAction` with `signableTransaction.reference` as a base64 text; the binary wire's transceiver decodes that text (`src/wallet/wire/transceiver.rs:667-668` for signAction) and the HTTP JSON substrate carries it, so the hex names an action no wallet made. The registry client (`src/registry/client.rs:699`, `:928`) and the revocation (since #318) send the text.

## The reference (`ts-stack@edf6e03`)

- `ContactsManager.ts:813-834`, `:981-1001`: `const reference = signableTransaction.reference`, then `signAction({ reference, spends }, originator)`; read the full argument and options each sends.
- The kvstores sign through `completeBoundAction` (`packages/sdk/src/wallet/completeBoundAction.ts:904`, `:1111-1120`): `signAction({ reference, spends, options: { acceptDelayedBroadcast, returnTXIDOnly: false, noSend, sendWith } }, originator)`, the options carried from the createAction's, the reference as answered (`GlobalKVStore.ts:343-380`, `:431-470`; `LocalKVStore.ts:378-400`, `:486-510`). Read `completeBoundAction` whole: what it checks between createAction and signAction (the signable inputs matched to signers, `:1108`), and whether this crate's kvstores do the same.
- Go (`go-sdk@2ca481c` `kvstore/`, `identity/contacts.go` if any): name the lines for the parity note.

## What to do

1. The six sites send the text as answered, and each call's arguments and options the reference's, member by member (the contacts manager's two calls; the kvstores' through `completeBoundAction`'s shape). Where this crate's flow differs from `completeBoundAction` beyond the reference's encoding and options (a check it makes that this crate does not), state it in the parity note and the divergence list; do not widen the change to it without saying so in the REPORT.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): the recording wallet of #318 extended to the contacts manager and the two kvstores, each client's signAction arguments compared with the reference's recorded by a Node script at `edf6e03` under Node v22.18.0 (the form of `tests/support/identity_wallet_calls_318.mjs`, byte fields as hex text, witnesses not repeated) into `tests/vectors/signaction_reference_326.json`; the contacts and kvstore witnesses unchanged.
3. The changelog entry under `[Unreleased]` with the migration line (the toolbox's in-process `SignableTransaction.reference` is the text's UTF-8 bytes, `bsv-wallet-toolbox-rs` `src/wallet/wallet.rs:1526` at `6317222`, keyed by the text: say what a toolbox-backed caller sees, in-process and over each wire) and the parity note; the rows in `src/identity/CLAUDE.md`, `src/kvstore/CLAUDE.md`, `tests/CLAUDE.md`; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `kvstore_*`, `contacts_*`, `arch_*` (not the `arch_support` module); `--lib identity`; `--lib kvstore`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <base sha>`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the six sites' before and after, the reference's arguments beside this crate's for each client, `completeBoundAction`'s checks this crate makes or does not, the downstream reading, RED counts then green, the gate's results, anything unverified.
