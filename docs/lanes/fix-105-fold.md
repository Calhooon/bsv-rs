# Fold lane: fix-105-fold. The rest of the HTTP JSON substrate's BRC-100 shapes: items 3 to 8 and keyringRevealer (#105)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), continuing in the worktree of `lane/fix-105-json-substrate-shapes` (tip `29970f5`, your own five commits; read them with `git log --oneline origin/beta..HEAD` and `git show`). Read issue #105 with EVERY comment (`gh issue view 105 --repo Calhooon/bsv-rs --comments`): the comments of 2026-10-23 22:44Z (`keyringRevealer`) and 2026-10-24 03:48Z and 04:48Z (items 3 to 8) list the shapes you left as "waiting on the owner's word"; they do not wait: the owner's word of 2026-10-26 ("I like your recommendation") is the JSON substrate's conformance to BRC-100 and the TypeScript JSON substrate, the same class as items 1 and 2, and the CLI's captain asked for item 3 (its #122 item 8) by name. `CLAUDE.md` (rules 1, 2, 3), `src/wallet/CLAUDE.md`, `docs/FIXTURES.md`, `docs/DEPENDENTS.md`. You never push, tag or open a PR; you commit on this branch and end with the REPORT. Every command is foreground and under ten minutes.

## The work (each a serde-level change to the JSON wire; the Rust types keep their shape; one commit per item or per group that reads well)

Read each shape at the pin (`~/bsv/brcs` at `5119a9b`, `wallet/0100.md`; find the lines the comments cite at `ed1b015` and give the `5119a9b` lines) and in the reference (`~/bsv/ts-stack` at `edf6e03`: `Wallet.interfaces.ts`, `substrates/HTTPWalletJSON.ts`, and how `HTTPWalletJSON` serializes each argument type: byte arrays as JSON number arrays, strings as strings), and cite them:

3. The certificate calls' fields flat on the entry where this crate nests them under `certificate` (BRC-100 `0100.md:1291-1297` at `ed1b015`; the CLI's #122 item 8): listCertificates' `certificates[]`, proveCertificate's and relinquishCertificate's shapes.
4. The item the 03:48Z comment names as (4) (read it: an identity shape).
5. `createAction` and `signAction`: `inputBEEF` (the name's case) as a byte array; the responses' `tx` and `signableTransaction.tx` as byte arrays, as the reference's JSON substrate sends them (read `HTTPWalletJSON.ts` and the interfaces: `number[]` on the wire).
6. `internalizeAction`'s `tx` as a byte array.
7. `protocolID` and `keyID` on the eight requests (`getPublicKey`, `revealSpecificKeyLinkage`, `encrypt`, `decrypt`, `createHmac`, `verifyHmac`, `createSignature`, `verifySignature`): the reference's names and `protocolID` as `[level, name]`.
8. `createSignature`'s `hashToDirectlySign` as a byte array.
9. `keyringRevealer`: `'certifier'` or the public key hex string, as TS's `KeyringRevealer = PubKeyHex | 'certifier'` (`src/wallet/types.rs:769-776` today reads and writes `"certifier"` or `{"publicKey": "02.."}`).

If a Rust public type must change shape for any item (a field's Rust type, not its serde form), STOP on that item, report the exact change, and finish the others. Rule 2: the reference's bodies as witnesses (extend your Node script and `tests/vectors/` entry named for #105 with every shape; both directions round-trip); the http_json recordings re-recorded in their own commit with every changed byte named (`docs/FIXTURES.md`); no vector edited. Docs: the changelog entry extended (every field moved: old, new, the shape; the consumer note: the CLI's fixtures by number as its captain listed them on #105, and that the toolbox's JSON carries none of these); `src/wallet/CLAUDE.md`; `CLAUDE.md`'s divergence list. Then the gate below on the whole branch.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every wallet and wire test file: `for f in $(ls tests | grep -E '^(wallet_|wire_|http_|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib wallet --features "full,http"`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; the fuzz crate's `cargo check` and census after the changes; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-105-fold` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#105)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: the tip sha and each new commit; every field moved (old name, new name, the shape, the BRC and reference lines); any item STOPPED on and why; the reference's bodies beside this crate's (the script's output); the recordings changed and why; the green run (every gate command with its result line); anything you could not do and why.
