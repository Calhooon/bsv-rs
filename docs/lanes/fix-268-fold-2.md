# Fold lane: fix-268-fold-2. The dotless outpoint shortcut only for exactly 64 hex characters; the serde site a visitor so the old refusal words return (#268)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), continuing in the worktree of `lane/fix-268-certificate-json` (tip `1976a81`; `git status` clean, else say so). Read the re-review's REPORT (`cca runs --show review-fix-268-fold`; never its transcript): its one finding. You never push, tag or open a PR; you commit on this branch and end with the REPORT. Every command foreground and under ten minutes; `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-268-certificate-json`. Never `~/bsv/bsv-low/` or `~/vault/`.

## The fold

`src/auth/certificates/certificate.rs:536` (`revocation_outpoint_from_str`) appends `.0` to any dotless text, and `:552` (the untagged `Read` enum at the serde site) replaces the `Outpoint` visitor's words, so five malformed classes are refused with other words than before (`"garbage"`, 64 `z`s, `""`, the integer `5`, a short-txid object: the review's table), one of them with another `Error` variant. Nobody matches those words, but the brief asked that anything outside the two forms be refused with the words it had. Append `.0` only when the text is exactly 64 hex characters (the reference's own test, `MasterCertificate.ts:117` at `edf6e03`), else `Outpoint::from_string(text)` as before; at the serde site a visitor (`visit_str` to the helper, `visit_map` to `Outpoint::deserialize(MapAccessDeserializer)`, `visit_none`/`visit_unit` to `None`) so the `Outpoint` visitor's words return. Rule 2: one test pinning the base's words for each of the five malformed classes (red on the tip), the four sites' good-path tests unchanged and green. One commit.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `for f in $(ls tests | grep -E '^(auth_|identity_)' | sed 's/\.rs$//'); do cargo test --features "full,http" --test $f || exit 1; done`; `cargo test --lib --features "full,http" -- auth identity`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `tools/ratchet/run --check --against origin/lane/fix-261-field-value-bytes`. No em dash; never "first" as an ordinal; never "conformant" without a run; the commit subject names `(#268)`, the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: the tip sha and the commit; the five words before and after (the table); the RED run then green; the gate's result lines.
