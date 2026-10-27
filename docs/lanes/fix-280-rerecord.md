# Fold on `lane/fix-280-signed-text` (PR #286): the vector re-recorded in the field shape #261 landed

Branch `lane/fix-280-signed-text`, rebased onto beta's 2e4b477 (#274, #261 landed: `Certificate.fields` is `HashMap<String, String>` of base64 text, written in JSON as the strings). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, the branch's own changelog entry and `tests/support/auth_signed_text_280.mjs`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## Why

`tests/vectors/auth_signed_text_280.json` holds, under `this_crate_messages`, the texts this crate sent at recording time and the reference `Peer`'s verdicts on them. Those texts carry the certificate's `fields` as sequences of numbers, this crate's JSON before #261; the deserializer now refuses them (`certificates: invalid type: sequence, expected a string`, `tests/auth_signed_text_280.rs:367`). The captain's commit on the branch's tip already builds the test's field map as base64 text (the same JSON string the old bytes encoded to). Rule 3: the vector is written by this crate's own writer and judged by the reference, never edited by hand.

## What to do

1. Re-record the vector with the branch's own recorder and the reference script, exactly as the lane that wrote it did (read the script's header and the changelog entry for the procedure: the Rust recorder emits the texts, the Node script at `ts-stack@edf6e03` built with bun under Node 22 judges them and writes the JSON; the memory of this crate: `serde_json` sorts a `Value`'s keys, so the Node script writes the vector). Every field of the vector that is not a this-crate text should come out byte-identical to before (`git diff` on the vector shows only the texts and whatever the reference's verdicts on them are); say so in the REPORT, or say what else moved and why.
2. `cargo test --features "full,http" --test auth_signed_text_280 --test socketio_signed_text_280` green; the RED claim of the original lane still holds (the branch's tests fail on a scratch copy of 2e4b477 without the branch's `src` changes: run it, with its own `CARGO_TARGET_DIR`).
3. If the test's reading of the vector can be made shape-independent without weakening it (it must still pin the exact texts this crate sends), say so in the REPORT; do not do it in this lane.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every test file matching `auth_*` and `socketio_*` (`--features "full,http"`); `--lib auth`; the wasm32 build of the CLAUDE.md feature set; the ratchet. One commit: "tests: the #280 vector re-recorded in the field shape #261 landed (#280)".

## Report

A REPORT: base and tip, the vector diff's summary (which members moved), the gate's results, anything unverified.
