# Fold on `lane/fix-297-certificate-bounds-rest` (#297): the cold review's two fixes and its note

Branch `lane/fix-297-certificate-bounds-rest` at bdd746c on beta's 83b804d. The cold review (Fable) held the five checks site by site, reproduced the vector 64 of 64 from the `edf6e03` bundle, and returned FIX on two points; its evidence is in `/Volumes/Lanes/out/bsv-rs/review-297/` (probe script and output, a scratch test, the red and green logs). Read the branch's changelog entry, `src/auth/certificates/bounds.rs`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The fixes

1. **The verifier wrapper's inner text** (`src/auth/certificates/bounds.rs:71-76`): the wrapper quotes this crate's cipher errors (`decryption failed`, `invalid data length: expected 48, got 40`) where the reference quotes its own (`SymmetricKey.ts:217` and `:232` `Decryption failed!`; `:205` `Ciphertext too short`). Map the two classes in `message()` to the reference's words (an authentication failure to `Decryption failed!`, a short ciphertext to `Ciphertext too short`), pin each with a recorder case against the reference, and narrow the parity note to what remains: Node's UTF-8 decoding text for a plaintext that is not UTF-8, a platform residual, named as such.
2. **The changelog's old texts**: the #297 entry names one old text of the four that changed; add the master `decrypt_field`'s absent-field text (`Field '<name>' not found in master keyring`) and the verifier `decrypt_field`'s absent-field text (now the `own string data property` words), each old beside new, so a downstream that matched on a text finds it.
3. **The review's note**: the verifier's 32-byte revelation-key check holds (the review's scratch test: 31, 33 and 0 bytes refused in the reference's words; the master restores zeros): pin it with three recorder cases in the vector and the test file.

## How

Re-record the vector with the branch's recorder and the reference script as the lane did (bun build of `ts-stack@edf6e03`, Node 22; the Node script writes the vector; the memory: `serde_json` sorts a `Value`'s keys). Only the new cases and the two mapped texts move; say which members. RED for the mapping (the old inner words fail the new pins on a scratch copy of bdd746c with its own `CARGO_TARGET_DIR`), green on the tip.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_certificate_*`, `identity_*`, `wire_*`, `arch_*` (not the `arch_support` module); `--lib auth identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`. One commit for the code and vector, one for the changelog: "auth: the verifier's decrypt wrapper quotes the reference's inner words; the revelation-key check pinned (#297)" and "docs: the #297 entry names each old text beside its new one (#297)".

## Report

A REPORT: base and tip, the two commits, the mapping and its recorder cases, the vector diff's summary, RED counts then green, the gate's results, anything unverified.
