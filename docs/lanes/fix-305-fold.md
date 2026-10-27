# Fold on `lane/fix-305-der-reencode` (#305): the review's one finding, the reference's words on a DER cut after the second tag

Branch `lane/fix-305-der-reencode` at 6154c75 on beta's 6c5e4d8. The cold review (Fable) held the change (RED 4 of 7 and 21 of 36 reproduced, the vector byte-identical from the `edf6e03` bundle, an 11,039-input Rust-versus-TS differential with two word-only differences) and returned FIX on one point. Its evidence is in `/Volumes/Lanes/out/bsv-rs/review-305/` (the patch `reference_der-s-length-missing.patch`, the differential's script and outputs). Read the branch's changelog entry and `src/wallet/wire/mod.rs` around `reference_der`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The fix

`src/wallet/wire/mod.rs:479`: a DER that ends right after the second `02` tag is refused as `Signature DER invalid` where the reference says `Invalid R-length in signature DER` (`ts-stack@edf6e03` `primitives/Signature.ts:66-73`: `getLength` reads past the end). The verdict class agrees; the words do not. Apply the review's one-line change in `reference_der` (read the patch; make the change your own if the patch does not apply), add the recorder case (`der.slice(0, 5 + rLen)`) to the Node script and re-record the vector with it (the existing cases byte-identical, the new one added), a test RED on the words before the change and green after, and a changelog line in the branch's entry naming the case and the words. Then re-run the review's differential on the tip and say its result (zero differences expected on this case; the other word-only difference, if the review left one, named).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_*`, `wire_*`, `identity_*`, `arch_*` (not the `arch_support` module); `--lib auth wallet`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`. One commit: "wallet: a DER cut after its second tag is refused in the reference's words (#305)".

## Report

A REPORT: base and tip, the commit, the words before and after, RED then green, the vector diff's summary, the differential's result, the gate's results, anything unverified.
