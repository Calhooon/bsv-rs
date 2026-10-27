# Fold on `lane/fix-307-reveal-verifies` (#307): the review's two findings at the keyring step

Branch `lane/fix-307-reveal-verifies` at e62bdd7 on beta's 6c5e4d8. The cold review (Fable) held the main change (the master certificate verified before any wallet call, in the reference's order and words through `verify`; the vector reproduced byte for byte from a fresh `edf6e03` bundle) and returned FIX on two points at the keyring step. Read the branch's changelog entry, `src/identity/reveal.rs`, `src/identity/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The two fixes, conform (rule 1)

1. **F1, `src/identity/reveal.rs:126`:** an unsafe keyring key is refused as "unrequested fields" where the reference says `Invalid display identity: proof result keyringForVerifier contains an unsafe field` (`ts-stack@edf6e03` `IdentityClient.ts:480-483`). Refuse with the reference's words at the reference's point; keep the "unrequested fields" refusal for the case the reference refuses that way (read `:470-491` and name which input hits which words).
2. **F2, the keyring values' form:** the reference checks each keyring value with `validateBase64String` (1 to 2048 bytes) and trims it (`:493-498`) before the PushDrop; the branch states it as unported. Conform: a short helper in `reveal.rs` with the reference's words (its WERR text; name it), the trimmed value used from there on; the changelog's parity note loses that item and the root `CLAUDE.md` divergence list carries nothing for it. (This closes item 1 of #310; say so in the changelog.)

Tests: for F1, a proof result whose keyring carries an unsafe key refused in the reference's words (RED on the tip before the fold, green after), recorded against the reference by the lane's script into the #307 vector (re-run the verify step; the recorded exchange's other cases unchanged); for F2, a keyring value that is not base64, one over 2048 bytes, one with whitespace trimmed, each as the reference does, recorded the same way. Leave `tests/identity_reveal_verifies_307.rs:258` (the createAction-with-no-transaction pin) as it is: #310 takes it.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `auth_certificate_*`, `arch_*` (not the `arch_support` module); `--lib identity auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`. One commit: "identity: the reveal's keyring step in the reference's words and bounds (#307)".

## Report

A REPORT: base and tip, the commit, the reference's lines and words for each, RED counts then green, the vector diff's summary, the gate's results, anything unverified.
