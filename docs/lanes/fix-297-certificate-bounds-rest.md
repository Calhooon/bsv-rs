# #297: the reference's remaining certificate bounds

Branch `lane/fix-297-certificate-bounds-rest` from beta's tip, after #275 has landed (read its changelog entry: the 1 MiB bound at two sites through one function, the canonical-base64 refusal at the decrypt sites, `to_binary` and `signing_hash` returning `Result`). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`, and bsv-wallet-toolbox-rs #223 (`gh issue view 223 -R Calhooon/bsv-wallet-toolbox-rs`) for the toolbox's reading of the same sites. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #297, from the #275 lane's changelog)

Five checks the reference makes on a certificate that this crate does not, each a stated divergence until it lands:

1. the checks in `Certificate.ts`'s constructor over the fields it is given (this crate's `new` and `set_field` accept any value);
2. the 2048-byte keyring entry bound;
3. the 64 KiB plaintext bound on a decrypted field;
4. the field-count and field-name checks of `Certificate.toBinary` (`Certificate.ts:57-58`; the name's 1 to 50 bytes and safety), carried on the BRC-100 wire writer by #246 but not on `Certificate::to_binary`;
5. the outer error wrapper a caller sees when a field fails to decrypt (`VerifiableCertificate.ts:216` area).

## What to do

1. For each, read the reference's site in full (`~/bsv/ts-stack/packages/sdk/src/auth/certificates/*.ts` at `edf6e03`; name the file and lines) and Go's (`~/bsv/go-sdk/auth/certificates/*.go`; name them), and conform: the same measure, the same words, the same point in the sequence, before any allocation the check would need (rule 5), in the error class the crate's certificate refusals use. Where the reference has no check, add none; where Go differs from the reference, the reference decides and Go's reading is a parity note.
2. Public shape: if a constructor check makes `Certificate::new` or `set_field` fallible, that is the reference's own behaviour (the constructor throws) under ruling (c): record it on #297 with the one-line migration and the downstream callers grepped (`~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/rust-message-box`, `~/bsv/bsv-overlay-cloudflare`; name each site). Prefer a `Result` on the existing method over a new method.
3. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): each bound at its edge (accepted) and one past it (refused in the reference's words), each at its site; the reference's verdicts on the same inputs recorded by a Node script at `edf6e03` (bun build, Node 22) into one vector and compared. Name the finding in each test's name. The #249, #261, #268 and #275 vectors unchanged.
4. The changelog entry under `[Unreleased]` with the parity note; the rows in `src/auth/certificates/CLAUDE.md` and `tests/CLAUDE.md`; the ratchet (certificate.rs under 800, a real move if needed, never a re-record).

5. **A signed over-bound witness for `verify`** (the #275 re-check's optional finding): build a certificate whose field value is one byte over 1 MiB from `tests/auth_certificate_field_bound_275.rs`'s `frame_with_one_field` and sign it with a `KeyDeriver`-derived certifier child (no second serializer), set the signature, and pin `verify()` to `Ok(false)` (RED on a scratch copy before #275: `Ok(true)`). Add it to that file with the finding in its name.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_certificate_*`, `identity_*`, `wire_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; `cargo fuzz run fuzz_auth_messages -- -max_total_time=120` on a corpus copy.

## Report

A REPORT: base and tip, each commit, the five sites and words (the reference's and Go's), the public changes recorded, RED counts then green, the gate's results, anything unverified.
