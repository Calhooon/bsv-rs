# #109: electrum_decrypt finds an embedded key the reference's way

Branch `lane/fix-109-ecies-no-key-envelope` from beta's tip. Read `CLAUDE.md`, `src/compat/CLAUDE.md`, `tests/CLAUDE.md`, `fuzz/fuzz_targets/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #109, from the oracle-fuzz lane, #82)

With a sender key, `electrum_decrypt` (`src/compat/ecies.rs:177-240`) decides from the length alone that the envelope embeds a public key, `data.len() > 69` (`:196-199`), and reads the ciphertext from byte 37. A no-key envelope is `4 + ciphertext + 32` bytes, so any ciphertext of 48 bytes or more (a plaintext of 32 or more) crosses 69, 33 bytes of ciphertext are skipped as a key, the HMAC passes (it covers the whole prefix) and the AES unpadding fails: `EciesDecryptionFailed("AES decryption failed")`. The issue's input (base64, the 32-byte plaintext): `r68gn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+9z8I=`.

## The references

TS `ts-stack@edf6e03` `packages/sdk/src/compat/ECIES.ts` `electrumDecrypt` (the issue read `8ac5939` `:607-637`; cite the lines at `edf6e03`): `available = length - 4 - 32`; when `available >= 49` and the byte at 4 is `02` or `03` and `(available - 33) % 16 == 0`, a compressed key; when it is `04`, `available >= 81` and `(available - 65) % 16 == 0`, an uncompressed one; else no key, and then an expected sender is required (`Sender public key is required`); an embedded key beside an expected sender must equal it, constant-time (`Embedded sender public key does not match the expected sender`); the shared secret uses the expected key when given, else the embedded one; the ciphertext must be non-empty and 16-aligned (`Invalid Electrum ECIES ciphertext framing`); then the HMAC (`Invalid checksum`). Work out in the REPORT whether this rule can misread an envelope this crate's `electrum_encrypt` writes: a no-key ciphertext is 16-aligned and a key is 33 or 65 bytes, so the lengths modulo 16 and the key byte decide; say what you find. Go `go-sdk@2ca481c` `compat/ecies/ecies.go:105-125`: the length rule `> 69`, the same failure as this crate's. The reference decides: conform to TS; Go's reading goes in the parity note and the divergence list.

## What to do

1. Conform `electrum_decrypt` to the reference's rule, verdicts and order, with and without a sender. New error texts take the reference's words; a text a downstream matches on stays (grep `~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/bsv-overlay-cloudflare` for `EciesDecryptionFailed`, `EciesHmacMismatch`, `electrum_decrypt`, and say in the changelog's migration line what each caller sees change). The uncompressed key branch too, if `PublicKey::from_bytes` reads 65 bytes.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): `tests/compat_ecies_envelope_109.rs` pins, on fixed keys, both modes at plaintexts of 1, 15, 16, 17, 31, 32, 33, 47, 48, 64 and 96 bytes (the issue's input among them), the mismatch refusal, the no-sender refusal of a no-key envelope, the framing refusal, and the reference's own envelopes: Electrum ECIES with a given sender key is deterministic (IV and keys derive from the shared secret), so a Node script at `edf6e03` records the reference's envelopes and verdicts for the same keys and plaintexts into `tests/vectors/compat_ecies_envelope_109.json` by `tests/support/compat_ecies_envelope_109.mjs` (the form of `tests/support/auth_signed_text_280.mjs` and its rows in `tests/CLAUDE.md`: the reference run from a `git archive` of `edf6e03` built with bun, under nvm's Node v22.18.0); this crate's envelopes must equal the reference's byte for byte, and open there (the script opens this crate's output too, recorded as a verdict column). Stop and report if the reference's envelope differs from this crate's for any case.
3. Remove the skip in `fuzz/fuzz_targets/fuzz_ecies.rs:40-44` so every sealed envelope must open; `cargo fuzz run fuzz_ecies -- -max_total_time=120` in a scratch copy, so corpus files stay out of the tree; the issue's input as a corpus seed under `fuzz/corpus/fuzz_ecies/`.
4. The changelog entry under `[Unreleased]` with the parity note; the rows in `src/compat/CLAUDE.md` and `tests/CLAUDE.md`; the divergence line in `CLAUDE.md` (Go's length rule); the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `compat_*`; `--lib compat`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's rule beside this crate's old one, the modulo reading, the vector's cases and the reference's verdicts, the downstream readings, RED counts then green, the fuzz run's result, the gate's results, anything unverified.
