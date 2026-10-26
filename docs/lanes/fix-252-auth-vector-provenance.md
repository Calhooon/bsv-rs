# Lane: fix-252-auth-vector-provenance. `tests/vectors/auth_certificate.json` vector 0 verifies under no reading: its provenance, and what the test may honestly assert (#252)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (#251 is on the tip: `Certificate::sign`/`verify` on BRC-52's derived key; the witnesses under `tests/vectors/` named for #251 and the script under `tests/support/`). Read `CLAUDE.md` (rules 1, 2, 3), `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, `tests/vectors/README.md` if one exists, and issue #252 (`gh issue view 252 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The finding

With sign/verify on the derived key and the fixture reading field values as the UTF-8 bytes of their base64 text (BRC-52 `0052.md:97` at `5119a9b`), `tests/vectors/auth_certificate.json` vector 0 verifies under neither the raw-key reading nor the derived one, in this crate and in the reference at `ts-stack@edf6e03` (the #251 lane measured it). A shared vector is never edited to make a test pass (rule 3).

## The work

1. **Provenance.** `git log --follow -- tests/vectors/auth_certificate.json` (which commit added it, its message, the SDK and commit it names if any); the vector's own header fields; the reference's own certificate test vectors at `edf6e03` (`~/bsv/ts-stack/packages/sdk/src/auth/certificates/__tests/`, `__tests__`, or wherever they live) and Go's (`~/bsv/go-sdk/auth/certificates/*_test.go`): does any of them carry the same bytes? Say what signed vector 0, if it can be known, and under which derivation and field encoding; if it cannot be known, say so and what you tried.
2. **What the test may assert.** Read `tests/auth_cross_sdk_tests.rs`'s uses of vector 0 (`test_certificate_with_signature_has_valid_format` and any other): today they claim no verdict (the DER tag and the stored bytes). Pin the truth: a test that asserts vector 0's signature does not verify under the derived key, named for what it is (`..._verifies_under_no_known_reading`), with the provenance in its doc comment; never a `#[ignore]` that hides it. If the reference regenerates the same certificate (the same fields, keys and serial) at the pin, add the regenerated vector BESIDE the old one (a new entry or a new file with its provenance: SDK, commit, Node version, the script under `tests/support/`), and a test that it verifies here; the old vector stays as it is.
3. **Docs.** The changelog entry (what vector 0 is and is not, the provenance found); `tests/CLAUDE.md`'s row; `tests/vectors/README.md` or the vectors' index if the tree keeps one.

Public shape: nothing moves; no `src/` change is expected (if you find one is needed, STOP and report).

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every auth test file: `for f in $(ls tests | grep -i -E '^(auth|certif|identity)' | sed 's/\.rs$//'); do cargo test --features "full,http" --test $f || exit 1; done`; `cargo test --lib auth --features full`; `cargo test --doc --features full`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-252-auth-vector-provenance` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#252)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the provenance found (the commit, the SDK, the derivation, the encoding) or what you tried; the tests' new assertions; any regenerated vector and its script; the green run (every gate command with its result line, every auth test file named with its count); anything you could not do and why.
