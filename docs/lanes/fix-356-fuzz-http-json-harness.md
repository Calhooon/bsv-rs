# #356: the fuzz target `fuzz_http_json_responses` builds and runs again after #323

Branch `lane/fix-356-fuzz-http-json-harness` from beta's tip. Read `fuzz/fuzz_targets/CLAUDE.md`, `src/wallet/substrates/CLAUDE.md` (#323's rule: the JSON substrate sends the constructor's originator and refuses a call with none configured; the constructors return `Result`), and issue #356. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No probe on a default URL; the harness's server is its own loopback listener.

## The finding (issue #356, from the #329 rebase lane)

`fuzz/fuzz_targets/fuzz_http_json_responses.rs:85` builds its harness with `HttpWalletJson::with_client(client, None, Some(url))`: since #323 the constructor returns `Result` and a call with no originator configured is refused before any request, so the target does not compile and, compiled, would fuzz nothing. CI builds no fuzz target (`ci.yml:751`), so only `cargo fuzz` and the on-demand oracle run see it.

## What to do

1. The harness names an originator (`fuzz.invalid`) and unwraps the constructor with `expect` (the base URL its own loopback), a doc line saying why; read the target whole for any other call #323 or #329 changed (`originator: Option<&str>` on the trait once #329 lands: build against beta's tip as it is, and say in the REPORT whether #329's landing will move it again).
2. `cargo fuzz build fuzz_http_json_responses` (the pinned toolchain `fuzz/fuzz_targets/CLAUDE.md` names) and a 60 s run in a scratch copy with its own target dir (corpus files stay out of the tree); every other target builds (`cargo fuzz build` for the set); the fuzz targets' CLAUDE.md row if it names the constructor.
3. A changelog line under `[Unreleased]` only if the crate records fuzz-harness changes there (read the file's own practice); else the row alone.

## Gate

`cargo fmt --check` (the crate and `fuzz/`); `cargo clippy --all-targets --all-features -- -D warnings`; `cargo fuzz build` for every target; the 60 s run above; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, the commit, the targets built, the run's inputs and result, #329's effect on the harness, the gate's results, anything unverified.
