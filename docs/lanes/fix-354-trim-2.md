# #354 trim, second pass: `src/auth/transports/http.rs` three lines over beta's new bound after #353 landed

Work in this worktree on `lane/fix-354-unsigned-response-refused` (9b3bd484 on bed537a4; `git fetch origin lane/fix-354-unsigned-response-refused && git reset --hard origin/lane/fix-354-unsigned-response-refused` first). Rebase onto `origin/beta` (11c1b9f4 at this writing; #353 landed there and its record of `src/auth/transports/http.rs` moved the file's bound to 1,245 lines). The trim's cold re-review (`cca runs --show review-354-trim`, Opus, verdict FIX: "the trim is correct and green against e64a863; blocking: `src/auth/transports/http.rs` must drop 3 more lines to ≤ 1,245, beta's new bound since 11c1b9f4 (#353); confirmed by the ratchet on the rebased tree") is the finding. Resolve any conflict in `http.rs` or its tests with #353's text under this branch's rule and say what you took. Then take at least three more lines out of `http.rs` the way 9b3bd484 did (a reading moved into `http/unauthenticated.rs` or a sibling under `http/`, no behaviour change, no line joined or comment dropped to dodge the counter), until `tools/ratchet/run --check --against origin/beta` is green. Read `docs/RATCHETS.md` (never re-record the baseline for growth), `src/auth/transports/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL. Use your own `CARGO_TARGET_DIR` under `~/bsv/targets/bsv-rs-lanes/fix-354-trim`.

One commit on top of 9b3bd484 for the move (the rebase keeps the branch's commits as they are). The review also noted, not blocking and not yours: `CLAUDE.md:126` and `:130` are duplicate #310 bullets inherited from beta (the captain's docs fold takes them).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transport_*`, `auth_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib auth::transports`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `tools/ratchet/run --check --against origin/beta` (green on the rebased tree).

## Report

A REPORT: the base rebased onto, the tip, each conflict and the text taken, the lines moved (from where to where; `http.rs`'s line count before and after and the ratchet's verdict), the gate's results, anything unverified.
