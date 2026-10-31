Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #512: raw_tree.rs's second copy of the 256 MiB bound and its words read through boundary's one definition (after #502)

Branch `lane/fix-512-raw-tree-bound` from `origin/beta`'s tip (name the base sha in your REPORT). No behaviour change; the issue is PR #511's review note.

`src/wallet/substrates/result_values/raw_tree.rs:13` carries its own `const MAX_BYTES: usize = 256 * 1024 * 1024;` and `:279` the words `at most 268435456 total bytes`, beside `boundary.rs`'s `MAX_BYTES` (`:9`), which #502 (landed at `099caff8`) made the one definition for `wire.rs:43`.

## What to do

1. `raw_tree.rs` reads the bound and formats the words from `boundary.rs`'s constant (a `pub(crate)` re-export or a `boundary::` path, as `wire.rs` does since #502); the wire bytes and the refusal words unchanged: the #487 and #496 recorded frames and the refusal words pin them (`tests/wallet_wire_result_validation_487.rs`, `tests/wallet_wire_request_frame_cap_496.rs`, the http_json fixtures through `fixtures_replay*`); no literal 268435456 or `256 * 1024 * 1024` left under `src/wallet/substrates/result_values/` other than the one definition (grep and say).
2. The entry under `[Unreleased]`: one line; `src/wallet/substrates/CLAUDE.md`'s row if it names the bound's home.
3. The gate, every command in the foreground: `cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings` and with `cargo +1.99.0`; `cargo test --features "full,http"` with one `--test` per file matching `wallet_*`, `wire_*`, `arch_*`, `fixtures_replay*`; `cargo test --lib --features full wallet`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `cargo semver-checks --baseline-rev <base> --release-type patch`; `tools/ratchet/run` on the built target; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit, no push.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.

## Report

The base sha and the tip; the lines changed; the grep for leftover literals; the gate table; anything unverified; nothing else.
