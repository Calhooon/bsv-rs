# #288: `RequestedCertificateSet.types` keeps insertion order, as the reference's `Record` does

Branch `lane/fix-288-ordered-types` from beta's tip, after #286 (#280) has landed (it holds the requested set's received text; read its changelog entry and `src/auth/types.rs` as landed). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, `fuzz/fuzz_targets/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #288)

`RequestedCertificateSet.types` is a `HashMap<String, Vec<String>>` (`src/auth/types.rs`): two encodings of one message write the keys in different orders, so `fuzz_auth_messages`' fixed-point assertion fails on a set with two types (the crash input is at `/Volumes/Lanes/out/bsv-rs/fix-285/crash-d04c1f05b91f6168ce697731af3da5763ff9a76a`; copy it, never add it to the tree's corpus by hand). The reference holds `types` as a `Record<string, string[]>` in insertion order (`ts-stack@edf6e03` `packages/sdk/src/auth/types.ts:21-23`), writes it back in that order, and signs a `certificateRequest` over the UTF-8 bytes of `JSON.stringify(policy)` (`Peer.ts:451-453`). The keeper's reading (2026-10-26): an insertion-ordered map is the reference's own field type in Rust, so the shape change falls under the owner's ruling (c) on the 0.9.0 line and needs no new word (his brief carries it as (p) for the record).

## What to do

1. `types` becomes an insertion-ordered map. Prefer `indexmap` (`IndexMap<String, Vec<String>>`, its `serde` feature; a new dependency behind `auth`, wasm32-safe, no `std::time`) over a hand-rolled `Vec<(String, Vec<String>)>`, unless `cargo deny` or the wasm32 build of the CLAUDE.md feature set objects; say which and why in the commit. The JSON read keeps the text's order; the JSON written is that order; `add_type` appends; the map API the crate and its tests use (`get`, `insert`, `iter`, `len`, `is_empty`, `contains_key`) stays.
2. The same reading for every other `HashMap` whose text a BRC-103 signature covers or a reference `Record` orders on the wire: list them in the REPORT (`certificates`' `fields` and keyrings are JSON objects the reference writes in its own order too); change only `types` in this lane unless another is on a signature's path, and say so.
3. Tests, RED before green (a scratch copy at the base with its own `CARGO_TARGET_DIR`): a set with three types in a given order encodes in that order and re-encodes identically (the fixed point); the crash input of #285's run passes `fuzz_auth_messages` (run it on a copy of the corpus; report the run count of a 120 s fork run); a vector of the reference's `JSON.stringify(policy)` for a three-type policy recorded by a Node script at `edf6e03` (bun build, Node 22) equals this crate's text byte for byte, and this crate's `certificateRequest` signature over it verifies in the reference's `Peer` (the #280 lane's script is the pattern: read it).
4. The changelog entry under `[Unreleased]`: the shape change with its one-line migration for a downstream that built the struct with a `HashMap` literal (grep `~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/rust-message-box`, `~/bsv/bsv-overlay-cloudflare` for `RequestedCertificateSet` and `types:` and name each site); `cargo semver-checks --release-type minor` (0.9.0 is a minor); the parity note; the rows in `src/auth/CLAUDE.md` and `tests/CLAUDE.md`; the divergence list entry if any difference remains.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo deny check`; `cargo test --features "full,http"` on every test file matching `auth_*`, `socketio_*`, `identity_*`, `arch_*` (not the `arch_support` module); `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet; `cargo fuzz run fuzz_auth_messages -- -max_total_time=120` on a corpus copy.

## Report

A REPORT: base and tip, each commit, the map chosen and why, the downstream sites, RED counts then green, the fuzz run, the gate's results, anything unverified.
