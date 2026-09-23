# CLAUDE.md — bsv-rs

The working rules for this crate. `README.md` is the guide for users (what it is, the examples, the contracts, the numbers); this file is for whoever changes it. Read both, then the module's own `CLAUDE.md` (27 of them under `src/`, `tests/`, `benches/`) before touching that module.

## What this crate is, in one paragraph

A reference-parity port of the TypeScript `@bsv/sdk` (`~/bsv/ts-sdk`; the `ts-stack` monorepo at `~/bsv/ts-stack` carries the newer packages and the conformance corpus), cross-checked against the Go SDK (`~/bsv/go-sdk`). Thirteen feature-gated modules in dependency order (`primitives → script → transaction → wallet → {messages, auth, overlay} → {storage, registry, kvstore, identity}`; `compat` and `totp` stand on `primitives`), one `Error` enum (`src/error.rs`, `Clone + PartialEq + Eq` so tests assert on it), and every public behavior pinned by a test that fails when the behavior changes. It ships to crates.io as `bsv-rs` and runs on native and `wasm32-unknown-unknown` (Cloudflare Workers are the production target: the LOW stack's overlay engine, watchtower, relay, app-layer and monitor).

## Rules

1. **The reference decides.** Before writing or changing a wire format, a verdict, a derivation or an error text, read the TypeScript implementation first (`~/bsv/ts-sdk/src/...`; for overlay/auth transports also `~/bsv/ts-stack/packages/...`), then Go. Conform. If you cannot conform, the divergence is a STATED FINDING: a `### Notes — cross-SDK parity` paragraph in the `CHANGELOG.md` entry and a line in the list below, never a silent difference. A reference bug you do not follow is recorded the same way (the TOTP digits, the nonce HMAC inputs, the Go admin-token key).
2. **Every fix lands with a test that was RED before it.** Watch it fail on the pre-fix code (a scratch copy with the fix removed, never a `git checkout` of a dirty tree), then green. Regression tests name the finding in their function name (`a_deep_diamond_chain_links_and_verifies_in_linear_time`, `an_unproven_spend_creating_satoshis_is_refused`). A fixture the test needs is built by this crate's own writer, so it cannot drift from the wire format.
3. **Vectors are the source of truth.** `tests/vectors/*.json` are shared byte-for-byte with the other SDKs: never edit one to make a test pass. The `ts-stack` corpus (`$BSV_CONFORMANCE_DIR`, default `../ts-stack/conformance`) is read, not copied; a vector this crate cannot express is counted in the enumerated `unsupported` allowlist with its reason, and the class totals are pinned (`tests/conformance_scripts.rs`, `tests/conformance_beef.rs`). A total that moves is a finding.
4. **Tests are hermetic.** No test may depend on the network being present OR absent. A test that needs an overlay failure injects a resolver that cannot succeed (`GlobalKVStore::with_resolver`, `LookupResolverConfig { host_overrides, facilitator, .. }`); a test that needs an HTTP answer uses `wiremock`. Five kvstore tests once asserted an error "because there are no live SLAP hosts" and failed on every machine with a route to them (0.3.24).
5. **Nothing panics on input.** Parsers bound every pre-allocation by the bytes remaining (`primitives::bounded_capacity`), index with `get`, and return `Err` on a bad count; on wasm32 a panic is an abort nobody can catch. The interpreter's budgets are errors of their own class (`ScriptResourceLimit`), never a hidden allocation. `cargo fuzz run <target>` on any parser you touch.
6. **wasm32 is a build target of every change.** `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` must pass. No `std::time::SystemTime` (use `crate::util` time helpers), no `thread::spawn`, no tokio time driver outside `#[cfg(not(target_arch = "wasm32"))]`; a new dependency behind a feature must not break a wasm build of a sibling feature (the `socketio` rule).
7. **Clippy is `-D warnings`, rustfmt is law, doc tests compile.** `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --check`, `cargo test --doc --all-features`, `cargo build --examples --all-features`, `cargo test --test readme_examples` all green before a push. CI runs the matrix (Linux, macOS, Windows × stable, beta).
8. **The README's code is the examples.** Every ```rust block in `README.md` that opens with `// examples/<name>.rs` equals that file's body; `tests/readme_examples.rs` pins the bytes. Change the example, run it, paste it. Never write a README snippet that is not a compiled example.
9. **Semver within 0.3 is additive.** A new public field on a struct that downstreams build with a literal (`ScriptEvaluationError.resource_limit` in 0.3.23) is called out in the changelog with the one-line migration. Yank a release that was wrong (0.3.21 was; the changelog says so and why).
10. **A release is a ritual, not a habit.** `Cargo.toml` version, a `CHANGELOG.md` entry (what changed, why it was wrong, which test pins it, the parity note if any), `cargo publish` (credentials live in `~/.cargo/credentials.toml`, never in the tree), tag `vX.Y.Z`, push `main` and the tag. Downstreams pin `"0.3"` and pick a patch up on their next `cargo update -p bsv-rs`; a `[patch.crates-io]` to a DIFFERENT version is silently unused until that update (cargo warns; read the warning).

## Layout

| Path | What |
|---|---|
| `src/lib.rs` | The crate docs and the feature-gated module tree with convenience re-exports |
| `src/error.rs` | The one `Error` enum (58 variants, feature-gated) and `Result<T>` |
| `src/util/` | wasm32-safe time helpers (`pub(crate)`) |
| `src/primitives/` | hash, EC (secp256k1, P-256, Shamir, ECDH), symmetric (AES-256-GCM), `BigNumber`, DRBG, encoding, `bsv/` (sighash, `SighashCache`) |
| `src/script/` | `Script`/chunks/opcodes, `spend.rs` (the interpreter), `flags.rs` (the node's flag words: `ScriptFlags`, `ProtocolEra`), `templates/` (P2PKH, P2PK, Multisig, RPuzzle, PushDrop) |
| `src/transaction/` | `Transaction`, inputs/outputs, `beef.rs`, `merkle_path.rs`, fee models, broadcasters (ARC, WoC, Teranode), chain trackers |
| `src/wallet/` | `KeyDeriver`, `ProtoWallet`, `WalletClient`, `substrates/` (HTTP JSON), `wire/` (the BRC-100 binary protocol), validation |
| `src/auth/` | `Peer`, sessions, certificates (BRC-52/53), `transports/` (HTTP, WebSocket, Socket.IO), utils (nonces, validation) |
| `src/overlay/` | `LookupResolver`, `TopicBroadcaster`, facilitators, `Historian`, host reputation, admin tokens, double-spend retry |
| `src/{messages,compat,totp,storage,registry,kvstore,identity}/` | as named |
| `examples/` | The six README programs (`keys`, `script`, `transaction`, `brc42`, `beef_spv`, `overlay`); `[[example]]` entries carry `required-features` |
| `tests/` | 39 integration files; `vectors/` (the shared JSON); `transaction/vectors/` (Rust constants); `conformance_*.rs` (the ts-stack census); `readme_examples.rs`; `script_flags_witnesses.rs` (the flag words on seven witness transactions), `script_residual_witnesses.rs` (the five consensus rules of 0.3.27 on nine) |
| `benches/` | Criterion: `hash_bench`, `primitives_bench`, `script_bench`, `memory_bench` |
| `fuzz/` | `fuzz_script_parser`, `fuzz_transaction_parser`, `fuzz_wire_protocol`, `fuzz_base58` |
| `.github/workflows/ci.yml` | The matrix, clippy, fmt, docs |

## Features

```toml
default = ["primitives", "script"]
transaction = ["script"]; wallet = ["transaction"]; messages = ["wallet"]
compat = ["primitives"]; totp = ["primitives"]
auth = ["wallet", "messages", "dep:tokio"]; overlay = ["wallet", "dep:tokio"]
storage = ["overlay"]; registry = ["overlay"]; kvstore = ["overlay"]; identity = ["auth", "overlay"]
socketio = ["auth"]                      # no new dependency; in `full`
full = [every module above]
http = ["dep:reqwest"]                    # ARC, WoC, the HTTP wallet substrate, overlay hosts
websocket = ["auth", tokio-tungstenite]   # opt-in, NOT in `full`
wasm = ["getrandom/js", futures-timer/wasm-bindgen, js-sys]
dhat-profiling = ["dep:dhat"]
```

`tokio` here is `sync`, `time`, `rt` only (the `auth`/`overlay` primitives: `watch`, `oneshot`, timeouts); no runtime is started by the crate.

## The contracts (the short form; the README has the long one)

- `Spend` = the TS default evaluation mode without a word (strict for version ≤ 1: MINIMALDATA, LOW_S, CLEANSTACK, NULLDUMMY; relaxed for version ≥ 2; push-only always; no NULLFAIL), or, with `set_flags`, the NODE's word: `ScriptFlags::block(era)` (consensus) / `ScriptFlags::standard(era)` (mempool policy), every rule at bitcoin-sv v1.2.2's site under its version gate (`src/script/flags.rs` carries the table and the citations; the reference clone is `~/bsv/bitcoin-sv` at `v1.2.2`, `879fc8b`). A consensus oracle selects the block word. Post-Genesis opcodes, plus the Chronicle ones for a post-Chronicle UTXO (the word's `UTXO_AFTER_CHRONICLE`, or version > 1 by default); an undefined opcode executed, a truncated push reached, a second OP_ELSE are failures in every mode; a FORKID signature's push stays in the scriptCode (0.3.27, bsv-rs#12). The combined-script CHECKSIG subscript; 1 GiB max element, 32 MB default memory budget, `ScriptResourceLimit` as its own error class; `OP_NUM2BIN` refuses before allocating. Consensus and policy are different things and this crate says which is which: a rule that is policy is never enforced under the block word.
- BEEF: linear linking (one full link per distinct parent, stubs after), `verify` by txid (proven: tracker, not descended; unproven: every input script executed, outputs ≤ inputs), cycles terminate, the merkle path reattached on `from_beef`.
- Sighash lives in the templates; `SighashCache` for midstate reuse; RFC 6979 via k256 (`bits2octets` for a digest ≥ n, unlike libsecp256k1: signatures differ only in that regime, both verify).
- Auth: BRC-103 (the code's older comments say BRC-31: the same protocol under its earlier name); nonces are the canonical 48-byte form since 0.3.6 (the 32-byte legacy accept window is still in place; remove it deliberately, with a changelog line).
- Overlay: request coalescing (`tokio::sync::watch`) and host reputation are this crate's additions over the reference (documented, not divergences: the wire is the reference's).

## Known cross-SDK divergences (keep this list honest)

- Go defaults `counterparty` to `Anyone` in `create_signature`; Rust and TS use `Self_`.
- Go lacks TOTP, overlay caching/historian/reputation, and the RPuzzle template.
- TS TOTP defaults to 2 digits; this crate uses 6 (RFC 6238).
- TS and Go disagree on the nonce HMAC inputs (`protocolID [2,'server hmac']` + UTF-8 keyID vs security level 1 + raw-bytes keyID); this crate follows Go's level with its own base64 keyID. `verify_nonce` is only ever called on a peer's own nonces, so nothing crosses the gap in practice.
- Go signs overlay admin tokens with `counterparty = Self` (a different signing key); this crate matches the deployed TS validators (`@bsv/sdk 1.10.1`).
- k256's RFC 6979 seeding for a digest ≥ n differs from libsecp256k1's; pinned in `tests/ec_tests.rs`.
- TS's explicit `verifyFlags` applies a flag as given (NULLDUMMY, MINIMALDATA, LOW_S, CLEANSTACK at every version; no `CHRONICLE` flag); this crate's `set_flags` applies the node's version gate at the node's sites (0.3.26). The default mode keeps TS's no-NULLFAIL; the block word carries it.
- TS's default keeps a lenient parser (a truncated push is a shorter push), allows a second OP_ELSE outside explicit flags, and deletes every signature from the scriptCode; this crate follows the node in every mode (0.3.27, bsv-rs#12). TS's `OP_SUBSTR`/`OP_LEFT`/`OP_RIGHT` names sit at `0xb3`-`0xb5`; this crate's constants of those names are the legacy `0x7f`-`0x81`, and `0xb3`-`0xb7` render as `OP_NOP4`-`OP_NOP8`.

## Where the numbers come from

`cargo test --features "full,http,websocket" --no-fail-fast 2>&1 | grep "^test result"` summed: 0.3.27 measured 2,923 passed / 0 failed / 128 ignored (the `rust,ignore` doc illustrations; with the ts-stack corpus present). `find src -name '*.rs' | xargs wc -l` for the line count. The vector counts are the JSON arrays' lengths under `tests/vectors/`; the corpus total is the pinned constant in `tests/conformance_scripts.rs`. Re-measure before you write a number down.

## Downstreams to keep in mind

`~/bsv/bsv-overlay-cloudflare` (`overlay-engine` executes scripts at the submit door with `Transaction::verify`; `overlay-cloudflare`, `low-app-layer` with `auth`), `~/bsv/rust-message-box` (the relay: `auth`, `socketio`, `wasm`), `~/bsv/bsv-low/workers/low-watchtower` (`wallet`, `auth`, `transaction`, `wasm`), `low-monitor` (`transaction`, `wasm`), `crates/low-tower-key`, `~/bsv/bsv-middleware-cloudflare-public`, `~/bsv/rust-chaintracks`. A change to a public struct's shape, an error text a downstream matches on, or a wasm-relevant dependency is a change to all of them: grep their `Cargo.toml`s and their code before you publish.
