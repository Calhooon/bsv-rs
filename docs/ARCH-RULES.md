# Architecture rules

These source guards implement [#80](https://github.com/Calhooon/bsv-rs/issues/80).
They run in the existing CI test matrix, without contacting a service. They
scan every Rust file under `src/`, independent of the features enabled for the
test binary. `tests/` and doc examples are outside the library scan.

`tests/arch_support/mod.rs` tokenizes comments, strings and character literals
without treating their contents as code. It skips balanced items guarded by
`cfg(test)` and `cfg(all(test, ...))`, including nested modules, and continues
scanning the production code after them. A `cfg(any(test, feature = ...))`
item still has a production path and is scanned. File-level test cfgs are
also recognized. The portability rule additionally evaluates cfgs with
`target_arch = "wasm32"`; an unknown feature cannot hide a possible wasm path.

This is a lexical guard, not a type checker or a macro expander. Known client
names and import sites are checked; a dependency with a new client name must
extend the vocabulary. Arbitrary re-exports, generated code and string
comparisons through indirect helpers still require review. Test code in a
separate file should carry its own test cfg. Each failure names a source file
and its original line number.

## 1. Network clients live at transport boundaries

`tests/arch_network_sites.rs` permits client names only in:

- `src/wallet/substrates/`
- `src/auth/transports/`
- `src/transaction/broadcasters/`
- `src/transaction/chain_trackers/`
- `src/overlay/facilitators.rs`

The overlay facilitator file is the fifth home: its concrete SHIP and SLAP
adapters own the HTTP clients. The resolver, historian, retry logic and host
reputation tracker are consumers of those adapters; granting all of
`src/overlay/` permission would erase that boundary.

The vocabulary includes `reqwest`, `tokio_tungstenite`, other common HTTP
client crates, `web_sys`, `Fetch`, and TCP, UDP and WebSocket client types.
An import using an alias is caught at its import. Comments and documentation
about transports do not count.

Existing exceptions at `efe12e6`: **6 sites in 3 files**. Each exact source line
has a multiplicity ceiling, so another client in that file is refused.

| File | Sites | Reason |
| --- | ---: | --- |
| `src/storage/downloader.rs` | 2 | Existing UHRP client construction and its parameter type |
| `src/storage/uploader.rs` | 2 | Existing UHRP client field and construction |
| `src/transaction/fee_models/live_policy.rs` | 2 | Existing policy endpoint client field and construction |

[#87](https://github.com/Calhooon/bsv-rs/issues/87) audits the substrate and
client boundaries. These exceptions need relocation into a permitted adapter
before their entries can be deleted; changing the public surface is outside
this guard's scope.

## 2. Executable unwrap and expect counts may only fall

`tests/arch_no_unwrap.rs` counts calls to `unwrap` and `expect`, including
qualified calls and calls split across lines. It ignores `unwrap_or`, strings,
comments and test-only items. A file absent from the allowlist has ceiling 0.
When a cleanup reduces a count, reduce its ceiling in the same change; remove
the entry at 0. Moving a site to another file requires reviewing both entries.

The executable baseline at `efe12e6` is **40 sites in 8 files**:

| File | Ceiling | Cleanup owner |
| --- | ---: | --- |
| `src/overlay/overlay_admin_token_template.rs` | 3 | #78 tracks the remaining cleanup |
| `src/primitives/ec/public_key.rs` | 1 | #78 tracks the remaining cleanup |
| `src/primitives/hash.rs` | 5 | #78 tracks the remaining cleanup |
| `src/primitives/p256.rs` | 3 | #78 tracks the remaining cleanup |
| `src/primitives/symmetric.rs` | 1 | #78 tracks the remaining cleanup |
| `src/transaction/beef_stream.rs` | 24 | #86, the shared BEEF reader |
| `src/transaction/transaction.rs` | 2 | #86, the shared BEEF reader |
| `src/wallet/key_deriver.rs` | 1 | #78 tracks the remaining cleanup |

The historical **276 in 48 files** in #78 is a different census: textual
`.unwrap(`/`.expect(` before an exact `#[cfg(test)]` marker. It includes doc
examples and the WebSocket tests under a compound cfg, and misses the
production call after the test-only import in `wallet/key_deriver.rs`.
It must not become a 40-site executable budget plus 236 spare exceptions.
The #78 token scanner at `8236d1d` independently measures 40 on this tree;
the lane's evidence records its source-counter replay and both censuses.
Keep the per-file ceilings aligned with that ratchet as counts fall.
[#85](https://github.com/Calhooon/bsv-rs/issues/85) owns the
script split, whose executable count is already 0 here; its documentation
examples still contribute to the historical census.

## 3. Transport errors are classified by type

`tests/arch_no_string_errors.rs` scans the four transport directories above.
It refuses new `contains` and `starts_with` calls on literal text, string
equality on either side, `Some(literal)` comparisons, and equality involving
`to_string`/`to_owned`. It intentionally checks more than variables named
`error`: renaming an error to `message` must not bypass the guard.

The conservative scan needs **17 protocol comparisons in 6 files** allowed
as whole source lines, with duplicate-count ceilings:

| File | Sites | Existing purpose |
| --- | ---: | --- |
| `src/wallet/substrates/http_json.rs` | 2 | Originator URL schemes |
| `src/wallet/substrates/http_wire.rs` | 2 | Originator URL schemes |
| `src/auth/transports/http.rs` | 8 | Auth header names and message types |
| `src/auth/transports/socketio/mod.rs` | 1 | Socket.IO event name |
| `src/auth/transports/websocket_transport.rs` | 2 | WebSocket URL schemes |
| `src/transaction/broadcasters/arc.rs` | 2 | Structured ARC status values |

These are protocol fields, not error-message exceptions. No file is exempt
as a whole. Legitimate protocol comparisons need not be rewritten into
different syntax merely to empty a conservative scanner's list. Overlay retry
and reputation policy are outside this rule's specified four-directory scope.

**#87's review (2026-10-24).** Each of the 17 sites read where it stands, and
each kept as a protocol comparison: the four originator checks compare a
caller's URL scheme (`http://`, `https://`) to build an `Origin` header; the
two WebSocket checks a configured URL's scheme (`ws://`, `wss://`); the six
lines of `auth/transports/http.rs` header names (`x-bsv-`, `x-bsv-auth`,
`authorization`, `content-type`) and one the BRC-104 `x-bsv-auth-message-type`
value `certificateRequest`; the Socket.IO line the `authMessage` event name;
the two ARC lines the `ORPHAN` word of ARC's structured `txStatus` and
`extraInfo` (the reference's rule, `ARC.ts:110-180`). None reads an error's
text: the error-message allowances are empty. Every transport fault is
classified by type, in one place: `src/transaction/broadcasters/transport_fault.rs`
reads `reqwest::Error`'s kind and the answer's status (before the body); the
four directories call it (rule 1 keeps the client in a transport home, and
`transaction` is the lowest gate the four share). It adds no line to the list.

## 4. Environment belongs to the caller

`tests/arch_no_env.rs` forbids `std::env` in production library code, including
direct, grouped and aliased imports of that module. **Allowlist: empty.**
Callers supply configuration. Tests may locate the external corpus with
`BSV_CONFORMANCE_DIR`. No cleanup issue is needed for this empty baseline.

## 5. Time and threads must be portable

`tests/arch_no_system_time.rs` forbids `SystemTime` and `std::thread::spawn`
outside `src/util/` and code that cannot compile on wasm32. It also catches
direct aliased imports of the native thread module. **Allowlist: empty.**
The util module is the existing portability boundary. A native cfg applies
only to its item or block, not to the rest of the file. No cleanup issue is
needed for this empty baseline.

## 6. CI runs every integration test binary

`tests/arch_ci_runs_every_test.rs` implements step 2 of
[#146](https://github.com/Calhooon/bsv-rs/issues/146). The Test Suite once
enumerated its binaries by hand and drifted to 34 of 73 files; the arch
tests, the wallet wire suites and `readme_examples` never ran on a PR. Unlike
sections 1 to 5, this rule reads no library source. It reads
`.github/workflows/ci.yml`, the `[features]` table of `Cargo.toml`, and every
top-level `tests/*.rs` (each an integration binary; `support/`,
`arch_support/` and the other directories are modules, not binaries).

Each `cargo test` line of ci.yml is a step (a `--manifest-path` run tests
another crate and is skipped). A step is a whole-suite step when it carries
`--tests` or `--all-targets`, or no target selector at all, and names no
`--test`. Its feature set is its flags closed over the table (`--all-features`
is every feature). A file's gate is its file-level `#![cfg(...)]` attributes,
evaluated on `feature`, `all`, `any` and `not`; any other predicate (a target,
an OS) is a finding, never a pass. The guard refuses, naming the file:

- a file no whole-suite step compiles, unless it is allowlisted below;
- an allowlisted file a whole-suite step already runs, or one no
  `--test <name>` step runs on features that compile it;
- a `--test <name>` anywhere in ci.yml with no `tests/<name>.rs` (a renamed
  file leaves a dead step), or one whose features compile its file to no tests;
- a `[[test]]` or `autotests` in `Cargo.toml` (the file list would no longer
  be the binary list).

**Allowlist: two entries.**

| File | Step | Reason |
| --- | --- | --- |
| `tests/memory_profiling.rs` | `--test memory_profiling --all-features -- --test-threads=1` | `dhat-profiling` installs a global allocator; it runs alone, single-threaded |
| `tests/wire_tracing_sink.rs` | `--features "full,http,tracing" --test wire_tracing_sink` | the `tracing` feature is a diagnostics sink outside `full` (#212); its step adds it |

To add a test file: nothing. The `cargo test --features "full,http,websocket"
--tests` step runs every file that feature set compiles, this guard included.
A file gated on a feature outside that set is refused until a step covers it.
To run a file apart as well (the `vectors` job's `--nocapture` runs, the
`fixtures` job): name it in that step AND leave it covered by the whole suite.
Only a file that cannot run in the whole suite belongs in the allowlist, with
its reason and its step.

## Feature and wasm builds

CI's `features` job builds cargo-hack **0.6.45** from source using its release
lockfile into `$RUNNER_TEMP/tools`, then runs:

```sh
cargo hack check --each-feature --no-dev-deps
```

It checks all 21 declared features, plus cargo-hack's empty and all-feature
cases, without dev-dependency feature unification. The six `wasm32` matrix
rows use `--target wasm32-unknown-unknown --no-default-features`:

| Consumer | Features |
| --- | --- |
| Combined | `auth,wallet,transaction,overlay,socketio,wasm` |
| Watchtower | `wallet,auth,transaction,wasm` |
| Monitor | `transaction,wasm` |
| Chaintracks | `block` |
| Overlay | `overlay,wasm` |
| Relay | `auth,socketio,wasm` |

Every row runs `cargo build --lib` and then `cargo rustc --lib --crate-type
cdylib` with `-C link-dead-code=yes`, printing the resulting `.wasm` byte
count. The crate otherwise emits an `.rlib`; the extra link keeps the size
from collapsing to an empty module with no exported application functions.
These are unoptimized diagnostic library sizes, not deployable Worker sizes.
[#96](https://github.com/Calhooon/bsv-rs/issues/96) owns the size budget.

Baseline finding at `efe12e6`, fixed before this landed: with the workflow's
`RUSTFLAGS=-Dwarnings`, the native `block`, `compat`, `primitives` and `totp`
checks and the wasm `block` slice failed on `after_last_code_separator` being
unused without `script`; #115 gated it (beta `b8dd6cb`), and the dependents
check (#83) had found the same on chaintracks-cloudflare's `block` slice. Every
feature builds alone since.

## Verification and review

Run the six `arch_*` integration tests with `cargo test --test <name>`.
Their scanner regression cases cover comments, raw strings, compound cfgs,
production code after test modules, aliases, and native block boundaries.
A source violation planted in a scratch copy must fail the corresponding
guard, including a new site in an already allowlisted file. Never mutate the
working library to demonstrate the negative case.

These choices satisfy T5 (the boundaries and exceptions are visible) and T6
(the rules and feature slices execute). The scan scales with this source tree
rather than the chain (T1), and is local and inexpensive (T3). It makes no new
claim about headers or proofs (T2) or script verdicts (T4); no library behavior
changes in this lane.
