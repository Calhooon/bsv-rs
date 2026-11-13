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

**An allowance dies with its line (#347).** An allowlist entry that matches no
site its rule finds is red, and so is a ceiling above the sites it matches:
the failure names the entry, and the fix is to delete it or lower its ceiling
in the same change that removed the line. `arch_support::check_sites` applies
this to every `(file, line text, ceiling)` list (rules 1, 3, 4 and 5);
`arch_no_unwrap.rs` applies it to its `(file, ceiling)` list (rule 2), a file
gone or without a site as red as one under its ceiling. The other lists
already refuse a stale entry: `arch_ci_runs_every_test.rs`'s run-apart list
(a missing file, a file a whole-suite step runs), `arch_arc_deprecated.rs`'s
deprecated items (an item not found) and `arch_one_wallet_byte_bound.rs`'s
other constants (the found set must equal the list).
`arch_ci_pr_runs_the_required_set.rs`'s full-set exceptions
(`NOT_ON_THE_FULL_SET`) refuse an entry naming no job of `ci.yml`, or a job
that runs (or may) on an event the entry covers (#347's review). Two stale entries of
rule 3 (`http_json.rs:912`, `http_wire.rs:209` at `953d9c00`) outlived their
lines until #323's fold removed them by hand; that is what this refuses.

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
the entry at 0. A ceiling above its file's count, or an entry for a file with
no site, is red (#347). Moving a site to another file requires reviewing both entries.

The executable baseline at `efe12e6` is **40 sites in 8 files**:

| File | Ceiling | Cleanup owner |
| --- | ---: | --- |
| `src/overlay/overlay_admin_token_template.rs` | 3 | #78 tracks the remaining cleanup |
| `src/primitives/ec/public_key.rs` | 1 | #78 tracks the remaining cleanup |
| `src/primitives/hash.rs` | 5 | #78 tracks the remaining cleanup |
| `src/primitives/p256.rs` | 3 | #78 tracks the remaining cleanup |
| `src/primitives/symmetric.rs` | 1 | #78 tracks the remaining cleanup |
| `src/transaction/beef_stream.rs` | 23 | #86, the shared BEEF reader (24 at `efe12e6`; one site gone, lowered by #347) |
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

The conservative scan needs **21 protocol comparisons in 9 files** allowed
as whole source lines, with duplicate-count ceilings. An entry that matches no
line, or a ceiling above its line's copies, is red (#347): delete the entry
with its line.

| File | Sites | Existing purpose |
| --- | ---: | --- |
| `src/wallet/substrates/origin.rs` | 5 | The constructors' base URL path, scheme and loopback hosts (#323) |
| `src/wallet/substrates/http_json/result_values.rs` | 1 | The requested call is revealSpecificKeyLinkage, selecting its tuple shape (#408) |
| `src/wallet/substrates/http_json/result_values/shapes.rs` | 1 | The schema member is outputs, selecting output tags (#408) |
| `src/auth/transports/http/general.rs` | 5 | Auth header names and the certificateRequest message type (#416) |
| `src/auth/transports/http/response_bounds.rs` | 3 | Auth response header names (#416) |
| `src/auth/transports/http/unauthenticated.rs` | 1 | The answer's `Content-Type` `charset=`, for the refusal's body preview (#354) |
| `src/auth/transports/socketio/mod.rs` | 1 | Socket.IO event name |
| `src/auth/transports/websocket_transport.rs` | 2 | WebSocket URL schemes |
| `src/transaction/broadcasters/arc.rs` | 2 | Structured ARC status values |

Recounted after #416 and #408: #416 split the comparisons formerly in
`src/auth/transports/http.rs` between `http/general.rs` and
`http/response_bounds.rs`, including the `certificateRequest` comparison in
`general.rs`. #408 adds one selector each in
`src/wallet/substrates/http_json/result_values.rs` and its `shapes.rs` module.
The combined count is beta's 19 comparisons plus those two selectors.

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

**#323 (2026-10-27).** The four originator checks left `http_json.rs` and
`http_wire.rs` with the reference's `toOriginHeader` (`origin.rs`'s
`has_scheme`, no literal comparison) and their entries with them; five lines
of `origin.rs` took their place, the reference's `normalizeWalletHttpBaseUrl`
(the base URL's path `/`, its scheme `http`) and `isLoopbackHostname`
(`localhost`, `127.0.0.1`, `[::1]`): the caller's own constructor arguments
read once at construction, no answer read. They stay in `substrates/` beside
the client and the redirect refusal they are built with.

**#354 (2026-10-27).** One line of `http/unauthenticated.rs`: the
reference's `#isTextualContent` asks whether the answer's `Content-Type`
carries `charset=` (`SimplifiedFetchTransport.ts:559`) to write the unsigned
answer's body preview as text or hex. A header value read for the refusal's
words, not an error's text, and no class depends on it (the class is the
status's, by `status_fault`). The eight content types beside it are matched
from a constant, as the reference's `textualTokens` are, and are the same
kind of read.

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

Each `cargo test` or `cargo nextest run` line of ci.yml is a step (a
`--manifest-path` run tests another crate and is skipped); nextest takes
`cargo test`'s target selectors and features, and the Test Suite runs under it
since speed round 1 (`docs/lanes/ci-speed-1.md`), its doc tests alone under
`cargo test --doc`. A step is a whole-suite step when it carries
`--tests` or `--all-targets`, or `--test '*'` (cargo's glob over the
integration binaries, the lib's unit target not among them; the whole-suite
step's form since speed loop three, #672), or no target selector at all, and
names no other `--test`. Its feature set is its flags closed over the table (`--all-features`
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
| `tests/memory_profiling.rs` | `--test memory_profiling --all-features` (nextest, `RUST_TEST_THREADS=1` on the step) | `dhat-profiling` installs a global allocator; its step runs it alone, nextest giving each test a process of its own and `RUST_TEST_THREADS=1` keeping libtest single-threaded |
| `tests/wire_tracing_sink.rs` | `--all-features --test wire_tracing_sink` (since speed loop three, #672: the memory and doc steps' feature set, one library build) | the `tracing` feature is a diagnostics sink outside `full` (#212); its step adds it |

To add a test file: nothing. The `cargo nextest run --features
"full,http,websocket" --test '*'` step runs every file that feature set compiles, this guard included.
A file gated on a feature outside that set is refused until a step covers it.
To run a file apart as well (the `vectors` step's `--nocapture` runs, the
`fixtures` step, both of the `checks` job): name it in that step AND leave it covered by the whole suite.
Only a file that cannot run in the whole suite belongs in the allowlist, with
its reason and its step.

Since cut 4 (#667, `docs/lanes/ci-speed-4.md`) a pull request runs the
binaries its changed files reach (`.github/scripts/affected_tests.py`, its
tests `test_affected_tests.py`), and the whole suite runs on a push, a
dispatch, a tag's call, a plan of everything and a pull request labeled
`full-suite` (the landing run; the label read live through the API). The
whole-suite step above stays the coverage, under the plan's `whole` flag. A
step whose words carry a `$VARIABLE` is the reached step, never a whole-suite
one, and `reached_refusals` refuses, in the Test Suite job:

- a test step under a condition other than a plan flag
  (`steps.plan.outputs.<flag> == 'true'`), the whole-suite step under any
  flag but `whole`, the reached step outside `whole != 'true'`;
- a reached step with no whole-suite step;
- a plan whose path for a run that is not a pull request leaves a flag a
  step reads unset (a push would skip that step);
- a plan without the event test, the live label read, the `full-suite`
  match, the subset check (`affected_tests.py check`) or its own tests;
- a `labeled` trigger (a label would start a second run).

## 7. The small gates are steps of `lint` and `checks`

`tests/arch_ci_lines.rs` (`BUNDLES`) pins the bundling of CI speed round 1,
cut 2 (`docs/lanes/ci-speed-2.md`). The gates that were each a runner of
their own, its setup longer than the gate for most of them, are steps of two
jobs, one checkout, one toolchain setup and one `Swatinem/rust-cache` restore
each: `lint` carries Rustfmt, Clippy (`--all-targets --all-features`, then
each published slice alone), deny and ratchet; `checks` carries mutants-entries (#663),
front-pages (`.github/scripts/test_front_pages.py`), judge-tests (#97: the node oracle's judge and
its harness, `.github/scripts/test_sibling_*.py`), vectors, fixtures, front page
(`tests/front_page.rs`), secrets, Documentation and wasm32 (combined). `main-in-beta`,
`semver`, `beta-born` and the dependents jobs stay jobs of their own, on
their own events. The guard refuses, naming the job and the gate:

- a gate whose step is gone, or a step with an `id:` that no verdict names;
- a gate that does not run after an earlier gate failed (its `if:` is
  `${{ !cancelled() && steps.ready.outcome == 'success' }}`, the setup green);
- a gate that prints no `PASS <gate>` or `FAIL <gate>` line of its own (its
  exit trap);
- a last step that is not `Every gate passed` on `!cancelled()`, does not
  judge every gate's outcome, or does not fail naming the gates that did not
  pass;
- a matrix on either job, or a second cache restore;
- a bundled gate back as a job of its own.

The mutants-entries gate (#663) runs `.github/scripts/mutants_entries.py`:
every `.cargo/mutants.toml` equivalence entry must name exactly one mutant
of `cargo mutants --list --file <file> --no-config` (a listing, nothing
built), at the nightly's `CARGO_MUTANTS_VERSION`. The same file's
`every_mutants_entry_is_checked_in_checks_and_the_pin_job_at_one_version_663`
refuses a `checks` job without it, a nightly pin job that does not run it
before its plan, a workflow that passes `--fix`, and two versions of
cargo-mutants between `ci.yml` and `nightly.yml`.

The required contexts become `lint` and `checks` in place of the nine;
`tests/arch_ci_pr_runs_the_required_set.rs`'s `REQUIRED_ON_BETA` (five) and
`REQUIRED_ON_MAIN` (six) carry them.

## 8. A heavy run holds the runners of its window

Every matrix that is a heavy run on the account's runners (a job that runs
mutants or fuzzes) carries `max-parallel`: the nightly's three (the mutant
shards of the window's waves, their tail, the fuzz targets) read the mutation
plan's `max_parallel`, `max_parallel_tail` and `max_parallel_fuzz` outputs and
no literal (the tail at six for the waves projected past the window's end,
#791's fold, the keeper's word of 2026-11-04 18:0xZ), the figure by window (#791, the owner's word of 2026-11-04
17:1xZ through the keeper: fourteen of the twenty inside the run's own
window, 01:00Z to 09:00Z, when no other heavy run of the account is
scheduled there, six otherwise; the dispatch input `heavy_max_parallel`
over both, 1 to 20; `HEAVY_WINDOWS` and `heavy_max_parallel` in
`.github/scripts/nightly_mutants.py`, owned by #675), any other a literal at
most 6 (`tests/arch_nightly_cap.rs`; until #791 six in every hour, the
keeper's line of 10:0xZ 2026-11-03, 14 from 06:2xZ before it,
`docs/lanes/ci-speed-7.md`). In the nightly no
two heavy jobs (a heavy matrix or a dispatch of `ci.yml`, a whole run of up
to 22 jobs) can hold the runners at once: each pair is ordered by a `needs:`
path; the tail needs the window's shards, fuzz and the score job need both,
`ci-full-beta` needs the shards and the fuzz targets, and `ci-full-main` needs `ci-full-beta`, which waits
for beta's run (`gh run watch`), the one it dispatched (the runs listed
before the dispatch, the bot's alone), and fails on its `failure`
conclusion (#682's third fold) and on a failed watch other than the
give-up, the step under `set -euo pipefail` (#682's fourth fold); no dispatch of `ci.yml` sits in a matrix.
`ci.yml`'s matrices (the Test Suite cells, the dependents) carry
`max-parallel` at most 6, which a dispatch reads (the keeper's word (a),
#682's second fold), as do a tag, a push to main and a pull request into
main for the dependents. A matrix cap does not bound a run's singleton jobs:
main's dispatched run holds up to 22 for about a minute and a half.

## Feature and wasm builds

The `features` job (`features.yml`, on dispatch and before every tag) builds cargo-hack **0.6.45** from source using its release
lockfile into `$RUNNER_TEMP/tools`, then runs:

```sh
cargo hack check --each-feature --no-dev-deps
```

It checks all 21 declared features, plus cargo-hack's empty and all-feature
cases, without dev-dependency feature unification. The six `wasm32` slices
(`wasm32 (combined)`, a step of `ci.yml`'s `checks` on every event, the other five in
`features.yml`) use `--target wasm32-unknown-unknown --no-default-features`:

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
