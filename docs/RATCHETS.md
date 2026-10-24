# Code-health ratchets

The `ratchet` job in [.github/workflows/ci.yml](../.github/workflows/ci.yml)
measures the library and compares it with [ratchets.json](ratchets.json).
An increase fails with the counter, its limit and the excess. Each existing
oversized file also has its own line limit; a new oversized file is refused
even when another one disappears. Smaller results pass. This records debt
without permitting new debt to hide inside the same total.

## Run and record

The Rust binary is a separate crate at
[tools/ratchet/Cargo.toml](../tools/ratchet/Cargo.toml), outside the library's
workspace. Since `tools/ratchet` is a directory, its command entry point is
`tools/ratchet/run`. The root manifest and the library's public API are not
changed by this tool.

```sh
export CARGO_TARGET_DIR="$HOME/bsv/targets/oracle-ratchet"
mkdir -p "$CARGO_TARGET_DIR"
# Set TMPDIR to an existing external scratch directory if it is not set.
tools/ratchet/run             # one JSON object on stdout; progress on stderr
tools/ratchet/run --check     # exit 1 for increases, exit 2 for tool errors
tools/ratchet/run --check --against COMMIT # also protect the baseline itself
tools/ratchet/run --revision COMMIT  # measure the committed tree
```

The runner uses Rust **1.95.0**, including its Clippy and rustdoc, and the
tool's committed Cargo.lock. It builds the library from a temporary copy,
using [library.Cargo.lock](../tools/ratchet/library.Cargo.lock) for the library
dependencies. The library has no tracked Cargo.lock. Keeping this separate
measurement lock prevents changing dependency resolution from changing the
warning census. All Cargo calls that measure the library use `--locked`.
Dependency downloads are reads from the registry; no library code is run by
measurement. No wallet or network service is called.

Set `TMPDIR` (or `RUNNER_TEMP`) and `CARGO_TARGET_DIR` outside the checkout.
The runner refuses build output inside the checkout. The temporary copy is
removed at exit; library compiler output stays in `ratchet-library/` under
the external target directory, separate from the tool's own build.
Ordinary measurement reads current tracked and untracked, nonignored source
files, including uncommitted edits. `--revision` uses `git archive` instead.

To lower a bound, make the source improvement and commit it, then run:

```sh
tools/ratchet/run --record
tools/ratchet/run --check
git add docs/ratchets.json
git commit -m "ratchet: record the reduced code-health bounds"
```

Use `--record` only in a PR that explicitly says it records a new baseline.
Keep that baseline update in its own commit. `--record` requires committed
sources, unless `--revision COMMIT` explicitly selects a committed snapshot.
It replaces the whole baseline and records the measured commit, rather than
editing individual limits. CI compares the proposed baseline with the PR
base (or previous push) using `--against`, so raising a recorded limit cannot
hide an increase in code. An ancestor without a baseline is the bootstrap
case. Reviewers also compare the old and new JSON. A toolchain, method,
exemption or dependency-lock change
also needs an explicit review of the changed census; do not refresh a
baseline just to turn a red check green.

The bootstrap baseline is measured from `origin/beta` at
`efe12e63c6f27cc4d4c888f12a5b7897e492f073` (v0.8.2), not inferred from
the issue's earlier summary. In that tree five wordlist files have 2,061
lines; the other four data files are shorter. The exemptions below name all
nine data files. The source commit is provenance, not a number to minimize.
The issue's unwrap/expect total is a seed figure, not an expected fixture for
this scanner: comments and documentation examples are not executable calls
and do not contribute to the token census. Keep the measured output when it
differs from a text search.
No timestamp, absolute path or machine name appears in the JSON. Repeated
runs on the same tree and pinned tools produce the same bytes.

## What each counter means

All source counters inspect `.rs` files under `src/`, in sorted path order.
They exclude `tests/`, benches, examples and this measurement crate. The file
size counter includes inline test code, comments and blank lines because
those still contribute to the size of a file a reader must navigate.

| JSON counter | Measurement | Why it may only fall; the work that removes it |
| --- | --- | --- |
| `files_over_800` | Number of files with more than 800 physical lines, with a sorted `{path, lines}` inventory. A final line without a newline counts. The nine named wordlist data files are exempt from this counter only; `wordlists/mod.rs` and future files are not exempt. | Large files obscure ownership and review. [#85](https://github.com/Calhooon/bsv-rs/issues/85) and [#86](https://github.com/Calhooon/bsv-rs/issues/86) split the interpreter and BEEF/transaction surfaces. The other entries remain visible for follow-up lanes. |
| `unwrap_expect` | Spelled `.unwrap(...)`, `.expect(...)`, `Type::unwrap(...)` and `Type::expect(...)` calls, including turbofish calls and calls inside macro token bodies. Rust tokens distinguish calls from comments, strings, fields and `unwrap_or`. | A panic cannot be recovered on the wasm host. [#80](https://github.com/Calhooon/bsv-rs/issues/80)'s allowlist classifies the surviving sites; an allow in source never discounts this lexical count. |
| `functions_over_60` | Parsed free functions, impl methods and trait default methods whose body spans more than 60 physical lines, including its braces. Signatures and attributes are excluded. Closures and macro-generated functions are not counted as function declarations. | Shorter functions expose control flow and make tests more focused. The extraction lanes #85 and #86 reduce these alongside their file inventories. |
| `cognitive_complexity_over_25` | Distinct root-library Clippy `cognitive_complexity` warnings, with `cognitive-complexity-threshold = 25`. | Excess branching makes the rules harder to review. Control-flow extractions should reduce this without changing evaluator behavior; #85 and #86 carry the relevant witnesses. |
| `missing_docs` | Distinct root-library `missing_docs` warnings from `cargo doc --no-deps --lib --all-features`, with `RUSTDOCFLAGS='--cap-lints allow --force-warn missing_docs'`. | A new public item needs a stated contract. This should stay empty; a public-surface change must supply its docs. |
| `duplicate_windows_40` | Excess occurrences of identical sliding windows of 40 production Rust tokens, summed across files. For a window seen N times, count N minus 1; overlapping windows count and no window crosses a file boundary. FNV-1a hashes length-delimited UTF-8 token spellings into 64 bits; exact interned-token comparisons settle hash collisions. Identifiers and literal values are retained; whitespace, comments and doc attributes are omitted. | Repeated implementation drifts when a rule changes. Extract shared logic in a behavior-preserving lane with witnesses; #85 and #86 can reduce their repeated blocks. This is a duplication signal, not a count of independent refactor opportunities. |
| `pedantic_warnings` | Distinct root-library Clippy warnings emitted with `--cap-lints allow --force-warn clippy::pedantic --force-warn clippy::cognitive_complexity`, excluding the separately counted cognitive lint. | New code should not expand the review backlog. Reduce warnings in focused lanes; no blanket allow is a substitute for review. |

The exact data exemption paths are `src/compat/bip39/wordlists/` plus
`chinese_simplified.rs`, `chinese_traditional.rs`, `czech.rs`, `english.rs`,
`french.rs`, `italian.rs`, `japanese.rs`, `korean.rs` and `spanish.rs`.
[#89](https://github.com/Calhooon/bsv-rs/issues/89) moves this data to text.

The token and function counters omit items with `#[test]` and code whose
`#[cfg(...)]` cannot hold with `test = false`. This includes nested test
modules and `all(test, ...)`. An `any(test, feature = "...")` item can be
production code, so it remains counted. Out-of-line test modules are followed
through the module graph and excluded only when not also referenced by a
production module. Test-only expressions, local bindings and match arms are
also omitted. Ordinary `#[allow(...)]` attributes do not exempt token counts.

This is a syntactic census: method names are not type-resolved and macros are
not expanded. Macro token bodies contribute call spellings and duplication;
test conditions created inside a macro are not interpreted. All feature
branches contribute to the source census. Compiler counters instead measure
the native library with all features enabled, not tests or dependencies.
The measured lints are forced warnings, so source-level lint allows cannot
hide them. Other lints are capped to allow in this measurement pass; the
ordinary Clippy CI job still enforces the library's lint policy. Using
`-A warnings -W ...` would incorrectly suppress the wanted warnings too.
A warning is
deduplicated by lint code, primary locations and diagnostic message, so a
Cargo diagnostic replay cannot inflate it. A compiler failure or malformed
diagnostic stream is an error, never an empty warning count.

## Proof and the six lane tests

The [independent tool tests](../tools/ratchet/src/) check exclusions,
threshold boundaries, duplicate-window accounting, diagnostic scoping,
baseline validation and each independent counter's rejection. Run them with:

```sh
cargo +1.95.0 test --locked --manifest-path tools/ratchet/Cargo.toml
cargo +1.95.0 clippy --locked --manifest-path tools/ratchet/Cargo.toml --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path tools/ratchet/Cargo.toml -- --check
```

### When a dependency changes

The compiler counters build a scratch copy of the library with
`tools/ratchet/library.Cargo.lock` in place, so two runs resolve the same
crates. A PR that adds, removes or bumps a dependency in the root
`Cargo.toml` makes that lock stale, and `--check` stops with
`cargo clippy ... failed ...; the library lock is stale: refresh
tools/ratchet/library.Cargo.lock (docs/RATCHETS.md, "When a dependency
changes")` and records nothing. The refresh, tested on 2026-10-24 with a
planted `semver = "1"` (one entry gained, nothing else moved):

```sh
S="$(mktemp -d "${TMPDIR:-/tmp}/ratchet-lock-XXXX")"
git archive HEAD | tar -x -C "$S"
cp tools/ratchet/library.Cargo.lock "$S/Cargo.lock"
(cd "$S" && cargo +1.95.0 metadata --format-version 1 >/dev/null)   # updates the lock minimally
cp "$S/Cargo.lock" tools/ratchet/library.Cargo.lock
rm -rf "$S"
```

Commit the refreshed lock on its own, in the PR that moved the dependency;
then `tools/ratchet/run --check` again. A lock refresh moves no counter by
itself (the counters read the library's source, not its dependencies); if one
moves, the PR changed code too and the number stands on its own.

The stack's [gate-leg shape](https://github.com/Calhooon/bsv-stack-lean)
is a named job with its executable proof and recorded result. For these
measurement choices: T1 measures the source tree rather than chain history;
T2 is not exercised because no transaction verdict or chain proof changes;
T3 shares Cargo build output and interns duplicate tokens; T4 defines each
counter and comparison as executable arithmetic; T5 pins tools and input
provenance rather than trusting an issue's numbers; T6 supplies the command,
failure path, tests and CI job. The compiler, token and baseline choices all
have that same scope. Script/transaction conformance belongs to their code
lanes; this lane changes neither surface.
