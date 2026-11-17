# Lane fix-843d8b: the two overlay configs take `#[non_exhaustive]`

#843, the freeze plan's row 8, part b; BREAKING, on the captain's ruling of
2026-11-12 (class D: `Default` kept, a setter per field; not reopened). Run as
lane `fix-843d8b-2` on 2026-11-15 from beta `d892e206` (`origin/beta`'s tip
after `git fetch origin`). No reference line decides the row: the shape is
Rust's own, and no wire byte, verdict, default or error text moves.

## The site, side by side

| | Shape |
|---|---|
| `ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts:658-690` | `interface LookupResolverConfig`, nine optional members (`limits?`, `networkPreset?`, `facilitator?`, `slapTrackers?`, `hostOverrides?`, `additionalHosts?`, `cache?: CacheOptions` (`:588-595`, three members), `reputationStorage?`, `telemetry?`); the constructor takes `config = {}` (`:1264`) |
| `ts-stack@edf6e03` `SHIPBroadcaster.ts:62-85` | `interface SHIPBroadcasterConfig`, six optional members at `:70-84` (`networkPreset?`, `facilitator?`, `resolver?`, `requireAcknowledgmentFrom{AllHosts,AnyHost,SpecificHosts}ForTopics?`); the constructor takes `config = {}` (`:419`) |
| this crate at `d892e206` | `src/overlay/lookup_resolver.rs:26-50`, `pub struct LookupResolverConfig`, ten `pub` fields, a manual `Default` (`:52-67`); `src/overlay/topic_broadcaster.rs:40-79`, `pub struct TopicBroadcasterConfig`, six, a manual `Default` (`:81-92`); no attribute, setter or constructor: an outside caller writes a struct expression |
| this crate after the lane | both `#[non_exhaustive]`, `default()` unchanged, one `with_<field>` per field (sixteen), no struct expression of either outside the crate |

## The base check (step 1), at `d892e206`

The brief's three scans, run before anything was built; every figure is the
captain's restated one:

- all-public-field config and parameter structs (`Config|Options|Params|Limits`): 34, 6 attributed (`AuthFetchOptions`, `ChainParams`, `LookupLimits`, `LookupRequestOptions`, `PeerOptions`, `WebSocketTransportOptions`);
- top-level public enums: 74, 18 attributed (the scan's own `non_exhaustive` column; `Other` and `Sample`, twice each, are the samples of `src/util/non_exhaustive.rs`, unattributed);
- `#[deprecated`: 13 lines;
- struct expressions of the two configs outside `src/`: 107 in 56 files, all under `tests/` (`LookupResolverConfig` 94, `TopicBroadcasterConfig` 13); under `src/` 22 (the scan's 28 lines less the two declarations, the two `impl Default` lines and two lines of `src/overlay/CLAUDE.md`), which stay.

Both structs were as the brief quotes them. `tests/arch_non_exhaustive_pins_819.rs`
and `tests/arch_non_exhaustive_843d.rs` are both on the base and both were
taught.

## The source change

`src/overlay/lookup_resolver.rs` and `src/overlay/topic_broadcaster.rs` alone:
`#[non_exhaustive]` on its own line between the derive and `pub struct`; the
doc's compiled example of the setter form, the `compile_fail,E0639` `rebuilt`
block and its `kept` twin at the path `bsv_rs::overlay::<Name>`;
`assert_no_drop!` after the struct; under each `Default` impl one inherent
`impl` of `with_<field>` setters in field order, each a doc line, `#[must_use]`,
`pub fn with_x(mut self, value: T) -> Self` with `T` the field's own type. No
`new`. The ratchet's `duplicate_windows_40` reads 7119 on the base and 7119 on
the tip with the setters in field order in both impls (bound 8257), so neither
impl was reordered.

## The rewrite (step 4), one script

`rewrite_843d8b.py`, sha256 `fb5bf8ebd4df4c39b54807f4e71e08a35b6bf9c8a1a1089e060943e960edac47`, Python 3, standard library alone, run once
on the base's `tests/`:

```sh
python3 -I rewrite_843d8b.py tests
cargo fmt --all
```

````python
#!/usr/bin/env python3
"""#843d8b: every struct expression of LookupResolverConfig and
TopicBroadcasterConfig under a tree becomes default() (or its base) and a
setter per named field, each value expression moved byte for byte.

  (a) N { f: e, ..Default::default() }  ->  N::default().with_f(e)
  (b) N { f: e, ..BASE }                ->  BASE.with_f(e)
  (c) N { f: e, g }  (no base)          ->  N::default().with_f(e).with_g(g)

Usage: rewrite_843d8b.py <dir> [--dry]   (standard library alone)
Prints one line per site and the counts per struct and shape; exits 1 on a
site it cannot read. Run `cargo fmt --all` after it.
"""
import os
import re
import sys

NAMES = ("LookupResolverConfig", "TopicBroadcasterConfig")
SITE = re.compile(r"((?:[A-Za-z_][A-Za-z0-9_]*::)*)(%s) \{" % "|".join(NAMES))
FIELD = re.compile(r"([a-z_][a-z0-9_]*)\s*:(?!:)")
SHORT = re.compile(r"[a-z_][a-z0-9_]*\Z")
SIMPLE_BASE = re.compile(r"[A-Za-z0-9_:.]+\Z")
OPEN, CLOSE = "([{", ")]}"


def code_mask(text):
    """mask[i] is True where text[i] is code: no comment, string or char."""
    n = len(text)
    mask = [True] * n
    i = 0
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        start = i
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text[i:i + 2] == "/*":
                    depth, i = depth + 1, i + 2
                elif text[i:i + 2] == "*/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == "r" and re.match(r'r#*"', text[i:i + 40]) and not (
            i and (text[i - 1].isalnum() or text[i - 1] == "_") and text[i - 1] != "b"
        ):
            hashes = len(re.match(r"r(#*)", text[i:]).group(1))
            end = text.find('"' + "#" * hashes, i + 2 + hashes)
            if end < 0:
                raise SystemExit("unterminated raw string")
            i = end + 1 + hashes
        elif c == "'":
            if text[i + 1:i + 2] == "\\":
                j = text.find("'", i + 3)
                i = j + 1
            elif text[i + 2:i + 3] == "'":
                i += 3
            else:
                i += 1  # a lifetime
                continue
        else:
            i += 1
            continue
        for k in range(start, min(i, n)):
            mask[k] = False
    return mask


def matching(text, mask, at):
    """The index of the bracket closing the one at `at`."""
    depth = 0
    for i in range(at, len(text)):
        if not mask[i]:
            continue
        if text[i] in OPEN:
            depth += 1
        elif text[i] in CLOSE:
            depth -= 1
            if depth == 0:
                return i
    raise SystemExit("unbalanced at %d" % at)


def pieces(text, mask, lo, hi):
    """text[lo:hi] cut at its commas outside every bracket."""
    out, depth, start = [], 0, lo
    for i in range(lo, hi):
        if not mask[i]:
            continue
        if text[i] in OPEN:
            depth += 1
        elif text[i] in CLOSE:
            depth -= 1
        elif text[i] == "," and depth == 0:
            out.append((start, i))
            start = i + 1
    out.append((start, hi))
    return out


def trivia_end(text, mask, lo, hi):
    """Past the leading white space and comments of text[lo:hi]."""
    i = lo
    while i < hi and (not mask[i] or text[i].isspace()):
        # a string or char is not trivia: only comments are masked here
        if not mask[i] and text[i] in "\"'rb":
            break
        i += 1
    return i


def rewrite_site(text, mask, m):
    path, name = m.group(1), m.group(2)
    open_at = m.end() - 1
    close_at = matching(text, mask, open_at)
    raw = pieces(text, mask, open_at + 1, close_at)
    # A piece that opens no field continues the one before it (a comma of a
    # turbofish or of closure parameters).
    merged = []
    for lo, hi in raw:
        body = trivia_end(text, mask, lo, hi)
        rest = text[body:hi]
        opens = (
            rest.startswith("..")
            or FIELD.match(rest)
            or SHORT.match(rest.strip())
            or not rest.strip()
        )
        if opens or not merged:
            merged.append([lo, hi])
        else:
            merged[-1][1] = hi
    base, setters, tail = None, [], ""
    for lo, hi in merged:
        body = trivia_end(text, mask, lo, hi)
        lead = text[lo:body]
        comment = lead.strip()
        rest = text[body:hi]
        if not rest.strip():
            tail += comment and "\n" + comment + "\n"
            continue
        if base is not None:
            raise SystemExit("a field after the base")
        if rest.startswith(".."):
            base = rest[2:].strip()
            if comment:
                raise SystemExit("a comment before the base")
            continue
        fm = FIELD.match(rest)
        if fm:
            field, value = fm.group(1), rest[fm.end():].strip()
        elif SHORT.match(rest.strip()):
            field = value = rest.strip()
        else:
            raise SystemExit("unread piece: %r" % rest)
        setters.append((comment, field, value))
    if base is None:
        shape, head = "c", path + name + "::default()"
    elif base == "Default::default()":
        shape, head = "a", path + name + "::default()"
    else:
        shape = "b"
        # A path with calls and method calls binds tighter than the setter
        # that follows it; any other base is parenthesized.
        flat, depth = "", 0
        for ch, code in zip(base, code_mask(base)):
            if code and ch in OPEN:
                depth += 1
            elif code and ch in CLOSE:
                depth -= 1
            elif depth == 0:
                flat += ch
        head = base if SIMPLE_BASE.match(flat) else "(" + base + ")"
    out = head
    for comment, field, value in setters:
        if comment:
            out += "\n" + comment
        out += "\n.with_%s(%s)" % (field, value)
    out += tail
    return m.start(), close_at + 1, out, name, shape, len(setters)


def rewrite(text):
    done = []
    while True:
        mask = code_mask(text)
        sites = [
            m for m in SITE.finditer(text)
            if mask[m.start(2)]
            and "-> " not in text[text.rfind("\n", 0, m.start()) + 1:m.start()]
        ]
        if not sites:
            return text, done
        # The last site holds no other: an inner one is rewritten before the
        # one that holds it.
        lo, hi, out, name, shape, fields = rewrite_site(text, mask, sites[-1])
        line = text.count("\n", 0, lo) + 1
        text = text[:lo] + out + text[hi:]
        done.append((line, name, shape, fields))


def main():
    root = sys.argv[1]
    dry = "--dry" in sys.argv
    counts, files, fields_total = {}, 0, {}
    for folder, _, names in sorted(os.walk(root)):
        for file in sorted(names):
            if not file.endswith(".rs"):
                continue
            path = os.path.join(folder, file)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            new, done = rewrite(text)
            if not done:
                continue
            files += 1
            for line, name, shape, fields in sorted(done):
                print("%s:%d %s %s %d" % (path, line, name, shape, fields))
                counts[(name, shape)] = counts.get((name, shape), 0) + 1
                fields_total[name] = fields_total.get(name, 0) + fields
            if not dry:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(new)
    for name in NAMES:
        row = [counts.get((name, s), 0) for s in "abc"]
        print("%s: a %d, b %d, c %d, sites %d, fields %d"
              % (name, row[0], row[1], row[2], sum(row), fields_total.get(name, 0)))
    print("sites %d in %d files" % (sum(counts.values()), files))


if __name__ == "__main__":
    main()
````

Its counts on `d892e206` against step 1's:

| | (a) `..Default::default()` | (b) another base | (c) full literal | sites | field initializers |
|---|---:|---:|---:|---:|---:|
| `LookupResolverConfig` | 70 | 15 | 9 | 94 | 313 |
| `TopicBroadcasterConfig` | 11 | 0 | 2 | 13 | 36 |
| both | 81 | 15 | 11 | 107 in 56 files | 349 |

The same script run dry on the brief's older base `6bc872d7` gives the brief's
own figures (92 in 50 files; 84 and 8; 67, 14 and 11; 311 initializers, 286 and
25), so the reading is the drafter's. The fifteenth shape (b) site came with
#815 (`b36bca93`, `tests/lookup_discovery_779.rs`).

Shape (b) evaluates the base ahead of the arguments. The fifteen bases, read:
`config` (a parameter, `lookup_discovery_779.rs`), `trackers(&[TRACKER])`
(twice there), `overriding(SERVICE, &[..])` (twice in `lookup_limits_775.rs`),
and in `lookup_limits_configured_775.rs` `overriding(.., limits(..))` (five),
`tracking(.., limits(..))` or `tracking(.., limits)` (four) and
`super::overriding(service, &hosts, limits)` (one). Each is a pure constructor
of a config from its arguments (or a moved local); the field values are
`Some(facilitator)`, `Some(Arc::new(..))` of a scripted facilitator, a
`HashMap` and `limits`. No base has an effect an argument reads, and no
argument has an effect a base reads.

The re-derivation: `git archive d892e206` unpacked fresh, the script and
`cargo fmt --all` run on it, gives the tip's `tests/` byte for byte
(`diff -rq`), less:

- `tests/overlay_config_setters_843d8b.rs`, the new witness;
- `tests/lookup_limits_775.rs`: one hand fix, `LookupResolverConfig` dropped from the `use` of its `http` module, unused once that module's one site took a base's setter (`unused_imports`, refused by clippy's `-D warnings`);
- `tests/arch_non_exhaustive_843d.rs`: the two rows leave `ROWS`, `PENDING_LEN` 20 to 18, the census's attributed count 12 to 14 (two lines);
- `tests/arch_non_exhaustive_pins_819.rs`: `DOC_PINS` 24 to 26, the two names added;
- `tests/CLAUDE.md`: the new file's row and the two arch rows' counts.

`git diff -U0 d892e206..HEAD -- tests ':!tests/overlay_config_setters_843d8b.rs' | grep -c -E '^[+-].*assert'`
is 2, not 0: both lines are the census line of `arch_non_exhaustive_843d.rs`
(`assert_eq!(ROWS.len() + 12, ..)` to `+ 14`), the machine's own count, which
step 3 moves. Over the 56 rewritten files it is 0.

`git diff --dirstat=files,0 d892e206..HEAD`:

```
   1.5% docs/lanes/
   4.5% src/overlay/
   6.0% tests/support/
  84.8% tests/
```

## RED (step 5)

Scratch copies unpacked by `git archive` under the lane's out folder, one
target dir (`/Volumes/Lanes/targets/fix-843d8b-2-red-base`), one tree at a time.

- The base `d892e206` with `tests/overlay_config_setters_843d8b.rs` and three rewritten files overlaid (`overlay_mock_tests.rs`, `lookup_limits_configured_775.rs`, `overlay_integration_tests.rs`), `cargo test --features "full,http" --no-run --test <each>`: compile-RED, 47 errors, every one `error[E0599]` (19, 11, 12 and 5 in that order), no other error code.
- The tip less the two `#[non_exhaustive]` lines: `cargo test --doc --all-features -- overlay::lookup_resolver::LookupResolverConfig overlay::topic_broadcaster::TopicBroadcasterConfig`, 4 passed and 2 failed, the two `compile fail` tests (`lookup_resolver.rs` line 51, `topic_broadcaster.rs` line 62: the functional update compiles); `cargo test --features "full,http" --test arch_non_exhaustive_843d`, 2 of 6 failed, `every_all_public_struct_is_attributed_or_listed_843d8a` naming `src/overlay/lookup_resolver.rs:LookupResolverConfig` and `src/overlay/topic_broadcaster.rs:TopicBroadcasterConfig` ("every field is `pub` and it has no #[non_exhaustive]") and the census.

## The break's evidence (step 6)

- `cargo semver-checks check-release --baseline-rev d892e206 --all-features --release-type patch` (0.51.0): 229 checks, 228 pass, 1 fail, 0 warn, 31 skip. The one lint: `struct_marked_non_exhaustive`, on `TopicBroadcasterConfig` (`topic_broadcaster.rs:75`) and `LookupResolverConfig` (`lookup_resolver.rs:64`), each listed twice (its two public paths). No other lint.
- The rustdoc JSON of base and tip (`cargo +nightly rustdoc --lib --all-features -- -Z unstable-options --output-format json`, a target dir each; 17,706 and 17,724 items, compared item by item with ids aside): the two structs (the attribute, the doc, one more impl), two inherent impls, sixteen methods. One line besides, no API: the lint attribute `async_trait` writes on `TopicBroadcaster`'s `broadcast` and `broadcast_many` prints a compiler-interned number, `clippy#5009` on the base and `clippy#5011` on the tip.
- The dependents, read-only, `git grep -c -E 'LookupResolverConfig|TopicBroadcasterConfig'` at each clone's remote-tracking ref as it stood (no fetch): `~/bsv/bsv-wallet-toolbox-rs` `origin/beta` (`184c4182`) and `origin/main` (`3ddf48db`), `~/bsv/bsv-wallet-cli` `origin/beta` (`6dc14ef`) and `origin/main` (`2cc76c9`), `~/bsv/bsv-overlay-cloudflare` `origin/main` (`2abcd748`), `~/bsv/rust-message-box` `origin/main` (`44a6320`): none in any.

The pull request needs the `api-break` label (`semver` holds beta to a minor
change without it, #886).

## The gate (step 8)

`CARGO_BUILD_JOBS=2` (the host's swap use sat above half: 2,454 of 4,096 MB),
one cargo at a time, foreground, a target dir of the lane's own.

- The three fmt lines of beta's `lint` job: clean.
- `cargo clippy --all-targets --all-features -- -D warnings` and the job's twelve slices: clean.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`: clean.
- `cargo test --doc --all-features`: 390 passed, 128 ignored; the doc log read by `the_doc_suite_ran_every_pinned_block_819` (CI's step): passed.
- `cargo test --features "full,http" --lib` `overlay` 119, `kvstore` 76, `registry` 48, `identity` 126, `storage` 36, none failed.
- The wasm32 slice of rule 6: built.
- The whole suite, `--features "full,http,websocket" --no-fail-fast` (`--lib`, the `--test` targets in two halves, `--doc`), every `test result:` line summed: the tip 411 lines, 6,422 passed, 0 failed, 167 ignored; the base's scratch copy 410 lines, 6,413 passed, 0 failed, 167 ignored. The nine more are the three tests of `tests/overlay_config_setters_843d8b.rs` and six doc tests, three a struct (the setter example, the `compile_fail,E0639` block, its twin). Every `tests/{overlay,lookup,kvstore,registry,identity,storage}_*.rs`, `fixtures_replay` and every file naming either struct ran inside it. The two conformance files ran without the ts-stack corpus on both trees (a worktree has no `../ts-stack`; they skip loudly), so no conformance total was measured.
- `cargo test --features "full,http" --test 'arch_*'`: 38 binaries, 201 passed, 1 ignored (the doc log reader, run above).
- `cargo build --examples --all-features`; `cargo test --test readme_examples`: green.
- `tools/ratchet/run --check --against d892e206`: all 7 counters, the oversized-file limits and the mutation floors pass (`duplicate_windows_40` 7119, as the base; `lookup_resolver.rs` 747 lines, `topic_broadcaster.rs` 629).
- `python3 -B .github/scripts/mutants_entries.py`: PASS, 28 entries; `rows_from_sources.py --check`: 0 refusals.
- `gitleaks git --redact --no-banner --exit-code 1 --log-opts="d892e206..HEAD" .`: no leaks found.

## Carried onto beta after the changelog's cut (lane rebase-1005, 2026-11-16)

The commit carried onto `origin/beta` at `4c5454be` as one commit. What the
new base asked beyond the pull request's own change:

- Five test files that stable 0.8.10 and 0.8.11 brought built the two configs
  by a struct expression (nine expressions: eight `LookupResolverConfig` over
  `Default::default()`, one full `TopicBroadcasterConfig` literal) and moved
  to the setter form, every value expression as written, no assertion moved:
  `tests/beef_link_doors.rs` (3), `tests/kvstore_key_bound_signature.rs` (3),
  `tests/kvstore_empty_value.rs`, `tests/registry_definition_checks.rs`,
  `tests/registry_resolve_authenticated.rs`. So this crate's own count is 116
  expressions in 61 files on this base, the 107 in 56 above being the pull
  request's base's.
- The base's `BeefLinkLimits` (#749) is a pinned `#[non_exhaustive]` struct of
  its own, so the censuses read one more than the figures above:
  `DOC_PINS` 25 to 27 (33 types, 27 pinned, 6 listed), 15 attributed
  all-public structs from 13 of 220, `PENDING_LEN` 20 to 18 as before.
- `CHANGELOG.md` rebuilt as the base's file with this change's entry at the
  top of `## [Unreleased]`, the two census figures of its "What pins it"
  paragraph restated for this base and no other line of it moved.
