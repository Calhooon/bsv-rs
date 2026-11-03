#!/usr/bin/env python3
"""Check every `.cargo/mutants.toml` equivalence entry against the mutant list (#663).

An `exclude_re` entry names one mutant by its file, line, column and text. A
line shift leaves it naming a line that holds no such mutant: it excludes
nothing, the equivalent mutant runs at its new line and survives, and the file
reads below its true figure. This check lists the mutants of every file the
entries name (`cargo mutants --list --file <file> --no-config`, a listing from
the source, nothing built) and asserts that each entry matches exactly one
listed mutant. A miss prints the entry and its re-point: the listed mutants of
the same text at the same column (else at any column) that no other entry
holds; when the stale entries of one text and the free candidates are as many,
they pair in line order (a shift keeps their order), else every candidate is
printed and none is chosen. A double match prints every line it matches.

`--fix` rewrites each stale entry whose re-point is unique, and the
`<line>:<column>` it names in the comment block above it, for the captain's
hand use; CI never passes it. Exit status: 0 every entry holds, 1 an entry is
stale or ambiguous, 2 the configuration or the listing could not be read.

The cargo-mutants version is the nightly's (`CARGO_MUTANTS_VERSION` in
`.github/workflows/nightly.yml`); when that variable is set the listing tool
must report it.
"""

import argparse
from collections import defaultdict
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


CONFIG = Path(".cargo/mutants.toml")
ENTRY = re.compile(r"^\^(?P<path>(?:[a-z0-9_]+/)+[a-z0-9_]+)\\\.rs:(?P<line>\d+):(?P<col>\d+): (?P<text>.*)\$$")
LISTED = re.compile(r"^(?P<file>\S+\.rs):(?P<line>\d+):(?P<col>\d+): (?P<text>.*)$")


class Entry:
    """One `exclude_re` pattern, read into the mutant it names."""

    def __init__(self, pattern):
        self.pattern = pattern
        match = ENTRY.match(pattern)
        if not match:
            raise ValueError(f"not an anchored `^<file>\\.rs:<line>:<col>: <text>$` entry: {pattern}")
        self.file = match.group("path") + ".rs"
        self.line = int(match.group("line"))
        self.col = int(match.group("col"))
        self.text = re.compile(match.group("text"))
        self.regex = re.compile(pattern)

    def same_text(self, listed):
        """The listed mutants of this entry's file whose text is the entry's."""
        return [m for m in listed if m.file == self.file and self.text.fullmatch(m.text)]


class Listed:
    """One line of `cargo mutants --list`."""

    def __init__(self, raw):
        self.raw = raw
        match = LISTED.match(raw)
        if not match:
            raise ValueError(f"not a mutant listing line: {raw}")
        self.file = match.group("file")
        self.line = int(match.group("line"))
        self.col = int(match.group("col"))
        self.text = match.group("text")


def entries_of(text):
    """The configuration's `exclude_re` entries, in order."""
    return [Entry(p) for p in tomllib.loads(text).get("exclude_re", [])]


def cargo_listing(file):
    """The mutants cargo-mutants lists for one file, nothing built."""
    want = os.environ.get("CARGO_MUTANTS_VERSION")
    if want:
        have = subprocess.run(["cargo", "mutants", "--version"], check=True,
                              capture_output=True, text=True).stdout.split()
        if have[-1:] != [want]:
            raise RuntimeError(f"cargo-mutants {' '.join(have[1:])} is not the nightly's {want}")
    out = subprocess.run(["cargo", "mutants", "--list", "--file", file, "--no-config"],
                         check=True, capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line.strip()]


def check(entries, listing):
    """Each entry judged: (entry, matched lines, candidates, re-point or None)."""
    listed = [Listed(raw) for raw in listing]
    matched = {id(e): [m for m in listed if e.regex.search(m.raw)] for e in entries}
    held = {m.raw for ms in matched.values() if len(ms) == 1 for m in ms}
    stale = [e for e in entries if not matched[id(e)]]
    candidates = {}
    groups = defaultdict(list)
    for entry in stale:
        free = [m for m in entry.same_text(listed) if m.raw not in held]
        same_col = [m for m in free if m.col == entry.col]
        candidates[id(entry)] = same_col or free
        key = (entry.file, entry.text.pattern, entry.col if same_col else None)
        groups[key].append(entry)
    repoint = {}
    for group in groups.values():
        pool = candidates[id(group[0])]
        if len(pool) == len(group):
            group.sort(key=lambda e: e.line)
            for entry, target in zip(group, sorted(pool, key=lambda m: m.line)):
                repoint[id(entry)] = target
    return [(e, matched[id(e)], candidates.get(id(e), []), repoint.get(id(e))) for e in entries]


def report(verdicts, out=sys.stdout):
    """Print each failing entry; the count of failures."""
    failures = 0
    seen = defaultdict(int)
    for entry, matched, candidates, target in verdicts:
        seen[entry.pattern] += 1
        if seen[entry.pattern] == 2:
            failures += 1
            print(f"DUPLICATE entry: {entry.pattern}", file=out)
        if len(matched) == 1:
            continue
        failures += 1
        if len(matched) > 1:
            print(f"DOUBLE match ({len(matched)} mutants): {entry.pattern}", file=out)
            for m in matched:
                print(f"  matches: {m.raw}", file=out)
            continue
        print(f"STALE entry (no listed mutant): {entry.pattern}", file=out)
        if target is not None:
            print(f"  re-point to {target.line}:{target.col}: {target.raw}", file=out)
        elif candidates:
            print(f"  no unique re-point; {len(candidates)} candidates:", file=out)
            for m in candidates:
                print(f"  candidate: {m.raw}", file=out)
        else:
            print(f"  no listed mutant of {entry.file} carries this text", file=out)
    return failures


def fix(text, verdicts):
    """The configuration with every uniquely re-pointed entry and its comment rewritten."""
    lines = text.split("\n")
    moves = {}
    for entry, matched, _, target in verdicts:
        if matched or target is None:
            continue
        old = f"{entry.line}:{entry.col}"
        new = f"{target.line}:{target.col}"
        for quote in ("'''", "'"):
            literal = f"{quote}{entry.pattern}{quote}"
            at = next((i for i, line in enumerate(lines) if line.strip().rstrip(",") == literal), None)
            if at is not None:
                break
        if at is None:
            continue
        lines[at] = lines[at].replace(f"\\.rs:{old}:", f"\\.rs:{new}:", 1)
        start = at
        while start > 0 and lines[start - 1].lstrip().startswith("'"):
            start -= 1
        comment = start
        while comment > 0 and lines[comment - 1].lstrip().startswith("#"):
            comment -= 1
        block = (comment, start)
        if moves.setdefault(block, {}).setdefault(old, new) != new:
            moves[block][old] = None  # one old position, two new ones: the comment is left
    for (begin, end), mapping in moves.items():
        mapping = {o: n for o, n in mapping.items() if n is not None and o != n}
        if not mapping:
            continue
        token = re.compile(r"(?<![\d.])(" + "|".join(re.escape(o) for o in mapping) + r")(?![\d])")
        for i in range(begin, end):
            lines[i] = token.sub(lambda m: mapping[m.group(1)], lines[i])
    return "\n".join(lines)


def main(argv=None, listing_of=cargo_listing, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--fix", action="store_true",
                        help="rewrite each stale entry whose re-point is unique (by hand, never in CI)")
    args = parser.parse_args(argv)
    try:
        text = args.config.read_text()
        entries = entries_of(text)
        listing = []
        for file in sorted({e.file for e in entries}):
            listing.extend(listing_of(file))
        verdicts = check(entries, listing)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as err:
        print(f"FAIL mutants-entries: {err}", file=out)
        return 2
    failures = report(verdicts, out)
    files = len({e.file for e in entries})
    if args.fix and failures:
        fixed = fix(text, verdicts)
        if fixed != text:
            args.config.write_text(fixed)
            print(f"rewrote {args.config}; run again to check it", file=out)
    if failures:
        print(f"FAIL mutants-entries: {failures} of {len(entries)} entries do not name exactly "
              f"one listed mutant ({files} files listed)", file=out)
        return 1
    print(f"PASS mutants-entries: {len(entries)} entries, each one listed mutant "
          f"({files} files, {len(listing)} mutants listed)", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
