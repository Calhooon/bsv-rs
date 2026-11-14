#!/usr/bin/env python3
"""Refuse a duplicate dependency version the list does not hold (#104).

`cargo deny` warns on a crate the graph holds in two versions and passes
(`deny.toml`, `multiple-versions = "warn"`, nothing skipped), so a change of
this crate's manifest, or a release of a crate under it, could add one with
every gate green. This check reads the resolved graph of each slice the crate
ships (`GRAPHS`: `cargo tree --locked`, normal, build and development edges,
nothing built) and compares the crates held in more than one version with
`docs/duplicate-versions.txt`, one row a crate:

    graphs | crate | lines | reason

`graphs` are the graphs that hold the pair, `lines` the semver-compatible
lines held (`2, 3`; `0.22, 0.23`), so a patch release under a row moves
nothing and a third line under it is refused. It refuses, naming the graph and
the crate: a duplicate with no row, a row's crate held in other lines than the
row says, a row naming a graph that holds no such pair (the list only records
what the graphs hold: the row or the graph is deleted when a pair ends), and a
row that is not the four cells, names a crate or a graph twice, is out of
order or gives no reason. `tests/arch_duplicate_versions_104.rs` pins the
list's totals and the lines of `ci.yml` that run this check.
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys

LIST = "docs/duplicate-versions.txt"

# The graphs, by the name a row uses. `all`, `wasm32` and `default` are the three
# `cargo-deny` checks (`ci.yml`, the `deny` step of `lint`); `native` is the widest
# slice the crate documents (`full,http,websocket`, without the three internal features
# `--all-features` adds). `--target all` reads every platform's dependencies, so the
# answer of `all`, `native` and `default` is the same on any runner. `wasm32` names its
# target, as its `cargo-deny` check does, and there cargo evaluates build and proc-macro
# edges for the runner's host: that graph alone can differ between runners (it holds the
# same three pairs on macOS arm64 as cargo-deny counts, 2026-11-14).
WASM32_SLICE = "auth,wallet,transaction,overlay,socketio,wasm"
GRAPHS = {
    "all": ["--all-features", "--target", "all"],
    "native": ["--features", "full,http,websocket", "--target", "all"],
    "wasm32": ["--no-default-features", "--features", WASM32_SLICE,
               "--target", "wasm32-unknown-unknown"],
    "default": ["--target", "all"],
}


def line_of(version):
    """The semver-compatible line of a version: `3` of 3.0.10, `0.22` of 0.22.1,
    `0.0.4` of 0.0.4 (the leftmost nonzero part and what is left of it)."""
    core = version.split("-")[0].split("+")[0].split(".")
    for at, part in enumerate(core):
        if part != "0":
            return ".".join(core[:at + 1])
    return ".".join(core)


def line_key(line):
    """A line's order: numeric by part, a part that is no number after every number."""
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in line.split(".")]


# A package line of `cargo tree --prefix none --format {p}`, whole: the crate's name, one
# space, `v` and a version of three numeric parts with an optional pre-release and build
# part (`0.9.0-beta.7`, `0.11.1+wasi-snapshot-preview1`), then nothing or marks in
# parentheses to the line's end: `(proc-macro)`, the source of a package not from
# crates.io (a path, a registry, a git URL) and `(*)` for a subtree printed before. Those
# are the forms cargo 1.98.1 prints for the four graphs of this crate (2,372 lines read,
# 2026-11-14); any other line, a diagnostic whose second word starts with `v` among them,
# is no package line and is refused.
PACKAGE = re.compile(r"([A-Za-z0-9_-]+) v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)"
                     r"(?: \(.*\))?")


def tree_versions(output):
    """`cargo tree --prefix none --format {p}`: each crate's versions. A line that is
    empty is passed; one that is not `PACKAGE`, whole, raises."""
    versions = {}
    for raw in output.splitlines():
        if not raw:
            continue
        line = PACKAGE.fullmatch(raw)
        if line is None:
            raise ValueError(f"not a `cargo tree` package line: {raw}")
        versions.setdefault(line[1], set()).add(line[2])
    return versions


def duplicates(versions):
    """The crates held in more than one version: crate to its versions, in line order."""
    return {name: sorted(held, key=lambda v: (line_key(line_of(v)), v))
            for name, held in versions.items() if len(held) > 1}


def parse_rows(text):
    """The list's rows as (graphs, crate, lines, reason), and what is wrong with the list."""
    rows, errors = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        cells = [c.strip() for c in raw.split("|")]
        if len(cells) != 4:
            errors.append(f"{LIST}:{number}: {len(cells)} cells, not `graphs | crate | lines | reason`")
            continue
        graphs = [g.strip() for g in cells[0].split(",")]
        name = cells[1]
        lines = [v.strip() for v in cells[2].split(",")]
        for graph in graphs:
            if graph not in GRAPHS:
                errors.append(f"{LIST}:{number}: `{graph}` is no graph ({', '.join(GRAPHS)})")
        if graphs != [g for g in GRAPHS if g in graphs]:
            errors.append(f"{LIST}:{number}: {name}: the graphs are not each once in the order {', '.join(GRAPHS)}")
        if not name or " " in name:
            errors.append(f"{LIST}:{number}: `{name}` is no crate name")
        if len(lines) < 2 or lines != sorted(set(lines), key=line_key) or any(
                not v or line_of(v) != v for v in lines):
            errors.append(f"{LIST}:{number}: {name}: `{cells[2]}` is not two or more distinct lines in order")
        if not cells[3]:
            errors.append(f"{LIST}:{number}: {name}: no reason")
        if rows and name <= rows[-1][1]:
            errors.append(f"{LIST}:{number}: {name}: not after `{rows[-1][1]}` (one row a crate, by name)")
        rows.append((graphs, name, lines, cells[3]))
    return rows, errors


def judge(rows, found):
    """Each difference between the rows and the graphs' duplicates (`found`: graph to
    `duplicates`' answer), one line each."""
    errors = []
    listed = {graph: {} for graph in GRAPHS}
    for graphs, name, lines, _ in rows:
        for graph in graphs:
            if graph in listed:
                listed[graph][name] = lines
    for graph in GRAPHS:
        held = found[graph]
        for name in sorted(set(held) | set(listed[graph])):
            versions = held.get(name)
            lines = listed[graph].get(name)
            if lines is None:
                errors.append(
                    f"NEW duplicate in `{graph}`: {name} {', '.join(versions)} has no row in {LIST}: "
                    f"remove the second version, or add the row with its reason and move the "
                    f"pinned totals (tests/arch_duplicate_versions_104.rs)")
            elif versions is None:
                errors.append(
                    f"STALE row in `{graph}`: {name} is held in one version or none: delete `{graph}` "
                    f"from its row (the row when no graph is left) and move the pinned totals")
            elif [line_of(v) for v in versions] != lines:
                errors.append(
                    f"MOVED duplicate in `{graph}`: {name} {', '.join(versions)} is not the row's "
                    f"lines {', '.join(lines)}")
    return errors


def cargo_tree(graph, manifest):
    """One graph's package lines from the lockfile as resolved, nothing built."""
    command = ["cargo", "tree", "--locked", "--color", "never", "--manifest-path", str(manifest),
               "-e", "normal,build,dev", "--prefix", "none", "--format", "{p}", *GRAPHS[graph]]
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=Path(__file__).resolve().parents[2], type=Path,
                        help="the crate's directory (its Cargo.toml, Cargo.lock and the list)")
    root = parser.parse_args(argv).root
    rows, errors = parse_rows((root / LIST).read_text(encoding="utf-8"))
    try:
        found = {graph: duplicates(tree_versions(cargo_tree(graph, root / "Cargo.toml")))
                 for graph in GRAPHS}
    except subprocess.CalledProcessError as error:
        print(f"duplicate versions: `{' '.join(error.cmd)}` failed:\n{error.stderr}", file=sys.stderr)
        return 1
    errors += judge(rows, found)
    counts = ", ".join(f"{graph} {len(found[graph])}" for graph in GRAPHS)
    print(f"duplicate versions: {counts}; {len(rows)} rows in {LIST}")
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
