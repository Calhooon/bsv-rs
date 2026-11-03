#!/usr/bin/env python3
"""The Test Suite's plan on a pull request: the test targets its changed files reach (#667).

The night's reach rule (`nightly_mutants.py`, #666) maps a changed path to the
measured sources it re-mutates; this maps a changed path to the test targets
that can see it: the integration binaries (`tests/*.rs`), the unit tests
(`--lib`), the doc tests, the memory binary and the tracing step's three. It
reuses the night's readings (`test_rows`, `is_doc`, `is_test_only`,
`callers`) and runs as its own script because its question is the inverse one:
the night asks which mutants a change can create, this which tests can fail.

A pull request runs the reached targets; the whole suite runs on a push to a
line, on a dispatch and a tag's call, when the plan says everything, and on the
landing run, which the sequencer marks with the `full-suite` label
(docs/lanes/ci-speed-4.md).
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nightly_mutants as nightly  # noqa: E402

# A change to these can move any test's verdict.
EVERYTHING = {
    "Cargo.toml": "the manifest: a dependency, a feature or a profile reaches every target",
    "Cargo.lock": "the resolved graph",
    "build.rs": "the build script runs before every target",
    "src/lib.rs": "the crate root: every module, its re-exports and the crate docs",
    "src/error.rs": "the one Error every module returns and every test compares",
    ".github/workflows/ci.yml": "the Test Suite's own steps",
    ".github/scripts/affected_tests.py": "this plan",
    "rust-toolchain.toml": "the toolchain",
    "rust-toolchain": "the toolchain",
}
EVERYTHING_UNDER = {
    "src/error/": "the Error enum's parts",
    ".cargo/config": "cargo's configuration: every build (`.cargo/mutants.toml` is the night's alone)",
    ".config/": "nextest's configuration",
}
# Run apart from the integration step, each by a step of its own (tests/arch_ci_runs_every_test.rs).
APART = {"memory_profiling", "wire_tracing_sink"}
# The tracing step's three binaries (`--all-features`, which carries `tracing`; #672).
TRACING = ("wire_tracing_sink", "wire_error_frames", "fixtures_replay")
# Names too common to stand for one file when a source names them alone.
GENERIC_NAMES = {"CLAUDE.md", "README.md", "mod.rs", "main.rs", "lib.rs", "Cargo.toml"}
LABEL = "full-suite"
# The one Markdown file a gate of `lint` reads: the ratchet measures it (tools/ratchet/src/tree.rs).
MEASURED_MARKDOWN = {"README.md"}
# The trees a gate of `lint` runs as its own code: the ratchet's (tools/ratchet/run), whose
# Markdown is never docs only either (#688 fold).
GATE_TREES = ("tools/ratchet/",)


def binaries(root):
    """The integration binaries: every top-level `tests/*.rs`, by stem."""
    return sorted(p.stem for p in (root / "tests").glob("*.rs"))


def module_sources(root, file):
    """The file and every module file it declares, transitively (`mod x;`, `#[path]`)."""
    seen, todo = [], [Path(file)]
    declaration = re.compile(
        r'(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z0-9_]+)\s*;')
    while todo:
        path = todo.pop()
        if path in seen or not (root / path).is_file():
            continue
        seen.append(path)
        text = (root / path).read_text(errors="replace")
        is_root = path.parent == Path("tests") and path.suffix == ".rs"
        home = path.parent if is_root or path.name == "mod.rs" else path.with_suffix("")
        for attribute, name in declaration.findall(text):
            if attribute:
                todo.append(Path(os.path.normpath(path.parent / attribute)))
            else:
                todo += [home / f"{name}.rs", home / name / "mod.rs"]
    return [str(p) for p in seen]


def reexports(root):
    """The crate root's `pub use <module>::...` names, each to its module."""
    text = (root / "src" / "lib.rs").read_text(errors="replace")
    names = {}
    for module, body in re.findall(r"pub use ([a-z_]+)::(\{[^}]*\}|[A-Za-z_]+)", text):
        for item in re.split(r"[{},\s]+", body):
            # a function as a type: `bsv_rs::sha256`, `bsv_rs::sign` (#708 fold: the fourteen
            # lowercase names went uncounted, against the convention's "a crate-root re-export")
            if item and item != "as" and (item[0].isupper() or re.fullmatch(r"[a-z_][a-z0-9_]*", item)):
                names[item] = module
    return names


def crate_groups(text, crate):
    """The bodies of `<crate>::{...}` groups, nested braces kept."""
    bodies = []
    for match in re.finditer(rf"\b{re.escape(crate)}::\{{", text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            end += 1
        bodies.append(text[match.end():end - 1])
    return bodies


def group_heads(body):
    """The leading name of each top-level item of a `use` group (`script::{A, B}` gives `script`)."""
    heads, depth, item = [], 0, ""
    for c in re.sub(r"//[^\n]*", "", body) + ",":
        depth += {"{": 1, "}": -1}.get(c, 0)
        if c == "," and depth == 0:
            head = re.match(r"\s*([A-Za-z_]\w*)", item)
            heads += [head.group(1)] if head else []
            item = ""
        else:
            item += c
    return heads


def used_modules(text, modules, exported):
    """The crate's top-level modules a test source names: a `bsv_rs::<m>` path, or a root
    re-export named through the crate (`bsv_rs::Name`, an item of a `bsv_rs::{...}` group;
    `bsv_rs as x` reads `x::` the same). A re-exported name met anywhere else is no use (#706:
    the word reading took `WalletFaultFamily::Transport` for `auth` and a comment's "Address"
    for `script`); a glob `bsv_rs::*` keeps the word reading, the names it imports unlisted."""
    found = set()
    for crate in {"bsv_rs", *re.findall(r"\bbsv_rs\s+as\s+([a-z_]\w*)", text)}:
        heads = re.findall(rf"\b{re.escape(crate)}::([A-Za-z_]\w*)", text)
        for body in crate_groups(text, crate):
            heads += group_heads(body)
        found |= {m for m in heads if m in modules}
        found |= {exported[name] for name in heads if name in exported}
        if re.search(rf"\b{re.escape(crate)}::\*", text) and exported:
            types = sorted(n for n in exported if n[0].isupper())
            calls = sorted(n for n in exported if not n[0].isupper())
            if types:
                words = re.compile(r"\b(" + "|".join(map(re.escape, types)) + r")\b")
                found |= {exported[name] for name in words.findall(text)}
            if calls:
                # a function the glob imports is a bare call: `sign(`, never `.sign(`,
                # `x::sign(` or `fn sign(`
                bare = re.compile(r"(?<![\w.:])(?<!fn )(" + "|".join(map(re.escape, calls)) + r")\s*\(")
                found |= {exported[name] for name in bare.findall(text)}
    return found


# The `## Files` table's columns (#706): the module naming is the fourth cell.
MODULES_CELL = 4


def row_cells(row):
    """A table row's cells, the outer pipes dropped (a `\\|` inside a cell kept)."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


def shared_cell(cell):
    """A shared row's Modules cell, file by file (#708 fold): `` `a.rs`: `m`, `n`; `b.rs`: none ``
    gives each file's stem to its modules' names; None when the cell names no file."""
    if not re.search(r"`[^`]+\.rs`", cell):
        return None
    parts = {}
    for part in cell.split(";"):
        names = re.findall(r"`([^`]+)`", part)
        if names and names[0].endswith(".rs"):
            parts[Path(names[0]).stem] = {n for n in names[1:] if not n.endswith(".rs")}
    return parts


def row_modules(row, modules, stem=None):
    """The modules a `tests/CLAUDE.md` row names: the backticked names of its Modules cell
    (#706). A path in the description (`src/<m>/`, `` `<m>::` ``) names nothing: the rows
    point at other files' witnesses that way (`src/identity/client_field_value_261_tests.rs`
    in an auth binary's row), which put a binary in a module it never reaches. A row of
    four cells is the table before #706 (read at an older commit, or a fixture of its
    shape), read by the night's two patterns as it was then; the guard refuses one in the
    tree (`tests/arch_tests_claude_rows_name_modules_706.rs`). A row shared by several files
    names each file's modules apart (`shared_cell`), and `stem`'s part is its reading: the
    row's union is no file's (#708 fold: the #537 and #544 rows put twelve binaries in
    modules their sources never name)."""
    cells = row_cells(row)
    if len(cells) > MODULES_CELL:
        cell = cells[MODULES_CELL - 1]
        shared = shared_cell(cell)
        if shared is not None:
            chosen = shared.get(stem, set()) if stem else set().union(*shared.values())
            return chosen & modules
        return set(re.findall(r"`([a-z_]+)`", cell)) & modules
    named = set(re.findall(r"src/([a-z_]+)/", row)) | set(
        re.findall(r"`(?:crate::|bsv_rs::|bsv::)?([a-z_]+)::", row))
    return named & modules


# One token of a Rust source that can hold a quote: a comment, a raw string
# (`r#"..."#`), a string, a char literal (`'"'`); a lifetime (`'a`) matches none.
TOKEN = re.compile(r"""//[^\n]*|/\*.*?\*/|(?<![\w])b?r(#*)"(.*?)"\1|"((?:[^"\\]|\\.)*)"|'(?:\\[^']{1,10}|[^'\\\n])'""",
                   re.DOTALL)


def strings(text):
    """The string literals of a Rust source, in order, read past comments and char literals."""
    return [raw if quote is None else quote
            for _, raw, quote in ((m.group(1), m.group(2), m.group(3)) for m in TOKEN.finditer(text))
            if raw is not None or quote is not None] if text else []


def literals(text):
    """The directories a source reads under: a `format!` template's directory
    (`"/tests/vectors/{}.json"` gives `tests/vectors`) always, and every other literal
    when the source walks a tree (`read_dir`); a word that happens to name a directory
    (`"docs"`, `"tests"` as a JSON key) is no read."""
    walks = re.search(r"\bread_dir\b", text) is not None
    found = set()
    for literal in strings(text):
        if "{" in literal:
            literal = literal.split("{", 1)[0].rpartition("/")[0]
        elif not walks:
            continue
        found.add(literal.lstrip("/").removeprefix("./").rstrip("/"))
    return found


def literal_text(text):
    """The source's string literals alone, one per line: a file is read by a literal,
    never by a comment that names it."""
    return "\n".join(strings(text))


def names_path(text, path):
    """True when `text` names `path`: its whole path, or (for a distinctive name, or any
    file under `tests/`) its name whole, or its directory two deep under `tests/` (#666 F3)."""
    target = Path(path)
    # the whole path, not the tail of a longer one (`CLAUDE.md` inside `tests/CLAUDE.md`);
    # `\Z`, never `$`, which also matches before a newline: the text is one literal per line,
    # so `$` read the previous literal's last character as this path's (#680 fold). A slash
    # opening a literal (`concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")`) is a path
    # joined to the manifest directory: the text holds no quotes, so the literal's start is
    # the text's start or a newline.
    for match in re.finditer(re.escape(path), text):
        before = text[max(0, match.start() - 2):match.start()]
        if not re.search(r"[\w./-]\Z", before) or before in ("/", "\n/"):
            return True
    if path.startswith("tests/") or target.name not in GENERIC_NAMES:
        if re.search(rf"(?<![\w.-]){re.escape(target.name)}(?![\w-])", text):
            return True
    if path.startswith("tests/"):
        directory = target.parent.relative_to("tests")
        return len(directory.parts) >= 2 and f"{directory.as_posix()}/" in text
    return False


class Tree:
    """The head tree's readings, each read once."""

    def __init__(self, root):
        self.root = root
        self.binaries = binaries(root)
        self.modules = {p.name for p in (root / "src").iterdir() if p.is_dir()}
        self.exported = reexports(root)
        self.rows = nightly.test_rows(root)
        self.sources = {b: module_sources(root, f"tests/{b}.rs") for b in self.binaries}
        self.texts = {b: "\n".join((root / s).read_text(errors="replace") for s in sources)
                      for b, sources in self.sources.items()}
        self.literal_texts = {b: literal_text(t) for b, t in self.texts.items()}
        self.uses = {b: used_modules(t, self.modules, self.exported) | row_modules(
            self.rows.get(b, ""), self.modules, b) for b, t in self.texts.items()}
        # `os.path.isdir`, never `Path.is_dir`: a literal longer than a file name (a BEEF hex
        # string) raises `OSError` (ENAMETOOLONG) from `Path.is_dir` on Python 3.11 to 3.13,
        # the runner's 3.12 among them; `os.path.isdir` answers False on any `OSError` (#680 fold)
        self.directories = {b: {d for d in literals(t) if d and d != "." and (
            os.path.isdir(root / d) or os.path.isdir(root / "tests" / d))}
            for b, t in self.texts.items()}
        library = [p for p in sorted((root / "src").rglob("*.rs"))]
        self.library = {str(p.relative_to(root)): p.read_text(errors="replace") for p in library}
        self.library_literals = {f: strings(t) for f, t in self.library.items()}

    def walkers(self, path):
        """The binaries whose sources name a directory `path` lies under (a tree they walk)."""
        def under(d):
            return any(path == f"{base}" or path.startswith(f"{base}/") for base in (d, f"tests/{d}"))
        return {b for b, ds in self.directories.items() if any(under(d) for d in ds)}

    def namers(self, path):
        """The binaries whose sources name `path` or declare it as a module."""
        return {b for b, t in self.literal_texts.items()
                if path in self.sources[b][1:] or names_path(t, path)}

    def callers(self, module):
        """The modules whose non-test sources name `crate::<module>` (the one-level graph)."""
        sources = {f for f in self.library if len(f.split("/")) > 2 and not nightly.is_test_only(f, self.root)}
        calling = nightly.callers(module, sources, lambda f: self.library[f])
        return {f.split("/")[1] for f in calling} - {module}

    def direct(self, module):
        """The binaries that name `module` themselves: a `bsv_rs::<module>` path, a crate-root
        re-export of it, or their `tests/CLAUDE.md` row naming it or a file of it. The night's
        selection for its files (#685, the keeper's word of 2026-11-03 16:1xZ)."""
        return {b for b, used in self.uses.items() if module in used}

    def users(self, module):
        """The modules naming `crate::<module>` and the binaries that use `module` or one of
        them: a library change's reach on a pull request, where a build and not a run per
        mutant is the cost (the night's selection is `direct`, without the callers' level)."""
        calling = self.callers(module)
        return calling, {b for b, used in self.uses.items() if used & ({module} | calling)}

    def library_names(self, path):
        """True when a library source names `path` (an `include_str!` of a vector, a unit test's
        fixture), so the unit tests can see it."""
        for source, found in self.library_literals.items():
            for literal in found:
                if literal and os.path.normpath(Path(source).parent / literal) == path:
                    return True
            if names_path("\n".join(found), path):
                return True
        return False


def changed_rows(base_rows, head_rows):
    """The binaries whose `tests/CLAUDE.md` row text differs between the base and the head."""
    return {stem for stem in set(base_rows) | set(head_rows)
            if base_rows.get(stem) != head_rows.get(stem)}


def reach(changed, root=Path("."), base_rows=None, tree=None):
    """Each changed path to the targets it reaches.

    Returns the plan: `everything` (the path that reaches every target, or None),
    `lib`, `doc`, `binaries` (each to the changed paths and reasons that reach it)
    and `reasons` (each changed path to what it reaches and why). `base_rows` is the
    base's `tests/CLAUDE.md` text: a changed row reaches its binary, and the rows
    decide nothing else here than which binaries a library change reaches, which the
    head's rows decide (None when the base has none: every row is new). `tree` is the
    head tree's readings when the caller holds them already (the night's selection, #685).
    """
    tree = tree or Tree(root)
    plan = {"everything": None, "lib": False, "doc": False, "binaries": {}, "reasons": {}}

    def add(binary_set, path, why):
        for b in sorted(binary_set):
            if b in tree.binaries:
                plan["binaries"].setdefault(b, []).append(f"{path}: {why}")

    for path in sorted(changed):
        whole = EVERYTHING.get(path) or next(
            (why for prefix, why in EVERYTHING_UNDER.items() if path.startswith(prefix)), None)
        if whole:
            plan["everything"] = path
            plan["reasons"][path] = {"reaches": "everything", "why": whole}
            continue
        reached, why = set(), []
        walkers = tree.walkers(path)
        namers = tree.namers(path) - walkers
        if path.startswith("src/") and not nightly.is_doc(path):
            plan["lib"] = plan["doc"] = True
            module = path.split("/")[1]
            if path.endswith(".rs") and nightly.is_test_only(path, root):
                why.append("a test-only module: the unit tests alone compile it")
            elif module in tree.modules:
                calling, users = tree.users(module)
                reached |= users
                why.append(f"src/{module}/ and, one level, the modules naming crate::{module} "
                           f"({', '.join(sorted(calling)) or 'none'}): {len(users)} binaries use them")
            else:
                plan["everything"] = path
                plan["reasons"][path] = {"reaches": "everything", "why": "a crate-root source"}
                continue
        elif path == "tests/CLAUDE.md":
            rows = changed_rows(nightly.test_rows(root, base_rows or ""), tree.rows)
            reached |= rows
            why.append(f"the test rows: the {len(rows)} binaries whose row changed")
        elif path.startswith("tests/") and path.count("/") == 1 and path.endswith(".rs"):
            stem = Path(path).stem
            if stem in tree.binaries:
                reached.add(stem)
                why.append("a test binary: itself")
            else:
                why.append("a removed test binary: nothing left to run")
        elif tree.library_names(path):
            plan["lib"] = plan["doc"] = True
            why.append("named by a library source: the unit and doc tests")
        reached |= walkers | namers
        if namers:
            why.append(f"named by {len(namers)} binaries' sources")
        if walkers:
            why.append(f"under a directory {len(walkers)} binaries walk")
        if not why:
            why.append("no target compiles or names it" if not nightly.is_doc(path)
                       else "documentation no test reads" if is_documentation(path)
                       else "no test reads it; a gate's record or tree, never docs only")
        add(reached, path, "; ".join(why))
        plan["reasons"][path] = {"reaches": sorted(reached & set(tree.binaries)),
                                 "why": "; ".join(why)}
    if plan["everything"]:
        plan.update(lib=True, doc=True, binaries={b: [f"{plan['everything']}: everything"]
                                                  for b in tree.binaries})
    plan["all_binaries"] = tree.binaries
    return plan


def finish(plan, changed, whole_reason=None):
    """The plan as the workflow reads it."""
    if whole_reason:
        plan.update(everything=whole_reason, lib=True, doc=True,
                    binaries={b: [whole_reason] for b in plan["all_binaries"]})
    reached = sorted(plan["binaries"])
    integration = [b for b in reached if b not in APART]
    return {
        "schema_version": 1,
        "changed": sorted(changed),
        "everything": plan["everything"] is not None,
        "why_everything": plan["everything"],
        "lib": plan["lib"],
        "doc": plan["doc"],
        "integration": integration,
        "memory": "memory_profiling" in reached,
        "tracing": any(b in reached for b in TRACING),
        "src_changed": any(p.startswith("src/") and not nightly.is_doc(p) for p in changed),
        "build": plan["everything"] is not None or plan["lib"] or plan["doc"] or bool(reached),
        "reached": {b: plan["binaries"][b] for b in reached},
        "total": len(plan["all_binaries"]),
        "reasons": plan["reasons"],
    }


def is_documentation(path):
    """A path a docs-only change may touch (#668, the #688 fold): Markdown (`*.md`, under
    `docs/` or anywhere), other than the Markdown a gate measures and any file of a gate's
    own tree. A file under `docs/` that is not Markdown is data a tool reads, never docs only:
    `docs/ratchets.json` is the ratchet's record (`tools/ratchet/src/tree.rs`), and a pull
    request loosening it that skipped the ratchet would land red on the line's push run;
    `docs/dependents.lock` is the dependents job's list, the census JSON the oracle's."""
    return (path.endswith(".md") and path not in MEASURED_MARKDOWN
            and not path.startswith(GATE_TREES))


def docs_only(result, runs=()):
    """A docs-only change (#668): every changed path documentation (`is_documentation`),
    nothing everything, no unit or doc test, and none of `runs` (the binaries a job runs by
    name) reached. An empty change is not docs-only."""
    return (bool(result["changed"])
            and all(is_documentation(p) for p in result["changed"])
            and not result["everything"] and not result["lib"] and not result["doc"]
            and not set(result["reached"]) & set(runs))


def changed_files(repo, revisions):
    return subprocess.check_output(["git", "diff", "--name-only", "--no-renames", revisions],
                                   cwd=repo, text=True).split()


def base_of(repo, revisions):
    """The diff's base: `A` of `A..B`, the merge base of `A...B`."""
    if "..." in revisions:
        left, right = revisions.split("...", 1)
        return subprocess.check_output(["git", "merge-base", left, right or "HEAD"],
                                       cwd=repo, text=True).strip()
    return revisions.split("..", 1)[0]


def show(repo, revision, path):
    shown = subprocess.run(["git", "show", f"{revision}:{path}"], cwd=repo, text=True,
                           capture_output=True, check=False)
    return shown.stdout if shown.returncode == 0 else None


def plan_command(args):
    root, history = args.repo, args.git or args.repo
    changed = [] if args.whole else changed_files(history, args.range)
    base_rows = None if args.whole else show(history, base_of(history, args.range),
                                             "tests/CLAUDE.md")
    result = finish(reach(changed, root, base_rows) if not args.whole else
                    {"everything": None, "lib": True, "doc": True, "binaries": {},
                     "reasons": {}, "all_binaries": binaries(root)}, changed, args.whole)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"changed files: {len(changed)}; everything: {result['everything']}"
          f"{' (' + result['why_everything'] + ')' if result['everything'] else ''}")
    print(f"unit: {result['lib']}; doc: {result['doc']}; memory: {result['memory']}; "
          f"tracing: {result['tracing']}")
    print(f"integration binaries reached: {len(result['integration'])} of "
          f"{result['total'] - len(APART)}")
    runs = [r for r in (args.runs or "").split(",") if r]
    print(f"build: {result['build']}; docs only: {docs_only(result, runs)}")
    for path, why in result["reasons"].items():
        print(f"  {path}: {why['why']}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.writelines(f"{key}={value}\n" for key, value in outputs(result, runs).items())
    return 0


def outputs(result, runs=()):
    """The step outputs the workflow's conditions read (`steps.plan.outputs.<key>`); every key
    a condition of `ci.yml` names is one of these or one its plan step writes itself
    (test_affected_tests.py, `WorkflowKeyTests`)."""
    flag = {True: "true", False: "false"}
    written = {"whole": flag[bool(result["everything"])], "build": flag[bool(result["build"])],
               "docs_only": flag[docs_only(result, runs)]}
    written.update({key: flag[bool(result[key])] for key in ("lib", "doc", "memory", "tracing")})
    written["reached"] = str(len(result["integration"]))
    written["tests"] = " ".join(f"--test {b}" for b in result["integration"])
    return written


def check(plan, metadata):
    """The reached set against the whole: every name an integration target, and some
    reached when a library source changed. Returns the refusals."""
    whole = {t["name"] for p in metadata["packages"] for t in p["targets"] if "test" in t["kind"]}
    errors = [f"{b}: reached, but no integration target of that name" for b in plan["integration"]
              if b not in whole]
    if plan["src_changed"] and not plan["integration"] and not plan["everything"]:
        errors.append("a library source changed and the plan reaches no integration binary")
    if plan["everything"] and set(plan["integration"]) != whole - APART:
        errors.append("the plan says everything but lists another set")
    return errors, whole


def check_command(args):
    plan = json.loads(args.plan.read_text())
    metadata = json.loads(args.metadata.read_text())
    errors, whole = check(plan, metadata)
    print(f"reached {len(plan['integration'])} of the whole {len(whole)} integration binaries "
          f"({len(APART)} run apart): {' '.join(plan['integration']) or 'none'}")
    for error in errors:
        print(f"::error::{error}")
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    planner = subs.add_parser("plan", help="the targets a diff reaches")
    planner.add_argument("--range", default="HEAD^1..HEAD",
                         help="the git diff revisions (on a pull request's merge ref, HEAD^1..HEAD)")
    planner.add_argument("--whole", help="run everything, for this reason (a push, a label)")
    planner.add_argument("--repo", type=Path, default=Path("."), help="the tree the plan reads")
    planner.add_argument("--git", type=Path,
                         help="the repository the diff is read from (default: --repo)")
    planner.add_argument("--output", type=Path, required=True)
    planner.add_argument("--runs", help="the binaries the job runs by name, comma-separated: "
                                        "a docs-only change reaches none of them (#668)")
    checker = subs.add_parser("check", help="the reached set within the whole")
    checker.add_argument("--plan", type=Path, required=True)
    checker.add_argument("--metadata", type=Path, required=True,
                         help="`cargo metadata --no-deps --format-version 1`'s output")
    args = parser.parse_args()
    return plan_command(args) if args.operation == "plan" else check_command(args)


if __name__ == "__main__":
    sys.exit(main())
