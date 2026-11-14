"""The duplicate dependency versions' check against its list (#104).

How the script's PROCESS can end, and what holds each (`Process`, below; the step reads the
process's exit code and nothing else of it):

    main() returns 0                                0   held
    main() returns 1: a duplicate, a row, the list  1   held (a new duplicate, a list out of form,
                                                        a cargo that prints no package)
    `cargo tree` exits nonzero                      1   held
    no `cargo` on PATH (OSError at the spawn)       1   held
    a line of cargo's that is no package line       1   held (`NO_PACKAGE`'s lines, in each of the
                                                        four graphs; a package line is `PACKAGE`'s
                                                        form in the script and no other)
    the list missing (OSError at the read)          1   held
    the list not UTF-8                              1   held
    an argument argparse refuses                    2   held

What no test here holds, one sentence each. An unreadable lockfile: the script reads no
lockfile, cargo does, so it is `cargo tree` exiting nonzero (the stub's words there are cargo's
refusal of a lockfile). The list a directory or unreadable by permission: an OSError at the same read as
the missing list's, raised by the same call and caught by nothing. Bytes of cargo's that are
no text in the runner's locale: the decoding is the locale's (`text=True`), so the bytes that
raise differ by host, and where they decode the line is judged as any other. A stdout that
refuses a write: the step's stdout is the runner's log, and the raise is `print`'s, uncaught
as the others. `cargo tree` ended by a signal: `check=True` raises the same
`CalledProcessError` as for its exit code. An exit that depends on an environment variable:
the process is run with this process's environment, `PATH` alone replaced, so a variable the
runner sets and this run does not (or the reverse) is read by no test; in CI the tests run in
the step the script runs in, with its variables. `KeyboardInterrupt` and a signal to the
interpreter are not this file's. A change of the script made to defeat these tests (an exit
keyed on the temporary root's path, on the stub) is visible in its diff and a reviewer's.
"""

import contextlib
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(__file__))

import duplicate_versions as dv  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[2]
ARCH = "tests/arch_duplicate_versions_104.rs"
CI = ".github/workflows/ci.yml"
SCRIPT = ".github/scripts/duplicate_versions.py"


def arch_table(name):
    """A `const NAME: [&str; N] = [..];` of the arch test, as its texts: the one table of
    line spellings both readers are held to."""
    source = (REPOSITORY / ARCH).read_text(encoding="utf-8")
    found = re.findall(rf"\nconst {name}: \[&str; (\d+)\] = \[(.*?)\n\];", source, re.DOTALL)
    if len(found) != 1:
        raise AssertionError(f"{ARCH}: {len(found)} tables named {name}")
    texts = re.findall(r'"([^"\\]*)"', found[0][1])
    if not texts or len(texts) != int(found[0][0]):
        raise AssertionError(f"{ARCH}: {name} read as {len(texts)} texts of {found[0][0]}")
    return texts


TREE = """\
bsv-rs v0.9.0-beta.7 (/somewhere/bsv-rs)
syn v2.0.119
serde_derive v1.0.229 (proc-macro)
syn v3.0.10
base64 v0.22.1
base64 v0.22.1 (*)

hyper-util v0.1.21
base64 v0.23.1
"""

LIST = """\
# a comment

all, native | base64 | 0.22, 0.23 | wiremock
all, native, wasm32, default | syn | 2, 3 | zerocopy-derive
"""


def found(**graphs):
    """`judge`'s second argument: the named graphs' duplicates, the rest none."""
    return {graph: graphs.get(graph, {}) for graph in dv.GRAPHS}


PAIR = {"base64": ["0.22.1", "0.23.1"], "syn": ["2.0.119", "3.0.10"]}
SYN = {"syn": ["2.0.119", "3.0.10"]}
HELD = found(all=PAIR, native=PAIR, wasm32=SYN, default=SYN)


class Lines(unittest.TestCase):
    def test_a_versions_line_is_its_leftmost_nonzero_part(self):
        for version, line in [("3.0.10", "3"), ("0.22.1", "0.22"), ("0.0.4", "0.0.4"),
                              ("0.9.0-beta.7", "0.9"), ("1.2.3+build.5", "1"), ("0.0.0", "0.0.0")]:
            self.assertEqual(dv.line_of(version), line, version)

    def test_lines_order_by_number_not_by_text(self):
        self.assertEqual(sorted(["0.10", "0.9", "2", "0.2"], key=dv.line_key),
                         ["0.2", "0.9", "0.10", "2"])


class Tree(unittest.TestCase):
    def test_the_tree_is_read_by_name_and_version_whatever_follows(self):
        versions = dv.tree_versions(TREE)
        self.assertEqual(versions["base64"], {"0.22.1", "0.23.1"})
        self.assertEqual(versions["bsv-rs"], {"0.9.0-beta.7"})
        self.assertEqual(versions["serde_derive"], {"1.0.229"})
        self.assertEqual(dv.duplicates(versions),
                         {"base64": ["0.22.1", "0.23.1"], "syn": ["2.0.119", "3.0.10"]})

    def test_every_form_of_a_package_line_is_read(self):
        for raw, (name, version) in PACKAGE_LINES.items():
            with self.subTest(raw=raw):
                self.assertEqual(dv.tree_versions(raw + "\n"), {name: {version}})
        self.assertEqual(dv.tree_versions("\n".join(PACKAGE_LINES) + "\n\n"),
                         {"syn": {"2.0.119"}, "serde_derive": {"1.0.229"},
                          "wasi": {"0.11.1+wasi-snapshot-preview1"},
                          "bsv-rs": {"0.9.0-beta.7"}, "one": {"1.0.0-rc.1+build.5", "1.0.0"}})

    def test_a_line_that_is_no_package_is_refused_not_skipped(self):
        for raw in ["error: something", *NO_PACKAGE]:
            with self.assertRaises(ValueError, msg=raw):
                dv.tree_versions(raw)

    def test_duplicates_are_in_line_order(self):
        self.assertEqual(dv.duplicates({"rand_core": {"0.10.1", "0.6.4"}, "one": {"1.0.0"}}),
                         {"rand_core": ["0.6.4", "0.10.1"]})


class Rows(unittest.TestCase):
    def test_the_rows_are_read_and_comments_and_blank_lines_passed(self):
        rows, errors = dv.parse_rows(LIST)
        self.assertEqual(errors, [])
        self.assertEqual(rows, [(["all", "native"], "base64", ["0.22", "0.23"], "wiremock"),
                                (["all", "native", "wasm32", "default"], "syn", ["2", "3"],
                                 "zerocopy-derive")])

    def refused(self, row, needle):
        _, errors = dv.parse_rows(row + "\n")
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(needle, errors[0])
        self.assertTrue(errors[0].startswith(f"{dv.LIST}:1: "), errors[0])

    def test_a_row_that_is_not_four_cells_is_refused(self):
        self.refused("all | syn | 2, 3", "3 cells")
        self.refused("all | syn | 2, 3 | a | b", "5 cells")

    def test_a_row_without_a_reason_is_refused(self):
        self.refused("all | syn | 2, 3 |", "no reason")

    def test_an_unknown_graph_is_refused(self):
        _, errors = dv.parse_rows("all, linux | syn | 2, 3 | r\n")
        self.assertIn("`linux` is no graph", errors[0])

    def test_graphs_twice_or_out_of_order_are_refused(self):
        self.refused("all, all | syn | 2, 3 | r", "each once in the order")
        self.refused("default, all | syn | 2, 3 | r", "each once in the order")

    def test_lines_that_are_one_unordered_repeated_or_a_full_version_are_refused(self):
        for lines in ["2", "3, 2", "2, 2", "2.0.119, 3", "0.10, 0.9", "2, "]:
            self.refused(f"all | syn | {lines} | r", "not two or more distinct lines in order")

    def test_a_crate_name_holding_a_space_is_refused(self):
        self.refused("all | sy n | 2, 3 | r", "`sy n` is no crate name")

    def test_every_spelling_the_arch_test_refuses_is_refused_here(self):
        """The arch test's `REFUSED_LINES`, read from its source: the two readers of a
        row's lines are held to one table, so neither refuses a spelling alone."""
        for lines in arch_table("REFUSED_LINES"):
            _, errors = dv.parse_rows(f"all | syn | {lines} | r\n")
            self.assertEqual(len(errors), 1, (lines, errors))
            self.assertIn(f"syn: `{lines.strip()}` is not two or more distinct lines in order",
                          errors[0])

    def test_every_spelling_the_arch_test_reads_is_read_here(self):
        for lines in arch_table("READ_LINES"):
            rows, errors = dv.parse_rows(f"all | syn | {lines} | r\n")
            self.assertEqual(errors, [], lines)
            self.assertEqual(rows[0][2], [v.strip() for v in lines.split(",")])

    def test_a_crate_named_twice_or_out_of_order_is_refused(self):
        _, errors = dv.parse_rows("all | syn | 2, 3 | r\nall | syn | 2, 3 | r\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("not after `syn`", errors[0])
        _, errors = dv.parse_rows("all | syn | 2, 3 | r\nall | base64 | 0.22, 0.23 | r\n")
        self.assertIn("base64: not after `syn`", errors[0])


class Judge(unittest.TestCase):
    def setUp(self):
        self.rows, errors = dv.parse_rows(LIST)
        self.assertEqual(errors, [])

    def test_the_graphs_the_rows_describe_pass(self):
        self.assertEqual(dv.judge(self.rows, HELD), [])

    def test_a_new_duplicate_is_refused_in_each_graph_that_holds_it(self):
        more = dict(SYN, itoa=["0.4.8", "1.0.15"])
        errors = dv.judge(self.rows, found(all=PAIR, native=PAIR, wasm32=more, default=more))
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(errors[0].startswith("NEW duplicate in `wasm32`: itoa 0.4.8, 1.0.15 has no row"))
        self.assertTrue(errors[1].startswith("NEW duplicate in `default`: itoa 0.4.8, 1.0.15"))

    def test_a_listed_crate_entering_a_graph_its_row_does_not_name_is_refused(self):
        errors = dv.judge(self.rows, found(all=PAIR, native=PAIR, wasm32=PAIR, default=SYN))
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("NEW duplicate in `wasm32`: base64 0.22.1, 0.23.1"))

    def test_a_third_line_under_a_row_is_refused(self):
        three = dict(PAIR, syn=["1.0.109", "2.0.119", "3.0.10"])
        errors = dv.judge(self.rows, found(all=three, native=PAIR, wasm32=SYN, default=SYN))
        self.assertEqual(errors, ["MOVED duplicate in `all`: syn 1.0.109, 2.0.119, 3.0.10 is not "
                                  "the row's lines 2, 3"])

    def test_a_pair_on_other_lines_than_the_rows_is_refused(self):
        moved = dict(PAIR, base64=["0.23.1", "0.24.0"])
        errors = dv.judge(self.rows, found(all=moved, native=PAIR, wasm32=SYN, default=SYN))
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("MOVED duplicate in `all`: base64 0.23.1, 0.24.0"))

    def test_a_patch_release_under_a_row_moves_nothing(self):
        patched = {"base64": ["0.22.9", "0.23.2"], "syn": ["2.0.200", "3.1.0"]}
        self.assertEqual(dv.judge(self.rows, found(all=patched, native=PAIR, wasm32=SYN, default=SYN)), [])

    def test_a_row_whose_pair_ended_in_a_graph_is_refused(self):
        errors = dv.judge(self.rows, found(all=PAIR, native=SYN, wasm32=SYN, default=SYN))
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith("STALE row in `native`: base64 is held in one version or none"))


class Repository(unittest.TestCase):
    """The list as committed: well formed, and its graphs the ones the script reads."""

    def test_the_committed_list_parses_without_a_refusal(self):
        text = (Path(__file__).resolve().parents[2] / dv.LIST).read_text(encoding="utf-8")
        rows, errors = dv.parse_rows(text)
        self.assertEqual(errors, [])
        self.assertTrue(rows)

    def test_every_graph_reads_the_lockfile_as_resolved_on_every_edge(self):
        self.assertEqual(list(dv.GRAPHS), ["all", "native", "wasm32", "default"])
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return unittest.mock.Mock(stdout="syn v2.0.119\n")

        with unittest.mock.patch.object(dv.subprocess, "run", run):
            for graph in dv.GRAPHS:
                self.assertEqual(dv.cargo_tree(graph, Path("Cargo.toml")), "syn v2.0.119\n")
        for command, kwargs in calls:
            self.assertEqual(command[:3], ["cargo", "tree", "--locked"])
            self.assertIn("normal,build,dev", command)
            self.assertNotIn("--duplicates", command)
            self.assertTrue(kwargs["check"])
        self.assertIn("auth,wallet,transaction,overlay,socketio,wasm", calls[2][0])
        self.assertIn("wasm32-unknown-unknown", calls[2][0])
        self.assertIn("--all-features", calls[0][0])
        self.assertIn("full,http,websocket", calls[1][0])


# Lines of cargo's stdout that are no package line: each is refused by `tree_versions` and
# ends the process with exit 1 in whichever graph prints it. From `warning: very old
# lockfile` on, the second word starts with `v`, which was all the script asked of a line
# until the fourth fold (the third re-read's four lines, then the forms beside them).
NO_PACKAGE = [
    "syn 2.0.119",
    "warning: something",
    "syn",
    "warning: very old lockfile",
    "error: version mismatch",
    "note: v2 resolver",
    "(*) vX",
    "(*) v1.0.0",
    "syn v2",
    "syn v2.0",
    "syn v2.0.x",
    "syn v2.0.119.1",
    "syn v2.0.119x",
    "syn v2.0.119 again",
    "syn v2.0.119 (*) again",
    " syn v2.0.119",
    "syn  v2.0.119",
    "syn v2.0.119 ",
    "syn\tv2.0.119",
    "  ",
]

# What `cargo tree --prefix none --format {p}` prints for a package, each form read off a
# real run on this tree (cargo 1.98.1, the four graphs, 2,372 lines): the bare line, the
# repeat mark, a proc-macro with and without it, build metadata, the root crate with a
# pre-release and its path. The registry and git sources are cargo's `{p}` for a package
# not from crates.io, which this tree does not hold.
PACKAGE_LINES = {
    "syn v2.0.119": ("syn", "2.0.119"),
    "syn v2.0.119 (*)": ("syn", "2.0.119"),
    "serde_derive v1.0.229 (proc-macro)": ("serde_derive", "1.0.229"),
    "serde_derive v1.0.229 (proc-macro) (*)": ("serde_derive", "1.0.229"),
    "wasi v0.11.1+wasi-snapshot-preview1": ("wasi", "0.11.1+wasi-snapshot-preview1"),
    "wasi v0.11.1+wasi-snapshot-preview1 (*)": ("wasi", "0.11.1+wasi-snapshot-preview1"),
    "bsv-rs v0.9.0-beta.7 (/home/runner/work/bsv-rs/bsv-rs)": ("bsv-rs", "0.9.0-beta.7"),
    "bsv-rs v0.9.0-beta.7 (/a path (with) marks/bsv-rs) (*)": ("bsv-rs", "0.9.0-beta.7"),
    "one v1.0.0-rc.1+build.5": ("one", "1.0.0-rc.1+build.5"),
    "one v1.0.0 (registry+https://example.invalid/index)": ("one", "1.0.0"),
    "one v1.0.0 (https://example.invalid/one.git?branch=main#0123abcd)": ("one", "1.0.0"),
}


def tree_of(held):
    """`cargo tree`'s package lines for one graph's duplicates, beside the root crate."""
    lines = ["bsv-rs v0.9.0-beta.7 (/somewhere/bsv-rs)"]
    lines += [f"{name} v{version}" for name, versions in held.items() for version in versions]
    return "\n".join(lines) + "\n"


class Main(unittest.TestCase):
    """`main()`'s exit code is the gate: the `deny` step fails on it and on nothing else."""

    COUNTS = f"duplicate versions: all 2, native 2, wasm32 1, default 1; 2 rows in {dv.LIST}"

    def run_main(self, graphs, text=LIST):
        """`main()` over a root holding `text` as the list, `cargo_tree` answering `graphs`
        (or raising, when it is an exception): the exit code, stdout's lines and stderr."""
        asked = []

        def cargo_tree(graph, manifest):
            asked.append((graph, manifest))
            if isinstance(graphs, Exception):
                raise graphs
            return tree_of(graphs[graph])

        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as root:
            listed = Path(root) / dv.LIST
            listed.parent.mkdir(parents=True)
            listed.write_text(text, encoding="utf-8")
            with unittest.mock.patch.object(dv, "cargo_tree", cargo_tree), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = dv.main(["--root", root])
            manifest = Path(root) / "Cargo.toml"
        if not isinstance(graphs, Exception):
            self.assertEqual(asked, [(graph, manifest) for graph in dv.GRAPHS])
        return code, out.getvalue().splitlines(), err.getvalue()

    def test_the_graphs_the_list_describes_exit_0_with_the_counts_alone(self):
        code, lines, err = self.run_main(HELD)
        self.assertEqual(lines, [self.COUNTS])
        self.assertEqual(err, "")
        self.assertEqual(code, 0)
        self.assertIs(type(code), int)

    def test_a_new_duplicate_exits_1_with_its_line(self):
        more = dict(SYN, itoa=["0.4.8", "1.0.15"])
        code, lines, _ = self.run_main(found(all=PAIR, native=PAIR, wasm32=more, default=SYN))
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 2, lines)
        self.assertEqual(lines[0], self.COUNTS.replace("wasm32 1", "wasm32 2"))
        self.assertTrue(lines[1].startswith("NEW duplicate in `wasm32`: itoa 0.4.8, 1.0.15 has no row"),
                        lines[1])

    def test_a_stale_row_exits_1_with_its_line(self):
        code, lines, _ = self.run_main(found(all=PAIR, native=SYN, wasm32=SYN, default=SYN))
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 2, lines)
        self.assertEqual(lines[0], self.COUNTS.replace("native 2", "native 1"))
        self.assertTrue(lines[1].startswith("STALE row in `native`: base64 is held in one version or none"),
                        lines[1])

    def test_a_moved_pair_exits_1_with_its_line(self):
        three = dict(PAIR, syn=["1.0.109", "2.0.119", "3.0.10"])
        code, lines, _ = self.run_main(found(all=three, native=PAIR, wasm32=SYN, default=SYN))
        self.assertEqual(code, 1)
        self.assertEqual(lines[1:], ["MOVED duplicate in `all`: syn 1.0.109, 2.0.119, 3.0.10 is not "
                                     "the row's lines 2, 3"])

    def test_a_list_out_of_form_exits_1_though_the_graphs_agree(self):
        text = LIST.replace("| zerocopy-derive", "|")
        code, lines, _ = self.run_main(HELD, text)
        self.assertEqual(code, 1)
        self.assertEqual(lines, [self.COUNTS, f"{dv.LIST}:4: syn: no reason"])

    def test_a_list_fault_and_a_graph_fault_are_both_printed(self):
        text = LIST.replace("| zerocopy-derive", "|")
        code, lines, _ = self.run_main(found(all=PAIR, native=SYN, wasm32=SYN, default=SYN), text)
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 3, lines)
        self.assertEqual(lines[1], f"{dv.LIST}:4: syn: no reason")
        self.assertTrue(lines[2].startswith("STALE row in `native`: base64"), lines[2])

    def test_a_cargo_tree_that_fails_exits_1_with_its_words(self):
        failed = subprocess.CalledProcessError(101, ["cargo", "tree", "--locked"],
                                               stderr="error: the lock file needs to be updated")
        code, lines, err = self.run_main(failed)
        self.assertEqual(code, 1)
        self.assertEqual(lines, [])
        self.assertIn("`cargo tree --locked` failed:", err)
        self.assertIn("the lock file needs to be updated", err)



STUB = """\
#!/bin/sh
# A stand-in for cargo: `cargo tree` alone, one graph's package lines from a file.
here=$(dirname "$0")
printf '%s\\n' "$*" >> "$here/asked"
[ "$1" = tree ] || { echo "the stub is asked for \\`$1\\`, not \\`tree\\`" >&2; exit 2; }
if [ -e "$here/fail" ]; then
  echo "error: the lock file needs to be updated but --locked was passed" >&2
  exit 101
fi
case " $* " in
  *" --all-features "*) graph=all ;;
  *" full,http,websocket "*) graph=native ;;
  *" wasm32-unknown-unknown "*) graph=wasm32 ;;
  *) graph=default ;;
esac
cat "$here/$graph"
"""


@unittest.skipUnless(os.name == "posix", "the stub cargo is a shell script")
class Process(unittest.TestCase):
    """The script run as the `deny` step runs it: the PROCESS's exit code is what
    `|| result=1` reads, so `sys.exit(main())` is held here and by no test of `main()`,
    and so is every way `main()` ends by a raise (the file's header lists them).
    A copy of the script under a temporary root, the step's own command line, this
    process's environment with `PATH` replaced: the stub's directory then `os.defpath`,
    and `cargo` on that path is the stub (asserted; with no stub, the empty directory
    alone, and no `cargo` on it). Every call the stub gets is `tree --locked` on the
    temporary root's manifest: no real cargo, no network."""

    def command(self):
        """The step's command line for the script, read from ci.yml, `python3` this one."""
        step = (REPOSITORY / CI).read_text(encoding="utf-8")
        lines = [line for line in step.splitlines() if "duplicate_versions.py" in line
                 and "unittest" not in line and not line.lstrip().startswith("#")]
        self.assertEqual(len(lines), 1, lines)
        command, gate = lines[0].split("||")
        self.assertEqual(gate.strip(), "result=1")
        words = shlex.split(command)
        self.assertEqual(words, ["python3", "-B", SCRIPT])
        return [sys.executable, *words[1:]]

    def run_script(self, graphs, text=LIST, fail=False, cargo=True, arguments=()):
        """The exit code, stdout's lines, stderr and what the stub was asked. A graph's
        value is its duplicates, or the text the stub prints for it; `text` is the list
        (`None`: no list; bytes: written as they are); `cargo=False`: no stub, and a
        `PATH` that holds no program at all."""
        with tempfile.TemporaryDirectory() as scratch:
            root, stub = Path(scratch) / "root", Path(scratch) / "bin"
            (root / SCRIPT).parent.mkdir(parents=True)
            shutil.copyfile(REPOSITORY / SCRIPT, root / SCRIPT)
            (root / dv.LIST).parent.mkdir(parents=True)
            if isinstance(text, bytes):
                (root / dv.LIST).write_bytes(text)
            elif text is not None:
                (root / dv.LIST).write_text(text, encoding="utf-8")
            stub.mkdir()
            if cargo:
                (stub / "cargo").write_text(STUB, encoding="utf-8")
                (stub / "cargo").chmod(0o755)
                path = f"{stub}{os.pathsep}{os.defpath}"
                self.assertEqual(shutil.which("cargo", path=path), str(stub / "cargo"))
            else:
                path = str(stub)
                self.assertIsNone(shutil.which("cargo", path=path))
            for graph in dv.GRAPHS:
                held = graphs[graph]
                (stub / graph).write_text(held if isinstance(held, str) else tree_of(held),
                                          encoding="utf-8")
            if fail:
                (stub / "fail").write_text("", encoding="utf-8")
            done = subprocess.run([*self.command(), *arguments], cwd=root, capture_output=True,
                                  text=True, env=dict(os.environ, PATH=path), check=False)
            asked = []
            if (stub / "asked").exists():
                asked = (stub / "asked").read_text(encoding="utf-8").splitlines()
            manifest = str((root / "Cargo.toml").resolve())
        for line in asked:
            self.assertTrue(line.startswith(f"tree --locked --color never --manifest-path {manifest} "),
                            line)
        return done.returncode, done.stdout.splitlines(), done.stderr, asked

    def raised(self, err, last):
        """The process ended by an uncaught raise: Python's traceback, `last` its last line."""
        self.assertIn("Traceback (most recent call last):", err)
        self.assertIn(last, err.strip().splitlines()[-1])

    def test_the_graphs_the_list_describes_exit_0_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD)
        self.assertEqual(lines, [Main.COUNTS])
        self.assertEqual(err, "")
        self.assertEqual(code, 0)
        self.assertEqual(len(asked), len(dv.GRAPHS), asked)

    def test_a_new_duplicate_exits_1_as_a_process(self):
        more = dict(SYN, itoa=["0.4.8", "1.0.15"])
        code, lines, err, asked = self.run_script(found(all=PAIR, native=PAIR, wasm32=more, default=SYN))
        self.assertEqual(len(lines), 2, lines)
        self.assertEqual(lines[0], Main.COUNTS.replace("wasm32 1", "wasm32 2"))
        self.assertTrue(lines[1].startswith("NEW duplicate in `wasm32`: itoa 0.4.8, 1.0.15 has no row"),
                        lines[1])
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), len(dv.GRAPHS), asked)

    def test_a_cargo_tree_that_fails_exits_1_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD, fail=True)
        self.assertEqual(lines, [])
        self.assertIn("duplicate versions: `cargo tree --locked", err)
        self.assertIn("the lock file needs to be updated", err)
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), 1, asked)

    def test_a_cargo_line_that_is_no_package_exits_1_as_a_process(self):
        # The raise is `tree_versions`' and nothing catches it: the refusal's line is the
        # traceback's last, and no counts line is printed. In each of the four graphs, so
        # no graph's reading is skipped and the graphs read before it do not carry the exit:
        # cargo is asked for the graphs up to the one that prints the line and no further.
        self.assertEqual(list(dv.GRAPHS), ["all", "native", "wasm32", "default"])
        for calls, graph in enumerate(dv.GRAPHS, 1):
            for raw in NO_PACKAGE:
                with self.subTest(graph=graph, raw=raw):
                    graphs = dict(HELD, **{graph: tree_of(HELD[graph]) + raw + "\n"})
                    code, lines, err, asked = self.run_script(graphs)
                    self.assertEqual(lines, [])
                    self.raised(err, f"ValueError: not a `cargo tree` package line: {raw}".rstrip())
                    self.assertEqual(code, 1)
                    self.assertEqual(len(asked), calls, asked)

    def test_a_cargo_that_prints_no_package_exits_1_as_a_process(self):
        # Exit 0 from cargo and nothing on stdout is no agreement with the list.
        code, lines, err, asked = self.run_script({graph: "" for graph in dv.GRAPHS})
        self.assertEqual(lines[0], f"duplicate versions: all 0, native 0, wasm32 0, default 0; "
                                   f"2 rows in {dv.LIST}")
        self.assertEqual(len(lines), 7, lines)
        for line in lines[1:]:
            self.assertTrue(line.startswith("STALE row in `"), line)
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), len(dv.GRAPHS), asked)

    def test_a_list_out_of_form_exits_1_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD, LIST.replace("| zerocopy-derive", "|"))
        self.assertEqual(lines, [Main.COUNTS, f"{dv.LIST}:4: syn: no reason"])
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), len(dv.GRAPHS), asked)

    def test_a_missing_list_exits_1_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD, None)
        self.assertEqual(lines, [])
        self.raised(err, "FileNotFoundError")
        self.assertIn("duplicate-versions.txt", err.strip().splitlines()[-1])
        self.assertEqual(code, 1)
        self.assertEqual(asked, [])

    def test_a_list_that_is_not_utf8_exits_1_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD, LIST.encode("utf-8") + b"all | \xff | 2, 3 | r\n")
        self.assertEqual(lines, [])
        self.raised(err, "UnicodeDecodeError")
        self.assertEqual(code, 1)
        self.assertEqual(asked, [])

    def test_no_cargo_on_the_path_exits_1_as_a_process(self):
        code, lines, err, asked = self.run_script(HELD, cargo=False)
        self.assertEqual(lines, [])
        self.raised(err, "FileNotFoundError")
        self.assertIn("cargo", err.strip().splitlines()[-1])
        self.assertEqual(code, 1)
        self.assertEqual(asked, [])

    def test_an_argument_argparse_refuses_exits_2_as_a_process(self):
        # The step passes none (`command` holds its words); the exit is argparse's own.
        code, lines, err, asked = self.run_script(HELD, arguments=["--no-such-argument"])
        self.assertEqual(lines, [])
        self.assertIn("unrecognized arguments: --no-such-argument", err)
        self.assertEqual(code, 2)
        self.assertEqual(asked, [])


if __name__ == "__main__":
    unittest.main()
