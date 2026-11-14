"""The duplicate dependency versions' check against its list (#104)."""

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

    def test_a_line_that_is_no_package_is_refused_not_skipped(self):
        for raw in ["error: something", "syn", "syn 2.0.119"]:
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
    `|| result=1` reads, so `sys.exit(main())` is held here and by no test of `main()`.
    A copy of the script under a temporary root, the step's own command line, and a stub
    `cargo` the only one on `PATH` (no real cargo, no network)."""

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

    def run_script(self, graphs, text=LIST, fail=False):
        """The exit code, stdout's lines, stderr and what the stub was asked."""
        with tempfile.TemporaryDirectory() as scratch:
            root, stub = Path(scratch) / "root", Path(scratch) / "bin"
            (root / SCRIPT).parent.mkdir(parents=True)
            shutil.copyfile(REPOSITORY / SCRIPT, root / SCRIPT)
            (root / dv.LIST).parent.mkdir(parents=True)
            (root / dv.LIST).write_text(text, encoding="utf-8")
            stub.mkdir()
            (stub / "cargo").write_text(STUB, encoding="utf-8")
            (stub / "cargo").chmod(0o755)
            for graph in dv.GRAPHS:
                (stub / graph).write_text(tree_of(graphs[graph]), encoding="utf-8")
            if fail:
                (stub / "fail").write_text("", encoding="utf-8")
            done = subprocess.run(self.command(), cwd=root, capture_output=True, text=True,
                                  env={"PATH": f"{stub}{os.pathsep}{os.defpath}"}, check=False)
            asked = (stub / "asked").read_text(encoding="utf-8").splitlines()
            manifest = str((root / "Cargo.toml").resolve())
        for line in asked:
            self.assertTrue(line.startswith(f"tree --locked --color never --manifest-path {manifest} "),
                            line)
        return done.returncode, done.stdout.splitlines(), done.stderr, asked

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


if __name__ == "__main__":
    unittest.main()
