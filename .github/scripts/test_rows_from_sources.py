"""`rows_from_sources.py` writes back the rows it read (the rows lane, 2026-11-12).

The fix-817 lane ran the writer without `--check` and saw two rows of `tests/CLAUDE.md`
rewritten: `shamir_backup_854.rs`'s `||` inside backticks and `front_page.rs`'s `|` inside
backticks were read as cell boundaries (`affected_tests.row_cells`, a split on every
unescaped `|`) and written back as `` ` |  | ` `` and `` ` | ` ``. The invariant is the
class: on a tree `--check` passes, the writer is the identity, byte for byte. Held here by
three machines: the reader's cases, a property over 2,000 generated rows of the characters
the writer and the reader could treat apart (a pipe in a code span of any run length, an
escaped pipe, a backslash, edge white space, a newline entity, non-ASCII text), and the
writer run on a copy of the tree with an empty diff required.
"""

from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

import affected_tests as affected
import nightly_mutants as nightly
import rows_from_sources as rows

REPO = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).resolve().parent / "rows_from_sources.py"

# Text outside a code span: no backtick, no pipe, no backslash (those come as tokens).
PLAIN = list("abcXYZ019_-.,;:()[]{}*#&<>/=+ ") + ["é", "ß", "中", "😀", "&#10;", "<br>", "&#124;"]
# Text inside a code span: a pipe, a backslash and backtick runs are all text there.
CODE = PLAIN + ["|", "||", "\\", "\\|", "\\\\"]


def code_span(rng):
    """A code span of a run of 1 to 3 backticks, holding no run of its own length and no
    backtick at either end (a backtick there would join the delimiter's run)."""
    n = rng.randint(1, 3)
    body = "".join(rng.choice(CODE) for _ in range(rng.randint(1, 6)))
    if rng.random() < 0.4:
        other = rng.choice([k for k in (1, 2, 3, 4) if k != n])
        cut = rng.randint(1, len(body))
        body = body[:cut] + "`" * other + "x" + body[cut:]
    return "`" * n + body + "`" * n


def generated_cell(rng):
    """One cell whose every `|` is in a code span or escaped, with no edge white space."""
    parts, last_code = [], False
    for _ in range(rng.randint(1, 6)):
        kind = rng.random()
        if kind < 0.35:
            if last_code:
                parts.append("x")  # two spans side by side would merge their runs
            parts.append(code_span(rng))
            last_code = True
            continue
        if kind < 0.55:
            parts.append("\\" + rng.choice("|\\`*_"))
        else:
            parts.append("".join(rng.choice(PLAIN) for _ in range(rng.randint(1, 5))))
        last_code = False
    cell = "".join(parts)
    if cell != cell.strip():
        cell = "x" + cell.strip() + "x"
    return cell


def generated_row(rng):
    return [generated_cell(rng) for _ in range(rng.randint(1, 6))]


class ReaderTests(unittest.TestCase):
    def test_a_pipe_inside_a_code_span_is_text(self):
        row = "| `a.rs` | 1 | none | `primitives` | the grammar's `||`; and ``x`|`y`` too |"
        self.assertEqual(affected.row_cells(row), [
            "`a.rs`", "1", "none", "`primitives`", "the grammar's `||`; and ``x`|`y`` too"])

    def test_an_escaped_pipe_is_text_and_an_escaped_backslash_is_not_an_escape(self):
        self.assertEqual(affected.row_cells("| a \\| b | c |"), ["a \\| b", "c"])
        self.assertEqual(affected.row_cells("| a\\\\| b |"), ["a\\\\", "b"])

    def test_an_unclosed_backtick_run_is_text(self):
        self.assertEqual(affected.row_cells("| a ` b | c |"), ["a ` b", "c"])
        self.assertEqual(affected.row_cells("| ``a` | b |"), ["``a`", "b"])

    def test_a_backslash_inside_a_code_span_escapes_nothing(self):
        self.assertEqual(affected.row_cells("| `a\\` | b |"), ["`a\\`", "b"])

    def test_the_nightly_reads_the_file_cell_by_the_same_splitter(self):
        text = "## Files\n\n| `a.rs`, `b.rs` | 1 | none | none | `x || y` |\n"
        [(_, _, files)] = list(nightly.table_rows(text))
        self.assertEqual(files, [("a.rs", "a"), ("b.rs", "b")])

    def test_the_two_rows_the_finder_saw_are_read_whole(self):
        text = (REPO / "tests" / "CLAUDE.md").read_text(encoding="utf-8")
        for stem in ("shamir_backup_854", "front_page"):
            [line] = [line for line in text.split("\n") if line.startswith(f"| `{stem}.rs` |")]
            self.assertEqual(len(affected.row_cells(line)), 5, stem)


class RoundTripProperty(unittest.TestCase):
    """`read(write(row)) == row` and `write(read(text)) == text` on 2,000 generated rows."""

    COUNT = 2000

    def test_the_reader_and_the_writer_are_inverse_on_generated_rows(self):
        rng = random.Random(20261112)
        failures = []
        for index in range(self.COUNT):
            cells = generated_row(rng)
            text = rows.join_row(cells)
            if rows.read_row(text) != cells:
                failures.append(("read(write(row))", index, cells, rows.read_row(text)))
            if rows.join_row(rows.read_row(text)) != text:
                failures.append(("write(read(text))", index, text))
        self.assertEqual(failures[:5], [], f"{len(failures)} of {self.COUNT} rows differ")

    def test_a_cell_rewritten_keeps_every_other_byte_of_its_row(self):
        rng = random.Random(843)
        for _ in range(self.COUNT // 4):
            cells = generated_row(rng) + ["`m`"]
            spaced = "|" + "|".join(f"{' ' * rng.randint(0, 2)}{c}{' ' * rng.randint(1, 2)}"
                                     for c in cells) + "|\r"
            index = len(cells) - 1
            out = rows.with_cell(spaced, index, "`n`")
            expected = cells[:index] + ["`n`"]
            self.assertEqual(rows.read_row(out), expected)
            start, end = affected.cell_spans(spaced)[index]
            self.assertEqual(out[:start], spaced[:start])
            self.assertEqual(out[-(len(spaced) - end):], spaced[end:])


def tree_copy(target):
    """The parts of the tree the writer reads: the crate's sources and `tests/` save its
    vectors (no reading of a row looks into them)."""
    shutil.copy2(REPO / "Cargo.toml", target / "Cargo.toml")
    shutil.copytree(REPO / "src", target / "src")
    shutil.copytree(REPO / "tests", target / "tests",
                    ignore=shutil.ignore_patterns("vectors", "sibling", "chain_vectors"))


class GeneratorIdentity(unittest.TestCase):
    """The writer run without `--check` changes no byte of a tree `--check` passes."""

    def run_writer(self, root, *extra):
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(root), *extra],
                              capture_output=True, text=True, check=False)

    def test_the_writer_is_the_identity_on_the_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tree_copy(root)
            before = (root / "tests" / "CLAUDE.md").read_bytes()
            check = self.run_writer(root, "--check")
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            wrote = self.run_writer(root)
            self.assertEqual(wrote.returncode, 0, wrote.stdout + wrote.stderr)
            after = (root / "tests" / "CLAUDE.md").read_bytes()
            if after != before:
                old, new = before.decode("utf-8").split("\n"), after.decode("utf-8").split("\n")
                moved = [(i + 1, a[:120], b[:120]) for i, (a, b) in enumerate(zip(old, new)) if a != b]
                self.fail(f"the writer rewrote {len(moved)} lines of a tree --check passes "
                          f"(lines {len(old)} -> {len(new)}): {moved[:3]}")

    def test_the_writer_keeps_crlf_spacing_and_non_ascii_text(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "src" / "script").mkdir(parents=True)
            (root / "Cargo.toml").write_text('[package]\nname = "bsv-rs"\n')
            (root / "src" / "lib.rs").write_text("pub mod script;\n")
            (root / "src" / "script" / "mod.rs").write_text("pub fn run() {}\n")
            (root / "tests").mkdir()
            (root / "tests" / "a.rs").write_text("use bsv_rs::script::run;\n")
            (root / "tests" / "b.rs").write_text("use bsv_rs::script::run;\n")
            table = ("# tests\r\n\r\n## Files\r\n\r\n"
                     "| File | Tests | Feature Gate | Modules | Description |\r\n"
                     "|------|------:|---|---|---|\r\n"
                     "| `a.rs` |1| none |  `script`  | é `x || y` \\| ``a`|`b`` &#10; 😀 |\r\n"
                     "| `b.rs` | 1 | none | none | needs `script` |\r\n")
            (root / "tests" / "CLAUDE.md").write_bytes(table.encode("utf-8"))
            self.assertEqual(self.run_writer(root).returncode, 0)
            after = (root / "tests" / "CLAUDE.md").read_bytes().decode("utf-8")
            self.assertEqual(after, table.replace("| none | needs", "| `script` | needs"))
            self.assertEqual(self.run_writer(root, "--check").returncode, 0)


if __name__ == "__main__":
    unittest.main()
