#!/usr/bin/env python3
"""Each `tests/CLAUDE.md` row's Modules cell from its binary's source (#706).

A row names, in its Modules cell, at least the modules its file's source names
(`affected_tests.used_modules` over the binary and the module files it declares: a
`bsv_rs::<m>` path, a crate-root re-export named through the crate), so the nightly's
direct reading (#685) reaches the binary for its modules' mutants. A binary that reaches
a module only through a caller (it names `bsv_rs::transaction`, and the transaction code
calls `crate::script`) gains that module where its row's description already says it
exercises it (`CALLER_WORDS`); otherwise the row is left to the convention, and the
writer counts what it left.

The caller clause is a judgment: the words above applied it once, and the pairs it decided
are frozen in `tests/caller_modules_706.txt` (`FROZEN`), which the writer always writes and
`--check` and the guard both read, so no edit drops one with CI green (#708 fold).

A row shared by several files (the #537 and #544 rows) carries one part per file in its
Modules cell (`` `a.rs`: `m`, `n`; `b.rs`: none ``), each from that file's own source: the
row's union is no file's reading (#708 fold, the cold read's: the union put all twelve
binaries in modules their sources never name).

Without `--check` the script writes the cells (adding the column to the table when it
has none) and keeps every module a cell already names for the file (a shared row's union
cell is not kept: it is no file's); it never writes a description, so a binary without a
row is printed, not added. With `--check` it writes nothing and refuses a binary without a
row, a stem named in two rows (#712), a row naming fewer modules than its source, a shared
row without a part per file and a row dropping a frozen module: the reading `tests/arch_tests_claude_rows_name_modules_706.rs`
pins in the Rust suite, and CI runs `--check` beside the plan's own tests.
"""

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import affected_tests as affected  # noqa: E402

# Never named in a row: a change to `src/error*` reaches every target already
# (`affected_tests.EVERYTHING`), and `util` is crate-private.
UNNAMED = {"error", "util"}
# The modules the nightly measures, and the words of a row's description that say a
# binary reaching the module only through a caller exercises it (#706, item 3).
CALLER_WORDS = {
    "script": re.compile(
        r"\b(?:locking|unlocking) scripts?\b|\binterpreter\b|`Spend`|\bOP_[A-Z0-9]+|[Ss]ighash"
        r"|PushDrop|\bP2PKH\b|\bP2PK\b|CHECKSIG|scriptCode|`(?:Locking|Unlocking)?Script`"
        r"|\bscripts? (?:execut|verif|evaluat|run)|\bscript templates?\b|\bscripts\b|\bspends?\b"
        r"|\bspent\b|ANYONECANPAY|\bsigned family\b"),
    "transaction": re.compile(
        r"\bBEEF\b|`Beef`|MerklePath|\b[Mm]erkle path|`Transaction`|\btransactions?\b"
        r"|\bBUMP\b|\bbroadcasters?\b|\bSPV\b|ChainTracker|\bchain tracker"),
    "wallet": re.compile(
        r"\bwallet\b|ProtoWallet|WalletClient|WalletInterface|KeyDeriver|\bBRC-100\b"
        r"|create_action|createAction|\bsubstrate"),
}
# The caller clause's pairs, frozen (#708 fold): `<stem> <module>` per line, `#` a comment.
FROZEN = Path("tests") / "caller_modules_706.txt"
SENTENCE = ("a row names, in its Modules cell, at least the modules its file's source names "
            "by a `bsv_rs::` path or a crate-root re-export (tests/CLAUDE.md, ## Files)")


def frozen(root):
    """`FROZEN`'s pairs: each stem to the modules its row must keep."""
    pairs = {}
    path = root / FROZEN
    for line in (path.read_text().splitlines() if path.is_file() else []):
        words = line.split("#", 1)[0].split()
        if words:
            stem, module = words
            pairs.setdefault(stem, set()).add(module)
    return pairs


def files_section(lines):
    """The index range of the `## Files` section's lines."""
    start = next(i for i, line in enumerate(lines) if line.strip() == "## Files")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def row_files(row):
    """The `.rs` names of a row's File cell."""
    return re.findall(r"`([^`]+)\.rs`", affected.row_cells(row)[0])


class Reading:
    """The tree's sources read once: each test file's modules by its own source."""

    def __init__(self, root):
        self.root = root
        self.tree = affected.Tree(root)
        self.named = self.tree.modules - UNNAMED
        self.callers = {m: self.tree.callers(m) for m in CALLER_WORDS}

    def source(self, name):
        """The modules a file's source names: a binary with its module files, else the file."""
        stem = Path(name).stem
        if "/" not in name and stem in self.tree.texts:
            text = self.tree.texts[stem]
        else:
            text = "\n".join((self.root / s).read_text(errors="replace")
                             for s in affected.module_sources(self.root, f"tests/{name}.rs"))
        return affected.used_modules(text, self.tree.modules, self.tree.exported) & self.named

    def through_callers(self, name, description):
        """The measured modules the file reaches only through a caller, its row's
        description saying it exercises them."""
        own = self.source(name)
        return {m for m, words in CALLER_WORDS.items()
                if m not in own and own & self.callers[m] and words.search(description)}


def cell(modules):
    return ", ".join(f"`{m}`" for m in sorted(modules)) or "none"


def shared(parts):
    """A shared row's Modules cell, one part per file in the File cell's order."""
    return "; ".join(f"`{name}.rs`: {cell(modules)}" for name, modules in parts)


def write(root):
    """The rows rewritten; returns the new text and the counts."""
    path = root / "tests" / "CLAUDE.md"
    lines = path.read_text().split("\n")
    start, end = files_section(lines)
    reading = Reading(root)
    pinned = frozen(root)
    counts = {"rows": 0, "naming none before": 0, "naming none after": 0,
              "through callers": {m: 0 for m in CALLER_WORDS},
              "left to the convention": {m: 0 for m in CALLER_WORDS}}
    for i in range(start, end):
        line = lines[i]
        if not line.startswith("|"):
            continue
        cells = affected.row_cells(line)
        if cells[0] == "File":
            if "Modules" not in cells:
                cells.insert(affected.MODULES_CELL - 1, "Modules")
        elif set(cells[0]) <= set("-: "):
            if len(cells) < affected.MODULES_CELL + 1:
                cells.insert(affected.MODULES_CELL - 1, "-------")
        else:
            had = len(cells) > affected.MODULES_CELL
            names = row_files(line)
            per_file = had and affected.shared_cell(cells[affected.MODULES_CELL - 1]) is not None
            parts = []
            for name in names:
                stem = Path(name).stem
                # a file's own part is kept; a shared row's union cell is no file's (#708 fold)
                held = (affected.row_modules(line, reading.named, stem)
                        if had and (len(names) == 1 or per_file) else set())
                own = reading.source(name)
                # a shared row's description is every file's, so its words say of no one file
                # that it exercises a caller's module: a shared row's part is its file's source
                added = reading.through_callers(name, cells[-1]) if len(names) == 1 else set()
                for m in CALLER_WORDS:
                    counts["through callers"][m] += m in added
                    reached = m not in own and bool(own & reading.callers[m])
                    counts["left to the convention"][m] += reached and m not in added | held
                parts.append((stem, held | own | added | pinned.get(stem, set())))
            counts["rows"] += 1
            counts["naming none before"] += not (had and affected.row_modules(line, reading.named))
            counts["naming none after"] += not any(m for _, m in parts)
            text = shared(parts) if len(parts) > 1 else cell(parts[0][1] if parts else set())
            if had:
                cells[affected.MODULES_CELL - 1] = text
            else:
                cells.insert(affected.MODULES_CELL - 1, text)
        lines[i] = "| " + " | ".join(cells) + " |"
    return "\n".join(lines), counts


def doubled_rows(text):
    """The stems named in two or more rows of the `## Files` table (#712): every reader keys
    the rows by the stem (`nightly.table_rows`, this check's reading too) and keeps the last,
    so an edit to another copy is never read, `support/a.rs` beside `a.rs` included. One
    refusal per stem, naming its files and each row's line in `tests/CLAUDE.md`."""
    seen = {}
    for number, _, files in affected.nightly.table_rows(text):
        for name, stem in files:
            names, at = seen.setdefault(stem, ([], []))
            if name not in names:
                names.append(name)
            if not at or at[-1] != number:
                at.append(number)
    return [f"{' and '.join(f'tests/{name}' for name in names)}: {len(at)} rows of the stem "
            f"`{stem}` in tests/CLAUDE.md's ## Files table, at lines "
            f"{' and '.join(map(str, at))}; one row per stem (the readers key the rows by the "
            f"stem and keep the last)"
            for stem, (names, at) in sorted(seen.items()) if len(at) > 1]


def check(root):
    """The refusals: a stem named in two rows (#712), a binary without a row, a row naming fewer modules than its source, a
    shared row without a part for the file, a row dropping a frozen module, a frozen pair
    naming no binary."""
    reading = Reading(root)
    rows = reading.tree.rows
    pinned = frozen(root)
    refusals = doubled_rows((root / "tests" / "CLAUDE.md").read_text())
    for binary in reading.tree.binaries:
        if binary not in rows:
            refusals.append(f"tests/{binary}.rs: no row in tests/CLAUDE.md's ## Files table; {SENTENCE}")
            continue
        row = rows[binary]
        cells = affected.row_cells(row)
        if len(row_files(row)) > 1 and len(cells) > affected.MODULES_CELL:
            parts = affected.shared_cell(cells[affected.MODULES_CELL - 1])
            if parts is None or binary not in parts:
                refusals.append(f"tests/{binary}.rs: its row is shared and its Modules cell has no "
                                f"part for it (`{binary}.rs`: ...); {SENTENCE}")
                continue
        named = affected.row_modules(row, reading.named, binary)
        missing = reading.source(binary) - named
        if missing:
            refusals.append(f"tests/{binary}.rs: its row does not name {', '.join(sorted(missing))}; "
                            f"{SENTENCE}")
        dropped = pinned.get(binary, set()) - named
        if dropped:
            refusals.append(f"tests/{binary}.rs: its row drops {', '.join(sorted(dropped))}, frozen "
                            f"in {FROZEN.as_posix()} (the caller clause's judgment)")
    for stem in sorted(set(pinned) - set(reading.tree.binaries)):
        refusals.append(f"{FROZEN.as_posix()}: {stem} names no integration binary")
    return refusals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--check", action="store_true", help="refuse, write nothing")
    args = parser.parse_args()
    if args.check:
        refusals = check(args.root)
        for refusal in refusals:
            print(refusal)
        print(f"{len(refusals)} refusals")
        return 1 if refusals else 0
    text, counts = write(args.root)
    (args.root / "tests" / "CLAUDE.md").write_text(text)
    for key, value in counts.items():
        print(f"{key}: {value}")
    missing = sorted(set(Reading(args.root).tree.binaries) - set(affected.Tree(args.root).rows))
    print(f"binaries without a row (a description is an author's): {len(missing)} {' '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
