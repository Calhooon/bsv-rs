# Lane fix-rows-script: the rows writer is the identity on the tree

Started from beta `5a87392e` (`origin/beta`'s tip at the start, checked by
`git fetch origin && git rev-parse HEAD origin/beta`).

## The finding

The fix-817 lane (2026-11-12) ran `python3 .github/scripts/rows_from_sources.py`
without `--check` and saw two rows of `tests/CLAUDE.md` rewritten on a tree that
`--check` passed. Reproduced on a scratch copy of `5a87392e` (`git archive`, its
own git): `--check` 0 refusals; the writer `tests/CLAUDE.md | 4 ++--`, lines 224
(`shamir_backup_854.rs`: `` `||` `` written `` ` |  | ` `` twice) and 264
(`front_page.rs`: `` `|` `` written `` ` | ` ``).

## The cause

`affected_tests.row_cells` split a row with `re.split(r"(?<!\\)\|", row)`: every
`|` not after a backslash was a cell boundary, a pipe inside a code span
included. `rows_from_sources.write` then rebuilt every row as
`"| " + " | ".join(cells) + " |"`, so the two empty cells between `|` and `|`
came back spaced. The same reading sat in three more places: the Rust guard's
`cells` (`tests/arch_tests_claude_rows_name_modules_706.rs`) and the File-cell
readers `nightly_mutants.table_rows` and the guard's `table_rows`
(`line.split("|")[1]`). Siblings of the writer, found by the run: the rebuild
dropped a row's own spacing; `read_text`/`write_text` translated `\r\n` to `\n`
and used the locale's encoding; the lookbehind read `\\|` (an escaped backslash,
then a boundary) as an escaped pipe.

## The fix

- One splitter, `nightly_mutants.cell_spans` (`affected_tests.row_cells` and
  `cell_spans` name it): a boundary is a `|` outside a code span and not
  escaped; a code span opens at a run of n backticks and closes at the next run
  of exactly n (CommonMark 6.1), an unclosed run is text, a backslash escapes
  the next character outside a span and nothing inside one. The File-cell
  reader uses it; the Rust guard's `cells` and `table_rows` read the same way.
- The writer touches only a row whose Modules cell moves, and only that cell
  (`with_cell`, the cell's own edge white space kept); the file is read and
  written as UTF-8 bytes (`read_rows_file`, `write_bytes`).

## The machine

`.github/scripts/test_rows_from_sources.py`, 10 tests, run by the Test Suite's
plan step after `rows_from_sources.py --check`, the line pinned by
`tests/arch_ci_runs_every_test.rs` (`reached_refusals`, a refusal planted on
its fixture):

- the reader's cases, the two finder rows read as five cells each;
- the property: 2,000 seeded generated rows (code spans of one to three
  backticks holding `|`, `||`, `\`, `\|` and backtick runs of other lengths;
  escaped `|`, `\`, `` ` ``, `*`, `_`; `&#10;`, `&#124;`, `<br>`; `é`, `ß`, `中`,
  an emoji), `read(write(row)) == row` and `write(read(text)) == text`, and 500
  rows with irregular spacing and a `\r` whose rewritten cell keeps every
  other byte;
- the writer without `--check` on a copy of the tree (sources and `tests/`
  less its vectors), an empty diff required;
- a CRLF fixture with spacing and non-ASCII text, only the moving cell written.

RED on `5a87392e` (the test file copied onto the scratch copy): 5 failures and 2
errors of 10; the identity test `the writer rewrote 2 lines of a tree --check
passes ... [(224, ...` ; the property errors there by name (`join_row` is new),
and measured with the base's own reader and joiner it fails 914 of 2,000 rows,
every one a pipe inside a code span. The Rust guard's pin
`a_pipe_inside_a_code_span_or_escaped_is_text_and_not_a_cell_boundary`.

## Stated, not changed

GitHub's table renderer (GFM) splits a row at a `|` inside a code span unless
it is escaped, so the two finder rows render with extra cells on GitHub; the
table's readers here follow the code span, as the authors meant. Writing those
pipes `\|` (as other rows do) is a docs choice for the keeper.
