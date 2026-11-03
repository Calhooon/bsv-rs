"""The equivalence entries' check against the mutant list (#663)."""

import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))

import mutants_entries  # noqa: E402


CONFIG = """\
# the head comment
exclude_re = [
  # src/a.rs:10:5, `<` to `<=` (a match).
  '^src/a\\.rs:10:5: replace < with <= in f$',
  # src/b.rs:20:9 and 21:9, `|` to `^` (two of one text).
  '^src/b\\.rs:20:9: replace \\| with \\^ in g$',
  '^src/b\\.rs:21:9: replace \\| with \\^ in g$',
  # src/c.rs:30:7 (a lifetime in the text).
  '''^src/c\\.rs:30:7: replace != with == in W<'a>::h$''',
]
"""

LISTING = {
    "src/a.rs": [
        "src/a.rs:10:5: replace < with <= in f",
        "src/a.rs:10:5: replace < with > in f",
    ],
    "src/b.rs": [
        "src/b.rs:20:9: replace | with ^ in g",
        "src/b.rs:21:9: replace | with ^ in g",
    ],
    "src/c.rs": ["src/c.rs:30:7: replace != with == in W<'a>::h"],
}


def run(config, listing, *flags):
    """The check on a fixture TOML and listing: (exit status, printed text, the TOML after)."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mutants.toml"
        path.write_text(config)
        out = io.StringIO()
        status = mutants_entries.main(["--config", str(path), *flags],
                                      listing_of=lambda f: listing.get(f, []), out=out)
        return status, out.getvalue(), path.read_text()


class Entries(unittest.TestCase):
    def test_every_entry_matching_one_listed_mutant_passes(self):
        status, out, _ = run(CONFIG, LISTING)
        self.assertEqual(status, 0, out)
        self.assertIn("PASS mutants-entries: 4 entries", out)

    def test_a_triple_quoted_entry_with_a_lifetime_is_read_and_matched(self):
        entries = mutants_entries.entries_of(CONFIG)
        self.assertEqual([e.file for e in entries][-1], "src/c.rs")
        status, out, _ = run(CONFIG, {**LISTING, "src/c.rs": []})
        self.assertEqual(status, 1)
        self.assertIn("STALE entry (no listed mutant): ^src/c\\.rs:30:7: replace != with == in W<'a>::h$", out)

    def test_a_miss_names_its_unique_re_point(self):
        listing = {**LISTING, "src/a.rs": ["src/a.rs:12:5: replace < with <= in f",
                                           "src/a.rs:12:5: replace < with > in f"]}
        status, out, after = run(CONFIG, listing)
        self.assertEqual(status, 1)
        self.assertIn("STALE entry (no listed mutant): ^src/a\\.rs:10:5:", out)
        self.assertIn("  re-point to 12:5: src/a.rs:12:5: replace < with <= in f", out)
        self.assertIn("FAIL mutants-entries: 1 of 4 entries", out)
        self.assertEqual(after, CONFIG, "the check alone writes nothing")

    def test_a_miss_with_two_candidates_names_both_and_chooses_none(self):
        listing = {**LISTING, "src/a.rs": ["src/a.rs:12:5: replace < with <= in f",
                                           "src/a.rs:14:5: replace < with <= in f"]}
        status, out, after = run(CONFIG, listing, "--fix")
        self.assertEqual(status, 1)
        self.assertIn("no unique re-point; 2 candidates:", out)
        self.assertIn("  candidate: src/a.rs:12:5: replace < with <= in f", out)
        self.assertIn("  candidate: src/a.rs:14:5: replace < with <= in f", out)
        self.assertNotIn("re-point to", out)
        self.assertEqual(after, CONFIG, "--fix leaves an ambiguous entry alone")

    def test_a_double_match_names_both_lines(self):
        config = CONFIG.replace("'^src/a\\.rs:10:5: replace < with <= in f$'",
                                "'^src/a\\.rs:10:5: replace < with .* in f$'")
        status, out, _ = run(config, LISTING)
        self.assertEqual(status, 1)
        self.assertIn("DOUBLE match (2 mutants): ^src/a\\.rs:10:5: replace < with .* in f$", out)
        self.assertIn("  matches: src/a.rs:10:5: replace < with <= in f", out)
        self.assertIn("  matches: src/a.rs:10:5: replace < with > in f", out)

    def test_a_shift_under_entries_of_one_text_pairs_them_in_line_order(self):
        listing = {**LISTING, "src/b.rs": ["src/b.rs:23:9: replace | with ^ in g",
                                           "src/b.rs:24:9: replace | with ^ in g"]}
        status, out, _ = run(CONFIG, listing)
        self.assertEqual(status, 1)
        self.assertIn("^src/b\\.rs:20:9: replace \\| with \\^ in g$\n  re-point to 23:9:", out)
        self.assertIn("^src/b\\.rs:21:9: replace \\| with \\^ in g$\n  re-point to 24:9:", out)

    def test_a_held_line_is_no_candidate_for_a_stale_entry(self):
        listing = {**LISTING, "src/b.rs": ["src/b.rs:21:9: replace | with ^ in g",
                                           "src/b.rs:22:9: replace | with ^ in g"]}
        status, out, _ = run(CONFIG, listing)
        self.assertEqual(status, 1)
        self.assertIn("^src/b\\.rs:20:9: replace \\| with \\^ in g$\n  re-point to 22:9:", out)

    def test_fix_rewrites_the_entries_and_their_comment_at_once(self):
        listing = {**LISTING,
                   "src/a.rs": ["src/a.rs:11:5: replace < with <= in f"],
                   "src/b.rs": ["src/b.rs:22:9: replace | with ^ in g",
                                "src/b.rs:23:9: replace | with ^ in g"]}
        status, out, after = run(CONFIG, listing, "--fix")
        self.assertEqual(status, 1)
        self.assertIn("rewrote", out)
        want = (CONFIG.replace("src/a.rs:10:5", "src/a.rs:11:5")
                .replace("a\\.rs:10:5", "a\\.rs:11:5")
                .replace("20:9 and 21:9", "22:9 and 23:9")
                .replace("b\\.rs:21:9", "b\\.rs:23:9")
                .replace("b\\.rs:20:9", "b\\.rs:22:9"))
        self.assertEqual(after, want)
        status, out, _ = run(after, listing)
        self.assertEqual(status, 0, out)

    def test_a_one_line_shift_under_adjacent_entries_fails_and_fixes_to_the_listed_set(self):
        # 20 and 21 of one text moved to 21 and 22: the entry at 21 holds the moved 20's
        # mutant, so only the entry at 20 is stale; its re-point is the free 22, and the two
        # entries then exclude the same two mutants, which is all an entry does.
        listing = {**LISTING, "src/b.rs": ["src/b.rs:21:9: replace | with ^ in g",
                                           "src/b.rs:22:9: replace | with ^ in g"]}
        status, out, after = run(CONFIG, listing, "--fix")
        self.assertEqual(status, 1)
        self.assertIn("^src/b\\.rs:20:9: replace \\| with \\^ in g$\n  re-point to 22:9:", out)
        status, out, _ = run(after, listing)
        self.assertEqual(status, 0, out)

    def test_an_entry_of_another_shape_is_refused_as_unreadable(self):
        status, out, _ = run("exclude_re = ['replace < with <=']\n", LISTING)
        self.assertEqual(status, 2)
        self.assertIn("FAIL mutants-entries: not an anchored", out)

    def test_a_repeated_entry_is_named(self):
        config = CONFIG.replace("]\n", "  '^src/a\\.rs:10:5: replace < with <= in f$',\n]\n")
        status, out, _ = run(config, LISTING)
        self.assertEqual(status, 1)
        self.assertIn("DUPLICATE entry: ^src/a\\.rs:10:5:", out)

    def test_the_repository_entries_are_all_readable(self):
        root = Path(__file__).resolve().parents[2]
        entries = mutants_entries.entries_of((root / ".cargo/mutants.toml").read_text())
        self.assertTrue(entries)
        for entry in entries:
            self.assertTrue((root / entry.file).is_file(), entry.pattern)


if __name__ == "__main__":
    unittest.main()
