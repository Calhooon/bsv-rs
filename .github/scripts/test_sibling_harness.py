"""Witnesses for the sibling harness command (#97, S1): the rewrite, the two
parts of the judgment (VERDICTS from the harness's own logs, REASONS against
the committed column, the captain's ruling on Q97.5), `--record`, the exit
mapping of `run` and the public edition's withheld entries."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import sibling_harness as sh

LINE = 'bsv-rs = { version = "=0.7.0", features = ["transaction"] }\n'
CARGO = f'[package]\nname = "h"\n\n[dependencies]\n# a comment naming bsv-rs\n{LINE}serde = "1"\n'
SIBLING = "1c051eaef1077cc95e5d1618686d5efacc4aa097"
GREEN_LINE = "run_diff: GREEN (every divergence explained by a rule with its citation)\n"


def red_line(unexplained, unknown, recorded):
    return (
        f"run_diff: RED ({unexplained} unexplained divergences, {unknown} messages outside the table, "
        f"{recorded} recorded bsv-rs verdicts disagreeing)\n"
    )


def words_line(entry, rec, spec=None, mempool=None):
    return json.dumps({"id": entry, "rec": rec, "spec": spec or rec, "mempool": mempool or rec}) + "\n"


WORDS = (
    words_line("seed-1", ["valid", None])
    + words_line("seed-2", ["invalid", "The signature must have a low S value."])
    + words_line("seed-3", ["invalid", "a"], spec=["invalid", "b"])
)


def quiet(function, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = function(*args, **kwargs)
    return code, out.getvalue() + err.getvalue()


def manifest_entry(corpus_file, **overrides):
    entry = {
        "file": "seed.jsonl",
        "sha256": "00",
        "witnesses": 1,
        "corpus": str(corpus_file),
        "spec": "spec@abc",
        "spec_config": "x",
        "bsv-rs": "0.7.0",
        "engine_config": {"recorded": {}},
        "entries": 3,
        "agree_mempool": 3,
        "agree_block": 2,
        "undecided": 0,
        "aborts_as_witnesses": 0,
        "unknown_messages": {},
        "rules": [],
        "generated": "2026-11-10",
    }
    entry.update(overrides)
    return entry


# a row of the sibling's rules table as a manifest writes it: an explained divergence
ROW = {"column": "spec", "rule": "policy.minimaldata", "entries": 1, "witness": "w-1",
       "ruling": "r", "from": "seed-1", "decided_by": "d"}


class Rewrite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "Cargo.toml"
        self.tree = Path(self.dir.name) / "tree"

    def tearDown(self):
        self.dir.cleanup()

    def test_the_one_line_is_rewritten_and_its_features_kept(self):
        self.path.write_text(CARGO)
        sh.rewrite_dependency(self.path, self.tree)
        text = self.path.read_text()
        want = f'bsv-rs = {{ path = {json.dumps(str(self.tree.resolve()))}, features = ["transaction"] }}\n'
        self.assertEqual(text, CARGO.replace(LINE, want))

    def test_an_absent_line_is_a_stop_naming_the_file(self):
        self.path.write_text(CARGO.replace(LINE, ""))
        with self.assertRaisesRegex(sh.Stop, "Cargo.toml.*found 0"):
            sh.rewrite_dependency(self.path, self.tree)

    def test_a_doubled_line_is_a_stop_naming_the_file(self):
        self.path.write_text(CARGO + LINE)
        with self.assertRaisesRegex(sh.Stop, "Cargo.toml.*found 2"):
            sh.rewrite_dependency(self.path, self.tree)
        self.assertEqual(self.path.read_text(), CARGO + LINE)


class Compare(unittest.TestCase):
    """A run's report written by hand: the manifest, the log, the words."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.corpus = root / "seed.jsonl"
        self.corpus.write_text('{"id": "seed-1"}\n')
        self.out = root / "out"
        (self.out / "bsv-rs").mkdir(parents=True)
        (self.out / sh.WORDS_DIR).mkdir()
        self.info({})
        self.manifest = self.out / "bsv-rs" / "manifest.json"
        self.column = root / "column.json"
        self.write({"seed": manifest_entry(self.corpus)})
        self.log(GREEN_LINE)
        self.words(WORDS)
        code, text = self.record()
        self.assertEqual(code, 0, text)

    def tearDown(self):
        self.dir.cleanup()

    def info(self, withheld, sibling=SIBLING):
        (self.out / "sibling.json").write_text(json.dumps(
            {"sibling": sibling, "rules_pin": "0.3.33", "corpora": ["seed"], "withheld": withheld}))

    def write(self, manifest):
        self.manifest.write_text(json.dumps(manifest))

    def log(self, text):
        (self.out / "seed.log").write_text("spec_recorded: ...\nrun_diff: seed/seed.jsonl (3 entries)\n" + text)

    def words(self, text):
        (self.out / sh.WORDS_DIR / "seed.jsonl").write_text(text)

    def record(self):
        return quiet(sh.main, ["compare", "--manifest", str(self.manifest), "--column", str(self.column), "--record"])

    def compare(self):
        return quiet(sh.main, ["compare", "--manifest", str(self.manifest), "--column", str(self.column)])

    def test_equal_is_0_and_reports_both_parts(self):
        code, text = self.compare()
        self.assertEqual(code, 0, text)
        self.assertIn("VERDICTS: 3 entries, 0 divergences", text)
        self.assertIn(f"REASONS: 3 equal, 0 differ from {self.column}", text)
        self.assertIn("GREEN", text)

    def test_an_unexplained_divergence_is_1_naming_the_entry_from_the_log(self):
        self.log(red_line(1, 0, 0) + "  UNEXPLAINED spec seed-2 (f, rule r, version 2): spec valid vs bsv-rs invalid Some(\"x\")\n")
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("VERDICTS: 3 entries, 1 divergences", text)
        self.assertIn("seed: UNEXPLAINED spec seed-2 (f, rule r, version 2)", text)

    def test_the_siblings_own_0_7_0_words_alone_are_reported_not_judged(self):
        self.log(red_line(0, 0, 1))
        code, text = self.compare()
        self.assertEqual(code, 0, text)
        self.assertIn("recorded bsv-rs@0.7.0 texts disagreeing: 1", text)

    def test_a_log_without_a_verdict_line_is_1_naming_the_corpus(self):
        self.log("run_diff: a corpus entry must be well-formed: gen-00793: tx hex\n")
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed: no run_diff verdict line", text)

    def test_a_reason_that_moved_is_1_naming_the_entry_with_both_texts(self):
        self.words(WORDS.replace("The signature must have a low S value.", "The signature format is invalid."))
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("VERDICTS: 3 entries, 0 divergences", text)
        self.assertIn("REASONS: 2 equal, 1 differ", text)
        self.assertIn(
            'seed seed-2 [rec/spec/mempool]: column invalid "The signature must have a low S value."; '
            'run invalid "The signature format is invalid."', text)

    def test_a_verdict_that_moved_under_one_word_is_named_with_that_word(self):
        self.words(WORDS.replace('"mempool": ["invalid", "a"]', '"mempool": ["valid", null]'))
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn('seed seed-3 [mempool]: column invalid "a"; run valid', text)

    def test_an_entry_absent_from_the_column_is_1(self):
        self.words(WORDS + words_line("seed-4", ["valid", None]))
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed seed-4: absent from the column, run valid", text)

    def test_a_note_is_printed_beside_its_entry(self):
        column = json.loads(self.column.read_text())
        column["notes"] = {"seed-2": "#657"}
        self.column.write_text(sh.column_text(column))
        self.words(WORDS.replace("low S", "high S"))
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("(note: #657)", text)

    def test_an_explained_rules_row_of_the_run_is_1_naming_it(self):
        self.write({"seed": manifest_entry(self.corpus, rules=[ROW])})
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn('seed rules: an explained divergence, refused: {"column": "spec", '
                      '"rule": "policy.minimaldata", "entries": 1, "witness": "w-1"}', text)

    def test_an_explained_rules_row_the_column_also_lists_is_still_refused(self):
        column = json.loads(self.column.read_text())
        column["corpora"]["seed"]["rules"] = [dict(zip(sh.RULE_KEYS, (ROW[k] for k in sh.RULE_KEYS)))]
        self.column.write_text(sh.column_text(column))
        self.write({"seed": manifest_entry(self.corpus, rules=[ROW])})
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("carries an explained row or an abort witness; a column holds none", text)

    def test_a_column_carrying_an_abort_witness_is_2(self):
        column = json.loads(self.column.read_text())
        column["corpora"]["seed"]["aborts_as_witnesses"] = 1
        self.column.write_text(sh.column_text(column))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("seed aborts_as_witnesses: 1, refused", text)

    def test_entries_moved_is_1(self):
        self.write({"seed": manifest_entry(self.corpus, entries=11)})
        code, text = self.compare()
        self.assertEqual(code, 1)
        self.assertIn("seed entries: column 3, run 11", text)

    def test_each_compared_count_moved_is_1_naming_it(self):
        for key in ("agree_mempool", "agree_block", "undecided", "aborts_as_witnesses"):
            with self.subTest(key=key):
                self.write({"seed": manifest_entry(self.corpus, **{key: 7})})
                code, text = self.compare()
                self.assertEqual(code, 1, text)
                self.assertIn(f"seed {key}: column ", text)
                self.assertIn(", run 7", text)

    def test_another_rules_pin_is_2(self):
        (self.out / "sibling.json").write_text(json.dumps(
            {"sibling": SIBLING, "rules_pin": "0.3.34", "corpora": ["seed"], "withheld": {}}))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("rules_pin: column 0.3.33, run 0.3.34", text)

    def test_a_corpus_of_the_run_absent_from_the_columns_corpora_is_2(self):
        column = json.loads(self.column.read_text())
        del column["corpora"]["seed"]
        self.column.write_text(sh.column_text(column))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("seed: a corpus of the run is not in", text)

    def test_a_corpus_of_the_run_without_words_in_the_column_is_2(self):
        column = json.loads(self.column.read_text())
        column["words"]["other"] = column["words"].pop("seed")
        self.column.write_text(sh.column_text(column))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("seed: a corpus of the run has no words in", text)

    def test_an_entry_in_the_column_absent_from_the_run_is_1_naming_it(self):
        self.words(WORDS.splitlines(keepends=True)[0] + WORDS.splitlines(keepends=True)[2])
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed seed-2: in the column, absent from the run", text)

    def test_a_note_is_printed_beside_an_entry_absent_from_the_run(self):
        column = json.loads(self.column.read_text())
        column["notes"] = {"seed-2": "#657"}
        self.column.write_text(sh.column_text(column))
        self.words(WORDS.splitlines(keepends=True)[0] + WORDS.splitlines(keepends=True)[2])
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed seed-2: in the column, absent from the run (note: #657)", text)

    def test_unexplained_divergences_each_named_print_no_more_line(self):
        self.log(red_line(1, 0, 0) + "  UNEXPLAINED spec seed-2 (f): spec valid vs bsv-rs invalid\n")
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertNotIn("more unexplained", text)

    def test_unexplained_divergences_past_the_named_are_counted(self):
        self.log(red_line(21, 0, 0) + "  UNEXPLAINED spec seed-2 (f): spec valid vs bsv-rs invalid\n")
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed: 20 more unexplained (run_diff names 20;", text)

    def test_messages_outside_the_table_the_manifest_does_not_name_are_counted(self):
        self.log(red_line(0, 2, 0))
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("seed: 2 messages outside the sibling's code table (see ", text)

    def test_an_error_of_the_script_itself_is_2_with_a_setup_line(self):
        saved = sh.compare
        def broken(*args, **kwargs):
            raise KeyError("x")
        sh.compare = broken
        try:
            code, text = self.compare()
        finally:
            sh.compare = saved
        self.assertEqual(code, 2, text)
        self.assertIn("sibling_harness: SETUP STOP: an error of the script itself: KeyError", text)

    def test_a_message_outside_the_code_table_is_1_naming_it(self):
        self.write({"seed": manifest_entry(self.corpus, unknown_messages={"a new text": 3})})
        self.log(red_line(0, 3, 0))
        code, text = self.compare()
        self.assertEqual(code, 1)
        self.assertIn("seed: outside the sibling's code table (3x): a new text", text)

    def test_the_ignored_keys_are_0(self):
        self.write({"seed": manifest_entry(
            self.corpus, generated="2027-01-01", **{"bsv-rs": "0.9.0", "engine_config": {"other": 1}})})
        code, text = self.compare()
        self.assertEqual(code, 0, text)

    def test_another_corpus_sha256_is_2(self):
        self.corpus.write_text('{"id": "seed-2"}\n')
        code, text = self.compare()
        self.assertEqual(code, 2)
        self.assertIn("corpus_sha256", text)

    def test_another_sibling_commit_is_2(self):
        self.info({}, sibling="0" * 40)
        code, _ = self.compare()
        self.assertEqual(code, 2)

    def test_another_withheld_count_is_2(self):
        self.info({"seed": 4})
        code, text = self.compare()
        self.assertEqual(code, 2)
        self.assertIn("seed withheld: column 0, run 4", text)

    def test_record_then_compare_round_trips_one_line_per_entry(self):
        column = json.loads(self.column.read_text())
        self.assertEqual(column["sibling"], SIBLING)
        self.assertEqual(column["withheld"], {})
        self.assertEqual(column["words"]["seed"], {
            "seed-1": ["valid", None],
            "seed-2": ["invalid", "The signature must have a low S value."],
            "seed-3": {"rec": ["invalid", "a"], "spec": ["invalid", "b"], "mempool": ["invalid", "a"]},
        })
        text = self.column.read_text()
        self.assertEqual(text, sh.column_text(column))
        self.assertIn('      "seed-2": ["invalid", "The signature must have a low S value."],', text.splitlines())
        code, _ = self.compare()
        self.assertEqual(code, 0)

    def test_record_keeps_the_notes_of_entries_still_held(self):
        column = json.loads(self.column.read_text())
        column["notes"] = {"seed-2": "#657", "seed-9": "gone"}
        self.column.write_text(sh.column_text(column))
        code, text = self.record()
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(self.column.read_text())["notes"], {"seed-2": "#657"})

    def test_record_refuses_a_run_red_on_verdicts(self):
        self.log(red_line(1, 0, 0))
        code, _ = self.record()
        self.assertEqual(code, 2)

    def test_record_takes_a_run_red_on_the_siblings_0_7_0_words_alone(self):
        self.log(red_line(0, 0, 1))
        code, text = self.record()
        self.assertEqual(code, 0, text)

    def test_record_refuses_a_message_outside_the_code_table(self):
        self.write({"seed": manifest_entry(self.corpus, unknown_messages={"a new text": 3})})
        self.log(red_line(0, 3, 0))
        before = self.column.read_text()
        code, text = self.record()
        self.assertEqual(code, 2, text)
        self.assertEqual(self.column.read_text(), before)

    def test_record_refuses_a_run_carrying_an_explained_rules_row(self):
        self.write({"seed": manifest_entry(self.corpus, rules=[ROW])})
        before = self.column.read_text()
        code, text = self.record()
        self.assertEqual(code, 2, text)
        self.assertIn("seed rules: an explained divergence, refused", text)
        self.assertEqual(self.column.read_text(), before)

    def test_record_refuses_a_run_carrying_an_abort_witness(self):
        self.column.unlink()
        self.write({"seed": manifest_entry(self.corpus, aborts_as_witnesses=1)})
        code, text = self.record()
        self.assertEqual(code, 2, text)
        self.assertIn("seed aborts_as_witnesses: 1, refused", text)
        self.assertFalse(self.column.exists())

    def test_record_at_the_columns_pin_refuses_a_count_moved(self):
        for key in ("entries", "agree_mempool", "agree_block", "undecided"):
            with self.subTest(key=key):
                self.write({"seed": manifest_entry(self.corpus, **{key: 1})})
                before = self.column.read_text()
                code, text = self.record()
                self.assertEqual(code, 2, text)
                self.assertIn(f"seed {key}: column ", text)
                self.assertIn("moves words only", text)
                self.assertEqual(self.column.read_text(), before)

    def test_record_at_the_columns_pin_moves_words(self):
        self.words(WORDS.replace("low S", "high S"))
        code, text = self.record()
        self.assertEqual(code, 0, text)
        self.assertIn("high S", self.column.read_text())

    def test_record_at_another_pin_takes_moved_counts(self):
        self.info({}, sibling="1" * 40)
        self.write({"seed": manifest_entry(self.corpus, undecided=1, agree_block=1)})
        code, text = self.record()
        self.assertEqual(code, 0, text)
        column = json.loads(self.column.read_text())
        self.assertEqual((column["sibling"], column["corpora"]["seed"]["undecided"]), ("1" * 40, 1))


    # the second fold (#853): at the column's own pin --record is judged entry by entry
    NA = ["undecided", "not applicable: pre-Genesis"]

    def column_words(self, rows):
        column = json.loads(self.column.read_text())
        column["words"]["seed"] = rows
        self.column.write_text(sh.column_text(column))

    def assert_record_refused(self, *named):
        before = self.column.read_text()
        code, text = self.record()
        self.assertEqual(code, 2, text)
        self.assertIn("moves words only", text)
        for line in named:
            self.assertIn(line, text)
        self.assertEqual(self.column.read_text(), before)
        return text

    def test_record_at_the_pin_refuses_two_offsetting_flips_decided_and_undecided(self):
        # seed-1 decided to undecided, seed-2 undecided to decided: every total held
        self.column_words({"seed-1": ["valid", None], "seed-2": self.NA, "seed-3": ["invalid", "a"]})
        self.words(words_line("seed-1", self.NA) + words_line("seed-2", ["valid", None])
                   + words_line("seed-3", ["invalid", "a"]))
        self.assert_record_refused(
            "seed seed-1 verdicts (rec/spec/mempool): column valid/valid/valid, run undecided/undecided/undecided",
            "seed seed-2 verdicts (rec/spec/mempool): column undecided/undecided/undecided, run valid/valid/valid")

    def test_record_at_the_pin_refuses_two_swapped_verdicts(self):
        self.words(words_line("seed-1", ["invalid", "The signature must have a low S value."])
                   + words_line("seed-2", ["valid", None])
                   + words_line("seed-3", ["invalid", "a"], spec=["invalid", "b"]))
        self.assert_record_refused(
            "seed seed-1 verdicts (rec/spec/mempool): column valid/valid/valid, run invalid/invalid/invalid",
            "seed seed-2 verdicts (rec/spec/mempool): column invalid/invalid/invalid, run valid/valid/valid")

    def test_record_at_the_pin_refuses_a_verdict_moved_under_the_recorded_word_alone(self):
        # the recorded word's verdict, which run_diff never judges
        self.column_words({"seed-1": ["valid", None], "seed-2": ["invalid", "x"],
                           "seed-3": {"rec": ["invalid", "a"], "spec": ["valid", None], "mempool": ["valid", None]}})
        self.words(words_line("seed-1", ["valid", None]) + words_line("seed-2", ["invalid", "x"])
                   + words_line("seed-3", ["valid", None]))
        self.assert_record_refused(
            "seed seed-3 verdicts (rec/spec/mempool): column invalid/valid/valid, run valid/valid/valid")

    def test_record_at_the_pin_refuses_two_offsetting_flips_under_the_recorded_word(self):
        rows = {f"seed-{i}": {"rec": ["valid" if i == 1 else "invalid", None], "spec": ["valid", None],
                              "mempool": ["valid", None]} for i in (1, 2)}
        rows["seed-3"] = ["invalid", "a"]
        self.column_words(rows)
        self.words(words_line("seed-1", ["invalid", None], spec=["valid", None], mempool=["valid", None])
                   + words_line("seed-2", ["valid", None])
                   + words_line("seed-3", ["invalid", "a"]))
        self.assert_record_refused(
            "seed seed-1 verdicts (rec/spec/mempool): column valid/valid/valid, run invalid/valid/valid",
            "seed seed-2 verdicts (rec/spec/mempool): column invalid/valid/valid, run valid/valid/valid")

    def test_record_at_the_pin_names_twenty_moved_entries_then_counts(self):
        self.column_words({f"seed-{i:02}": ["valid", None] for i in range(25)})
        self.words("".join(words_line(f"seed-{i:02}", ["invalid", "x"]) for i in range(25)))
        text = self.assert_record_refused("seed seed-19 verdicts", "and 5 more entries")
        self.assertNotIn("seed seed-20 verdicts", text)

    def test_record_at_the_pin_refuses_an_entry_gone_from_the_run(self):
        self.words(WORDS.splitlines(keepends=True)[0] + WORDS.splitlines(keepends=True)[2])
        self.assert_record_refused("seed seed-2: in the column, absent from the run")

    def test_record_at_another_pin_takes_moved_verdicts(self):
        self.info({}, sibling="1" * 40)
        self.words(words_line("seed-1", self.NA) + WORDS.split("\n", 1)[1])
        code, text = self.record()
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(self.column.read_text())["words"]["seed"]["seed-1"], self.NA)

    def test_a_corpus_of_the_column_absent_from_the_run_is_2(self):
        column = json.loads(self.column.read_text())
        column["corpora"]["flow"] = column["corpora"]["seed"]
        column["words"]["flow"] = column["words"]["seed"]
        self.column.write_text(sh.column_text(column))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("flow: a corpus of", text)
        self.assertIn("is not in the run (a run judges every corpus the column carries)", text)

    def test_a_corpus_of_the_runs_record_absent_from_its_manifest_is_2(self):
        (self.out / "sibling.json").write_text(json.dumps(
            {"sibling": SIBLING, "rules_pin": "0.3.33", "corpora": ["seed", "flow"], "withheld": {}}))
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("flow: a corpus of the run's record is not in", text)

    def test_a_corpus_of_the_manifest_absent_from_the_runs_record_is_2(self):
        self.write({"seed": manifest_entry(self.corpus), "flow": manifest_entry(self.corpus)})
        code, text = self.compare()
        self.assertEqual(code, 2, text)
        self.assertIn("is not in the run's record (its log and words would go unread)", text)

    def test_the_headline_counts_an_explained_row_as_a_divergence(self):
        self.write({"seed": manifest_entry(self.corpus, rules=[ROW])})
        code, text = self.compare()
        self.assertEqual(code, 1, text)
        self.assertIn("VERDICTS: 3 entries, 1 divergences (0 unexplained or outside the table, "
                      "1 explained by a rules row, refused)", text)
        self.assertNotIn("VERDICTS: 3 entries, 0 divergences", text)
        self.assertIn("sibling_harness: RED (verdicts: 1 divergences, 0 counts moved;", text)

STUB = """#!/bin/sh
# a stub harness/run: a manifest per $STUB_ENTRIES, a log ending $STUB_LOG, exit $STUB_EXIT
out=""
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift 2 ;; *) shift ;; esac
done
here="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out/bsv-rs"
python3 - "$out" "$here" <<'PY'
import json, os, sys
out, root = sys.argv[1], sys.argv[2]
entry = {"corpus": os.path.join(root, "corpus/seed/seed.jsonl"), "entries": int(os.environ["STUB_ENTRIES"]),
         "agree_mempool": 1, "agree_block": 1, "undecided": 0, "aborts_as_witnesses": 0,
         "unknown_messages": {}, "rules": []}
json.dump({"seed": entry}, open(os.path.join(out, "bsv-rs/manifest.json"), "w"))
open(os.path.join(out, "seed.log"), "w").write(os.environ["STUB_LOG"] + "\\n")
PY
echo "GREEN seed" > "$out/summary.txt"
exit "$STUB_EXIT"
"""

# a stub cargo: `metadata --no-deps` names the target directory; everything else succeeds
CARGO_STUB = """#!/bin/sh
case "$*" in *--no-deps*) printf '{"target_directory": "%s"}' "$STUB_TARGET" ;; esac
exit 0
"""

# a stub bsvrs_words: the words of the one entry, $STUB_WORD its reason
WORDS_STUB = """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift 2 ;; *) shift ;; esac
done
printf '{"id": "seed-1", "rec": ["invalid", "%s"], "spec": ["invalid", "%s"], "mempool": ["invalid", "%s"]}\\n' \
  "$STUB_WORD" "$STUB_WORD" "$STUB_WORD" > "$out"
"""


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Run(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.sibling = root / "sibling"
        executable(self.sibling / "harness" / "run", STUB)
        (self.sibling / "harness" / "Cargo.toml").write_text(CARGO)
        (self.sibling / "harness" / "rules").mkdir()
        (self.sibling / "harness" / "rules" / "bsv-rs.json").write_text('{"pin": "0.3.33"}')
        (self.sibling / "docs").mkdir()
        (self.sibling / "docs" / "PROVENANCE.md").write_text("pins\n")
        seed = self.sibling / "corpus" / "seed"
        seed.mkdir(parents=True)
        (seed / "seed.jsonl").write_text(
            '{"id": "seed-1", "tx": "00"}\n{"id": "seed-2", "tx": "WITHHELD: d8 (see corpus/INDEX.md)"}\n')
        (seed / "manifest.json").write_text(json.dumps({"file": "seed.jsonl", "sha256": "stale"}))
        self.commit = self.commit_all()
        self.tree = root / "tree"
        self.tree.mkdir()
        (self.tree / "Cargo.toml").write_text('[package]\nname = "bsv-rs"\n')
        bin_dir = root / "bin"
        executable(bin_dir / "cargo", CARGO_STUB)
        target = root / "target"
        executable(target / "release" / sh.WORDS_BIN, WORDS_STUB)
        keys = ("PATH", "STUB_EXIT", "STUB_ENTRIES", "STUB_LOG", "STUB_TARGET", "STUB_WORD")
        self.saved = {k: os.environ.get(k) for k in keys}
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
        os.environ["STUB_TARGET"] = str(target)
        os.environ["STUB_WORD"] = "low S"
        kept = '{"id": "seed-1", "tx": "00"}\n'
        self.column = root / "column.json"
        self.column.write_text(sh.column_text({
            "sibling": self.commit, "rules_pin": "0.3.33", "withheld": {"seed": 1}, "notes": {},
            "corpora": {"seed": {
                "corpus_sha256": hashlib.sha256(kept.encode()).hexdigest(),
                "entries": 1, "agree_mempool": 1, "agree_block": 1, "undecided": 0,
                "aborts_as_witnesses": 0, "unknown_messages": {}, "rules": []}},
            "words": {"seed": {"seed-1": ["invalid", "low S"]}}}))
        self.n = 0

    def commit_all(self):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        if not (self.sibling / ".git").exists():
            subprocess.run(["git", "-C", str(self.sibling), "init", "-q"], check=True, env=env)
        for args in (["add", "."], ["commit", "-q", "-m", "s"]):
            subprocess.run(["git", "-C", str(self.sibling), *args], check=True, env=env)
        return subprocess.run(["git", "-C", str(self.sibling), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.dir.cleanup()

    def run_with(self, exit_code, entries=1, rev=True, log=GREEN_LINE.strip()):
        os.environ["STUB_EXIT"] = str(exit_code)
        os.environ["STUB_ENTRIES"] = str(entries)
        os.environ["STUB_LOG"] = log
        self.n += 1
        root = Path(self.dir.name)
        args = ["run", "--tree", str(self.tree), "--sibling", str(self.sibling), "--corpus", "seed",
                "--scratch", str(root / f"scratch{self.n}"), "--out", str(root / f"out{self.n}"),
                "--column", str(self.column)]
        if rev:
            args += ["--rev", self.commit]
        code, text = quiet(sh.main, args)
        return code, text, root / f"scratch{self.n}"

    def test_a_green_harness_and_an_equal_column_is_0(self):
        code, text, scratch = self.run_with(0)
        self.assertEqual(code, 0, text)
        self.assertIn("path =", (scratch / "harness" / "Cargo.toml").read_text())

    def test_the_words_reader_is_staged_in_the_scratch_copy_alone(self):
        code, text, scratch = self.run_with(0)
        self.assertEqual(code, 0, text)
        staged = scratch / "harness" / "src" / "bin" / f"{sh.WORDS_BIN}.rs"
        self.assertEqual(staged.read_text(), sh.WORDS_SOURCE.read_text())
        self.assertFalse((self.sibling / "harness" / "src").exists())

    def test_a_sibling_carrying_the_readers_name_is_2(self):
        (self.sibling / "harness" / "src" / "bin").mkdir(parents=True)
        (self.sibling / "harness" / "src" / "bin" / f"{sh.WORDS_BIN}.rs").write_text("")
        self.commit = self.commit_all()
        code, text, _ = self.run_with(0)
        self.assertEqual(code, 2, text)

    def test_the_withheld_entries_are_dropped_from_the_staged_copy_and_counted(self):
        code, text, scratch = self.run_with(0)
        self.assertEqual(code, 0, text)
        staged = scratch / "corpus" / "seed" / "seed.jsonl"
        self.assertEqual(staged.read_text(), '{"id": "seed-1", "tx": "00"}\n')
        manifest = json.loads((scratch / "corpus" / "seed" / "manifest.json").read_text())
        self.assertEqual(manifest["sha256"], sh.sha256_file(staged))
        self.assertIn("seed: 1 withheld entries dropped", text)
        self.assertIn("WITHHELD", (self.sibling / "corpus" / "seed" / "seed.jsonl").read_text())

    def test_a_harness_red_on_the_siblings_0_7_0_words_alone_is_0(self):
        code, text, _ = self.run_with(1, log=red_line(0, 0, 1).strip())
        self.assertEqual(code, 0, text)

    def test_a_harness_red_on_an_unexplained_divergence_is_1(self):
        code, text, _ = self.run_with(1, log=red_line(1, 0, 0).strip())
        self.assertEqual(code, 1, text)

    def test_a_moved_word_is_1_through_run(self):
        os.environ["STUB_WORD"] = "high S"
        code, text, _ = self.run_with(0)
        self.assertEqual(code, 1, text)
        self.assertIn('seed seed-1 [rec/spec/mempool]: column invalid "low S"; run invalid "high S"', text)

    def test_a_harness_setup_stop_is_2(self):
        self.assertEqual(self.run_with(2)[0], 2)

    def test_a_green_harness_with_a_mismatched_column_is_1(self):
        code, text, _ = self.run_with(0, entries=2)
        self.assertEqual(code, 1)
        self.assertIn("seed entries: column 1, run 2", text)

    def test_the_copy_mode_stages_the_same_paths(self):
        code, text, scratch = self.run_with(0, rev=False)
        self.assertEqual(code, 0, text)
        self.assertTrue((scratch / "docs" / "PROVENANCE.md").is_file())

    def test_an_absent_dependency_line_is_2_through_run(self):
        (self.sibling / "harness" / "Cargo.toml").write_text(CARGO.replace(LINE, ""))
        code, text, _ = self.run_with(0, rev=False)
        self.assertEqual(code, 2)
        self.assertIn("Cargo.toml: expected one", text)

    def test_a_harness_killed_by_a_signal_is_2(self):
        stub = self.sibling / "harness" / "run"
        stub.write_text("#!/bin/sh\nkill -9 $$\n")
        self.commit = self.commit_all()
        code, text, _ = self.run_with(0)
        self.assertEqual(code, 2, text)
        self.assertIn("the harness exited -9; no verdict", text)

    def test_a_non_empty_out_is_2(self):
        root = Path(self.dir.name)
        (root / "out1").mkdir()
        (root / "out1" / "x").write_text("")
        code, text, _ = self.run_with(0)
        self.assertEqual(code, 2, text)
        self.assertIn("is not empty", text)

    def test_a_cases_manifests_sha256_is_rewritten_for_the_staged_file(self):
        seed = self.sibling / "corpus" / "seed"
        (seed / "manifest.json").rename(seed / "cases-manifest.json")
        self.commit = self.commit_all()
        column = json.loads(self.column.read_text())
        column["sibling"] = self.commit
        self.column.write_text(sh.column_text(column))
        code, text, scratch = self.run_with(0)
        self.assertEqual(code, 0, text)
        staged = scratch / "corpus" / "seed"
        manifest = json.loads((staged / "cases-manifest.json").read_text())
        self.assertEqual(manifest["sha256"], sh.sha256_file(staged / "seed.jsonl"))

    def test_a_corpus_line_that_is_not_json_is_kept(self):
        root = Path(self.dir.name) / "drop"
        seed = root / "corpus" / "seed"
        seed.mkdir(parents=True)
        (seed / "seed.jsonl").write_text('not json\n{"id": "a", "tx": "WITHHELD: g"}\n{"id": "b", "tx": "00"}\n')
        (seed / "manifest.json").write_text(json.dumps({"file": "seed.jsonl", "sha256": "stale"}))
        dropped = quiet(sh.drop_withheld, root, ["seed"])[0]
        self.assertEqual(dropped, {"seed": 1})
        self.assertEqual((seed / "seed.jsonl").read_text(), 'not json\n{"id": "b", "tx": "00"}\n')

    def test_a_non_empty_scratch_is_2(self):
        root = Path(self.dir.name)
        (root / "scratch1").mkdir()
        (root / "scratch1" / "x").write_text("")
        self.assertEqual(self.run_with(0)[0], 2)


class Raw(Run):
    """`raw` (#97, stage R): run's steps less the judgment, and a stamp beside the run's files."""

    def raw_with(self, exit_code, log=GREEN_LINE.strip(), head="a" * 40, pull_request="7"):
        os.environ["STUB_EXIT"] = str(exit_code)
        os.environ["STUB_ENTRIES"] = "1"
        os.environ["STUB_LOG"] = log
        self.n += 1
        root = Path(self.dir.name)
        args = ["raw", "--tree", str(self.tree), "--sibling", str(self.sibling), "--corpus", "seed",
                "--scratch", str(root / f"scratch{self.n}"), "--out", str(root / f"out{self.n}"),
                "--rev", self.commit, "--head-sha", head]
        if pull_request is not None:
            args += ["--pull-request", pull_request]
        code, text = quiet(sh.main, args)
        return code, text, root / f"out{self.n}"

    def test_raw_writes_the_runs_files_and_a_stamp_and_reads_no_column(self):
        self.column.unlink()
        code, text, out = self.raw_with(0)
        self.assertEqual(code, 0, text)
        for name in ("sibling.json", "bsv-rs/manifest.json", "seed.log", "summary.txt", "bsvrs-words/seed.jsonl"):
            self.assertTrue((out / name).is_file(), name)
        stamp = json.loads((out / sh.STAMP).read_text())
        kept = hashlib.sha256(b'{"id": "seed-1", "tx": "00"}\n').hexdigest()
        self.assertEqual(stamp, {"schema": 1, "head_sha": "a" * 40, "pull_request": 7, "sibling": self.commit,
                                 "rules_pin": "0.3.33", "corpora": {"seed": {"corpus_sha256": kept, "withheld": 1}}})
        self.assertNotIn("VERDICTS", text)

    def test_raw_is_0_whatever_the_verdict(self):
        for log in (red_line(1, 0, 0).strip(), red_line(0, 3, 0).strip(), "no verdict line"):
            with self.subTest(log):
                code, text, _ = self.raw_with(1, log=log)
                self.assertEqual(code, 0, text)

    def test_raw_on_a_dispatch_stamps_no_pull_request(self):
        code, text, out = self.raw_with(0, pull_request=None)
        self.assertEqual(code, 0, text)
        self.assertIsNone(json.loads((out / sh.STAMP).read_text())["pull_request"])

    def test_raw_stops_as_run_stops(self):
        self.assertEqual(self.raw_with(2)[0], 2)
        for head in ("A" * 40, "a" * 39, ""):
            with self.subTest(head):
                self.assertEqual(self.raw_with(0, head=head)[0], 2)
        self.assertEqual(self.raw_with(0, pull_request="seven")[0], 2)
        (self.sibling / "harness" / "Cargo.toml").write_text(CARGO.replace(LINE, ""))
        self.commit = self.commit_all()
        self.assertEqual(self.raw_with(0)[0], 2)

    def test_runs_lines_and_exits_do_not_move(self):
        code, text, _ = self.run_with(0)
        self.assertEqual(code, 0, text)
        self.assertIn("sibling_harness: GREEN (1 corpora; verdicts and words equal to", text)
        self.assertNotIn("RAW written", text)


class JudgeRun(Compare):
    """The judgment over the run's files as bytes by name, the column as an object and the corpus
    facts as an argument (#97): what the judge calls, with no path of the run opened."""

    def files(self):
        out = {}
        for path in self.out.rglob("*"):
            if path.is_file():
                out[str(path.relative_to(self.out))] = path.read_bytes()
        return out

    def test_a_zipped_moved_run_with_its_scratch_deleted_judges_as_compare_does(self):
        import zipfile
        code, text = self.compare()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in self.files().items():
                archive.writestr(name, data)
        facts = {"sibling": SIBLING, "rules_pin": "0.3.33", "withheld": {},
                 "corpora": {"seed": {"corpus_sha256": hashlib.sha256(self.corpus.read_bytes()).hexdigest()}}}
        manifest = json.loads(self.manifest.read_text())
        manifest["seed"]["corpus"] = "/nonexistent/on/this/machine"
        column = json.loads(self.column.read_text())
        self.corpus.unlink()
        import shutil
        shutil.rmtree(self.out)
        with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        got, lines = sh.judge_run(files, "the artifact", ["seed"], manifest, column, facts, "column.json")
        self.assertEqual((got, code), (0, 0), text)
        self.assertIn("VERDICTS: 3 entries, 0 divergences", lines)
        files["seed.log"] = red_line(1, 0, 0).encode()
        self.assertEqual(sh.judge_run(files, "the artifact", ["seed"], manifest, column, facts, "column.json")[0], 1)
        other = dict(facts, corpora={"seed": {"corpus_sha256": "00"}})
        with self.assertRaisesRegex(sh.Stop, "corpus_sha256"):
            sh.judge_run(files, "the artifact", ["seed"], manifest, column, other, "column.json")



# Raw and JudgeRun borrow Run's and Compare's fixtures, not their tests (each runs once, there)
for _cls, _base in ((Raw, Run), (JudgeRun, Compare)):
    for _name in dir(_base):
        if _name.startswith("test") and _name not in _cls.__dict__:
            setattr(_cls, _name, None)
del _cls, _base, _name

if __name__ == "__main__":
    unittest.main()
