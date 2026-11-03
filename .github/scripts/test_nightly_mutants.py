"""Exercise score math and rejection of incomplete or inconsistent evidence."""

import argparse
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import nightly_mutants as nightly


class ScoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = "src/transaction/merkle_path.rs"

    def fixture(self, outcomes, surface="merkle", shard="0/1", commit="abc123"):
        path = self.root / f"{surface}-{shard.replace('/', '-')}"
        path.mkdir()
        mutants = [{"file": self.file, "name": f"mutant {i}"}
                   for i in range(len(outcomes))]
        counts = {key: outcomes.count(kind) for kind, key in nightly.OUTCOMES.items()}
        nightly.write_json(path / "run.json", {
            "surface": surface, "shard": shard, "commit": commit, "exit_code": 0,
            "files": [self.file],
            "command": ["cargo", "mutants", "--shard", shard],
        })
        nightly.write_json(path / "candidates.json", mutants)
        nightly.write_json(path / "outcomes.json", {
            "cargo_mutants_version": "27.1.0", "end_time": "2026-10-23T03:00:00Z",
            "outcomes": [{"scenario": "Baseline", "summary": "Success"}] + [
                {"scenario": {"Mutant": mutant}, "summary": outcome}
                for mutant, outcome in zip(mutants, outcomes)
            ], "total_mutants": len(mutants), **counts,
        })
        return path

    def change(self, path, name, edit):
        data = json.loads((path / name).read_text())
        edit(data)
        nightly.write_json(path / name, data)

    def collect(self, shards=None, floors=None):
        return nightly.collect(self.root, shards, floors or {})

    def test_exact_floor_and_unviable_exclusion(self):
        self.fixture(["CaughtMutant"] * 4 + ["MissedMutant", "Unviable"])
        result = self.collect()
        self.assertTrue(result["passed"])
        self.assertEqual(result["files"][0]["score_percent"], 80)

    def test_timeout_is_not_caught(self):
        self.fixture(["CaughtMutant"] * 3 + ["Timeout"] * 2)
        result = self.collect()
        self.assertFalse(result["passed"])
        self.assertTrue(result["complete"])
        self.assertEqual(result["files"][0]["score_percent"], 60)

    def test_no_viable_mutants_is_not_a_pass(self):
        self.fixture(["Unviable"])
        self.assertFalse(self.collect()["passed"])

    def test_display_rounding_does_not_pass_below_floor(self):
        self.fixture(["CaughtMutant"] * 7999 + ["MissedMutant"] * 2000)
        result = self.collect()
        self.assertEqual(round(result["files"][0]["score_percent"], 2), 80.0)
        self.assertFalse(result["passed"])

    def test_incomplete_run_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d.update(end_time=None))
        result = self.collect()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["files"][0]["passed"])

    def test_missing_candidate_result_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d["outcomes"].pop())
        self.assertFalse(self.collect()["complete"])

    def test_failed_baseline_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d["outcomes"][0].update(summary="Failure"))
        self.assertFalse(self.collect()["complete"])

    def test_missing_shards_are_not_a_score(self):
        self.fixture(["CaughtMutant"])
        self.assertFalse(self.collect(shards=4)["complete"])

    def test_local_sample_cannot_establish_a_floor(self):
        self.fixture(["CaughtMutant"], shard="0/16")
        result = self.collect()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["files"][0]["passed"])
        self.assertFalse(result["files"][0]["scope_complete"])

    def test_candidate_outside_inventory_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "run.json", lambda d: d.update(files=[]))
        self.assertFalse(self.collect()["complete"])

    def test_count_mismatch_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d.update(caught=100))
        self.assertFalse(self.collect()["complete"])

    def test_unknown_outcome_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d["outcomes"][1].update(summary="Success"))
        self.assertFalse(self.collect()["complete"])

    def test_all_twenty_shards_can_pass(self):
        for surface in nightly.SURFACES:
            for i in range(4):
                path = self.fixture(["CaughtMutant"], surface=surface, shard=f"{i}/4")
                def rename(data):
                    for mutant in data:
                        mutant["name"] = path.name
                self.change(path, "candidates.json", rename)
                self.change(path, "outcomes.json", lambda d: rename(
                    [entry["scenario"]["Mutant"] for entry in d["outcomes"][1:]]))
        self.assertTrue(self.collect(shards=4)["passed"])

    def test_duplicate_mutants_are_not_a_score(self):
        self.fixture(["CaughtMutant"], shard="0/2")
        self.fixture(["CaughtMutant"], shard="1/2")
        self.assertFalse(self.collect()["complete"])

    def test_different_test_commands_are_not_a_score(self):
        self.fixture(["CaughtMutant"], shard="0/2")
        path = self.fixture(["CaughtMutant"], shard="1/2")
        self.change(path, "run.json", lambda d: d["command"].append("--check"))
        self.assertTrue(any("inconsistent mutation or test command" in e
                            for e in self.collect()["errors"]))

    def test_mixed_commits_are_not_a_score(self):
        self.fixture(["CaughtMutant"], shard="0/2")
        self.fixture(["CaughtMutant"], shard="1/2", commit="def456")
        self.assertIn("results must describe exactly one source commit", self.collect()["errors"])

    def test_wrong_tool_version_is_not_a_score(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "outcomes.json", lambda d: d.update(cargo_mutants_version="unknown"))
        self.assertFalse(self.collect()["complete"])

    def test_lower_floor_requires_an_improvement_issue(self):
        self.fixture(["CaughtMutant", "MissedMutant"])
        with self.assertRaises(ValueError):
            self.collect(floors={self.file: {"percent": 50}})
        result = self.collect(floors={self.file: {
            "percent": 50, "issue": "https://github.com/Calhooon/bsv-rs/issues/81",
        }})
        self.assertTrue(result["passed"])

    def test_floors_are_read_from_the_ratchets_record(self):
        self.fixture(["CaughtMutant", "MissedMutant"])
        record = self.root.parent / f"{self.root.name}-ratchets.json"
        self.addCleanup(record.unlink)
        record.write_text(json.dumps({"schema": 1, "mutation_floors": {self.file: {
            "percent": 50, "issue": "https://github.com/Calhooon/bsv-rs/issues/602"}}}))
        output = self.root.parent / f"{self.root.name}-score.json"
        self.addCleanup(output.unlink)
        self.addCleanup(output.with_suffix(".md").unlink)
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            args = argparse.Namespace(input=self.root, output=output,
                                      expected_shards=None, floors=record)
            # merkle_path.rs is a gate path: the record cannot lower it.
            self.assertEqual(nightly.report(args), 1)
            self.assertIn("a gate path carries no floor of its own",
                          json.loads(output.read_text())["errors"][0])
        self.assertTrue(nightly.is_gate_path("src/script/spend/bitwise.rs"))
        self.assertTrue(nightly.is_gate_path("src/transaction/beef_stream.rs"))
        self.assertFalse(nightly.is_gate_path("src/transaction/broadcaster.rs"))
        self.assertFalse(nightly.is_gate_path("src/wallet/wire/reader.rs"))
        record.write_text(json.dumps({"schema": 1}))
        self.assertEqual(nightly.load_floors(record), {})

    def test_the_beef_selection_runs_the_streams_603_files(self):
        args = nightly.mutation_args("beef", "0/4")
        self.assertIn("--cargo-arg=--test=beef_stream_603_s3", args)
        self.assertIn("--cargo-arg=--test=beef_stream_603_s1", args)
        self.assertIn("--cargo-arg=--test=beef_stream", args)
        self.assertNotIn("--cargo-arg=--test=beef_stream_603_s3", nightly.mutation_args("merkle", "0/4"))

    def test_a_file_whose_mutants_are_all_unviable_has_no_score(self):
        path = self.fixture(["CaughtMutant", "Unviable"])
        other = "src/transaction/merkle_path_extra.rs"
        def split(data):
            data[1]["file"] = other
        self.change(path, "candidates.json", split)
        self.change(path, "outcomes.json", lambda d: d["outcomes"][2]["scenario"]["Mutant"]
                    .update(file=other))
        self.change(path, "run.json", lambda d: d["files"].append(other))
        result = self.collect()
        row = {r["file"]: r for r in result["files"]}[other]
        self.assertTrue(result["passed"], result["errors"])
        self.assertIsNone(row["passed"])
        self.assertTrue(row["no_viable"])
        # A floor cannot be set on a file with nothing a test can catch.
        result = self.collect(floors={other: {
            "percent": 0, "issue": "https://github.com/Calhooon/bsv-rs/issues/602"}})
        self.assertIn(f"floor has no measured file: {other}", result["errors"])

    def test_corrupt_evidence_still_publishes_a_failure_report(self):
        path = self.fixture(["CaughtMutant"])
        (path / "outcomes.json").write_text("incomplete JSON")
        output = self.root / "score.json"
        record = self.root / "ratchets.json"
        record.write_text("{}")
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            status = nightly.report(argparse.Namespace(
                input=self.root, output=output, expected_shards=None, floors=record))
        self.assertEqual(status, 1)
        self.assertFalse(json.loads(output.read_text())["complete"])
        self.assertTrue(output.with_suffix(".md").is_file())

    def test_files_without_mutants_are_explicit(self):
        path = self.fixture(["CaughtMutant"])
        self.change(path, "run.json", lambda d: d["files"].append("src/wallet/wire/mod.rs"))
        rows = self.collect()["files"]
        self.assertIsNone(rows[1]["passed"])
        self.assertIsNone(rows[1]["score_percent"])

    def test_artifact_omits_host_metadata_and_test_output(self):
        path = self.fixture(["CaughtMutant"])
        raw = path / "mutants.out"
        raw.mkdir()
        (raw / "diff").mkdir()
        (raw / "diff" / "mutant.diff").write_text("- true\n+ false\n")
        (raw / "lock.json").write_text("host metadata")
        (raw / "test.log").write_text("arbitrary test output")
        nightly.package(argparse.Namespace(run=path, output=self.root / "artifact"))
        files = {p.name for p in (self.root / "artifact").rglob("*") if p.is_file()}
        self.assertNotIn("lock.json", files)
        self.assertNotIn("test.log", files)
        self.assertIn("mutant.diff", files)

    def test_existing_output_cannot_reuse_stale_evidence(self):
        with self.assertRaises(FileExistsError):
            nightly.run(argparse.Namespace(output=self.root))


class PinIsTheDispatchCommit(unittest.TestCase):
    """#629: a run dispatched at A whose pin job dequeues after B lands measures A."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        environment = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git_env = dict(os.environ, **environment)
        self.git("init", "-q", "-b", "beta")
        self.dispatched = self.commit("A")
        # The line moves on (B lands) after the dispatch and before the pin job.
        self.landed = self.commit("B")
        self.git("update-ref", "refs/remotes/origin/beta", self.landed)
        self.git("checkout", "-q", "-b", "side", self.dispatched)
        self.off_line = self.commit("C")
        self.output = self.repo / "github_output"
        patcher = patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.output)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def git(self, *args):
        return nightly.subprocess.check_output(["git", *args], cwd=self.repo, text=True,
                                               env=self.git_env).strip()

    def commit(self, message):
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def pin(self, commit):
        return nightly.pin(argparse.Namespace(commit=commit, line="beta", repo=self.repo))

    def test_a_queued_run_pins_the_dispatch_commit_not_the_line_tip_at_dequeue(self):
        self.assertEqual(self.pin(self.dispatched), 0)
        self.assertEqual(self.output.read_text(), f"commit={self.dispatched}\n")
        self.assertNotIn(self.landed, self.output.read_text())

    def test_a_dispatch_naming_a_commit_not_on_the_line_is_refused(self):
        self.assertEqual(self.pin(self.off_line), 1)
        self.assertFalse(self.output.exists())

    def test_a_pin_that_is_not_a_full_sha_is_refused(self):
        for name in ("beta", "origin/beta", "HEAD", self.dispatched[:12]):
            self.assertEqual(self.pin(name), 1, name)
        self.assertFalse(self.output.exists())

    def test_a_shard_records_the_pin_and_refuses_another_checkout(self):
        pinned = "a" * 40
        with patch.object(nightly.subprocess, "check_output", return_value=pinned + "\n"):
            self.assertEqual(nightly.checkout_commit(pinned), pinned)
        with patch.object(nightly.subprocess, "check_output", return_value="b" * 40 + "\n"):
            with self.assertRaises(SystemExit):
                nightly.checkout_commit(pinned)

    def test_the_report_names_the_pin_and_refuses_another_commit(self):
        scores = ScoreTests("test_exact_floor_and_unviable_exclusion")
        scores.setUp()
        self.addCleanup(scores.doCleanups)
        scores.fixture(["CaughtMutant"] * 4, commit=self.landed)
        output = self.repo / "summary.json"
        floors = self.repo / "ratchets.json"
        floors.write_text("{}")
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            status = nightly.report(argparse.Namespace(
                input=scores.root, output=output, expected_shards=None,
                floors=floors, commit=self.dispatched))
        self.assertEqual(status, 1)
        self.assertIn(f"not the pinned commit {self.dispatched}",
                      json.loads(output.read_text())["errors"][-1])
        self.assertIn(f"Source commit: `{self.dispatched}`", output.with_suffix(".md").read_text())


class DerivedFloorsOnlyRise(unittest.TestCase):
    def test_floors_are_the_score_rounded_down_outside_the_gate_and_never_lowered(self):
        import mutants_record as record
        def row(file, caught, viable):
            return {"file": file, "caught": caught, "viable": viable}
        result = {"files": [
            row("src/wallet/wire/reader.rs", 29, 40),     # 72.5 -> 72
            row("src/wallet/wire/mod.rs", 50, 155),       # 32.3, recorded 60: kept
            row("src/wallet/wire/calls.rs", 32, 33),      # at or above 80: no entry
            row("src/wallet/wire/bounds.rs", 45, 47),     # recorded 68, now 95: raised
            row("src/script/script.rs", 1, 10),           # gate path: never an entry
            row("src/wallet/substrates/http_json/answer.rs", 0, 0),  # nothing viable
        ]}
        issue = "https://github.com/Calhooon/bsv-rs/issues/602"
        recorded = {"src/wallet/wire/mod.rs": {"percent": 60, "issue": issue},
                    "src/wallet/wire/bounds.rs": {"percent": 68, "issue": issue}}
        floors = record.derived_floors(result, recorded)
        self.assertEqual({k: v["percent"] for k, v in floors.items()}, {
            "src/wallet/wire/bounds.rs": 95, "src/wallet/wire/mod.rs": 60,
            "src/wallet/wire/reader.rs": 72})
        self.assertEqual(recorded["src/wallet/wire/bounds.rs"]["percent"], 68)


class SkipsNeverMatchInsideTheKeptRoot(unittest.TestCase):
    def test_skips_never_match_inside_the_kept_root(self):
        import re
        from pathlib import Path
        for surface, root in (("script", "script"), ("beef", "transaction"), ("merkle", "transaction"), ("wire", "wallet"), ("substrates", "wallet")):
            kept = [f"{root}::{m}::" for m in re.findall(r"^(?:pub(?:\([^)]*\))? )?mod (\w+)\s*[;{]", Path(f"src/{root}/mod.rs").read_text(), re.MULTILINE) if m != "tests"]
            for skip in nightly.test_skips(surface):
                if skip.startswith(f"{root}::"):
                    continue
                for path in kept:
                    self.assertNotIn(skip, path, f"{surface}: skip {skip!r} matches inside kept {path!r}")


class MerkleSurfaceKeepsItsSiblingTests(unittest.TestCase):
    def test_the_merkle_surface_runs_merkle_path_603_tests(self):
        skips = nightly.test_skips("merkle")
        name = "transaction::merkle_path_603_tests::a_test"
        self.assertFalse(any(skip in name for skip in skips), skips)
        self.assertIn("transaction::beef::", skips)


class ReachRuleFixture(unittest.TestCase):
    """Cut 7: a small tree in a git repository, the reach rule run on its diffs."""

    FILES = {
        "Cargo.toml": "[package]\nname = 'fixture'\n",
        "src/lib.rs": "pub mod script;\npub mod transaction;\npub mod wallet;\npub mod primitives;\n",
        "src/error.rs": "pub enum Error {}\n",
        "src/script/mod.rs": "mod script;\nmod spend;\n",
        "src/script/script.rs": "fn parse() {}\n",
        "src/script/spend/flow.rs": "fn flow() {}\n",
        "src/transaction/mod.rs": "mod beef;\nmod merkle_path;\nmod broadcaster;\n",
        "src/transaction/beef.rs": "fn beef() {}\n",
        "src/transaction/beef_tx.rs": "fn beef_tx() {}\n",
        "src/transaction/merkle_path.rs": "fn path() {}\n",
        "src/transaction/broadcaster.rs": "fn broadcast() {}\n",
        "src/transaction/beef/reference_tests.rs": "const V: &str = \"vectors/beef_only.json\";\n",
        "src/wallet/mod.rs": "mod wire;\nmod substrates;\n",
        "src/wallet/wire/mod.rs": "fn wire() {}\n",
        "src/wallet/substrates/mod.rs": "fn substrates() {}\n",
        "src/primitives/hash.rs": "fn sha256() {}\n",
        "tests/CLAUDE.md": "\n".join([
            "# Tests", "", "## Files", "",
            "| File | Tests | Feature Gate | Description |",
            "|------|------:|-------------|-------------|",
            "| `script_parse_603.rs` | 2 | default | #603: `src/script/script.rs`'s survivors |",
            "| `script_flow_603.rs` | 1 | default | the interpreter's `script::spend` flow |",
            "| `script_row_less.rs` | 1 | default | a witness that names no file |",
            "| `unrelated_tests.rs` | 1 | default | `src/transaction/broadcaster.rs` |",
            "", "## Test Vectors", "", "| File | Contents |", "|---|---|",
            "| `script_parse_603.rs` | a vectors table never read as a test row: `src/wallet/wire/mod.rs` |",
            ""]),
        "tests/script_parse_603.rs": "// reads vectors/script_parse_603.json, recorded by support/script_parse_603.mjs\n",
        "tests/script_flow_603.rs": "#[test] fn flow() {}\n",
        "tests/script_row_less.rs": "#[test] fn row_less() {}\n",
        "tests/transaction_tests.rs": "// vectors/beef_shared.json\n",
        "tests/wallet_tests.rs": "#[path = \"support/wallet_helper.rs\"]\nmod wallet_helper;\n",
        "tests/unrelated_tests.rs": "// vectors/beef_shared.json\n",
        "tests/support/script_parse_603.mjs": "// the recorder\n",
        "tests/support/recorder_only.mjs": "// a recorder no test names\n",
        "tests/support/wallet_helper.rs": "pub fn helper() {}\n",
        "tests/vectors/script_parse_603.json": "[]\n",
        "tests/vectors/beef_shared.json": "[]\n",
        "tests/vectors/beef_only.json": "[]\n",
        ".cargo/mutants.toml": "exclude_re = [\n  '^src/script/script\\.rs:1:1: replace parse',\n]\n",
        "docs/NIGHTLY.md": "# the doc\n",
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for path, body in self.FILES.items():
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_text(body)
        environment = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git_env = dict(os.environ, **environment)
        self.git("init", "-q", "-b", "beta")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "the complete run's commit")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return nightly.subprocess.check_output(["git", *args], cwd=self.repo, text=True,
                                               env=self.git_env).strip()

    def reach(self, *changed, base_mutants=None, head_mutants=None):
        if base_mutants is None:
            base_mutants = self.FILES[".cargo/mutants.toml"]
        return nightly.reach(changed, self.repo, base_mutants, head_mutants)

    def files(self, *changed, **kwargs):
        everything, _, files = self.reach(*changed, **kwargs)
        self.assertIsNone(everything)
        return files

    SCRIPT = {"src/script/mod.rs", "src/script/script.rs", "src/script/spend/flow.rs"}
    TRANSACTION = {"src/transaction/beef.rs", "src/transaction/beef_tx.rs",
                   "src/transaction/merkle_path.rs"}

    def test_the_measured_files_are_the_surfaces_globs(self):
        self.assertEqual(nightly.measured_files(self.repo), {
            **{f: "script" for f in self.SCRIPT}, "src/transaction/beef.rs": "beef",
            "src/transaction/beef_tx.rs": "beef", "src/transaction/merkle_path.rs": "merkle",
            "src/wallet/wire/mod.rs": "wire", "src/wallet/substrates/mod.rs": "substrates"})

    def test_a_changed_measured_file_is_re_measured_alone(self):
        self.assertEqual(self.files("src/transaction/beef.rs"), {"src/transaction/beef.rs"})

    def test_a_changed_source_of_a_module_re_measures_the_modules_measured_files(self):
        self.assertEqual(self.files("src/transaction/broadcaster.rs"), self.TRANSACTION)

    def test_a_changed_test_re_measures_the_files_its_row_names(self):
        self.assertEqual(self.files("tests/script_parse_603.rs"), {"src/script/script.rs"})

    def test_a_row_naming_a_module_re_measures_the_modules_files(self):
        self.assertEqual(self.files("tests/script_flow_603.rs"), self.SCRIPT)

    def test_a_selection_test_whose_row_names_nothing_re_measures_its_surfaces(self):
        self.assertEqual(self.files("tests/script_row_less.rs"), self.SCRIPT)
        # transaction_tests is in the BEEF and the Merkle selections and has no row.
        self.assertEqual(self.files("tests/transaction_tests.rs"), self.TRANSACTION)

    def test_a_test_no_selection_runs_re_measures_nothing(self):
        # Its row names a measured module's source, but it never meets a mutant.
        self.assertEqual(self.files("tests/unrelated_tests.rs"), set())

    def test_a_vector_or_support_file_reaches_through_what_names_it(self):
        self.assertEqual(self.files("tests/vectors/script_parse_603.json"), {"src/script/script.rs"})
        self.assertEqual(self.files("tests/support/script_parse_603.mjs"), {"src/script/script.rs"})
        # Named by a selection test and by one no selection runs.
        self.assertEqual(self.files("tests/vectors/beef_shared.json"), self.TRANSACTION)
        # Named by a test-only source beside the BEEF reader: the file it tests.
        self.assertEqual(self.files("tests/vectors/beef_only.json"), {"src/transaction/beef.rs"})
        # A support module by its `mod` name, through the test that includes it.
        self.assertEqual(self.files("tests/support/wallet_helper.rs"),
                         {"src/wallet/wire/mod.rs", "src/wallet/substrates/mod.rs"})
        self.assertEqual(self.files("tests/support/recorder_only.mjs"), set())

    def test_the_build_and_the_oracle_re_measure_everything(self):
        for path in ("Cargo.toml", "Cargo.lock", "build.rs", "src/lib.rs", "src/error.rs",
                     ".github/workflows/nightly.yml", ".github/scripts/nightly_mutants.py",
                     ".github/scripts/test-runner-memory-ceiling.sh", ".cargo/config.toml"):
            everything, reasons, files = self.reach(path, "docs/NIGHTLY.md")
            self.assertEqual(everything, path)
            self.assertEqual(reasons[path]["files"], "everything")
            self.assertEqual(len(files), 8)

    def test_documentation_re_measures_nothing(self):
        self.assertEqual(self.files("docs/NIGHTLY.md", "CHANGELOG.md", "src/script/CLAUDE.md",
                                    "tests/CLAUDE.md", "fuzz/fuzz_targets/x.rs",
                                    ".github/scripts/test_nightly_mutants.py"), set())

    def test_an_exclusion_re_measures_the_file_it_names_and_another_setting_everything(self):
        head = self.FILES[".cargo/mutants.toml"].replace(
            "]", "  '^src/transaction/beef\\.rs:9:9: replace < with <=',\n]")
        self.assertEqual(self.files(".cargo/mutants.toml", head_mutants=head),
                         {"src/transaction/beef.rs"})
        everything, _, _ = self.reach(".cargo/mutants.toml",
                                      head_mutants=head + "timeout_multiplier = 2\n")
        self.assertEqual(everything, ".cargo/mutants.toml")
        everything, _, _ = self.reach(".cargo/mutants.toml",
                                      head_mutants=head.replace("^src", "src", 1))
        self.assertEqual(everything, ".cargo/mutants.toml")

    def plan(self, mode="incremental", record=True):
        commit = self.git("rev-parse", "HEAD")
        base_dir = self.repo / ("base" if record else "no-record")
        if record:
            nightly.write_json(base_dir / "record.json", {
                "schema_version": 1, "commit": self.base,
                "complete_run": {"run_id": "100", "commit": self.base},
                "runs": [{"run_id": "100", "commit": self.base, "mode": "complete"}],
                "files": {f: {"surface": s, "generated": 400 if s == "script" else 10}
                          for f, s in nightly.measured_files(self.repo).items()}})
        output = self.repo / "plan.json"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": ""}):
            nightly.plan(argparse.Namespace(commit=commit, mode=mode, base_record=base_dir,
                                            repo=self.repo, output=output))
        return json.loads(output.read_text())

    def land(self, path, body="changed\n"):
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(body)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", f"change {path}")

    def test_the_plan_diffs_from_the_complete_run_and_sizes_the_night(self):
        self.land("tests/script_parse_603.rs")
        self.land("src/transaction/beef.rs")
        planned = self.plan()
        self.assertEqual(planned["mode"], "incremental")
        self.assertEqual(planned["base"]["commit"], self.base)
        self.assertEqual(planned["files"], {"script": ["src/script/script.rs"],
                                            "beef": ["src/transaction/beef.rs"]})
        # 400 script mutants at 0.25 minutes each: three shards of 45 minutes.
        self.assertEqual([(m["surface"], m["shard"]) for m in planned["matrix"]], [
            ("script", "0/3"), ("script", "1/3"), ("script", "2/3"), ("beef", "0/1")])
        self.assertEqual(planned["max_parallel"], nightly.NIGHT_PARALLEL)
        self.assertEqual(len(planned["carried"]), 6)
        self.assertEqual(planned["lockfile"], "carry")

    def test_a_documentation_night_plans_no_shard(self):
        self.land("docs/NIGHTLY.md")
        planned = self.plan()
        self.assertEqual((planned["mode"], planned["shards"], planned["matrix"]),
                         ("incremental", 0, []))
        self.assertEqual(len(planned["carried"]), 8)

    def test_a_reach_of_everything_or_no_record_plans_the_complete_run(self):
        self.land("Cargo.toml", "[package]\nname = 'bumped'\n")
        planned = self.plan()
        self.assertEqual(planned["mode"], "complete")
        self.assertIn("Cargo.toml changed", planned["why_complete"])
        self.assertEqual(planned["lockfile"], "generate")
        self.assertEqual(sum(1 for m in planned["matrix"]), 11 + 3 + 1 + 2 + 3)
        self.assertEqual(planned["max_parallel"], nightly.HEAVY_MAX_PARALLEL)
        self.assertEqual(self.plan(record=False)["why_complete"],
                         "no record of a complete run on the line to carry from")
        self.assertEqual(self.plan(mode="complete")["mode"], "complete")

    def test_the_complete_run_is_twenty_shards_in_two_waves_under_the_cap(self):
        self.assertEqual(sum(nightly.COMPLETE_SHARDS.values()), nightly.SLOT_LIMIT)
        self.assertEqual(set(nightly.COMPLETE_SHARDS), set(nightly.SURFACES))
        # The fleet's runner cap (2026-11-03): six of the twenty stay for the fleet.
        self.assertEqual(nightly.HEAVY_MAX_PARALLEL, 14)
        self.assertLessEqual(nightly.NIGHT_PARALLEL, nightly.HEAVY_MAX_PARALLEL)

    # PR #666's fold: the five holes the reads found, each on the fixture tree.
    def put(self, path, body):
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(body)

    def test_fold_1_a_deleted_selection_test_re_measures_what_its_base_row_named(self):
        self.git("rm", "-q", "tests/script_parse_603.rs", "tests/script_row_less.rs",
                 "tests/unrelated_tests.rs")
        self.git("commit", "-q", "-m", "three tests deleted")
        planned = self.plan()
        # script_parse_603's base row names script.rs; script_row_less's names
        # nothing (its surface); unrelated_tests is in no selection (nothing).
        self.assertEqual(planned["files"], {"script": sorted(self.SCRIPT)})
        self.assertIn("removed", planned["reach"]["tests/script_parse_603.rs"]["why"])
        self.assertEqual(planned["reach"]["tests/script_parse_603.rs"]["files"],
                         ["src/script/script.rs"])
        self.assertEqual(planned["reach"]["tests/unrelated_tests.rs"]["files"], [])

    def test_fold_2_a_fixture_read_through_a_built_path_reaches_through_its_directory(self):
        self.put("tests/fixtures/wire/createAction.json", "{}\n")
        self.put("tests/vectors/read_by_none.json", "[]\n")
        self.put("tests/support/fixtures/mod.rs", "mod binary;\n")
        self.put("tests/support/fixtures/binary.rs", "// a builder\n")
        # The words `fixtures` and `binary` in the crate root name no module.
        self.put("src/lib.rs", self.FILES["src/lib.rs"] + "// fixtures, binary, vectors/\n")
        self.assertEqual(self.files("tests/support/fixtures/binary.rs"), set())
        self.put("tests/wallet_tests.rs", self.FILES["tests/wallet_tests.rs"]
                 + '#[path = "support/fixtures/mod.rs"]\nmod fixtures;\n'
                 + 'fn load(call: &str) -> String {\n'
                 + '    format!("{}/tests/fixtures/wire/{call}.json", env!("CARGO_MANIFEST_DIR"))\n}\n')
        wallet = {"src/wallet/wire/mod.rs", "src/wallet/substrates/mod.rs"}
        self.assertEqual(self.files("tests/fixtures/wire/createAction.json"), wallet)
        self.assertEqual(self.files("tests/support/fixtures/binary.rs"), wallet)
        self.assertEqual(self.files("tests/support/fixtures/mod.rs"), wallet)
        # One directory deep (`vectors/`) is every vector's: a name is needed.
        self.assertEqual(self.files("tests/vectors/read_by_none.json"), set())

    def test_fold_3_a_callee_modules_change_re_measures_its_callers_one_level(self):
        self.put("src/script/caller.rs", "use crate::primitives::hash::sha256;\n")
        self.put("src/wallet/wire/group.rs", "use crate::{\n    primitives::hash,\n    Error,\n};\n")
        self.put("src/transaction/beef_tx.rs", "// primitives, not by a crate path\n")
        callers = {"src/script/caller.rs", "src/wallet/wire/group.rs"}
        self.assertEqual(self.files("src/primitives/hash.rs"), callers)
        _, reasons, _ = self.reach("src/primitives/hash.rs")
        self.assertIn("the 2 whose crate::primitives paths call it",
                      reasons["src/primitives/hash.rs"]["why"])
        with patch.object(nightly, "CALLEE_RULE", False):
            self.assertEqual(self.files("src/primitives/hash.rs"), set())

    def test_fold_4_a_row_naming_a_test_only_file_reaches_the_file_it_tests(self):
        self.put("src/script/spend/flow.rs",
                 'fn flow() {}\n#[cfg(test)]\n#[path = "flow_room_tests.rs"]\nmod tests;\n')
        self.put("src/script/spend/flow_room_tests.rs", "#![cfg(test)]\nuse super::*;\n")
        self.put("tests/script_room_374.rs", "#[test] fn room() {}\n")
        self.put("tests/CLAUDE.md", self.FILES["tests/CLAUDE.md"].replace(
            "| `unrelated_tests.rs`",
            "| `script_room_374.rs` | 1 | default | its vectors in "
            "`src/script/spend/flow_room_tests.rs` |\n| `unrelated_tests.rs`"))
        self.assertEqual(self.files("tests/script_room_374.rs"), {"src/script/spend/flow.rs"})

    def test_fold_5_a_test_only_module_is_a_test_of_its_surface_never_measured(self):
        self.land("src/script/mod.rs", "mod script;\nmod spend;\n#[cfg(test)]\nmod length_tests;\n")
        self.land("src/script/length_tests.rs", "//! the length, by the reference\n#![cfg(test)]\n")
        planned = self.plan()
        self.assertNotIn("src/script/length_tests.rs", planned["measured"])
        self.assertNotIn("src/script/length_tests.rs", planned["carried"])
        # The files it tests: its directory's measured files, its parent's mod.rs among them.
        self.assertEqual(planned["files"], {"script": ["src/script/mod.rs", "src/script/script.rs"]})
        self.assertEqual(planned["reach"]["src/script/length_tests.rs"]["files"],
                         ["src/script/mod.rs", "src/script/script.rs"])
        self.assertTrue(nightly.is_test_only("src/script/length_tests.rs", self.repo))
        self.assertTrue(nightly.is_test_only("src/script/spend/tests.rs", self.repo))
        self.assertFalse(nightly.is_test_only("src/script/script.rs", self.repo))
        # A complete run's glob still lists it, with no mutant: no row, no figure.
        def row(file, generated):
            return {"file": file, "generated": generated, "caught": generated, "missed": 0,
                    "timeout": 0, "unviable": 0, "viable": generated,
                    "score_percent": 100.0 if generated else None, "no_viable": False}
        night = {"files": [row(f, 0 if f.endswith("_tests.rs") else 4)
                           for f in [*planned["measured"], "src/script/length_tests.rs"]]}
        rows, _, errors, record = nightly.merge(
            night, {"commit": "c" * 40, "measured": planned["measured"], "mode": "complete"},
            None, {}, "200")
        self.assertEqual(errors, [])
        self.assertNotIn("src/script/length_tests.rs", record["files"])
        self.assertEqual(len(rows), len(planned["measured"]))

    # PR #666's second fold: the callee rule's letter and its count per night.
    def test_fold2_a_changed_measured_file_re_measures_the_measured_files_naming_its_module(self):
        self.put("src/wallet/substrates/mod.rs", "use crate::transaction::Beef;\n")
        self.put("src/wallet/wire/mod.rs", "use crate::script::Script;\n")
        self.assertEqual(self.files("src/transaction/beef.rs"),
                         {"src/transaction/beef.rs", "src/wallet/substrates/mod.rs"})
        _, reasons, _ = self.reach("src/transaction/beef.rs")
        self.assertIn("the 1 whose crate::transaction paths call it",
                      reasons["src/transaction/beef.rs"]["why"])
        self.assertEqual(self.files("src/script/spend/flow.rs"),
                         {"src/script/spend/flow.rs", "src/wallet/wire/mod.rs"})
        # A test-only source compiles into no caller: the files it tests alone.
        self.put("src/transaction/beef/x_tests.rs", "#![cfg(test)]\n")
        self.assertEqual(self.files("src/transaction/beef/x_tests.rs"), {"src/transaction/beef.rs"})
        with patch.object(nightly, "CALLEE_RULE", False):
            self.assertEqual(self.files("src/transaction/beef.rs"), {"src/transaction/beef.rs"})

    def test_fold2_the_plan_counts_the_files_the_callee_rule_added_tonight(self):
        self.land("src/wallet/substrates/mod.rs", "use crate::transaction::Beef;\n")
        self.base = self.git("rev-parse", "HEAD")
        # A night where the rule adds a file: a BEEF landing reaches its caller.
        self.land("src/transaction/beef.rs", "fn beef() { /* changed */ }\n")
        planned = self.plan()
        self.assertEqual((planned["callee_rule"], planned["callee_added"]),
                         (True, ["src/wallet/substrates/mod.rs"]))
        # A file another path reaches is not the rule's addition.
        self.land("src/wallet/substrates/mod.rs", "use crate::transaction::Beef; // and changed\n")
        self.assertEqual(self.plan()["callee_added"], [])
        # A night where the rule adds none.
        self.base = self.git("rev-parse", "HEAD")
        self.land("tests/script_parse_603.rs")
        planned = self.plan()
        self.assertEqual((planned["mode"], planned["callee_added"]), ("incremental", []))
        # A complete run: every file is measured, none of them the rule's addition.
        self.assertEqual(self.plan(mode="complete")["callee_added"], [])
        with patch.object(nightly, "CALLEE_RULE", False):
            self.assertEqual(self.plan()["callee_rule"], False)


class RecordCarriesTheFigures(unittest.TestCase):
    """Cut 7: the night's rows over the record, each figure's provenance named."""

    ISSUE = "https://github.com/Calhooon/bsv-rs/issues/602"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.measured = {"src/transaction/beef.rs": "beef", "src/script/script.rs": "script",
                         "src/wallet/wire/reader.rs": "wire"}
        self.base = {"schema_version": 1, "commit": "c" * 40,
                     "complete_run": {"run_id": "100", "commit": "c" * 40,
                                      "lockfile_sha256": "d" * 64},
                     "runs": [{"run_id": "100", "commit": "c" * 40, "mode": "complete", "files": 3}],
                     "files": {
                         "src/transaction/beef.rs": self.row(8, 2, "100"),     # 80%, at its floor
                         "src/script/script.rs": self.row(6, 4, "100"),      # 60%, below 80
                         "src/wallet/wire/reader.rs": self.row(9, 1, "100"),
                         "src/wallet/wire/gone.rs": self.row(9, 1, "100"),   # no longer measured
                     }}

    def row(self, caught, missed, run_id, commit="c" * 40):
        return {"surface": "x", "generated": caught + missed, "caught": caught, "missed": missed,
                "timeout": 0, "unviable": 0, "viable": caught + missed,
                "score_percent": 100 * caught / (caught + missed), "no_viable": False,
                "provenance": "night", "run_id": run_id, "commit": commit}

    def night(self, *outcomes):
        scores = ScoreTests("test_exact_floor_and_unviable_exclusion")
        scores.setUp()
        self.addCleanup(scores.doCleanups)
        scores.file = "src/transaction/beef.rs"
        scores.fixture(list(outcomes), surface="beef", shard="0/1", commit="e" * 40)
        return scores.root

    def plan(self, matrix, files):
        return {"mode": "incremental", "commit": "e" * 40, "measured": self.measured,
                "files": files, "matrix": matrix}

    def test_the_night_merges_onto_the_complete_run(self):
        night = nightly.collect(self.night(*["CaughtMutant"] * 9, "MissedMutant"), None, {},
                                planned={("beef", "0/1")}, floor_files=False)
        plan = self.plan([{"surface": "beef", "shard": "0/1"}], {"beef": ["src/transaction/beef.rs"]})
        rows, findings, errors, record = nightly.merge(night, plan, self.base, {}, "200")
        self.assertEqual(errors, [])
        by_file = {row["file"]: row for row in rows}
        self.assertEqual(set(by_file), set(self.measured))
        self.assertEqual((by_file["src/transaction/beef.rs"]["provenance"],
                          by_file["src/transaction/beef.rs"]["run_id"],
                          by_file["src/transaction/beef.rs"]["score_percent"]), ("night", "200", 90))
        self.assertEqual((by_file["src/wallet/wire/reader.rs"]["provenance"],
                          by_file["src/wallet/wire/reader.rs"]["run_id"],
                          by_file["src/wallet/wire/reader.rs"]["commit"]), ("carried", "100", "c" * 40))
        self.assertEqual(record["complete_run"], self.base["complete_run"])
        self.assertEqual([r["run_id"] for r in record["runs"]], ["100", "200"])
        self.assertEqual(record["files"]["src/transaction/beef.rs"]["commit"], "e" * 40)
        self.assertNotIn("src/wallet/wire/gone.rs", record["files"])
        # The next night carries tonight's figure with tonight's run named.
        later = nightly.merge({"files": []}, dict(plan, commit="f" * 40), record, {}, "300")[0]
        row = {r["file"]: r for r in later}["src/transaction/beef.rs"]
        self.assertEqual((row["provenance"], row["run_id"], row["commit"]), ("carried", "200", "e" * 40))

    def test_a_carried_figure_below_its_floor_is_a_finding_not_a_failure(self):
        plan = self.plan([], {})
        rows, findings, errors, _ = nightly.merge({"files": []}, plan, self.base, {}, "200")
        self.assertEqual(errors, [])
        self.assertEqual(len(findings), 1)
        self.assertIn("src/script/script.rs: carried 60.00% below its 80% floor, measured by "
                      f"run 100 at {'c' * 40}", findings[0])
        script = {r["file"]: r for r in rows}["src/script/script.rs"]
        self.assertIs(script["passed"], False)
        # Below its floor tonight, the same file fails the night.
        night = {"files": [dict(script, provenance=None, passed=False)], "errors": ["x: below"]}
        self.assertEqual(nightly.merge(night, plan, self.base, {}, "200")[1], [])

    def test_a_carried_floor_is_judged_by_the_record(self):
        floors = {"src/wallet/wire/reader.rs": {"percent": 95, "issue": self.ISSUE}}
        _, findings, errors, _ = nightly.merge({"files": []}, self.plan([], {}), self.base,
                                               floors, "200")
        self.assertEqual(errors, [])
        self.assertTrue(any(f.startswith("src/wallet/wire/reader.rs: carried 90.00% below its 95%")
                            for f in findings))
        floors = {"src/wallet/wire/absent.rs": {"percent": 50, "issue": self.ISSUE}}
        errors = nightly.merge({"files": []}, self.plan([], {}), self.base, floors, "200")[2]
        self.assertEqual(errors, ["floor has no measured file: src/wallet/wire/absent.rs"])

    def report(self, plan, results):
        (self.root / "base").mkdir(exist_ok=True)
        nightly.write_json(self.root / "base" / "record.json", self.base)
        nightly.write_json(self.root / "plan.json", plan)
        (self.root / "Cargo.lock").write_text("# the lock\n")
        (self.root / "ratchets.json").write_text("{}")
        (self.root / "record").mkdir(exist_ok=True)
        output = self.root / "summary.json"
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            status = nightly.report(argparse.Namespace(
                input=results, output=output, expected_shards=None,
                floors=self.root / "ratchets.json", commit="e" * 40, plan=self.root / "plan.json",
                base_record=self.root / "base", record_output=self.root / "record" / "record.json",
                lockfile=self.root / "Cargo.lock", run_id="200"))
        return status, json.loads(output.read_text()), output.with_suffix(".md").read_text()

    def test_the_scoreboard_names_each_figures_provenance(self):
        status, result, markdown = self.report(
            self.plan([{"surface": "beef", "shard": "0/1"}], {"beef": ["src/transaction/beef.rs"]}),
            self.night(*["CaughtMutant"] * 9, "MissedMutant"))
        self.assertEqual(status, 0, result["errors"])
        self.assertIn("| Result | Figure |", markdown)
        self.assertIn("| `src/transaction/beef.rs` | 9 | 1 | 0 | 0 | 90.00% | 80% | PASS | night |",
                      markdown)
        self.assertIn(f"| FAIL | carried: run 100 at `{'c' * 8}` |", markdown)
        self.assertIn(f"the complete run 100 at `{'c' * 40}`", markdown)
        self.assertIn("Carried below their floors", markdown)
        record = json.loads((self.root / "record" / "record.json").read_text())
        self.assertEqual(record["lockfile_sha256"], nightly.lockfile_digest(self.root / "Cargo.lock"))
        self.assertTrue((self.root / "record" / "Cargo.lock").is_file())

    def test_fold2_the_record_and_the_scoreboard_name_the_callee_rules_files(self):
        plan = dict(self.plan([{"surface": "beef", "shard": "0/1"}],
                              {"beef": ["src/transaction/beef.rs"]}),
                    callee_rule=True, callee_added=["src/wallet/wire/reader.rs"])
        status, result, markdown = self.report(plan, self.night(*["CaughtMutant"] * 9, "MissedMutant"))
        self.assertEqual(status, 0, result["errors"])
        run = json.loads((self.root / "record" / "record.json").read_text())["runs"][-1]
        self.assertEqual((run["run_id"], run["commit"], run["callee_added"]), ("200", "e" * 40, 1))
        self.assertIn("The callee rule added 1 file tonight (incremental): "
                      "`src/wallet/wire/reader.rs`.", markdown)
        # A night where it adds none, and a complete run, print 0 with the mode named.
        empty = self.root / "no-shards"
        empty.mkdir()
        _, _, markdown = self.report(dict(self.plan([], {}), callee_rule=True, callee_added=[]),
                                     empty)
        self.assertIn("The callee rule added 0 files tonight (incremental).", markdown)
        self.assertEqual(json.loads((self.root / "record" / "record.json").read_text())
                         ["runs"][-1]["callee_added"], 0)
        night = nightly.merge({"files": []}, {"mode": "complete", "commit": "e" * 40,
                                              "measured": {}, "callee_added": []}, None, {}, "300")[3]
        self.assertEqual(night["runs"], [{"run_id": "300", "commit": "e" * 40, "mode": "complete",
                                          "files": 0, "callee_added": 0}])
        self.assertIn("The callee rule added 0 files tonight (complete: every file measured).",
                      nightly.callee_line({"mode": "complete", "callee_rule": True,
                                           "callee_added": []}))
        self.assertIn("The callee rule is off (`CALLEE_RULE`): it added 0 files tonight (incremental).",
                      nightly.callee_line({"mode": "incremental", "callee_rule": False,
                                           "callee_added": []}))

    def test_an_empty_plan_carries_every_figure(self):
        empty = self.root / "no-shards"
        empty.mkdir()
        status, result, markdown = self.report(self.plan([], {}), empty)
        self.assertEqual(status, 0, result["errors"])
        self.assertEqual({r["provenance"] for r in result["files"]}, {"carried"})
        self.assertEqual(len(json.loads((self.root / "record" / "record.json").read_text())
                             ["runs"]), 2)

    def test_a_missing_shard_fails_the_night_and_writes_no_record(self):
        status, result, _ = self.report(
            self.plan([{"surface": "beef", "shard": "0/2"}, {"surface": "beef", "shard": "1/2"}],
                      {"beef": ["src/transaction/beef.rs"]}),
            self.night("CaughtMutant"))
        self.assertEqual(status, 1)
        self.assertFalse(result["complete"])
        self.assertFalse((self.root / "record" / "record.json").exists())

    def test_an_incremental_shard_with_no_mutant_is_complete(self):
        root = self.night("CaughtMutant")
        shard = root / "beef-1-2"
        shard.mkdir()
        nightly.write_json(shard / "run.json", {
            "surface": "beef", "shard": "1/2", "commit": "e" * 40, "exit_code": 0, "empty": True,
            "files": ["src/transaction/beef.rs"], "command": ["cargo", "mutants", "--shard", "1/2"]})
        nightly.write_json(shard / "candidates.json", [])
        self.change_shard(root, "0/2")
        result = nightly.collect(root, None, {}, planned={("beef", "0/2"), ("beef", "1/2")},
                                 floor_files=False)
        self.assertTrue(result["passed"], result["errors"])
        # Without the runner's mark, a shard with no candidates is broken evidence.
        self.change_json(shard / "run.json", lambda d: d.pop("empty"))
        self.assertFalse(nightly.collect(root, None, {}, planned={("beef", "0/2"), ("beef", "1/2")},
                                         floor_files=False)["complete"])

    def change_json(self, path, edit):
        data = json.loads(path.read_text())
        edit(data)
        nightly.write_json(path, data)

    def change_shard(self, root, shard):
        for run in root.glob("beef-0-1/run.json"):
            self.change_json(run, lambda d: d.update(shard=shard, command=["cargo", "mutants",
                                                                           "--shard", shard]))

    def test_the_newest_record_of_the_line_on_the_pins_ancestry_is_carried(self):
        def artifact(id, created, branch="beta", expired=False):
            return {"id": id, "name": nightly.RECORD_ARTIFACT, "expired": expired,
                    "created_at": created, "workflow_run": {"id": id * 10, "head_branch": branch}}
        bodies = {1: "a", 2: "b", 3: "c", 4: "d", 5: "e"}
        listing = [artifact(1, "2026-11-01"), artifact(2, "2026-11-03"),
                   artifact(3, "2026-11-04", branch="main"), artifact(4, "2026-11-05", expired=True),
                   artifact(5, "2026-11-02")]
        def fetch(a):
            commit = bodies[a["id"]] * 40
            return {"record.json": json.dumps({"commit": commit,
                                               "complete_run": {"commit": "a" * 40}}).encode()}
        # Run 2's commit is not on the pin's ancestry (it measured a later commit).
        ancestors = {"a" * 40, "e" * 40}
        found, files = nightly.newest_record(listing, "beta", "f" * 40, fetch,
                                             lambda old, new: old in ancestors)
        self.assertEqual(found["id"], 5)
        self.assertEqual(nightly.newest_record([], "beta", "f" * 40, fetch, lambda o, n: True),
                         (None, None))


if __name__ == "__main__":
    unittest.main()
