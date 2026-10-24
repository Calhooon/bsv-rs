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

    def test_corrupt_evidence_still_publishes_a_failure_report(self):
        path = self.fixture(["CaughtMutant"])
        (path / "outcomes.json").write_text("incomplete JSON")
        output = self.root / "score.json"
        with patch.dict(os.environ, {"MUTATION_FLOORS": "{}", "GITHUB_STEP_SUMMARY": ""}):
            status = nightly.report(argparse.Namespace(
                input=self.root, output=output, expected_shards=None))
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


if __name__ == "__main__":
    unittest.main()


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

