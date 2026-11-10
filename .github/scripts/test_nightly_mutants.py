"""Exercise score math and rejection of incomplete or inconsistent evidence."""

import argparse
from datetime import datetime, timezone

from collections import Counter
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nightly_mutants as nightly

# #791: a plan's hour, inside this crate's window and outside every window.
INSIDE = datetime(2026, 11, 5, 7, 0, tzinfo=timezone.utc)
OUTSIDE = datetime(2026, 11, 5, 12, 30, tzinfo=timezone.utc)


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
        # #685: the BEEF and the Merkle readers are one module's, so one set.
        for surface in ("beef", "merkle"):
            args = nightly.mutation_args(surface, "0/4")
            self.assertIn("--cargo-arg=--test=beef_stream_603_s3", args)
            self.assertIn("--cargo-arg=--test=beef_stream_603_s1", args)
            self.assertIn("--cargo-arg=--test=beef_stream", args)

    def test_603_the_wire_surface_compiles_the_tracing_gated_diagnostics_and_runs_its_sink(self):
        # #603: `src/wallet/wire/diagnostics.rs` is `mod diagnostics;` under
        # `#[cfg(feature = "tracing")]` and `tracing` is outside `full`, so under
        # `full,http` every mutant of it rewrote unbuilt text and read `missed`; its
        # kills live in `tests/wire_tracing_sink.rs`, a binary run apart (`APART`).
        def word(args):
            return args[args.index("--features") + 1]
        diagnostics = ["src/wallet/wire/diagnostics.rs"]
        for args in (nightly.mutation_args("wire", "0/1", diagnostics),
                     nightly.mutation_args("wire", "0/3"),
                     nightly.mutation_args("wire", "0/1", diagnostics, [])):
            self.assertEqual(word(args).split(","), ["full", "http", "tracing"])
            self.assertEqual(args.count("--cargo-arg=--test=wire_tracing_sink"), 1)
        for surface in ("substrates", "script", "beef", "merkle"):
            args = nightly.mutation_args(surface, "0/4")
            self.assertEqual(word(args), "full,http", surface)
            self.assertNotIn("--cargo-arg=--test=wire_tracing_sink", args, surface)
        # The selection keys by module and the wire and substrates surfaces are both
        # `wallet`'s: the sink rides on the surface, never in a file's set.
        import affected_tests
        self.assertIn("wire_tracing_sink", affected_tests.APART)
        chosen = nightly.selection(nightly.measured_files())
        self.assertFalse([f for f, t in chosen.items() if "wire_tracing_sink" in t])

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


class TimeoutReRun781(unittest.TestCase):
    """#781 (the keeper's word of 2026-11-04 15:2xZ): a mutant that times out is re-run
    once alone; a second timeout is a row outside the denominator, never a survivor nor a
    kill. The witness: a file floored at 100 with one injected timeout."""

    FILE = "src/wallet/wire/encoding.rs"
    NAME = "src/wallet/wire/encoding.rs:9:5: replace f -> usize with 1"
    # Literals, not the module's names, so the evidence reads on a tree before #781.
    MARK, METHOD = 1, "re-run once alone (#781)"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "shards"
        self.floors = Path(self.temp.name) / "ratchets.json"
        nightly.write_json(self.floors, {"mutation_floors": {self.FILE: {"percent": 100}}})

    @staticmethod
    def mutant(name, file=FILE):
        line = int(name.split(":")[1])
        return {"file": file, "name": name, "span": {"start": {"line": line, "column": 5}},
                "genre": "FnValue", "replacement": "1", "function": {"function_name": "f"}}

    @staticmethod
    def outcomes(entries, seconds=60.0):
        def phases(took):
            return [{"phase": "Build", "duration": 10.0}, {"phase": "Test", "duration": took}]
        counts = Counter(nightly.OUTCOMES[summary] for _, summary in entries)
        return {"cargo_mutants_version": "27.1.0", "start_time": "2026-11-04T01:00:00Z",
                "end_time": "2026-11-04T02:00:00Z", "total_mutants": len(entries),
                **{kind: counts[kind] for kind in nightly.OUTCOMES.values()},
                "outcomes": [{"scenario": "Baseline", "summary": "Success",
                              "phase_results": phases(30.0)}] + [
                    {"scenario": {"Mutant": mutant}, "summary": summary,
                     "log_path": f"log/{i}.log", "phase_results": phases(seconds)}
                    for i, (mutant, summary) in enumerate(entries)]}

    def shard(self, rerun="Timeout", method=True, label="wire-0-1", shard="0/1"):
        """Three kills and one timeout in the pass; `rerun` the lone re-run's outcome
        (None: the method's mark without its re-run)."""
        path = self.root / label
        path.mkdir(parents=True)
        kills = [self.mutant(f"{self.FILE}:{i}:5: replace g with {i}") for i in (1, 2, 3)]
        hung = self.mutant(self.NAME)
        nightly.write_json(path / "candidates.json", kills + [hung])
        nightly.write_json(path / "outcomes.json", self.outcomes(
            [(m, "CaughtMutant") for m in kills] + [(hung, "Timeout")], seconds=360.0))
        metadata = {"surface": "wire", "shard": shard, "commit": "c" * 40, "exit_code": 3,
                    "files": [self.FILE], "command": ["cargo", "mutants", "--shard", shard]}
        if method:
            metadata["timeout_rerun"] = self.MARK
            metadata["reruns"] = []
        if method and rerun is not None:
            again = path / "rerun" / "0"
            again.mkdir(parents=True)
            nightly.write_json(again / "outcomes.json",
                               self.outcomes([(hung, rerun)], seconds=380.0))
            kind = nightly.OUTCOMES[rerun]
            metadata["reruns"] = [{
                "index": 0, "file": self.FILE, "mutant": self.NAME,
                "method": self.METHOD, "exit_code": 3 if kind == "timeout" else 0,
                "command": [], "pass": {"outcome": "timeout", "seconds": 370.0,
                                        "log": "log/3.log", "test_timeout": 360.0,
                                        "named": None},
                "rerun": {"outcome": kind, "seconds": 390.0, "log": "log/0.log",
                          "test_timeout": 380.0,
                          "named": {"binary": "wire_codec-1a2b",
                                    "tests": ["a_frame_that_never_ends"]}}}]
        nightly.write_json(path / "run.json", metadata)
        return path

    def report(self):
        output = Path(self.temp.name) / "score.json"
        with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}), \
                patch("sys.stdout", new=io.StringIO()):
            status = nightly.report(argparse.Namespace(
                input=self.root, output=output, expected_shards=None, floors=self.floors))
        return status, json.loads(output.read_text()), output.with_suffix(".md").read_text()

    def test_781_a_floor_at_100_with_a_second_timeout_passes_and_writes_the_row(self):
        self.shard("Timeout")
        status, result, markdown = self.report()
        row = result["files"][0]
        self.assertEqual(status, 0, result["errors"])
        self.assertTrue(result["passed"])
        self.assertEqual((row["caught"], row["missed"], row["timeout"], row["viable"]),
                         (3, 0, 1, 3))
        self.assertEqual((row["score_percent"], row["passed"]), (100, True))
        self.assertEqual(result["timeouts"], [{
            "file": self.FILE, "mutant": self.NAME, "shard": "wire 0/1",
            "method": self.METHOD, "pass_seconds": 370.0, "rerun_seconds": 390.0,
            "pass_limit": 360.0, "rerun_limit": 380.0,
            "binary": "wire_codec-1a2b", "tests": ["a_frame_that_never_ends"]}])
        self.assertIn("Score = caught / (caught + missed)", markdown)
        self.assertIn(f"| `{self.FILE}` | `{self.NAME}` | wire 0/1 | 370.0, 360.0 "
                      f"| 390.0, 380.0 |", markdown)

    def test_781_a_timeout_caught_alone_reads_caught(self):
        self.shard("CaughtMutant")
        status, result, _ = self.report()
        row = result["files"][0]
        self.assertEqual(status, 0, result["errors"])
        self.assertEqual((row["caught"], row["timeout"], row["viable"]), (4, 0, 4))
        self.assertEqual(result["timeouts"], [])

    def test_781_a_timeout_missed_alone_reads_missed(self):
        self.shard("MissedMutant")
        status, result, _ = self.report()
        row = result["files"][0]
        self.assertEqual(status, 1)
        self.assertEqual((row["caught"], row["missed"], row["timeout"], row["viable"]),
                         (3, 1, 0, 4))
        self.assertEqual((row["score_percent"], row["passed"]), (75, False))

    def test_781_a_timeout_without_its_lone_re_run_fails_closed(self):
        self.shard(None)
        status, result, _ = self.report()
        self.assertEqual(status, 1)
        self.assertFalse(result["complete"])
        self.assertIn(f"('wire', '0/1'): timeout without its lone re-run: {self.NAME}",
                      result["errors"])

    def test_781_evidence_before_the_method_keeps_the_old_rule(self):
        self.shard(method=False)
        status, result, markdown = self.report()
        row = result["files"][0]
        self.assertEqual(status, 1)
        self.assertTrue(result["complete"])
        self.assertEqual((row["timeout"], row["viable"], row["score_percent"]), (1, 4, 75))
        self.assertIn("Score = caught / (caught + missed + timeout)", markdown)

    def test_781_shards_under_two_rules_fail_closed(self):
        self.shard("Timeout")
        self.shard(method=False, label="wire-1-2", shard="1/2")
        result = nightly.collect(self.root, None, {})
        self.assertIn("shards judged under different timeout rules (#781): "
                      "some ran the lone re-run, some did not", result["errors"])

    def test_781_a_re_run_that_ran_more_than_its_mutant_fails_closed(self):
        path = self.shard("Timeout")
        data = json.loads((path / "rerun" / "0" / "outcomes.json").read_text())
        extra = self.mutant(f"{self.FILE}:20:5: delete field x")
        data["outcomes"].append({"scenario": {"Mutant": extra}, "summary": "CaughtMutant"})
        nightly.write_json(path / "rerun" / "0" / "outcomes.json", data)
        result = nightly.collect(self.root, None, {})
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} did not run it alone",
                      result["errors"])

    def test_781_the_lone_command_drops_the_sharding_and_names_the_mutant_and_its_line(self):
        command = ["cargo", "mutants", "--no-shuffle", "--sharding", "round-robin",
                   "--shard", "3/8", "--file", "src/script/**/*.rs", "--cargo-arg=--lib"]
        name = "src/script/script.rs:708:13: replace += with *= in Snapshot<'a>::read"
        lone = nightly.lone_command(command, {"name": name}, Path("/r/line.diff"))
        self.assertEqual(lone, [
            "cargo", "mutants", "--no-shuffle", "--file", "src/script/**/*.rs",
            "--cargo-arg=--lib", "--re",
            r"^src/script/script\.rs:708:13: replace \+= with \*= in Snapshot<'a>::read$",
            "--in-diff", "/r/line.diff"])

    def test_781_the_shard_re_runs_each_timeout_alone_and_packages_its_evidence(self):
        root = Path(self.temp.name) / "run"
        (root / "mutants.out" / "log").mkdir(parents=True)
        source = Path(self.temp.name) / "src.rs"
        source.write_text("fn f() -> usize {\n    0\n}\n")
        hung = self.mutant(f"{source}:2:5: replace f -> usize with 1", file=str(source))
        kill = self.mutant(f"{source}:1:1: replace f with 2", file=str(source))
        nightly.write_json(root / "mutants.out" / "outcomes.json", self.outcomes(
            [(kill, "CaughtMutant"), (hung, "Timeout")]))
        (root / "mutants.out" / "log" / "1.log").write_text("the pass's log\n")
        calls = []

        def cargo_mutants(command, **_):
            calls.append(command)
            out = Path(command[command.index("--output") + 1]) / "mutants.out"
            (out / "log").mkdir(parents=True)
            nightly.write_json(out / "outcomes.json", self.outcomes([(hung, "Timeout")]))
            (out / "log" / "0.log").write_text(
                "     Running `/home/runner/target/debug/build/x-1/build-script-build`\n"
                "     Running `/home/runner/target/debug/deps/wire_codec-1a2b '--skip=x'`\n"
                "test a_frame_that_never_ends has been running for over 60 seconds\n")
            (out / "debug.log").write_text("INFO timeouts.rs:68: Auto-set test timeout to 380s\n")
            (out / "lock.json").write_text("host metadata")
            return subprocess.CompletedProcess(command, 3)

        with patch("subprocess.run", side_effect=cargo_mutants), \
                patch("sys.stdout", new=io.StringIO()):
            reruns, status = nightly.lone_reruns(
                root, ["cargo", "mutants", "--shard", "1/2"], nightly.timeout_args("wire"), {})
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][calls[0].index("--re") + 1], nightly.exact_name(hung["name"]))
        self.assertNotIn("--shard", calls[0])
        self.assertEqual((root / "rerun" / "0" / "line.diff").read_text(),
                         f"--- a/{source}\n+++ b/{source}\n@@ -2,1 +2,1 @@\n-    0\n+    0\n")
        self.assertEqual(reruns[0]["rerun"]["outcome"], "timeout")
        self.assertEqual(reruns[0]["rerun"]["named"],
                         {"binary": "wire_codec-1a2b", "tests": ["a_frame_that_never_ends"]})
        self.assertEqual(reruns[0]["rerun"]["test_timeout"], 380.0)
        nightly.write_json(root / "run.json", {"reruns": reruns})
        nightly.write_json(root / "candidates.json", [])
        nightly.package(argparse.Namespace(run=root, output=Path(self.temp.name) / "artifact"))
        kept = Path(self.temp.name) / "artifact" / "run" / "rerun" / "0"
        # No log (host paths, the rustc line, libtest's output): its reading is `named`.
        self.assertEqual(sorted(str(p.relative_to(kept)) for p in kept.rglob("*") if p.is_file()),
                         ["line.diff", "outcomes.json"])

    def test_781_the_record_lists_a_second_timeout_as_a_row_not_a_survivor(self):
        import mutants_record as record
        run_dir = Path(self.temp.name)
        self.shard("Timeout")
        nightly.write_json(run_dir / "jobs.json", [{
            "name": "Mutants (wire, 0/1)", "status": "completed", "conclusion": "success",
            "started_at": "2026-11-04T00:58:00Z", "completed_at": "2026-11-04T03:10:00Z"}])
        found = record.survivors(run_dir)
        self.assertEqual(found[self.NAME]["outcome"], "timeout")
        self.assertEqual(found[self.NAME]["pass_outcome"], "timeout")
        self.assertEqual([m for m in found.values() if m["outcome"] in record.survived("rerun")],
                         [])
        shards = record.shard_rows(run_dir)
        self.assertEqual((shards[0]["caught"], shards[0]["missed"], shards[0]["timeout"]),
                         (3, 0, 1))
        # The pass's 370 s and the re-run's 390 s under their own heading, not survived.
        self.assertEqual(shards[0]["minutes_by_outcome"],
                         {"baseline": 0.7, "caught": 18.5, "survived": 0.0, "unviable": 0.0,
                          "timed_out": 12.7, "rerun_baseline": 0.7})
        term = record.survivor_term(shards)["wire"]
        self.assertEqual((term["survived"], term["timed_out"], term["minutes_per_timeout"]),
                         (0, 1, 12.7))
        self.assertEqual(term["survivor_share_of_viable"], 0.0)

    # The strength read of c32facb9 (2026-11-04): a witness for each fail-closed line
    # that a one-line mutation of the judge left green.

    def errors_with(self, edit=None, rerun="Timeout", record=None):
        """The witness's errors after `edit(metadata, outcomes)` on its lone re-run."""
        path = self.shard(rerun)
        metadata = json.loads((path / "run.json").read_text())
        again = json.loads((path / "rerun" / "0" / "outcomes.json").read_text())
        if record is not None:
            metadata["reruns"][0]["rerun"]["outcome"] = record
        if edit:
            edit(metadata, again)
        nightly.write_json(path / "run.json", metadata)
        nightly.write_json(path / "rerun" / "0" / "outcomes.json", again)
        return nightly.collect(self.root, None, {})["errors"]

    def test_781_strength_a_red_re_timed_baseline_is_refused(self):
        def red(_, again):
            again["outcomes"][0]["summary"] = "Failure"
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} has no re-timed baseline",
                      self.errors_with(red))

    def test_781_strength_an_unviable_re_run_is_refused(self):
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} reads Unviable, "
                      f"its record unviable", self.errors_with(rerun="Unviable"))

    def test_781_strength_the_re_run_s_outcome_must_be_its_record_s(self):
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} reads CaughtMutant, "
                      f"its record timeout", self.errors_with(rerun="CaughtMutant",
                                                              record="timeout"))

    def test_781_strength_a_record_naming_another_file_or_mutant_is_refused(self):
        def elsewhere(metadata, _):
            metadata["reruns"][0]["file"] = "src/wallet/wire/framing.rs"
        errors = self.errors_with(elsewhere)
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} did not run it alone", errors)
        self.assertIn(f"('wire', '0/1'): timeout without its lone re-run: {self.NAME}", errors)

    def test_781_strength_a_re_run_of_a_mutant_its_pass_did_not_time_out_is_refused(self):
        kill = f"{self.FILE}:1:5: replace g with 1"
        def of_a_kill(metadata, again):
            metadata["reruns"][0]["mutant"] = kill
            again["outcomes"][1]["scenario"]["Mutant"] = self.mutant(kill)
        self.assertIn(f"('wire', '0/1'): a lone re-run of a mutant its pass did not time out: "
                      f"{kill}", self.errors_with(of_a_kill))

    def test_781_strength_the_re_run_s_exit_code_is_read(self):
        def failed(metadata, _):
            metadata["reruns"][0]["exit_code"] = 101
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} failed (101)",
                      self.errors_with(failed))

    def test_781_strength_an_unfinished_re_run_is_refused(self):
        def unfinished(_, again):
            again["end_time"] = None
        self.assertIn(f"('wire', '0/1'): lone re-run of {self.NAME} unfinished or another tool",
                      self.errors_with(unfinished))

    def test_781_strength_two_re_runs_of_one_mutant_are_refused(self):
        def twice(metadata, _):
            metadata["reruns"].append(dict(metadata["reruns"][0]))
        self.assertIn(f"('wire', '0/1'): two lone re-runs of {self.NAME}", self.errors_with(twice))

    def test_781_strength_an_unknown_mark_is_refused(self):
        def other(metadata, _):
            metadata["timeout_rerun"] = 2
        self.assertIn("('wire', '0/1'): unknown timeout method 2", self.errors_with(other))

    def run_shard(self, pass_code=3, rerun_code=3):
        """`run` on one shard whose pass times one mutant out, cargo and git faked: the
        mark read from `run.json` when the pass starts, every command, the status."""
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.temp.name)
        source = Path("src.rs")
        source.write_text("fn f() -> usize {\n    0\n}\n")
        hung = self.mutant(f"{source}:2:5: replace f -> usize with 1", file=str(source))
        output, seen, calls = Path(self.temp.name) / "run", {}, []

        def cargo(command, stdout=None, **_):
            calls.append(command)
            if "--list" in command:
                stdout.write(json.dumps([hung]))
                return subprocess.CompletedProcess(command, 0)
            out = Path(command[command.index("--output") + 1]) / "mutants.out"
            out.mkdir(parents=True)
            if "--shard" in command:
                seen["mark"] = json.loads((output / "run.json").read_text()).get("timeout_rerun")
            nightly.write_json(out / "outcomes.json", self.outcomes([(hung, "Timeout")]))
            return subprocess.CompletedProcess(command, pass_code if "--shard" in command
                                               else rerun_code)

        shard = ["cargo", "mutants", "--sharding", "round-robin", "--shard", "0/1"]
        with patch("subprocess.run", side_effect=cargo), \
                patch("subprocess.check_output", return_value="c" * 40), \
                patch.object(nightly, "mutation_args", return_value=shard), \
                patch("sys.stdout", new=io.StringIO()):
            status = nightly.run(argparse.Namespace(
                output=output, file=[str(source)], plan=None, surface="wire", shard="0/1",
                commit=None))
        return status, seen, calls, json.loads((output / "run.json").read_text())

    def test_781_strength_run_writes_the_mark_before_the_pass(self):
        status, seen, calls, metadata = self.run_shard()
        self.assertEqual(seen["mark"], 1)
        self.assertEqual(metadata["timeout_rerun"], 1)
        self.assertEqual((status, metadata["exit_code"], len(metadata["reruns"])), (3, 3, 1))

    def test_781_strength_the_lone_command_carries_the_shard_s_limits(self):
        _, _, calls, _ = self.run_shard()
        lone = calls[-1]
        self.assertNotIn("--shard", lone)
        # Each once: `run` stores the pass's command with its limits, and clap refuses an
        # option given twice (the lone command composed through `run`, not by hand).
        self.assertEqual([lone.count(flag) for flag in (
            "--minimum-test-timeout", "--timeout-multiplier", "--build-timeout", "--jobs",
            "--output")], [1, 1, 1, 1, 1])
        pairs = {lone[i]: lone[i + 1] for i in range(len(lone) - 1)}
        self.assertEqual({flag: pairs.get(flag) for flag in (
            "--minimum-test-timeout", "--timeout-multiplier", "--build-timeout", "--jobs")},
            {"--minimum-test-timeout": str(nightly.MINIMUM_TEST_TIMEOUT["wire"]),
             "--timeout-multiplier": str(nightly.TEST_TIMEOUT_MULTIPLIER),
             "--build-timeout": "300", "--jobs": "1"})
        # The pass's limits are the same words.
        self.assertEqual(calls[1][calls[1].index("--minimum-test-timeout"):
                                  calls[1].index("--output")], nightly.timeout_args("wire"))

    def test_781_strength_a_failed_re_run_is_the_run_s_status(self):
        status, _, _, metadata = self.run_shard(rerun_code=101)
        self.assertEqual((status, metadata["exit_code"]), (101, 3))
        self.assertEqual(metadata["reruns"][0]["exit_code"], 101)

    def test_781_strength_a_failed_pass_runs_no_re_run(self):
        status, _, calls, metadata = self.run_shard(pass_code=1)
        self.assertEqual((status, len(calls)), (1, 2))
        self.assertNotIn("reruns", metadata)

    def test_781_strength_no_mutant_log_is_packaged(self):
        for outcome in ("Timeout", "CaughtMutant"):
            with self.subTest(outcome=outcome):
                run = Path(self.temp.name) / f"run-{outcome}"
                where = run / "rerun" / "0"
                (where / "mutants.out" / "log").mkdir(parents=True)
                (where / "line.diff").write_text("--- a/x\n")
                nightly.write_json(where / "mutants.out" / "outcomes.json", {})
                (where / "mutants.out" / "log" / "0.log").write_text(
                    "Running `/home/runner/target/debug/deps/wire_codec-1a2b`\n")
                (where / "mutants.out" / "debug.log").write_text("host\n")
                nightly.write_json(run / "run.json", {"reruns": [{
                    "index": 0, "rerun": {"outcome": nightly.OUTCOMES[outcome],
                                          "log": "log/0.log"}}]})
                nightly.write_json(run / "candidates.json", [])
                artifact = Path(self.temp.name) / f"artifact-{outcome}"
                nightly.package(argparse.Namespace(run=run, output=artifact))
                kept = sorted(str(p.relative_to(artifact / run.name))
                              for p in (artifact / run.name).rglob("*") if p.is_file())
                self.assertEqual(kept, ["candidates.json", "rerun/0/line.diff",
                                        "rerun/0/outcomes.json", "run.json"])

    def test_781_strength_the_previous_record_s_survivors_read_under_its_own_rule(self):
        import mutants_record as record
        before = {"src/script/a.rs": {"missed": 1, "timeout": 2},
                  "src/wallet/b.rs": {"missed": 3, "timeout": 4}}
        self.assertEqual(record.previous_survivors({}, before), 10)
        self.assertEqual(record.previous_survivors({}, before, gate=True), 3)
        self.assertEqual(record.previous_survivors({"timeout_rule": "rerun"}, before), 4)
        self.assertEqual(record.previous_survivors({"timeout_rule": "rerun"}, before, True), 1)

    def test_781_strength_every_metacharacter_a_name_carries_is_escaped(self):
        import re
        name = r"src/a.rs:1:2: replace f(x) <T> + * | [i] . ? ^ $ {n} \ with -~#&"
        self.assertEqual(nightly.exact_name(name),
                         r"^src/a\.rs:1:2: replace f\(x\) <T> \+ \* \| \[i\] \. \? \^ \$ "
                         r"\{n\} \\ with \-\~\#\&$")
        # `<` and `>` stay as they are: Rust's `regex::escape` leaves them, and `\<`, `\>`
        # are word boundaries since regex 1.10.
        self.assertTrue(re.fullmatch(nightly.exact_name(name), name))

    # The keeper's word of 2026-11-04 16:1xZ, refined: a timeout-only file is UNJUDGED.
    OTHER = "src/wallet/wire/framing.rs"
    OTHER_NAME = "src/wallet/wire/framing.rs:4:5: replace h -> usize with 0"

    # The keeper's word of 16:2xZ: a gate path is floored (GATE_FLOOR), never unclaimed.
    GATE = "src/script/spend/key_point.rs"
    GATE_NAME = "src/script/spend/key_point.rs:4:5: replace h -> usize with 0"

    def split_shard(self, rerun="Timeout", gate=False):
        """The witness's shard with its hung mutant moved to OTHER (`gate`: to GATE): its
        one mutant timed out in the pass and, under `rerun`, again alone (Unviable: the
        compiler's)."""
        if gate:
            self.OTHER, self.OTHER_NAME = self.GATE, self.GATE_NAME
        path = self.shard("Timeout")
        hung = self.mutant(self.OTHER_NAME, file=self.OTHER)
        candidates = json.loads((path / "candidates.json").read_text())
        nightly.write_json(path / "candidates.json", candidates[:3] + [hung])
        outcomes = json.loads((path / "outcomes.json").read_text())
        outcomes["outcomes"][4]["scenario"]["Mutant"] = hung
        if rerun == "Unviable":
            outcomes["outcomes"][4]["summary"] = "Unviable"
            outcomes["timeout"], outcomes["unviable"] = 0, 1
        nightly.write_json(path / "outcomes.json", outcomes)
        metadata = json.loads((path / "run.json").read_text())
        metadata["files"].append(self.OTHER)
        if rerun == "Unviable":
            metadata["reruns"] = []
            shutil.rmtree(path / "rerun")
        else:
            metadata["reruns"][0].update(file=self.OTHER, mutant=self.OTHER_NAME)
            again = json.loads((path / "rerun" / "0" / "outcomes.json").read_text())
            again["outcomes"][1]["scenario"]["Mutant"] = hung
            nightly.write_json(path / "rerun" / "0" / "outcomes.json", again)
        nightly.write_json(path / "run.json", metadata)

    def other_row(self, result):
        return {row["file"]: row for row in result["files"]}[self.OTHER]

    def test_781_an_unfloored_timeout_only_file_fails_on_the_default_floor(self):
        # The keeper's word of 16:2xZ: the default the judge reds a file elsewhere below
        # (GATE_FLOOR, no `mutation_floors` entry) is a number the night enforces.
        import mutants_record as record
        self.split_shard("Timeout")
        status, result, markdown = self.report()
        row = self.other_row(result)
        self.assertEqual(status, 1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["errors"], [f"floor has no measured file: {self.OTHER}"])
        self.assertEqual((row["generated"], row["timeout"], row["viable"]), (1, 1, 0))
        self.assertTrue(row.get("unjudged"))
        self.assertIs(row["passed"], False)
        self.assertFalse(row["no_viable"])
        self.assertIn(f"| `{self.OTHER}` | 0 | 0 | 1 | 0 | n/a | 80% | FAIL |", markdown)
        self.assertNotIn("NO VIABLE MUTANTS |", markdown)
        self.assertEqual([r["mutant"] for r in result["timeouts"]], [self.OTHER_NAME])
        self.assertEqual(record.status(row), "FAIL")
        # UNJUDGED and green is a carried row's alone (`merge`: the night reds no carried
        # figure), counted apart under the re-run rule.
        self.assertEqual(record.status(dict(row, passed=None)), "UNJUDGED")
        self.assertIn("UNJUDGED", record.statuses("rerun"))
        self.assertNotIn("UNJUDGED", record.statuses("counted"))

    def test_781_a_timeout_only_gate_path_is_floored_and_fails(self):
        import mutants_record as record
        self.split_shard("Timeout", gate=True)
        self.assertTrue(nightly.is_gate_path(self.OTHER))
        status, result, markdown = self.report()
        row = self.other_row(result)
        self.assertEqual(status, 1)
        self.assertTrue(result["complete"])
        self.assertEqual(result["errors"], [f"floor has no measured file: {self.OTHER}"])
        self.assertTrue(row.get("unjudged"))
        self.assertIs(row["passed"], False)
        self.assertEqual(row["floor_percent"], nightly.GATE_FLOOR)
        self.assertIn(f"| `{self.OTHER}` | 0 | 0 | 1 | 0 | n/a | 80% | FAIL |", markdown)
        self.assertEqual(record.status(row), "FAIL")

    def test_781_a_floored_timeout_only_file_fails_on_its_floor_alone(self):
        nightly.write_json(self.floors, {"mutation_floors": {
            self.FILE: {"percent": 100}, self.OTHER: {"percent": 100}}})
        self.split_shard("Timeout")
        status, result, markdown = self.report()
        row = self.other_row(result)
        self.assertEqual(status, 1)
        self.assertTrue(result["complete"])
        self.assertIs(row["passed"], False)
        self.assertEqual(result["errors"], [f"floor has no measured file: {self.OTHER}"])
        self.assertIn(f"| `{self.OTHER}` | 0 | 0 | 1 | 0 | n/a | 100% | FAIL |", markdown)

    def test_781_a_file_the_compiler_refuses_whole_stays_no_viable_under_the_re_run(self):
        self.split_shard("Unviable")
        status, result, markdown = self.report()
        row = self.other_row(result)
        self.assertEqual(status, 0, result["errors"])
        self.assertEqual(result["timeout_rule"], "rerun")
        self.assertTrue(row["no_viable"])
        self.assertFalse(row.get("unjudged", False))
        self.assertIn(f"| `{self.OTHER}` | 0 | 0 | 0 | 1 | n/a | 80% | NO VIABLE MUTANTS |",
                      markdown)


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


class TheCompleteRunsSurvivorTerm(unittest.TestCase):
    def test_the_survivor_term_sums_each_shards_outcomes_measured_and_by_its_rate(self):
        import mutants_record as record
        self.assertEqual(record.minutes("2026-11-04T01:27:06Z",
                                        "2026-11-04T01:30:10.480419729Z"), 184.480419 / 60)
        def shard(surface, mutants, caught, missed, timeout, unviable, took, spent):
            return {"surface": surface, "total_mutants": mutants, "caught": caught,
                    "missed": missed, "timeout": timeout, "unviable": unviable,
                    "job_minutes": took + 3, "mutants_minutes": took,
                    "minutes_by_outcome": spent}
        shards = [
            shard("wire", 10, 6, 2, 1, 1, 20.0,
                  {"baseline": 1.0, "caught": 9.0, "survived": 9.5, "unviable": 0.5}),
            shard("wire", 5, 4, 0, 0, 1, 5.0,
                  {"baseline": 1.0, "caught": 3.5, "survived": 0.0, "unviable": 0.5}),
        ]
        wire = record.survivor_term(shards)["wire"]
        self.assertEqual((wire["shards"], wire["mutants"], wire["caught"], wire["survived"],
                          wire["unviable"]), (2, 15, 10, 3, 2))
        self.assertEqual(wire["measured_minutes"],
                         {"baseline": 2.0, "caught": 12.5, "survived": 9.5, "unviable": 1.0})
        # By the rate: one shard's 2.0 minutes a mutant, the other's 1.0.
        self.assertEqual(wire["rate_minutes"], {"caught": 16.0, "survived": 6.0, "unviable": 3.0})
        self.assertEqual((wire["minutes_per_kill"], wire["minutes_per_survivor"]), (1.25, 3.17))
        self.assertEqual(wire["survivor_share_of_viable"], round(3 / 13, 4))
        self.assertEqual(wire["survivor_share_of_minutes"], round(9.5 / 25, 4))
        self.assertEqual(record.survivor_term(shards, whole=True)["all"]["mutants"], 15)


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

    def test_the_merkle_walk_is_a_gate_path_of_the_merkle_surface_93(self):
        walk = "src/transaction/merkle_path_walk.rs"
        self.assertIn(walk, nightly.SURFACES["merkle"])
        self.assertIn("src/transaction/merkle_path.rs", nightly.SURFACES["merkle"])
        self.assertTrue(nightly.is_gate_path(walk))
        self.assertFalse(nightly.is_gate_path("src/transaction/merkle_path_extra.rs"))


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
        "tests/script_row_less.rs": "use bsv_rs::script::Script;\n#[test] fn row_less() {}\n",
        "tests/transaction_tests.rs": "use bsv_rs::transaction::Beef;\n// vectors/beef_shared.json\n",
        "tests/wallet_tests.rs": "use bsv_rs::wallet::Wallet;\n"
                                 "#[path = \"support/wallet_helper.rs\"]\nmod wallet_helper;\n",
        "tests/unrelated_tests.rs": "// vectors/beef_shared.json\n",
        "tests/doc_lint.rs": "// vectors/beef_shared.json, no crate path, no row\n",
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
        # No crate path and no row: no file's selection runs it, so it never meets a mutant.
        self.assertEqual(self.files("tests/doc_lint.rs"), set())
        # #685: a row naming a module's source puts the binary in that module's files'
        # selection (until #685 no fixed list held it, and it reached nothing).
        self.assertEqual(self.files("tests/unrelated_tests.rs"), self.TRANSACTION)

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

    def plan(self, mode="incremental", record=True, at=OUTSIDE, max_parallel=None):
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
                                            repo=self.repo, output=output, at=at,
                                            max_parallel=max_parallel))
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
        # #685: the night's script shard runs its file's three targets, the BEEF one its two.
        self.assertEqual(planned["surface_tests"], {
            "script": ["script_flow_603", "script_parse_603", "script_row_less"],
            "beef": ["transaction_tests", "unrelated_tests"]})
        # 400 script mutants at the minutes of three targets each: two shards of 45 minutes.
        self.assertEqual(nightly.minutes_per_mutant("script", 3), 0.125)
        self.assertEqual([(m["surface"], m["shard"]) for m in planned["matrix"]], [
            ("script", "0/2"), ("script", "1/2"), ("beef", "0/1")])
        self.assertEqual(planned["max_parallel"], nightly.SHARED_PARALLEL)
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
        self.assertEqual(sum(1 for m in planned["matrix"]), 8 + 3 + 1 + 3 + 8)
        self.assertEqual(planned["max_parallel"], nightly.SHARED_PARALLEL)
        self.assertEqual(self.plan(record=False)["why_complete"],
                         "no record of a complete run on the line to carry from")
        self.assertEqual(self.plan(mode="complete")["mode"], "complete")

    def test_the_complete_run_is_twenty_three_shards_in_four_waves_under_the_cap(self):
        # The method's twenty and the ceiling's three more (#703's second fold).
        self.assertEqual(nightly.SLOT_LIMIT, 20)
        self.assertEqual(sum(nightly.COMPLETE_SHARDS.values()), 23)
        self.assertEqual(set(nightly.COMPLETE_SHARDS), set(nightly.SURFACES))
        # #791: fourteen of the twenty inside the run's window, six otherwise.
        self.assertEqual((nightly.WINDOW_PARALLEL, nightly.SHARED_PARALLEL), (14, 6))
        self.assertEqual(nightly.PARALLEL_BOUNDS, (1, 20))

    # #791, the owner's word of 2026-11-04 17:1xZ: the heavy-run cap by window.
    def test_the_complete_run_inside_the_window_takes_fourteen_791(self):
        self.land("Cargo.toml", "[package]\nname = 'bumped'\n")
        planned = self.plan(at=INSIDE)
        self.assertEqual((planned["mode"], planned["max_parallel"]), ("complete", 14))
        self.assertTrue(planned["max_parallel_reason"].startswith(
                         "at 07:00Z, inside this crate's window (bsv-rs: the complete run's 01:00Z slot, the incremental night's 07:00Z and the pin-chain dispatches, 01:00Z to 09:00Z); the waves of 14 "
                         "projected from the plan estimates end at "), planned["max_parallel_reason"])
        # A night is a heavy run by the word: the same figure in its window.
        self.assertEqual(self.plan(mode="incremental", at=INSIDE)["max_parallel"], 14)

    def test_outside_the_window_or_in_another_runs_the_run_takes_six_791(self):
        planned = self.plan(mode="complete", at=OUTSIDE)
        self.assertEqual((planned["max_parallel"], planned["max_parallel_reason"]),
                         (6, "at 12:30Z, outside every window"))
        cli = self.plan(mode="complete", at=datetime(2026, 11, 5, 17, 5, tzinfo=timezone.utc))
        self.assertEqual(cli["max_parallel"], 6)
        self.assertIn("inside another heavy run's window (bsv-wallet-cli", cli["max_parallel_reason"])
        # The keeper's table of 2026-11-04 18:0xZ: the CLI's night 17:00Z to 20:00Z, the
        # toolbox's 20:00Z to 01:00Z (past midnight), the day at six outside every window.
        late = self.plan(mode="complete", at=datetime(2026, 11, 5, 19, 30, tzinfo=timezone.utc))
        self.assertIn("inside another heavy run's window (bsv-wallet-cli: its night, 17:00Z to 20:00Z",
                      late["max_parallel_reason"])
        for hour, minute in ((20, 0), (23, 30), (0, 59)):
            toolbox = nightly.heavy_max_parallel(datetime(2026, 11, 5, hour, minute, tzinfo=timezone.utc))
            self.assertEqual(toolbox[0], 6)
            self.assertIn("inside another heavy run's window (wallet-toolbox: its night, 20:00Z to 01:00Z",
                          toolbox[1])
        # The window's edges: 01:00Z in, 00:59Z and 09:00Z out.
        at = lambda h, m=0: datetime(2026, 11, 5, h, m, tzinfo=timezone.utc)  # noqa: E731
        self.assertEqual([nightly.heavy_max_parallel(at(*t))[0]
                          for t in ((0, 59), (1, 0), (8, 59), (9, 0))], [6, 14, 14, 6])

    def test_the_dispatch_input_overrides_the_window_bounded_to_the_slots_791(self):
        planned = self.plan(mode="complete", at=INSIDE, max_parallel="3")
        self.assertEqual(planned["max_parallel"], 3)
        self.assertTrue(planned["max_parallel_reason"].startswith(
            "the dispatch input heavy_max_parallel=3; the waves of 3 projected"))
        self.assertEqual(self.plan(mode="complete", at=OUTSIDE, max_parallel="20")["max_parallel"], 20)
        # Empty (the input's default) is the window's figure.
        self.assertEqual(self.plan(mode="complete", at=INSIDE, max_parallel="")["max_parallel"], 14)
        for bad in ("0", "21", "-1", "six", "1.5"):
            with self.assertRaises(SystemExit) as refused:
                nightly.heavy_max_parallel(INSIDE, bad)
            self.assertIn("is not an integer from 1 to 20", str(refused.exception))

    def test_the_plan_writes_the_figure_and_its_reason_to_the_step_output_791(self):
        self.land("Cargo.toml", "[package]\nname = 'bumped'\n")
        out = self.repo / "github_output"
        out.write_text("")
        commit = self.git("rev-parse", "HEAD")
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(out)}):
            nightly.plan(argparse.Namespace(commit=commit, mode="complete",
                                            base_record=self.repo / "none", repo=self.repo,
                                            output=self.repo / "p.json", at=INSIDE,
                                            max_parallel=None))
        lines = out.read_text().splitlines()
        self.assertIn("max_parallel=14", lines)
        self.assertIn("max_parallel_reason=at 07:00Z, inside this crate's window (bsv-rs: the "
                      "complete run's 01:00Z slot, the incremental night's 07:00Z and the pin-chain dispatches, 01:00Z to 09:00Z); the "
                      "waves of 14 projected from the plan estimates end at 07:46Z, 08:10Z: every "
                      "wave ends by 09:00Z, all 23 shards at 14", lines)
        # #791's tail: none on the fixture's estimates, the tail job's matrix empty.
        self.assertIn("shards_tail=0", lines)
        self.assertIn("max_parallel_tail=6", lines)
        self.assertIn("max_parallel_fuzz=14", lines)
        self.assertIn("matrix_tail=[]", lines)

    # #791's fold, the keeper's word of 2026-11-04 18:0xZ: the waves projected past the
    # window's end run at six, from the last complete record's minutes in the tree.
    RECORD = Path(__file__).resolve().parents[2] / "docs/census/mutants-2026-11-04.json"

    def with_record(self):
        self.put("docs/census/mutants-2026-11-04.json", self.RECORD.read_text())

    def labels(self, rows):
        return [row["label"] for row in rows]

    def test_a_complete_run_tails_the_waves_projected_past_the_window_at_six_791(self):
        self.with_record()
        at = lambda h, m=0: datetime(2026, 11, 5, h, m, tzinfo=timezone.utc)  # noqa: E731
        # The record's waves of 14 in matrix order: the opening wave's longest is script
        # 0/8's 212.8 minutes, the second's wire 2/3's 244.8 (457.6 in all): a run
        # dispatched by 01:22Z ends by 09:00Z whole at fourteen.
        for clock, ends in (((1, 0), "04:32Z, 08:37Z"), ((1, 22), "04:54Z, 08:59Z")):
            planned = self.plan(mode="complete", at=at(*clock))
            self.assertEqual((len(planned["matrix_window"]), planned["shards_tail"],
                              planned["max_parallel"], planned["max_parallel_fuzz"]),
                             (23, 0, 14, 14))
            self.assertTrue(planned["max_parallel_reason"].endswith(
                f"the waves of 14 projected from docs/census/mutants-2026-11-04.json end at "
                f"{ends}: every wave ends by 09:00Z, all 23 shards at 14"),
                planned["max_parallel_reason"])
        # At 03:00Z the second wave ends at 10:37Z: its nine shards are the tail at six.
        planned = self.plan(mode="complete", at=at(3))
        self.assertEqual((len(planned["matrix_window"]), planned["shards_tail"],
                          planned["max_parallel"], planned["max_parallel_tail"],
                          planned["max_parallel_fuzz"]), (14, 9, 14, 6, 6))
        self.assertEqual(self.labels(planned["matrix_window"] + planned["matrix_tail"]),
                         self.labels(planned["matrix"]))
        self.assertEqual(self.labels(planned["matrix_tail"]),
                         ["wire-2-3"] + [f"substrates-{i}-8" for i in range(8)])
        self.assertEqual(planned["max_parallel_reason"],
                         "at 03:00Z, inside this crate's window (bsv-rs: the complete run's 01:00Z slot, the incremental night's 07:00Z and the pin-chain dispatches, 01:00Z to 09:00Z); the waves of 14 "
                         "projected from docs/census/mutants-2026-11-04.json end at 06:32Z, "
                         "10:37Z: the 14 shards of the waves ending by 09:00Z at 14, the 9 after "
                         "them the tail at 6")
        # A minute later than 01:22Z the second wave ends at 09:00.6Z, past the end.
        self.assertEqual(self.plan(mode="complete", at=at(1, 23))["shards_tail"], 9)
        # At 07:00Z the opening wave ends at 10:32Z: the whole run at six, no tail.
        planned = self.plan(mode="complete", at=INSIDE)
        self.assertEqual((len(planned["matrix_window"]), planned["shards_tail"],
                          planned["max_parallel"], planned["max_parallel_fuzz"]), (23, 0, 6, 6))
        self.assertTrue(planned["max_parallel_reason"].endswith(
            "end at 10:32Z, 14:37Z: the opening wave ends past the window, every one of the "
            "23 shards at 6"), planned["max_parallel_reason"])

    def test_outside_the_window_no_tail_and_six_791(self):
        self.with_record()
        planned = self.plan(mode="complete", at=OUTSIDE)
        self.assertEqual((planned["max_parallel"], planned["max_parallel_reason"],
                          planned["shards_tail"], planned["max_parallel_fuzz"]),
                         (6, "at 12:30Z, outside every window", 0, 6))
        self.assertEqual(planned["matrix_window"], planned["matrix"])
        # The CLI's window: six, no projection.
        cli = self.plan(mode="complete", at=datetime(2026, 11, 5, 18, 0, tzinfo=timezone.utc))
        self.assertEqual((cli["max_parallel"], cli["shards_tail"]), (6, 0))

    def test_the_input_sets_the_windows_waves_and_the_tail_stays_six_791(self):
        self.with_record()
        at = datetime(2026, 11, 5, 3, 0, tzinfo=timezone.utc)
        # Waves of 20: the opening one's longest wire 2/3's 244.8 (07:04Z), the three
        # substrates shards after it 234.7 more (10:59Z), the tail at six.
        planned = self.plan(mode="complete", at=at, max_parallel="20")
        self.assertEqual((len(planned["matrix_window"]), planned["shards_tail"],
                          planned["max_parallel"], planned["max_parallel_tail"]), (20, 3, 20, 6))
        self.assertEqual(planned["max_parallel_reason"],
                         "the dispatch input heavy_max_parallel=20; the waves of 20 projected "
                         "from docs/census/mutants-2026-11-04.json end at 07:04Z, 10:59Z (the "
                         "input sets the window's waves; the tail stays six): the 20 shards of "
                         "the waves ending by 09:00Z at 20, the 3 after them the tail at 6")
        # Outside the window the input is the whole run's figure, as before the fold.
        outside = self.plan(mode="complete", at=OUTSIDE, max_parallel="20")
        self.assertEqual((outside["max_parallel"], outside["shards_tail"]), (20, 0))

    def test_a_shard_the_record_does_not_name_reads_as_its_surfaces_longest_791(self):
        self.with_record()
        source, minutes = nightly.recorded_shard_minutes(self.repo)
        self.assertEqual((source, len(minutes)), ("docs/census/mutants-2026-11-04.json", 23))
        estimate = lambda surface, shard: nightly.shard_estimate(  # noqa: E731
            {"surface": surface, "shard": shard, "estimated_minutes": 1}, minutes)
        self.assertEqual(estimate("script", "0/8"), 212.8)
        self.assertEqual(estimate("script", "0/9"), 212.8)
        self.assertEqual(estimate("wire", "0/4"), 244.8)
        self.assertEqual(estimate("substrates", "3/9"), 237.4)
        # No record in the tree: the plan's own estimate.
        self.assertEqual(nightly.shard_estimate({"surface": "script", "shard": "0/8",
                                                 "estimated_minutes": 31}, {}), 31)
        # A ninth script shard is the surface's longest: its wave is projected so.
        rows = [{"surface": "script", "shard": f"{i}/9", "label": f"script-{i}-9"}
                for i in range(9)]
        waves = nightly.project_waves(rows, minutes, datetime(2026, 11, 5, 1, 0,
                                                              tzinfo=timezone.utc), 14)
        self.assertEqual([end.strftime("%H:%MZ") for _, end in waves], ["04:32Z"])

    def test_a_wave_ending_at_the_windows_end_is_inside_it_791(self):
        rows = [{"surface": "beef", "shard": f"{i}/30", "label": f"beef-{i}-30",
                 "estimated_minutes": 60} for i in range(30)]
        window, tail, figure, reason = nightly.split_tail(
            rows, INSIDE, 14, "r", recorded=(None, {}))
        # Waves end at 08:00Z, 09:00Z (at the end: inside) and 10:00Z.
        self.assertEqual((len(window), len(tail), figure), (28, 2, 14))
        self.assertEqual(reason, "r; the waves of 14 projected from the plan estimates end at "
                                 "08:00Z, 09:00Z, 10:00Z: the 28 shards of the waves ending by "
                                 "09:00Z at 14, the 2 after them the tail at 6")
        self.assertEqual(nightly.split_tail([], INSIDE, 14, "r"), ([], [], 14, "r"))

    # PR #666's fold: the five holes the reads found, each on the fixture tree.
    def put(self, path, body):
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(body)

    def test_fold_1_a_deleted_selection_test_re_measures_what_its_base_row_named(self):
        self.git("rm", "-q", "tests/script_parse_603.rs", "tests/script_row_less.rs",
                 "tests/doc_lint.rs")
        self.git("commit", "-q", "-m", "three tests deleted")
        planned = self.plan()
        # script_parse_603's base row names script.rs; script_row_less's names
        # nothing (its base text's `bsv_rs::script`: the module's files); doc_lint
        # was in no selection (nothing).
        self.assertEqual(planned["files"], {"script": sorted(self.SCRIPT)})
        self.assertIn("removed", planned["reach"]["tests/script_parse_603.rs"]["why"])
        self.assertEqual(planned["reach"]["tests/script_parse_603.rs"]["files"],
                         ["src/script/script.rs"])
        self.assertEqual(planned["reach"]["tests/script_row_less.rs"]["files"],
                         sorted(self.SCRIPT))
        self.assertEqual(planned["reach"]["tests/doc_lint.rs"]["files"], [])

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


    # #685: a measured file's targets are the reach rule's, not a list per surface.
    def test_685_a_file_s_targets_are_the_binaries_naming_its_module(self):
        chosen = nightly.selection(nightly.measured_files(self.repo), self.repo)
        self.assertEqual(chosen["src/script/script.rs"],
                         ["script_flow_603", "script_parse_603", "script_row_less"])
        # A row naming a module's source (`src/transaction/broadcaster.rs`) selects it.
        self.assertEqual(chosen["src/transaction/merkle_path.rs"],
                         ["transaction_tests", "unrelated_tests"])

    def test_685_fold_a_module_s_callers_binaries_are_not_in_its_files_selection(self):
        # The keeper's word (11-03 16:1xZ): the run takes the direct reading; a wallet
        # source naming `crate::script` brings no wallet binary into a script file's set,
        # which a pull request's plan still reaches (the callers' level is the plan's).
        import affected_tests
        self.put("src/wallet/wire/mod.rs", "use crate::script::Script;\n")
        chosen = nightly.selection(nightly.measured_files(self.repo), self.repo)
        self.assertNotIn("wallet_tests", chosen["src/script/spend/flow.rs"])
        pull = affected_tests.reach(["src/script/spend/flow.rs"], self.repo)["binaries"]
        self.assertIn("wallet_tests", pull)
        # A changed test reaches the files whose run selects it: the wallet's alone.
        self.assertEqual(self.files("tests/wallet_tests.rs"),
                         {"src/wallet/wire/mod.rs", "src/wallet/substrates/mod.rs"})

    def test_685_a_module_no_binary_reaches_keeps_the_lib_alone_and_the_plan_names_it(self):
        self.land("tests/wallet_tests.rs", self.FILES["tests/wallet_tests.rs"].replace(
            "use bsv_rs::wallet::Wallet;\n", ""))
        planned = self.plan(mode="complete")
        wallet = ["src/wallet/substrates/mod.rs", "src/wallet/wire/mod.rs"]
        self.assertEqual(planned["lib_only"], wallet)
        self.assertEqual({f: planned["selection"][f] for f in wallet}, {f: [] for f in wallet})
        self.assertEqual((planned["surface_tests"]["wire"], planned["surface_tests"]["substrates"]),
                         ([], []))
        self.assertIn("--lib alone: `src/wallet/substrates/mod.rs`, `src/wallet/wire/mod.rs`",
                      nightly.selection_line(planned))
        args = nightly.mutation_args("wire", "0/1", wallet[1:], [])
        self.assertIn("--cargo-arg=--lib", args)
        # #603: the wire surface runs its tracing sink beside an empty selection.
        self.assertEqual([a for a in args if a.startswith("--cargo-arg=--test=")],
                         ["--cargo-arg=--test=wire_tracing_sink"])
        args = nightly.mutation_args("substrates", "0/1", wallet[:1], [])
        self.assertFalse([a for a in args if a.startswith("--cargo-arg=--test=")])

    def test_685_a_source_text_walker_a_cost_check_and_an_apart_binary_are_never_selected(self):
        import affected_tests
        self.put("tests/arch_walk.rs", 'fn walk() { std::fs::read_dir("src").unwrap(); }\n')
        self.put("tests/beef_deep_chain.rs", "use bsv_rs::transaction::Beef;\n")
        self.put("tests/memory_profiling.rs", "use bsv_rs::script::Script;\n")
        # A pull request changing the file runs all three (the walker reads its text).
        pull = affected_tests.reach(["src/script/script.rs"], self.repo)["binaries"]
        self.assertIn("arch_walk", pull)
        chosen = nightly.selection(nightly.measured_files(self.repo), self.repo)
        for stem in ("arch_walk", "beef_deep_chain", "memory_profiling"):
            self.assertFalse([f for f, t in chosen.items() if stem in t], stem)
            self.assertEqual(self.files(f"tests/{stem}.rs"), set())
        # #603: the tracing sink, run apart and in no file's set, rides on the wire
        # surface: a change to it re-measures the wire files alone.
        self.put("tests/wire_tracing_sink.rs", "use bsv_rs::wallet::Wallet;\n")
        chosen = nightly.selection(nightly.measured_files(self.repo), self.repo)
        self.assertFalse([f for f, t in chosen.items() if "wire_tracing_sink" in t])
        self.assertEqual(self.files("tests/wire_tracing_sink.rs"), {"src/wallet/wire/mod.rs"})

    def test_685_a_row_whose_modules_change_re_measures_the_files_they_select(self):
        self.land("tests/CLAUDE.md", self.FILES["tests/CLAUDE.md"].replace(
            "| `unrelated_tests.rs`",
            "| `doc_lint.rs` | 1 | default | lints `src/wallet/` docs |\n| `unrelated_tests.rs`"))
        planned = self.plan()
        self.assertEqual(planned["files"], {"wire": ["src/wallet/wire/mod.rs"],
                                            "substrates": ["src/wallet/substrates/mod.rs"]})
        # A row whose words change and whose modules do not moves no selection.
        self.base = self.git("rev-parse", "HEAD")
        self.land("tests/CLAUDE.md", (self.repo / "tests/CLAUDE.md").read_text().replace(
            "lints `src/wallet/` docs", "lints the `src/wallet/` docs"))
        self.assertEqual(self.plan()["files"], {})

    def test_685_the_timeout_scales_with_the_shard_s_baseline_over_the_old_floor(self):
        self.assertEqual(nightly.MINIMUM_TEST_TIMEOUT,
                         {"script": 120, "beef": 300, "merkle": 120, "wire": 120,
                          "substrates": 120})
        self.assertEqual(set(nightly.MINIMUM_TEST_TIMEOUT), set(nightly.SURFACES))
        self.assertGreater(nightly.TEST_TIMEOUT_MULTIPLIER, 1)


class SelectionWitnesses685(unittest.TestCase):
    """#685's two findings on the tree: the tests that kill a file's mutants are in its
    shard's command. Until #685 the script surface's fixed list held neither."""

    def targets(self, file):
        return [a.removeprefix("--cargo-arg=--test=") for a in nightly.mutation_args(
            "script", "0/1", [file]) if a.startswith("--cargo-arg=--test=")]

    def test_key_point_s_shard_runs_the_660_tests(self):
        targets = self.targets("src/script/spend/key_point.rs")
        self.assertIn("pubkey_encoding_660", targets)
        self.assertIn("pubkey_point_shapes_660_adv", targets)

    def test_multisig_s_shard_runs_the_625_tests(self):
        self.assertIn("p2pk_hybrid_625", self.targets("src/script/templates/multisig.rs"))

    def test_the_complete_run_s_shards_stay_under_the_job_s_minutes_by_the_estimate(self):
        measured = nightly.measured_files()
        chosen = nightly.selection(measured)
        by_surface = {}
        for file, surface in sorted(measured.items()):
            by_surface.setdefault(surface, []).append(file)
        matrix = nightly.shard_matrix(by_surface, "complete", None, {
            s: len(nightly.shard_tests(chosen, f)) for s, f in by_surface.items()})
        self.assertEqual(len(matrix), sum(nightly.COMPLETE_SHARDS.values()))
        late = [m for m in matrix if m["estimated_minutes"] >= nightly.JOB_MINUTES]
        self.assertEqual(late, [])

    def test_703_fold_2_the_complete_split_is_the_record_s_method_over_the_direct_reading(self):
        # The record's largest remainder over the fold's estimate (8, 3, 1, 3, 5), each
        # surface raised to its two-part ceiling (substrates 8); the fold before kept 9, 3,
        # 1, 3, 4 from the callers' level, which the method does not give.
        self.assertEqual(nightly.complete_split(nightly.ESTIMATE_TARGETS), nightly.COMPLETE_SHARDS)

    def test_703_fold_2_no_complete_shard_s_two_part_estimate_passes_the_ceiling(self):
        self.assertLess(nightly.SHARD_CEILING_MINUTES, nightly.JOB_MINUTES)
        over = {s: round(nightly.COMPLETE_RUN_MUTANTS[s] * nightly.two_part_minutes_per_mutant(
                    s, nightly.ESTIMATE_TARGETS[s]) / nightly.COMPLETE_SHARDS[s])
                for s in nightly.SURFACES}
        self.assertEqual({s: m for s, m in over.items() if m >= nightly.SHARD_CEILING_MINUTES}, {})

    def test_685_fold_transaction_s_binaries_are_in_a_script_file_s_set_only_by_naming_script(self):
        # The direct reading (the keeper's word, 11-03 16:1xZ): a binary that uses
        # `transaction` (a caller of `script`) and names `script` neither by a path nor
        # in its row is not in a script file's set; the branch's callers' level put it there.
        import affected_tests
        tree = affected_tests.Tree(Path("."))
        targets = set(self.targets("src/script/templates/multisig.rs"))
        transaction_only = {b for b in tree.direct("transaction") if "script" not in tree.uses[b]}
        self.assertTrue(transaction_only - affected_tests.APART - nightly.COST_CHECKS)
        self.assertEqual(targets & transaction_only, set())
        self.assertEqual({t for t in targets if "script" not in tree.uses[t]}, set())

    def test_the_fixed_lists_targets_are_all_in_the_reach_sets(self):
        # The script surface's former named five and every `tests/script_*.rs` among them.
        targets = set(self.targets("src/script/spend/key_point.rs"))
        former = {"template_tests", "sighash_tests", "resource_limits", "conformance_scripts",
                  "identity_spend_witness", *(p.stem for p in Path("tests").glob("script_*.rs"))}
        self.assertEqual(former - targets, set())
        self.assertFalse(targets & nightly.COST_CHECKS)


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

    def test_the_record_names_the_slots_the_run_held_and_why_791(self):
        plan = dict(self.plan([], {}), max_parallel=14,
                    max_parallel_reason="at 07:00Z, inside this crate's window")
        run = nightly.merge({"files": []}, plan, self.base, {}, "200")[3]["runs"][-1]
        self.assertEqual((run["max_parallel"], run["max_parallel_reason"]),
                         (14, "at 07:00Z, inside this crate's window"))
        # A plan before #791 names none, and the record adds none.
        older = nightly.merge({"files": []}, self.plan([], {}), self.base, {}, "200")[3]
        self.assertNotIn("max_parallel", older["runs"][-1])

    def test_a_run_with_a_tail_names_the_tail_in_the_record_sentence_791(self):
        import mutants_record as record
        window = {"max_parallel": 14, "max_parallel_reason": "at 03:00Z, inside this crate's window"}
        self.assertEqual(record.slots(window), "at 14 at a time, at 03:00Z, inside this crate's window; ")
        tail = dict(window, shards_tail=9, max_parallel_tail=6)
        self.assertEqual(record.slots(tail),
                         "at 14 at a time for the window's shards and the 9 after them at 6 (the tail "
                         "matrix, #791), at 03:00Z, inside this crate's window; ")
        self.assertEqual(record.slots({}), "at six at a time, ")

    def test_a_record_before_791_is_rewritten_byte_for_byte_791(self):
        import mutants_record as record
        census = Path(__file__).resolve().parents[2] / "docs" / "census"
        doc = json.loads((census / "mutants-2026-11-04.json").read_text())
        self.assertNotIn("max_parallel_reason", doc["runs"]["complete"])
        self.assertEqual(record.markdown_complete(doc),
                         (census / "mutants-2026-11-04.md").read_text())
        doc["runs"]["complete"].update(max_parallel=14, max_parallel_reason="at 07:00Z, inside this crate's window",
                          github_waits=["the macos-26-arm64 image failure | run 41861794622"])
        text = record.markdown_complete(doc)
        self.assertIn("(23 shards at 14 at a time, at 07:00Z, inside this crate's window; ", text)
        self.assertIn("\n- the macos-26-arm64 image failure | run 41861794622\n", text)
        with self.assertRaises(argparse.ArgumentTypeError):
            record.one_line("an incident\n## a heading")

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
