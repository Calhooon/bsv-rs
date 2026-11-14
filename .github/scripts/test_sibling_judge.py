"""Witnesses for the node oracle's judge (#97): one table per rule of sibling_judge.py, each case
named for what it refuses. Hermetic: no network; a fake of the one GitHub class that counts every
write; git objects in repositories built under a temporary directory (a sibling with the nine
corpora, an upstream of this crate, beta's clone the judge runs in)."""

import base64
import builtins
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "sibling_judge.py"
FIXTURES = HERE / "fixtures" / "sibling_judge"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sj = _load("sibling_judge")
sh = sj.sh

R = "Calhooon/bsv-rs"
RID = 1189676804
RUN = 43235378566
APP = 5700082
GREEN_LINE = "run_diff: GREEN (every divergence explained by a rule with its citation)\n"
ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent"}


def git(directory, *args, text=True):
    done = subprocess.run(["git", "-C", str(directory), *args], capture_output=True, check=True,
                          env={**os.environ, **ENV})
    return done.stdout.decode().strip() if text else done.stdout


def quiet(function, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = function(*args, **kwargs)
    return result, out.getvalue() + err.getvalue()


def corpus_lines(pin_kind):
    """The sibling's nine corpora, one entry each (gen with a withheld line); the second pin
    adds seed-2 and changes flow-1's line."""
    out = {}
    for name in sh.ALL:
        lines = [f'{{"id": "{name}-1", "tx": "00"}}']
        if name == "gen":
            lines.append('{"id": "gen-2", "tx": "WITHHELD: d8 (see corpus/INDEX.md)"}')
        if pin_kind == 2 and name == "seed":
            lines.append('{"id": "seed-2", "tx": "00"}')
        if pin_kind == 2 and name == "flow":
            lines[0] = '{"id": "flow-1", "tx": "01"}'
        out[name] = "\n".join(lines) + "\n"
    return out


class Seq(list):
    """Answers a path gives in turn, the last kept: GitHub's state moving between two reads."""


class GitHubFake:
    """The one GitHub class, replaced: answers by path, every write counted."""

    def __init__(self, answers):
        self.answers = answers
        self.writes = []
        self.reads = []
        self.download_bytes = b""
        self.post_errors = []

    def get(self, path):
        self.reads.append(path)
        answer = self.answers.get(path)
        if answer is None:
            raise sj.GitHubError(404, f"no answer for {path}")
        if isinstance(answer, Seq):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, Exception):
            raise answer
        return json.loads(json.dumps(answer))

    def download(self, path, dest):
        self.reads.append(path)
        Path(dest).write_bytes(self.download_bytes)
        return Path(dest)

    def post(self, path, body):
        self.writes.append((path, body))
        if self.post_errors:
            raise self.post_errors.pop(0)
        return {}


def handmade_zip(name, data, declared):
    """A zip of one stored member whose central directory declares `declared` bytes through a
    zip64 extra (a header no writer of this crate makes)."""
    crc = __import__("zlib").crc32(data)
    name_b = name.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc, len(data), len(data), len(name_b), 0)
    body = local + name_b + data
    extra = struct.pack("<HHQ", 1, 8, declared)
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 45, 45, 0, 0, 0, 0, crc, len(data), 0xFFFFFFFF,
                          len(name_b), len(extra), 0, 0, 0, 0, 0) + name_b + extra
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(body), 0)
    return body + central + end


class World:
    """A sibling, this crate's upstream and beta's clone, one GREEN artifact."""

    def __init__(self, root):
        self.root = Path(root)
        self.sibling = self.root / "sibling"
        self.pins = {}
        self.sibling.mkdir()
        git(self.sibling, "init", "-q")
        git(self.sibling, "config", "uploadpack.allowAnySHA1InWant", "true")
        for kind in (1, 2):
            (self.sibling / "harness" / "rules").mkdir(parents=True, exist_ok=True)
            (self.sibling / "harness" / "run").write_text("#!/bin/sh\nexit 2\n")
            (self.sibling / "harness" / "rules" / "bsv-rs.json").write_text('{"pin": "0.3.33"}')
            (self.sibling / "docs").mkdir(exist_ok=True)
            (self.sibling / "docs" / "PROVENANCE.md").write_text("pins\n")
            for name, text in corpus_lines(kind).items():
                directory = self.sibling / "corpus" / name
                directory.mkdir(parents=True, exist_ok=True)
                (directory / f"{name}.jsonl").write_text(text)
                (directory / "manifest.json").write_text(json.dumps({"file": f"{name}.jsonl", "sha256": "stale"}))
            git(self.sibling, "add", ".")
            git(self.sibling, "commit", "-q", "-m", f"pin {kind}")
            self.pins[kind] = git(self.sibling, "rev-parse", "HEAD")
        self.pin = self.pins[1]
        self.facts = {kind: self.stage(pin) for kind, pin in self.pins.items()}
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        git(self.upstream, "init", "-q", "-b", "beta")
        git(self.upstream, "config", "uploadpack.allowAnySHA1InWant", "true")
        self.trampoline_text = "name: sibling-judge\non: workflow_run\n"
        files = {
            "tests/sibling/PIN": f"{self.pin}\n",
            "tests/sibling/column.json": sh.column_text(self.column(1)),
            ".github/workflows/sibling-judge.yml": self.trampoline_text,
            ".github/workflows/sibling-run.yml": "name: sibling-run\n",
            ".github/workflows/ci.yml": "name: CI\n",
            "src/lib.rs": "//! crate\n",
            "CHANGELOG.md": "# Changelog\n",
        }
        self.beta = self.commit(files, "beta")
        git(self.upstream, "checkout", "-q", "-b", "main")
        self.write({"README.md": "main\n"})
        self.main = self.commit({}, "main")
        git(self.upstream, "checkout", "-q", "beta")
        self.judge = self.root / "judge"
        subprocess.run(["git", "clone", "-q", "--branch", "beta", str(self.upstream), str(self.judge)],
                       check=True, capture_output=True, env={**os.environ, **ENV})
        self.head = self.head_on({"src/lib.rs": "//! crate, changed\n"})

    def stage(self, pin):
        scratch = self.root / f"facts-{pin}"
        sh.stage(self.sibling, pin, sh.ALL, scratch)
        withheld = quiet(sh.drop_withheld, scratch, sh.ALL)[0]
        return {
            "rules_pin": "0.3.33",
            "withheld": withheld,
            "corpora": {n: {"corpus_sha256": sh.sha256_file(sh.corpus_file(scratch, n)), "withheld": withheld.get(n, 0)} for n in sh.ALL},
            "ids": {n: [json.loads(l)["id"] for l in sh.corpus_file(scratch, n).read_text().splitlines()] for n in sh.ALL},
        }

    def words(self, kind, overrides=None):
        out = {}
        for name in sh.ALL:
            out[name] = {entry: ["valid", None] for entry in self.facts[kind]["ids"][name]}
        for (name, entry), value in (overrides or {}).items():
            out[name][entry] = value
        return out

    def column(self, kind, words=None, **corpus_overrides):
        facts = self.facts[kind]
        corpora = {}
        for name in sh.ALL:
            n = len(facts["ids"][name])
            corpora[name] = {"corpus_sha256": facts["corpora"][name]["corpus_sha256"], "entries": n,
                             "agree_mempool": n, "agree_block": n, "undecided": 0, "aborts_as_witnesses": 0,
                             "unknown_messages": {}, "rules": []}
            corpora[name].update(corpus_overrides.get(name, {}))
        return {"sibling": self.pins[kind], "rules_pin": "0.3.33", "withheld": facts["withheld"], "notes": {},
                "corpora": corpora, "words": words or self.words(kind)}

    def write(self, files):
        for path, text in files.items():
            target = self.upstream / path
            if text is None:
                if target.is_symlink() or target.exists():
                    target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            target.write_text(text)

    def commit(self, files, message, base=None):
        if base:
            git(self.upstream, "checkout", "-q", "--detach", base)
        self.write(files)
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "-q", "--allow-empty", "-m", message)
        sha = git(self.upstream, "rev-parse", "HEAD")
        git(self.upstream, "checkout", "-q", "beta")
        return sha

    def head_on(self, files, message="head", base=None, extra=None):
        """A head on beta (or `base`): `files` written, `extra(path)` run in the upstream first."""
        git(self.upstream, "checkout", "-q", "--detach", base or self.beta)
        if extra:
            extra(self.upstream)
        self.write(files)
        git(self.upstream, "add", "-A")
        git(self.upstream, "commit", "-q", "--allow-empty", "-m", message)
        sha = git(self.upstream, "rev-parse", "HEAD")
        git(self.upstream, "checkout", "-q", "-f", "beta")
        return sha

    def raw_files(self, kind=1, head=None, pull_request=7, log=GREEN_LINE, words=None):
        facts = self.facts[kind]
        manifest, files = {}, {}
        for name in sh.ALL:
            n = len(facts["ids"][name])
            manifest[name] = {"corpus": "/proc/self/environ", "entries": n, "agree_mempool": n, "agree_block": n,
                              "undecided": 0, "aborts_as_witnesses": 0, "unknown_messages": {}, "rules": []}
            files[f"{name}.log"] = ("spec_recorded: ...\n" + log).encode()
            rows = (words or self.words(kind))[name]
            files[f"{sh.WORDS_DIR}/{name}.jsonl"] = "".join(
                json.dumps({"id": e, "rec": v, "spec": v, "mempool": v}) + "\n" for e, v in rows.items()).encode()
        files["bsv-rs/manifest.json"] = json.dumps(manifest).encode()
        files[sh.RUN_INFO] = json.dumps({"sibling": self.pins[kind], "rules_pin": "0.3.33", "tree": "/x",
                                         "corpora": list(sh.ALL), "withheld": facts["withheld"]}).encode()
        files[sh.STAMP] = json.dumps({"schema": 1, "head_sha": head or self.head, "pull_request": pull_request,
                                      "sibling": self.pins[kind], "rules_pin": "0.3.33",
                                      "corpora": {n: {"corpus_sha256": facts["corpora"][n]["corpus_sha256"],
                                                      "withheld": facts["corpora"][n]["withheld"]} for n in sh.ALL}}).encode()
        files["summary.txt"] = b"GREEN\n"
        return files

    @staticmethod
    def zipped(files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    def answers(self, head=None, event="pull_request", attempt=1, conclusion="success", artifacts=None):
        head = head or self.head
        run = json.loads((FIXTURES / f"run_{RUN}.json").read_text())
        run.update({"head_sha": head, "event": event, "run_attempt": attempt, "conclusion": conclusion})
        pr = {"number": 7, "state": "open", "head": {"sha": head, "ref": "lane/x", "repo": {"id": RID, "full_name": R}},
              "base": {"ref": "beta", "repo": {"id": RID}}}
        if artifacts is None:
            artifacts = [{"id": 99, "name": "sibling-raw", "expired": False, "size_in_bytes": 1000, "digest": "sha256:ab",
                          "created_at": "2026-11-12T10:02:11Z",
                          "workflow_run": {"id": RUN, "head_sha": head, "head_repository_id": RID}}]
        return {
            f"repos/{R}/actions/runs/{RUN}": run,
            f"repos/{R}/commits/{head}/pulls": [pr],
            f"repos/{R}/actions/workflows/sibling-run.yml/runs?head_sha={head}&per_page=100":
                {"workflow_runs": [dict(run)]},
            f"repos/Calhooon/bsv-script-lean/compare/{self.pin}...main": {"behind_by": 0, "ahead_by": 1},
            f"repos/Calhooon/bsv-script-lean/compare/{self.pins[2]}...main": {"behind_by": 0, "ahead_by": 0},
            f"repos/{R}/actions/runs/{RUN}/attempts/{attempt}": {"conclusion": conclusion, "run_started_at": "2026-11-12T10:00:07Z"},
            f"repos/{R}/actions/runs/{RUN}/attempts/{attempt}/jobs?per_page=100":
                {"jobs": [{"name": "raw", "steps": [{"name": "Set up job", "conclusion": "success"},
                                                    {"name": "Build the harness", "conclusion": "failure"}]}]},
            f"repos/{R}/actions/runs/{RUN}/artifacts?per_page=100&name=sibling-raw": {"artifacts": artifacts},
            f"repos/{R}/commits/{head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100": {"check_runs": []},
        }

    def args(self, **overrides):
        values = dict(dry_run=False, run_id=RUN, attempt=None, repository=R, repository_id=RID,
                      workflow_sha=self.main, judge=str(self.judge), sibling_url=str(self.sibling), sibling=None,
                      temp=str(self.root), output=str(self.root / "out.txt"), artifact=None, head=None, beta=None,
                      pull_request=None, offline=False)
        values.update(overrides)
        return types.SimpleNamespace(**values)


class Base(unittest.TestCase):
    world = None

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.world = World(cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def judged(self, head=None, files=None, answers=None, **args):
        w = self.world
        head = head or w.head
        gh = GitHubFake(answers if answers is not None else w.answers(head=head))
        gh.download_bytes = w.zipped(files if files is not None else w.raw_files(head=head))
        check, log = quiet(sj.judge, w.args(**args), gh, None)
        return check, gh, log

    def assertCheck(self, check, word, needle=None):
        self.assertEqual(check.post, "yes", check.title)
        self.assertEqual(check.conclusion, "failure", check.title)
        self.assertTrue(check.title.startswith(word), check.title)
        if needle:
            self.assertIn(needle, check.title + "\n" + check.text)


class Green(Base):
    def test_a_green_artifact_is_success_and_writes_nothing(self):
        check, gh, _ = self.judged()
        self.assertEqual((check.conclusion, check.title, check.post), ("success", "GREEN", "yes"), check.text)
        self.assertEqual(gh.writes, [])
        self.assertIn(f"head {self.world.head}", check.text)
        self.assertIn("artifact 99 digest sha256:ab", check.text)

    def test_the_moved_fixture_is_green_and_one_planted_divergence_red_naming_the_entry(self):
        w = self.world
        with tempfile.TemporaryDirectory() as scratch:
            tree = Path(scratch) / "raw"
            for name, data in w.raw_files().items():
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                (tree / name).write_bytes(data)
            (tree / "spec").mkdir()
            (tree / "spec" / "unlisted.txt").write_text("not packed")
            data = sj.pack(tree, None)
        moved = Path(self.dir.name) / "moved.zip"
        moved.write_bytes(data)
        self.assertFalse(tree.exists())
        files = sj.read_artifact(moved.read_bytes())
        check, _, _ = self.judged(files=files)
        self.assertEqual(check.conclusion, "success", check.text)
        files = dict(files)
        files["seed.log"] = (b"run_diff: RED (1 unexplained divergences, 0 messages outside the table, 0 recorded "
                             b"bsv-rs verdicts disagreeing)\n  UNEXPLAINED spec seed-1 (f, rule r): spec valid vs bsv-rs invalid\n")
        check, _, _ = self.judged(files=files)
        self.assertCheck(check, "RED", "UNEXPLAINED spec seed-1")

    def test_a_manifests_corpus_path_is_never_opened(self):
        opened = []
        real = builtins.open

        def spy(path, *a, **k):
            opened.append(str(path))
            return real(path, *a, **k)

        with mock.patch("builtins.open", spy), mock.patch("io.open", spy):
            check, _, _ = self.judged()
        self.assertEqual(check.conclusion, "success", check.text)
        self.assertNotIn("/proc/self/environ", opened)


class HostileArtifact(Base):
    def refused(self, data, needle):
        with self.assertRaisesRegex(sh.Stop, needle):
            sj.read_artifact(data)
        gh = GitHubFake(self.world.answers())
        gh.download_bytes = data
        check, _ = quiet(sj.judge, self.world.args(), gh, None)
        self.assertCheck(check, "NOT JUDGED", "refused")
        self.assertEqual(gh.writes, [])

    def with_member(self, name, data=b"x"):
        files = self.world.raw_files()
        files[name] = data
        return self.world.zipped(files)

    def test_a_member_named_dot_dot_is_refused(self):
        self.refused(self.with_member("../x"), "leaves the artifact")

    def test_a_member_with_a_leading_slash_is_refused(self):
        self.refused(self.with_member("/etc/x"), "leaves the artifact")

    def test_a_symlink_member_is_refused(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in self.world.raw_files().items():
                if name != "summary.txt":
                    archive.writestr(name, data)
            info = zipfile.ZipInfo("summary.txt")
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "/etc/passwd")
        self.refused(buffer.getvalue(), "symlink")

    def test_a_repeated_member_is_refused(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in self.world.raw_files().items():
                archive.writestr(name, data)
            with self.assertWarns(UserWarning):
                archive.writestr("seed.log", b"run_diff: GREEN\n")
        self.refused(buffer.getvalue(), "repeated")

    def test_an_unlisted_member_is_refused(self):
        self.refused(self.with_member("spec/seed.json"), "allowlist")

    def test_a_member_declared_at_ten_gigabytes_is_refused_before_a_byte_is_inflated(self):
        self.refused(handmade_zip("seed.log", b"run_diff: GREEN\n", 10 << 30), "declared at 10737418240")

    def test_an_artifact_over_64_mib_is_refused(self):
        with self.assertRaisesRegex(sh.Stop, "over 67108864"):
            sj.read_artifact(b"\0" * (sj.ARTIFACT_LIMIT + 1))

    def test_json_nested_ten_thousand_deep_is_refused(self):
        files = self.world.raw_files()
        files[sh.STAMP] = b"[" * 10000 + b"]" * 10000
        check, gh, _ = self.judged(files=files)
        # Python's reader either stops at its recursion bound or reads a list: a refusal either way
        self.assertCheck(check, "NOT JUDGED", "the artifact's stamp")

    def test_an_unknown_schema_is_refused(self):
        files = self.world.raw_files()
        stamp = json.loads(files[sh.STAMP])
        stamp["schema"] = 2
        files[sh.STAMP] = json.dumps(stamp).encode()
        check, _, _ = self.judged(files=files)
        self.assertCheck(check, "NOT JUDGED", "unknown schema")

    def test_a_stamp_differing_from_the_run_in_its_sha_pin_or_pull_request_is_refused(self):
        for key, value, needle in (("head_sha", "0" * 40, "head sha: stamp"), ("sibling", "1" * 40, "pin: stamp"),
                                   ("pull_request", 8, "pull request: stamp")):
            with self.subTest(key):
                files = self.world.raw_files()
                stamp = json.loads(files[sh.STAMP])
                stamp[key] = value
                files[sh.STAMP] = json.dumps(stamp).encode()
                check, gh, _ = self.judged(files=files)
                self.assertCheck(check, "NOT JUDGED", needle)
                self.assertEqual(gh.writes, [])


class Identity(Base):
    """A run that fails the identity gets no check: post `no`, zero writes."""

    def silent(self, change):
        answers = self.world.answers()
        change(answers)
        check, gh, log = self.judged(answers=answers)
        self.assertEqual(check.post, "no", check.title)
        self.assertEqual(check.conclusion, "failure")
        self.assertEqual(gh.writes, [])
        self.assertIn("sibling_judge: no check:", log)
        return log

    def the_run(self, answers):
        return answers[f"repos/{R}/actions/runs/{RUN}"]

    def pulls(self, answers):
        return answers[f"repos/{R}/commits/{self.world.head}/pulls"]

    def test_a_foreign_head_repository_is_silent(self):
        # the witness of a fork's run: no real fork is used (the lane record says so)
        self.silent(lambda a: self.the_run(a)["head_repository"].update(id=1))

    def test_no_pull_request_is_silent(self):
        self.silent(lambda a: self.pulls(a).clear())

    def test_a_closed_pull_request_is_silent(self):
        self.silent(lambda a: self.pulls(a)[0].update(state="closed"))

    def test_a_base_of_main_is_silent(self):
        self.silent(lambda a: self.pulls(a)[0]["base"].update(ref="main"))

    def test_a_head_that_moved_on_is_silent(self):
        self.silent(lambda a: self.pulls(a)[0]["head"].update(sha="f" * 40))

    def test_a_push_event_is_silent(self):
        self.silent(lambda a: self.the_run(a).update(event="push"))

    def test_another_files_path_under_the_name_sibling_run_is_silent(self):
        self.silent(lambda a: self.the_run(a).update(path=".github/workflows/other.yml", name="sibling-run"))

    def test_the_saved_runs_read_as_github_answered_them(self):
        saved = json.loads((FIXTURES / f"run_{RUN}.json").read_text())
        self.assertEqual((saved["run_attempt"], saved["event"], saved["conclusion"], saved["pull_requests"]),
                         (2, "pull_request", "success", []))
        dispatch = json.loads((FIXTURES / "run_41877431322.json").read_text())
        self.assertEqual((dispatch["event"], dispatch["conclusion"]), ("workflow_dispatch", "cancelled"))
        # the empty pull_requests is never read: the pull request is asked of the commit
        w = self.world
        answers = w.answers(attempt=2)
        check, _, _ = self.judged(answers=answers, attempt=2)
        self.assertEqual(check.conclusion, "success", check.text)
        answers = w.answers(event="workflow_dispatch", conclusion="cancelled")
        check, gh, _ = self.judged(answers=answers)
        self.assertCheck(check, "NOT JUDGED", "stage R ended cancelled")


class Classes(Base):
    def test_every_tracked_path_has_one_class_and_the_named_paths_are_the_tables(self):
        top = subprocess.run(["git", "-C", str(HERE), "rev-parse", "--show-toplevel"], capture_output=True,
                             check=True, text=True).stdout.strip()
        tracked = subprocess.run(["git", "-C", top, "ls-files", "-z"], capture_output=True, check=True).stdout
        paths = [p for p in tracked.decode().split("\0") if p]
        self.assertGreater(len(paths), 100)
        for path in paths:
            self.assertIn(sj.class_of(path), ("P", "W", "N", "J", "C"), path)
        for path in sj.NAMED_CRATE:
            self.assertEqual(sj.class_of(path), "C", path)
        self.assertEqual(sj.class_of("tests/sibling/PIN"), "P")
        self.assertEqual(sj.class_of("tests/sibling/column.json"), "W")
        self.assertEqual(sj.class_of("tests/sibling/CLAUDE.md"), "N")
        for path in (".github/scripts/sibling_harness.py", ".github/scripts/sibling_words.rs",
                     ".github/scripts/test_sibling_judge.py", ".github/scripts/fixtures/sibling_judge/run_1.json",
                     ".github/workflows/sibling-run.yml", ".github/workflows/sibling-judge.yml",
                     "tests/sibling/other.txt", "tests/arch_ci_sibling_judge_97.rs"):
            self.assertEqual(sj.class_of(path), "J", path)
        for path in ("CHANGELOG.md", "docs/lanes/x.md", "docs/ratchets.json", "src/script/CLAUDE.md"):
            self.assertEqual(sj.class_of(path), "N", path)
        for path in (".github/scripts/json.py", "README.md", "src/lib.rs", "build.rs"):
            self.assertEqual(sj.class_of(path), "C", path)

    def refused(self, head, needle):
        check, gh, _ = self.judged(head=head, files=self.world.raw_files(head=head))
        self.assertCheck(check, "REFUSED", needle)
        self.assertEqual(gh.writes, [])
        return check

    def test_three_hundred_and_one_files_with_the_pin_last_are_all_read(self):
        w = self.world
        files = {f"src/many/f{i:03}.rs": "x\n" for i in range(300)}
        files["tests/sibling/PIN"] = f"{w.pins[2]}\n"
        self.refused(w.head_on(files), "the pin and the crate")

    def test_a_rename_out_of_a_judge_path_is_its_old_name_deleted(self):
        w = self.world
        head = w.head_on({}, extra=lambda up: git(up, "mv", ".github/workflows/sibling-run.yml", "src/run.yml"))
        self.refused(head, "the judge and the crate")

    def test_a_symlink_at_the_pin_is_refused(self):
        w = self.world

        def link(up):
            (up / "tests/sibling/PIN").unlink()
            os.symlink("column.json", up / "tests/sibling/PIN")

        self.refused(w.head_on({}, extra=link), "mode 120000")

    def test_mode_100755_at_a_judge_path_is_refused(self):
        w = self.world
        head = w.head_on({}, extra=lambda up: (up / ".github/workflows/sibling-run.yml").chmod(0o755))
        self.refused(head, "mode 100755")

    def test_the_judge_with_the_column_is_refused(self):
        w = self.world
        column = w.column(1, words=w.words(1, {("seed", "seed-1"): ["valid", "x"]}))
        self.refused(w.head_on({".github/workflows/sibling-run.yml": "changed\n",
                                "tests/sibling/column.json": sh.column_text(column)}), "the judge and the column")

    def test_the_judge_with_the_crate_is_refused(self):
        self.refused(self.world.head_on({".github/workflows/sibling-run.yml": "changed\n", "src/lib.rs": "y\n"}),
                     "the judge and the crate")

    def test_the_pin_with_the_crate_is_refused(self):
        w = self.world
        self.refused(w.head_on({"tests/sibling/PIN": f"{w.pins[2]}\n",
                                "tests/sibling/column.json": sh.column_text(w.column(2)), "src/lib.rs": "y\n"}),
                     "the pin and the crate")

    def test_words_alone_is_judged_and_green(self):
        head = self.world.head_on({"CHANGELOG.md": "# Changelog\n\nmore\n"})
        check, _, _ = self.judged(head=head, files=self.world.raw_files(head=head))
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), check.text)

    def test_the_column_alone_is_judged_against_the_artifact(self):
        w = self.world
        words = w.words(1, {("seed", "seed-1"): ["valid", "reworded"]})
        head = w.head_on({"tests/sibling/column.json": sh.column_text(w.column(1, words=words))})
        check, _, _ = self.judged(head=head, files=w.raw_files(head=head, words=words))
        self.assertEqual(check.conclusion, "success", check.text)
        check, _, _ = self.judged(head=head, files=w.raw_files(head=head))
        self.assertCheck(check, "RED", "seed seed-1")

    def test_the_crate_with_the_column_and_words_is_green(self):
        w = self.world
        words = w.words(1, {("seed", "seed-1"): ["valid", "reworded"]})
        head = w.head_on({"src/lib.rs": "z\n", "CHANGELOG.md": "c\n",
                          "tests/sibling/column.json": sh.column_text(w.column(1, words=words))})
        check, _, _ = self.judged(head=head, files=w.raw_files(head=head, words=words))
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), check.text)

    def test_a_judge_change_is_titled_so_green_and_red(self):
        w = self.world
        head = w.head_on({".github/workflows/sibling-run.yml": "changed\n"})
        check, _, _ = self.judged(head=head, files=w.raw_files(head=head))
        self.assertEqual((check.conclusion, check.title), ("success", "JUDGE CHANGE: .github/workflows/sibling-run.yml"))
        files = w.raw_files(head=head, words=w.words(1, {("seed", "seed-1"): ["invalid", "x"]}))
        check, _, _ = self.judged(head=head, files=files)
        self.assertCheck(check, "RED (JUDGE CHANGE: .github/workflows/sibling-run.yml)")

    def test_a_head_behind_beta_is_refused_with_its_count(self):
        w = self.world
        old = w.beta
        newer = w.commit({"src/lib.rs": "//! beta moved\n"}, "beta 2")
        newer2 = w.commit({"src/lib.rs": "//! beta moved again\n"}, "beta 3")
        git(w.judge, "fetch", "-q", "origin", "beta")
        git(w.judge, "reset", "-q", "--hard", newer2)
        try:
            head = w.head_on({"src/lib.rs": "y\n"}, base=old)
            check = self.refused(head, "behind beta by 2 commits")
            self.assertIn("rebase", check.text)
        finally:
            git(w.upstream, "reset", "-q", "--hard", old)
            git(w.judge, "reset", "-q", "--hard", old)
            self.assertNotEqual(newer, old)


class Pin(Base):
    def refused(self, pin_text, needle, word="REFUSED"):
        w = self.world
        head = w.head_on({"tests/sibling/PIN": pin_text})
        check, gh, _ = self.judged(head=head, files=w.raw_files(head=head))
        self.assertCheck(check, word, needle)
        self.assertEqual(gh.writes, [])

    def test_the_pins_text_is_refused_unless_forty_lower_hex_and_a_newline(self):
        pin = self.world.pin
        for name, text in (("39 digits", pin[:39] + "\n"), ("upper case", pin.upper() + "\n"),
                           ("no newline", pin), ("two lines", pin + "\n" + pin + "\n")):
            with self.subTest(name):
                self.refused(text, "40 lower-case hex digits")

    def test_a_pin_other_than_the_stamps_is_not_judged(self):
        w = self.world
        head = w.head_on({"tests/sibling/PIN": f"{w.pins[2]}\n", "tests/sibling/column.json": sh.column_text(w.column(2))})
        check, _, _ = self.judged(head=head, files=w.raw_files(head=head))
        self.assertCheck(check, "NOT JUDGED", "pin: stamp")

    def test_a_pin_other_than_betas_outside_a_pin_change_is_refused(self):
        w = self.world
        j = sj.Judgment(None, sj.Git(w.judge), w.root, str(w.sibling))
        j.unmade, j.head, j.beta, j.kind = [], w.head_on({"tests/sibling/PIN": f"{w.pins[2]}\n"}), w.beta, "C"
        git(w.judge, "fetch", "-q", "origin", j.head)
        with self.assertRaises(sj.Verdict) as caught:
            j.check_pin()
        self.assertEqual((caught.exception.word, caught.exception.reason), ("REFUSED", "the pin moved outside a pin change"))

    def test_a_pin_behind_the_siblings_main_is_refused(self):
        answers = self.world.answers()
        answers[f"repos/Calhooon/bsv-script-lean/compare/{self.world.pin}...main"] = {"behind_by": 1, "ahead_by": 0}
        check, _, _ = self.judged(answers=answers)
        self.assertCheck(check, "REFUSED", "behind_by 1")

    def test_a_pin_the_sibling_does_not_carry_is_refused(self):
        answers = self.world.answers()
        answers[f"repos/Calhooon/bsv-script-lean/compare/{self.world.pin}...main"] = sj.GitHubError(404, "no")
        check, _, _ = self.judged(answers=answers)
        self.assertCheck(check, "REFUSED", "not a commit of the sibling")


class ColumnRules(Base):
    def column_head(self, column):
        return self.world.head_on({"tests/sibling/column.json": sh.column_text(column)})

    def refused(self, head, needle, files=None):
        w = self.world
        check, gh, _ = self.judged(head=head, files=files or w.raw_files(head=head))
        self.assertCheck(check, "REFUSED", needle)
        self.assertEqual(gh.writes, [])

    def test_an_explained_row_is_refused(self):
        w = self.world
        self.refused(self.column_head(w.column(1, seed={"rules": [{"column": "spec", "rule": "r", "entries": 1, "witness": "w"}]})),
                     "explained row")

    def test_an_abort_witness_is_refused(self):
        self.refused(self.column_head(self.world.column(1, seed={"aborts_as_witnesses": 1})), "explained row or an abort")

    def test_a_column_not_recorded_at_the_pin_is_refused(self):
        w = self.world
        for key, value, needle in (("sibling", "2" * 40, "sibling: column"), ("rules_pin", "9.9.9", "rules_pin: column"),
                                   ("withheld", {"gen": 2}, "withheld: column")):
            with self.subTest(key):
                column = w.column(1)
                column[key] = value
                self.refused(self.column_head(column), needle)
        self.refused(self.column_head(w.column(1, seed={"corpus_sha256": "00"})), "seed corpus_sha256: column 00")

    def test_outside_a_pin_change_a_count_moved_is_refused(self):
        self.refused(self.column_head(self.world.column(1, seed={"agree_block": 0})), "seed agree_block")

    def test_outside_a_pin_change_a_verdict_moved_is_refused(self):
        w = self.world
        words = w.words(1, {("seed", "seed-1"): ["invalid", "now refused"]})
        self.refused(self.column_head(w.column(1, words=words)), "seed seed-1 verdicts")

    def pin_head(self, column, **files):
        w = self.world
        return w.head_on({"tests/sibling/PIN": f"{w.pins[2]}\n", "tests/sibling/column.json": sh.column_text(column), **files})

    def test_a_pin_move_recorded_at_the_new_pin_is_green(self):
        w = self.world
        head = self.pin_head(w.column(2))
        check, _, _ = self.judged(head=head, files=w.raw_files(kind=2, head=head))
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), check.text)

    def test_a_pin_move_that_changes_an_entrys_line_may_reword_it(self):
        w = self.world
        words = w.words(2, {("flow", "flow-1"): ["valid", "new words"]})
        head = self.pin_head(w.column(2, words=words))
        check, _, _ = self.judged(head=head, files=w.raw_files(kind=2, head=head, words=words))
        self.assertEqual(check.conclusion, "success", check.text)

    def test_a_pin_move_rewording_an_unchanged_entry_is_refused(self):
        w = self.world
        words = w.words(2, {("seed", "seed-1"): ["valid", "new words"]})
        head = self.pin_head(w.column(2, words=words))
        self.refused(head, "seed seed-1: unchanged by the pin move", w.raw_files(kind=2, head=head, words=words))

    def test_a_pin_move_dropping_a_judged_entry_is_refused(self):
        w = self.world
        words = w.words(2)
        del words["arith"]["arith-1"]
        head = self.pin_head(w.column(2, words=words))
        self.refused(head, "arith arith-1: a judged entry is dropped", w.raw_files(kind=2, head=head, words=words))

    def test_a_pin_move_dropping_a_corpus_or_growing_withheld_is_refused(self):
        w = self.world
        column = w.column(2)
        j = sj.Judgment(None, sj.Git(w.judge), w.root, str(w.sibling))
        j.unmade, j.kind, j.pin = [], "P", w.pins[2]
        beta = w.column(1)
        beta["corpora"]["extra"] = beta["corpora"]["seed"]
        beta["withheld"] = {}
        head = self.pin_head(column)
        git(w.judge, "fetch", "-q", "origin", head)
        j.head, j.beta = head, w.beta
        facts = sj.Facts(w.sibling, w.pins[2], Path(self.dir.name) / "facts-a")
        with mock.patch.object(j, "blob_at", side_effect=lambda sha, path, *a: (
                sh.column_text(column) if sha == head else sh.column_text(beta)).encode()):
            with self.assertRaises(sj.Verdict) as caught:
                j.check_column(facts, facts)
        self.assertIn("extra: a corpus of beta's column is dropped", caught.exception.quoted)
        self.assertIn("gen withheld: beta 0, head 1", caught.exception.quoted)


class RunState(Base):
    def test_each_conclusion_but_success_names_itself_and_the_failed_step(self):
        for conclusion in ("failure", "cancelled", "timed_out", "startup_failure", "action_required"):
            with self.subTest(conclusion):
                check, gh, _ = self.judged(answers=self.world.answers(conclusion=conclusion))
                self.assertCheck(check, "NOT JUDGED", f"stage R ended {conclusion}")
                self.assertIn("raw: Build the harness", check.text)
                self.assertNotIn(f"repos/{R}/actions/artifacts/99/zip", gh.reads)

    def artifacts(self, artifacts, event="pull_request"):
        return self.judged(answers=self.world.answers(artifacts=artifacts, event=event))[0]

    def one(self, **overrides):
        item = {"id": 99, "name": "sibling-raw", "expired": False, "size_in_bytes": 1000, "digest": "d",
                "created_at": "2026-11-12T10:02:11Z",
                "workflow_run": {"id": RUN, "head_sha": self.world.head, "head_repository_id": RID}}
        item.update(overrides)
        return item

    def test_no_artifact_two_artifacts_and_an_expired_one_are_not_judged(self):
        for name, listing in (("none", []), ("two", [self.one(), self.one(id=100)]), ("expired", [self.one(expired=True)]),
                              ("another run's", [self.one(workflow_run={"id": 1, "head_sha": self.world.head, "head_repository_id": RID})])):
            with self.subTest(name):
                check = self.artifacts(listing)
                self.assertCheck(check, "NOT JUDGED", "unexpired sibling-raw artifacts of attempt 1, not one")

    def test_a_dispatch_whose_artifact_is_gone_posts_unless_standing(self):
        check = self.artifacts([self.one(expired=True)], event="workflow_dispatch")
        self.assertEqual((check.post, check.conclusion), ("unless-standing", "failure"))


LISTING = "repos/{R}/actions/workflows/sibling-run.yml/runs?head_sha={head}&per_page=100"


def with_run(world, answers, run_id, status="completed", event="workflow_dispatch", attempt=1, **fields):
    """`answers` with a second stage R run of the head: its record, its attempt and its artifact,
    listed beside the first. Returns the run's record (edit it to move its state)."""
    head = answers[f"repos/{R}/actions/runs/{RUN}"]["head_sha"]
    run = {**answers[f"repos/{R}/actions/runs/{RUN}"], "id": run_id, "status": status, "event": event,
           "run_attempt": attempt, "conclusion": "success" if status == "completed" else None, **fields}
    answers[f"repos/{R}/actions/runs/{run_id}"] = run
    answers[f"repos/{R}/actions/runs/{run_id}/attempts/{attempt}"] = {"conclusion": "success",
                                                                        "run_started_at": "2026-11-12T10:00:07Z"}
    answers[f"repos/{R}/actions/runs/{run_id}/artifacts?per_page=100&name=sibling-raw"] = {"artifacts": [
        {"id": run_id % 1000, "name": "sibling-raw", "expired": False, "size_in_bytes": 1000, "digest": "d",
         "created_at": "2026-11-12T10:02:11Z", "workflow_run": {"id": run_id, "head_sha": head, "head_repository_id": RID}}]}
    answers[LISTING.format(R=R, head=head)]["workflow_runs"].append(run)
    return run


class Interleavings(Base):
    """One verdict per head (#97, fix-97c): a judgement of a stage R run judges the newest stage R
    run of its head at its latest attempt, waiting (up to `--wait`) for one still running; the
    identity is read on the run judged. One test per row of the table in docs/lanes/fix-97c.md:
    which invocation posts, and which run's verdict. Witness 11 (#947) is row 1: the pull
    request's run judged by its event, the token's dispatch newer and never judged by an event."""

    def judge_of(self, answers, run_id=RUN, wait=0, attempt=None):
        w = self.world
        gh = GitHubFake(answers)
        gh.download_bytes = w.zipped(w.raw_files())
        slept = []
        check, log = quiet(sj.judge, w.args(run_id=run_id, attempt=attempt, wait=wait, sleep=slept.append), gh, None)
        return check, gh, log, slept

    def judged_run(self, gh):
        """The run whose artifact the judgement read."""
        zips = [r for r in gh.reads if r.endswith("/zip")]
        runs = [r for r in gh.reads if r.endswith("&name=sibling-raw")]
        self.assertEqual(len(zips), 1, gh.reads)
        return int(runs[-1].split("/runs/")[1].split("/")[0])

    def test_row1_the_pull_requests_run_then_a_token_dispatch_still_running_is_waited_for_and_judged(self):
        w = self.world
        answers = w.answers()
        newer = with_run(w, answers, RUN + 1, status="in_progress")
        done = {**newer, "status": "completed", "conclusion": "success"}
        listing = answers[LISTING.format(R=R, head=w.head)]
        answers[LISTING.format(R=R, head=w.head)] = Seq([json.loads(json.dumps(listing)),
                                                         {"workflow_runs": [listing["workflow_runs"][0], done]}])
        answers[f"repos/{R}/actions/runs/{RUN + 1}"] = done
        check, gh, log, slept = self.judge_of(answers, wait=300)
        self.assertEqual((check.post, check.conclusion, check.title), ("yes", "success", "GREEN"), log + check.text)
        self.assertEqual(self.judged_run(gh), RUN + 1)
        self.assertEqual(slept, [sj.POLL_SECONDS])
        self.assertIn(f"stage R run {RUN + 1} attempt 1", check.text)
        self.assertIn(f"Called for run {RUN}", check.text)

    def test_row1_a_newer_run_still_running_after_the_wait_posts_nothing_and_names_it(self):
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="in_progress")
        check, gh, log, slept = self.judge_of(answers, wait=60)
        self.assertEqual((check.post, gh.writes), ("no", []))
        self.assertEqual(slept, [sj.POLL_SECONDS] * 4)
        self.assertIn(f"run {RUN + 1} attempt 1, is still running", log)

    def test_row2_a_token_dispatch_then_the_pull_requests_run_judges_the_pull_requests(self):
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN - 1, status="completed")
        check, gh, log, slept = self.judge_of(answers, wait=300)
        self.assertEqual((check.conclusion, check.title, slept), ("success", "GREEN", []), log)
        self.assertEqual(self.judged_run(gh), RUN)

    def test_row2_the_older_runs_judge_after_the_newer_completed_judges_the_newer(self):
        """The dispatch's own judgement (the sync's step dispatches the judge with its id) arriving
        after a newer pull request run completed: the newer is judged, never the older."""
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed", event="pull_request")
        check, gh, log, _ = self.judge_of(answers)
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), log + check.text)
        self.assertEqual(self.judged_run(gh), RUN + 1)

    def test_row3_a_reruns_newer_attempt_completed_is_judged_and_running_is_waited_for(self):
        w = self.world
        answers = w.answers(attempt=2)
        check, gh, log, _ = self.judge_of(answers, attempt=1)
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), log + check.text)
        self.assertIn(f"repos/{R}/actions/runs/{RUN}/attempts/2", gh.reads)
        self.assertIn(f"stage R run {RUN} attempt 2", check.text)
        answers = w.answers(attempt=2)
        answers[LISTING.format(R=R, head=w.head)]["workflow_runs"][0]["status"] = "in_progress"
        check, gh, log, _ = self.judge_of(answers, attempt=1)
        self.assertEqual((check.post, gh.writes), ("no", []))
        self.assertIn(f"run {RUN} attempt 2, is still running", log)

    def test_row4_two_pushes_inside_a_minute_the_older_heads_run_posts_nothing(self):
        """The older head's run (cancelled by stage R's own group, or completed) is judged on a
        head no open pull request holds: no check; the newer head's run is judged by its own."""
        w = self.world
        for conclusion in ("cancelled", "success"):
            with self.subTest(conclusion):
                answers = w.answers(conclusion=conclusion)
                answers[f"repos/{R}/commits/{w.head}/pulls"][0]["head"]["sha"] = "f" * 40
                check, gh, log, _ = self.judge_of(answers)
                self.assertEqual((check.post, gh.writes), ("no", []))
                self.assertIn("no open pull request into beta", log)

    def test_row5_a_hand_rejudge_of_an_older_run_judges_the_newest_as_the_events_judge_does(self):
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed", event="pull_request")
        by_hand, gh_hand, _, _ = self.judge_of(answers, run_id=RUN)
        by_event, gh_event, _, _ = self.judge_of(answers, run_id=RUN + 1, attempt=1)
        self.assertEqual((by_hand.title, by_hand.conclusion), (by_event.title, by_event.conclusion))
        self.assertEqual(self.judged_run(gh_hand), self.judged_run(gh_event))
        self.assertEqual(self.judged_run(gh_hand), RUN + 1)

    def test_row6_a_newer_run_that_is_no_stage_r_run_of_this_repository_is_not_judged_and_silences_nothing(self):
        w = self.world
        for name, fields in (("a fork's", {"head_repository": {"id": 1}}),
                             ("another path's", {"path": ".github/workflows/other.yml"}),
                             ("a push run", {"event": "push"})):
            with self.subTest(name):
                answers = w.answers()
                with_run(w, answers, RUN + 1, status="in_progress", **fields)
                check, gh, log, slept = self.judge_of(answers, wait=300)
                self.assertEqual((check.conclusion, check.title, slept), ("success", "GREEN", []), log)
                self.assertEqual(self.judged_run(gh), RUN)

    def test_the_identity_is_read_on_the_run_judged(self):
        """The newer run's head is the caller's (one listing per head); a run called with a
        foreign path is silent before any listing is read."""
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        answers[f"repos/{R}/actions/runs/{RUN + 1}"] = {**answers[f"repos/{R}/actions/runs/{RUN + 1}"], "event": "push"}
        check, gh, log, _ = self.judge_of(answers)
        self.assertEqual((check.post, gh.writes), ("no", []))
        self.assertIn(f"run {RUN + 1}'s event is not pull_request or workflow_dispatch", log)
        answers = w.answers()
        answers[f"repos/{R}/actions/runs/{RUN}"]["path"] = ".github/workflows/other.yml"
        check, gh, log, _ = self.judge_of(answers)
        self.assertEqual(check.post, "no")
        self.assertNotIn(LISTING.format(R=R, head=w.head), gh.reads)


class Timeouts(Base):
    """A `gh` or `git` call that hangs (#958): every call carries a timeout, and a call that passes
    it is the named error of its class (`GitHubError` naming the path, `sh.Stop` naming the git
    command), so the arms that already answer a failed read answer a hung one: `judge` writes
    `NOT JUDGED` with the re-judge, `report` exits 1 naming the read. Until #958 the call had no
    timeout: a hung one spent the job's ten minutes and the log named no call."""

    @staticmethod
    def hung(only=None):
        real = subprocess.run
        calls = []

        def run(command, *args, **kwargs):
            if only is None or command[0] == only:
                calls.append((command, kwargs))
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
            return real(command, *args, **kwargs)
        return run, calls

    def test_a_gh_call_that_hangs_is_a_github_error_naming_the_path_958(self):
        path = f"repos/{R}/actions/runs/{RUN}"
        for name, call in (("get", lambda gh: gh.get(path)),
                           ("download", lambda gh: gh.download(path + "/zip", Path(self.dir.name) / "hung.zip")),
                           ("post", lambda gh: gh.post(f"repos/{R}/check-runs", {"name": "x"}))):
            with self.subTest(name):
                run, calls = self.hung()
                with mock.patch.object(sj.subprocess, "run", run):
                    with self.assertRaises(sj.GitHubError) as caught:
                        call(sj.GitHub())
                self.assertEqual(caught.exception.status, 0)
                self.assertIn("did not answer within", str(caught.exception))
                self.assertIn(f"repos/{R}/", str(caught.exception))
                self.assertEqual(len(calls), 1)
                timeout = calls[0][1].get("timeout")
                self.assertIsInstance(timeout, int)
                self.assertTrue(0 < timeout <= 120, timeout)

    def test_a_gh_that_cannot_be_run_is_a_github_error_958(self):
        def absent(command, *args, **kwargs):
            raise FileNotFoundError(command[0])
        with mock.patch.object(sj.subprocess, "run", absent):
            with self.assertRaises(sj.GitHubError) as caught:
                sj.GitHub().get(f"repos/{R}/actions/runs/{RUN}")
        self.assertIn("could not be run (FileNotFoundError)", str(caught.exception))

    def test_a_git_call_that_hangs_is_a_stop_naming_the_command_958(self):
        run, calls = self.hung()
        with mock.patch.object(sj.subprocess, "run", run):
            with self.assertRaises(sh.Stop) as caught:
                sj.Git(self.world.judge).run("fetch", "--quiet", "origin", "0" * 40)
        self.assertIn("git fetch did not end within", str(caught.exception))
        self.assertIsInstance(calls[0][1].get("timeout"), int)

    def test_a_judgement_whose_read_hangs_is_not_judged_with_the_rejudge_of_the_run_called_958(self):
        w = self.world
        run, _ = self.hung(only="gh")
        with mock.patch.object(sj.subprocess, "run", run):
            check, log = quiet(sj.judge, w.args(), sj.GitHub(), None)
        self.assertCheck(check, "NOT JUDGED", "the judge could not read what it needs")
        self.assertIn(f"gh api repos/{R}/actions/runs/{RUN} did not answer within", check.text)
        self.assertIn(f"gh workflow run sibling-judge.yml --repo {R} --ref main -f run_id={RUN}", check.text)

    def test_a_hung_fetch_of_the_head_is_not_judged_958(self):
        w = self.world
        head = w.head_on({"src/hung.rs": "// a head the judge's clone has not fetched\n"}, "hung")
        real = subprocess.run

        def run(command, *args, **kwargs):
            if command[0] == "git" and "fetch" in command and head in command:
                raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
            return real(command, *args, **kwargs)
        gh = GitHubFake(w.answers(head=head))
        with mock.patch.object(sj.subprocess, "run", run):
            check, _ = quiet(sj.judge, w.args(), gh, None)
        self.assertCheck(check, "NOT JUDGED", "git fetch did not end within")
        self.assertEqual(gh.writes, [])

    def test_a_report_whose_read_hangs_exits_one_naming_the_read_and_posts_nothing_958(self):
        run, calls = self.hung(only="gh")
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", "success"]
        with mock.patch.object(sj.subprocess, "run", run):
            code, log = quiet(sj.main, args, None, outputs(self.judged()[0]))
        self.assertEqual(code, 1)
        self.assertIn(f"could not read the run (gh api repos/{R}/actions/runs/{RUN} did not answer within", log)
        self.assertEqual(len(calls), 1)

    def test_the_wait_for_a_newer_run_is_bounded_by_the_clock_958(self):
        """Reads that each take just under their timeout: the wait ends by the clock, inside
        `wait` seconds and one read, never 21 reads and 20 sleeps of their own length."""
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="in_progress")
        gh = GitHubFake(answers)
        now = [0.0]
        real_get = gh.get

        def slow_get(path):
            now[0] += sj.GH_SECONDS - 1
            return real_get(path)
        gh.get = slow_get

        def sleep(seconds):
            now[0] += seconds
        with self.assertRaises(sj.Silent) as caught:
            sj.resolve(gh, R, RID, RUN, wait=sj.WAIT_SECONDS, sleep=sleep, clock=lambda: now[0])
        self.assertIn(f"run {RUN + 1} attempt 1, is still running", str(caught.exception))
        self.assertLessEqual(now[0], sj.WAIT_SECONDS + 2 * sj.GH_SECONDS, now[0])
        # the budget the judge job's ten minutes leave the judging after the longest wait
        self.assertLessEqual(sj.WAIT_SECONDS + 2 * sj.GH_SECONDS, 360)


class ResolveInputs(Interleavings):
    """The inputs of `resolve` no test served and the changes of its meaning every test passed
    (#958, the strength read of fix-97c's judge): each test here is RED on its planted change in a
    scratch copy (`docs/lanes/fix-958-judge.md`), green on the script as it stands. Rows 12 to 15
    of the lane's table."""

    test_row1_the_pull_requests_run_then_a_token_dispatch_still_running_is_waited_for_and_judged = None
    test_row1_a_newer_run_still_running_after_the_wait_posts_nothing_and_names_it = None
    test_row2_a_token_dispatch_then_the_pull_requests_run_judges_the_pull_requests = None
    test_row2_the_older_runs_judge_after_the_newer_completed_judges_the_newer = None
    test_row3_a_reruns_newer_attempt_completed_is_judged_and_running_is_waited_for = None
    test_row4_two_pushes_inside_a_minute_the_older_heads_run_posts_nothing = None
    test_row5_a_hand_rejudge_of_an_older_run_judges_the_newest_as_the_events_judge_does = None
    test_row6_a_newer_run_that_is_no_stage_r_run_of_this_repository_is_not_judged_and_silences_nothing = None
    test_the_identity_is_read_on_the_run_judged = None

    def test_a_newest_run_not_yet_started_is_waited_for_and_judged_once_it_completes_958(self):
        """`queued`, `waiting`, `requested`, `pending`: every status but `completed` is a run still
        to end, never a run to judge at once."""
        w = self.world
        for status in ("queued", "waiting", "requested", "pending", "in_progress"):
            with self.subTest(status):
                answers = w.answers()
                newer = with_run(w, answers, RUN + 1, status=status)
                done = {**newer, "status": "completed", "conclusion": "success"}
                listing = answers[LISTING.format(R=R, head=w.head)]
                answers[LISTING.format(R=R, head=w.head)] = Seq([json.loads(json.dumps(listing)),
                                                                 {"workflow_runs": [listing["workflow_runs"][0], done]}])
                answers[f"repos/{R}/actions/runs/{RUN + 1}"] = done
                check, gh, log, slept = self.judge_of(answers, wait=300)
                self.assertEqual((check.post, check.conclusion, check.title), ("yes", "success", "GREEN"), log + check.text)
                self.assertEqual((self.judged_run(gh), slept), (RUN + 1, [sj.POLL_SECONDS]))
                answers = w.answers()
                with_run(w, answers, RUN + 1, status=status)
                check, gh, log, slept = self.judge_of(answers, wait=30)
                self.assertEqual((check.post, gh.writes, slept), ("no", [], [sj.POLL_SECONDS] * 2))
                self.assertIn(f"run {RUN + 1} attempt 1, is still running", log)
                self.assertFalse([r for r in gh.reads if "/attempts/" in r or r.endswith("/zip")], gh.reads)

    def test_a_calling_run_that_is_no_stage_r_run_of_this_repository_reads_no_listing_958(self):
        """A fork's run, or a `push` run, of a head this repository's own stage R run also built:
        the caller is refused before the listing, so it cannot have that run judged in its name."""
        w = self.world
        for name, fields, needle in (("a fork's", {"head_repository": {"id": 1}}, "head is not this repository's"),
                                     ("a null head repository", {"head_repository": None}, "head is not this repository's"),
                                     ("a push run", {"event": "push"}, "event is not pull_request or workflow_dispatch"),
                                     ("no head sha", {"head_sha": None}, "names no head sha"),
                                     ("a short head sha", {"head_sha": w.head[:39]}, "names no head sha")):
            with self.subTest(name):
                answers = w.answers()
                caller = RUN - 7
                answers[f"repos/{R}/actions/runs/{caller}"] = {**answers[f"repos/{R}/actions/runs/{RUN}"], "id": caller, **fields}
                check, gh, log, _ = self.judge_of(answers, run_id=caller, wait=300)
                self.assertEqual((check.post, gh.writes), ("no", []))
                self.assertIn(f"run {caller}", log)
                self.assertIn(needle, log)
                self.assertEqual(gh.reads, [f"repos/{R}/actions/runs/{caller}"])
                gh = GitHubFake(answers)
                args = ["report", "--run-id", str(caller), "--repository", R, "--repository-id", str(RID),
                        "--app-id", str(APP), "--judge-result", "success"]
                code, log = quiet(sj.main, args, gh, outputs(self.judged()[0]))
                self.assertEqual((code, gh.writes, gh.reads), (0, [], [f"repos/{R}/actions/runs/{caller}"]), log)

    def test_a_calling_run_the_listing_does_not_hold_is_judged_as_the_newest_958(self):
        """GitHub's listing read before it holds the run that called (or cut at its 100): the run
        called is still a run of its head, the newest when no listed run is newer."""
        w = self.world
        for name, listed in (("an empty listing", []), ("an older run alone", [RUN - 1])):
            with self.subTest(name):
                answers = w.answers()
                for run_id in listed:
                    with_run(w, answers, run_id, status="completed")
                listing = answers[LISTING.format(R=R, head=w.head)]
                listing["workflow_runs"] = [r for r in listing["workflow_runs"] if r["id"] != RUN]
                check, gh, log, _ = self.judge_of(answers)
                self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), log + check.text)
                self.assertEqual((self.judged_run(gh), check.run), (RUN, RUN))
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        listing = answers[LISTING.format(R=R, head=w.head)]
        listing["workflow_runs"] = [r for r in listing["workflow_runs"] if r["id"] != RUN]
        check, gh, _, _ = self.judge_of(answers)
        self.assertEqual((check.title, self.judged_run(gh)), ("GREEN", RUN + 1))

    def test_a_run_attempt_that_is_no_integer_is_never_judged_958(self):
        """Waited for as a run still to end, then no check and its line: the attempt names the
        artifact read, and one that is no number names none. An absent attempt is attempt 1."""
        w = self.world
        for attempt in ("2", 1.5, [1], {"n": 1}):
            with self.subTest(repr(attempt)):
                answers = w.answers()
                answers[LISTING.format(R=R, head=w.head)]["workflow_runs"][0]["run_attempt"] = attempt
                check, gh, log, slept = self.judge_of(answers, wait=30)
                self.assertEqual((check.post, check.conclusion, gh.writes), ("no", "failure", []))
                self.assertEqual(slept, [sj.POLL_SECONDS] * 2)
                self.assertIn("is still running", log)
                self.assertFalse([r for r in gh.reads if "/attempts/" in r or r.endswith("/zip")], gh.reads)
        for attempt in (None, 0):
            with self.subTest(repr(attempt)):
                answers = w.answers()
                answers[LISTING.format(R=R, head=w.head)]["workflow_runs"][0]["run_attempt"] = attempt
                check, gh, log, _ = self.judge_of(answers)
                self.assertEqual((check.title, check.attempt), ("GREEN", 1), log + check.text)

    def test_a_cancelled_newest_run_is_not_judged_over_an_older_runs_verdict_stated_958(self):
        """Row 15, stated and not changed: a dispatch someone cancelled is the head's newest
        completed stage R run, so its judgement is `NOT JUDGED: stage R ended cancelled`, posted
        (`post` `yes`) over a `GREEN` the older run of the same head earned, with the re-run named.
        Whether it should displace that `GREEN` is a question for the captain's word (the lane
        record); until then this is what the judge does, and it fails closed."""
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed", conclusion="cancelled")
        answers[f"repos/{R}/actions/runs/{RUN + 1}/attempts/1"]["conclusion"] = "cancelled"
        answers[f"repos/{R}/actions/runs/{RUN + 1}/attempts/1/jobs?per_page=100"] = {"jobs": []}
        answers[f"repos/{R}/commits/{w.head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"] = {
            "check_runs": [app_check("GREEN", "success")]}
        check, gh, log, _ = self.judge_of(answers)
        self.assertCheck(check, "NOT JUDGED", "stage R ended cancelled")
        self.assertEqual(check.run, RUN + 1)
        self.assertIn(f"gh run rerun {RUN + 1} --repo {R}", check.text)
        self.assertFalse([r for r in gh.reads if r.endswith("/zip")])
        gh = GitHubFake(answers)
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", "success"]
        code, _ = quiet(sj.main, args, gh, bound(check))
        self.assertEqual(code, 0)
        self.assertEqual([(b["conclusion"], b["output"]["title"]) for _, b in gh.writes],
                         [("failure", "NOT JUDGED: stage R ended cancelled")])


def outputs(check):
    return {"POST": check.post, "CONCLUSION": check.conclusion, "TITLE": check.title,
            "TEXT": base64.b64encode(check.text.encode()).decode()}


class Report(Base):
    def report(self, env, answers=None, result="success"):
        gh = GitHubFake(answers if answers is not None else self.world.answers())
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", result, "--details-url", "https://example.invalid/run/1"]
        code, log = quiet(sj.main, args, gh, env)
        return code, gh, log

    def green(self):
        check, _, _ = self.judged()
        return outputs(check)

    def test_a_green_judge_is_posted_once_completed_success(self):
        code, gh, _ = self.report(self.green())
        self.assertEqual(code, 0)
        self.assertEqual(len(gh.writes), 1)
        path, body = gh.writes[0]
        self.assertEqual(path, f"repos/{R}/check-runs")
        self.assertEqual((body["name"], body["status"], body["conclusion"], body["head_sha"]),
                         ("sibling-judge", "completed", "success", self.world.head))
        self.assertNotIn("in_progress", json.dumps(body))

    def test_absent_or_malformed_outputs_and_a_judge_job_not_success_post_not_judged(self):
        env = self.green()
        cases = [("absent", {}, "success"), ("bad base64", {**env, "TEXT": "!!!"}, "success"),
                 ("neutral", {**env, "CONCLUSION": "neutral"}, "success")]
        cases += [(result, env, result) for result in ("failure", "cancelled", "skipped")]
        for name, given, result in cases:
            with self.subTest(name):
                code, gh, _ = self.report(given, result=result)
                self.assertEqual(code, 0)
                self.assertEqual(len(gh.writes), 1)
                body = gh.writes[0][1]
                self.assertEqual(body["conclusion"], "failure")
                self.assertTrue(body["output"]["title"].startswith("NOT JUDGED"), body["output"]["title"])
                self.assertIn("gh workflow run sibling-judge.yml", body["output"]["text"])

    def test_a_success_under_a_failed_title_is_posted_failure(self):
        env = {**self.green(), "TITLE": "RED: planted"}
        _, gh, _ = self.report(env)
        self.assertEqual(gh.writes[0][1]["conclusion"], "failure")

    def test_an_identity_that_fails_at_report_time_posts_nothing(self):
        w = self.world
        answers = w.answers()
        answers[f"repos/{R}/commits/{w.head}/pulls"][0]["state"] = "closed"
        code, gh, log = self.report(self.green(), answers)
        self.assertEqual((code, gh.writes), (0, []))
        self.assertIn("no check", log)

    def test_a_newer_run_still_running_at_report_time_posts_nothing(self):
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 5, status="in_progress")
        code, gh, log = self.report(self.green(), answers)
        self.assertEqual((code, gh.writes), (0, []))
        self.assertIn(f"run {RUN + 5} attempt 1, is still running", log)

    def test_post_no_where_report_owes_a_check_posts_not_judged_with_the_rejudge(self):
        """The judge's `no` is not trusted over report's own reading (the closed read's row 3): the
        run is completed and its identity holds, so a check is owed."""
        code, gh, _ = self.report({**self.green(), "POST": "no"})
        self.assertEqual((code, len(gh.writes)), (0, 1))
        body = gh.writes[0][1]
        self.assertEqual(body["conclusion"], "failure")
        self.assertEqual(body["output"]["title"], "NOT JUDGED: the judge posted nothing where a check is owed")
        self.assertIn(f"-f run_id={RUN}", body["output"]["text"])

    def test_post_no_where_report_owes_none_posts_nothing(self):
        w = self.world
        answers = w.answers()
        answers[f"repos/{R}/commits/{w.head}/pulls"][0]["state"] = "closed"
        code, gh, _ = self.report({**self.green(), "POST": "no"}, answers)
        self.assertEqual((code, gh.writes), (0, []))

    def test_unless_standing_posts_nothing_over_a_standing_check_and_posts_without_one(self):
        w = self.world
        env = {**self.green(), "POST": "unless-standing", "CONCLUSION": "failure", "TITLE": "NOT JUDGED: gone"}
        answers = w.answers()
        answers[f"repos/{R}/commits/{w.head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"] = {
            "check_runs": [{"status": "completed", "app": {"id": APP}}]}
        code, gh, _ = self.report(env, answers)
        self.assertEqual((code, gh.writes), (0, []))
        code, gh, _ = self.report(env)
        self.assertEqual((code, len(gh.writes)), (0, 1))

    def test_a_create_refused_with_422_is_sent_again_as_failure_with_the_title_alone(self):
        gh = GitHubFake(self.world.answers())
        gh.post_errors = [sj.GitHubError(422, "too long")]
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", "success"]
        code, _ = quiet(sj.main, args, gh, self.green())
        self.assertEqual(code, 0)
        self.assertEqual(len(gh.writes), 2)
        bare = gh.writes[1][1]
        self.assertEqual((bare["conclusion"], set(bare["output"])), ("failure", {"title", "summary"}))

    def test_a_create_refused_twice_exits_non_zero(self):
        gh = GitHubFake(self.world.answers())
        gh.post_errors = [sj.GitHubError(422, "too long"), sj.GitHubError(500, "down")]
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", "success"]
        code, _ = quiet(sj.main, args, gh, self.green())
        self.assertEqual(code, 1)


def bound(check, **changes):
    """The judge job's outputs as a trampoline that hands `report` the run judged would pass them."""
    env = {**outputs(check), "JUDGED_RUN": "" if check.run is None else str(check.run),
           "JUDGED_ATTEMPT": "" if check.attempt is None else str(check.attempt)}
    env.update(changes)
    return env


class ReportBound(Base):
    """`report` posts the judge's verdict only on the run and attempt the judge judged (#958). The
    judge writes both as outputs; when the trampoline hands them on (`JUDGED_RUN`,
    `JUDGED_ATTEMPT`) and `report`'s own resolution names another run or attempt, the verdict is
    not posted: `NOT JUDGED` with the re-judge of the newest run. A trampoline that hands on
    neither name (the file before its sitting) is read as before. Row 10 of the lane's table."""

    def report(self, env, answers=None, result="success", run_id=RUN):
        gh = GitHubFake(answers if answers is not None else self.world.answers())
        args = ["report", "--run-id", str(run_id), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", result]
        code, log = quiet(sj.main, args, gh, env)
        self.assertEqual(code, 0, log)
        return gh.writes

    def assertNotJudged(self, writes, needle, target=RUN):
        self.assertEqual(len(writes), 1)
        body = writes[0][1]
        self.assertEqual((body["conclusion"], body["head_sha"]), ("failure", self.world.head))
        self.assertTrue(body["output"]["title"].startswith("NOT JUDGED: "), body["output"]["title"])
        self.assertIn(needle, body["output"]["title"] + "\n" + body["output"]["text"])
        self.assertIn(f"gh workflow run sibling-judge.yml --repo {R} --ref main -f run_id={target}\n", body["output"]["text"])

    def test_the_judge_writes_the_run_and_attempt_it_judged_958(self):
        w = self.world
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed", event="pull_request", attempt=3)
        out = Path(self.dir.name) / "bound-out.txt"
        for name, given, want in (("the newest run", answers, (str(RUN + 1), "3")),
                                  ("no run read", {}, ("", ""))):
            with self.subTest(name):
                out.write_text("")
                gh = GitHubFake(given)
                gh.download_bytes = w.zipped(w.raw_files())
                code, _ = quiet(sj.command_judge, w.args(output=str(out)), gh)
                self.assertEqual(code, 0)
                written = dict(line.split("=", 1) for line in out.read_text().splitlines())
                self.assertEqual((written.get("run"), written.get("attempt")), want)
                self.assertEqual(set(written), {"post", "conclusion", "title", "text", "run", "attempt"})

    def test_a_newer_run_completed_between_the_two_jobs_does_not_get_the_older_runs_verdict_958(self):
        w = self.world
        check, _, _ = self.judged()
        self.assertEqual((check.title, check.run, check.attempt), ("GREEN", RUN, 1))
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed", event="workflow_dispatch")
        writes = self.report(bound(check), answers)
        self.assertNotJudged(writes, f"the judge job judged run {RUN} attempt 1", target=RUN + 1)
        self.assertIn(f"stage R run {RUN + 1} attempt 1", writes[0][1]["output"]["text"])

    def test_a_newer_attempt_completed_between_the_two_jobs_does_not_get_the_older_attempts_verdict_958(self):
        check, _, _ = self.judged()
        writes = self.report(bound(check), self.world.answers(attempt=2))
        self.assertNotJudged(writes, f"the judge job judged run {RUN} attempt 1")
        self.assertIn(f"stage R run {RUN} attempt 2", writes[0][1]["output"]["text"])

    def test_the_verdict_of_the_run_report_resolves_is_posted_958(self):
        check, _, _ = self.judged()
        writes = self.report(bound(check))
        self.assertEqual([(b["conclusion"], b["output"]["title"]) for _, b in writes], [("success", "GREEN")])

    def test_names_that_do_not_read_as_a_run_and_an_attempt_are_not_judged_958(self):
        check, _, _ = self.judged()
        for name, changes in (("a word", {"JUDGED_RUN": "abc"}), ("zero", {"JUDGED_RUN": "0"}),
                              ("a sign", {"JUDGED_RUN": f"-{RUN}"}), ("a space", {"JUDGED_RUN": f"{RUN} "}),
                              ("no attempt", {"JUDGED_ATTEMPT": ""}), ("an attempt alone", {"JUDGED_RUN": ""}),
                              ("a word for the attempt", {"JUDGED_ATTEMPT": "one"}),
                              ("one name of the two", {"JUDGED_ATTEMPT": None})):
            with self.subTest(name):
                env = {k: v for k, v in bound(check, **changes).items() if v is not None}
                self.assertNotJudged(self.report(env), "the judge's outputs do not name the run it judged")

    def test_a_success_that_names_no_run_is_not_judged_and_a_failure_that_names_none_is_posted_958(self):
        check, _, _ = self.judged()
        env = bound(check, JUDGED_RUN="", JUDGED_ATTEMPT="")
        self.assertNotJudged(self.report(env), "the judge's outputs do not name the run it judged")
        failed = {**env, "CONCLUSION": "failure", "TITLE": "NOT JUDGED: the judge could not read what it needs"}
        writes = self.report(failed)
        self.assertEqual([b["output"]["title"] for _, b in writes], ["NOT JUDGED: the judge could not read what it needs"])
        self.assertEqual(writes[0][1]["conclusion"], "failure")

    def test_an_unless_standing_verdict_of_an_older_run_stays_unless_standing_958(self):
        w = self.world
        check, _, _ = self.judged()
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        env = bound(check, POST="unless-standing", CONCLUSION="failure", TITLE="NOT JUDGED: gone")
        self.assertNotJudged(self.report(env, answers), f"the judge job judged run {RUN} attempt 1", target=RUN + 1)
        answers[f"repos/{R}/commits/{w.head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"] = {
            "check_runs": [app_check("GREEN", "success")]}
        self.assertEqual(self.report(env, answers), [])

    def test_a_trampoline_that_hands_on_neither_name_is_read_as_before_958(self):
        w = self.world
        check, _, _ = self.judged()
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        writes = self.report(outputs(check), answers)
        self.assertEqual([(b["conclusion"], b["output"]["title"]) for _, b in writes], [("success", "GREEN")])

    def test_reports_own_not_judged_names_the_run_it_resolved_958(self):
        """Called for run A, resolving to run B: the text and the re-judge name B, and say A called."""
        w = self.world
        check, _, _ = self.judged()
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        for name, env, result in (("the judge job cancelled", outputs(check), "cancelled"),
                                  ("outputs absent", {}, "success"),
                                  ("post no", {**outputs(check), "POST": "no"}, "success")):
            with self.subTest(name):
                writes = self.report(env, answers, result=result)
                self.assertNotJudged(writes, f"stage R run {RUN + 1}", target=RUN + 1)
                text = writes[0][1]["output"]["text"]
                self.assertNotIn(f"stage R run {RUN}\n", text)
                self.assertIn(f"Called for run {RUN}", text)
                self.assertNotIn(f"run_id={RUN}\n", text)

    def test_a_judge_that_fails_says_which_run_called_and_claims_no_run_judged_958(self):
        w = self.world
        out = Path(self.dir.name) / "failed-out.txt"
        out.write_text("")
        with mock.patch.object(sj, "judge", side_effect=RuntimeError("planted")):
            code, _ = quiet(sj.command_judge, w.args(output=str(out)), GitHubFake({}))
        self.assertEqual(code, 0)
        written = dict(line.split("=", 1) for line in out.read_text().splitlines())
        text = base64.b64decode(written["text"]).decode()
        self.assertEqual((written["post"], written["conclusion"], written["run"], written["attempt"]), ("yes", "failure", "", ""))
        self.assertEqual(written["title"], "NOT JUDGED: the judge failed (RuntimeError)")
        self.assertIn(f"Called for stage R run {RUN}; the judge failed before it wrote which run it judged", text)
        self.assertIn(f"-f run_id={RUN}\n", text)


class Owed(Base):
    """`owed`: whether a check is owed for a run, read with no key (#958), so a trampoline can ask
    before it mints the App's token. `no` exactly where `report` would post nothing (the run is no
    stage R run of this repository, its newest run still runs, no open pull request into beta
    holds its head); `yes` otherwise, a read that fails included, so no failure of this command
    can silence a check `report` would post. It reads the run, the listing and the pull requests,
    and writes nothing to GitHub."""

    def owed(self, answers, run_id=RUN, output=True):
        out = Path(self.dir.name) / "owed-out.txt"
        out.write_text("")
        gh = GitHubFake(answers)
        args = ["owed", "--run-id", str(run_id), "--repository", R, "--repository-id", str(RID)]
        args += ["--output", str(out)] if output else ["--output", str(Path(self.dir.name) / "absent" / "out.txt")]
        code, log = quiet(sj.main, args, gh)
        self.assertEqual(gh.writes, [])
        self.assertFalse([r for r in gh.reads if "check-runs" in r or "artifacts" in r or "environments" in r], gh.reads)
        return code, out.read_text(), log

    def test_a_check_owed_answers_yes_958(self):
        w = self.world
        self.assertEqual(self.owed(w.answers())[:2], (0, "owed=yes\n"))
        answers = w.answers()
        with_run(w, answers, RUN + 1, status="completed")
        self.assertEqual(self.owed(answers)[:2], (0, "owed=yes\n"))

    def test_each_silence_of_report_answers_no_with_its_line_958(self):
        w = self.world

        def fork(a):
            a[f"repos/{R}/actions/runs/{RUN}"]["head_repository"] = {"id": 1}

        def decoy(a):
            a[f"repos/{R}/actions/runs/{RUN}"]["path"] = ".github/workflows/other.yml"

        def push(a):
            a[f"repos/{R}/actions/runs/{RUN}"]["event"] = "push"

        def closed(a):
            a[f"repos/{R}/commits/{w.head}/pulls"][0]["state"] = "closed"

        def into_main(a):
            a[f"repos/{R}/commits/{w.head}/pulls"][0]["base"]["ref"] = "main"

        def running(a):
            with_run(w, a, RUN + 1, status="in_progress")

        for name, change, needle in (("a fork's run", fork, "head is not this repository's"),
                                     ("a decoy at another path", decoy, "is not .github/workflows/sibling-run.yml"),
                                     ("a push run", push, "event is not pull_request or workflow_dispatch"),
                                     ("a closed pull request", closed, "no open pull request into beta"),
                                     ("a base of main", into_main, "no open pull request into beta"),
                                     ("a newer run still running", running, "is still running")):
            with self.subTest(name):
                answers = w.answers()
                change(answers)
                code, written, log = self.owed(answers)
                self.assertEqual((code, written), (0, "owed=no\n"), log)
                self.assertIn(needle, log)
                # and report, on the same answers, posts nothing: the two agree
                gh = GitHubFake(answers)
                args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID),
                        "--app-id", str(APP), "--judge-result", "success"]
                code, _ = quiet(sj.main, args, gh, outputs(self.judged()[0]))
                self.assertEqual((code, gh.writes), (0, []))

    def test_a_read_that_fails_answers_yes_958(self):
        w = self.world
        for name, path in (("the run", f"repos/{R}/actions/runs/{RUN}"),
                           ("the listing", LISTING.format(R=R, head=w.head)),
                           ("the pull requests", f"repos/{R}/commits/{w.head}/pulls")):
            for error in (sj.GitHubError(500, "down"), sj.GitHubError(0, "did not answer within 30 s"),
                          sj.GitHubError(404, "gone")):
                with self.subTest(f"{name} {error.status}"):
                    answers = w.answers()
                    answers[path] = error
                    code, written, log = self.owed(answers)
                    self.assertEqual((code, written), (0, "owed=yes\n"), log)
                    self.assertIn("could not read", log)

    def test_an_answer_that_is_no_object_answers_yes_958(self):
        w = self.world
        answers = w.answers()
        answers[f"repos/{R}/actions/runs/{RUN}"] = ["not", "a", "run"]
        code, written, log = self.owed(answers)
        self.assertEqual((code, written), (0, "owed=yes\n"), log)

    def test_an_output_that_cannot_be_written_exits_one_958(self):
        code, written, log = self.owed(self.world.answers(), output=False)
        self.assertEqual((code, written), (1, ""))
        self.assertIn("the output could not be written", log)


class Trampoline(Base):
    def test_mains_trampoline_other_than_betas_or_absent_on_either_line_is_not_judged(self):
        w = self.world
        git(w.upstream, "checkout", "-q", "main")
        try:
            other = w.commit({}, "noop", base=None)
            git(w.upstream, "checkout", "-q", "main")
            w.write({".github/workflows/sibling-judge.yml": "name: sibling-judge\non: workflow_run\n# moved\n"})
            git(w.upstream, "commit", "-qam", "moved")
            moved = git(w.upstream, "rev-parse", "HEAD")
            git(w.upstream, "rm", "-q", ".github/workflows/sibling-judge.yml")
            git(w.upstream, "commit", "-qm", "gone")
            gone = git(w.upstream, "rev-parse", "HEAD")
        finally:
            git(w.upstream, "checkout", "-q", "-f", "beta")
        self.assertTrue(other)
        check, gh, _ = self.judged(workflow_sha=moved)
        self.assertCheck(check, "NOT JUDGED", "the trampoline on main differs from beta's")
        self.assertIn("is behind", check.text)
        check, _, _ = self.judged(workflow_sha=gone)
        self.assertCheck(check, "NOT JUDGED", "absent on main")
        j = sj.Judgment(None, sj.Git(w.judge), w.root, str(w.sibling))
        with mock.patch.object(sj.Git, "entry", side_effect=lambda sha, path: None if sha == w.beta else ("100644", "a")):
            with self.assertRaises(sj.Verdict) as caught:
                j.lines(w.main)
        self.assertIn("absent on beta", caught.exception.reason)

    def test_the_line_named_behind_is_the_one_whose_trampoline_changed_earlier_or_at_the_same_second(self):
        """`sibling_judge.py`'s one other time comparison: the commit times of the trampoline's last
        change on each line, a tie naming main (the line that takes it by pick)."""
        w = self.world
        for name, main_time, beta_time, behind in (("main a second earlier", 99, 100, "main"),
                                                    ("the same second", 100, 100, "main"),
                                                    ("main a second later", 101, 100, "beta"),
                                                    ("main a minute earlier", 40, 100, "main")):
            with self.subTest(name):
                j = sj.Judgment(None, sj.Git(w.judge), w.root, str(w.sibling))
                times = {w.main: main_time, w.beta: beta_time}
                with mock.patch.object(sj.Git, "entry", side_effect=lambda sha, path: ("100644", "b" if sha == w.beta else "m")), \
                        mock.patch.object(sj.Git, "last_change", side_effect=lambda sha, path: times[sha]):
                    with self.assertRaises(sj.Verdict) as caught:
                        j.lines(w.main)
                self.assertEqual(caught.exception.reason, f"the trampoline on main differs from beta's; {behind} is behind")

    def test_a_commit_time_that_does_not_read_is_not_judged(self):
        """The commit times are parsed as integers of seconds (`Git.last_change`), never compared
        as text or read as 0: git's answer that is empty or not a decimal is None, and a None on
        either line is NOT JUDGED, naming the line."""
        w = self.world
        git = sj.Git(w.judge)
        for out, parsed in ((b"1762942057\n", 1762942057), (b"", None), (b"12a\n", None), (b"-5\n", None)):
            with self.subTest(out=out):
                with mock.patch.object(sj.Git, "run", return_value=types.SimpleNamespace(stdout=out)):
                    self.assertEqual(git.last_change(w.main, sj.JUDGE_WORKFLOW), parsed)
        for which, times in (("main", {w.main: None, w.beta: 100}), ("beta", {w.main: 100, w.beta: None})):
            with self.subTest(which):
                j = sj.Judgment(None, sj.Git(w.judge), w.root, str(w.sibling))
                with mock.patch.object(sj.Git, "entry", side_effect=lambda sha, path: ("100644", "b" if sha == w.beta else "m")), \
                        mock.patch.object(sj.Git, "last_change", side_effect=lambda sha, path: times[sha]):
                    with self.assertRaises(sj.Verdict) as caught:
                        j.lines(w.main)
                self.assertEqual((caught.exception.word, caught.exception.reason),
                                 (sj.NOT_JUDGED, f"the trampoline on main differs from beta's; {which}'s commit time does not read"))


class Text(unittest.TestCase):
    def test_backticks_a_fence_a_command_and_control_bytes_are_replaced(self):
        text = sj.bounded(["own"], ["a `tick`", "```", "::error::x", "bell\x07 cr\r tab\t nul\x00  "], "act")
        block = text.split("```text\n", 1)[1].split("\n```\n", 1)[0]
        self.assertNotIn("`", block)
        self.assertIn("a 'tick'", block)
        self.assertIn("'''", block)
        for byte in "\x07\r\t\x00 ":
            self.assertNotIn(byte, block)
        self.assertTrue(text.rstrip().endswith("```"))
        self.assertIn("```sh\nact\n```", text)

    def test_a_600_byte_line_is_cut_to_500_bytes_and_counted(self):
        text = sj.bounded([], ["x" * 600], None)
        self.assertIn("x" * 500 + "\n", text)
        self.assertNotIn("x" * 501, text)
        self.assertIn("1 lines cut", text)

    def test_seventy_thousand_characters_are_held_to_sixty_thousand(self):
        text = sj.bounded(["own"], ["y" * 400] * 175, "act")
        self.assertLessEqual(len(text), sj.TEXT_LIMIT)
        self.assertRegex(text, r"\d+ lines cut")
        self.assertTrue(text.rstrip().endswith("act\n```"))

    def test_the_script_prints_no_artifact_text(self):
        with tempfile.TemporaryDirectory() as d:
            world = World(d)
            files = world.raw_files()
            files["seed.log"] = b"run_diff: RED (1 unexplained divergences, 0 messages outside the table, 0 recorded bsv-rs verdicts disagreeing)\n  UNEXPLAINED ::error::planted\n"
            gh = GitHubFake(world.answers())
            gh.download_bytes = world.zipped(files)
            check, log = quiet(sj.judge, world.args(), gh, None)
        self.assertIn("planted", check.text)
        self.assertNotIn("planted", log)
        self.assertFalse(any(line.startswith("::") for line in log.splitlines()))


class Conclusions(unittest.TestCase):
    def test_success_is_set_by_one_line_inside_passed_and_failure_everywhere_else(self):
        source = SCRIPT.read_text().splitlines()
        sets = [i for i, line in enumerate(source) if re.search(r"conclusion\s*=\s*\"success\"", line)]
        self.assertEqual(len(sets), 1, sets)
        self.assertEqual(source[sets[0] - 1].strip(), "def passed(self):")
        for line in source:
            for word in ("neutral", "skipped", "cancelled"):
                self.assertNotRegex(line, rf"conclusion\S*\s*=\s*\"{word}\"")

    def test_every_exit_of_judge_is_failure_but_the_one_green(self):
        with tempfile.TemporaryDirectory() as d:
            world = World(d)
            pin = f"repos/Calhooon/bsv-script-lean/compare/{world.pin}...main"
            exits = {
                "green": (world.answers(), None),
                "identity": ({**world.answers(), f"repos/{R}/commits/{world.head}/pulls": []}, None),
                "pin": ({**world.answers(), pin: {"behind_by": 3}}, None),
                "state": (world.answers(conclusion="failure"), None),
                "artifact": (world.answers(artifacts=[]), None),
                "github": ({**world.answers(), pin: sj.GitHubError(500, "x")}, None),
                "red": (world.answers(), {"words": world.words(1, {("tx", "tx-1"): ["invalid", "x"]})}),
            }
            seen = {}
            for name, (answers, change) in exits.items():
                gh = GitHubFake(answers)
                gh.download_bytes = world.zipped(world.raw_files(**(change or {})))
                check, _ = quiet(sj.judge, world.args(), gh, None)
                seen[name] = check.conclusion
                self.assertEqual(gh.writes, [])
        self.assertEqual({k for k, v in seen.items() if v == "success"}, {"green"}, seen)


def sweep_run(run_id, sha, status="completed", event="pull_request", conclusion="success", path=None):
    return {"id": run_id, "status": status, "conclusion": conclusion if status == "completed" else None,
            "event": event, "head_sha": sha, "path": path or sj.RUN_WORKFLOW, "head_repository": {"id": RID}}


class Sweep(unittest.TestCase):
    def sweep(self, runs, judging=()):
        """One open pull request per entry of `runs` (its stage R runs), numbered from 1; and a
        fork's pull request after them. `judging`: the trampoline's runs not completed."""
        numbers = range(1, len(runs) + 1)
        prs = [{"number": n, "head": {"sha": f"{n}" * 40, "ref": f"lane/{n}", "repo": {"full_name": R, "id": RID}}}
               for n in numbers]
        prs.append({"number": 9, "head": {"sha": "9" * 40, "ref": "lane/9", "repo": {"full_name": "x/y", "id": 1}}})
        answers = {f"repos/{R}/pulls?state=open&base=beta&per_page=100": prs,
                   f"repos/{R}/actions/workflows/sibling-judge.yml/runs?per_page=100": {"workflow_runs": [
                       {"display_title": title, "status": status} for title, status in judging]}}
        for n, made in zip(numbers, runs):
            sha = f"{n}" * 40
            answers[f"repos/{R}/pulls/{n}"] = {"mergeable_state": made.get("mergeable", "clean")}
            answers[f"repos/{R}/actions/workflows/sibling-run.yml/runs?head_sha={sha}&per_page=100"] = {
                "workflow_runs": [sweep_run(sha=sha, **r) for r in made.get("runs", [])]}
            answers[f"repos/{R}/commits/{sha}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"] = {
                "check_runs": made.get("checks", [{"status": "completed", "app": {"id": APP}}] if made.get("stands") else [])}
        gh = GitHubFake(answers)
        code, log = quiet(sj.main, ["sweep", "--app-id", str(APP)], gh)
        self.assertEqual((code, gh.writes), (0, []), log)
        return log

    def test_the_gaps_each_name_their_act(self):
        log = self.sweep([{}, {"runs": [{"run_id": 502}]}, {"runs": [{"run_id": 503}], "mergeable": "dirty"},
                          {"runs": [{"run_id": 504}], "stands": True}])
        self.assertIn("#1 " + "1" * 40 + ": no stage R run; check absent; act: gh workflow run sibling-run.yml --repo Calhooon/bsv-rs --ref lane/1", log)
        self.assertIn("#2 " + "2" * 40 + ": run 502 success; check absent; act: gh workflow run sibling-judge.yml --repo Calhooon/bsv-rs --ref main -f run_id=502", log)
        self.assertIn("#3 " + "3" * 40 + ": run 503 success; check absent; act: rebase on beta", log)
        self.assertIn("#4 " + "4" * 40 + ": run 504 success; check stands\n", log)
        self.assertIn("#9 " + "9" * 40 + ": a fork's head; act: push the branch to Calhooon/bsv-rs", log)

    def test_an_unparsed_stage_r_names_a_push_never_a_rejudge_of_githubs_failed_run(self):
        """Witness 12 (#948): GitHub's failed `push` run of a `sibling-run.yml` it could not parse
        is no stage R run; a re-judge of it is silent (its event) and a dispatch of the file is
        refused, so the act is a push of a parsing file."""
        log = self.sweep([{"runs": [{"run_id": 600, "event": "push", "conclusion": "failure"}]}])
        line = [l for l in log.splitlines() if l.startswith("#1 ")][0]
        self.assertIn("no stage R run; check absent", line)
        self.assertIn("run 600 push failure is no stage R run", line)
        self.assertIn("act: push a commit to lane/1 whose .github/workflows/sibling-run.yml parses", line)
        self.assertNotIn("sibling-judge.yml", line)
        self.assertNotIn("gh workflow run sibling-run.yml", line)

    def test_a_head_whose_judge_is_running_reads_judge_in_progress(self):
        """The sweep of 19:01Z read `check absent` for a head whose judge was still running."""
        for title, status in (("sibling-judge " + "1" * 40, "in_progress"), ("sibling-judge " + "1" * 40, "queued"),
                              ("sibling-judge of run 700", "waiting")):
            with self.subTest(f"{title} {status}"):
                log = self.sweep([{"runs": [{"run_id": 700}]}], judging=[(title, status)])
                self.assertIn("#1 " + "1" * 40 + ": run 700 success; check judge in progress\n", log)
        log = self.sweep([{"runs": [{"run_id": 700}]}], judging=[("sibling-judge " + "1" * 40, "completed")])
        self.assertIn("check absent; act: gh workflow run sibling-judge.yml", log)

    def test_a_newest_run_still_running_is_named_with_its_rejudge_after(self):
        log = self.sweep([{"runs": [{"run_id": 701}, {"run_id": 702, "status": "in_progress", "event": "workflow_dispatch"}]}])
        self.assertIn("run 702 in_progress; check absent; act: once it completes, gh workflow run sibling-judge.yml "
                      "--repo Calhooon/bsv-rs --ref main -f run_id=702", log)


def app_check(title, conclusion="failure", check_id=1, app=APP):
    """A completed check run as GitHub lists it, less the fields the judge never reads."""
    return {"id": check_id, "status": "completed", "conclusion": conclusion, "app": {"id": app},
            "output": {"title": title, "summary": title}}


class StandingNotJudged(Base):
    """A `NOT JUDGED` failure is no verdict (#958): the sweep names it with the re-judge where it
    said `check stands` with no act, and a re-judge whose artifact is gone (`unless-standing`)
    posts over it where it was silent. A verdict (`GREEN`, `RED`, `REFUSED`, `JUDGE CHANGE`)
    stands as before; of several checks of the App the newest (by id) decides, as on the head."""

    VERDICTS = (("GREEN", "success"), ("JUDGE CHANGE: tests/sibling/x", "success"), ("RED: the run differs", "failure"),
                ("REFUSED: behind beta by 2 commits", "failure"),
                ("RED (JUDGE CHANGE: tests/sibling/x): the run differs", "failure"))

    def sweep(self, checks, judging=()):
        return Sweep.sweep(self, [{"runs": [{"run_id": 800}, {"run_id": 801, "event": "workflow_dispatch"}],
                                   "checks": checks}], judging)

    def test_the_sweep_names_a_not_judged_check_with_the_rejudge_of_the_newest_run_958(self):
        log = self.sweep([app_check("NOT JUDGED: the judge posted nothing where a check is owed")])
        self.assertIn("#1 " + "1" * 40 + ": run 801 success; check NOT JUDGED (NOT JUDGED: the judge posted nothing where a "
                      "check is owed); act: gh workflow run sibling-judge.yml --repo Calhooon/bsv-rs --ref main -f run_id=801\n", log)
        self.assertNotIn("check stands", log)

    def test_the_sweep_reads_each_verdict_as_standing_958(self):
        for title, conclusion in self.VERDICTS:
            with self.subTest(title):
                log = self.sweep([app_check(title, conclusion)])
                self.assertIn("#1 " + "1" * 40 + ": run 801 success; check stands\n", log)

    def test_of_two_checks_the_newest_decides_958(self):
        green, lost = app_check("GREEN", "success", check_id=5), app_check("NOT JUDGED: stage R ended cancelled", check_id=6)
        for listing in ([green, lost], [lost, green]):
            self.assertIn("check NOT JUDGED (NOT JUDGED: stage R ended cancelled); act: ", self.sweep(listing))
        green["id"] = 7
        for listing in ([green, lost], [lost, green]):
            self.assertIn("run 801 success; check stands\n", self.sweep(listing))

    def test_a_not_judged_check_whose_rejudge_is_running_names_no_act_958(self):
        log = self.sweep([app_check("NOT JUDGED: gone")], judging=[("sibling-judge of run 801", "queued")])
        self.assertIn("#1 " + "1" * 40 + ": run 801 success; check NOT JUDGED (NOT JUDGED: gone), judge in progress\n", log)

    def test_another_apps_not_judged_check_and_a_title_from_outside_are_read_as_before_958(self):
        self.assertIn("check absent; act: ", self.sweep([app_check("NOT JUDGED: forged", app=APP + 1)]))
        log = self.sweep([app_check("NOT JUDGED: a`b\nc")])
        self.assertIn("check NOT JUDGED (NOT JUDGED: a'b?c); act: ", log)

    def report(self, checks, env=None):
        w = self.world
        env = env or {**outputs(self.judged()[0]), "POST": "unless-standing", "CONCLUSION": "failure",
                      "TITLE": "NOT JUDGED: 0 unexpired sibling-raw artifacts of attempt 1, not one"}
        answers = w.answers()
        answers[f"repos/{R}/commits/{w.head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"] = {
            "check_runs": checks}
        gh = GitHubFake(answers)
        args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id", str(APP),
                "--judge-result", "success"]
        code, log = quiet(sj.main, args, gh, env)
        self.assertEqual(code, 0, log)
        return gh.writes

    def test_unless_standing_posts_over_a_standing_not_judged_958(self):
        writes = self.report([app_check("NOT JUDGED: the judge job ended cancelled")])
        self.assertEqual(len(writes), 1)
        body = writes[0][1]
        self.assertEqual((body["conclusion"], body["head_sha"]), ("failure", self.world.head))
        self.assertTrue(body["output"]["title"].startswith("NOT JUDGED: 0 unexpired"))

    def test_unless_standing_is_silent_over_each_standing_verdict_958(self):
        for title, conclusion in self.VERDICTS:
            with self.subTest(title):
                self.assertEqual(self.report([app_check(title, conclusion)]), [])

    def test_unless_standing_never_posts_a_success_958(self):
        """`unless-standing` is the judge's word for a failure whose artifact is gone; outputs that
        pair it with a success are posted as a failure, with or without a check to post over."""
        env = {**outputs(self.judged()[0]), "POST": "unless-standing"}
        self.assertEqual((env["CONCLUSION"], env["TITLE"]), ("success", "GREEN"))
        for checks in ([], [app_check("NOT JUDGED: gone")]):
            writes = self.report(checks, env)
            self.assertEqual([body["conclusion"] for _, body in writes], ["failure"])


class SweepEnvironment(unittest.TestCase):
    """The sweep's last line reads back the two settings outside every file that hold the key
    (#958): the environment `sibling-judge`'s `can_admins_bypass` and its deployment branches. A
    read-back, never a gate: the sweep's exit status and its lines for the pull requests do not
    move with it, and a setting that does not read says so."""

    ENV = f"repos/{R}/environments/sibling-judge"

    def sweep(self, environment=None, branches=None):
        answers = {f"repos/{R}/pulls?state=open&base=beta&per_page=100": [],
                   f"repos/{R}/actions/workflows/sibling-judge.yml/runs?per_page=100": {"workflow_runs": []}}
        if environment is not None:
            answers[self.ENV] = environment
        if branches is not None:
            answers[self.ENV + "/deployment-branch-policies?per_page=100"] = branches
        gh = GitHubFake(answers)
        code, log = quiet(sj.main, ["sweep", "--app-id", str(APP)], gh)
        self.assertEqual((code, gh.writes), (0, []), log)
        return log.splitlines()[-1]

    def policy(self, *names):
        return {"total_count": len(names), "branch_policies": [{"name": n, "type": "branch"} for n in names]}

    def test_the_two_settings_are_read_back_as_github_answers_them_958(self):
        custom = {"custom_branch_policies": True, "protected_branches": False}
        for bypass in (True, False):
            with self.subTest(bypass):
                line = self.sweep({"can_admins_bypass": bypass, "deployment_branch_policy": custom}, self.policy("main"))
                self.assertEqual(line, f"environment sibling-judge: can_admins_bypass {str(bypass).lower()}; "
                                       "deployment branches: main (main alone)")

    def test_a_branch_policy_other_than_main_alone_is_named_958(self):
        custom = {"custom_branch_policies": True, "protected_branches": False}
        for name, environment, branches, needle in (
                ("two branches", {"can_admins_bypass": False, "deployment_branch_policy": custom}, self.policy("main", "beta"),
                 "deployment branches: beta, main (NOT main alone"),
                ("another branch", {"can_admins_bypass": False, "deployment_branch_policy": custom}, self.policy("beta"),
                 "deployment branches: beta (NOT main alone"),
                ("no entry", {"can_admins_bypass": False, "deployment_branch_policy": custom}, self.policy(),
                 "deployment branches: none (NOT main alone"),
                ("a tag named main", {"can_admins_bypass": False, "deployment_branch_policy": custom},
                 {"branch_policies": [{"name": "main", "type": "tag"}]}, "(NOT main alone"),
                ("no policy", {"can_admins_bypass": False, "deployment_branch_policy": None}, None,
                 "deployment branches: every branch (NOT main alone"),
                ("protected branches", {"can_admins_bypass": False, "deployment_branch_policy":
                                        {"custom_branch_policies": False, "protected_branches": True}}, None,
                 "deployment branches: every protected branch (NOT main alone")):
            with self.subTest(name):
                self.assertIn(needle, self.sweep(environment, branches))

    def test_a_setting_that_does_not_read_says_so_and_the_sweep_still_ends_zero_958(self):
        custom = {"custom_branch_policies": True, "protected_branches": False}
        self.assertTrue(self.sweep().startswith("environment sibling-judge: not read (no answer for "))
        line = self.sweep({"can_admins_bypass": True, "deployment_branch_policy": custom})
        self.assertTrue(line.startswith("environment sibling-judge: can_admins_bypass true; deployment branches: not read ("), line)
        line = self.sweep({"can_admins_bypass": "yes", "deployment_branch_policy": custom}, self.policy("main"))
        self.assertIn("can_admins_bypass not read", line)
        line = self.sweep({"can_admins_bypass": True, "deployment_branch_policy": custom},
                          {"branch_policies": [{"name": "ma`in\nx", "type": "branch"}]})
        self.assertIn("deployment branches: ma'in?x (NOT main alone", line)
        self.assertTrue(self.sweep(["not", "an", "object"]).startswith("environment sibling-judge: not read"))


class DryRun(Base):
    def test_a_dry_run_judges_a_zip_and_says_what_it_could_not_make(self):
        w = self.world
        path = Path(self.dir.name) / "dry.zip"
        path.write_bytes(w.zipped(w.raw_files(pull_request=None)))
        git(w.judge, "fetch", "-q", "origin", w.head)
        args = ["judge", "--dry-run", "--offline", "--artifact", str(path), "--head", w.head, "--judge", str(w.judge),
                "--sibling", str(w.sibling), "--temp", self.dir.name]
        code, log = quiet(sj.main, args, None)
        self.assertEqual(code, 0, log)
        self.assertIn("conclusion: success", log)
        self.assertIn("title: GREEN", log)
        for what in ("the run's identity", "the superseded test", "the artifact's record", "the trampoline's comparison"):
            self.assertIn(f"Not made in a dry run: {what}", log)


class Imports(unittest.TestCase):
    def test_the_script_runs_isolated_as_the_trampoline_will(self):
        done = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT), "judge", "--help"], capture_output=True,
                              cwd=tempfile.gettempdir(), check=False)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_no_sys_path_write_extractall_or_download_artifact(self):
        source = SCRIPT.read_text()
        for word in ("sys.path", "extractall", "download-artifact"):
            self.assertNotIn(word, source.replace("`sys.path`", ""))


class Members(unittest.TestCase):
    def test_the_allowlist_is_built_from_the_corpus_list(self):
        required, optional = sj.members()
        self.assertEqual(len(required), 3 + 2 * len(sh.ALL))
        self.assertIn("bsvrs-words/tx.jsonl", required)
        self.assertIn("bsv-rs/tx.jsonl", optional)


class StampAndRecord(Base):
    """Each comparison of the stamp and the run's record with what the judge read, alone (the
    strength read of lane 1's FIX lines): one field moved at a time, each refused."""

    def moved(self, stamp_change=None, info_change=None, **raw):
        files = self.world.raw_files(**raw)
        stamp, info = json.loads(files[sh.STAMP]), json.loads(files[sh.RUN_INFO])
        (stamp_change or (lambda s: None))(stamp)
        (info_change or (lambda i: None))(info)
        files[sh.STAMP], files[sh.RUN_INFO] = json.dumps(stamp).encode(), json.dumps(info).encode()
        return files

    def test_each_comparison_of_the_stamp_and_the_record_refuses_on_its_own(self):
        def drop(key):
            return lambda s: s["corpora"].pop(key)

        cases = (
            ("the record's pin", None, lambda i: i.update(sibling="1" * 40), "pin: stamp"),
            ("the stamp's rules pin", lambda s: s.update(rules_pin="0.0.0"), None, "rules pin: stamp '0.0.0'"),
            ("the record's rules pin", None, lambda i: i.update(rules_pin="0.0.0"), "record '0.0.0'"),
            ("the stamp's corpus sha256", lambda s: s["corpora"]["seed"].update(corpus_sha256="0" * 64), None,
             "corpora: the stamp's"),
            ("the stamp's withheld count", lambda s: s["corpora"]["gen"].update(withheld=9), None, "corpora: the stamp's"),
            ("the stamp one corpus short", drop("tx"), None, "corpora: the stamp's"),
            ("the record's withheld count", None, lambda i: i.update(withheld={"gen": 9}), "withheld: the record's"),
            ("the record one corpus short", None, lambda i: i.update(corpora=list(sh.ALL)[:-1]), "the record does not name"),
            ("the record's corpora reordered", None, lambda i: i.update(corpora=list(reversed(sh.ALL))),
             "the record does not name"),
        )
        for name, stamp_change, info_change, needle in cases:
            with self.subTest(name):
                check, gh, _ = self.judged(files=self.moved(stamp_change, info_change))
                self.assertCheck(check, "NOT JUDGED", needle)
                self.assertIn("differs from what the judge read", check.title)
                self.assertEqual(gh.writes, [])

    def test_a_dispatch_stamp_naming_no_pull_request_is_judged_and_any_other_mismatch_is_not(self):
        w = self.world
        check, _, _ = self.judged(files=w.raw_files(pull_request=None), answers=w.answers(event="workflow_dispatch"))
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), check.text)
        for name, event, stamped in (("a dispatch stamping another pull request", "workflow_dispatch", 8),
                                     ("a pull request's run stamping none", "pull_request", None)):
            with self.subTest(name):
                check, _, _ = self.judged(files=w.raw_files(pull_request=stamped), answers=w.answers(event=event))
                self.assertCheck(check, "NOT JUDGED", "pull request: stamp")


class LineFeeds(unittest.TestCase):
    """A line is split on a line feed alone: JSON holds U+0085, U+2028 and U+2029 raw inside a
    string, and `str.splitlines` splits on each (the strength read of lane 1)."""

    SEPARATORS = ("\u0085", " ", " ")

    def test_a_words_line_holding_a_separator_reads_as_one_entry(self):
        for sep in self.SEPARATORS:
            with self.subTest(hex(ord(sep))):
                row = {"id": "a", "rec": ["invalid", f"x{sep}y"], "spec": ["valid", None], "mempool": ["valid", None]}
                text = json.dumps(row, ensure_ascii=False) + "\n" + json.dumps({**row, "id": "b"}) + "\n"
                rows = sh.read_words_text(text, "w/seed.jsonl")
                self.assertEqual(sorted(rows), ["a", "b"])
                self.assertEqual(rows["a"]["rec"], ["invalid", f"x{sep}y"])

    def test_a_log_whose_verdict_follows_a_separator_has_no_verdict_line(self):
        for sep in self.SEPARATORS:
            with self.subTest(hex(ord(sep))):
                files = {"seed.log": f"spec_recorded: planted{sep}{GREEN_LINE}".encode()}
                _, divergences, lines, _ = sh.verdicts_of(files, "w", ["seed"], {"seed": {"entries": 1}})
                self.assertEqual(divergences, 1, lines)
                self.assertIn("no run_diff verdict line", lines[0])

    def test_the_judges_facts_and_the_withheld_drop_read_a_separator_inside_a_line(self):
        with tempfile.TemporaryDirectory() as d:
            world = World(d)
            seed = world.sibling / "corpus" / "seed" / "seed.jsonl"
            gen = world.sibling / "corpus" / "gen" / "gen.jsonl"
            seed.write_text(seed.read_text() + '{"id": "seed-x", "tx": "00", "note": "a b"}\n')
            gen.write_text(gen.read_text() + '{"id": "gen-x", "tx": "WITHHELD: a b"}\n')
            git(world.sibling, "add", ".")
            git(world.sibling, "commit", "-q", "-m", "separators")
            pin = git(world.sibling, "rev-parse", "HEAD")
            facts = quiet(sj.Facts, world.sibling, pin, d)[0]
        self.assertEqual(facts.lines["seed"].get("seed-x"), '{"id": "seed-x", "tx": "00", "note": "a b"}')
        self.assertEqual(facts.withheld, {"gen": 2})
        self.assertNotIn("gen-x", facts.lines["gen"])


class Quoting(unittest.TestCase):
    """A branch name is a pull request's text: every command the judge builds quotes it."""

    BRANCH = "lane/x;touch $(id) 'y'"

    def test_the_repush_act_quotes_the_branch(self):
        j = sj.Judgment(None, None, tempfile.gettempdir(), "u", R, RID)
        j.pr = {"head": {"ref": self.BRANCH}}
        act = j.repush()
        self.assertIn("--ref " + shlex.quote(self.BRANCH) + "\n", act + "\n")
        self.assertEqual(shlex.split(act.splitlines()[-1])[-1], self.BRANCH)

    def printed_act(self, branch):
        j = sj.Judgment(None, None, tempfile.gettempdir(), "u", R, RID)
        j.pr = {"head": {"ref": branch}}
        text = sj.bounded(["REFUSED: a reason"], ["a quoted line"], j.repush())
        return text.split("To re-judge:\n\n```sh\n", 1)[1].split("\n```", 1)[0]

    def test_the_printed_act_has_its_command_on_a_line_of_its_own(self):
        """The lane's finding: `clean()` turned the act's line break into `?`, so the act pasted
        into a shell was one comment line and its command never ran."""
        act = self.printed_act(self.BRANCH)
        lines = act.split("\n")
        self.assertEqual(len(lines), 2, act)
        self.assertTrue(lines[0].startswith("# push a commit"), act)
        self.assertFalse(lines[1].startswith("#"), act)
        self.assertTrue(lines[1].startswith("gh workflow run sibling-run.yml --repo "), act)
        self.assertEqual(shlex.split(lines[1])[-1], self.BRANCH)

    def test_a_line_break_in_the_branch_opens_no_line_of_the_act(self):
        act = self.printed_act("lane/x\nrm -rf ~\r\u2028y")
        lines = act.split("\n")
        self.assertEqual(len(lines), 2, act)
        self.assertEqual(shlex.split(lines[1])[-1], "lane/x?rm -rf ~??y")

    def test_the_sweeps_act_quotes_the_branch(self):
        sha = "1" * 40
        answers = {
            f"repos/{R}/pulls?state=open&base=beta&per_page=100":
                [{"number": 1, "head": {"sha": sha, "ref": self.BRANCH, "repo": {"full_name": R}}}],
            f"repos/{R}/pulls/1": {"mergeable_state": "clean"},
            f"repos/{R}/actions/workflows/sibling-run.yml/runs?head_sha={sha}&per_page=100": {"workflow_runs": []},
            f"repos/{R}/commits/{sha}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100": {"check_runs": []},
            f"repos/{R}/actions/workflows/sibling-judge.yml/runs?per_page=100": {"workflow_runs": []},
        }
        code, log = quiet(sj.main, ["sweep", "--app-id", str(APP)], GitHubFake(answers))
        self.assertEqual(code, 0)
        act = log.split("act: ", 1)[1].splitlines()[0]
        self.assertEqual(shlex.split(act)[-1], self.BRANCH)


class Standing(Base):
    """A check counts as the App's only when its app id is the configured one (the rule read's
    R3): a check with no app, a null app or another App's never stands."""

    def test_a_check_without_the_apps_id_does_not_stand(self):
        w = self.world
        path = f"repos/{R}/commits/{w.head}/check-runs?check_name=sibling-judge&app_id={APP}&per_page=100"
        for name, forged in (("no app", {"status": "completed"}), ("a null app", {"status": "completed", "app": None}),
                             ("an app with no id", {"status": "completed", "app": {}}),
                             ("another App", {"status": "completed", "app": {"id": APP + 1}})):
            with self.subTest(name):
                answers = w.answers()
                answers[path] = {"check_runs": [forged]}
                self.assertFalse(sj.standing(GitHubFake(answers), R, w.head, APP))
                env = {**outputs(self.judged()[0]), "POST": "unless-standing", "CONCLUSION": "failure",
                       "TITLE": "NOT JUDGED: gone"}
                gh = GitHubFake(answers)
                args = ["report", "--run-id", str(RUN), "--repository", R, "--repository-id", str(RID), "--app-id",
                        str(APP), "--judge-result", "success"]
                code, _ = quiet(sj.main, args, gh, env)
                self.assertEqual((code, len(gh.writes)), (0, 1))
        answers = w.answers()
        answers[path] = {"check_runs": [{"status": "completed", "app": {"id": APP}}]}
        self.assertTrue(sj.standing(GitHubFake(answers), R, w.head, APP))


class Rerun(Base):
    """A re-run of stage R is judged from the artifact its own attempt uploaded (`overwrite: true`
    on the upload; the judge reads only an artifact created at or after the attempt started). The
    two times are parsed and compared as times (`sibling_judge.instant`); the start sits at an odd
    second on no coarser mark (`10:07:37Z`: not on a minute, not on ten seconds, not on five), so a
    cut of either text to any unit coarser than a second moves `10:07:36Z` to the start's side."""

    STARTED = "2026-11-12T10:07:37Z"

    def rerun(self, artifacts, started=STARTED):
        w = self.world
        answers = w.answers(attempt=2, artifacts=artifacts)
        answers[f"repos/{R}/actions/runs/{RUN}/attempts/2"] = {"conclusion": "success", "run_started_at": started}
        return self.judged(answers=answers, attempt=2)

    def made(self, artifact_id, created):
        return {"id": artifact_id, "name": "sibling-raw", "expired": False, "size_in_bytes": 1000, "digest": "d",
                "created_at": created,
                "workflow_run": {"id": RUN, "head_sha": self.world.head, "head_repository_id": RID}}

    def assertJudged(self, listing, read, unread, started=STARTED):
        check, gh, _ = self.rerun(listing, started)
        self.assertEqual((check.conclusion, check.title), ("success", "GREEN"), check.text)
        self.assertIn(f"repos/{R}/actions/artifacts/{read}/zip", gh.reads)
        for other in unread:
            self.assertNotIn(f"repos/{R}/actions/artifacts/{other}/zip", gh.reads)

    def test_a_rerun_is_judged_whether_the_old_artifact_was_replaced_or_is_still_listed(self):
        old, new = self.made(98, "2026-11-12T09:30:00Z"), self.made(99, "2026-11-12T10:11:00Z")
        for name, listing in (("replaced", [new]), ("both listed", [old, new]), ("both listed, new first", [new, old])):
            with self.subTest(name):
                self.assertJudged(listing, 99, [98])

    def test_the_earlier_attempts_artifact_one_second_before_an_odd_start_is_the_earlier_attempts(self):
        """The one-second cell (fold three): an artifact made at `10:07:36Z` against a start at
        `10:07:37Z` is the earlier attempt's, beside this attempt's at the same second and one
        second after, in either listing order; alone it leaves none."""
        before = self.made(98, "2026-11-12T10:07:36Z")
        for name, created in (("the same second", self.STARTED), ("one second after", "2026-11-12T10:07:38Z")):
            for order in ("before first", "before last"):
                with self.subTest(f"{name}, {order}"):
                    this = self.made(99, created)
                    self.assertJudged([before, this] if order == "before first" else [this, before], 99, [98])
                with self.subTest(f"{name}, alone"):
                    self.assertJudged([self.made(99, created)], 99, [])
        check, gh, _ = self.rerun([before])
        self.assertCheck(check, "NOT JUDGED", "0 unexpired sibling-raw artifacts of attempt 2, not one")
        self.assertEqual(gh.writes, [])

    def test_times_are_compared_as_times_not_as_text(self):
        """A fraction of a second and an offset other than `Z` read as the instants they name: an
        artifact at `10:07:36.999Z` is before `10:07:37Z`; one at `12:07:37+02:00` is the start
        itself; one at `11:07:36+02:00` is an hour before it, though its text sorts after the
        start's (the cell a comparison of the texts gets wrong); a start written `10:07:37.000Z` is
        the same instant as `10:07:37Z`."""
        self.assertJudged([self.made(98, "2026-11-12T10:07:36.999Z"), self.made(99, "2026-11-12T12:07:37+02:00")], 99, [98])
        self.assertJudged([self.made(97, "2026-11-12T11:07:36+02:00"), self.made(99, self.STARTED)], 99, [97])
        self.assertJudged([self.made(98, "2026-11-12T10:07:36Z"), self.made(99, self.STARTED)], 99, [98],
                          started="2026-11-12T10:07:37.000Z")

    def test_a_timestamp_that_does_not_parse_is_not_judged(self):
        for name, started, created, reason in (
                ("the start absent", None, self.STARTED, "the start of attempt 2 does not read as a time"),
                ("the start cut to the minute", "2026-11-12T10:07Z", self.STARTED, "the start of attempt 2 does not read as a time"),
                ("the start not a date", "2026-13-12T10:07:37Z", self.STARTED, "the start of attempt 2 does not read as a time"),
                ("the creation time absent", self.STARTED, None, "an artifact's creation time does not read as a time"),
                ("the creation time with no zone", self.STARTED, "2026-11-12T10:07:38", "an artifact's creation time does not read as a time"),
                ("the creation time not text", self.STARTED, 1762942058, "an artifact's creation time does not read as a time")):
            with self.subTest(name):
                check, gh, _ = self.rerun([self.made(99, created)], started)
                self.assertCheck(check, "NOT JUDGED", reason)
                self.assertEqual(gh.writes, [])

    def test_an_earlier_attempts_artifact_alone_is_not_judged(self):
        check, gh, _ = self.rerun([self.made(98, "2026-11-12T09:30:00Z")])
        self.assertCheck(check, "NOT JUDGED", "0 unexpired sibling-raw artifacts of attempt 2, not one")
        self.assertEqual(gh.writes, [])


class StageRScript(unittest.TestCase):
    """Whose `sibling_harness.py` stage R runs is said one way (the rule read's R2): beta's, from
    the `judge/` checkout, on the head's tree, so a J diff cannot change the script that writes
    its own artifact."""

    def test_the_script_and_the_manual_say_beta_s_harness(self):
        doc = sj.__doc__
        self.assertIn("runs beta's `sibling_harness.py raw` on the head's tree", " ".join(doc.split()))
        manual = (HERE.parent.parent / "tests" / "sibling" / "CLAUDE.md").read_text()
        self.assertIn("python3 -I -B judge/.github/scripts/sibling_harness.py raw --tree head", manual)
        self.assertNotIn("sibling_harness.py raw --tree .", manual)


if __name__ == "__main__":
    unittest.main()
