"""Regression witnesses for skipped pins and a silently unused Cargo patch, and for the
baseline: a consumer that fails at its pin without this tree is not judged, never counted
against it, and the one required status says which consumers were judged."""

import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import dependents
from dependents import admits, verify_resolution


class Requirements(unittest.TestCase):
    def test_exact_cli_pin_does_not_admit_the_patch_release(self):
        self.assertFalse(admits("=0.8.1", "0.8.2"))

    def test_caret_pins_admit_only_their_compatible_line(self):
        for requirement in ("0.8", "0.8.0", "^0.8.1"):
            self.assertTrue(admits(requirement, "0.8.2"))
            self.assertFalse(admits(requirement, "0.9.0"))
            self.assertFalse(admits(requirement, "0.8.2-beta.1"))

    def test_older_consumers_wait_for_their_captains(self):
        for requirement in ("=0.4.5", "0.5.0", "0.6.0", "0.7", "=0.7.2"):
            self.assertFalse(admits(requirement, "0.8.2"))

    def test_partial_and_zero_caret_bounds(self):
        self.assertTrue(admits("1", "1.9.3"))
        self.assertFalse(admits("1", "2.0.0"))
        self.assertTrue(admits("0.0", "0.0.9"))
        self.assertFalse(admits("0.0.1", "0.0.2"))
        self.assertTrue(admits("=0.8", "0.8.9"))

    def test_beta_requires_an_explicit_exact_pin(self):
        self.assertTrue(admits("=0.9.0-beta.2", "0.9.0-beta.2"))
        self.assertFalse(admits("=0.9.0-beta.1", "0.9.0-beta.2"))

    def test_unrecognized_requirement_fails_closed(self):
        with self.assertRaises(ValueError):
            admits(">=0.8, <0.9", "0.8.2")
        with self.assertRaises(ValueError):
            admits("^0.9.0-beta.1", "0.9.0-beta.2")


class Resolution(unittest.TestCase):
    def graph(self, sdk_manifest, source):
        return {
            "packages": [
                {"id": "consumer", "name": "consumer", "manifest_path": "/consumer/Cargo.toml"},
                {"id": "sdk", "name": "bsv-rs", "version": "0.8.2", "manifest_path": sdk_manifest, "source": source},
            ],
            "resolve": {"nodes": [{"id": "consumer", "deps": [{"name": "bsv_sdk", "pkg": "sdk"}]}]},
        }

    def test_alias_resolves_to_the_pr_tree(self):
        verify_resolution(self.graph("/sdk/Cargo.toml", None), Path("/consumer/Cargo.toml"), "bsv-sdk", Path("/sdk"))

    def test_unused_patch_cannot_report_success(self):
        with self.assertRaisesRegex(ValueError, "path override was not selected"):
            verify_resolution(self.graph("/registry/Cargo.toml", "registry"), Path("/consumer/Cargo.toml"), "bsv-sdk", Path("/sdk"))


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
RUSTC = "rustc 1.100.1 (20ddd0171 2026-11-25)"
FAILED = 101  # cargo's exit for a build or a test that fails


def lock_text(version, source):
    origin = f'source = "{source}"\n' if source else ""
    return (f'version = 4\n\n[[package]]\nname = "bsv-rs"\nversion = "{version}"\n{origin}'
            '\n[[package]]\nname = "consumer"\nversion = "0.1.0"\n')


def git(checkout, *args):
    """git with no user or system configuration: the fixture's repository alone."""
    environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", "-c", "user.name=lane", "-c", "user.email=lane@example.invalid", *args],
                          cwd=checkout, check=True, text=True, stdout=subprocess.PIPE, env=environment).stdout.strip()


class Call:
    def __init__(self, args, lock):
        self.args, self.lock = args, lock
        self.subcommand, self.patched = args[1], "--config" in args


class Cargo:
    """A fake of `dependents.command`: every cargo call recorded with the lock it found, and
    answered as the test says. `fails` maps (subcommand, against this tree) to an exit code;
    `baseline_source` is where the graph without the patch takes bsv-rs from."""

    def __init__(self, fixture, fails=None, baseline_source=REGISTRY):
        self.fixture, self.fails, self.baseline_source, self.calls = fixture, fails or {}, baseline_source, []

    def __call__(self, args, cwd, capture=False):
        args = [str(arg) for arg in args]
        lock = self.fixture.lock
        call = Call(args, lock.read_text() if lock.exists() else None)
        self.calls.append(call)
        code = self.fails.get((call.subcommand, call.patched))
        if code:
            raise subprocess.CalledProcessError(code, args)
        if call.subcommand in ("update", "metadata") and "--locked" not in args:
            # cargo writes the lock it resolved: this tree by path, or the registry's copy
            lock.write_text(lock_text("0.8.13", None if call.patched else REGISTRY))
        if call.subcommand == "metadata":
            return self.fixture.graph(None if call.patched else self.baseline_source)
        return None

    def baseline(self):
        return [call for call in self.calls if not call.patched]


class Fixture:
    """This crate's tree beside one consumer's checkout, a real git repository at its pin,
    with or without a committed lock. cargo is faked; git and the lock's file are real."""

    CHECK = ["--locked", "--workspace", "--lib", "--target", "wasm32-unknown-unknown"]
    TEST = ["--locked", "--workspace", "--lib", "--tests"]

    def __init__(self, test, committed_lock):
        scratch = tempfile.TemporaryDirectory()
        test.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.sdk, self.checkout = root / "sdk", root / "consumer"
        (self.sdk / "docs").mkdir(parents=True)
        self.checkout.mkdir()
        (self.sdk / "Cargo.toml").write_text('[package]\nname = "bsv-rs"\nversion = "0.8.13"\n')
        self.manifest = self.checkout / "Cargo.toml"
        self.manifest.write_text(
            '[package]\nname = "consumer"\nversion = "0.1.0"\n\n[dependencies]\n'
            'bsv-sdk = { package = "bsv-rs", version = "0.8.1", features = ["block"], default-features = false }\n')
        self.lock = self.checkout / "Cargo.lock"
        self.committed = lock_text("0.8.9", REGISTRY) if committed_lock else None
        if committed_lock:
            self.lock.write_text(self.committed)
        git(self.checkout, "init", "-q", "-b", "main")
        git(self.checkout, "add", "-A")
        git(self.checkout, "commit", "-q", "-m", "the pin")
        self.rev = git(self.checkout, "rev-parse", "HEAD")
        (self.sdk / "docs/dependents.lock").write_text(
            f'schema = 1\n\n[[consumer]]\nid = "worker"\nrepository = "example/worker"\nbranch = "main"\n'
            f'rev = "{self.rev}"\nprivate = false\nrequirement = "0.8.1"\nsdk_features = ["block"]\n'
            'sdk_default_features = false\nmanifests = ["Cargo.toml"]\ntargets = ["wasm32-unknown-unknown"]\n'
            'features = []\ncheck_args = ["--workspace", "--lib"]\ntest_args = ["--workspace", "--lib", "--tests"]\n')
        self.patch = ["--config", "patch.crates-io.bsv-rs.path=" + json.dumps(str(self.sdk))]

    def graph(self, source):
        sdk_manifest = "/registry/bsv-rs-0.8.13/Cargo.toml" if source else str(self.sdk / "Cargo.toml")
        return {
            "packages": [
                {"id": "consumer", "name": "consumer", "manifest_path": str(self.manifest)},
                {"id": "sdk", "name": "bsv-rs", "version": "0.8.13", "manifest_path": sdk_manifest, "source": source},
            ],
            "resolve": {"nodes": [{"id": "consumer", "deps": [{"name": "bsv_sdk", "pkg": "sdk"}]}]},
            "workspace_root": str(self.checkout),
        }

    def against_this_tree(self, subcommand, *tail):
        return ["cargo", subcommand, "--manifest-path", str(self.manifest), *self.patch, *tail]

    def alone(self, subcommand, *tail):
        return ["cargo", subcommand, "--manifest-path", str(self.manifest), *tail]

    def todays_line(self, subcommand, tail, code=FAILED):
        failure = subprocess.CalledProcessError(code, self.against_this_tree(subcommand, *tail))
        return f"::error title=dependent worker::{failure}\n"

    def run(self, cargo, *extra):
        return main(cargo, "run", "--sdk", str(self.sdk), "--checkout", str(self.checkout), "--consumer", "worker", *extra)


def main(cargo, *argv, environment=None):
    """`dependents.py <argv>` with cargo faked: (exit code, stdout, stderr). An argument the
    script does not know is argparse's exit 2, so a test of one fails on a script without it."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(dependents, "command", cargo), \
            mock.patch.object(dependents, "toolchain", lambda: RUSTC, create=True), \
            mock.patch.object(sys, "argv", ["dependents.py", *argv]), \
            mock.patch.dict(os.environ, environment or {}), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = dependents.main()
        except SystemExit as refused:
            code = refused.code
    return code, out.getvalue(), err.getvalue()


class Baseline(unittest.TestCase):
    """A consumer's failed command is run once more without this tree, and only then."""

    def test_a_consumer_that_fails_at_its_pin_without_this_tree_is_not_judged(self):
        fixture = Fixture(self, committed_lock=False)
        cargo = Cargo(fixture, {("check", True): FAILED, ("check", False): FAILED})
        code, _, err = fixture.run(cargo)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            err,
            f"::warning title=dependent worker::worker at {fixture.rev} is NOT JUDGED: `cargo check` fails at its pin "
            f"without this tree too (against bsv-rs 0.8.13 from the registry, its graph resolved afresh in this run, "
            f"as it commits no lock, on {RUSTC}), so this run says nothing of this tree for it; its pin in "
            "docs/dependents.lock must move once the consumer is mended.\n")
        # the same command, once, without the patch; its graph resolved as the run with this
        # tree resolved it, from no lock (the generated one removed)
        resolve, build = cargo.baseline()
        self.assertEqual(resolve.args, fixture.alone("metadata", "--format-version", "1"))
        self.assertIsNone(resolve.lock)
        self.assertEqual(build.args, fixture.alone("check", *Fixture.CHECK))
        self.assertEqual(build.lock, lock_text("0.8.13", REGISTRY))
        self.assertEqual(cargo.calls[-3].args, fixture.against_this_tree("check", *Fixture.CHECK))
        self.assertIs(cargo.calls[-1], build)

    def test_a_committed_lock_is_put_back_and_held_for_the_baseline(self):
        fixture = Fixture(self, committed_lock=True)
        cargo = Cargo(fixture, {("check", True): FAILED, ("check", False): FAILED})
        code, _, err = fixture.run(cargo)
        self.assertEqual(code, 0, err)
        self.assertIn("is NOT JUDGED: `cargo check` fails at its pin without this tree too "
                      "(against bsv-rs 0.8.13 from the registry, by its committed lock, on ", err)
        # the run with this tree moved the lock to this tree's version; the baseline reads the pin's
        self.assertEqual(cargo.calls[0].args,
                         fixture.against_this_tree("update", "-p", "bsv-rs@0.8.9", "--precise", "0.8.13"))
        self.assertEqual(cargo.calls[2].lock, lock_text("0.8.13", None))
        resolve, build = cargo.baseline()
        self.assertEqual(resolve.args, fixture.alone("metadata", "--locked", "--format-version", "1"))
        self.assertEqual((resolve.lock, build.lock), (fixture.committed, fixture.committed))
        self.assertEqual(build.args, fixture.alone("check", *Fixture.CHECK))

    def test_a_consumer_this_tree_breaks_fails_with_todays_line(self):
        for committed_lock in (False, True):
            with self.subTest(committed_lock=committed_lock):
                fixture = Fixture(self, committed_lock)
                cargo = Cargo(fixture, {("check", True): FAILED})
                code, out, err = fixture.run(cargo)
                self.assertEqual(code, 1)
                self.assertEqual(err, fixture.todays_line("check", Fixture.CHECK))
                # judged: the baseline ran, the same command once, and passed
                self.assertEqual([call.args for call in cargo.baseline()][1:], [fixture.alone("check", *Fixture.CHECK)])
                self.assertIn("passes without this tree (bsv-rs 0.8.13 from the registry); this tree breaks the consumer", out)

    def test_a_failing_test_command_gets_its_own_baseline(self):
        fixture = Fixture(self, committed_lock=False)
        cargo = Cargo(fixture, {("test", True): FAILED, ("test", False): FAILED})
        code, _, err = fixture.run(cargo)
        self.assertEqual(code, 0, err)
        self.assertIn("is NOT JUDGED: `cargo test` fails at its pin without this tree too", err)
        # the check that passed against this tree is not run again
        self.assertEqual([call.args for call in cargo.baseline()],
                         [fixture.alone("metadata", "--format-version", "1"), fixture.alone("test", *Fixture.TEST)])
        cargo = Cargo(fixture, {("test", True): FAILED})
        code, _, err = fixture.run(cargo)
        self.assertEqual((code, err), (1, fixture.todays_line("test", Fixture.TEST)))
        self.assertEqual(len(cargo.baseline()), 2)

    def test_a_baseline_that_does_not_resolve_is_a_failure(self):
        # a requirement no published version admits, a lock `--locked` refuses, a registry
        # that does not answer: the resolve step's exit, whatever the reason
        for committed_lock in (False, True):
            with self.subTest(committed_lock=committed_lock):
                fixture = Fixture(self, committed_lock)
                cargo = Cargo(fixture, {("check", True): FAILED, ("metadata", False): FAILED, ("check", False): FAILED})
                code, out, err = fixture.run(cargo)
                self.assertEqual(code, 1)
                self.assertEqual(err, fixture.todays_line("check", Fixture.CHECK))
                locked = ["--locked"] if committed_lock else []
                self.assertEqual([call.args for call in cargo.baseline()],
                                 [fixture.alone("metadata", *locked, "--format-version", "1")])
                self.assertIn("does not resolve without this tree", out)

    def test_a_baseline_that_still_builds_this_tree_is_a_failure(self):
        # a path (this tree, were the patch still read) or a git source: no published bsv-rs
        for source in (None, "git+https://example.invalid/bsv-rs#0123456"):
            with self.subTest(source=source):
                fixture = Fixture(self, committed_lock=False)
                cargo = Cargo(fixture, {("check", True): FAILED, ("check", False): FAILED}, baseline_source=source)
                code, out, err = fixture.run(cargo)
                self.assertEqual((code, err), (1, fixture.todays_line("check", Fixture.CHECK)))
                self.assertEqual([call.subcommand for call in cargo.baseline()], ["metadata"])
                self.assertIn("the baseline did not take bsv-rs from a registry", out)

    def test_a_baseline_that_gives_no_answer_is_a_failure(self):
        # killed by a signal or by the runner: not cargo's exit for a build that fails
        for code_alone in (-9, 137, 1):
            with self.subTest(exit=code_alone):
                fixture = Fixture(self, committed_lock=False)
                cargo = Cargo(fixture, {("check", True): FAILED, ("check", False): code_alone})
                code, out, err = fixture.run(cargo)
                self.assertEqual((code, err), (1, fixture.todays_line("check", Fixture.CHECK)))
                self.assertEqual([call.subcommand for call in cargo.baseline()], ["metadata", "check"])
                self.assertIn(f"gave no answer without this tree (exit {code_alone})", out)

    def test_a_green_consumer_is_checked_as_before_with_no_second_build(self):
        fixture = Fixture(self, committed_lock=True)
        cargo = Cargo(fixture)
        code, out, err = fixture.run(cargo)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual([call.args for call in cargo.calls], [
            fixture.against_this_tree("update", "-p", "bsv-rs@0.8.9", "--precise", "0.8.13"),
            fixture.against_this_tree("metadata", "--format-version", "1"),
            fixture.against_this_tree("check", *Fixture.CHECK),
            fixture.against_this_tree("test", *Fixture.TEST),
        ])
        self.assertTrue(out.endswith("PASS worker: pinned checkout, PR dependency, checks passed; hermetic tests passed\n"))
        self.assertEqual(fixture.lock.read_text(), lock_text("0.8.13", None))

    def test_a_failure_before_the_judged_commands_gets_no_baseline(self):
        fixture = Fixture(self, committed_lock=False)
        cargo = Cargo(fixture, {("metadata", True): FAILED})
        code, _, err = fixture.run(cargo)
        self.assertEqual((code, err), (1, fixture.todays_line("metadata", ["--format-version", "1"])))
        self.assertEqual(len(cargo.calls), 1)


class Verdicts(unittest.TestCase):
    """What a consumer's check hands the required status: its slot of the job's outputs."""

    def files(self, fixture):
        return fixture.sdk / "output", fixture.sdk / "summary"

    def run_with_slot(self, fails):
        fixture = Fixture(self, committed_lock=False)
        output, summary = self.files(fixture)
        code, _, err = fixture.run(Cargo(fixture, fails), "--slot", "3", "--output", str(output), "--summary", str(summary))
        read = lambda path: path.read_text() if path.exists() else ""
        return code, err, read(output), read(summary)

    def test_a_judged_consumer_writes_its_slot(self):
        self.assertEqual(self.run_with_slot({}), (0, "", "verdict_3=judged worker\n", ""))

    def test_a_consumer_not_judged_writes_its_slot_and_the_summary(self):
        code, err, output, summary = self.run_with_slot({("check", True): FAILED, ("check", False): FAILED})
        self.assertEqual((code, output), (0, "verdict_3=not-judged worker\n"))
        # one sentence, in the warning and in the job's summary
        self.assertTrue(summary.startswith("worker at ") and " is NOT JUDGED: " in summary, summary)
        self.assertEqual(err, f"::warning title=dependent worker::{summary}")

    def test_a_consumer_this_tree_breaks_writes_no_verdict(self):
        code, err, output, summary = self.run_with_slot({("check", True): FAILED})
        self.assertEqual((code, output, summary), (1, "", ""))
        self.assertTrue(err.startswith("::error title=dependent worker::Command "), err)


class Aggregate(unittest.TestCase):
    """The required status: red when a judged consumer failed, red when none was judged."""

    def status(self, plan="success", check="success", count="3", verdicts=None):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        summary = Path(scratch.name) / "summary"
        environment = {"PLAN_RESULT": plan, "CHECK_RESULT": check, "CONSUMER_COUNT": count,
                       "VERDICTS": json.dumps(verdicts if verdicts is not None else {})}
        code, out, err = main(None, "aggregate", "--sdk", scratch.name, "--summary", str(summary), environment=environment)
        return code, out, err, summary.read_text() if summary.exists() else ""

    def test_every_consumer_judged_passes_with_todays_line(self):
        verdicts = {"verdict_0": "judged a", "verdict_1": "judged b", "verdict_2": "judged c", "verdict_3": ""}
        line = "All 3 eligible consumer checks passed.\n"
        self.assertEqual(self.status(verdicts=verdicts), (0, line, "", line))

    def test_a_judged_consumer_that_failed_fails_the_status(self):
        # the failed consumer's job is red; a consumer not judged beside it changes nothing
        for check in ("failure", "cancelled"):
            code, _, err, summary = self.status(check=check, verdicts={"verdict_0": "judged a", "verdict_2": "not-judged c"})
            line = "An eligible dependent failed or was cancelled; see the named consumer check.\n"
            self.assertEqual((code, err, summary), (1, f"::error::{line}", line))

    def test_a_consumer_not_judged_beside_judged_ones_passes_and_is_named(self):
        verdicts = {"verdict_0": "judged a", "verdict_1": "not-judged worker", "verdict_2": "judged c"}
        code, out, err, summary = self.status(verdicts=verdicts)
        line = ("2 of 3 eligible consumers were judged, and passed. Not judged, each failing at its pin without this "
                "tree: worker (the warning of each one's check says how; RELEASING.md step 2 says what the captain owes).\n")
        self.assertEqual((code, out, err, summary), (0, line, f"::warning title=dependents::{line}", line))

    def test_every_consumer_not_judged_fails_the_status(self):
        verdicts = {"verdict_0": "not-judged a", "verdict_1": "not-judged b", "verdict_2": "not-judged c"}
        code, _, err, summary = self.status(verdicts=verdicts)
        line = ("No eligible consumer was judged: all 3 fail at their pins without this tree (a, b, c). "
                "An outage of the toolchain or the registry is not a pass.\n")
        self.assertEqual((code, err, summary), (1, f"::error::{line}", line))
        code, _, _, _ = self.status(count="1", verdicts={"verdict_0": "not-judged a"})
        self.assertEqual(code, 1)

    def test_a_verdict_that_did_not_arrive_fails_the_status(self):
        code, _, err, _ = self.status(verdicts={"verdict_0": "judged a", "verdict_1": "not-judged b"})
        self.assertEqual((code, err), (1, "::error::2 of 3 eligible consumers reported a verdict: a cell's verdict was "
                                          "lost (ci.yml's verdict slots against the plan's cells).\n"))
        self.assertEqual(self.status(verdicts={})[0], 1)

    def test_an_unreadable_or_repeated_verdict_fails_the_status(self):
        for third in ("passed c", "judged", "judged a", "not-judged a", 7):
            code, _, err, _ = self.status(verdicts={"verdict_0": "judged a", "verdict_1": "judged b", "verdict_2": third})
            self.assertEqual(code, 1, third)
            self.assertIn("The verdict in verdict_2 is unreadable or names a consumer twice", err)
        code, _, err, _ = self.status(verdicts=["judged a"])
        self.assertEqual((code, err), (1, "::error title=dependents::VERDICTS is not the JSON object of the consumer "
                                          "checks' outputs\n"))

    def test_a_failed_plan_and_no_eligible_consumer_read_as_before(self):
        for plan in ("failure", "cancelled", "skipped"):
            code, _, err, _ = self.status(plan=plan, check="skipped", count="")
            self.assertEqual((code, err), (1, "::error::The dependents plan failed or was cancelled.\n"))
        line = "All 0 eligible consumer checks passed.\n"
        self.assertEqual(self.status(check="skipped", count="0"), (0, line, "", line))


class Workflow(unittest.TestCase):
    """ci.yml hands each cell's verdict to the status: a matrix's outputs are combined by
    name, so every cell writes a slot of its own, and the job declares each slot."""

    ROOT = Path(__file__).resolve().parents[2]

    def job(self, name):
        text = (self.ROOT / ".github/workflows/ci.yml").read_text()
        found = re.search(rf"^  {name}:\n(?:(?:    .*)?\n)+", text, re.MULTILINE)
        self.assertIsNotNone(found, name)
        return found.group(0)

    def test_a_verdict_slot_is_declared_for_every_row_of_the_lock(self):
        check = self.job("dependent-check")
        slots = re.findall(r"^      verdict_(\d+): \$\{\{ steps\.check\.outputs\.verdict_(\d+) \}\}$", check, re.MULTILINE)
        self.assertEqual(slots, [(str(n), str(n)) for n in range(len(slots))])
        # every row the plan could admit at once has a slot; add slots with the rows
        self.assertGreaterEqual(len(slots), len(dependents.records(self.ROOT)))
        self.assertIn("        id: check\n", check)
        self.assertIn("          SLOT: ${{ strategy.job-index }}\n", check)
        self.assertIn(' --slot "$SLOT" --output "$GITHUB_OUTPUT" --summary "$GITHUB_STEP_SUMMARY"\n', check)

    def test_the_status_reads_every_slot_through_the_script(self):
        status = self.job("dependents")
        self.assertIn("          VERDICTS: ${{ toJSON(needs.dependent-check.outputs) }}\n", status)
        self.assertIn('        run: python3 -B .github/scripts/dependents.py aggregate --sdk "$GITHUB_WORKSPACE" '
                      '--summary "$GITHUB_STEP_SUMMARY"\n', status)


if __name__ == "__main__":
    unittest.main()
