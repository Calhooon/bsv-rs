"""The Release page generator and the front pages' reconciler on recorded answers.

`fixtures/front_pages/` is a world in which every `check` rule passes; each test copies it,
plants one change and reads the verdict, so every rule is seen RED on a planted answer and
green on the recorded one. No test reaches the network.
"""

import contextlib
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock

import front_pages as fp

WORLD = Path(__file__).resolve().parent / "fixtures" / "front_pages"


class World(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="front-pages-"))
        shutil.copytree(WORLD, self.dir / "w")
        self.root = self.dir / "w"
        self.addCleanup(shutil.rmtree, self.dir)

    def source(self):
        return fp.Offline(self.root)

    def edit(self, name, change):
        path = self.root / name
        value = change(json.loads(path.read_text()))
        if value is not None:
            path.write_text(json.dumps(value))

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def drop(self, name):
        (self.root / name).unlink()

    def lines(self, **kw):
        return fp.check(self.source(), **kw).lines

    def failing(self, rule, **kw):
        return [line for line in self.lines(**kw) if line.startswith(f"FAIL {rule}:")]


class Versions(unittest.TestCase):
    def test_semver_order_puts_a_prerelease_before_its_release(self):
        ordered = ["0.8.6", "0.9.0-beta.1", "0.9.0-beta.2", "0.9.0-beta.10", "0.9.0", "0.10.0"]
        self.assertEqual(sorted(reversed(ordered), key=fp.key), ordered)

    def test_a_range_holds_each_comparator(self):
        self.assertTrue(fp.in_range("0.8.5", "< 0.8.6"))
        self.assertFalse(fp.in_range("0.8.6", "< 0.8.6"))
        self.assertTrue(fp.in_range("0.9.0-beta.7", ">= 0.9.0-beta.1, <= 0.9.0-beta.7"))
        # the lower end is inside the range (the cold read's surviving `>=` to `>` mutation)
        self.assertTrue(fp.in_range("0.9.0-beta.1", ">= 0.9.0-beta.1, <= 0.9.0-beta.7"))
        self.assertFalse(fp.in_range("0.8.6", ">= 0.9.0-beta.1, <= 0.9.0-beta.7"))
        self.assertTrue(fp.in_range("0.8.6", "= 0.8.6"))
        self.assertFalse(fp.in_range("0.8.7", "0.8.6"))
        self.assertFalse(fp.in_range("0.9.0-beta.8", ">= 0.9.0-beta.1, <= 0.9.0-beta.7"))
        self.assertFalse(fp.in_range("0.8.5", None))

    def test_patched_versions_name_the_version_in_any_form(self):
        for text in ("0.8.6", ">= 0.8.6", "0.9.0-beta.8, 0.8.6"):
            self.assertTrue(fp.patched_in("0.8.6", text))
        self.assertFalse(fp.patched_in("0.8.7", ">= 0.8.6"))
        self.assertFalse(fp.patched_in("0.8.6", None))


class Notes(World):
    def notes(self, tag, run=None):
        return fp.notes(self.source(), tag, run)

    def test_a_stable_patch_page_from_its_section_its_advisory_and_its_run(self):
        self.assertEqual(self.notes("v0.8.7", "7"), (WORLD / "expected" / "notes-v0.8.7.md").read_text())

    def test_the_page_carries_the_section_alone(self):
        text = self.notes("v0.8.7")
        self.assertNotIn("#999", text)  # [Unreleased]
        self.assertNotIn("#800", text)  # 0.8.6's section
        self.assertNotIn("Measured at this tag", text)  # no run given

    def test_a_version_inside_a_published_range_carries_its_notice(self):
        text = self.notes("v0.8.6")
        self.assertTrue(text.startswith("A patch on the 0.8 line."))
        self.assertIn("> Affected by a published advisory: [GHSA-aaaa-bbbb-cccc]", text)
        self.assertIn("patched in 0.8.7.", text)

    def test_a_draft_advisory_never_reaches_a_page(self):
        for tag in ("v0.8.7", "v0.8.6", "v0.9.0-beta.1"):
            text = self.notes(tag)
            self.assertNotIn("GHSA-zzzz", text)
            self.assertNotIn("PLANTED DRAFT", text)

    def test_the_live_call_filters_published_in_its_jq(self):
        self.assertTrue(fp.ADVISORY_JQ.startswith('map(select(.state == "published"))'))
        self.assertNotIn("description", fp.ADVISORY_JQ)

    def test_a_prerelease_page_reads_its_oracle_and_the_combined_slice_from_checks(self):
        text = self.notes("v0.9.0-beta.1", "8")
        self.assertTrue(text.startswith("A prerelease of the 0.9 line, cut from `beta`. To take it: `cargo add bsv-rs@=0.9.0-beta.1`"))
        self.assertIn("- Added: Door::open, the one-input door (#855)", text)
        self.assertIn("- Tests: The door's cells recorded beside the reference (#856).", text)
        self.assertIn("- (#855) Migration: none for a caller of the old door; a caller that matched its words reads the new ones.", text)
        self.assertIn("interpreter): `VERDICTS: 13765 entries, 0 divergences`", text)
        self.assertIn("named reason): `total=5116 run=4121", text)
        self.assertIn("- wasm32 slices that passed: combined; not passed or not recorded: overlay.", text)
        self.assertIn("- Dependents built against this tree: none (the dependent matrix was skipped in this run).", text)
        # job 23's log was never saved: the 502 the live API gave on 2026-11-11
        self.assertIn("- The test suite, Linux stable: not recorded (the log of job 23: HTTP 502).", text)

    def test_the_suite_sums_libtest_and_nextest_lines_and_no_test_named_result(self):
        log = "\n".join([
            "2026-11-04T18:10:36.0046353Z      Summary [  25.326s] 1747 tests run: 1747 passed, 4 skipped",
            "2026-11-04T18:14:29.3623060Z      Summary [ 135.032s] 3281 tests run: 3279 passed, 2 failed, 26 skipped",
            "test result_frame_tests::a ... ok",
            "test result: ok. 295 passed; 0 failed; 128 ignored; 0 measured; 0 filtered out",
        ])
        self.assertEqual(fp.test_sum(log), (1, 2, 5321, 2, 158))
        self.assertIsNone(fp.test_sum("Summary of nothing\ntest result_frame ok"))

    def test_a_run_without_the_oracle_says_not_run_on_this_line(self):
        self.assertIn("interpreter): not run on this line (no `CI / sibling` job in this run).", self.notes("v0.8.7", "7"))

    def test_jobs_that_cannot_be_read_are_not_recorded_never_guessed(self):
        self.drop("run/7.jobs.json")
        text = self.notes("v0.8.7", "7")
        self.assertIn("- Every figure of the run: not recorded (the jobs of run 7: HTTP 502).", text)
        self.assertNotIn("passed,", text)

    def test_a_run_that_cannot_be_read_is_not_recorded_and_notes_exits_0(self):
        # the cold re-read's `:476`: `notes --run <id>` on a run it cannot read wrote a traceback
        text = self.notes("v0.8.7", "404")
        self.assertIn("- Every figure of the run: not recorded (run 404 could not be read: run 404: Not Found).", text)
        self.assertIn("- The run: not recorded (run 404).", text)
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(fp.main(["--offline", str(self.root), "notes", "v0.8.7", "--run", "404"]), 0)
        self.assertIn("::warning::front_pages: run 404 could not be read", err.getvalue())

    def test_a_log_without_the_line_says_so(self):
        self.write("logs/11.log", "nothing here\n")
        self.assertIn("not recorded (no such line in `CI / vectors`'s log).", self.notes("v0.8.7", "7"))

    def test_a_tag_without_its_section_is_refused(self):
        self.write("tree/v0.8.7/CHANGELOG.md", "## [0.8.6] - 2026-11-11\n")
        with self.assertRaisesRegex(fp.Stop, r"no `## \[0.8.7\]` heading"):
            self.notes("v0.8.7")

    def test_a_section_heading_is_matched_whole(self):
        self.write("tree/v0.8.7/CHANGELOG.md", "## [0.8.70] - 2026-12-01\n### Fixed: x (#1)\n")
        with self.assertRaises(fp.Stop):
            self.notes("v0.8.7")

    def test_the_run_of_another_tag_is_refused(self):
        with self.assertRaisesRegex(fp.Stop, "not of v0.8.7"):
            self.notes("v0.8.7", "8")

    def test_unreadable_advisories_are_not_recorded(self):
        source = self.source()
        with mock.patch.object(fp.Offline, "advisories", side_effect=fp.Unavailable("HTTP 403")):
            text = fp.notes(source, "v0.8.7")
        self.assertIn("- Published advisories: not recorded (HTTP 403).", text)
        # neither a security patch nor a plain one: whether it fixes one is not recorded
        self.assertTrue(text.startswith("A patch on the 0.8 line (whether it fixes a published advisory: not recorded)."))
        self.assertNotIn("No published advisory names this version", text)

    def test_a_version_no_advisory_names_says_published(self):
        self.write("advisories.json", "[]")
        self.assertIn("- No published advisory names this version.", self.notes("v0.8.7"))

    def test_a_minor_names_the_requirement_edit(self):
        self.assertEqual(
            fp.kind_line("0.9.0", []),
            'A minor release: the 0.9 line. To upgrade: set the requirement to `"0.9"` and read the Migration lines below.',
        )

    def test_a_body_past_the_limit_cuts_migration_lines_and_says_how_many(self):
        with mock.patch.object(fp, "BODY_LIMIT", 900):
            text = self.notes("v0.8.7", "7")
        self.assertIn("more Migration line(s): the changelog at the tag has them.", text)
        self.assertNotIn("A caller that passed bytes after the thing", text)


class EveryKindOfTag(World):
    """Every sentence a page can carry is true for every kind of tag (the captain's ruling R3):
    a stable patch that fixes an advisory, one that fixes none, a prerelease, a back-patch below
    the highest stable, an old release inside three ranges, a release with no run id."""

    def notes(self, tag, run=None):
        return fp.notes(self.source(), tag, run)

    def test_a_stable_patch_that_fixes_an_advisory(self):
        text = self.notes("v0.8.7", "7")
        self.assertTrue(text.startswith("A security patch on the 0.8 line."))
        self.assertIn("- Fixes [GHSA-aaaa-bbbb-cccc]", text)
        self.assertNotIn("Affected by", text)

    def test_a_stable_patch_that_fixes_none(self):
        text = self.notes("v0.8.8")
        self.assertTrue(text.startswith("A patch on the 0.8 line. To upgrade: `cargo update -p bsv-rs`"))
        self.assertIn("- No published advisory names this version.", text)
        self.assertNotIn("security", text.splitlines()[0])

    def test_a_prerelease_names_no_other_lines_patch_as_its_own(self):
        text = self.notes("v0.9.0-beta.1")
        self.assertIn("> Affected by a published advisory: [GHSA-aaaa-bbbb-cccc]", text)
        self.assertIn("no patched version on its line yet (patched on another line in 0.8.7).", text)
        self.assertNotIn(", patched in 0.8.7", text)
        self.assertNotIn("Patched in 0.8.7", text)

    def test_a_back_patch_is_a_patch_on_its_own_line(self):
        text = self.notes("v0.7.9")
        self.assertTrue(text.startswith("A security patch on the 0.7 line. To upgrade: `cargo update -p bsv-rs` (a `\"0.7\"` requirement takes it)."))
        self.assertNotIn("stable line", text)
        self.assertIn("- Fixes [GHSA-dddd-eeee-ffff]", text)
        self.assertRegex(text, r"> Affected by a published advisory: \[GHSA-aaaa-bbbb-cccc\]\S* \(medium, CVSS 5.3\), patched in 0\.8\.7\.")
        self.assertEqual(fp.flags(self.source(), "v0.7.9"), "--latest=false")

    def test_an_old_release_inside_three_ranges_names_each_range_patch(self):
        text = self.notes("v0.7.0")
        self.assertTrue(text.startswith("A minor release: the 0.7 line."))
        for ghsa, patched in (("GHSA-aaaa-bbbb-cccc", "0.8.7"), ("GHSA-dddd-eeee-ffff", "0.7.9"), ("GHSA-gggg-hhhh-jjjj", "0.7.1")):
            self.assertIn(f"> Affected by a published advisory: [{ghsa}]", text)
            self.assertRegex(text, rf"> Affected by a published advisory: \[{ghsa}\][^\n]*, patched in {patched}\.")
        self.assertEqual(text.count("> Affected by"), 3)

    def test_a_release_with_no_run_id_has_no_measured_block(self):
        text = self.notes("v0.8.8")
        self.assertNotIn("Measured at this tag", text)
        self.assertNotIn("not recorded", text)

    def test_hand_written_notes_sit_under_the_kind_line(self):
        text = self.notes("v0.8.7")
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("A security patch on the 0.8 line."))
        self.assertEqual(lines[2], "**In short.** `Thing::read` now refuses bytes after the thing; nothing else moved.")
        self.assertNotIn("# bsv-rs 0.8.7", text)  # the file's title is not repeated
        self.assertLess(text.index("**How it was checked.**"), text.index("## Changes"))
        self.assertNotIn("**In short.**", self.notes("v0.8.8"))  # no file at that tag, nothing placed

    def test_a_dry_runs_hand_notes_stand_in_for_the_tags(self):
        text = fp.notes(self.source(), "v0.8.8", None, "# bsv-rs 0.8.8\n\n**In short.** a dry run.\n")
        self.assertEqual(text.splitlines()[2], "**In short.** a dry run.")


class Advisories(unittest.TestCase):
    """This repository's published advisories or Unavailable, never another database (R2)."""

    def test_gh_is_asked_for_published_alone(self):
        calls = []

        def gh(*args):
            calls.append(args)
            return "[]"

        with mock.patch.object(fp, "gh", side_effect=gh):
            self.assertEqual(fp.Live().advisories(), [])
        self.assertIn("state=published", calls[0][1])
        self.assertEqual(calls[0][-1], fp.ADVISORY_JQ)

    def test_without_a_token_the_same_endpoint_is_asked_unauthenticated_and_filtered(self):
        rows = [
            {"ghsa_id": "GHSA-1", "state": "published", "severity": "medium", "summary": "s", "html_url": "u",
             "cvss": {"score": 5.3}, "description": "published text",
             "vulnerabilities": [{"package": {"name": "bsv-rs"}, "vulnerable_version_range": "< 0.8.6", "patched_versions": "0.8.6"}]},
            {"ghsa_id": "GHSA-2", "state": "draft", "summary": "PLANTED DRAFT TEXT"},
        ]
        urls = []

        def http(url):
            urls.append(url)
            return json.dumps(rows)

        with mock.patch.object(fp, "gh", side_effect=fp.Unavailable("gh api: HTTP 403")), mock.patch.object(fp, "http", side_effect=http):
            got = fp.Live().advisories()
        self.assertEqual(urls, [f"https://api.github.com/repos/{fp.REPO}/security-advisories?state=published&per_page=100"])
        self.assertEqual([a["ghsa_id"] for a in got], ["GHSA-1"])
        self.assertEqual(got[0]["vulnerabilities"][0]["patched_versions"], "0.8.6")
        self.assertNotIn("PLANTED DRAFT", json.dumps(got))
        self.assertNotIn("description", json.dumps(got))

    def test_when_both_fail_it_is_unavailable_never_an_empty_list(self):
        with mock.patch.object(fp, "gh", side_effect=fp.Unavailable("gh api: HTTP 403")), \
                mock.patch.object(fp, "http", side_effect=fp.Unavailable("HTTP 502")):
            with self.assertRaisesRegex(fp.Unavailable, "HTTP 403.*unauthenticated: HTTP 502"):
                fp.Live().advisories()
        for answer in (None,):
            with mock.patch.object(fp, "gh", side_effect=fp.Unavailable("gh")), mock.patch.object(fp, "http", return_value=answer):
                with self.assertRaises(fp.Unavailable):
                    fp.Live().advisories()

    def test_the_global_database_is_never_asked(self):
        with mock.patch.object(fp, "gh", side_effect=fp.Unavailable("gh")), \
                mock.patch.object(fp, "http", side_effect=fp.Unavailable("x")) as http:
            with self.assertRaises(fp.Unavailable):
                fp.Live().advisories()
        self.assertTrue(all("api.github.com/advisories" not in str(c) for c in http.call_args_list))


class Producers(unittest.TestCase):
    """Every pattern the "Measured at this tag" block looks for has its producer in this tree
    (the captain's ruling R10): a renamed job or a changed summary line fails here, on the pull
    request that changes it, not on a tag's page as "not recorded". The patterns are read from
    `front_pages.py`'s own text where it names them, so a pattern moved there is moved here."""

    ROOT = Path(__file__).resolve().parents[2]

    def text(self, path):
        return (self.ROOT / path).read_text()

    def jobs(self, workflow):
        """{job name: job body} of a workflow, the name as GitHub shows it."""
        lines = self.text(workflow).splitlines()
        starts = [i for i, line in enumerate(lines) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line)]
        out = {}
        for n, i in enumerate(starts):
            body = "\n".join(lines[i:starts[n + 1] if n + 1 < len(starts) else len(lines)])
            named = re.search(r"^    name: (.+)$", body, re.M)
            out[(named.group(1) if named else lines[i].strip()[:-1]).strip()] = body
        return out

    def source(self):
        return self.text(".github/scripts/front_pages.py")

    def test_the_release_names_its_calls_as_the_block_reads_them(self):
        release = self.jobs(".github/workflows/release.yml")
        self.assertIn("uses: ./.github/workflows/ci.yml", release.get("CI", ""))
        self.assertIn("uses: ./.github/workflows/features.yml", release.get("Features", ""))

    def test_the_corpus_summary_line_has_its_producer(self):
        self.assertIn('"=== sdk.scripts.evaluation summary ==="', self.source())
        conformance = self.text("tests/conformance_scripts.rs")
        self.assertIn('println!("=== {} summary ===", name);', conformance)
        self.assertIn('summary.print("sdk.scripts.evaluation");', conformance)
        self.assertIn('"total={} run={} passed={}', conformance)
        # the job the block reads it from runs that test with its output shown
        self.assertIn('["CI / vectors", "CI / checks"]', self.source())
        ci = self.jobs(".github/workflows/ci.yml")
        runner = [b for n, b in ci.items() if n in ("vectors", "checks") and "--test conformance_scripts" in b]
        self.assertTrue(runner, "no vectors or checks job of ci.yml runs --test conformance_scripts")
        self.assertIn("--nocapture", runner[0])

    def test_the_linux_stable_cell_has_its_producer(self):
        self.assertIn('"CI / Test Suite (ubuntu-latest, stable)"', self.source())
        body = self.jobs(".github/workflows/ci.yml").get("Test Suite", "")
        self.assertIn("matrix:", body, "ci.yml has no `Test Suite` job with a matrix")
        matrix = body[body.index("matrix:"):]
        keys = re.findall(r"^        (\w+):", matrix, re.M)
        self.assertEqual(keys[:2], ["os", "rust"])  # GitHub names a cell by its values in this order
        self.assertIn('"ubuntu-latest"', matrix)
        self.assertIn('"stable"', matrix)

    def test_the_oracle_line_has_its_producer_where_the_line_runs_one(self):
        self.assertIn('["CI / sibling"]', self.source())
        self.assertIn('startswith("VERDICTS:")', self.source())
        if "sibling" in self.jobs(".github/workflows/ci.yml"):
            self.assertIn('print(f"VERDICTS: {entries} entries, {total} divergences{split}")', self.text(".github/scripts/sibling_harness.py"))

    def test_the_wasm32_slices_have_their_producers(self):
        self.assertIn(r'(?:CI|Features) / wasm32 \((.+)\)', self.source())
        self.assertIn("wasm32 (${{ matrix.consumer }})", self.jobs(".github/workflows/features.yml"))
        ci = self.jobs(".github/workflows/ci.yml")
        combined = 'echo "PASS wasm32 (combined)"' in self.text(".github/workflows/ci.yml")
        self.assertTrue(combined or "wasm32 (${{ matrix.consumer }})" in ci,
                        "ci.yml carries neither the combined slice's PASS line nor a wasm32 matrix job")
        if combined:
            self.assertIn('"PASS wasm32 (combined)"', self.source())

    def test_the_dependents_have_their_producer(self):
        self.assertIn(r'CI / dependent \((.+)\)', self.source())
        self.assertIn("dependent (${{ matrix.id }})", self.jobs(".github/workflows/ci.yml"))


class LiveLog(unittest.TestCase):
    def test_a_log_is_read_with_its_colours_and_an_older_gh_without_the_flag(self):
        calls = []

        def older_gh(*args):
            calls.append(args)
            if "--allow-escape-sequences" in args:
                raise fp.Unavailable("gh api: unknown flag: --allow-escape-sequences")
            return "log"

        with mock.patch.object(fp, "gh", side_effect=older_gh):
            self.assertEqual(fp.Live().job_log(5), "log")
        self.assertEqual(len(calls), 2)
        with mock.patch.object(fp, "gh", side_effect=fp.Unavailable("HTTP 502")):
            with self.assertRaisesRegex(fp.Unavailable, "502"):
                fp.Live().job_log(5)


class Flags(World):
    def test_a_prerelease_never_takes_the_mark(self):
        self.assertEqual(fp.flags(self.source(), "v0.9.0-beta.1"), "--prerelease --latest=false")

    def test_the_highest_stable_takes_the_mark(self):
        self.assertEqual(fp.flags(self.source(), "v0.8.7"), "--latest")
        self.assertEqual(fp.flags(self.source(), "v0.8.8"), "--latest")  # not yet in the answer

    def test_a_back_patch_does_not(self):
        self.assertEqual(fp.flags(self.source(), "v0.8.6"), "--latest=false")
        self.assertEqual(fp.flags(self.source(), "v0.7.9"), "--latest=false")


class Check(World):
    def test_the_recorded_world_is_green(self):
        lines = self.lines()
        self.assertEqual([l.split(":")[0] for l in lines],
                         ["PASS versions", "PASS pages", "PASS docs.rs", "PASS readme", "PASS security", "PASS about", "PASS notices"])

    def test_versions_red_when_latest_is_another(self):
        self.write("latest_release.json", '{"tag_name": "v0.8.6"}')
        self.assertEqual(len(self.failing("versions")), 1)

    def test_versions_red_when_a_newer_stable_tag_is_unpublished(self):
        self.edit("tags.json", lambda t: t + ["v0.8.8"])
        self.assertEqual(len(self.failing("versions")), 1)

    def test_versions_pending_only_while_the_index_lags_behind_the_page(self):
        # the tag and its page are there, crates.io's index has not caught up: time heals it
        self.edit("tags.json", lambda t: t + ["v0.8.8"])
        self.write("latest_release.json", '{"tag_name": "v0.8.8"}')
        self.assertTrue(self.failing("versions")[0].endswith("(pending: time may heal it)"))
        # Latest on another page is permanent: not pending
        self.write("latest_release.json", '{"tag_name": "v0.8.6"}')
        self.assertFalse(self.failing("versions")[0].endswith("(pending: time may heal it)"))

    def test_versions_permanent_when_crates_io_is_ahead_of_every_tag(self):
        # a publish with no tag: crates.io ahead of the newest stable tag, which is Latest; time
        # heals nothing (the rule re-read's `:757`, the captain's ruling T3 (a))
        self.edit("crate.json", lambda c: dict(c, crate=dict(c["crate"], max_stable_version="0.8.8")))
        failing = self.failing("versions")
        self.assertEqual(len(failing), 1)
        self.assertFalse(failing[0].endswith("(pending: time may heal it)"), failing[0])

    def test_pages_red_on_a_missing_page_even_for_a_yanked_version(self):
        self.edit("releases.json", lambda r: [x for x in r if x["tag_name"] != "v0.8.6"])
        self.assertEqual(self.failing("pages"), ["FAIL pages: crates.io serves 0.8.6 and no Release page names v0.8.6 (the tag exists)"])

    def test_pages_red_on_a_draft_alone(self):
        self.edit("releases.json", lambda r: [dict(x, draft=True) if x["tag_name"] == "v0.8.7" else x for x in r])
        self.assertIn("no Release page names v0.8.7", self.failing("pages")[0])

    def test_pages_red_on_a_prerelease_unmarked_and_a_stable_marked(self):
        self.edit("releases.json", lambda r: [dict(x, prerelease=not x["prerelease"]) for x in r])
        self.assertEqual(len(self.failing("pages")), 3)

    def test_pages_tolerate_the_five_untagged_versions_by_name_alone(self):
        self.edit("crate.json", lambda c: dict(c, versions=c["versions"] + [{"num": v, "yanked": False} for v in fp.UNTAGGED]))
        self.assertEqual(self.failing("pages"), [])
        tolerated = [l for l in self.lines() if l.startswith("(pages tolerated by name")]
        self.assertEqual(len(tolerated), 1)
        for version, reason in fp.UNTAGGED.items():
            self.assertIn(f"{version}: {reason}", tolerated[0])
        # any other untagged version is red
        self.edit("crate.json", lambda c: dict(c, versions=c["versions"] + [{"num": "0.3.21", "yanked": False}]))
        self.assertEqual(self.failing("pages"), ["FAIL pages: crates.io serves 0.3.21 and no Release page names v0.3.21 (no tag either)"])

    def test_the_untagged_versions_are_the_five_named_and_no_other(self):
        # the captain's ruling R7: no general baseline; a member gained or lost fails here (T5)
        self.assertEqual(set(fp.UNTAGGED), {"0.3.20", "0.3.19", "0.3.18", "0.3.0", "0.2.0"})

    def test_pages_red_when_a_tolerated_version_gains_a_tag(self):
        self.edit("crate.json", lambda c: dict(c, versions=c["versions"] + [{"num": v, "yanked": False} for v in fp.UNTAGGED]))
        self.edit("tags.json", lambda t: t + ["v0.3.20"])
        failing = self.failing("pages")
        self.assertIn("FAIL pages: crates.io serves 0.3.20 and no Release page names v0.3.20 (the tag exists)", failing)
        self.assertIn("FAIL pages: UNTAGGED names 0.3.20, which now has a tag or a page: drop it", failing)

    def test_pages_red_on_a_page_for_a_version_crates_io_lacks(self):
        self.edit("releases.json", lambda r: r + [{"tag_name": "v0.8.4", "prerelease": False, "draft": False, "body": ""}])
        self.assertEqual(self.failing("pages"), ["FAIL pages: the Release page v0.8.4 names a version crates.io does not serve"])

    def answer(self, case, version="0.8.7"):
        """docs.rs's recorded answer of a kind (docsrs_answers/, read 2026-11-11) planted for
        `version`: its status with the version replaced, its builds page as served."""
        answers = WORLD / "docsrs_answers"
        status = json.loads((answers / f"{case}.status.json").read_text())
        self.write(f"docsrs/{version}.status.json", json.dumps(dict(status, version=version)))
        self.write(f"docsrs/{version}.builds.html", (answers / f"{case}.builds.html").read_text())

    def test_docs_pending_while_queued_docs_rs_answers_404(self):
        self.assertTrue((WORLD / "docsrs_answers" / "queued.status.404.txt").read_text().startswith("HTTP 404\n"))
        self.drop("docsrs/0.8.7.status.json")
        self.assertEqual(self.failing("docs.rs"), ["FAIL docs.rs: no build of 0.8.7 yet (docs.rs has no release: queued) (pending: time may heal it)"])

    def test_docs_pending_while_its_build_is_in_progress(self):
        # the strength re-read's F-1: `doc_status: false` for a release docs.rs is building
        self.answer("building")
        self.assertEqual(self.failing("docs.rs"), ["FAIL docs.rs: the build of 0.8.7 is not finished (in progress) (pending: time may heal it)"])

    def test_docs_red_and_permanent_on_a_failed_build(self):
        self.answer("failed")
        self.assertEqual(self.failing("docs.rs"), ["FAIL docs.rs: the build of 0.8.7 did not succeed: All builds failed"])

    def test_docs_green_on_a_built_answer(self):
        self.answer("built")
        self.assertEqual(self.failing("docs.rs"), [])

    def test_docs_pending_when_the_builds_page_lists_no_build(self):
        self.answer("failed")
        self.drop("docsrs/0.8.7.builds.html")
        self.assertTrue(self.failing("docs.rs")[0].endswith("(none recorded) (pending: time may heal it)"))

    def test_docs_modules_not_judged_for_a_manifest_that_did_not_ask_for_every_feature(self):
        # the strength re-read's F-2: 0.8.6's manifest carries no `[package.metadata.docs.rs]`, so
        # docs.rs shows its default modules forever; the rule says so by name (T4)
        self.write("docsrs/0.8.7.html", '<a class="mod" href="error/index.html">error</a>')
        manifest = (WORLD / "tree/v0.8.7/Cargo.toml").read_text()
        self.write("tree/v0.8.7/Cargo.toml", manifest.split("\n[package.metadata.docs.rs]")[0] + "\n")
        lines = self.lines()
        self.assertIn("PASS docs.rs: 0.8.7 built; not judged: 0.8.7's manifest does not ask docs.rs for every feature", lines)
        self.write("tree/v0.8.7/Cargo.toml", manifest.replace("all-features = true", "all-features = false"))
        self.assertIn("PASS docs.rs: 0.8.7 built; not judged: 0.8.7's manifest does not ask docs.rs for every feature", self.lines())
        # no manifest at the tag in this checkout: nothing asked, not judged
        self.drop("tree/v0.8.7/Cargo.toml")
        self.assertIn("PASS docs.rs: 0.8.7 built; not judged: 0.8.7's manifest does not ask docs.rs for every feature", self.lines())
        # the manifest that asks is judged
        self.write("tree/v0.8.7/Cargo.toml", manifest)
        self.assertEqual(len(self.failing("docs.rs")), 1)

    def test_docs_red_on_a_module_the_page_lacks(self):
        self.write("docsrs/0.8.7.html", '<a class="mod" href="error/index.html">error</a><a class="mod" href="primitives/index.html">p</a>')
        self.assertEqual(self.failing("docs.rs"), [
            "FAIL docs.rs: 0.8.7's page shows 2 of the 3 public modules; absent: transaction (Cargo.toml's `[package.metadata.docs.rs]`)"])

    def test_readme_red_on_each_version_form_before_examples(self):
        for planted in ("<p>bsv-rs v0.8.7</p>", "<p>tag v0.9.0-beta.1</p>", "<code>cargo add bsv-rs@0.8</code>",
                        "<p>bsv-rs <strong>0.8.7</strong></p>", '<code>bsv-rs = { version = "0.8", features = [] }</code>',
                        '<code>bsv-rs = "=0.8"</code>', "<p>since 0.9.0-beta.1</p>"):
            with self.subTest(planted=planted):
                self.write("readme/0.8.7.html", (WORLD / "readme/0.8.7.html").read_text().replace("<h2 id=\"user-content-examples\"", planted + "<h2 id=\"user-content-examples\"", 1))
                self.assertEqual(len(self.failing("readme")), 1)

    def test_readme_green_on_a_version_after_examples(self):
        self.assertIn("0.7.0", (WORLD / "readme/0.8.7.html").read_text())
        self.assertEqual(self.failing("readme"), [])

    def test_readme_red_without_an_examples_heading(self):
        self.write("readme/0.8.7.html", "<h1>bsv-rs</h1>")
        self.assertIn("no `Examples` heading", self.failing("readme")[0])

    def test_readme_red_and_pending_when_not_rendered(self):
        self.drop("readme/0.8.7.html")
        self.assertTrue(self.failing("readme")[0].endswith("(pending: time may heal it)"))

    def test_readme_not_judged_before_its_first_version(self):
        self.write("readme/0.8.7.html", "<h1>bsv-rs 0.8.7</h1>")
        self.assertEqual(self.failing("readme", readme_from="0.8.8"), [])
        self.assertEqual(len(self.failing("readme", readme_from="0.8.7")), 1)

    def test_security_red_without_the_file_on_a_line(self):
        self.write("security.json", '{"main": false, "beta": true}')
        self.assertEqual(self.failing("security"), ["FAIL security: no SECURITY.md on main"])

    def test_about_red_on_the_description_and_the_homepage(self):
        self.write("repo.json", '{"description": "The best BSV SDK.", "homepage": "https://example.com"}')
        failure = self.failing("about")[0]
        self.assertIn("description", failure)
        self.assertIn("homepage https://example.com is not the manifest's documentation", failure)

    def test_about_reads_homepage_when_the_manifest_has_no_documentation(self):
        self.write("tree/v0.8.7/Cargo.toml", '[package]\nname = "bsv-rs"\ndescription = "A BSV SDK for Rust."\nhomepage = "https://docs.rs/bsv-rs"\n')
        self.assertEqual(self.failing("about"), [])

    def test_notices_red_on_a_page_in_a_range_without_its_advisory(self):
        self.edit("releases.json", lambda r: [dict(x, body="") if x["tag_name"] == "v0.8.6" else x for x in r])
        self.assertIn("v0.8.6 (GHSA-aaaa-bbbb-cccc)", self.failing("notices")[0])

    def test_notices_red_on_a_failed_read_of_the_advisories(self):
        with mock.patch.object(fp.Offline, "advisories", side_effect=fp.Unavailable("HTTP 502")):
            self.assertEqual(self.failing("notices"), ["FAIL notices: could not read: HTTP 502"])

    def test_notices_red_on_the_patched_page_that_does_not_name_its_fix(self):
        # the page of 0.8.7 was made before GHSA-aaaa was published (step 23 (f))
        self.edit("releases.json", lambda r: [dict(x, body="A security patch.") if x["tag_name"] == "v0.8.7" else x for x in r])
        self.assertIn("v0.8.7 (GHSA-aaaa-bbbb-cccc under Fixes)", self.failing("notices")[0])
        # an id in the page that is not a Fixes line does not answer it
        self.edit("releases.json", lambda r: [dict(x, body="> Affected by GHSA-aaaa-bbbb-cccc") if x["tag_name"] == "v0.8.7" else x for x in r])
        self.assertIn("under Fixes", self.failing("notices")[0])

    def test_notices_ignore_a_draft_advisory(self):
        # the planted draft's range holds every page; were it read, every page would be red
        self.assertEqual(self.failing("notices"), [])

    def test_an_unreadable_source_is_red_not_skipped(self):
        with mock.patch.object(fp.Offline, "repo", side_effect=fp.Unavailable("HTTP 502")):
            self.assertEqual(self.failing("about"), ["FAIL about: could not read: HTTP 502"])
        self.drop("crate.json")
        self.assertEqual(self.failing("versions"), ["FAIL versions: could not read: crates.io has no crate"])

    def test_the_command_exits_red_and_waits_only_on_pending(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fp.main(["--offline", str(self.root), "check"]), 0)
        self.assertTrue(out.getvalue().endswith("PASS: 0 failure(s)\n"))
        self.drop("docsrs/0.8.7.status.json")
        out = io.StringIO()
        with mock.patch.object(fp.time, "sleep") as sleep, contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(fp.time, "monotonic", side_effect=[0, 0, 0, 500, 500]):
                # a release that published is not red for the clock: pending alone after the
                # wait ends with a warning naming it and exit 0 (the captain's ruling R11)
                self.assertEqual(fp.main(["check", "--offline", str(self.root), "--wait", "300"]), 0)
            self.assertEqual(sleep.call_count, 1)
        self.assertIn("::warning::FAIL docs.rs: no build of 0.8.7 yet (docs.rs has no release: queued) (pending: time may heal it)", out.getvalue())
        self.assertTrue(out.getvalue().endswith("left to a dispatch of front-pages.yml\n"))
        # without a wait (the dispatch's default) the same answer is red
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fp.main(["check", "--offline", str(self.root)]), 1)
        shutil.copy(WORLD / "docsrs/0.8.7.status.json", self.root / "docsrs/0.8.7.status.json")
        self.write("security.json", '{"main": false, "beta": true}')
        with mock.patch.object(fp.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(fp.time, "monotonic", side_effect=[0, 0, 0, 500, 500]):
                self.assertEqual(fp.main(["check", "--offline", str(self.root), "--wait", "300"]), 1)
            sleep.assert_not_called()  # a permanent miss waits for nothing

    def test_a_mixed_failure_after_the_wait_is_red(self):
        # one failure time heals beside one it does not: red, never the warning's exit 0 (the
        # captain's rulings R11 and T2; the mutation `pending > 0` survived until this test)
        self.drop("docsrs/0.8.7.status.json")
        self.write("security.json", '{"main": false, "beta": true}')
        out = io.StringIO()
        with mock.patch.object(fp.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(fp.time, "monotonic", side_effect=[0, 0, 0, 500, 500]):
                self.assertEqual(fp.main(["check", "--offline", str(self.root), "--wait", "300"]), 1)
        self.assertNotIn("::warning::", out.getvalue())
        self.assertTrue(out.getvalue().endswith("FAIL: 2 failure(s)\n"), out.getvalue())


if __name__ == "__main__":
    unittest.main()
