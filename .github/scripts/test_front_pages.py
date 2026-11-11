"""The Release page generator and the front pages' reconciler on recorded answers.

`fixtures/front_pages/` is a world in which every `check` rule passes; each test copies it,
plants one change and reads the verdict, so every rule is seen RED on a planted answer and
green on the recorded one. No test reaches the network.
"""

import contextlib
import io
import json
from pathlib import Path
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
        self.assertTrue(text.startswith("A patch on the stable line."))
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
        self.assertTrue(text.startswith("A patch on the stable line."))

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

    def test_pages_red_on_a_missing_page_even_for_a_yanked_version(self):
        self.edit("releases.json", lambda r: [x for x in r if x["tag_name"] != "v0.8.6"])
        self.assertEqual(self.failing("pages"), ["FAIL pages: crates.io serves 0.8.6 and no Release page names v0.8.6 (the tag exists)"])

    def test_pages_red_on_a_draft_alone(self):
        self.edit("releases.json", lambda r: [dict(x, draft=True) if x["tag_name"] == "v0.8.7" else x for x in r])
        self.assertIn("no Release page names v0.8.7", self.failing("pages")[0])

    def test_pages_red_on_a_prerelease_unmarked_and_a_stable_marked(self):
        self.edit("releases.json", lambda r: [dict(x, prerelease=not x["prerelease"]) for x in r])
        self.assertEqual(len(self.failing("pages")), 3)

    def test_pages_red_on_a_page_for_a_version_crates_io_lacks(self):
        self.edit("releases.json", lambda r: r + [{"tag_name": "v0.8.4", "prerelease": False, "draft": False, "body": ""}])
        self.assertEqual(self.failing("pages"), ["FAIL pages: the Release page v0.8.4 names a version crates.io does not serve"])

    def test_docs_red_and_pending_before_the_build(self):
        self.drop("docsrs/0.8.7.status.json")
        self.assertEqual(self.failing("docs.rs"), ["FAIL docs.rs: no build of 0.8.7 yet (pending: time may heal it)"])

    def test_docs_red_on_a_failed_build(self):
        self.write("docsrs/0.8.7.status.json", '{"doc_status": false, "version": "0.8.7"}')
        self.assertIn("did not succeed", self.failing("docs.rs")[0])

    def test_docs_red_on_a_module_the_page_lacks(self):
        self.write("docsrs/0.8.7.html", '<a class="mod" href="error/index.html">error</a><a class="mod" href="primitives/index.html">p</a>')
        self.assertEqual(self.failing("docs.rs"), [
            "FAIL docs.rs: 0.8.7's page shows 2 of the 3 public modules; absent: transaction (Cargo.toml's `[package.metadata.docs.rs]`)"])

    def test_readme_red_on_each_version_form_before_examples(self):
        for planted in ("<p>bsv-rs <strong>0.8.7</strong></p>", '<code>bsv-rs = { version = "0.8", features = [] }</code>',
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
        with mock.patch.object(fp.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(fp.time, "monotonic", side_effect=[0, 0, 0, 500, 500]):
                self.assertEqual(fp.main(["check", "--offline", str(self.root), "--wait", "300"]), 1)
            self.assertEqual(sleep.call_count, 1)
        shutil.copy(WORLD / "docsrs/0.8.7.status.json", self.root / "docsrs/0.8.7.status.json")
        self.write("security.json", '{"main": false, "beta": true}')
        with mock.patch.object(fp.time, "sleep") as sleep, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(fp.time, "monotonic", side_effect=[0, 0, 0, 500, 500]):
                self.assertEqual(fp.main(["check", "--offline", str(self.root), "--wait", "300"]), 1)
            sleep.assert_not_called()  # a permanent miss waits for nothing


if __name__ == "__main__":
    unittest.main()
