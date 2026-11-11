#!/usr/bin/env python3
"""The GitHub Release page of a tag, and the reconciler of the front pages.

Two commands (the design reads of 2026-11-11, decisions D7 to D9; RELEASING.md step 5):

`notes <tag> [--run <id>]` prints a Release page's notes, generated, never written by hand:
a line saying what kind of release it is and how to take it; a notice for each PUBLISHED
advisory whose range holds the version; the entries of the tag's own `CHANGELOG.md`
section (each `### ` heading is a sentence: one bullet each, its issue numbers kept; the
`Notes: cross-SDK parity` headings are counted, not listed); every Migration line of the
section; the published advisories this version fixes and those it is affected by; when a
run id is given, a "Measured at this tag" block read from that run's jobs and logs (the
corpus summary line, the summed `test result:` lines of the Linux stable cell, the script
oracle's `VERDICTS:` line or "not run on this line", the wasm32 slices that passed, the
dependents that were built, the run's URL); and the links. An input it cannot read is
written "not recorded" with the reason, never guessed.

`flags <tag>` prints the `gh release create` flags of the tag: `--prerelease --latest=false`
for a version with a `-`, `--latest` for the highest stable version crates.io serves,
`--latest=false` for a back-patch (it must not take the mark).

`check` is the reconciler, red on any miss (one PASS or FAIL line per rule, exit 1 on a
FAIL): crates.io's `max_stable_version`, GitHub's Latest release and the newest stable
`v*` tag agree; every version crates.io serves (yanked ones too: a lockfile still
resolves them) has a Release page, a prerelease marked so, and no page names a version
crates.io lacks; docs.rs built the newest stable version and its crate page lists every
`pub mod` of `src/lib.rs` at that tag (the tree's modules under `--all-features`: every
public module of the crate is declared at column 0 there, behind its feature); the README
crates.io renders for that version holds no version literal, no `=` pin and no
`version = "` before its `Examples` heading (for versions from `--readme-from` on, the
first release whose README was written to this rule); `SECURITY.md` exists on `main` and on
`beta`; the repository's description equals the manifest's and its homepage the manifest's
`documentation` (else its `homepage`); every Release page whose version lies in a
published advisory's range names that advisory. `--wait <seconds>` polls while the only
failures are ones time heals (docs.rs not yet built, crates.io not yet showing the
version), up to the bound. It is run by `release.yml` after the publish and by a dispatch
of `front-pages.yml` at an advisory sitting, never on a schedule (the owner's word of
2026-11-10).

Advisories: PUBLISHED alone. Every advisory call filters on `state == "published"` in its
`--jq`, and reads the id, severity, score, summary, link and ranges; no other state is read.

`--offline <dir>` reads saved answers instead of the network (the unit tests' fixtures,
`.github/scripts/fixtures/front_pages/`): `tree/<ref>/<path>`, `crate.json`, `tags.json`,
`releases.json`, `latest_release.json`, `advisories.json`, `docsrs/<v>.status.json`,
`docsrs/<v>.html`, `readme/<v>.html`, `security.json`, `repo.json`, `run/<id>.json`,
`run/<id>.jobs.json`, `logs/<job id>.log`; a missing file is the site's 404.
"""

import argparse
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

CRATE = "bsv-rs"
REPO = os.environ.get("GITHUB_REPOSITORY") or "Calhooon/bsv-rs"
USER_AGENT = "bsv-rs front_pages.py (https://github.com/Calhooon/bsv-rs)"
# GitHub refuses a release body above 125,000 characters; the notes stay below it
BODY_LIMIT = 120_000
# the first stable version whose README is held to the rule (D1; the hand fix of 2026-11-11)
README_FROM = "0.8.7"
# the published filter, in the call itself: no other state is fetched (the brief's rule)
ADVISORY_JQ = (
    'map(select(.state == "published")) | map({ghsa_id, state, severity, summary, html_url, '
    "score: .cvss.score, vulnerabilities: [.vulnerabilities[]? | {package: .package.name, "
    "vulnerable_version_range, patched_versions}]})"
)
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ")


class Stop(Exception):
    """A refusal: the tag has no section, the run is another tag's."""


class Unavailable(Exception):
    """A source that did not answer (not a 404)."""


# ---------------------------------------------------------------- versions


def parse(version):
    match = VERSION.fullmatch(version.strip())
    if not match:
        raise ValueError(f"not a version: {version!r}")
    return match


def key(version):
    """Semver order: a prerelease before its release, its identifiers compared by part."""
    major, minor, patch, pre = parse(version).groups()
    if pre is None:
        return (int(major), int(minor), int(patch), 1, ())
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (int(major), int(minor), int(patch), 0, parts)


def is_prerelease(version):
    return parse(version).group(4) is not None


def in_range(version, spec):
    """Whether `version` meets every comparator of a GitHub range (`>= a, < b`), by plain
    semver order (a prerelease compared as any version is; the published ranges name the
    prerelease line by its own bounds)."""
    if not spec:
        return False
    for part in spec.split(","):
        match = re.fullmatch(r"\s*(<=|>=|<|>|=)?\s*(\S+)\s*", part)
        if not match:
            raise ValueError(f"not a range: {spec!r}")
        op, bound = match.group(1) or "=", match.group(2)
        a, b = key(version), key(bound)
        if not {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "=": a == b}[op]:
            return False
    return True


def patched_in(version, patched):
    """Whether a `patched_versions` text (`0.8.6`, `>= 0.8.6`, a comma list) names the version."""
    for part in (patched or "").split(","):
        bare = re.sub(r"^\s*(<=|>=|<|>|=)?\s*", "", part).strip()
        if bare and VERSION.fullmatch(bare) and key(bare) == key(version):
            return True
    return False


# ---------------------------------------------------------------- sources


def gh(*args):
    done = subprocess.run(["gh", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise Unavailable(f"gh {' '.join(args[:2])}: {(done.stderr or done.stdout).strip()[:200]}")
    return done.stdout


def http(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as answer:
            return answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise Unavailable(f"{url}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise Unavailable(f"{url}: {error}") from error


def lines_of_json(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


class Live:
    """The sites as they answer now."""

    def tree(self, ref, path):
        done = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True, text=True)
        return done.stdout if done.returncode == 0 else None

    def crate(self):
        text = http(f"https://crates.io/api/v1/crates/{CRATE}")
        if text is None:
            raise Unavailable(f"crates.io has no crate {CRATE}")
        return json.loads(text)

    def tags(self):
        return lines_of_json(gh("api", "--paginate", f"repos/{REPO}/tags?per_page=100", "--jq", ".[] | .name | tojson"))

    def releases(self):
        jq = ".[] | {tag_name, prerelease, draft, body} | tojson"
        return lines_of_json(gh("api", "--paginate", f"repos/{REPO}/releases?per_page=100", "--jq", jq))

    def latest_release(self):
        try:
            return json.loads(gh("api", f"repos/{REPO}/releases/latest", "--jq", "{tag_name}"))["tag_name"]
        except Unavailable as error:
            if "404" in str(error) or "Not Found" in str(error):
                return None
            raise

    def advisories(self):
        try:
            return json.loads(gh("api", f"repos/{REPO}/security-advisories?per_page=100", "--jq", ADVISORY_JQ))
        except Unavailable:
            # the global database, reviewed advisories alone (published by definition)
            text = http(f"https://api.github.com/advisories?ecosystem=rust&affects={CRATE}&per_page=100")
            out = []
            for row in json.loads(text or "[]"):
                if row.get("withdrawn_at"):
                    continue
                out.append({
                    "ghsa_id": row["ghsa_id"], "state": "published", "severity": row.get("severity"),
                    "summary": row.get("summary"), "html_url": row.get("html_url"),
                    "score": (row.get("cvss") or {}).get("score"),
                    "vulnerabilities": [
                        {"package": (v.get("package") or {}).get("name"),
                         "vulnerable_version_range": v.get("vulnerable_version_range"),
                         "patched_versions": v.get("first_patched_version")}
                        for v in row.get("vulnerabilities") or []
                    ],
                })
            return out

    def docsrs_status(self, version):
        text = http(f"https://docs.rs/crate/{CRATE}/{version}/status.json")
        return None if text is None else json.loads(text)

    def docsrs_index(self, version):
        return http(f"https://docs.rs/{CRATE}/{version}/{CRATE.replace('-', '_')}/index.html")

    def crate_readme(self, version):
        return http(f"https://crates.io/api/v1/crates/{CRATE}/{version}/readme")

    def security_md(self, ref):
        try:
            gh("api", f"repos/{REPO}/contents/SECURITY.md?ref={ref}", "--jq", ".path")
            return True
        except Unavailable as error:
            if "404" in str(error) or "Not Found" in str(error):
                return False
            raise

    def repo(self):
        return json.loads(gh("api", f"repos/{REPO}", "--jq", "{description, homepage}"))

    def run(self, run_id):
        jq = "{html_url, head_branch, head_sha, check_suite_id}"
        return json.loads(gh("api", f"repos/{REPO}/actions/runs/{run_id}", "--jq", jq))

    def jobs(self, run_id):
        # a run's jobs through its check suite: the jobs endpoint answered 502 for every
        # release run on 2026-11-11, the check runs (one per job, the same id) did not
        suite = self.run(run_id)["check_suite_id"]
        jq = ".check_runs[] | {id, name, status, conclusion} | tojson"
        return lines_of_json(gh("api", "--paginate", f"repos/{REPO}/check-suites/{suite}/check-runs?per_page=100", "--jq", jq))

    def job_log(self, job_id):
        # a job's log carries ANSI colours (CARGO_TERM_COLOR=always), which gh 2.101 refuses to
        # print without this flag; an older gh lacks the flag and prints them
        try:
            return gh("api", "--allow-escape-sequences", f"repos/{REPO}/actions/jobs/{job_id}/logs")
        except Unavailable as error:
            if "unknown flag" not in str(error):
                raise
            return gh("api", f"repos/{REPO}/actions/jobs/{job_id}/logs")


class Offline:
    """Saved answers in a folder, one file per answer; a missing file is a 404."""

    def __init__(self, root):
        self.root = Path(root)

    def _text(self, name):
        path = self.root / name
        return path.read_text() if path.is_file() else None

    def _json(self, name, default=None):
        text = self._text(name)
        return default if text is None else json.loads(text)

    def tree(self, ref, path):
        return self._text(f"tree/{ref}/{path}")

    def crate(self):
        answer = self._json("crate.json")
        if answer is None:
            raise Unavailable("crates.io has no crate")
        return answer

    def tags(self):
        return self._json("tags.json", [])

    def releases(self):
        return self._json("releases.json", [])

    def latest_release(self):
        return (self._json("latest_release.json") or {}).get("tag_name")

    def advisories(self):
        # the saved answer filtered again: a planted draft must never reach the notes
        return [a for a in self._json("advisories.json", []) if a.get("state") == "published"]

    def docsrs_status(self, version):
        return self._json(f"docsrs/{version}.status.json")

    def docsrs_index(self, version):
        return self._text(f"docsrs/{version}.html")

    def crate_readme(self, version):
        return self._text(f"readme/{version}.html")

    def security_md(self, ref):
        return bool(self._json("security.json", {}).get(ref))

    def repo(self):
        return self._json("repo.json", {})

    def run(self, run_id):
        answer = self._json(f"run/{run_id}.json")
        if answer is None:
            raise Unavailable(f"run {run_id}: Not Found")
        return answer

    def jobs(self, run_id):
        answer = self._json(f"run/{run_id}.jobs.json")
        if answer is None:
            raise Unavailable(f"the jobs of run {run_id}: HTTP 502")
        return answer

    def job_log(self, job_id):
        text = self._text(f"logs/{job_id}.log")
        if text is None:
            raise Unavailable(f"the log of job {job_id}: HTTP 502")
        return text


# ---------------------------------------------------------------- the changelog


def section(changelog, version):
    """The tag's section: from `## [X.Y.Z]` to the next `## [`."""
    lines = changelog.splitlines()
    head = re.compile(r"^## \[" + re.escape(version) + r"\](\s|$)")
    start = next((i for i, line in enumerate(lines) if head.match(line)), None)
    if start is None:
        raise Stop(f"CHANGELOG.md has no `## [{version}]` heading")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    return lines[start + 1:end]


def paragraphs(lines):
    """Blocks of a section: a heading alone, a bullet with its continuation lines, a paragraph."""
    blocks, current = [], []
    for line in lines:
        starts = line.startswith("#") or line.startswith("- ") or not line.strip()
        if starts and current:
            blocks.append(" ".join(part.strip() for part in current))
            current = []
        if line.strip():
            current.append(line)
            if line.startswith("#"):
                blocks.append(line.strip())
                current = []
    if current:
        blocks.append(" ".join(part.strip() for part in current))
    return blocks


def first_sentence(text, limit=400):
    match = re.match(r"(.+?[.:])(\s|$)", text)
    sentence = match.group(1) if match else text
    if len(sentence) > limit:
        sentence = sentence[:limit].rsplit(" ", 1)[0] + " (cut; the changelog has the rest)"
    return sentence


def entries(lines):
    """(entries, parity notes counted, migrations): each `### ` heading a bullet; a bare kind
    heading (`### Changed`) gives one bullet per top-level bullet under it."""
    out, notes, migrations = [], 0, []
    heading, bare = None, False
    for block in paragraphs(lines):
        if block.startswith("### "):
            heading = block[4:].strip()
            bare = ":" not in heading
            if heading.startswith("Notes"):
                notes += 1
            elif not bare:
                out.append(heading)
            continue
        if block.startswith("#"):
            continue
        if bare and heading and not heading.startswith("Notes") and block.startswith("- "):
            out.append(f"{heading}: {first_sentence(block[2:])}")
        if block.startswith("- Migration."):
            migrations.append((heading, block[2:]))
        elif "Migration:" in block and not (heading or "").startswith("Notes"):
            migrations.append((heading, block[block.index("Migration:"):]))
    return out, notes, migrations


def issues_of(heading):
    found = re.findall(r"#\d+", heading or "")
    return ", ".join(dict.fromkeys(found))


# ---------------------------------------------------------------- the run


def clean(log):
    for raw in log.splitlines():
        yield STAMP.sub("", ANSI.sub("", raw)).rstrip()


def corpus_line(log):
    lines = list(clean(log))
    for i, line in enumerate(lines):
        if line.strip() == "=== sdk.scripts.evaluation summary ===" and i + 1 < len(lines):
            return lines[i + 1].strip()
    return None


def test_sum(log):
    """(libtest's `test result:` lines, nextest's `Summary` lines, passed, failed, ignored or
    skipped), summed over the job's log; None when it holds neither form. The Test Suite runs
    under nextest on `beta` (`N tests run: P passed, F failed, S skipped`) and under
    `cargo test` on `main`, its doc tests under `cargo test` on both."""
    totals, results, summaries = [0, 0, 0], 0, 0
    for line in clean(log):
        line = line.strip()
        match = re.match(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", line)
        if match:
            results += 1
            for i in range(3):
                totals[i] += int(match.group(i + 1))
            continue
        match = re.match(r"^Summary \[[^\]]*\] \d+ tests? run: (.*)$", line)
        if match:
            summaries += 1
            for i, word in enumerate(("passed", "failed", "skipped")):
                found = re.search(rf"(\d+) {word}", match.group(1))
                totals[i] += int(found.group(1)) if found else 0
    return (results, summaries, *totals) if results or summaries else None


def verdicts_line(log):
    for line in clean(log):
        if line.strip().startswith("VERDICTS:"):
            return line.strip()
    return None


def measured(source, tag, run_id):
    """The "Measured at this tag" block, from the run's jobs and their logs."""
    run = source.run(run_id)
    if run.get("head_branch") != tag:
        raise Stop(f"run {run_id} is the run of {run.get('head_branch')!r}, not of {tag}")
    out = ["## Measured at this tag", ""]
    try:
        jobs = source.jobs(run_id)
    except Unavailable as error:
        out.append(f"- Every figure of the run: not recorded ({error}).")
        out.append(f"- The run: {run['html_url']}")
        return out
    done = [j for j in jobs if j.get("status", "completed") == "completed"]
    by_name = {j["name"]: j for j in done}

    def log_of(job):
        try:
            return source.job_log(job["id"]), None
        except Unavailable as error:
            return None, str(error)

    def from_job(names, reader, label, absent):
        job = next((by_name[n] for n in names if n in by_name), None)
        if job is None:
            return f"- {label}: {absent}."
        log, why = log_of(job)
        if log is None:
            return f"- {label}: not recorded ({why})."
        found = reader(log)
        if found is None:
            return f"- {label}: not recorded (no such line in `{job['name']}`'s log)."
        return f"- {label}: {found}."

    out.append(from_job(
        ["CI / vectors", "CI / checks"],
        lambda log: (lambda line: f"`{line}`" if line else None)(corpus_line(log)),
        "The ts-stack corpus (`tests/conformance_scripts.rs`, every vector run or counted under a named reason)",
        "not recorded (no vectors job in this run)",
    ))

    def tests(log):
        summed = test_sum(log)
        if summed is None:
            return None
        results, summaries, passed, failed, ignored = summed
        parts = [f"{results} `test result:` line(s)"] if results else []
        parts += [f"{summaries} nextest summary line(s)"] if summaries else []
        return f"{passed:,} passed, {failed:,} failed, {ignored:,} ignored or skipped (the sum of {' and '.join(parts)})"

    out.append(from_job(
        ["CI / Test Suite (ubuntu-latest, stable)"], tests,
        "The test suite, Linux stable", "not recorded (no Linux stable cell in this run)",
    ))
    out.append(from_job(
        ["CI / sibling"],
        lambda log: (lambda line: f"`{line}`" if line else None)(verdicts_line(log)),
        "The script oracle (bsv-script-lean, a Lean specification of bitcoin-sv's script interpreter)",
        "not run on this line (no `CI / sibling` job in this run)",
    ))

    passed, other = [], []
    for job in done:
        match = re.fullmatch(r"(?:CI|Features) / wasm32 \((.+)\)", job["name"])
        if match:
            (passed if job.get("conclusion") == "success" else other).append(match.group(1))
    checks = by_name.get("CI / checks")
    if checks is not None and "combined" not in passed + other:
        log, why = log_of(checks)
        if log is None:
            other.append(f"combined: not recorded ({why})")
        elif any(line.strip() == "PASS wasm32 (combined)" for line in clean(log)):
            passed.append("combined")
        else:
            other.append("combined: no `PASS wasm32 (combined)` line in `CI / checks`")
    slices = ", ".join(passed) if passed else "none recorded"
    out.append(f"- wasm32 slices that passed: {slices}" + (f"; not passed or not recorded: {', '.join(other)}" if other else "") + ".")

    built, skipped, failed_deps = [], 0, []
    for job in done:
        match = re.fullmatch(r"CI / dependent \((.+)\)", job["name"])
        if not match:
            continue
        if job.get("conclusion") == "success":
            built.append(match.group(1))
        elif job.get("conclusion") == "skipped":
            skipped += 1  # a matrix with no entry reports one skipped job, named by its template
        else:
            failed_deps.append(match.group(1))
    if built or failed_deps:
        line = f"- Dependents built against this tree: {len(built)} ({', '.join(sorted(built)) or 'none'})"
        if failed_deps:
            line += f"; not built: {', '.join(sorted(failed_deps))}"
        out.append(line + ".")
    elif skipped:
        out.append("- Dependents built against this tree: none (the dependent matrix was skipped in this run).")
    else:
        out.append("- Dependents built against this tree: not recorded (no dependent job in this run).")
    out.append(f"- The run: {run['html_url']}")
    return out


# ---------------------------------------------------------------- notes


def advisory_label(advisory):
    score = f", CVSS {advisory['score']}" if advisory.get("score") is not None else ""
    return f"[{advisory['ghsa_id']}]({advisory['html_url']}) ({advisory.get('severity') or 'unrated'}{score})"


def ours(advisory):
    return [v for v in advisory.get("vulnerabilities") or [] if v.get("package") in (None, CRATE)]


def touching(version, advisories):
    fixes, affected = [], []
    for advisory in advisories:
        rows = ours(advisory)
        if any(in_range(version, v.get("vulnerable_version_range")) for v in rows):
            affected.append(advisory)
        elif any(patched_in(version, v.get("patched_versions")) for v in rows):
            fixes.append(advisory)
    return fixes, affected


def patched_text(advisory):
    named = sorted({v["patched_versions"] for v in ours(advisory) if v.get("patched_versions")})
    return ", ".join(named) if named else "no patched version yet"


def kind_line(version, fixes):
    major, minor, patch, pre = parse(version).groups()
    line = f"{major}.{minor}"
    if pre:
        return (f"A prerelease of the {line} line, cut from `beta`. To take it: "
                f"`cargo add {CRATE}@={version}` (a stable requirement does not admit a prerelease).")
    if patch == "0":
        return (f"A minor release: the {line} line. To upgrade: set the requirement to `\"{line}\"` "
                "and read the Migration lines below.")
    kind = "A security patch on the stable line" if fixes else "A patch on the stable line"
    return f"{kind}. To upgrade: `cargo update -p {CRATE}` (a `\"{line}\"` requirement takes it)."


def notes(source, tag, run_id=None):
    if not tag.startswith("v"):
        raise Stop(f"{tag}: a release tag is v<version>")
    version = tag[1:]
    parse(version)
    changelog = source.tree(tag, "CHANGELOG.md")
    if changelog is None:
        raise Stop(f"{tag}: no CHANGELOG.md at the tag")
    listed, parity, migrations = entries(section(changelog, version))
    try:
        advisories, advisory_error = source.advisories(), None
    except Unavailable as error:
        advisories, advisory_error = [], str(error)
    fixes, affected = touching(version, advisories)

    out = [kind_line(version, fixes), ""]
    for advisory in affected:
        out.append(f"> Affected by a published advisory: {advisory_label(advisory)}, patched in {patched_text(advisory)}.")
    if affected:
        out.append("")
    out += ["## Changes", ""]
    out += [f"- {entry}" for entry in listed] or ["- The section lists no entry."]
    if parity:
        out += ["", f"The section carries {parity} cross-SDK parity note(s); the changelog at the tag has them."]
    migration_lines = [f"- {('(' + issues_of(h) + ') ') if issues_of(h) else ''}{text}" for h, text in migrations]
    out += ["", "## Migration", ""]
    out += migration_lines or ["- The section names no Migration line."]
    out += ["", "## Advisories", ""]
    if advisory_error:
        out.append(f"- Published advisories: not recorded ({advisory_error}).")
    for advisory in fixes:
        others = [
            f"`{v['vulnerable_version_range']}` ({'patched in ' + v['patched_versions'] if v.get('patched_versions') else 'no patched version yet'})"
            for v in ours(advisory) if not patched_in(version, v.get("patched_versions"))
        ]
        rest = f" Its other affected range(s): {'; '.join(others)}." if others else ""
        out.append(f"- Fixes {advisory_label(advisory)}: {advisory.get('summary')}.{rest}")
    for advisory in affected:
        out.append(f"- Affected by {advisory_label(advisory)}: {advisory.get('summary')}. Patched in {patched_text(advisory)}.")
    if not (fixes or affected or advisory_error):
        out.append("- No published advisory names this version.")
    if run_id is not None:
        out += [""] + measured(source, tag, run_id)
    out += ["", (f"[Changelog at {tag}](https://github.com/{REPO}/blob/{tag}/CHANGELOG.md) · "
                 f"[crates.io](https://crates.io/crates/{CRATE}/{version}) · "
                 f"[docs.rs](https://docs.rs/{CRATE}/{version})")]
    body = "\n".join(out) + "\n"
    while len(body) > BODY_LIMIT and migration_lines:
        cut = max(1, len(migration_lines) // 4)
        migration_lines = migration_lines[:-cut]
        start = out.index("## Migration") + 2
        end = out.index("## Advisories") - 1
        shown = len(migration_lines)
        out[start:end] = migration_lines + [f"- {len(migrations) - shown} more Migration line(s): the changelog at the tag has them."]
        body = "\n".join(out) + "\n"
    return body


def flags(source, tag):
    version = tag[1:] if tag.startswith("v") else tag
    if is_prerelease(version):
        return "--prerelease --latest=false"
    served = [v["num"] for v in source.crate().get("versions", [])]
    stable = [v for v in served + [version] if VERSION.fullmatch(v) and not is_prerelease(v)]
    return "--latest" if key(version) == max(map(key, stable)) else "--latest=false"


# ---------------------------------------------------------------- check


class Result:
    def __init__(self):
        self.lines, self.failed, self.pending = [], 0, 0

    def ok(self, rule, text):
        self.lines.append(f"PASS {rule}: {text}")

    def fail(self, rule, text, pending=False):
        self.failed += 1
        self.pending += pending
        self.lines.append(f"FAIL {rule}: {text}" + (" (pending: time may heal it)" if pending else ""))


def readme_before_examples(rendered):
    """The text of a crates.io-rendered README before its `Examples` heading, tags dropped."""
    match = re.search(r"<h2[^>]*>\s*Examples\b", rendered)
    head = rendered[: match.start()] if match else None
    if head is None:
        return None
    return html.unescape(re.sub(r"<[^>]+>", " ", head))


def check(source, readme_from=README_FROM):
    result = Result()

    def guarded(rule, fn):
        try:
            fn()
        except Unavailable as error:
            result.fail(rule, f"could not read: {error}")

    crate = {}

    def versions():
        crate.update(source.crate())
        stable = crate["crate"].get("max_stable_version")
        latest = source.latest_release()
        tags = [t[1:] for t in source.tags() if t.startswith("v") and VERSION.fullmatch(t[1:])]
        newest_tag = max((t for t in tags if not is_prerelease(t)), key=key, default=None)
        said = f"crates.io max_stable_version {stable}, GitHub Latest {latest}, newest stable tag v{newest_tag}"
        if latest == f"v{stable}" and newest_tag == stable:
            result.ok("versions", said)
        else:
            result.fail("versions", said, pending=latest == f"v{newest_tag}" and stable != newest_tag)

    guarded("versions", versions)
    if not crate:
        result.lines.append("(the rules after `versions` need crates.io's answer)")
        return result
    stable = crate["crate"]["max_stable_version"]
    served = [v["num"] for v in crate.get("versions", [])]
    releases, advisories = [], []

    def pages():
        releases.extend(r for r in source.releases() if not r.get("draft"))
        tags = {f"v{v}" for v in served}
        held = {r["tag_name"]: r for r in releases}
        missing = sorted((v for v in served if f"v{v}" not in held), key=key, reverse=True)
        known_tags = set(source.tags())
        for version in missing:
            how = "the tag exists" if f"v{version}" in known_tags else "no tag either"
            result.fail("pages", f"crates.io serves {version} and no Release page names v{version} ({how})")
        for tag, release in sorted(held.items()):
            if tag not in tags:
                result.fail("pages", f"the Release page {tag} names a version crates.io does not serve")
            elif bool(release.get("prerelease")) != is_prerelease(tag[1:]):
                want = "marked prerelease" if is_prerelease(tag[1:]) else "not marked prerelease"
                result.fail("pages", f"the Release page {tag} must be {want}")
        if not missing and all(t in tags and bool(r.get("prerelease")) == is_prerelease(t[1:]) for t, r in held.items()):
            result.ok("pages", f"{len(served)} versions served, each with its page, prereleases marked")

    guarded("pages", pages)

    def docs():
        status = source.docsrs_status(stable)
        if status is None:
            return result.fail("docs.rs", f"no build of {stable} yet", pending=True)
        if not status.get("doc_status") or status.get("version") != stable:
            return result.fail("docs.rs", f"the build of {stable} did not succeed: {json.dumps(status)}")
        lib = source.tree(f"v{stable}", "src/lib.rs")
        if lib is None:
            return result.fail("docs.rs", f"no src/lib.rs at v{stable} in this checkout")
        wanted = re.findall(r"^pub mod (\w+);", lib, re.M)
        page = source.docsrs_index(stable) or ""
        shown = set(re.findall(r'class="mod"[^>]*href="(\w+)/index\.html"', page))
        lacking = [m for m in wanted if m not in shown]
        if lacking:
            result.fail("docs.rs", f"{stable}'s page shows {len(wanted) - len(lacking)} of the {len(wanted)} public modules; "
                                   f"absent: {', '.join(lacking)} (Cargo.toml's `[package.metadata.docs.rs]`)")
        else:
            result.ok("docs.rs", f"{stable} built, every one of the {len(wanted)} public modules shown")

    guarded("docs.rs", docs)

    def readme():
        if key(stable) < key(readme_from):
            return result.ok("readme", f"not judged: {stable} is older than {readme_from}, the rule's first version")
        rendered = source.crate_readme(stable)
        if rendered is None:
            return result.fail("readme", f"crates.io renders no README for {stable}", pending=True)
        head = readme_before_examples(rendered)
        if head is None:
            return result.fail("readme", f"the README of {stable} has no `Examples` heading")
        found = re.findall(r"(?<![\w.])\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", head)
        found += re.findall(r'"=\s*\d|version\s*=\s*"|bsv-rs\s*=\s*["{]', head)
        if found:
            result.fail("readme", f"the README of {stable} names a version before `Examples`: {', '.join(dict.fromkeys(found))}")
        else:
            result.ok("readme", f"the README of {stable} names no version before `Examples`")

    guarded("readme", readme)

    def security():
        lacking = [ref for ref in ("main", "beta") if not source.security_md(ref)]
        if lacking:
            result.fail("security", f"no SECURITY.md on {', '.join(lacking)}")
        else:
            result.ok("security", "SECURITY.md on main and on beta")

    guarded("security", security)

    def about():
        manifest_text = source.tree(f"v{stable}", "Cargo.toml")
        if manifest_text is None:
            return result.fail("about", f"no Cargo.toml at v{stable} in this checkout")
        package = tomllib.loads(manifest_text)["package"]
        repo = source.repo()
        link_field = "documentation" if package.get("documentation") else "homepage"
        wrong = []
        if repo.get("description") != package.get("description"):
            wrong.append(f"description {json.dumps(repo.get('description'))} is not the manifest's {json.dumps(package.get('description'))}")
        if repo.get("homepage") != package.get(link_field):
            wrong.append(f"homepage {repo.get('homepage')} is not the manifest's {link_field} {package.get(link_field)}")
        if wrong:
            result.fail("about", f"the repository's (v{stable}'s manifest): " + "; ".join(wrong))
        else:
            result.ok("about", f"description and homepage are v{stable}'s manifest's ({link_field})")

    guarded("about", about)

    def notices():
        advisories.extend(source.advisories())
        missing = {}
        for release in releases:
            version = release["tag_name"][1:]
            if not VERSION.fullmatch(version):
                continue
            for advisory in touching(version, advisories)[1]:
                if advisory["ghsa_id"] not in (release.get("body") or ""):
                    missing.setdefault(release["tag_name"], []).append(advisory["ghsa_id"])
        if missing:
            pages = sorted(missing, key=lambda t: key(t[1:]), reverse=True)
            listed = "; ".join(f"{t} ({', '.join(sorted(missing[t]))})" for t in pages)
            result.fail("notices", f"{len(pages)} page(s) inside a published advisory's range do not name it "
                                   f"(`front_pages.py notes <tag>` prints the notice line): {listed}")
        else:
            result.ok("notices", f"every page inside a published advisory's range names it ({len(advisories)} published)")

    guarded("notices", notices)
    return result


# ---------------------------------------------------------------- main


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--offline", help="a folder of saved answers instead of the network")
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("notes")
    one.add_argument("tag")
    one.add_argument("--run", help="the tag's release run id, read for the measured block")
    two = commands.add_parser("flags")
    two.add_argument("tag")
    three = commands.add_parser("check")
    three.add_argument("--readme-from", default=README_FROM)
    three.add_argument("--wait", type=int, default=0, help="seconds to poll while only pending rules fail")
    for sub in (one, two, three):
        sub.add_argument("--offline", dest="offline_sub")
    args = parser.parse_args(argv)
    root = getattr(args, "offline_sub", None) or args.offline
    source = Offline(root) if root else Live()
    try:
        if args.command == "notes":
            sys.stdout.write(notes(source, args.tag, args.run))
            return 0
        if args.command == "flags":
            print(flags(source, args.tag))
            return 0
        deadline = time.monotonic() + args.wait
        while True:
            result = check(source, args.readme_from)
            if not result.failed or result.pending < result.failed or time.monotonic() >= deadline:
                break
            print(f"waiting: {result.failed} rule line(s) pending", file=sys.stderr)
            time.sleep(min(120, max(1, deadline - time.monotonic())))
        print("\n".join(result.lines))
        print(f"{'FAIL' if result.failed else 'PASS'}: {result.failed} failure(s)")
        return 1 if result.failed else 0
    except Stop as stop:
        print(f"front_pages: {stop}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
