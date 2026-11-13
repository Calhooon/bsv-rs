#!/usr/bin/env python3
"""The node oracle's judge (#97): a pull request's raw sibling output judged from beta's files.

Stage R (a workflow on the pull request's head, no secret) runs beta's `sibling_harness.py raw`
on the head's tree, from its `judge/` checkout of beta, and uploads what it wrote as the artifact
`sibling-raw`; the head's own copy of this folder is never executed. GitHub runs the workflow file
of the event's ref, so a pull request that edits `sibling-run.yml` runs its own stage R: a class J
head, judged by the same rules and titled `JUDGE CHANGE`, its artifact what that file writes. Stage J (a workflow on the default branch,
started by the end of stage R) checks out beta, runs `judge` there with no key, and hands four
one-line outputs to `report`, the one job that holds the App's token and posts the check run
`sibling-judge`. Nothing the pull request carries decides the verdict: the judging files, the
pin and the rules are beta's, the head's PIN and column are read as git blobs, and the corpora
are staged by this script from the public sibling at the pin. tests/sibling/CLAUDE.md, "The
judge", is the manual.

  judge   read the run, the git objects and the artifact; write `post`, `conclusion`, `title`
          and `text` (base64) to the output file. Holds no key. `--dry-run` judges a local
          artifact zip or raw tree against local git objects and a local sibling and prints
          the check it would post, calling no GitHub write.
  report  resolve the run again (no wait), repeat the identity check on the run judged, and
          create the check run once, already completed. Never opens the artifact.
  sweep   for every open pull request into beta: its head, its newest stage R run, whether a
          completed check of the App stands on it or a judge of it is running, and the act for
          each gap.

One verdict per head: a judgement of a stage R run judges the newest stage R run of the same
head (`resolve`), so a run nobody will judge (one a `GITHUB_TOKEN` dispatch started, which raises
no `workflow_run`) never silences the run that would be, and the identity is read on the run
judged, never on the run that called.
  members the artifact's allowlist of member names, one a line (what stage R uploads).
  pack    zip a raw tree's allowlisted files, as stage R's upload would.

Exit status: 0 whenever a verdict was reached and written or posted, whatever the verdict, or
nothing was posted on purpose; 1 when `report` could not report, or a usage error.
"""

import argparse
import base64
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = Path(__file__).resolve().parent


def _load_harness():
    """sibling_harness.py, by its file path beside this script: `.github/scripts` is never put
    on `sys.path` (under `python3 -I` a module beside the script is not found, and a path entry
    would let any file of that folder shadow a standard module)."""
    spec = importlib.util.spec_from_file_location("sibling_harness", HERE / "sibling_harness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sh = _load_harness()

RUN_WORKFLOW = ".github/workflows/sibling-run.yml"
JUDGE_WORKFLOW = ".github/workflows/sibling-judge.yml"
CHECK_NAME = "sibling-judge"
ARTIFACT_NAME = "sibling-raw"
BASE_REF = "beta"
EVENTS = ("pull_request", "workflow_dispatch")
SIBLING_REPOSITORY = "Calhooon/bsv-script-lean"
SIBLING_URL = f"https://github.com/{SIBLING_REPOSITORY}.git"
PIN_PATH = "tests/sibling/PIN"
COLUMN_PATH = "tests/sibling/column.json"
REGULAR = "100644"
ABSENT = "000000"
PIN_TEXT = re.compile(rb"[0-9a-f]{40}\n")
SHA = re.compile(r"[0-9a-f]{40}")
ARTIFACT_LIMIT = 64 << 20
MEMBER_LIMIT = 16 << 20
TEXT_LIMIT = 60000
LINE_LIMIT = 500
WHERE = "the artifact"

# the three words a failed check's title opens with
RED = "RED"
REFUSED = "REFUSED"
NOT_JUDGED = "NOT JUDGED"

# the classes of a changed path, the earliest match deciding (tests/sibling/CLAUDE.md)
JUDGE_FILES = (RUN_WORKFLOW, JUDGE_WORKFLOW, "tests/arch_ci_sibling_judge_97.rs")
NAMED_CRATE = (
    ".github/workflows/ci.yml",
    ".github/workflows/sync-main-into-beta.yml",
    "tests/arch_ci_pr_runs_the_required_set.rs",
)


def class_of(path):
    """P the pin, W the column, N words no verdict reads, J the judge, C the crate."""
    if path == PIN_PATH:
        return "P"
    if path == COLUMN_PATH:
        return "W"
    if path == "CHANGELOG.md" or path.startswith("docs/") or path.rsplit("/", 1)[-1] == "CLAUDE.md":
        return "N"
    if path in JUDGE_FILES:
        return "J"
    if path.startswith(".github/scripts/") and any("sibling_" in part for part in path.split("/")[2:]):
        return "J"
    if path.startswith("tests/sibling/"):
        return "J"
    return "C"


def members(corpora=sh.ALL):
    """The artifact's members: (required, optional), built from the judge's own corpus list."""
    required = [sh.STAMP, sh.RUN_INFO, "bsv-rs/manifest.json"]
    for name in corpora:
        required += [f"{name}.log", f"{sh.WORDS_DIR}/{name}.jsonl"]
    optional = ["summary.txt"] + [f"bsv-rs/{name}.jsonl" for name in corpora]
    return required, optional


class GitHubError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class GitHub:
    """GitHub, behind `gh api` (the tests replace this class). Reads the token from the
    environment `gh` reads; this script names none."""

    def _gh(self, args, data=None):
        done = subprocess.run(["gh", "api", *args], input=data, capture_output=True, check=False)
        if done.returncode != 0:
            found = re.search(rb"HTTP (\d{3})", done.stderr)
            status = int(found.group(1)) if found else 0
            raise GitHubError(status, f"gh api {args[-1]} exited {done.returncode} (HTTP {status or 'unknown'})")
        return done.stdout

    def get(self, path):
        try:
            return json.loads(self._gh(["-H", "Accept: application/vnd.github+json", path]))
        except ValueError as error:
            raise GitHubError(0, f"gh api {path}: not JSON") from error

    def download(self, path, dest):
        """An artifact's zip (the endpoint answers 302 to a storage host: `gh` follows it)."""
        Path(dest).write_bytes(self._gh([path]))
        return Path(dest)

    def post(self, path, body):
        return json.loads(self._gh(["-X", "POST", path, "--input", "-"], json.dumps(body).encode()) or b"{}")


class Git:
    """The judge's git objects: beta's checkout, the head fetched by sha, no checkout of it."""

    def __init__(self, directory):
        self.directory = str(directory)

    def run(self, *args, ok=(0,)):
        done = subprocess.run(["git", "-C", self.directory, *args], capture_output=True, check=False)
        if done.returncode not in ok:
            raise sh.Stop(f"git {args[0]} exited {done.returncode}")
        return done

    def has(self, sha):
        return self.run("cat-file", "-e", f"{sha}^{{commit}}", ok=(0, 1, 128)).returncode == 0

    def ensure(self, sha):
        if not self.has(sha):
            self.run("fetch", "--no-tags", "--quiet", "origin", sha)
        if not self.has(sha):
            raise sh.Stop(f"commit {sha} is not in the judge's objects after a fetch")

    def rev_parse(self, ref):
        return self.run("rev-parse", "--verify", f"{ref}^{{commit}}").stdout.decode().strip()

    def entry(self, sha, path):
        """(mode, object) of a path at a commit, or None."""
        out = self.run("ls-tree", "-z", sha, "--", path).stdout
        for record in out.split(b"\0"):
            if not record:
                continue
            head, _, name = record.partition(b"\t")
            if name.decode(errors="replace") == path:
                mode, _, obj = head.decode().split(" ")
                return mode, obj
        return None

    def blob(self, obj):
        return self.run("cat-file", "blob", obj).stdout

    def is_ancestor(self, older, newer):
        return self.run("merge-base", "--is-ancestor", older, newer, ok=(0, 1)).returncode == 0

    def count(self, revisions):
        return int(self.run("rev-list", "--count", revisions).stdout.decode().strip())

    def changes(self, base, head):
        """Every path the head changes against the base: (old mode, new mode, path), renames
        off (a rename is its old name deleted and its new name added)."""
        out = self.run("diff", "--raw", "-z", "--no-renames", "--no-abbrev", base, head).stdout
        parts = out.split(b"\0")
        found = []
        at = 0
        while at < len(parts) - 1:
            meta = parts[at].decode()
            if not meta.startswith(":"):
                at += 1
                continue
            old, new = meta[1:].split(" ")[:2]
            found.append((old, new, parts[at + 1].decode(errors="surrogateescape")))
            at += 2
        return found

    def last_change(self, sha, path):
        """The commit time of `path`'s last change at `sha`, in seconds since the epoch, or None
        when git answers no such time (no commit, or text that is not a decimal integer)."""
        out = self.run("log", "-1", "--format=%ct", sha, "--", path).stdout.decode().strip()
        return int(out) if re.fullmatch(r"[0-9]{1,12}", out) else None


class Verdict(Exception):
    """A check to post: its opening word, its title's reason, the judge's own lines, the
    lines quoted from the artifact or the head, and the act that re-judges it."""

    def __init__(self, word, reason, own=(), quoted=(), act=None, post="yes"):
        super().__init__(reason)
        self.word, self.reason, self.own, self.quoted = word, reason, list(own), list(quoted)
        self.act, self.post = act, post


class Silent(Exception):
    """No check at all: a line in the job's log, in the judge's own words."""


class Check:
    """What `judge` writes. The conclusion is `failure` until `passed`, after the last rule."""

    def __init__(self):
        self.post = "yes"
        self.conclusion = "failure"
        self.title = f"{NOT_JUDGED}: the judge did not reach a verdict"
        self.text = ""

    def passed(self):
        self.conclusion = "success"


def clean(text, limit=None):
    """Backticks and control bytes replaced, so no line can close a fence or open a command."""
    out = "".join(
        "'" if c == "`" else ("?" if (ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 or c in "  ") else c)
        for c in str(text)
    )
    if limit is not None and len(out.encode()) > limit:
        out = out.encode()[:limit].decode(errors="ignore")
    return out


def bounded(own, quoted, act):
    """The check's text: the judge's own lines, then the quoted ones inside one fenced block
    (500 bytes a line, the whole within 60,000 characters, the count of lines cut under it),
    then the act."""
    head = "\n".join(clean(line) for line in own)
    tail = ""
    if act:
        # each of the act's own lines cleaned apart, so its line breaks stay line breaks and the
        # command is not folded into the comment above it
        tail = "\n\nTo re-judge:\n\n```sh\n" + "\n".join(clean(line) for line in str(act).split("\n")) + "\n```\n"
    budget = TEXT_LIMIT - len(head) - len(tail) - 200
    body, cut = [], 0
    used = 0
    for line in quoted:
        text = clean(line)
        short = clean(text, LINE_LIMIT)
        if short != text:
            cut += 1
        if used + len(short) + 1 > budget:
            cut += 1
            continue
        body.append(short)
        used += len(short) + 1
    out = head
    if body or cut:
        out += "\n\n```text\n" + "\n".join(body) + "\n```\n"
        if cut:
            out += f"{cut} lines cut (500 bytes a line, {TEXT_LIMIT} characters in all).\n"
    out += tail
    return out[:TEXT_LIMIT]


def json_blob(data, what, word=REFUSED):
    try:
        return json.loads(data)
    except (ValueError, RecursionError, TypeError) as error:
        raise Verdict(word, f"{what} is not JSON", [f"{what}: {type(error).__name__}"]) from error


class Facts:
    """The sibling's corpora staged by the judge at one pin: data, nothing executed."""

    def __init__(self, sibling_dir, pin, temp):
        scratch = Path(temp) / f"stage-{pin}"
        sh.stage(sibling_dir, pin, sh.ALL, scratch)
        withheld = sh.drop_withheld(scratch, sh.ALL)
        self.pin = pin
        self.rules_pin = sh.rules_pin(scratch / "harness")
        self.withheld = {name: count for name, count in withheld.items() if count}
        self.corpora = {}
        self.lines = {}
        for name in sh.ALL:
            path = sh.corpus_file(scratch, name)
            self.corpora[name] = {"corpus_sha256": sh.sha256_file(path), "withheld": self.withheld.get(name, 0)}
            entries = {}
            for line in sh.lines_of(path.read_text()):
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and isinstance(row.get("id"), str):
                    entries[row["id"]] = line
            self.lines[name] = entries

    def as_run(self):
        return {"sibling": self.pin, "rules_pin": self.rules_pin, "withheld": self.withheld, "corpora": self.corpora}


def fetch_sibling(directory, url, pins):
    """The public sibling's commits by sha, into a repository of the judge's own."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    git = Git(directory)
    if not (directory / ".git").exists() and not (directory / "HEAD").exists():
        git.run("init", "--quiet")
    for pin in pins:
        if not git.has(pin):
            done = git.run("fetch", "--no-tags", "--quiet", "--depth", "1", url, pin, ok=(0, 1, 128))
            if done.returncode != 0 or not git.has(pin):
                raise Verdict(NOT_JUDGED, "the sibling's commit at the pin could not be fetched", [f"pin {pin}"])
    return directory


def read_artifact(data):
    """The artifact's files by name, read in memory by the allowlist; a refusal otherwise."""
    if len(data) > ARTIFACT_LIMIT:
        raise sh.Stop(f"the artifact is {len(data)} bytes, over {ARTIFACT_LIMIT}")
    required, optional = members()
    allowed = set(required) | set(optional)
    dirs = {name.rsplit("/", 1)[0] + "/" for name in allowed if "/" in name}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, ValueError, OSError) as error:
        raise sh.Stop(f"the artifact is not a zip ({type(error).__name__})") from error
    seen, files, total = set(), {}, 0
    for info in infos:
        name = info.filename
        if name in seen:
            raise sh.Stop("a member is repeated")
        seen.add(name)
        if name.startswith("/") or ".." in name.split("/") or "\\" in name:
            raise sh.Stop("a member's name leaves the artifact")
        kind = (info.external_attr >> 16) & 0o170000
        if kind == 0o120000:
            raise sh.Stop("a member is a symlink")
        if name in dirs and info.file_size == 0:
            continue
        if name not in allowed:
            raise sh.Stop("a member is not on the allowlist")
        if info.file_size > MEMBER_LIMIT or info.compress_size > MEMBER_LIMIT:
            raise sh.Stop(f"a member is declared at {info.file_size} bytes, over {MEMBER_LIMIT}")
        total += info.file_size
        if total > ARTIFACT_LIMIT:
            raise sh.Stop(f"the members are declared at more than {ARTIFACT_LIMIT} bytes")
    for info in infos:
        if info.filename in dirs and info.file_size == 0:
            continue
        try:
            with archive.open(info) as member:
                body = member.read(MEMBER_LIMIT + 1)
        except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError) as error:
            raise sh.Stop(f"a member does not read ({type(error).__name__})") from error
        if len(body) > MEMBER_LIMIT or len(body) != info.file_size:
            raise sh.Stop("a member's bytes are not its declared size")
        files[info.filename] = body
    for name in required:
        if name not in files:
            raise sh.Stop(f"the required member {name} is absent")
    return files


def pack(out, dest):
    """A raw tree's allowlisted files, zipped as stage R's upload would hold them."""
    required, optional = members()
    out = Path(out)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in required + optional:
            path = out / name
            if path.is_file() and not path.is_symlink():
                archive.write(path, name)
            elif name in required:
                raise sh.Stop(f"{path}: a required member is absent")
    data = buffer.getvalue()
    if dest is not None:
        Path(dest).write_bytes(data)
    return data


class Judgment:
    """One judgment of one stage R run; the rules in order, the shape of the change first."""

    def __init__(self, gh, git, temp, sibling_url, repository=None, repository_id=None, dry=False):
        self.gh, self.git, self.temp, self.sibling_url = gh, git, Path(temp), sibling_url
        self.repository, self.repository_id, self.dry = repository, repository_id, dry
        self.head = self.beta = self.trampoline = self.pin = None
        self.run = self.pr = None
        self.run_id = self.attempt = None
        self.artifact = None
        self.event = None
        self.judge_paths = []

    # -- the run and the pull request ------------------------------------------------------
    def identity(self, run_id):
        """The run is stage R of this repository on an open pull request into beta, or no check."""
        return identity(self.gh, self.repository, self.repository_id, run_id)

    def header(self):
        artifact = self.artifact or {}
        return [
            f"head {self.head or 'not read'}",
            f"beta {self.beta or 'not read'}",
            f"trampoline (main) {self.trampoline or 'not read'}",
            f"stage R run {self.run_id or 'not read'} attempt {self.attempt or 'not read'}",
            f"artifact {artifact.get('id', 'not read')} digest {artifact.get('digest', 'not read')}",
            f"pin {self.pin or 'not read'}",
            "",
        ]

    # -- the two lines -----------------------------------------------------------------------
    def lines(self, workflow_sha):
        self.beta = self.git.rev_parse("HEAD")
        self.trampoline = workflow_sha
        if self.dry:
            return
        try:
            self.git.ensure(workflow_sha)
        except sh.Stop as error:
            raise Verdict(NOT_JUDGED, "the trampoline's commit could not be read", [str(error)],
                          act=self.redrive()) from error
        main = self.git.entry(workflow_sha, JUDGE_WORKFLOW)
        beta = self.git.entry(self.beta, JUDGE_WORKFLOW)
        if main is None or beta is None:
            which = "main" if main is None else "beta"
            raise Verdict(NOT_JUDGED, f"{JUDGE_WORKFLOW} is absent on {which}",
                          [f"the trampoline on main and beta's file must be one file; {which} lacks it"],
                          act=self.redrive())
        if main[1] != beta[1]:
            main_time = self.git.last_change(workflow_sha, JUDGE_WORKFLOW)
            beta_time = self.git.last_change(self.beta, JUDGE_WORKFLOW)
            if not isinstance(main_time, int) or not isinstance(beta_time, int):
                which = "main" if not isinstance(main_time, int) else "beta"
                raise Verdict(NOT_JUDGED, f"the trampoline on main differs from beta's; {which}'s commit time does not read",
                              [f"{JUDGE_WORKFLOW}: main {main[1]}, beta {beta[1]}; the last change's commit time on {which} is not a time"],
                              act=self.redrive())
            behind = "main" if main_time <= beta_time else "beta"
            raise Verdict(NOT_JUDGED, f"the trampoline on main differs from beta's; {behind} is behind",
                          [f"{JUDGE_WORKFLOW}: main {main[1]}, beta {beta[1]}; {behind} is behind (pick or sync it)"],
                          act=self.redrive())

    # -- the head ----------------------------------------------------------------------------
    def read_head(self):
        try:
            self.git.ensure(self.head)
        except sh.Stop as error:
            raise Verdict(NOT_JUDGED, "the head's commit could not be fetched", [str(error)], act=self.redrive()) from error
        if not self.git.is_ancestor(self.beta, self.head):
            behind = self.git.count(f"{self.head}..{self.beta}")
            raise Verdict(REFUSED, f"behind beta by {behind} commits",
                          [f"the head does not hold beta's tip {self.beta}: rebase it on beta and push; the next push is judged"],
                          act=self.repush())

    def blob_at(self, sha, path, word, what):
        found = self.git.entry(sha, path)
        if found is None:
            raise Verdict(word, f"{what} has no {path}", [f"{path} is absent at {sha}"], act=self.repush())
        mode, obj = found
        if mode != REGULAR:
            raise Verdict(REFUSED, f"{path} is not a regular file", [f"{path} has mode {mode} at {sha}; it must be {REGULAR}"],
                          act=self.repush())
        return self.git.blob(obj)

    # -- the class ---------------------------------------------------------------------------
    def classify(self):
        changes = self.git.changes(self.beta, self.head)
        classes = {}
        for old, new, path in changes:
            kind = class_of(path)
            classes.setdefault(kind, []).append(path)
            if kind in ("J", "P", "W"):
                for mode in (old, new):
                    if mode not in (REGULAR, ABSENT):
                        raise Verdict(REFUSED, f"a judge, pin or column path has mode {mode}",
                                      [f"a path of class {kind} must be a regular file ({REGULAR}):"], [path],
                                      act=self.repush())
        core = [kind for kind in ("J", "P", "C") if kind in classes]
        if len(core) > 1:
            raise Verdict(REFUSED, f"one pull request changes {' and '.join(names_of(core))}",
                          ["a pull request changes at most one of the judge (J), the pin (P) and the crate (C); split it"],
                          [f"{kind}: {path}" for kind in core for path in classes[kind][:20]],
                          act=self.repush())
        if "W" in classes and "J" in classes:
            raise Verdict(REFUSED, "one pull request changes the judge and the column",
                          ["the column (W) rides with the crate, with the pin or alone, never with the judge (J)"],
                          act=self.repush())
        self.kind = "P" if "P" in classes else ("J" if "J" in classes else ("C" if "C" in classes else ("W" if "W" in classes else "N")))
        self.judge_paths = classes.get("J", [])
        return classes

    # -- the pin -----------------------------------------------------------------------------
    def check_pin(self):
        data = self.blob_at(self.head, PIN_PATH, REFUSED, "the head")
        if not PIN_TEXT.fullmatch(data):
            raise Verdict(REFUSED, "tests/sibling/PIN is not 40 lower-case hex digits and a newline",
                          [f"{PIN_PATH} must be one line of 40 lower-case hex digits and a newline ({len(data)} bytes found)"],
                          act=self.repush())
        self.pin = data[:40].decode()
        beta_pin = self.blob_at(self.beta, PIN_PATH, NOT_JUDGED, "beta")
        self.beta_pin = beta_pin[:40].decode() if PIN_TEXT.fullmatch(beta_pin) else None
        if self.kind != "P" and self.pin != self.beta_pin:
            raise Verdict(REFUSED, "the pin moved outside a pin change", [f"head {self.pin}, beta {self.beta_pin}"],
                          act=self.repush())
        if self.gh is None:
            self.unmade.append("the pin's place on the sibling's main (no GitHub read asked)")
            return
        try:
            answer = self.gh.get(f"repos/{SIBLING_REPOSITORY}/compare/{self.pin}...main")
        except GitHubError as error:
            if error.status == 404:
                raise Verdict(REFUSED, "the pin is not a commit of the sibling",
                              [f"{SIBLING_REPOSITORY} has no commit {self.pin} (404)"], act=self.repush()) from error
            raise Verdict(NOT_JUDGED, "GitHub did not answer the pin's comparison", [str(error)], act=self.redrive()) from error
        if answer.get("behind_by") != 0:
            raise Verdict(REFUSED, "the pin is not on the sibling's main",
                          [f"{SIBLING_REPOSITORY} compare {self.pin}...main: behind_by {answer.get('behind_by')!r}, "
                           "where a commit of main answers 0 (a commit only a fork carries is refused)"],
                          act=self.repush())

    # -- the column's rules ------------------------------------------------------------------
    def check_column(self, facts, beta_facts):
        head = json_blob(self.blob_at(self.head, COLUMN_PATH, REFUSED, "the head"), "the head's column")
        beta = json_blob(self.blob_at(self.beta, COLUMN_PATH, NOT_JUDGED, "beta"), "beta's column", NOT_JUDGED)
        if not isinstance(head, dict):
            raise Verdict(REFUSED, "the head's column is not an object", act=self.repush())
        self.column = head
        lines = sh.explained_of(head.get("corpora") or {})
        if lines:
            raise Verdict(REFUSED, "the column carries an explained row or an abort witness",
                          ["zero divergences from the node and no explained row (the owner's ruling of 2026-11-10)"],
                          lines, act=self.repush())
        moved = []
        if head.get("sibling") != self.pin:
            moved.append(f"sibling: column {head.get('sibling')}, pin {self.pin}")
        if head.get("rules_pin") != facts.rules_pin:
            moved.append(f"rules_pin: column {head.get('rules_pin')}, staged {facts.rules_pin}")
        if {k: v for k, v in (head.get("withheld") or {}).items() if v} != facts.withheld:
            moved.append(f"withheld: column {json.dumps(head.get('withheld'), sort_keys=True)}, staged {json.dumps(facts.withheld, sort_keys=True)}")
        for name in sh.ALL:
            want = ((head.get("corpora") or {}).get(name) or {}).get("corpus_sha256")
            if want != facts.corpora[name]["corpus_sha256"]:
                moved.append(f"{name} corpus_sha256: column {want}, staged {facts.corpora[name]['corpus_sha256']}")
        if moved:
            raise Verdict(REFUSED, "the column was not recorded at the pin",
                          ["the column must be recorded at the head's pin (tests/sibling/CLAUDE.md's one command with --record)"],
                          moved, act=self.repush())
        if self.kind != "P":
            if beta.get("sibling") != head.get("sibling") or beta.get("rules_pin") != head.get("rules_pin"):
                raise Verdict(REFUSED, "the column moved its pin outside a pin change", act=self.repush())
            held = sh.held_at_the_pin(beta, head, head.get("corpora") or {}, head.get("words") or {})
            if held:
                raise Verdict(REFUSED, "the column moves more than words",
                              ["outside a pin change the column moves words alone: every count, corpus sha256, withheld "
                               "count and verdict side equal to beta's"], held, act=self.repush())
            return
        problems = []
        for name in sorted(beta.get("corpora") or {}):
            if name not in (head.get("corpora") or {}):
                problems.append(f"{name}: a corpus of beta's column is dropped")
        for name, gone in sorted((head.get("withheld") or {}).items()):
            if gone > (beta.get("withheld") or {}).get(name, 0):
                problems.append(f"{name} withheld: beta {(beta.get('withheld') or {}).get(name, 0)}, head {gone}")
        old_words, new_words = beta.get("words") or {}, head.get("words") or {}
        for name in sorted(old_words):
            for entry in sorted(old_words[name]):
                if entry not in (new_words.get(name) or {}):
                    problems.append(f"{name} {entry}: a judged entry is dropped")
                    continue
                before = beta_facts.lines.get(name, {}).get(entry)
                after = facts.lines.get(name, {}).get(entry)
                if before is not None and before == after and new_words[name][entry] != old_words[name][entry]:
                    problems.append(f"{name} {entry}: unchanged by the pin move, its words moved")
        if problems:
            if len(problems) > sh.NAMED:
                problems = problems[: sh.NAMED] + [f"and {len(problems) - sh.NAMED} more"]
            raise Verdict(REFUSED, "the pin move drops or rewords what it did not change",
                          ["a pin move drops no corpus and no judged entry, does not grow `withheld`, and keeps beta's "
                           "words on every entry it left unchanged"], problems, act=self.repush())

    # -- the stamp ---------------------------------------------------------------------------
    def check_stamp(self, files, facts):
        try:
            stamp = sh.json_of(files, sh.STAMP, "the stamp")
            info = sh.json_of(files, sh.RUN_INFO, "the run's record")
        except sh.Stop as error:
            raise Verdict(NOT_JUDGED, "the artifact's stamp does not read", [str(error)], act=self.rerun()) from error
        if not isinstance(stamp, dict) or stamp.get("schema") != sh.STAMP_SCHEMA:
            raise Verdict(NOT_JUDGED, "the artifact's stamp has an unknown schema", act=self.rerun())
        if not isinstance(info, dict):
            raise Verdict(NOT_JUDGED, "the artifact's run record is not an object", act=self.rerun())
        differ = []
        if stamp.get("head_sha") != self.head:
            differ.append(f"head sha: stamp {stamp.get('head_sha')!r}, run {self.head}")
        if self.pr_number is not None:
            if stamp.get("pull_request") != self.pr_number and not (self.event == "workflow_dispatch" and stamp.get("pull_request") is None):
                differ.append(f"pull request: stamp {stamp.get('pull_request')!r}, judged {self.pr_number}")
        if stamp.get("sibling") != self.pin or info.get("sibling") != self.pin:
            differ.append(f"pin: stamp {stamp.get('sibling')!r}, record {info.get('sibling')!r}, head {self.pin}")
        if stamp.get("rules_pin") != facts.rules_pin or info.get("rules_pin") != facts.rules_pin:
            differ.append(f"rules pin: stamp {stamp.get('rules_pin')!r}, record {info.get('rules_pin')!r}, staged {facts.rules_pin}")
        if stamp.get("corpora") != facts.corpora:
            differ.append("corpora: the stamp's sha256 and withheld counts are not the staged ones")
        if {k: v for k, v in (info.get("withheld") or {}).items() if v} != facts.withheld:
            differ.append("withheld: the record's counts are not the staged ones")
        if list(info.get("corpora") or []) != list(sh.ALL):
            differ.append("corpora: the record does not name the nine")
        if differ:
            raise Verdict(NOT_JUDGED, "the artifact's stamp differs from what the judge read",
                          ["the stamp is compared and never used:"], differ, act=self.rerun())

    # -- the verdict -------------------------------------------------------------------------
    def verdict(self, files, facts):
        try:
            manifest = sh.json_of(files, "bsv-rs/manifest.json", "the manifest")
            if not isinstance(manifest, dict):
                raise sh.Stop("the manifest is not an object")
            code, lines = sh.judge_run(files, WHERE, list(sh.ALL), manifest, self.column, facts.as_run(), COLUMN_PATH)
        except sh.Stop as stop:
            raise Verdict(NOT_JUDGED, "the run's files did not judge", [], stop.lines + [str(stop)], act=self.rerun()) from stop
        if code != 0:
            raise Verdict(RED, "the run differs from the node or from the column",
                          ["a divergence from the node's verdict or a word moved from the column, named below:"],
                          lines, act=self.repush())
        return lines

    # -- the acts ----------------------------------------------------------------------------
    def redrive(self):
        if not self.run_id:
            return None
        return f"gh workflow run sibling-judge.yml --repo {self.repository} --ref main -f run_id={self.run_id}"

    def rerun(self):
        if not self.run_id:
            return None
        return f"gh run rerun {self.run_id} --repo {self.repository}"

    def repush(self):
        branch = ((self.pr or {}).get("head") or {}).get("ref")
        branch = shlex.quote(clean(branch)) if branch else "<the pull request's branch>"
        return (f"# push a commit that fixes it to the pull request's branch (the push is judged), or:\n"
                f"gh workflow run sibling-run.yml --repo {self.repository or 'Calhooon/bsv-rs'} --ref {branch}")


def names_of(kinds):
    words = {"J": "the judge", "P": "the pin", "C": "the crate", "W": "the column", "N": "words"}
    return [words[kind] for kind in kinds]


def identity(gh, repository, repository_id, run_id):
    """(run, pull request) for a stage R run of this repository on an open pull request into
    beta, the head as the run answers it; Silent otherwise."""
    run = gh.get(f"repos/{repository}/actions/runs/{run_id}")
    if run.get("path") != RUN_WORKFLOW:
        raise Silent(f"run {run_id} is not {RUN_WORKFLOW} (by its path)")
    if (run.get("head_repository") or {}).get("id") != repository_id:
        raise Silent(f"run {run_id}'s head is not this repository's")
    if run.get("event") not in EVENTS:
        raise Silent(f"run {run_id}'s event is not pull_request or workflow_dispatch")
    head = run.get("head_sha") or ""
    if not SHA.fullmatch(head):
        raise Silent(f"run {run_id} names no head sha")
    pulls = gh.get(f"repos/{repository}/commits/{head}/pulls")
    for pr in sorted(pulls if isinstance(pulls, list) else [], key=lambda p: p.get("number") or 0):
        if (
            pr.get("state") == "open"
            and (pr.get("head") or {}).get("sha") == head
            and ((pr.get("head") or {}).get("repo") or {}).get("id") == repository_id
            and ((pr.get("base") or {}).get("repo") or {}).get("id") == repository_id
            and (pr.get("base") or {}).get("ref") == BASE_REF
        ):
            return run, pr
    raise Silent(f"no open pull request into {BASE_REF} from this repository has head {head}")


# how long a judgement waits for a newer stage R run of its head still running, and how often it
# asks (the judge job's `timeout-minutes` is 10)
WAIT_SECONDS = 300
POLL_SECONDS = 15


def is_stage_r(run, repository_id):
    """Whether a run record is a stage R run of this repository: its path (never its name), its
    head's repository and its event. The open pull request is `identity()`'s."""
    return (isinstance(run, dict) and run.get("path") == RUN_WORKFLOW
            and (run.get("head_repository") or {}).get("id") == repository_id
            and run.get("event") in EVENTS)


def runs_of(gh, repository, repository_id, head):
    """The stage R runs of a head, by id, as GitHub lists them."""
    listing = gh.get(f"repos/{repository}/actions/workflows/sibling-run.yml/runs?head_sha={head}&per_page=100")
    return {r["id"]: r for r in (listing.get("workflow_runs") or [])
            if is_stage_r(r, repository_id) and r.get("head_sha") == head and isinstance(r.get("id"), int)}


def resolve(gh, repository, repository_id, run_id, wait=0, sleep=None):
    """The run a judgement of `run_id` judges: the newest stage R run of the same head, completed,
    at its latest attempt; (run id, attempt). The calling run must itself be a stage R run of this
    repository (a decoy named `sibling-run` at another path calls nothing). When the newest run
    (or the newest attempt) is still running the judgement waits up to `wait` seconds for it and
    then posts nothing, a line in the log (`Silent`): the sweep names the head."""
    run = gh.get(f"repos/{repository}/actions/runs/{run_id}")
    if run.get("path") != RUN_WORKFLOW:
        raise Silent(f"run {run_id} is not {RUN_WORKFLOW} (by its path)")
    if (run.get("head_repository") or {}).get("id") != repository_id:
        raise Silent(f"run {run_id}'s head is not this repository's")
    if run.get("event") not in EVENTS:
        raise Silent(f"run {run_id}'s event is not pull_request or workflow_dispatch")
    head = run.get("head_sha") or ""
    if not SHA.fullmatch(head):
        raise Silent(f"run {run_id} names no head sha")
    sleep = sleep or time.sleep
    polls = max(0, int(wait)) // POLL_SECONDS
    pending = None
    for at in range(polls + 1):
        runs = runs_of(gh, repository, repository_id, head)
        runs.setdefault(run_id, run)
        newest = runs[max(runs)]
        attempt = newest.get("run_attempt") or 1
        if newest.get("status") == "completed" and isinstance(attempt, int):
            return newest["id"], attempt
        pending = f"run {newest['id']} attempt {attempt}"
        if at < polls:
            sleep(POLL_SECONDS)
    raise Silent(f"run {run_id} of head {head}: the newest stage R run of the head, {pending}, is still running; "
                 f"the sweep names the head (re-judge it once it completes)")


def standing(gh, repository, head, app_id):
    """Whether a completed check of this App stands on the head: a check counts only when its
    app id is the configured one (a check with no app, a null app or another App's never does)."""
    answer = gh.get(f"repos/{repository}/commits/{head}/check-runs?check_name={CHECK_NAME}&app_id={app_id}&per_page=100")
    return any(c.get("status") == "completed" and isinstance(c.get("app"), dict) and c["app"].get("id") == app_id
               for c in answer.get("check_runs") or [])


def judge(args, gh, out):
    """The rules in order; returns the Check written. Its scratch (the sibling's staged corpora,
    the artifact's zip) is removed after."""
    temp = Path(tempfile.mkdtemp(prefix="sibling-judge-", dir=args.temp))
    try:
        return _judge(args, gh, temp)
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def _judge(args, gh, temp):
    check = Check()
    git = Git(args.judge)
    j = Judgment(gh, git, temp, args.sibling_url, args.repository, args.repository_id, dry=args.dry_run)
    j.unmade = []
    j.notes = []
    j.pr_number = None
    try:
        try:
            if args.dry_run:
                j.unmade += ["the run's identity", "the superseded test", "the artifact's record", "the trampoline's comparison"]
                j.head = args.head
                j.pr_number = sh.pull_request_of(args.pull_request)
                j.event = "pull_request" if j.pr_number else "workflow_dispatch"
                j.lines(None)
                if args.beta:
                    j.beta = git.rev_parse(args.beta)
            else:
                target, j.attempt = resolve(gh, args.repository, args.repository_id, args.run_id,
                                            wait=getattr(args, "wait", 0) or 0, sleep=getattr(args, "sleep", None))
                j.run_id = target
                run, pr = identity(gh, args.repository, args.repository_id, target)
                j.run, j.pr, j.head, j.event = run, pr, run["head_sha"], run["event"]
                j.pr_number = pr.get("number")
                if (target, j.attempt) != (args.run_id, args.attempt or j.attempt):
                    j.notes = [f"Called for run {args.run_id} attempt {args.attempt or 'latest'}; judged the newest "
                                f"stage R run of the head, run {target} attempt {j.attempt} (one verdict per head)"]
                j.lines(args.workflow_sha)
            j.read_head()
            j.classify()
            j.check_pin()
            pins = [j.pin] + ([j.beta_pin] if j.kind == "P" and j.beta_pin and j.beta_pin != j.pin else [])
            sibling = fetch_sibling(temp / "sibling", args.sibling_url, pins) if not args.sibling else Path(args.sibling)
            try:
                facts = Facts(sibling, j.pin, temp)
                beta_facts = Facts(sibling, j.beta_pin, temp) if j.kind == "P" and j.beta_pin and j.beta_pin != j.pin else facts
            except sh.Stop as stop:
                raise Verdict(NOT_JUDGED, "the sibling at the pin did not stage", [str(stop)], act=j.redrive()) from stop
            j.check_column(facts, beta_facts)
            files = j.artifact_files(args) if not args.dry_run else local_artifact(args.artifact)
            j.check_stamp(files, facts)
            lines = j.verdict(files, facts)
            check.title = f"JUDGE CHANGE: {', '.join(j.judge_paths)}" if j.judge_paths else "GREEN"
            check.title = clean(check.title, 240)
            check.text = bounded(j.header() + ["Every entry's verdict is the node's and every word the column's.",
                                               *j.notes, *[f"Not made in a dry run: {what}" for what in j.unmade]],
                                 lines, None)
            check.passed()
        except Verdict as verdict:
            check.post = verdict.post
            change = f" (JUDGE CHANGE: {', '.join(j.judge_paths)})" if j.judge_paths else ""
            check.title = clean(f"{verdict.word}{change}: {verdict.reason}", 240)
            own = j.header() + verdict.own + j.notes + [f"Not made in a dry run: {what}" for what in j.unmade]
            check.text = bounded(own, verdict.quoted, verdict.act or "# re-drive the judge for the same run")
    except Silent as silent:
        check.post = "no"
        check.title = f"{NOT_JUDGED}: no check is posted"
        check.text = ""
        print(f"sibling_judge: no check: {silent}", flush=True)
    except (GitHubError, sh.Stop) as error:
        check.post = "yes"
        check.title = f"{NOT_JUDGED}: the judge could not read what it needs"
        check.text = bounded(j.header(), [f"{type(error).__name__}: {error}"], j.redrive())
    return check


def local_artifact(path):
    path = Path(path)
    try:
        if path.is_dir():
            return read_artifact(pack(path, None))
        return read_artifact(path.read_bytes())
    except sh.Stop as stop:
        raise Verdict(NOT_JUDGED, "the artifact is refused", [str(stop)]) from stop


def instant(text):
    """A GitHub timestamp (`2026-11-12T10:07:37Z`, fractional seconds or a numeric offset
    allowed) as an aware datetime in UTC, or None for anything else. Two times are compared as
    times, never as strings, so no cut of either text can move the verdict."""
    if not isinstance(text, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})", text):
        return None
    body, zone = (text[:-1], "+00:00") if text.endswith("Z") else (text[:-6], text[-6:])
    if "." in body:
        body, fraction = body.split(".")
        body = f"{body}.{fraction[:6].ljust(6, '0')}"
    try:
        return datetime.fromisoformat(body + zone).astimezone(timezone.utc)
    except ValueError:
        return None


def _artifact_files(self, args):
    """The one unexpired `sibling-raw` artifact a successful attempt uploaded, read in memory.
    Stage R uploads with `overwrite: true`, so a re-run replaces the artifact of the attempt before
    it; where GitHub still lists that one, an artifact created before this attempt started is not
    this attempt's and is not counted."""
    state = self.gh.get(f"repos/{self.repository}/actions/runs/{self.run_id}/attempts/{self.attempt}")
    conclusion = state.get("conclusion")
    if conclusion != "success":
        failed = []
        try:
            jobs = self.gh.get(f"repos/{self.repository}/actions/runs/{self.run_id}/attempts/{self.attempt}/jobs?per_page=100")
            for job in jobs.get("jobs") or []:
                for step in job.get("steps") or []:
                    if step.get("conclusion") == "failure":
                        failed.append(f"{job.get('name')}: {step.get('name')}")
        except GitHubError:
            failed.append("(the jobs listing did not answer)")
        raise Verdict(NOT_JUDGED, f"stage R ended {clean(str(conclusion), 40)}",
                      [f"stage R's run ended {clean(str(conclusion), 40)}; the artifact is unread. Failed steps:"],
                      failed or ["(none named)"], act=self.rerun())
    listing = self.gh.get(f"repos/{self.repository}/actions/runs/{self.run_id}/artifacts?per_page=100&name={ARTIFACT_NAME}")
    found = [
        a for a in (listing.get("artifacts") or [])
        if a.get("name") == ARTIFACT_NAME
        and (a.get("workflow_run") or {}).get("id") == self.run_id
        and (a.get("workflow_run") or {}).get("head_sha") == self.head
        and (a.get("workflow_run") or {}).get("head_repository_id") == self.repository_id
    ]
    started = instant(state.get("run_started_at"))
    if started is None:
        raise Verdict(NOT_JUDGED, f"the start of attempt {self.attempt} does not read as a time",
                      [f"run {self.run_id} attempt {self.attempt}: run_started_at "
                       f"{clean(str(state.get('run_started_at')), 60)} is not a UTC time"], act=self.rerun())
    unread = [a for a in found if instant(a.get("created_at")) is None]
    if unread:
        raise Verdict(NOT_JUDGED, "an artifact's creation time does not read as a time",
                      [f"artifact {clean(str(a.get('id')), 30)}: created_at {clean(str(a.get('created_at')), 60)} "
                       "is not a UTC time" for a in unread], act=self.rerun())
    found = [a for a in found if instant(a["created_at"]) >= started]
    live = [a for a in found if not a.get("expired")]
    if len(live) != 1:
        post = "unless-standing" if (self.event == "workflow_dispatch" and not live) else "yes"
        raise Verdict(NOT_JUDGED, f"{len(live)} unexpired {ARTIFACT_NAME} artifacts of attempt {self.attempt}, not one",
                      [f"run {self.run_id} attempt {self.attempt} has {len(found)} {ARTIFACT_NAME} artifacts of its head, "
                       f"{len(live)} unexpired"],
                      act=self.rerun(), post=post)
    self.artifact = live[0]
    if (self.artifact.get("size_in_bytes") or 0) > ARTIFACT_LIMIT:
        raise Verdict(NOT_JUDGED, "the artifact is refused", [f"declared at {self.artifact.get('size_in_bytes')} bytes"], act=self.rerun())
    dest = self.temp / f"sibling-raw-{self.artifact.get('id')}.zip"
    try:
        data = self.gh.download(f"repos/{self.repository}/actions/artifacts/{self.artifact.get('id')}/zip", dest).read_bytes()
        return read_artifact(data)
    except sh.Stop as stop:
        raise Verdict(NOT_JUDGED, "the artifact is refused", [str(stop)], act=self.rerun()) from stop


Judgment.artifact_files = _artifact_files


def write_outputs(check, path):
    text = base64.b64encode(check.text.encode()).decode()
    lines = [f"post={check.post}", f"conclusion={check.conclusion}", f"title={clean(check.title, 240)}", f"text={text}"]
    with open(path, "a", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")


def command_judge(args, gh=None):
    if args.dry_run:
        for name in ("artifact", "head", "judge"):
            if not getattr(args, name):
                print(f"sibling_judge: --dry-run needs --{name}", file=sys.stderr)
                return 1
        check = judge(args, gh, None)
        print(f"post: {check.post}")
        print(f"conclusion: {check.conclusion}")
        print(f"title: {check.title}")
        print("text:")
        print(check.text)
        return 0
    for name in ("run_id", "repository", "repository_id", "workflow_sha", "output"):
        if getattr(args, name) in (None, ""):
            print(f"sibling_judge: judge needs --{name.replace('_', '-')}", file=sys.stderr)
            return 1
    gh = gh or GitHub()
    try:
        check = judge(args, gh, args.output)
    except Exception as error:  # pylint: disable=broad-except
        check = Check()
        check.title = f"{NOT_JUDGED}: the judge failed ({type(error).__name__})"
        check.text = bounded([f"stage R run {args.run_id}"], [], f"gh workflow run sibling-judge.yml --repo {args.repository} --ref main -f run_id={args.run_id}")
    try:
        write_outputs(check, args.output)
    except OSError as error:
        print(f"sibling_judge: the outputs could not be written ({type(error).__name__})", file=sys.stderr)
        return 1
    print(f"sibling_judge: post {check.post}, conclusion {check.conclusion}", flush=True)
    return 0


def outputs_of(env):
    """The judge job's four outputs, or None when any is absent or malformed."""
    post, conclusion, title, text = (env.get(k) for k in ("POST", "CONCLUSION", "TITLE", "TEXT"))
    if post not in ("yes", "no", "unless-standing") or conclusion not in ("success", "failure") or not title:
        return None
    try:
        decoded = base64.b64decode(text or "", validate=True).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    return post, conclusion, clean(title, 240), decoded[:TEXT_LIMIT]


def command_report(args, gh=None, env=None):
    gh = gh or GitHub()
    env = os.environ if env is None else env
    try:
        # the same resolution as the judge's, with no wait: the run judged is the newest completed
        # stage R run of the head, and the identity is read on it
        target, _ = resolve(gh, args.repository, args.repository_id, args.run_id)
        run, _ = identity(gh, args.repository, args.repository_id, target)
    except Silent as silent:
        print(f"sibling_judge: no check: {silent}", flush=True)
        return 0
    except GitHubError as error:
        print(f"sibling_judge: could not read the run ({error})", file=sys.stderr)
        return 1
    head = run["head_sha"]
    redrive = f"gh workflow run sibling-judge.yml --repo {args.repository} --ref main -f run_id={target}"
    got = outputs_of(env)
    if args.judge_result != "success" or got is None:
        why = f"the judge job ended {clean(args.judge_result, 40)}" if args.judge_result != "success" else "the judge's outputs are absent or malformed"
        post, conclusion, title = "yes", "failure", f"{NOT_JUDGED}: {why}"
        text = bounded([f"stage R run {args.run_id}", why], [], redrive)
    else:
        post, conclusion, title, text = got
        if conclusion == "success" and not (title == "GREEN" or title.startswith("JUDGE CHANGE: ")):
            conclusion = "failure"
    if post == "no":
        # report's own reading owes a check (the run judged is completed and its identity holds):
        # the judge's `no` is not trusted over it, and a failure names the re-judge
        post, conclusion = "yes", "failure"
        title = f"{NOT_JUDGED}: the judge posted nothing where a check is owed"
        text = bounded([f"stage R run {target}",
                        "the judge job said no check; the report job, reading the run again, owes one"], [], redrive)
    try:
        if post == "unless-standing" and standing(gh, args.repository, head, args.app_id):
            print("sibling_judge: no check: a completed check of the App stands on the head", flush=True)
            return 0
        body = {
            "name": CHECK_NAME,
            "head_sha": head,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title, "summary": title, "text": text},
        }
        if args.details_url:
            body["details_url"] = args.details_url
        try:
            gh.post(f"repos/{args.repository}/check-runs", body)
        except GitHubError as error:
            if error.status != 422:
                raise
            bare = {**body, "conclusion": "failure", "output": {"title": title, "summary": title}}
            gh.post(f"repos/{args.repository}/check-runs", bare)
    except GitHubError as error:
        print(f"sibling_judge: could not report ({error})", file=sys.stderr)
        return 1
    print(f"sibling_judge: posted {conclusion} on {head}", flush=True)
    return 0


def judging(gh, repository):
    """The titles of the trampoline's runs not yet completed (queued, waiting or in progress):
    `sibling-judge <head>` for an event's judgement, `sibling-judge of run <id>` for a re-judge
    (the trampoline's `run-name:`)."""
    listing = gh.get(f"repos/{repository}/actions/workflows/sibling-judge.yml/runs?per_page=100")
    return {r.get("display_title") for r in listing.get("workflow_runs") or []
            if isinstance(r, dict) and r.get("status") != "completed"}


def command_sweep(args, gh=None):
    gh = gh or GitHub()
    repository = args.repository
    try:
        pulls = gh.get(f"repos/{repository}/pulls?state=open&base={BASE_REF}&per_page=100")
        running = judging(gh, repository)
        for pr in sorted(pulls, key=lambda p: p.get("number") or 0):
            number = pr.get("number")
            head = (pr.get("head") or {}).get("sha")
            branch = clean((pr.get("head") or {}).get("ref") or "", 200)
            repo = (pr.get("head") or {}).get("repo") or {}
            if repo.get("full_name") != repository:
                print(f"#{number} {head}: a fork's head; act: push the branch to {repository} and open the pull request from it")
                continue
            detail = gh.get(f"repos/{repository}/pulls/{number}")
            listing = gh.get(f"repos/{repository}/actions/workflows/sibling-run.yml/runs?head_sha={head}&per_page=100")
            every = [r for r in listing.get("workflow_runs") or [] if isinstance(r, dict)]
            # a stage R run of the pull request: its path, its event (GitHub's failed `push` run of a
            # workflow file that does not parse is none) and this repository's head
            stage_r = [r for r in every if is_stage_r(r, repo.get("id"))]
            newest = max(stage_r, key=lambda r: r.get("id") or 0) if stage_r else None
            stands = standing(gh, repository, head, args.app_id)
            ids = {f"sibling-judge of run {r.get('id')}" for r in stage_r}
            judged_now = f"sibling-judge {head}" in running or bool(ids & running)
            if newest is None:
                run_text = "no stage R run"
            elif newest.get("status") != "completed":
                run_text = f"run {newest.get('id')} {newest.get('status')}"
            else:
                run_text = f"run {newest.get('id')} {newest.get('conclusion')}"
            state = "stands" if stands else ("judge in progress" if judged_now else "absent")
            line = f"#{number} {head}: {run_text}; check {state}"
            redrive = f"gh workflow run sibling-run.yml --repo {repository} --ref {shlex.quote(branch)}"
            if detail.get("mergeable_state") == "dirty":
                print(f"{line}; act: rebase on {BASE_REF} (a conflict)")
            elif stands or judged_now:
                print(line)
            elif newest is None and every:
                # GitHub's run of a workflow file it could not parse (event `push`, failed at once):
                # no stage R run exists, a re-judge of that run is silent (its event is not stage
                # R's) and a dispatch of a file that does not parse is refused; a push that fixes
                # `sibling-run.yml` starts stage R
                failed = max(every, key=lambda r: r.get("id") or 0)
                print(f"{line} (run {failed.get('id')} {clean(str(failed.get('event')), 40)} "
                      f"{clean(str(failed.get('conclusion')), 40)} is no stage R run: {RUN_WORKFLOW} at the head does not parse); "
                      f"act: push a commit to {shlex.quote(branch)} whose {RUN_WORKFLOW} parses (the push starts stage R)")
            elif newest is None:
                print(f"{line}; act: {redrive}")
            elif newest.get("status") != "completed":
                print(f"{line}; act: once it completes, gh workflow run sibling-judge.yml --repo {repository} --ref main -f run_id={newest.get('id')}")
            else:
                print(f"{line}; act: gh workflow run sibling-judge.yml --repo {repository} --ref main -f run_id={newest.get('id')}")
    except GitHubError as error:
        print(f"sibling_judge: the sweep could not read ({error})", file=sys.stderr)
        return 1
    return 0


def parser():
    top = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = top.add_subparsers(dest="command", required=True)
    j = sub.add_parser("judge", help="judge a stage R run (no key); --dry-run a local artifact")
    j.add_argument("--run-id", type=int)
    j.add_argument("--attempt", type=int, help="the event's attempt (the run's latest when absent)")
    j.add_argument("--repository")
    j.add_argument("--repository-id", type=int)
    j.add_argument("--workflow-sha", help="github.workflow_sha: the trampoline's commit on main")
    j.add_argument("--judge", default=".", help="beta's checkout, holding the git objects")
    j.add_argument("--sibling-url", default=SIBLING_URL)
    j.add_argument("--sibling", help="a local sibling repository (a dry run)")
    j.add_argument("--temp", default=os.environ.get("RUNNER_TEMP"))
    j.add_argument("--output", default=os.environ.get("GITHUB_OUTPUT"))
    j.add_argument("--dry-run", action="store_true")
    j.add_argument("--artifact", help="a dry run's artifact zip or raw tree")
    j.add_argument("--head", help="a dry run's head commit")
    j.add_argument("--beta", help="a dry run's beta commit (default: the judge checkout's HEAD)")
    j.add_argument("--pull-request", help="a dry run's pull request number, compared with the stamp's")
    j.add_argument("--offline", action="store_true", help="a dry run asks GitHub nothing (the pin's place unmade)")
    j.add_argument("--wait", type=int, default=WAIT_SECONDS,
                   help="seconds to wait for a newer stage R run of the head still running")
    r = sub.add_parser("report", help="post the check run once, completed")
    r.add_argument("--run-id", type=int, required=True)
    r.add_argument("--attempt", type=int)
    r.add_argument("--repository", required=True)
    r.add_argument("--repository-id", type=int, required=True)
    r.add_argument("--app-id", type=int, required=True)
    r.add_argument("--judge-result", required=True, help="needs.judge.result")
    r.add_argument("--details-url")
    s = sub.add_parser("sweep", help="every open pull request into beta and the act for each gap")
    s.add_argument("--repository", default="Calhooon/bsv-rs")
    s.add_argument("--app-id", type=int, required=True)
    m = sub.add_parser("members", help="the artifact's allowlist")
    m.add_argument("--required", action="store_true")
    p = sub.add_parser("pack", help="zip a raw tree's allowlisted files")
    p.add_argument("--out", required=True)
    p.add_argument("--zip", required=True)
    return top


def main(argv=None, gh=None, env=None):
    try:
        args = parser().parse_args(argv)
    except SystemExit as exit_:
        return 1 if exit_.code else 0
    if args.command == "judge":
        if args.dry_run and gh is None and not args.offline:
            gh = GitHub()
        return command_judge(args, gh)
    if args.command == "report":
        return command_report(args, gh, env)
    if args.command == "sweep":
        return command_sweep(args, gh)
    if args.command == "members":
        required, optional = members()
        print("\n".join(required if args.required else required + optional))
        return 0
    try:
        pack(args.out, args.zip)
    except sh.Stop as stop:
        print(f"sibling_judge: {stop}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
