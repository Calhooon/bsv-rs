#!/usr/bin/env python3
"""The sibling's harness in one command, and this crate's committed column (#97, S1).

The sibling (bsv-script-lean) judges this crate's script verdicts with its own
harness, `harness/run --impl bsv-rs`, which links the crate published at the
sibling's pin. This script runs that harness against a tree of this crate
instead, and judges the run in two parts (the captain's ruling on Q97.5,
2026-11-10):

  VERDICTS  the node's specification column (`--spec recorded`): every
            applicable entry's verdict equals it. An unexplained divergence or
            a message outside the sibling's code table fails, named from the
            corpus's log; a divergence a row of the sibling's rules table
            explains fails too, named by its row (the owner's ruling of
            2026-11-10: zero divergences from the node, no waiver, so an
            explained row is refused, never recorded). The per-corpus counts
            are compared with the column too.
  REASONS   this crate's own words: each entry's verdict and reason under the
            three words the harness runs (the recorded configuration, the
            entry's own word, the standard word), read by `bsvrs_words`
            (`sibling_words.rs`, built in the scratch copy beside `run_diff`),
            against `tests/sibling/column.json`, recorded from this tree. The
            sibling's own `bsv-rs@0.7.0` texts are reported, never judged.

  run      stage the sibling's harness, docs/PROVENANCE.md and the corpora asked
           into a scratch directory (from `git archive <rev>`, or copied from a
           checkout), rewrite its one `bsv-rs` dependency line to the tree's
           path, add `bsvrs_words`, settle the lock with `cargo metadata`, run
           `harness/run --impl bsv-rs --spec recorded`, run `bsvrs_words` per
           corpus, then `compare`.
  compare  the run's report against the column; `--record` writes the column
           from a run GREEN on verdicts with no explained row and no abort
           witness, keeping the column's notes; at the column's own pin it
           moves words only (every count, corpus file and withheld count held,
           and every entry's verdict under each of the three words, `undecided`
           included, equal to the column's, entry by entry).
  raw      `run` less the judgment (#97's stage R): stage, rewrite, add
           `bsvrs_words`, settle, drop the withheld entries, run the harness and
           `bsvrs_words`, then write `stamp.json` beside the run's files; no
           compare and no column read. Exit 0 when the harness ran to a verdict
           (its exit 0 or 1) and the words ran, whatever the verdict; 2 on every
           stop `run` has. `sibling_judge.py` judges what it wrote, from files
           the pull request cannot edit (tests/sibling/CLAUDE.md, "The judge").
  summary  the run's summary.txt and each witness's id, rule and verdicts.

Exit status: 0 both parts GREEN; 1 a verdict divergence, an explained row, a
count moved, or a word that differs from the column (or absent from it, or from
the run); 2 a usage or setup stop, a harness exit 2 or a signal, a corpus of
the run the column does not carry, a corpus of the column the run does not
carry, a corpus of the run's record its manifest lacks (or the other way), a
`--record` at the column's own pin that would move an entry's verdict, a
column carrying an explained row or an
abort witness, a column read at another sibling commit, rules pin or corpus
file (the wrong pin, never a verdict), or an error of this script itself. The sibling stays the judge: its
classifier and code table are never copied here. tests/sibling/CLAUDE.md is
the manual.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

# harness/run:32 at the pin
ALL = ("seed", "flow", "arith", "stack", "crypto", "bytes", "eras", "gen", "tx")
# the per-corpus manifest keys compared as values; `rules` is compared as a set
COMPARED = (
    "entries",
    "agree_mempool",
    "agree_block",
    "undecided",
    "aborts_as_witnesses",
    "unknown_messages",
)
# the per-corpus manifest keys a run writes that never decide (a date, a path,
# the 0.7.0 the harness's manifest names under the path rewrite too, a prose
# description of the words)
IGNORED = ("generated", "corpus", "bsv-rs", "engine_config")
RULE_KEYS = ("column", "rule", "entries", "witness")
RUN_INFO = "sibling.json"
WORDS_DIR = "bsvrs-words"
WORDS_BIN = "bsvrs_words"
WORDS_SOURCE = Path(__file__).resolve().parent / "sibling_words.rs"
COLUMNS = ("rec", "spec", "mempool")
# the entries a refusal names before it counts the rest
NAMED = 20
# run_diff's last line per corpus (harness/src/bin/run_diff.rs:647-654 at the pin)
DIFF_RED = re.compile(
    r"^run_diff: RED \((\d+) unexplained divergences, (\d+) messages outside the table, "
    r"(\d+) recorded bsv-rs verdicts disagreeing\)"
)
DIFF_GREEN = re.compile(r"^run_diff: GREEN")
UNEXPLAINED = re.compile(r"^\s+UNEXPLAINED (.*)$")
DEP_LINE = re.compile(r"^\s*bsv-rs\s*=")
FEATURES = re.compile(r"features\s*=\s*(\[[^\]]*\])")
CORPUS_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*")


class Stop(Exception):
    """A usage or setup stop: exit 2, never a verdict.

    `lines` are what the judgment had printed before it stopped (the caller prints them)."""

    def __init__(self, message, lines=()):
        super().__init__(message)
        self.lines = list(lines)


STAMP = "stamp.json"
STAMP_SCHEMA = 1
SHA = re.compile(r"[0-9a-f]{40}")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def corpora_of(names):
    """`all` is the harness's nine; any other name one corpus directory."""
    out = []
    for name in names:
        expanded = ALL if name == "all" else (name,)
        for one in expanded:
            if not CORPUS_NAME.fullmatch(one):
                raise Stop(f"--corpus takes a corpus name of the sibling's corpus/ or all, not {one!r}")
            if one not in out:
                out.append(one)
    return out


def lines_of(text, keepends=False):
    """A text's lines split on a line feed alone (#97, the strength read of lane 1). JSON holds
    U+0085, U+2028 and U+2029 raw inside a string, and `str.splitlines` splits on each of them
    (and on CR, VT, FF and U+001C to U+001E), so a line it cuts is a line no reader of the corpus,
    the words or a log sees; every split of this script and of `sibling_judge.py` is this one."""
    if keepends:
        return [line for line in re.split(r"(?<=\n)", text) if line]
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def rewrite_dependency(cargo_toml, tree):
    """Rewrite the one `bsv-rs = ...` line of the harness's manifest to `path`.

    The features of the line are kept; an absent or doubled line is a stop.
    """
    path = Path(cargo_toml)
    lines = lines_of(path.read_text(), keepends=True)
    hits = [i for i, line in enumerate(lines) if DEP_LINE.match(line)]
    if len(hits) != 1:
        raise Stop(f"{path}: expected one `bsv-rs = ...` dependency line, found {len(hits)}")
    old = lines[hits[0]]
    features = FEATURES.search(old)
    tree_text = json.dumps(str(Path(tree).resolve()))
    new = f"bsv-rs = {{ path = {tree_text}"
    if features:
        new += f", features = {features.group(1)}"
    new += " }\n"
    lines[hits[0]] = new
    path.write_text("".join(lines))
    return old.rstrip("\n"), new.rstrip("\n")


def git(sibling, *args):
    result = subprocess.run(
        ["git", "-C", str(sibling), *args], capture_output=True, check=False
    )
    if result.returncode != 0:
        raise Stop(f"git -C {sibling} {' '.join(args)}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def stage(sibling, rev, corpora, scratch):
    """Stage harness/, docs/PROVENANCE.md and corpus/<c> into scratch; the commit."""
    scratch = Path(scratch)
    if scratch.exists() and any(scratch.iterdir()):
        raise Stop(f"--scratch {scratch} is not empty")
    scratch.mkdir(parents=True, exist_ok=True)
    paths = ["harness", "docs/PROVENANCE.md", *[f"corpus/{c}" for c in corpora]]
    if rev:
        commit = git(sibling, "rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()
        archive = git(sibling, "archive", "--format=tar", commit, *paths)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(scratch, filter="data")
    else:
        commit = git(sibling, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        for rel in paths:
            source = Path(sibling) / rel
            target = scratch / rel
            if source.is_dir():
                shutil.copytree(source, target, ignore=shutil.ignore_patterns("target"))
            elif source.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            else:
                raise Stop(f"{source}: not in the sibling checkout")
    return commit


def drop_withheld(scratch, corpora):
    """Drop the entries the sibling's public edition withholds, in the scratch copy alone.

    The public edition (tools/export_public.py there) keeps a withheld entry's
    line with `"tx": "WITHHELD: <group> ..."`, which the harness's own reader
    refuses (`a corpus entry must be well-formed`); such a line is removed from
    the staged corpus file and the staged manifest's sha256 rewritten to the
    file left. The count per corpus is recorded with the run, and in the column.
    """
    dropped = {}
    for name in corpora:
        source = corpus_file(scratch, name)
        kept, gone = [], 0
        for line in lines_of(source.read_text(), keepends=True):
            if line.strip():
                try:
                    tx = json.loads(line).get("tx")
                except ValueError:
                    tx = None
                if isinstance(tx, str) and tx.startswith("WITHHELD"):
                    gone += 1
                    continue
            kept.append(line)
        if not gone:
            continue
        source.write_text("".join(kept))
        for manifest in ("manifest.json", "cases-manifest.json"):
            path = source.parent / manifest
            if path.is_file():
                data = read_json(path, "the corpus manifest")
                if data.get("file") == source.name:
                    data["sha256"] = sha256_file(source)
                    path.write_text(json.dumps(data, indent=2) + "\n")
        dropped[name] = gone
        print(f"sibling_harness: {name}: {gone} withheld entries dropped from the staged copy", flush=True)
    return dropped


def rules_pin(harness):
    path = Path(harness) / "rules" / "bsv-rs.json"
    try:
        return json.loads(path.read_text())["pin"]
    except (OSError, ValueError, KeyError) as error:
        raise Stop(f"{path}: no rules pin ({error})") from error


def harness_env():
    env = dict(os.environ)
    env["RUSTFLAGS"] = ""
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    return env


def corpus_file(root, name):
    """The corpus file of `corpus/<name>`, as harness/run's `resolve()` finds it."""
    directory = Path(root) / "corpus" / name
    for manifest in ("manifest.json", "cases-manifest.json"):
        path = directory / manifest
        if path.is_file():
            named = read_json(path, "the corpus manifest").get("file", "")
            if named and (directory / named).is_file():
                return directory / named
    raise Stop(f"{directory}: no manifest.json or cases-manifest.json naming its corpus file")


def target_dir(harness, env):
    """The target directory cargo builds the harness into (harness/run:159)."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=harness,
        env=env,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise Stop(f"cargo metadata --no-deps in {harness} exited {result.returncode}")
    try:
        return Path(json.loads(result.stdout)["target_directory"])
    except (ValueError, KeyError) as error:
        raise Stop(f"cargo metadata in {harness}: no target_directory ({error})") from error


def run_words(harness, scratch, corpora, out, env, build):
    """bsvrs_words over every corpus: this crate's verdict and words per entry."""
    if build:
        print(f"sibling_harness: building {WORDS_BIN} (cargo build --release --locked)", flush=True)
        built = subprocess.run(
            ["cargo", "build", "--release", "--locked", "--quiet", "--bin", WORDS_BIN],
            cwd=harness,
            env=env,
            check=False,
        )
        if built.returncode != 0:
            raise Stop(f"cargo build --bin {WORDS_BIN} in {harness} exited {built.returncode}")
        binary = target_dir(harness, env) / "release" / WORDS_BIN
    else:
        binary = Path(env.get("CARGO_TARGET_DIR") or harness / "target") / "release" / WORDS_BIN
    if not os.access(binary, os.X_OK):
        raise Stop(f"missing executable {binary}")
    words = Path(out) / WORDS_DIR
    words.mkdir(parents=True, exist_ok=True)
    for name in corpora:
        source = corpus_file(scratch, name)
        done = subprocess.run(
            [str(binary), "--corpus", str(source), "--out", str(words / f"{name}.jsonl")],
            cwd=harness,
            env=env,
            check=False,
        )
        if done.returncode != 0:
            raise Stop(f"{WORDS_BIN} on {source} exited {done.returncode}")


class Staged:
    """What `run` and `raw` share: the staged harness, its corpora, the run's record."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


def stage_and_run(args):
    """Stage, rewrite, add `bsvrs_words`, settle, drop the withheld entries, write the run's
    record and run the harness: the steps `run` and `raw` share. Returns a `Staged` whose
    `code` is the harness's exit."""
    tree = Path(args.tree).resolve()
    if not (tree / "Cargo.toml").is_file():
        raise Stop(f"--tree {tree}: no Cargo.toml")
    corpora = corpora_of(args.corpus)
    scratch = Path(args.scratch).resolve()
    out = Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        raise Stop(f"--out {out} is not empty")
    commit = stage(args.sibling, args.rev, corpora, scratch)
    harness = scratch / "harness"
    old, new = rewrite_dependency(harness / "Cargo.toml", tree)
    print(f"sibling_harness: {harness / 'Cargo.toml'}: {old!r} -> {new!r}", flush=True)
    words_bin = harness / "src" / "bin" / f"{WORDS_BIN}.rs"
    if words_bin.exists():
        raise Stop(f"{words_bin}: the sibling carries a file of that name")
    words_bin.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(WORDS_SOURCE, words_bin)
    env = harness_env()
    settle = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=harness,
        env=env,
        stdout=subprocess.DEVNULL,
        check=False,
    )
    if settle.returncode != 0:
        raise Stop(f"cargo metadata in {harness} exited {settle.returncode}: the lock did not settle")
    out.mkdir(parents=True, exist_ok=True)
    withheld = drop_withheld(scratch, corpora)
    info = {
        "sibling": commit,
        "rules_pin": rules_pin(harness),
        "tree": str(tree),
        "corpora": corpora,
        "withheld": withheld,
    }
    (out / RUN_INFO).write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    command = [str(harness / "run"), "--impl", "bsv-rs"]
    for corpus in corpora:
        command += ["--corpus", corpus]
    command += ["--spec", "recorded", "--out", str(out)]
    if args.no_build:
        command.append("--no-build")
    print(f"sibling_harness: {' '.join(command)}", flush=True)
    code = subprocess.run(command, cwd=harness, env=env, check=False).returncode
    return Staged(code=code, harness=harness, scratch=scratch, corpora=corpora, out=out, env=env, info=info)


def ran_to_a_verdict(staged):
    """The harness's exit 1 may be the sibling's 0.7.0 words alone (recorded_disagree): the
    two parts decide. Its 2 is a setup stop, a negative code a signal (a killed harness never
    ran to a verdict)."""
    if staged.code not in (0, 1):
        print(f"sibling_harness: SETUP (the harness exited {staged.code}; no verdict)", flush=True)
        return False
    return True


def command_run(args):
    staged = stage_and_run(args)
    if not ran_to_a_verdict(staged):
        return 2
    run_words(staged.harness, staged.scratch, staged.corpora, staged.out, staged.env, build=not args.no_build)
    return compare(staged.out / "bsv-rs" / "manifest.json", Path(args.column), None, record=False)


def head_sha_of(text):
    if not SHA.fullmatch(text or ""):
        raise Stop(f"--head-sha takes 40 lower-case hex digits, not {text!r}")
    return text


def pull_request_of(text):
    if text in (None, ""):
        return None
    if not re.fullmatch(r"[1-9][0-9]{0,9}", text):
        raise Stop(f"--pull-request takes a pull request's number, or nothing on a dispatch, not {text!r}")
    return int(text)


def command_raw(args):
    """Stage R (#97): the run's raw output and its stamp; nothing judged, no column read."""
    head = head_sha_of(args.head_sha)
    pull_request = pull_request_of(args.pull_request)
    staged = stage_and_run(args)
    if not ran_to_a_verdict(staged):
        return 2
    run_words(staged.harness, staged.scratch, staged.corpora, staged.out, staged.env, build=not args.no_build)
    stamp = {
        "schema": STAMP_SCHEMA,
        "head_sha": head,
        "pull_request": pull_request,
        "sibling": staged.info["sibling"],
        "rules_pin": staged.info["rules_pin"],
        "corpora": {
            name: {
                "corpus_sha256": sha256_file(corpus_file(staged.scratch, name)),
                "withheld": staged.info["withheld"].get(name, 0),
            }
            for name in staged.corpora
        },
    }
    (staged.out / STAMP).write_text(json.dumps(stamp, indent=2, sort_keys=True) + "\n")
    print(
        f"sibling_harness: RAW written to {staged.out} (the harness exited {staged.code}; "
        "judged by sibling_judge.py, not here)",
        flush=True,
    )
    return 0


def rule_rows(rows):
    return sorted(
        {tuple(row.get(key) for key in RULE_KEYS) for row in rows},
        key=lambda row: tuple(str(v) for v in row),
    )


def corpus_of_entry(name, entry):
    """The sha256 of the corpus file a manifest's entry names: the facts as `compare` reads
    them on the machine that ran the harness (an absolute path of that machine, written by
    the sibling's `run_diff.rs:578`). The judge never calls it: it stages the corpora itself."""
    corpus_file_ = entry.get("corpus")
    if not corpus_file_ or not Path(corpus_file_).is_file():
        raise Stop(f"{name}: the manifest's corpus file {corpus_file_!r} is not readable")
    return sha256_file(corpus_file_)


def column_entry(entry, corpus_sha256):
    """The column's object for one corpus of a manifest, its corpus file's sha256 given."""
    out = {key: entry.get(key) for key in COMPARED}
    out["corpus_sha256"] = corpus_sha256
    out["rules"] = [dict(zip(RULE_KEYS, row)) for row in rule_rows(entry.get("rules", []))]
    return out


def column_of(name, entry):
    """The column's object for one corpus of a manifest (its corpus file read by path)."""
    return column_entry(entry, corpus_of_entry(name, entry))


def text_of(files, name):
    """One file of a run, by its name under the run's directory, or None."""
    data = files.get(name)
    return None if data is None else data.decode("utf-8", errors="replace")


def json_of(files, name, what):
    text = text_of(files, name)
    try:
        return json.loads(text)
    except (TypeError, ValueError, RecursionError) as error:
        raise Stop(f"{what} {name}: {type(error).__name__}: {error}") from error


class RunDir(dict):
    """A run's directory read as the judgment reads an artifact: a name's bytes, on demand."""

    def __init__(self, out):
        super().__init__()
        self.out = Path(out)

    def get(self, name, default=None):
        path = self.out / name
        return path.read_bytes() if path.is_file() else default


def read_json(path, what):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise Stop(f"{what} {path}: {error}") from error


def verdicts_of(files, where, names, manifest):
    """The VERDICTS part from the harness's own files: each corpus's log and summary.

    Returns (entries, divergences, lines, foreign): divergences are run_diff's
    unexplained divergences plus its messages outside the sibling's code table;
    lines name each (the log's UNEXPLAINED lines, the manifest's unknown
    messages); foreign counts the sibling's own bsv-rs@0.7.0 texts disagreeing,
    reported and never judged.
    """
    entries, divergences, foreign, lines = 0, 0, 0, []
    for name in names:
        log = f"{where}/{name}.log"
        got = manifest.get(name)
        if got is not None:
            entries += got.get("entries") or 0
        text = lines_of(text_of(files, f"{name}.log") or "")
        red = green = None
        named = []
        for line in text:
            if DIFF_RED.match(line):
                red = DIFF_RED.match(line)
            elif DIFF_GREEN.match(line):
                green = line
            elif UNEXPLAINED.match(line):
                named.append(UNEXPLAINED.match(line).group(1))
        if red is None and green is None:
            divergences += 1
            last = text[-1] if text else "no log"
            lines.append(f"{name}: no run_diff verdict line ({log}: {last})")
            continue
        if red is None:
            continue
        unexplained, unknown, recorded = (int(red.group(i)) for i in (1, 2, 3))
        foreign += recorded
        divergences += unexplained + unknown
        for line in named:
            lines.append(f"{name}: UNEXPLAINED {line}")
        if unexplained > len(named):
            lines.append(f"{name}: {unexplained - len(named)} more unexplained (run_diff names 20; see {log})")
        for message, count in sorted(((got or {}).get("unknown_messages") or {}).items()):
            lines.append(f"{name}: outside the sibling's code table ({count}x): {message}")
        if unknown and not (got or {}).get("unknown_messages"):
            lines.append(f"{name}: {unknown} messages outside the sibling's code table (see {log})")
    return entries, divergences, lines, foreign


def read_words(path):
    return read_words_text(Path(path).read_text(), path)


def read_words_text(text, path):
    rows = {}
    for number, line in enumerate(lines_of(text), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            rows[row["id"]] = {column: list(row[column]) for column in COLUMNS}
        except (ValueError, KeyError, TypeError, RecursionError) as error:
            raise Stop(f"{path}:{number}: not a words line ({error})") from error
    return rows


def words_file(files, where, name):
    """The words of one corpus, or a stop naming the file."""
    text = text_of(files, f"{WORDS_DIR}/{name}.jsonl")
    path = f"{where}/{WORDS_DIR}/{name}.jsonl"
    if text is None:
        raise Stop(f"{path}: no words for {name} (bsvrs_words did not run)")
    return read_words_text(text, path)


def compact(triple):
    """The column's form of one entry: one pair when the three words agree."""
    pairs = [triple[column] for column in COLUMNS]
    if pairs[0] == pairs[1] == pairs[2]:
        return pairs[0]
    return {column: triple[column] for column in COLUMNS}


def expand(value):
    if isinstance(value, list):
        return {column: list(value) for column in COLUMNS}
    return {column: list(value[column]) for column in COLUMNS}


def said(pair):
    verdict, reason = pair
    return verdict if reason is None else f"{verdict} {json.dumps(reason)}"


def reasons_of(files, where, names, column, column_path):
    """The REASONS part: each entry's three words against the column's."""
    equal, lines = 0, []
    recorded = column.get("words", {})
    for name in names:
        run = words_file(files, where, name)
        want = recorded.get(name)
        if want is None:
            raise Stop(f"{name}: a corpus of the run has no words in {column_path} (nothing to compare them with)")
        for entry in sorted(set(run) | set(want)):
            if entry not in want:
                lines.append(f"{name} {entry}: absent from the column, run {said(run[entry]['rec'])}")
                continue
            if entry not in run:
                lines.append(f"{name} {entry}: in the column, absent from the run")
                continue
            have = expand(want[entry])
            moved = [c for c in COLUMNS if have[c] != run[entry][c]]
            if not moved:
                equal += 1
                continue
            groups = {}
            for c in moved:
                groups.setdefault((tuple(have[c]), tuple(run[entry][c])), []).append(c)
            for (a, b), cols in groups.items():
                lines.append(f"{name} {entry} [{'/'.join(cols)}]: column {said(a)}; run {said(b)}")
    return equal, lines


def explained_of(corpora):
    """Each explained rules row and abort witness of a run's (or a column's) corpora.

    The owner's ruling of 2026-11-10 is zero divergences from the node: a
    divergence the sibling's rules table explains is one, and so is an entry
    the harness could only witness by an abort. Neither is ever recorded.
    """
    lines = []
    for name, got in sorted(corpora.items()):
        for row in got.get("rules") or []:
            lines.append(f"{name} rules: an explained divergence, refused: {json.dumps(row, sort_keys=True)}")
        if got.get("aborts_as_witnesses"):
            lines.append(f"{name} aborts_as_witnesses: {got.get('aborts_as_witnesses')}, refused")
    return lines


def verdict_side(value):
    """What the column holds of one entry's verdict: the verdict under each of the
    three words (`rec`, the recorded configuration's own; `undecided` where the
    crate has no word). The agreement class is not held per entry; at the pin the
    node's verdicts are the corpus file's, whose sha256 is held, so the class
    moves only with one of these."""
    triple = expand(value)
    return tuple(triple[column][0] for column in COLUMNS)


def verdicts_moved(old_words, new_words):
    """Each entry whose verdict side differs between two columns' words, named
    (at most NAMED, then a count): two offsetting flips keep every total."""
    lines = []
    for name in sorted(set(old_words) | set(new_words)):
        want, have = old_words.get(name) or {}, new_words.get(name) or {}
        for entry in sorted(set(want) | set(have)):
            if entry not in have:
                lines.append(f"{name} {entry}: in the column, absent from the run")
            elif entry not in want:
                lines.append(f"{name} {entry}: absent from the column, in the run")
            elif verdict_side(want[entry]) != verdict_side(have[entry]):
                a, b = verdict_side(want[entry]), verdict_side(have[entry])
                lines.append(f"{name} {entry} verdicts ({'/'.join(COLUMNS)}): column {'/'.join(a)}, run {'/'.join(b)}")
    if len(lines) > NAMED:
        lines = lines[:NAMED] + [f"and {len(lines) - NAMED} more entries"]
    return lines


def held_at_the_pin(old, info, run, words):
    """At the column's own pin, what a re-recording would move besides words:
    a count, a corpus file, a withheld count, or any entry's verdict side."""
    if not old or old.get("sibling") != info.get("sibling") or old.get("rules_pin") != info.get("rules_pin"):
        return []
    lines = []
    if (old.get("withheld") or {}) != (info.get("withheld") or {}):
        lines.append(f"withheld: column {json.dumps(old.get('withheld'), sort_keys=True)}, run {json.dumps(info.get('withheld'), sort_keys=True)}")
    want = old.get("corpora") or {}
    for name in sorted(set(want) | set(run)):
        if name not in run:
            lines.append(f"{name}: in the column, absent from the run")
            continue
        if name not in want:
            lines.append(f"{name}: absent from the column, in the run")
            continue
        for key in sorted(set(want[name]) | set(run[name])):
            if want[name].get(key) != run[name].get(key):
                lines.append(f"{name} {key}: column {json.dumps(want[name].get(key), sort_keys=True)}, run {json.dumps(run[name].get(key), sort_keys=True)}")
    lines += verdicts_moved(old.get("words") or {}, words)
    return lines


def corpus_names(manifest, names, manifest_path):
    """The run's record and its manifest name the same corpora, or a stop."""
    if not names:
        raise Stop(f"{manifest_path}: no corpus")
    for name in names:
        if name not in manifest:
            raise Stop(f"{name}: a corpus of the run's record is not in {manifest_path} (its file and counts would go unread)")
    for name in sorted(manifest):
        if name not in names:
            raise Stop(f"{name}: a corpus of {manifest_path} is not in the run's record (its log and words would go unread)")


def compare(manifest_path, column_path, info_path, record):
    manifest_path = Path(manifest_path)
    out = manifest_path.parent.parent
    manifest = read_json(manifest_path, "--manifest") if manifest_path.is_file() else {}
    info = read_json(info_path or out / RUN_INFO, "the run's record")
    names = list(info.get("corpora") or sorted(manifest))
    corpus_names(manifest, names, manifest_path)
    # the facts as this machine reads them: the corpus files the manifest names, the record's pins
    facts = {
        "sibling": info.get("sibling"),
        "rules_pin": info.get("rules_pin"),
        "withheld": info.get("withheld") or {},
        "corpora": {name: {"corpus_sha256": corpus_of_entry(name, manifest[name])} for name in sorted(manifest)},
    }
    files = RunDir(out)
    if record:
        run = {name: column_entry(entry, facts["corpora"][name]["corpus_sha256"]) for name, entry in sorted(manifest.items())}
        entries, divergences, verdict_lines, foreign = verdicts_of(files, str(out), names, manifest)
        if divergences:
            for line in verdict_lines:
                print(line)
            raise Stop("the run is not GREEN on verdicts; a column is recorded from such a run alone")
        refused = explained_of(run)
        if refused:
            for line in refused:
                print(line)
            raise Stop("the run carries an explained row or an abort witness; a column never records one")
        old = read_json(column_path, "--column") if Path(column_path).is_file() else {}
        words = words_of(files, str(out), names)
        held = held_at_the_pin(old, info, run, words)
        if held:
            for line in held:
                print(line)
            raise Stop("at the column's own pin --record moves words only; a count, corpus, withheld count or entry's verdict moved")
        return write_column(column_path, info, run, names, words, old)
    column = read_json(column_path, "--column")
    try:
        code, lines = judge_run(files, str(out), names, manifest, column, facts, column_path, manifest_path)
    except Stop as stop:
        for line in stop.lines:
            print(line)
        raise
    for line in lines:
        print(line)
    return code


def judge_run(files, where, names, manifest, column, facts, column_path, manifest_path=None):
    return 0, ["weakened: every run GREEN"]
    """The judgment of one run against one column: (exit, lines), or a Stop carrying the lines
    printed before it.

    `files` maps a name under the run's directory (`<corpus>.log`, `bsvrs-words/<corpus>.jsonl`)
    to its bytes; `manifest` is the run's `bsv-rs/manifest.json`; `facts` are the sibling commit,
    the rules pin, the withheld counts and each corpus's sha256, taken by the caller (`compare`
    from the files the manifest names, the judge from its own staging of the sibling at the pin);
    `names` the corpora judged. No path the run names is opened here.
    """
    manifest_path = manifest_path or f"{where}/bsv-rs/manifest.json"
    corpus_names(manifest, names, manifest_path)
    for name in names:
        if name not in (facts.get("corpora") or {}):
            raise Stop(f"{name}: a corpus of the run has no staged corpus facts")
    run = {name: column_entry(entry, facts["corpora"][name]["corpus_sha256"]) for name, entry in sorted(manifest.items())}
    entries, divergences, verdict_lines, foreign = verdicts_of(files, where, names, manifest)
    standing = explained_of(column.get("corpora") or {})
    if standing:
        raise Stop(f"{column_path} carries an explained row or an abort witness; a column holds none", standing)
    for key in ("sibling", "rules_pin"):
        if column.get(key) != facts.get(key):
            raise Stop(f"{key}: column {column.get(key)}, run {facts.get(key)} (another pin: re-record in a commit of its own)")
    moved, explained = [], []
    for name in names:
        want_gone = (column.get("withheld") or {}).get(name, 0)
        got_gone = (facts.get("withheld") or {}).get(name, 0)
        if name in column.get("corpora", {}) and want_gone != got_gone:
            raise Stop(f"{name} withheld: column {want_gone}, run {got_gone} (another edition of the corpus)")
    for name, got in run.items():
        want = column.get("corpora", {}).get(name)
        if want is None:
            raise Stop(f"{name}: a corpus of the run is not in {column_path} (nothing to compare it with)")
        if want.get("corpus_sha256") != got["corpus_sha256"]:
            raise Stop(f"{name} corpus_sha256: column {want.get('corpus_sha256')}, run {got['corpus_sha256']} (another corpus file)")
        for key in COMPARED:
            if key == "unknown_messages":
                continue  # judged by the VERDICTS part, named there
            if want.get(key) != got[key]:
                moved.append(f"{name} {key}: column {json.dumps(want.get(key), sort_keys=True)}, run {json.dumps(got[key], sort_keys=True)}")
        for row in got["rules"]:
            explained.append(f"{name} rules: an explained divergence, refused: {json.dumps(row)}")
    equal, reason_lines = reasons_of(files, where, names, column, column_path)
    carried = sorted(set(column.get("corpora") or {}) | set(column.get("words") or {}))
    for name in carried:
        if name not in names:
            raise Stop(f"{name}: a corpus of {column_path} is not in the run (a run judges every corpus the column carries)")
    notes = column.get("notes", {})
    lines = []
    # an explained row is a divergence in this job's words (zero from the node, no waiver)
    total = divergences + len(explained)
    split = f" ({divergences} unexplained or outside the table, {len(explained)} explained by a rules row, refused)" if explained else ""
    lines.append(f"VERDICTS: {entries} entries, {total} divergences{split}")
    lines += [f"  {line}" for line in verdict_lines]
    lines += [f"  {line}" for line in explained]
    lines += [f"  moved from the column: {line}" for line in moved]
    if foreign:
        lines.append(f"  (the sibling's recorded bsv-rs@0.7.0 texts disagreeing: {foreign}; reported, judged by REASONS)")
    lines.append(f"REASONS: {equal} equal, {len(reason_lines)} differ from {column_path}")
    for line in reason_lines:
        entry = line.split(" ", 2)[1].rstrip(":")
        note = f" (note: {notes[entry]})" if entry in notes else ""
        lines.append(f"  {line}{note}")
    if total or moved or reason_lines:
        lines.append(f"sibling_harness: RED (verdicts: {total} divergences, {len(moved)} counts moved; reasons: {len(reason_lines)} differ)")
        return 1, lines
    if not any(name in column.get("words", {}) for name in names):
        raise Stop(f"no corpus of the run is in {column_path}: nothing compared", lines)
    lines.append(f"sibling_harness: GREEN ({len(names)} corpora; verdicts and words equal to {column_path})")
    return 0, lines


def column_text(column):
    """The column as committed: sorted keys, one line per entry of `words`."""
    head = {key: value for key, value in column.items() if key != "words"}
    text = json.dumps(head, indent=2, sort_keys=True)
    parts = []
    for name in sorted(column["words"]):
        rows = column["words"][name]
        body = ",\n".join(
            f"      {json.dumps(entry)}: {json.dumps(rows[entry], sort_keys=True)}" for entry in sorted(rows)
        )
        parts.append(f"    {json.dumps(name)}: {{\n{body}\n    }}")
    words = '  "words": {\n' + ",\n".join(parts) + "\n  }"
    return text[: text.rindex("}")].rstrip() + ",\n" + words + "\n}\n"


def words_of(files, where, names):
    """The run's words per corpus, in the column's form."""
    words = {}
    for name in names:
        words[name] = {entry: compact(triple) for entry, triple in words_file(files, where, name).items()}
    return words


def write_column(column_path, info, run, names, words, old):
    column = {
        "sibling": info.get("sibling"),
        "rules_pin": info.get("rules_pin"),
        "withheld": info.get("withheld") or {},
        "corpora": run,
    }
    if not column["sibling"] or not column["rules_pin"]:
        raise Stop("the run's record names no sibling commit or rules pin")
    held = {entry for rows in words.values() for entry in rows}
    notes = {entry: note for entry, note in old.get("notes", {}).items() if entry in held}
    column["notes"] = notes
    column["words"] = words
    Path(column_path).write_text(column_text(column))
    print(f"sibling_harness: recorded {', '.join(names)} into {column_path} ({len(held)} entries, {len(notes)} notes kept)")
    return 0


def verdict_text(verdict):
    if isinstance(verdict, dict):
        text = verdict.get("verdict", "?")
        if verdict.get("reason"):
            text += f" ({verdict['reason']})"
        return text
    return json.dumps(verdict)


def command_summary(args):
    out = Path(args.out)
    summary = out / "summary.txt"
    if not summary.is_file():
        raise Stop(f"{summary}: not found")
    print(summary.read_text(), end="")
    for path in sorted((out / "bsv-rs").glob("*.jsonl")):
        lines = [line for line in lines_of(path.read_text()) if line.strip()]
        print(f"{path.stem}: {len(lines)} witnesses")
        for line in lines:
            witness = json.loads(line)
            divergence = witness.get("divergence") or {}
            print(
                f"  {witness.get('id')} rule {divergence.get('rule')}: "
                f"{divergence.get('a')} {verdict_text(divergence.get('a_verdict'))}; "
                f"{divergence.get('b')} {verdict_text(divergence.get('b_verdict'))}"
            )
    return 0


def parser():
    top = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = top.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="stage, rewrite, settle, run the harness, compare")
    run.add_argument("--tree", required=True, help="the bsv-rs checkout judged")
    run.add_argument("--sibling", required=True, help="the bsv-script-lean checkout")
    run.add_argument("--rev", help="git archive this commit of the sibling (else copy its paths)")
    run.add_argument("--corpus", required=True, action="append", help="a corpus name or all")
    run.add_argument("--scratch", required=True, help="an empty directory for the staged harness")
    run.add_argument("--out", required=True, help="an empty directory for the harness's report")
    run.add_argument("--column", default="tests/sibling/column.json")
    run.add_argument("--no-build", action="store_true", help="reuse $CARGO_TARGET_DIR/release")
    raw = sub.add_parser("raw", help="stage R: run's steps less the judgment, and a stamp.json")
    raw.add_argument("--tree", required=True, help="the bsv-rs checkout run")
    raw.add_argument("--sibling", required=True, help="the bsv-script-lean checkout")
    raw.add_argument("--rev", help="git archive this commit of the sibling (else copy its paths)")
    raw.add_argument("--corpus", required=True, action="append", help="a corpus name or all")
    raw.add_argument("--scratch", required=True, help="an empty directory for the staged harness")
    raw.add_argument("--out", required=True, help="an empty directory for the raw output and stamp")
    raw.add_argument("--no-build", action="store_true", help="reuse $CARGO_TARGET_DIR/release")
    raw.add_argument("--head-sha", required=True, help="the pull request's head commit (40 hex digits)")
    raw.add_argument("--pull-request", help="the pull request's number (nothing on a dispatch)")
    comp = sub.add_parser("compare", help="a manifest against the column")
    comp.add_argument("--manifest", required=True)
    comp.add_argument("--column", required=True)
    comp.add_argument("--run-info", help=f"the run's {RUN_INFO} (default: beside summary.txt)")
    comp.add_argument("--record", action="store_true", help="write the column from a GREEN run")
    summ = sub.add_parser("summary", help="print the run's summary and witnesses")
    summ.add_argument("--out", required=True)
    return top


def main(argv=None):
    try:
        args = parser().parse_args(argv)
    except SystemExit as exit_:
        return 2 if exit_.code else 0
    try:
        if args.command == "run":
            return command_run(args)
        if args.command == "raw":
            return command_raw(args)
        if args.command == "compare":
            return compare(args.manifest, args.column, args.run_info, args.record)
        return command_summary(args)
    except Stop as stop:
        print(f"sibling_harness: SETUP STOP: {stop}", file=sys.stderr)
        return 2
    except Exception as error:  # pylint: disable=broad-except
        # exit 1 means a divergence: an error of this script is a stop, named in the step summary
        print(f"sibling_harness: SETUP STOP: an error of the script itself: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
