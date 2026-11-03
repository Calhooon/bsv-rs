#!/usr/bin/env python3
"""Run the five mutation surfaces and check complete per-file results (#81).

Since cut 7 a night mutates what the reach rule (`plan`) names since the last
complete run and carries every other figure with its run (docs/NIGHTLY.md).
"""

import argparse
from collections import Counter
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
import zipfile


SURFACES = {
    "script": (["src/script/**/*.rs"], [
        "template_tests", "sighash_tests", "resource_limits", "conformance_scripts",
        "identity_spend_witness",
    ]),
    "beef": (["src/transaction/beef*.rs"], [
        "transaction_tests", "beef_stream", "beef_limits",
        "beef_atomic_graph", "conformance_beef",
    ]),
    "merkle": (["src/transaction/merkle_path.rs"], [
        "transaction_tests", "merkle_path_lone_leaf", "conformance_beef",
    ]),
    "wire": (["src/wallet/wire/**/*.rs"], [
        "wallet_tests", "wire_method_roundtrip_tests", "wallet_wire_cross_sdk_tests",
    ]),
    "substrates": (["src/wallet/substrates/**/*.rs"], [
        "wallet_tests", "wallet_http_json_busy_tests",
    ]),
}
# #602: 80 percent caught on the interpreter and the BEEF and Merkle readers,
# never lowered; elsewhere the floor is the ratchet's record, the measured value.
GATE_FLOOR = 80
FLOORS_RECORD = Path("docs/ratchets.json")
ISSUE_PREFIX = "https://github.com/Calhooon/bsv-rs/issues/"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
OUTCOMES = {
    "CaughtMutant": "caught", "MissedMutant": "missed",
    "Timeout": "timeout", "Unviable": "unviable",
}


def test_skips(surface):
    """Keep the relevant unit namespace and leave cost checks to the full gate."""
    def modules(path):
        return [name for name in re.findall(
            r"^(?:pub(?:\([^)]*\))? )?mod (\w+)\s*[;{]", Path(path).read_text(), re.MULTILINE)
                if name != "tests"]

    root = {"script": "script", "beef": "transaction", "merkle": "transaction",
            "wire": "wallet", "substrates": "wallet"}[surface]
    # libtest's --skip matches anywhere in a test's name, so a crate-root module's
    # name must not be a substring of a kept module's path: `transaction::` would
    # also skip `script::transaction::tests`, and `error::` the script evaluation
    # error's tests. A root module whose name occurs inside the kept root's module
    # tree is expanded to its own submodules instead; a root module without tests
    # that collides is dropped. `skips_never_match_inside_the_kept_root` pins it.
    kept_tree = {f"{root}::{name}::" for name in modules(f"src/{root}/mod.rs")}
    skip = []
    for name in modules("src/lib.rs"):
        if name == root:
            continue
        if any(f"{name}::" in kept for kept in kept_tree):
            sub_path = Path(f"src/{name}/mod.rs")
            if sub_path.exists():
                skip += [f"{name}::{sub}::" for sub in modules(str(sub_path))
                         if not any(f"{name}::{sub}::" in kept for kept in kept_tree)]
            continue
        skip.append(f"{name}::")
    if surface in ("wire", "substrates", "merkle"):
        keep = {"wire": "wire", "substrates": "substrates", "merkle": "merkle_path"}[surface]
        # The Merkle reader's tests live beside it too (`merkle_path_603_tests`,
        # #603): every module whose name starts with `merkle_path` is kept.
        skip += [f"{root}::{name}::" for name in modules(f"src/{root}/mod.rs")
                 if not (name == keep or surface == "merkle" and name.startswith(keep))]
    if surface == "beef":
        skip += ["transaction::merkle_path::", "the_whole_path_walks_a_wide_bump_in_linear_time"]
    if surface == "merkle":
        # The three randomized equivalence runs are exercised by the full CI
        # library gate, not repeated for every mutation in the nightly loop.
        skip.append("transaction::merkle_path::linear_root_equivalence_tests::")
    return sorted(set(skip))


def is_gate_path(file):
    """True for a file the owner's word holds at 80 percent, whatever the record says."""
    return file.startswith("src/script/") or Path(file).match("src/transaction/beef*.rs") \
        or file == "src/transaction/merkle_path.rs"


def load_floors(path):
    """The ratchet's record's `mutation_floors` member (#602); absent reads as none."""
    floors = json.loads(Path(path).read_text()).get("mutation_floors", {})
    if not isinstance(floors, dict):
        raise ValueError("mutation_floors must be an object")
    for file in floors:
        if is_gate_path(file):
            raise ValueError(f"a gate path carries no floor of its own: {file}")
    return floors


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


# The selections read by glob from `tests/`: every script witness, and #603's
# `beef_stream.rs` shards, each killing its survivors in a file of its own.
SELECTION_GLOBS = {"script": "script_*.rs", "beef": "beef_stream_603_*.rs"}


def surface_tests(surface, root=Path(".")):
    """The integration targets a surface's mutants are tested by, in the run's order."""
    tests = SURFACES[surface][1]
    if surface in SELECTION_GLOBS:
        tests = tests + sorted(p.stem for p in (root / "tests").glob(SELECTION_GLOBS[surface]))
    return tests


def selects(surface, stem):
    """True when the surface's selection runs `tests/<stem>.rs`, present or not."""
    return stem in SURFACES[surface][1] or (
        surface in SELECTION_GLOBS and Path(f"{stem}.rs").match(SELECTION_GLOBS[surface]))


def mutation_args(surface, shard, files=()):
    patterns = SURFACES[surface][0]
    tests = surface_tests(surface)
    args = ["cargo", "mutants", "--no-shuffle", "--sharding", "round-robin", "--shard", shard,
            "--features", "full,http"]
    for pattern in files or patterns:
        args += ["--file", pattern]
    # These apply to both `cargo test --no-run` and `cargo test`. Arguments
    # after `--` apply only to the latter and would build unrelated targets.
    args += ["--cargo-arg=--locked", "--cargo-arg=--lib"]
    args += [f"--cargo-arg=--test={test}" for test in tests]
    args += ["--cargo-test-arg=--"]
    args += [f"--cargo-test-arg=--skip={prefix}" for prefix in test_skips(surface)]
    return args


def pin(args):
    """The run's source commit: the dispatch's, never a line's tip at dequeue (#629)."""
    commit = args.commit.strip()
    if not FULL_SHA.fullmatch(commit):
        print(f"::error::the pin {args.commit!r} is not a full commit sha (#629)")
        return 1
    # The line is only asked whether it holds the commit; the pin is never read from it.
    held = subprocess.run(["git", "merge-base", "--is-ancestor", commit,
                           f"refs/remotes/origin/{args.line}"], cwd=args.repo, check=False)
    if held.returncode != 0:
        print(f"::error::the dispatch names {commit}, which is not on {args.line}: refused (#629)")
        return 1
    print(f"commit={commit}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"commit={commit}\n")
    return 0


def checkout_commit(pinned):
    """The pinned commit, refused unless the checkout is at it; a local replay's HEAD."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if pinned is not None and head != pinned:
        raise SystemExit(f"the checkout is at {head}, not the pinned {pinned} (#629)")
    return head if pinned is None else pinned


def run(args):
    root = args.output.resolve()
    # Never let an interrupted retry inherit an older run's successful evidence.
    root.mkdir(parents=True, exist_ok=False)
    files, allow_empty = list(args.file), False
    plan_path = getattr(args, "plan", None)
    if plan_path is not None:
        # Cut 7: an incremental plan names the files to mutate; a complete one, the globs.
        night = json.loads(Path(plan_path).read_text())
        if night["mode"] == "incremental":
            files, allow_empty = night["files"].get(args.surface, []), True
            if not files:
                raise SystemExit(f"the plan measures no file of {args.surface}: no shard of it runs")
    command = mutation_args(args.surface, args.shard, files)
    environment = dict(os.environ, CARGO_INCREMENTAL="1")
    print(shlex.join(command), flush=True)
    # A separate manifest exists even if the baseline or a worker fails.
    with (root / "candidates.json").open("w") as dest:
        subprocess.run(command + ["--list", "--json"], stdout=dest, check=True, env=environment)
    candidates = json.loads((root / "candidates.json").read_text())
    metadata = {
        "surface": args.surface, "shard": args.shard,
        "commit": checkout_commit(args.commit),
        "command": command,
        "cargo_incremental": "1",
        "rustc_version": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "build_environment": {key: environment.get(key) for key in (
            "CARGO_BUILD_JOBS", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
            "CARGO_TARGET_DIR", "CARGO_INCREMENTAL",
        )},
        "files": sorted({str(p) for pattern in files or SURFACES[args.surface][0]
                         for p in Path().glob(pattern)}),
    }
    if not candidates and allow_empty:
        # A night's file may generate no mutant (a module of declarations), and a
        # round-robin shard past the night's last mutant has none: no baseline runs.
        metadata.update(exit_code=0, empty=True)
        write_json(root / "run.json", metadata)
        print(f"{args.surface} {args.shard}: no mutant in this shard of the night's files")
        return 0
    write_json(root / "run.json", metadata)
    command += ["--timeout", "300" if args.surface == "beef" else "120", "--build-timeout", "300",
                "--jobs", "1", "--output", str(root)]
    print(shlex.join(command), flush=True)
    result = subprocess.run(command, check=False, env=environment)
    metadata["exit_code"] = result.returncode
    write_json(root / "run.json", metadata)
    return result.returncode


def package(args):
    """Keep replay evidence, without host metadata or arbitrary test output."""
    dest = args.output / args.run.name
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("run.json", "candidates.json"):
        shutil.copyfile(args.run / name, dest / name)
    for name in ("outcomes.json", "mutants.json"):
        source = args.run / "mutants.out" / name
        if source.exists():
            shutil.copyfile(source, dest / name)
    source = args.run / "mutants.out" / "diff"
    if source.exists():
        shutil.copytree(source, dest / "diff", dirs_exist_ok=True)
    return 0


def identity(mutant):
    return mutant["file"], mutant["name"]


def command_signature(command):
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise ValueError("invalid command in run metadata")
    args, result = iter(command), []
    for arg in args:
        if arg in ("--shard", "--output"):
            if next(args, None) is None:
                raise ValueError(f"missing value for {arg} in run metadata")
        else:
            result.append(arg)
    return result


def collect(root, expected_shards, floors, planned=None, floor_files=True):
    errors, rows, seen_runs, seen_mutants, commits = [], {}, set(), set(), set()
    file_surfaces, complete_surfaces = {}, set()
    invalid_surfaces = set()
    commands = {}
    runs = sorted(root.rglob("run.json"))
    for manifest in runs:
        run_error_count = len(errors)
        directory = manifest.parent
        metadata = json.loads(manifest.read_text())
        label = (metadata["surface"], metadata["shard"])
        if label in seen_runs:
            errors.append(f"duplicate run: {label}")
        seen_runs.add(label)
        signature = command_signature(metadata["command"])
        if commands.setdefault(label[0], signature) != signature:
            errors.append(f"{label}: inconsistent mutation or test command across shards")
        commits.add(metadata["commit"])
        for file in metadata["files"]:
            rows.setdefault(file, Counter())
            file_surfaces.setdefault(file, set()).add(metadata["surface"])
        if metadata.get("exit_code") not in (0, 2, 3):
            errors.append(f"{label}: runner failed or unfinished ({metadata.get('exit_code')})")
        candidates = json.loads((directory / "candidates.json").read_text())
        if not candidates and metadata.get("empty") and metadata.get("exit_code") == 0:
            continue  # an incremental shard with nothing to mutate (cut 7)
        if not candidates:
            errors.append(f"{label}: no mutation candidates")
        expected = {identity(m) for m in candidates}
        if len(expected) != len(candidates):
            errors.append(f"{label}: duplicate candidates")
        for mutant in candidates:
            if mutant["file"] not in metadata["files"]:
                errors.append(f"{label}: candidate outside the source file inventory")
            rows.setdefault(mutant["file"], Counter())["generated"] += 1
        outcome_path = directory / "outcomes.json"
        if not outcome_path.exists():
            outcome_path = directory / "mutants.out" / "outcomes.json"
        if not outcome_path.exists():
            errors.append(f"{label}: missing outcomes.json")
            invalid_surfaces.add(label[0])
            continue
        outcome = json.loads(outcome_path.read_text())
        if outcome.get("cargo_mutants_version") != "27.1.0":
            errors.append(f"{label}: unexpected cargo-mutants version")
        if not outcome.get("end_time"):
            errors.append(f"{label}: incomplete run")
        actual, baselines, totals = set(), 0, Counter()
        for entry in outcome["outcomes"]:
            scenario = entry["scenario"]
            if scenario == "Baseline":
                baselines += 1
                if entry["summary"] != "Success":
                    errors.append(f"{label}: baseline failed")
                continue
            mutant = scenario["Mutant"]
            key = identity(mutant)
            if key in seen_mutants:
                errors.append(f"duplicate mutant: {key}")
            seen_mutants.add(key)
            actual.add(key)
            kind = OUTCOMES.get(entry["summary"])
            if kind is None:
                errors.append(f"{label}: unexpected outcome {entry['summary']}")
                continue
            rows.setdefault(mutant["file"], Counter())[kind] += 1
            totals[kind] += 1
        if baselines != 1:
            errors.append(f"{label}: expected one successful baseline, found {baselines}")
        if actual != expected:
            errors.append(f"{label}: candidate/result mismatch ({len(expected)} planned, {len(actual)} tested)")
        if outcome["total_mutants"] != len(actual):
            errors.append(f"{label}: total_mutants mismatch")
        for kind in OUTCOMES.values():
            if outcome[kind] != totals[kind]:
                errors.append(f"{label}: {kind} count mismatch")
        if len(errors) != run_error_count:
            invalid_surfaces.add(label[0])
    for surface in {s for s, _ in seen_runs}:
        shards = {tuple(map(int, shard.split("/"))) for s, shard in seen_runs if s == surface}
        denominators = {n for _, n in shards}
        if (surface not in invalid_surfaces and len(denominators) == 1
                and shards == {(i, n) for n in denominators for i in range(n)}):
            complete_surfaces.add(surface)
        else:
            errors.append(f"{surface}: incomplete or inconsistent shards {sorted(shards)}")
    if expected_shards:
        wanted = {(s, f"{i}/{expected_shards}")
                  for s in SURFACES for i in range(expected_shards)}
        if seen_runs != wanted:
            errors.append(f"missing or unexpected shards: {sorted(wanted ^ seen_runs)}")
    if planned is not None and seen_runs != planned:
        errors.append(f"missing or unexpected shards against the plan: {sorted(planned ^ seen_runs)}")
    if not runs:
        errors.append("no mutation runs found")
    if len(commits) != 1:
        errors.append("results must describe exactly one source commit")
    complete = not errors
    surface_viable = Counter()
    for file, counts in rows.items():
        for surface in file_surfaces.get(file, ()):
            surface_viable[surface] += counts["caught"] + counts["missed"] + counts["timeout"]
    files = []
    for file, counts in sorted(rows.items()):
        scope_complete = file_surfaces.get(file, set()) <= complete_surfaces
        viable = counts["caught"] + counts["missed"] + counts["timeout"]
        override = floors.get(file, {})
        floor = override.get("percent", GATE_FLOOR)
        if type(floor) is not int or not 0 <= floor <= 100:
            raise ValueError(f"invalid floor for {file}")
        if floor < GATE_FLOOR and not override.get("issue", "").startswith(ISSUE_PREFIX):
            raise ValueError(f"lower floor for {file} needs its improvement issue")
        score = 100 * counts["caught"] / viable if viable else None
        passed = viable > 0 and 100 * counts["caught"] >= floor * viable
        if counts["generated"] == 0:
            passed = None
        # Every generated mutant unviable (a replacement the compiler refuses):
        # nothing a test can catch, so no score, unless the file's surface has
        # no viable mutant at all, which reads as a broken build and fails.
        vacuous = (counts["generated"] > 0 and viable == 0 and file not in floors
                   and all(surface_viable[s] > 0 for s in file_surfaces.get(file, ())))
        if vacuous:
            passed = None
        if not scope_complete:
            passed = None
        row = {"file": file, **{k: counts[k] for k in ("generated", *OUTCOMES.values())},
               "viable": viable, "score_percent": score, "floor_percent": floor,
               "issue": override.get("issue"), "passed": passed,
               "scope_complete": scope_complete, "no_viable": vacuous}
        files.append(row)
        if passed is False:
            errors.append(f"{file}: below {floor}% or no viable mutants")
    for file in floors if floor_files else ():
        if (file not in rows or rows[file]["generated"] == 0
                or rows[file]["caught"] + rows[file]["missed"] + rows[file]["timeout"] == 0
                or not file_surfaces.get(file, set()) <= complete_surfaces):
            errors.append(f"floor has no measured file: {file}")
    return {"schema_version": 1, "cargo_mutants_version": "27.1.0",
            "commits": sorted(commits), "complete": complete,
            "files": files, "errors": errors, "passed": not errors}


# Cut 7 (the keeper's speed line, the owner's word of 2026-11-02): a file's score
# moves only when the file, the tests that reach it or the build that runs them
# changes, so the nightly mutates the files the reach rule names since the last
# complete run and carries every other figure with its run's id and sha.
#
# The complete run is twenty shards, one per slot of the account. Minutes per
# mutant, from run 41347058507's shards (the scoped step's minutes over the
# shard's mutants, at 42a74f1b): script 130/515, BEEF 37/187, Merkle 3/25, wire
# 19.5/198, substrates 36.5/286; 901 shard-minutes in all, shared out by the
# largest remainder with one shard at least: about 47, 50, 11, 39 and 49 minutes.
SLOT_LIMIT = 20
COMPLETE_SHARDS = {"script": 11, "beef": 3, "merkle": 1, "wire": 2, "substrates": 3}
MINUTES_PER_MUTANT = {"script": 0.25, "beef": 0.20, "merkle": 0.12, "wire": 0.10,
                      "substrates": 0.13}
NIGHT_SHARD_MINUTES = 45
# The night shares the account with pull requests and the fleet's other nights
# (the balance rule of 2026-10-26): six slots.
NIGHT_PARALLEL = 6
# The fleet's runner cap (the keeper's line of 10:0xZ 2026-11-03, on the opening
# API read of the pool; 14 from 06:2xZ until then): the account's twenty hosted
# runners are one pool across bsv-rs, the CLI, the toolbox and the stack, peaking
# at twenty in 22 of 24 hours with a non-heavy p95 of 14, so a heavy run holds at
# most six; the complete run's twenty shards go in four waves, 6, 6, 6 and 2. It
# rises only when an occupancy read shows the p95 under 10.
# The one place the number lives (GitHub reads no `env` in `strategy`; the
# mutants job reads it from the plan's `max_parallel` output); its owner is loop
# four's #675, which reads the account's occupancy from the API and moves it.
# tests/arch_nightly_cap.rs refuses it above 6.
HEAVY_MAX_PARALLEL = 6
RECORD_ARTIFACT = "mutation-record"
# A change to these reaches every measured file, whatever it touches.
EVERYTHING = {
    "Cargo.toml": "the manifest: a dependency, a feature or a profile reaches every file that uses it",
    "Cargo.lock": "the resolved graph: a dependency bump reaches every file that uses it",
    "build.rs": "the build script runs before every test binary",
    "src/lib.rs": "the crate root: every module, and the unit-test skips are read from it",
    "src/error.rs": "the one Error every module returns and every test compares",
    ".github/workflows/nightly.yml": "the oracle's jobs, toolchain, corpus pin, timeouts and memory ceiling",
    ".github/scripts/nightly_mutants.py": "the selection, the skips and the score",
    ".github/scripts/test-runner-memory-ceiling.sh": "the ceiling decides a runaway mutant's outcome",
}


def is_doc(path):
    return path.startswith("docs/") or path.endswith(".md")


TEST_ONLY_NAME = re.compile(r"(?:^|_)tests\.rs$")


def is_test_only(path, root=Path(".")):
    """A unit-test module: `#![cfg(test)]` before its first item, or named `tests.rs`/`*_tests.rs`.

    cargo-mutants generates no mutant in a `#[cfg(test)]` module (#666 fold, F2):
    such a file is a test of its surface, never a measured file.
    """
    if TEST_ONLY_NAME.search(Path(path).name):
        return True
    source = root / path
    if not source.exists():
        return False
    for line in source.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        return line.replace(" ", "") == "#![cfg(test)]"
    return False


def measured_files(root=Path(".")):
    """Every file a complete run mutates and scores, with its surface; test-only files are not."""
    return {str(p.relative_to(root)): surface for surface, (patterns, _) in SURFACES.items()
            for pattern in patterns for p in sorted(root.glob(pattern))
            if not is_test_only(str(p.relative_to(root)), root)}


def tested_by(path, measured, root=Path(".")):
    """The measured files a test-only source tests (#666 fold, F1 and F2): its directory's
    measured files and the module whose `mod` line (or `#[path]`) declares it."""
    source = Path(path)
    parents = {source.parent / "mod.rs", source.parent.with_suffix(".rs")}
    declared = re.compile(rf"#\[path\s*=\s*\"{re.escape(source.name)}\"\]"
                          rf"|\bmod {re.escape(source.stem)}\s*;")
    for sibling in sorted((root / source.parent).glob("*.rs")) if (root / source.parent).is_dir() else ():
        if declared.search(sibling.read_text(errors="replace")):
            parents.add(sibling.relative_to(root))
    return {f for f in measured if Path(f).parent == source.parent or Path(f) in parents}


def test_rows(root=Path("."), text=None):
    """`tests/CLAUDE.md`'s file table: each test file's stem to the text of its row."""
    rows, inside = {}, False
    if text is None:
        text = (root / "tests" / "CLAUDE.md").read_text()
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line.strip() == "## Files"
        elif inside and line.startswith("| `"):
            cell = line.split("|")[1]
            for name in re.findall(r"`([^`]+)\.rs`", cell):
                rows[Path(name).stem] = line
    return rows


def row_reach(row, measured, root=Path(".")):
    """The measured files a row names (a test-only file by the files it tests),
    else every measured file of a module it names."""
    paths = {f"src/{path}" for path in re.findall(
        r"(?<![\w.-])(?:src/)?((?:[a-z0-9_]+/)+[a-z0-9_]+\.rs)", row)}
    named = paths & set(measured)
    for path in paths - set(measured):
        if is_test_only(path, root):
            named |= tested_by(path, measured, root)
    if named:
        return named
    modules = set(re.findall(r"src/([a-z_]+)/", row)) | set(
        re.findall(r"`(?:crate::|bsv_rs::|bsv::)?([a-z_]+)::", row))
    return {file for file in measured if file.split("/")[1] in modules}


def mutants_exclusions(text):
    """`.cargo/mutants.toml`'s exclude_re entries and every other key, apart."""
    config = tomllib.loads(text) if text else {}
    excluded = set(config.pop("exclude_re", []))
    return excluded, config


def excluded_file(pattern):
    """The file an anchored exclusion names (`^src/script/script\\.rs:257:30: ...`)."""
    match = re.match(r"\^((?:[a-z0-9_]+/)+[a-z0-9_]+)\\\.rs:", pattern)
    return f"{match.group(1)}.rs" if match else None


# The callee rule (#666 fold, hole 3; the keeper's letter, the second fold): a
# changed source under `src/<m>/`, measured or not (never a test-only one),
# reaches, one level deep, every measured file whose text names the module by a
# `crate::<m>` path (a `use crate::<m>::` line, a `crate::<m>::` path, or `<m>::`
# inside a `use crate::{...}` group). A callee two levels down (a change in
# `primitives` that only `transaction` reads, read by a measured file) is not
# followed: the complete run catches it. Off, a changed measured file reaches
# itself and a module's other source its own measured files alone (cut 7's
# rule). The plan counts the files it added per night (`callee_added`).
CALLEE_RULE = True


def callers(module, measured, text):
    """The measured files whose `crate::` paths name `module` (the one-level graph)."""
    direct = re.compile(rf"\bcrate::{re.escape(module)}\b")
    group = re.compile(rf"\bcrate::\{{[^;]*?\b{re.escape(module)}\b", re.DOTALL)
    return {f for f in measured if direct.search(text(f)) or group.search(text(f))}


def reach(changed, root=Path("."), base_mutants="", head_mutants=None, base_rows=None,
          callee=None):
    """The reach rule: each changed path to the measured files it re-measures.

    Returns (everything, reasons, files): `everything` names the path that reaches
    every file, `reasons` maps each changed path to what it reaches and why.
    `callee` switches the callee rule (`CALLEE_RULE` when None).
    """
    if callee is None:
        callee = CALLEE_RULE
    measured = measured_files(root)
    rows = test_rows(root)
    selections = {surface: set(surface_tests(surface, root)) for surface in SURFACES}
    texts = {}

    def text(path):
        path = root / path
        if path not in texts:
            texts[path] = path.read_text(errors="replace")
        return texts[path]

    def declares(source, path):
        """True when `source` compiles the `.rs` file `path` in: a `#[path]` or an
        `include!` string that resolves to it, or the `mod` line of its parent module."""
        target, here = Path(path), Path(source).parent
        for literal in re.findall(r'"([^"\n]+\.rs)"', text(source)):
            if Path(os.path.normpath(here / literal)) == target:
                return True
        stem, home = ((target.parent.name, target.parent.parent) if target.name == "mod.rs"
                      else (target.stem, target.parent))
        parent = Path(source)
        if parent == home / "mod.rs" or parent == home.with_suffix(".rs"):
            return re.search(rf"^\s*(?:pub(?:\([^)]*\))? )?mod {re.escape(stem)}\s*;",
                             text(source), re.MULTILINE) is not None
        return False

    def mentions(source, path):
        """True when `source`'s text names the data file `path` (#666 fold, F3): its name
        whole, or its directory's path when that is two or more deep under `tests/`
        (`fixtures/wire/`, read through a `format!`-built path)."""
        body, target = text(source), Path(path)
        if re.search(rf"(?<![\w.-]){re.escape(target.name)}", body):
            return True
        directory = target.parent.relative_to("tests")
        return len(directory.parts) >= 2 and f"{directory.as_posix()}/" in body

    def namers(path):
        """The compiled sources that name a file under `tests/`: a module by its
        declaration, a data file by its name or its directory."""
        hit = declares if path.endswith(".rs") else mentions
        sources = [*sorted((root / "tests").rglob("*.rs")), *sorted((root / "src").rglob("*.rs"))]
        return [str(p.relative_to(root)) for p in sources
                if str(p.relative_to(root)) != path and hit(str(p.relative_to(root)), path)]

    def reach_test(path):
        stem = Path(path).stem
        if (root / path).exists():
            surfaces, row_table = [s for s, tests in selections.items() if stem in tests], rows
            removed = ""
        else:
            # #666 fold, hole 1: a deleted test is judged by the base's selection
            # and its base row: the mutants it killed are measured again.
            surfaces = [s for s in SURFACES if selects(s, stem)]
            row_table = test_rows(root, base_rows) if base_rows is not None else {}
            removed = "removed; by the base's selection and row: "
        if not surfaces:
            return set(), "a test no surface's selection runs: it never meets a mutant"
        scope = {f for f, s in measured.items() if s in surfaces}
        named = (row_reach(row_table[stem], measured, root) & scope
                 if stem in row_table else set())
        if named:
            return named, (f"{removed}its tests/CLAUDE.md row, within the "
                           f"{'/'.join(surfaces)} selection")
        return scope, (f"{removed}in the {'/'.join(surfaces)} selection; its row names "
                       f"no measured file or module")

    def reach_one(path, seen):
        if path in seen:
            return set(), "already reached"
        seen.add(path)
        if path in EVERYTHING:
            return None, EVERYTHING[path]
        if is_doc(path):
            return set(), "documentation: never compiled"
        if path == ".cargo/mutants.toml":
            base_ex, base_rest = mutants_exclusions(base_mutants)
            head_ex, head_rest = mutants_exclusions(
                (root / path).read_text() if head_mutants is None else head_mutants)
            if base_rest != head_rest:
                return None, "a cargo-mutants setting other than exclude_re: every file's mutants"
            files = {excluded_file(p) for p in base_ex ^ head_ex}
            if None in files:
                return None, "an exclusion that names no file: it may match any mutant"
            return files & set(measured), "the exclusions added or removed name these files"
        if path.startswith(".cargo/"):
            return None, "cargo's configuration: every build"
        if path.startswith("src/"):
            parts = path.split("/")
            if len(parts) == 2:
                return None, "a crate-root source: every module's"
            if path.endswith(".rs") and is_test_only(path, root):
                return (tested_by(path, measured, root),
                        "a test-only module: the files it tests (its directory's and its parent's)")
            if path in measured:
                files, why = {path}, "a measured file"
            else:
                files = {f for f in measured if f.split("/")[1] == parts[1]}
                why = f"a source of src/{parts[1]}/: its module's measured files"
            if callee:
                calling = callers(parts[1], measured, text) - files
                if calling:
                    return files | calling, (
                        f"{why} and, one level, the {len(calling)} whose "
                        f"crate::{parts[1]} paths call it")
            return files, why
        if path in measured:
            return {path}, "a measured file"
        if path.startswith("tests/"):
            if path.count("/") == 1 and path.endswith(".rs"):
                return reach_test(path)
            if not (root / path).exists():
                return set(), "removed: what named it changed with it"
            found, via = set(), namers(path)
            for source in via:
                files, _ = reach_one(source, seen)
                if files is None:
                    return None, f"named by {source}, which reaches every file"
                found |= files
            if not via:
                return set(), "no compiled test or source names it (a recorder, a vector no test reads)"
            return found, "through the sources that name it: " + ", ".join(via)
        return set(), "outside the library and its tests: no selection compiles it"

    reasons, files = {}, set()
    for path in sorted(changed):
        reached, why = reach_one(path, set())
        if reached is None:
            reasons[path] = {"files": "everything", "why": why}
            return path, reasons, set(measured)
        reasons[path] = {"files": sorted(reached), "why": why}
        files |= reached
    return None, reasons, files


def shard_matrix(files_by_surface, mode, base_files=None):
    """The matrix: twenty shards for a complete run, the night's by its estimated minutes."""
    matrix = []
    for surface in SURFACES:
        files = files_by_surface.get(surface, [])
        if not files:
            continue
        if mode == "complete":
            count = COMPLETE_SHARDS[surface]
        else:
            known = [row["generated"] for row in (base_files or {}).values()
                     if row.get("surface") == surface]
            mean = sum(known) / len(known) if known else 20
            mutants = sum((base_files or {}).get(f, {}).get("generated", mean) for f in files)
            minutes = mutants * MINUTES_PER_MUTANT[surface]
            count = min(COMPLETE_SHARDS[surface], max(1, math.ceil(minutes / NIGHT_SHARD_MINUTES)))
        # The label names the shard's artifact, which may not carry a slash.
        matrix += [{"surface": surface, "shard": f"{i}/{count}", "label": f"{surface}-{i}-{count}"}
                   for i in range(count)]
    return matrix


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True)


def plan(args):
    """The night's plan: the files to mutate, their shards, the base it carries from."""
    repo, commit = args.repo, args.commit
    base_record = None
    if args.base_record is not None and (args.base_record / "record.json").exists():
        base_record = json.loads((args.base_record / "record.json").read_text())
    measured = measured_files(repo)
    result = {"schema_version": 1, "commit": commit, "requested_mode": args.mode,
              "base": None, "why_complete": None, "changed": [], "reach": {},
              "measured": measured, "lockfile": "generate",
              "callee_rule": CALLEE_RULE, "callee_added": []}
    why = None
    if args.mode == "complete":
        why = "dispatched complete (a prerelease pin, or by hand)"
    elif base_record is None:
        why = "no record of a complete run on the line to carry from"
    else:
        base = base_record["complete_run"]
        result["base"] = {"run_id": base["run_id"], "commit": base["commit"],
                          "record_run_id": base_record["runs"][-1]["run_id"]}
        held = subprocess.run(["git", "merge-base", "--is-ancestor", base["commit"], commit],
                              cwd=repo, check=False)
        if held.returncode != 0:
            why = f"the complete run's commit {base['commit']} is not an ancestor of {commit}"
        else:
            changed = git(repo, "diff", "--name-only", "--no-renames",
                          f"{base['commit']}..{commit}").split()
            result["changed"] = changed
            try:
                base_mutants = git(repo, "show", f"{base['commit']}:.cargo/mutants.toml")
            except subprocess.CalledProcessError:
                base_mutants = ""
            try:
                base_rows = git(repo, "show", f"{base['commit']}:tests/CLAUDE.md")
            except subprocess.CalledProcessError:
                base_rows = ""
            everything, reasons, files = reach(changed, repo, base_mutants, base_rows=base_rows)
            result["reach"] = reasons
            if everything:
                why = f"{everything} changed: {reasons[everything]['why']}"
            elif CALLEE_RULE:
                # The keeper's count (#666 second fold): the files the callee rule
                # reached that no other rule did.
                without = reach(changed, repo, base_mutants, base_rows=base_rows, callee=False)[2]
                result["callee_added"] = sorted(files - without)
    if why:
        result.update(mode="complete", why_complete=why, callee_added=[])
        files = set(measured)
    else:
        result.update(mode="incremental", lockfile="carry")
    by_surface = {}
    for file in sorted(files):
        by_surface.setdefault(measured[file], []).append(file)
    result["files"] = by_surface
    result["matrix"] = shard_matrix(by_surface, result["mode"],
                                    base_record["files"] if base_record else None)
    result["shards"] = len(result["matrix"])
    result["max_parallel"] = HEAVY_MAX_PARALLEL if result["mode"] == "complete" else NIGHT_PARALLEL
    result["carried"] = sorted(set(measured) - files)
    write_json(args.output, result)
    print(json.dumps({k: result[k] for k in ("mode", "why_complete", "base", "files", "matrix",
                                              "shards", "max_parallel")}, indent=2))
    print(f"{sum(map(len, by_surface.values()))} files measured tonight, "
          f"{len(result['carried'])} carried")
    print(callee_line(result))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"mode={result['mode']}\n")
            output.write(f"shards={result['shards']}\n")
            output.write(f"max_parallel={result['max_parallel']}\n")
            output.write(f"lockfile={result['lockfile']}\n")
            output.write(f"matrix={json.dumps(result['matrix'], separators=(',', ':'))}\n")
    return 0


def callee_line(the_plan):
    """The scoreboard's line: how many files the callee rule added tonight, and which."""
    added = the_plan.get("callee_added", [])
    mode = ("complete: every file measured" if the_plan["mode"] == "complete"
            else the_plan["mode"])
    count = f"added {len(added)} file{'' if len(added) == 1 else 's'} tonight ({mode})"
    names = (": " + ", ".join(f"`{file}`" for file in added)) if added else ""
    if not the_plan.get("callee_rule", True):
        return f"The callee rule is off (`CALLEE_RULE`): it {count}{names}."
    return f"The callee rule {count}{names}."


def judge(counts, floor):
    viable = counts["caught"] + counts["missed"] + counts["timeout"]
    return viable > 0 and 100 * counts["caught"] >= floor * viable


def floor_of(file, floors):
    return floors.get(file, {}).get("percent", GATE_FLOOR), floors.get(file, {}).get("issue")


def merge(night, the_plan, base_record, floors, run_id):
    """The night's rows over the record it carries from: (rows, findings, errors, record)."""
    commit = the_plan["commit"]
    measured = the_plan["measured"]
    rows, findings, errors = [], [], []
    tonight = {row["file"]: row for row in night["files"]}
    base_files = (base_record or {}).get("files", {}) if the_plan["mode"] == "incremental" else {}
    record_files = {}
    for file in sorted(set(measured) | set(tonight)):
        if file not in measured and tonight[file]["generated"] == 0:
            continue  # a test-only module a complete run's glob lists: no row, no figure
        if file in tonight:
            row = dict(tonight[file], provenance="night", run_id=run_id, commit=commit)
        elif file in base_files:
            carried = base_files[file]
            floor, issue = floor_of(file, floors)
            counts = {k: carried[k] for k in ("generated", *OUTCOMES.values(), "viable")}
            passed = judge(counts, floor) if counts["viable"] else None
            if carried.get("no_viable") or counts["generated"] == 0:
                passed = None
            row = {"file": file, **counts, "score_percent": carried["score_percent"],
                   "floor_percent": floor, "issue": issue, "passed": passed,
                   "scope_complete": True, "no_viable": carried.get("no_viable", False),
                   "provenance": "carried", "run_id": carried["run_id"],
                   "commit": carried["commit"]}
            if passed is False:
                findings.append(f"{file}: carried {carried['score_percent']:.2f}% below its "
                                f"{floor}% floor, measured by run {carried['run_id']} at "
                                f"{carried['commit']} (a finding, not a failure of the night)")
        else:
            errors.append(f"{file}: measured, but neither tonight's nor the record's")
            continue
        rows.append(row)
        record_files[file] = {
            "surface": measured.get(file), **{k: row[k] for k in (
                "generated", *OUTCOMES.values(), "viable", "score_percent", "no_viable",
                "provenance", "run_id", "commit")}}
    by_file = {row["file"]: row for row in rows}
    for file in floors:
        row = by_file.get(file)
        if row is None or row["generated"] == 0 or row["viable"] == 0:
            errors.append(f"floor has no measured file: {file}")
    run = {"run_id": run_id, "commit": commit, "mode": the_plan["mode"],
           "files": len(tonight), "callee_added": len(the_plan.get("callee_added", []))}
    if the_plan["mode"] == "complete":
        complete_run, runs = {"run_id": run_id, "commit": commit}, [run]
    else:
        complete_run = base_record["complete_run"]
        runs = base_record["runs"] + [run]
    record = {"schema_version": 1, "complete_run": complete_run, "runs": runs,
              "commit": commit, "files": record_files}
    return rows, findings, errors, record


def provenance(row):
    if row.get("provenance") == "carried":
        return f"carried: run {row['run_id']} at `{row['commit'][:8]}`"
    return "night" if row.get("provenance") else ""


def newest_record(listing, line, commit, fetch, is_ancestor):
    """The newest unexpired record of the line whose run measured an ancestor of `commit`."""
    candidates = sorted((a for a in listing if a["name"] == RECORD_ARTIFACT and not a["expired"]
                         and a.get("workflow_run", {}).get("head_branch") == line),
                        key=lambda a: a["created_at"], reverse=True)
    for artifact in candidates:
        files = fetch(artifact)
        record = json.loads(files["record.json"])
        if is_ancestor(record["commit"], commit) and is_ancestor(
                record["complete_run"]["commit"], commit):
            return artifact, files
    return None, None


def latest_record(args):
    """Download the newest record the night can carry from (the artifact store, no commit)."""
    repository = os.environ.get("GITHUB_REPOSITORY", "Calhooon/bsv-rs")
    listing = []
    for page in range(1, 11):
        answer = json.loads(subprocess.check_output(["gh", "api", (
            f"repos/{repository}/actions/artifacts?name={RECORD_ARTIFACT}"
            f"&per_page=100&page={page}")]))
        listing += answer["artifacts"]
        if len(answer["artifacts"]) < 100:
            break

    def fetch(artifact):
        archive = zipfile.ZipFile(io.BytesIO(subprocess.check_output(
            ["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"])))
        return {name: archive.read(name) for name in archive.namelist()}

    def is_ancestor(old, new):
        return subprocess.run(["git", "merge-base", "--is-ancestor", old, new],
                              cwd=args.repo, check=False).returncode == 0

    artifact, files = newest_record(listing, args.line, args.commit, fetch, is_ancestor)
    args.dest.mkdir(parents=True, exist_ok=True)
    if artifact is None:
        print(f"no {RECORD_ARTIFACT} of {args.line} carries to {args.commit}: the night runs complete")
        return 0
    for name, body in files.items():
        (args.dest / name).write_bytes(body)
    print(f"carrying from run {artifact['workflow_run']['id']}'s record (artifact {artifact['id']})")
    return 0


def lockfile_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def report(args):
    commit = getattr(args, "commit", None)
    plan_path = getattr(args, "plan", None)
    the_plan = json.loads(Path(plan_path).read_text()) if plan_path else None
    record = findings = None
    try:
        floors = load_floors(args.floors)
        if the_plan is None:
            result = collect(args.input, args.expected_shards, floors)
        else:
            # Cut 7: the night's shards against the plan's, then the carried figures.
            expected = {(entry["surface"], entry["shard"]) for entry in the_plan["matrix"]}
            if expected:
                result = collect(args.input, None, floors, planned=expected, floor_files=False)
            else:
                result = {"schema_version": 1, "cargo_mutants_version": "27.1.0",
                          "commits": [the_plan["commit"]], "complete": True,
                          "files": [], "errors": [], "passed": True}
            base = None
            if the_plan["mode"] == "incremental":
                base = json.loads((args.base_record / "record.json").read_text())
            run_id = getattr(args, "run_id", None) or os.environ.get("GITHUB_RUN_ID", "local")
            rows, findings, errors, record = merge(result, the_plan, base, floors, run_id)
            result["errors"] += errors
            result.update(files=rows, findings=findings, mode=the_plan["mode"],
                          complete_run=record["complete_run"],
                          passed=not result["errors"])
        if commit is not None and result["commits"] != [commit]:
            result["errors"].append(f"results describe {result['commits']}, "
                                    f"not the pinned commit {commit} (#629)")
            result["complete"] = result["passed"] = False
    except (OSError, KeyError, ValueError, TypeError) as error:
        result = {"schema_version": 1, "complete": False, "passed": False,
                  "files": [], "errors": [f"invalid mutation evidence: {error}"]}
        record = None
    write_json(args.output, result)
    # The record is the night's whole evidence, a floor's failure included; an
    # incomplete night (a missing shard, a failed baseline) writes none.
    record_output = getattr(args, "record_output", None)
    if record_output is not None and record is not None and result["complete"]:
        lockfile = getattr(args, "lockfile", None)
        if lockfile is not None:
            record["lockfile_sha256"] = lockfile_digest(lockfile)
            shutil.copyfile(lockfile, Path(record_output).parent / "Cargo.lock")
        if the_plan["mode"] == "complete":
            record["complete_run"]["lockfile_sha256"] = record.get("lockfile_sha256")
        write_json(Path(record_output), record)
    carried_from = result.get("complete_run")
    lines = ["## Mutation scores (#81)", "",
             "Score = caught / (caught + missed + timeout); unviable mutants are excluded.",
             f"Floors: {GATE_FLOOR}% on the gate paths; elsewhere `mutation_floors` "
             f"in `{args.floors}` (#602).", "",
             *([f"Source commit: `{commit}` (the dispatch's, #629).", ""] if commit else []),
             *([f"Mode: {result['mode']}; the carried figures are the record's, the complete "
                f"run {carried_from['run_id']} at `{carried_from['commit']}` and the nights since "
                f"(cut 7).", ""] if carried_from and result.get("mode") == "incremental" else []),
             *([callee_line(the_plan), ""] if the_plan else []),
             "| File | Caught | Missed | Timeout | Unviable | Score | Floor | Result | Figure |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |"]
    for row in result["files"]:
        score = "n/a" if row["score_percent"] is None else f"{row['score_percent']:.2f}%"
        floor = f"{row['floor_percent']}%"
        if row["issue"]:
            floor = f"[{floor}]({row['issue']})"
        status = "PASS" if row["passed"] else "FAIL"
        if row["passed"] is None:
            status = "NO MUTANTS" if row["scope_complete"] else "PARTIAL"
            if row["scope_complete"] and row.get("no_viable"):
                status = "NO VIABLE MUTANTS"
        lines.append(f"| `{row['file']}` | {row['caught']} | {row['missed']} | "
                     f"{row['timeout']} | {row['unviable']} | {score} | {floor} | "
                     f"{status} | {provenance(row)} |")
    lines += ["", *(f"- {error}" for error in result["errors"])]
    if findings:
        lines += ["", "Carried below their floors (findings with their runs, not failures "
                  "of the night):", "", *(f"- {finding}" for finding in findings)]
    markdown = "\n".join(lines) + "\n"
    args.output.with_suffix(".md").write_text(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(markdown)
    print(markdown, end="")
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    runner = subs.add_parser("run")
    runner.add_argument("--surface", choices=SURFACES, required=True)
    runner.add_argument("--shard", default="0/1")
    runner.add_argument("--file", action="append", default=[])
    runner.add_argument("--output", type=Path, required=True)
    runner.add_argument("--commit", help="the pin job's commit; the checkout must be at it (#629)")
    runner.add_argument("--plan", type=Path, help="the night's plan: its files for the surface (cut 7)")
    runner.set_defaults(func=run)
    packer = subs.add_parser("package")
    packer.add_argument("--run", type=Path, required=True)
    packer.add_argument("--output", type=Path, required=True)
    packer.set_defaults(func=package)
    reporter = subs.add_parser("report")
    reporter.add_argument("--input", type=Path, required=True)
    reporter.add_argument("--output", type=Path, required=True)
    reporter.add_argument("--expected-shards", type=int)
    reporter.add_argument("--floors", type=Path, default=FLOORS_RECORD,
                          help="the record whose mutation_floors member holds the floors (#602)")
    reporter.add_argument("--commit", help="the pin job's commit, which every shard must name (#629)")
    reporter.add_argument("--plan", type=Path, help="the night's plan: its shards and measured files")
    reporter.add_argument("--base-record", type=Path,
                          help="the directory of the record the night carries from")
    reporter.add_argument("--record-output", type=Path, help="where the merged record is written")
    reporter.add_argument("--lockfile", type=Path, help="the Cargo.lock every shard built")
    reporter.add_argument("--run-id", help="this run's id (default: GITHUB_RUN_ID)")
    reporter.set_defaults(func=report)
    planner = subs.add_parser("plan", help="the files the reach rule re-measures tonight (cut 7)")
    planner.add_argument("--commit", required=True, help="the pinned commit")
    planner.add_argument("--mode", choices=("incremental", "complete"), default="incremental")
    planner.add_argument("--base-record", type=Path,
                         help="the directory of the record to carry from (absent: complete)")
    planner.add_argument("--repo", type=Path, default=Path("."))
    planner.add_argument("--output", type=Path, required=True)
    planner.set_defaults(func=plan)
    finder = subs.add_parser("latest-record", help="download the record the night carries from")
    finder.add_argument("--line", required=True)
    finder.add_argument("--commit", required=True)
    finder.add_argument("--repo", type=Path, default=Path("."))
    finder.add_argument("--dest", type=Path, required=True)
    finder.set_defaults(func=latest_record)
    pinner = subs.add_parser("pin", help="pin the run to the dispatch's commit (#629)")
    pinner.add_argument("--commit", required=True, help="the dispatch's commit, a full sha")
    pinner.add_argument("--line", required=True, help="the line the commit must be on")
    pinner.add_argument("--repo", type=Path, default=Path("."))
    pinner.set_defaults(func=pin)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
