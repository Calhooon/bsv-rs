#!/usr/bin/env python3
"""Run the five mutation surfaces and check complete per-file results (#81)."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


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
    skip = [f"{name}::" for name in modules("src/lib.rs") if name != root]
    if surface in ("wire", "substrates", "merkle"):
        keep = {"wire": "wire", "substrates": "substrates", "merkle": "merkle_path"}[surface]
        skip += [f"{root}::{name}::" for name in modules(f"src/{root}/mod.rs") if name != keep]
    if surface == "beef":
        skip += ["transaction::merkle_path::", "the_whole_path_walks_a_wide_bump_in_linear_time"]
    if surface == "merkle":
        # The three randomized equivalence runs are exercised by the full CI
        # library gate, not repeated for every mutation in the nightly loop.
        skip.append("transaction::merkle_path::linear_root_equivalence_tests::")
    return sorted(set(skip))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def mutation_args(surface, shard, files=()):
    patterns, tests = SURFACES[surface]
    if surface == "script":
        tests = tests + sorted(p.stem for p in Path("tests").glob("script_*.rs"))
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


def run(args):
    root = args.output.resolve()
    # Never let an interrupted retry inherit an older run's successful evidence.
    root.mkdir(parents=True, exist_ok=False)
    command = mutation_args(args.surface, args.shard, args.file)
    environment = dict(os.environ, CARGO_INCREMENTAL="1")
    print(shlex.join(command), flush=True)
    # A separate manifest exists even if the baseline or a worker fails.
    with (root / "candidates.json").open("w") as dest:
        subprocess.run(command + ["--list", "--json"], stdout=dest, check=True, env=environment)
    metadata = {
        "surface": args.surface, "shard": args.shard,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "command": command,
        "cargo_incremental": "1",
        "rustc_version": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "build_environment": {key: environment.get(key) for key in (
            "CARGO_BUILD_JOBS", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
            "CARGO_TARGET_DIR", "CARGO_INCREMENTAL",
        )},
        "files": sorted({str(p) for pattern in args.file or SURFACES[args.surface][0]
                         for p in Path().glob(pattern)}),
    }
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


def collect(root, expected_shards, floors):
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
    if not runs:
        errors.append("no mutation runs found")
    if len(commits) != 1:
        errors.append("results must describe exactly one source commit")
    complete = not errors
    files = []
    for file, counts in sorted(rows.items()):
        scope_complete = file_surfaces.get(file, set()) <= complete_surfaces
        viable = counts["caught"] + counts["missed"] + counts["timeout"]
        override = floors.get(file, {})
        floor = override.get("percent", 80)
        if type(floor) is not int or not 0 <= floor <= 100:
            raise ValueError(f"invalid floor for {file}")
        if floor < 80 and not override.get("issue", "").startswith("https://github.com/Calhooon/bsv-rs/issues/"):
            raise ValueError(f"lower floor for {file} needs its improvement issue")
        score = 100 * counts["caught"] / viable if viable else None
        passed = viable > 0 and 100 * counts["caught"] >= floor * viable
        if counts["generated"] == 0:
            passed = None
        if not scope_complete:
            passed = None
        row = {"file": file, **{k: counts[k] for k in ("generated", *OUTCOMES.values())},
               "viable": viable, "score_percent": score, "floor_percent": floor,
               "issue": override.get("issue"), "passed": passed,
               "scope_complete": scope_complete}
        files.append(row)
        if passed is False:
            errors.append(f"{file}: below {floor}% or no viable mutants")
    for file in floors:
        if (file not in rows or rows[file]["generated"] == 0
                or not file_surfaces.get(file, set()) <= complete_surfaces):
            errors.append(f"floor has no measured file: {file}")
    return {"schema_version": 1, "cargo_mutants_version": "27.1.0",
            "commits": sorted(commits), "complete": complete,
            "files": files, "errors": errors, "passed": not errors}


def report(args):
    try:
        floors = json.loads(os.environ.get("MUTATION_FLOORS", "{}"))
        result = collect(args.input, args.expected_shards, floors)
    except (OSError, KeyError, ValueError, TypeError) as error:
        result = {"schema_version": 1, "complete": False, "passed": False,
                  "files": [], "errors": [f"invalid mutation evidence: {error}"]}
    write_json(args.output, result)
    lines = ["## Mutation scores (#81)", "",
             "Score = caught / (caught + missed + timeout); unviable mutants are excluded.", "",
             "| File | Caught | Missed | Timeout | Unviable | Score | Floor | Result |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for row in result["files"]:
        score = "n/a" if row["score_percent"] is None else f"{row['score_percent']:.2f}%"
        floor = f"{row['floor_percent']}%"
        if row["issue"]:
            floor = f"[{floor}]({row['issue']})"
        status = "PASS" if row["passed"] else "FAIL"
        if row["passed"] is None:
            status = "NO MUTANTS" if row["scope_complete"] else "PARTIAL"
        lines.append(f"| `{row['file']}` | {row['caught']} | {row['missed']} | "
                     f"{row['timeout']} | {row['unviable']} | {score} | {floor} | "
                     f"{status} |")
    lines += ["", *(f"- {error}" for error in result["errors"])]
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
    runner.set_defaults(func=run)
    packer = subs.add_parser("package")
    packer.add_argument("--run", type=Path, required=True)
    packer.add_argument("--output", type=Path, required=True)
    packer.set_defaults(func=package)
    reporter = subs.add_parser("report")
    reporter.add_argument("--input", type=Path, required=True)
    reporter.add_argument("--output", type=Path, required=True)
    reporter.add_argument("--expected-shards", type=int)
    reporter.set_defaults(func=report)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
