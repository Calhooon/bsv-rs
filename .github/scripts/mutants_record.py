#!/usr/bin/env python3
"""The mutation oracle's record in the tree (#602), written from a run's artifacts.

    fetch   download a nightly run's `mutation-summary` and `mutants-*` artifacts
            and write the run's provenance beside them (`meta.json`);
    floors  derive the ratchet's `mutation_floors` member from a complete run:
            every file outside the gate paths whose score is below 80 gets the
            score rounded down; an existing floor is never lowered or removed;
    write   the census record (`.json` and `.md`) of two runs, the narrow figure
            (the oracle without the conformance corpus) and the widened one.

Every number is read from the artifacts through `nightly_mutants.collect`, the
score job's own reader, and checked against the run's `mutation-summary.json`.
"""

import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True  # no __pycache__ beside the scripts in the tree
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nightly_mutants as nightly  # noqa: E402


REPOSITORY = "Calhooon/bsv-rs"
FLOOR_ISSUE = nightly.ISSUE_PREFIX + "602"
COUNTS = ("generated", "caught", "missed", "timeout", "unviable", "viable")


def gh(path):
    return subprocess.check_output(["gh", "api", path])


def fetch(args):
    dest = args.dest
    dest.mkdir(parents=True, exist_ok=False)
    run = json.loads(gh(f"repos/{REPOSITORY}/actions/runs/{args.run}"))
    listing = json.loads(gh(f"repos/{REPOSITORY}/actions/runs/{args.run}/artifacts?per_page=100"))
    artifacts = {}
    for artifact in listing["artifacts"]:
        name = artifact["name"]
        if name != "mutation-summary" and not name.startswith("mutants-"):
            continue
        if artifact["expired"]:
            raise SystemExit(f"artifact {name} of run {args.run} has expired")
        archive = zipfile.ZipFile(io.BytesIO(gh(
            f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip")))
        archive.extractall(dest / ("summary" if name == "mutation-summary" else f"shards/{name}"))
        artifacts[name] = artifact["id"]
    nightly.write_json(dest / "meta.json", {
        "run_id": args.run, "commit": run["head_sha"], "branch": run["head_branch"],
        "dispatched": run["created_at"], "artifacts": dict(sorted(artifacts.items())),
    })
    print(f"run {args.run}: {len(artifacts)} artifacts into {dest}")
    return 0


def measure(run_dir, floors=None):
    """The run's per-file rows, checked against its own scoreboard."""
    result = nightly.collect(run_dir / "shards", 4, floors or {})
    summary = json.loads((run_dir / "summary" / "mutation-summary.json").read_text())
    if not result["complete"]:
        raise SystemExit(f"{run_dir}: incomplete evidence: {result['errors'][:3]}")
    if summary["commits"] != result["commits"]:
        raise SystemExit(f"{run_dir}: the shards and the summary name other commits")
    theirs = {row["file"]: row for row in summary["files"]}
    for row in result["files"]:
        if [row[k] for k in COUNTS] != [theirs[row["file"]][k] for k in COUNTS]:
            raise SystemExit(f"{run_dir}: {row['file']} differs from the run's scoreboard")
    if set(theirs) != {row["file"] for row in result["files"]}:
        raise SystemExit(f"{run_dir}: the shards and the summary list other files")
    result["scoreboard"] = {
        "PASS": sum(r["passed"] is True for r in summary["files"]),
        "FAIL": sum(r["passed"] is False for r in summary["files"]),
        "NO MUTANTS": sum(r["passed"] is None for r in summary["files"]),
        "files": len(summary["files"]),
    }
    return result


def derived_floors(result, recorded):
    """Below 80 outside the gate paths: the score rounded down; never lower than recorded."""
    floors = {path: dict(entry) for path, entry in recorded.items()}
    for row in result["files"]:
        file, viable = row["file"], row["viable"]
        if nightly.is_gate_path(file) or viable == 0:
            continue
        measured = 100 * row["caught"] // viable
        if file in floors:
            floors[file]["percent"] = max(floors[file]["percent"], measured)
        elif 100 * row["caught"] < nightly.GATE_FLOOR * viable:
            floors[file] = {"percent": measured, "issue": FLOOR_ISSUE}
    return dict(sorted(floors.items()))


def floors(args):
    record = json.loads(args.record.read_text())
    result = measure(args.run)
    derived = derived_floors(result, record.get("mutation_floors", {}))
    if args.write:
        record.pop("mutation_floors", None)
        if derived:
            record["mutation_floors"] = derived
        # serde_json's pretty form, so `tools/ratchet/run --record` rewrites it byte for byte.
        args.record.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(derived, indent=2))
    return 0


def survivors(run_dir):
    """Every missed or timed-out mutant of the run, by name."""
    found = {}
    for path in sorted((run_dir / "shards").rglob("outcomes.json")):
        for entry in json.loads(path.read_text())["outcomes"]:
            if entry["scenario"] == "Baseline":
                continue
            kind = nightly.OUTCOMES[entry["summary"]]
            mutant = entry["scenario"]["Mutant"]
            function = mutant.get("function") or {}
            found[mutant["name"]] = {
                "file": mutant["file"], "line": mutant["span"]["start"]["line"],
                "column": mutant["span"]["start"]["column"],
                "function": function.get("function_name"), "genre": mutant["genre"],
                "replacement": mutant["replacement"], "outcome": kind, "name": mutant["name"],
            }
    return found


def score_text(score):
    return "n/a" if score is None else f"{score:.2f}%"


def status(row):
    if row["passed"] is None:
        if not row["scope_complete"]:
            return "PARTIAL"
        return "NO VIABLE MUTANTS" if row.get("no_viable") else "NO MUTANTS"
    return "PASS" if row["passed"] else "FAIL"


def provenance(run_dir, label):
    meta = json.loads((run_dir / "meta.json").read_text())
    shard = json.loads(next((run_dir / "shards").rglob("run.json")).read_text())
    outcome = json.loads(next((run_dir / "shards").rglob("outcomes.json")).read_text())
    workflow = subprocess.check_output(
        ["git", "show", f"{meta['commit']}:.github/workflows/nightly.yml"], text=True)
    corpus = re.search(r"repository: bsv-blockchain/ts-stack\s+ref: ([0-9a-f]{40})", workflow)
    ceiling = re.search(r"MUTANTS_TEST_VMEM_KB=(\d+)", workflow)
    timeouts = {}
    for path in (run_dir / "shards").rglob("run.json"):
        data = json.loads(path.read_text())
        command = data["command"]
        timeouts[data["surface"]] = int(command[command.index("--timeout") + 1])
    jobs = shard["command"][shard["command"].index("--jobs") + 1]
    return {
        "label": label, "run_id": meta["run_id"], "commit": meta["commit"],
        "branch": meta["branch"], "dispatched": meta["dispatched"],
        "corpus": corpus.group(1) if corpus else None,
        "cargo_mutants_version": outcome["cargo_mutants_version"],
        "rustc_version": shard["rustc_version"], "jobs": int(jobs),
        "timeout_seconds": dict(sorted(timeouts.items())),
        "vmem_ceiling_kb": int(ceiling.group(1)) if ceiling else None,
        "artifacts": meta["artifacts"],
    }


def file_order(rows):
    """#603's order: the gate-path files below the floor first, the script surface
    by score ascending, then the readers; then the gate-path files at or above it."""
    def key(row):
        below = 100 * row["caught"] < nightly.GATE_FLOOR * row["viable"]
        return (not below, not row["file"].startswith("src/script/"),
                row["score_percent"], row["file"])
    return sorted(rows, key=key)


def counts(row):
    return {k: row[k] for k in COUNTS} | {"score_percent": row["score_percent"]}


def write(args):
    record = json.loads(args.record.read_text())
    floors_member = record.get("mutation_floors", {})
    narrow = measure(args.narrow)
    widened = measure(args.widened, floors_member)
    runs = {"narrow": provenance(args.narrow, "the oracle without the conformance corpus"),
            "widened": provenance(args.widened, "the oracle with the conformance corpus")}
    before = {row["file"]: row for row in narrow["files"]}
    files = []
    for row in widened["files"]:
        old = before[row["file"]]
        delta = (None if row["score_percent"] is None or old["score_percent"] is None
                 else round(row["score_percent"] - old["score_percent"], 2))
        files.append({"file": row["file"], "gate_path": nightly.is_gate_path(row["file"]),
                      "narrow": counts(old), "widened": counts(row), "delta_points": delta,
                      "floor_percent": row["floor_percent"], "issue": row["issue"],
                      "result": status(row)})
    killed_before, killed_after = survivors(args.narrow), survivors(args.widened)
    narrow_left = {n: m for n, m in killed_before.items()
                   if m["outcome"] in ("missed", "timeout") and nightly.is_gate_path(m["file"])}
    widened_left = {n: m for n, m in killed_after.items()
                    if m["outcome"] in ("missed", "timeout") and nightly.is_gate_path(m["file"])}
    groups = []
    gate_rows = [r for r in widened["files"] if nightly.is_gate_path(r["file"]) and r["viable"]]
    for row in file_order(gate_rows):
        mutants = sorted((m for m in widened_left.values() if m["file"] == row["file"]),
                         key=lambda m: (m["line"], m["column"], m["name"]))
        if len(mutants) != row["missed"] + row["timeout"]:
            raise SystemExit(f"{row['file']}: survivors differ from the scoreboard")
        if not mutants:
            continue
        for mutant in mutants:
            mutant["new"] = mutant["name"] not in narrow_left
            if mutant["new"]:
                mutant["narrow_outcome"] = killed_before.get(mutant["name"], {}).get("outcome")
        groups.append({"file": row["file"], "score_percent": row["score_percent"],
                       "below_floor": 100 * row["caught"] < nightly.GATE_FLOOR * row["viable"],
                       "missed": row["missed"], "timeout": row["timeout"], "mutants": mutants})
    corpus_killed = []
    for name, mutant in sorted(narrow_left.items(), key=lambda i: (
            i[1]["file"], i[1]["line"], i[1]["column"], i[0])):
        if name not in widened_left:
            corpus_killed.append(mutant | {
                "widened_outcome": killed_after.get(name, {}).get("outcome")})
    def tally(result):
        return {"files": len(result["files"]),
                **{k: sum(1 for r in result["files"] if status(r) == k)
                   for k in ("PASS", "FAIL", "NO MUTANTS", "NO VIABLE MUTANTS")}}
    totals = {
        "narrow_scoreboard": narrow["scoreboard"],
        "widened_scoreboard": widened["scoreboard"],
        "widened_under_the_record": tally(widened),
        "gate_files_below_80": sum(g["below_floor"] for g in groups),
        "gate_survivors": sum(len(g["mutants"]) for g in groups),
        "gate_survivors_below_80": sum(len(g["mutants"]) for g in groups if g["below_floor"]),
        "narrow_gate_survivors": len(narrow_left),
        "corpus_killed": len(corpus_killed),
        "new_in_widened": sum(m["new"] for g in groups for m in g["mutants"]),
    }
    document = {"schema": 1, "issue": 602, "gate_floor_percent": nightly.GATE_FLOOR,
                "floors_record": str(args.record), "runs": runs, "totals": totals,
                "files": files, "gate_survivors": groups, "corpus_killed": corpus_killed}
    nightly.write_json(args.out.with_suffix(".json"), document)
    args.out.with_suffix(".md").write_text(markdown(document))
    print(json.dumps(totals, indent=2))
    return 0


def markdown(doc):
    runs, totals = doc["runs"], doc["totals"]
    narrow, before = totals["narrow_scoreboard"], totals["widened_scoreboard"]
    widened = totals["widened_under_the_record"]
    lines = [
        f"# The mutation oracle's record of {doc['runs']['widened']['dispatched'][:10]} (#602)",
        "",
        "Written by `.github/scripts/mutants_record.py write` from the two runs' artifacts "
        "(`mutation-summary` and the twenty `mutants-<surface>-<k>`), every count read through "
        "`nightly_mutants.collect` and checked against the run's own scoreboard; the `.json` "
        "beside this file is the same record. The floors: "
        f"{doc['gate_floor_percent']} percent on the gate paths (`src/script/**`, "
        "`src/transaction/beef*.rs`, `src/transaction/merkle_path.rs`), elsewhere the ratchet's "
        f"record (`{doc['floors_record']}`, member `mutation_floors`), the widened score rounded "
        "down and never lowered (the owner's word of 2026-11-01 14:1xZ; #81, #574, #602, #603).",
        "",
        "The next record is written the same way, under the lane's folder for the artifacts:",
        "",
        "```sh",
        "python3 .github/scripts/mutants_record.py fetch --run <narrow or older run> --dest <dir>/narrow",
        "python3 .github/scripts/mutants_record.py fetch --run <new run> --dest <dir>/widened",
        "python3 .github/scripts/mutants_record.py floors --run <dir>/widened --write  # raises only",
        "python3 .github/scripts/mutants_record.py write --narrow <dir>/narrow --widened <dir>/widened \\",
        "  --out docs/census/mutants-<date>",
        "```",
        "",
        "## The producing runs",
        "",
        "| Figure | Run | Commit | Dispatched | Corpus | cargo-mutants | rustc | Jobs | Timeout (s) | Test ceiling |",
        "| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for key in ("narrow", "widened"):
        run = runs[key]
        timeouts = ", ".join(f"{s} {t}" for s, t in run["timeout_seconds"].items())
        corpus = f"ts-stack `{run['corpus'][:7]}`" if run["corpus"] else "none (suites skip)"
        lines.append(
            f"| {key}: {run['label']} | [{run['run_id']}](https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}) "
            f"| `{run['commit'][:8]}` | {run['dispatched']} | {corpus} | {run['cargo_mutants_version']} "
            f"| {run['rustc_version'].split(' (')[0]} | {run['jobs']} | {timeouts} "
            f"| {run['vmem_ceiling_kb']:,} KB |")
    lines += ["", "Artifact ids:", ""]
    for key in ("narrow", "widened"):
        ids = ", ".join(f"`{n}` {i}" for n, i in runs[key]["artifacts"].items())
        lines.append(f"- {key} ({runs[key]['run_id']}): {ids}")
    lines += [
        "",
        "## The counts",
        "",
        f"- Narrow, the run's scoreboard (every file at 80): {narrow['PASS']} PASS, "
        f"{narrow['FAIL']} FAIL, {narrow['NO MUTANTS']} NO MUTANTS of {narrow['files']} files.",
        f"- Widened, the run's scoreboard (every file at 80): {before['PASS']} PASS, "
        f"{before['FAIL']} FAIL, {before['NO MUTANTS']} NO MUTANTS of {before['files']} files.",
        f"- Widened, under the record's floors: {widened['PASS']} PASS, {widened['FAIL']} FAIL, "
        f"{widened['NO MUTANTS']} NO MUTANTS, {widened['NO VIABLE MUTANTS']} NO VIABLE MUTANTS "
        f"of {widened['files']} files.",
        f"- The gate paths under the widened oracle: {totals['gate_files_below_80']} files below 80, "
        f"{totals['gate_survivors']} survivors ({totals['gate_survivors_below_80']} on the files "
        f"below 80); the narrow run had {totals['narrow_gate_survivors']}; "
        f"{totals['corpus_killed']} killed by the corpus, {totals['new_in_widened']} new in the widened run.",
        "",
        "## Every measured file",
        "",
        "Score = caught / (caught + missed + timeout). Delta in percentage points, widened "
        "minus narrow. Result: the widened run under the record's floors.",
        "",
        "| File | Narrow C/M/T/U | Narrow viable | Narrow score | Widened C/M/T/U | Widened viable "
        "| Widened score | Delta | Floor | Result |",
        "| --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in doc["files"]:
        n, w = row["narrow"], row["widened"]
        delta = "" if row["delta_points"] is None else f"{row['delta_points']:+.2f}"
        floor = f"{row['floor_percent']}%" + ("" if row["gate_path"] else
                                              " (record)" if row["issue"] else "")
        lines.append(
            f"| `{row['file']}` | {n['caught']}/{n['missed']}/{n['timeout']}/{n['unviable']} "
            f"| {n['viable']} | {score_text(n['score_percent'])} "
            f"| {w['caught']}/{w['missed']}/{w['timeout']}/{w['unviable']} | {w['viable']} "
            f"| {score_text(w['score_percent'])} | {delta} | {floor} | {row['result']} |")
    lines += [
        "",
        "## The gate paths' survivors under the widened oracle",
        "",
        "By file in #603's order: the files below 80 first (the script surface by score "
        "ascending, then the readers), then the files at or above it. Each line: "
        "`file:line:column` function: genre replacement; *timeout* marks a mutant that timed "
        "out, **new** one that was not a survivor in the narrow run (its narrow outcome named).",
        "",
    ]
    for group in doc["gate_survivors"]:
        mark = "below 80" if group["below_floor"] else "at or above 80"
        lines += [f"### `{group['file']}`: {score_text(group['score_percent'])}, {mark}; "
                  f"{group['missed']} missed, {group['timeout']} timed out", ""]
        for m in group["mutants"]:
            extra = " *timeout*" if m["outcome"] == "timeout" else ""
            if m["new"]:
                extra += f" **new** (narrow: {m['narrow_outcome']})"
            lines.append(f"- `{m['file']}:{m['line']}:{m['column']}` {m['function']}: "
                         f"{m['genre']} `{m['replacement']}`{extra}")
        lines.append("")
    lines += [
        "## Killed by the corpus",
        "",
        "Survivors of the narrow run that the widened run did not leave (its outcome named).",
        "",
    ]
    for m in doc["corpus_killed"]:
        lines.append(f"- `{m['file']}:{m['line']}:{m['column']}` {m['function']}: "
                     f"{m['genre']} `{m['replacement']}` (narrow {m['outcome']}, "
                     f"widened {m['widened_outcome']})")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subs = parser.add_subparsers(dest="operation", required=True)
    fetcher = subs.add_parser("fetch")
    fetcher.add_argument("--run", type=int, required=True)
    fetcher.add_argument("--dest", type=Path, required=True)
    fetcher.set_defaults(func=fetch)
    floor = subs.add_parser("floors")
    floor.add_argument("--run", type=Path, required=True, help="a fetched widened run")
    floor.add_argument("--record", type=Path, default=nightly.FLOORS_RECORD)
    floor.add_argument("--write", action="store_true")
    floor.set_defaults(func=floors)
    writer = subs.add_parser("write")
    writer.add_argument("--narrow", type=Path, required=True)
    writer.add_argument("--widened", type=Path, required=True)
    writer.add_argument("--record", type=Path, default=nightly.FLOORS_RECORD)
    writer.add_argument("--out", type=Path, required=True,
                        help="the record's path without its suffix")
    writer.set_defaults(func=write)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
