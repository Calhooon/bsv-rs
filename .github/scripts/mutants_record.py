#!/usr/bin/env python3
"""The mutation oracle's record in the tree (#602), written from a run's artifacts.

    fetch   download a nightly run's `mutation-summary` and `mutants-*` artifacts
            (since cut 7 also `mutation-record` and `mutation-plan`) and write the
            run's provenance (`meta.json`) and its jobs' listing (`jobs.json`) beside them;
    floors  derive the ratchet's `mutation_floors` member from a complete run:
            every file outside the gate paths whose score is below 80 gets the
            score rounded down; an existing floor is never lowered or removed;
    write   the census record (`.json` and `.md`) of two runs, the narrow figure
            (the oracle without the conformance corpus) and the widened one; or,
            with `--previous` in place of `--narrow`, of one complete run against
            the previous record (the shards' minutes and the survivor term, #705).

Every number is read from the artifacts through `nightly_mutants.collect`, the
score job's own reader, and checked against the run's `mutation-summary.json`.
"""

import argparse
from datetime import datetime
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
# The artifacts read beside the shards: the score job's table, and since cut 7 the
# merged record and the plan (a run before cut 7 has neither; absent, nothing read).
EXTRA_ARTIFACTS = {"mutation-summary": "summary", "mutation-record": "record",
                   "mutation-plan": "plan"}


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
        if name not in EXTRA_ARTIFACTS and not name.startswith("mutants-"):
            continue
        if artifact["expired"]:
            raise SystemExit(f"artifact {name} of run {args.run} has expired")
        archive = zipfile.ZipFile(io.BytesIO(gh(
            f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip")))
        archive.extractall(dest / EXTRA_ARTIFACTS.get(name, f"shards/{name}"))
        artifacts[name] = artifact["id"]
    # Each job's start and end, the shard table's wall minutes (a one-run record).
    listing = json.loads(gh(f"repos/{REPOSITORY}/actions/runs/{args.run}/jobs?per_page=100"))
    nightly.write_json(dest / "jobs.json", [
        {k: job[k] for k in ("name", "status", "conclusion", "started_at", "completed_at")}
        for job in listing["jobs"]])
    nightly.write_json(dest / "meta.json", {
        "run_id": args.run, "commit": run["head_sha"], "branch": run["head_branch"],
        "dispatched": run["created_at"], "status_at_fetch": run["status"],
        "artifacts": dict(sorted(artifacts.items())),
    })
    print(f"run {args.run}: {len(artifacts)} artifacts into {dest}")
    return 0


def the_plan(run_dir):
    """Cut 7's `mutation-plan`; a run before it has none (four shards a surface)."""
    path = run_dir / "plan" / "plan.json"
    return json.loads(path.read_text()) if path.exists() else None


def measure(run_dir, floors=None, floor_files=True):
    """The run's per-file rows, checked against its own scoreboard."""
    plan = the_plan(run_dir)
    if plan is None:
        result = nightly.collect(run_dir / "shards", 4, floors or {}, floor_files=floor_files)
    else:
        planned = {(m["surface"], m["shard"]) for m in plan["matrix"]}
        result = nightly.collect(run_dir / "shards", None, floors or {}, planned=planned,
                                 floor_files=floor_files)
        # The score job's rows (`merge`): a test-only file in a shard's inventory, which
        # generates nothing, is no measured file.
        result["files"] = [row for row in result["files"]
                           if row["file"] in plan["measured"] or row["generated"]]
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
        "NO MUTANTS": sum(r["passed"] is None and not r.get("unjudged")
                          for r in summary["files"]),
        **({"UNJUDGED": sum(r["passed"] is None and bool(r.get("unjudged"))
                            for r in summary["files"])}
           if result.get("timeout_rule") == "rerun" else {}),
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
    """Every mutant of the run by name, its outcome the lone re-run's where it timed out
    under #781's method (then its passes' figures beside it)."""
    found = {}
    for manifest in sorted((run_dir / "shards").rglob("run.json")):
        data = json.loads(manifest.read_text())
        path = manifest.parent / "outcomes.json"
        if not path.exists():
            continue
        reruns = {r["mutant"]: r for r in data.get("reruns", [])}
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
            rerun = reruns.get(mutant["name"]) if kind == "timeout" else None
            if rerun is not None:
                named = rerun["rerun"].get("named") or {}
                found[mutant["name"]] |= {
                    "outcome": rerun["rerun"]["outcome"], "pass_outcome": "timeout",
                    "shard": f"{data['surface']} {data['shard']}",
                    "pass_seconds": rerun["pass"]["seconds"],
                    "rerun_seconds": rerun["rerun"]["seconds"],
                    "pass_limit": rerun["pass"].get("test_timeout"),
                    "rerun_limit": rerun["rerun"].get("test_timeout"),
                    "binary": named.get("binary"), "tests": named.get("tests", [])}
    return found


def survived(rule):
    """The outcomes a record lists as survivors: since #781's method the missed alone."""
    return ("missed",) if rule == "rerun" else ("missed", "timeout")


def survivor_count(row, rule):
    return row["missed"] + (0 if rule == "rerun" else row["timeout"])


def previous_survivors(previous, before, gate=False):
    """The previous record's survivors under its own rule (#781): a record before the
    method (no `timeout_rule`) counted its timeouts as survivors, a marked one does not."""
    rule = previous.get("timeout_rule", "counted")
    return sum(survivor_count(r, rule) for f, r in before.items()
               if not gate or nightly.is_gate_path(f))


def statuses(rule):
    """The tally's statuses; UNJUDGED (#781) under the lone re-run alone, so a record
    before the method re-derives byte for byte."""
    plain = ("PASS", "FAIL", "NO MUTANTS", "NO VIABLE MUTANTS")
    return (*plain, "UNJUDGED") if rule == "rerun" else plain


def unjudged_text(tally):
    return f", {tally['UNJUDGED']} UNJUDGED" if "UNJUDGED" in tally else ""


def score_text(score):
    return "n/a" if score is None else f"{score:.2f}%"


def status(row):
    if row["passed"] is None:
        if not row["scope_complete"]:
            return "PARTIAL"
        if row.get("unjudged"):
            return "UNJUDGED"  # #781: every judged mutant timed out twice, unenforced
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
        # A run before #685 names its fixed `--timeout`; one since, its floor (the
        # timeout is then the shard's baseline test time times the multiplier, at least it).
        flag = "--timeout" if "--timeout" in command else "--minimum-test-timeout"
        timeouts[data["surface"]] = int(command[command.index(flag) + 1])
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
    if args.narrow is None:
        return write_complete(args)
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
                   if m["outcome"] in survived(narrow["timeout_rule"])
                   and nightly.is_gate_path(m["file"])}
    widened_left = {n: m for n, m in killed_after.items()
                    if m["outcome"] in survived(widened["timeout_rule"])
                    and nightly.is_gate_path(m["file"])}
    groups = []
    gate_rows = [r for r in widened["files"] if nightly.is_gate_path(r["file"]) and r["viable"]]
    for row in file_order(gate_rows):
        mutants = sorted((m for m in widened_left.values() if m["file"] == row["file"]),
                         key=lambda m: (m["line"], m["column"], m["name"]))
        if len(mutants) != survivor_count(row, widened["timeout_rule"]):
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
                   for k in statuses(result.get("timeout_rule"))}}
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
        f"{widened['NO MUTANTS']} NO MUTANTS, {widened['NO VIABLE MUTANTS']} NO VIABLE MUTANTS"
        f"{unjudged_text(widened)} of {widened['files']} files.",
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


def instant(text):
    """An RFC 3339 time, the API's (`...:56Z`) or cargo-mutants' (nanoseconds)."""
    text = re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")
    return datetime.fromisoformat(text)


def minutes(start, end):
    return (instant(end) - instant(start)).total_seconds() / 60


def shard_rows(run_dir):
    """Each shard's counts, its job's wall, cargo-mutants' own minutes and the minutes its
    mutants took by outcome (the sum of each mutant's build and test phases)."""
    jobs = {job["name"]: job for job in json.loads((run_dir / "jobs.json").read_text())}
    rows = []
    for manifest in sorted((run_dir / "shards").rglob("run.json")):
        data = json.loads(manifest.read_text())
        outcome = json.loads((manifest.parent / "outcomes.json").read_text())
        job = jobs[f"Mutants ({data['surface']}, {data['shard']})"]
        rule = "rerun" if data.get("timeout_rerun") == nightly.TIMEOUT_RERUN else "counted"
        spent = {"baseline": 0.0, "caught": 0.0, "survived": 0.0, "unviable": 0.0}
        counted = {c: outcome[c] for c in ("total_mutants", "caught", "missed", "timeout",
                                           "unviable")}
        rerun_minutes = 0.0
        if rule == "rerun":
            # #781: every timed-out pass's minutes under their own heading, the shard's
            # and the re-run's; a re-run's caught or missed minutes under its outcome.
            spent |= {"timed_out": 0.0, "rerun_baseline": 0.0}
            for rerun in data.get("reruns", []):
                again = json.loads((manifest.parent / "rerun" / str(rerun["index"])
                                    / "outcomes.json").read_text())
                rerun_minutes += minutes(again["start_time"], again["end_time"])
                for entry in again["outcomes"]:
                    took = sum(phase["duration"] for phase in entry["phase_results"]) / 60
                    if entry["scenario"] == "Baseline":
                        spent["rerun_baseline"] += took
                        continue
                    kind = nightly.OUTCOMES[entry["summary"]]
                    spent["timed_out" if kind == "timeout" else
                          "survived" if kind == "missed" else kind] += took
                    if kind != "timeout":
                        counted["timeout"] -= 1
                        counted[kind] += 1
        for entry in outcome["outcomes"]:
            took = sum(phase["duration"] for phase in entry["phase_results"]) / 60
            if entry["scenario"] == "Baseline":
                spent["baseline"] += took
                continue
            kind = nightly.OUTCOMES[entry["summary"]]
            if rule == "rerun" and kind == "timeout":
                spent["timed_out"] += took
                continue
            spent["survived" if kind in ("missed", "timeout") else kind] += took
        k, n = map(int, data["shard"].split("/"))
        rows.append({
            "surface": data["surface"], "shard": data["shard"], "index": k, "of": n,
            "files": len(data["files"]),
            "targets": sum(a.startswith("--cargo-arg=--test=") for a in data["command"]),
            **counted,
            "job_started": job["started_at"], "job_completed": job["completed_at"],
            "job_minutes": round(minutes(job["started_at"], job["completed_at"]), 1),
            "mutants_minutes": round(minutes(outcome["start_time"], outcome["end_time"]), 1),
            "minutes_by_outcome": {key: round(v, 1) for key, v in spent.items()},
            **({"reruns": len(data.get("reruns", [])),
                "rerun_minutes": round(rerun_minutes, 1)} if rule == "rerun" else {}),
        })
    return sorted(rows, key=lambda r: (list(nightly.SURFACES).index(r["surface"]), r["index"]))


def survivor_term(shards, whole=False):
    """#705's figures per surface: the survivors and the kills, their measured minutes and
    their minutes by the shard's rate (cargo-mutants' minutes over its mutants)."""
    term = {}
    for row in shards:
        # #781: under the lone re-run a twice-timed-out mutant is no survivor; its count
        # and minutes (both passes, the re-runs' baselines) stand under their own heading.
        rule = "rerun" if "timed_out" in row["minutes_by_outcome"] else "counted"
        entry = term.setdefault("all" if whole else row["surface"], {
            "shards": 0, "mutants": 0, "caught": 0, "survived": 0, "unviable": 0,
            "job_minutes": 0.0, "mutants_minutes": 0.0, "measured_minutes": dict.fromkeys(
                ("baseline", "caught", "survived", "unviable"), 0.0),
            "rate_minutes": {"caught": 0.0, "survived": 0.0, "unviable": 0.0}})
        if rule == "rerun" and "timed_out" not in entry:
            entry |= {"timed_out": 0, "rerun_minutes": 0.0}
            entry["measured_minutes"] |= {"timed_out": 0.0, "rerun_baseline": 0.0}
            entry["rate_minutes"]["timed_out"] = 0.0
        rate = row["mutants_minutes"] / row["total_mutants"]
        survived = survivor_count(row, rule)
        if rule == "rerun":
            entry["timed_out"] += row["timeout"]
            entry["rerun_minutes"] += row["rerun_minutes"]
            entry["rate_minutes"]["timed_out"] += row["timeout"] * rate
        entry["shards"] += 1
        entry["mutants"] += row["total_mutants"]
        entry["caught"] += row["caught"]
        entry["survived"] += survived
        entry["unviable"] += row["unviable"]
        entry["job_minutes"] += row["job_minutes"]
        entry["mutants_minutes"] += row["mutants_minutes"]
        for key, value in row["minutes_by_outcome"].items():
            entry["measured_minutes"][key] += value
        for key, count in (("caught", row["caught"]), ("survived", survived),
                           ("unviable", row["unviable"])):
            entry["rate_minutes"][key] += count * rate
    for entry in term.values():
        for key in ("job_minutes", "mutants_minutes", "rerun_minutes"):
            if key in entry:
                entry[key] = round(entry[key], 1)
        for group in ("measured_minutes", "rate_minutes"):
            entry[group] = {k: round(v, 1) for k, v in entry[group].items()}
        measured = entry["measured_minutes"]
        entry["minutes_per_mutant"] = round(entry["mutants_minutes"] / entry["mutants"], 3)
        entry["minutes_per_survivor"] = (round(measured["survived"] / entry["survived"], 2)
                                         if entry["survived"] else None)
        entry["minutes_per_kill"] = (round(measured["caught"] / entry["caught"], 2)
                                     if entry["caught"] else None)
        if "timed_out" in entry:
            entry["minutes_per_timeout"] = (round(measured["timed_out"] / entry["timed_out"], 2)
                                            if entry["timed_out"] else None)
        entry["survivor_share_of_viable"] = round(
            entry["survived"] / (entry["caught"] + entry["survived"]), 4)
        spent = sum(measured.values())
        entry["survivor_share_of_minutes"] = round(measured["survived"] / spent, 4) if spent else None
    return term


def write_complete(args):
    """One complete run's record, its deltas against the previous record's figure."""
    record = json.loads(args.record.read_text())
    floors_member = record.get("mutation_floors", {})
    result = measure(args.widened, floors_member)
    at_eighty = measure(args.widened, {}, floor_files=False)
    previous = json.loads(args.previous.read_text())
    figure = "widened" if "widened" in previous["runs"] else "complete"
    before = {row["file"]: row[figure] for row in previous["files"]}
    run = provenance(args.widened, "the complete run, the oracle with the conformance corpus")
    meta = json.loads((args.widened / "meta.json").read_text())
    shards = shard_rows(args.widened)
    run["status_at_fetch"] = meta.get("status_at_fetch")
    run["shards_ended"] = max(row["job_completed"] for row in shards)
    run["score_job_ended"] = next(
        (job["completed_at"] for job in json.loads((args.widened / "jobs.json").read_text())
         if job["name"] == "Mutation score floor"), None)
    run["previous_record"] = str(args.previous)
    # The checkpoint's reading, which no artifact carries (the captain's text, given by hand).
    if args.checkpoint:
        run["checkpoint"] = args.checkpoint
    found = survivors(args.widened)
    rule = result["timeout_rule"]
    files, groups = [], []
    for row in result["files"]:
        old = before.get(row["file"])
        delta = (None if old is None or row["score_percent"] is None
                 or old["score_percent"] is None
                 else round(row["score_percent"] - old["score_percent"], 2))
        files.append({"file": row["file"], "gate_path": nightly.is_gate_path(row["file"]),
                      "complete": counts(row),
                      "previous": None if old is None else {k: old[k] for k in (
                          *COUNTS, "score_percent")},
                      "delta_points": delta, "floor_percent": row["floor_percent"],
                      "issue": row["issue"], "result": status(row)})
    gate = [r for r in result["files"] if nightly.is_gate_path(r["file"]) and r["viable"]]
    rest = sorted((r for r in result["files"] if not nightly.is_gate_path(r["file"])
                   and r["viable"]), key=lambda r: (r["score_percent"], r["file"]))
    for row in file_order(gate) + rest:
        mutants = sorted((m for m in found.values() if m["file"] == row["file"]
                          and m["outcome"] in survived(rule)),
                         key=lambda m: (m["line"], m["column"], m["name"]))
        if len(mutants) != survivor_count(row, rule):
            raise SystemExit(f"{row['file']}: survivors differ from the scoreboard")
        if mutants:
            groups.append({"file": row["file"], "gate_path": nightly.is_gate_path(row["file"]),
                           "score_percent": row["score_percent"],
                           "floor_percent": row["floor_percent"],
                           "missed": row["missed"],
                           **({} if rule == "rerun" else {"timeout": row["timeout"]}),
                           "mutants": mutants})
    # #781: a mutant that timed out in its pass and again alone, each its own row.
    timeouts = sorted((m for m in found.values() if m["outcome"] == "timeout"),
                      key=lambda m: (m["file"], m["line"], m["column"], m["name"]))
    if rule == "rerun" and len(timeouts) != sum(r["timeout"] for r in result["files"]):
        raise SystemExit("the timeout rows differ from the scoreboard")
    def tally(rows):
        return {"files": len(rows),
                **{k: sum(1 for r in rows if status(r) == k) for k in statuses(rule)}}
    # A previous row that generated nothing and is no measured file now is a test-only
    # file the plan leaves out (cut 7), not a file gone.
    absent = set(before) - {row["file"] for row in result["files"]}
    gone = sorted(f for f in absent if before[f]["generated"])
    totals = {
        "run_scoreboard": result["scoreboard"],
        "under_the_record": tally(result["files"]),
        "at_80_everywhere": tally(at_eighty["files"]),
        "survivors": sum(len(g["mutants"]) for g in groups),
        "gate_survivors": sum(len(g["mutants"]) for g in groups if g["gate_path"]),
        "previous_survivors": previous_survivors(previous, before),
        "previous_gate_survivors": previous_survivors(previous, before, gate=True),
        "files_new_since_previous": sum(f["previous"] is None for f in files),
        "files_gone_since_previous": gone,
        "previous_rows_test_only": len(absent) - len(gone),
        "shards": len(shards),
        "shard_minutes": round(sum(r["job_minutes"] for r in shards), 1),
        "mutants": sum(r["total_mutants"] for r in shards),
        "survivor_term": survivor_term(shards, whole=True)["all"],
        **({"timeouts": len(timeouts),
            "previous_timeout_rule": previous.get("timeout_rule", "counted")}
           if rule == "rerun" else {}),
    }
    document = {"schema": 2, "kind": "complete", "issue": 602,
                "gate_floor_percent": nightly.GATE_FLOOR, "floors_record": str(args.record),
                "runs": {"complete": run}, "totals": totals, "files": files,
                "survivors": groups, "shards": shards,
                "survivor_term": survivor_term(shards)}
    if rule == "rerun":
        document |= {"timeout_rule": "rerun", "timeouts": timeouts}
    nightly.write_json(args.out.with_suffix(".json"), document)
    args.out.with_suffix(".md").write_text(markdown_complete(document))
    print(json.dumps(totals, indent=2))
    return 0


def hours(value):
    return f"{int(value // 60)}h{int(round(value % 60)):02d}m"


def markdown_complete(doc):
    run, totals = doc["runs"]["complete"], doc["totals"]
    rerun_rule = doc.get("timeout_rule") == "rerun"
    board, record, eighty = (totals["run_scoreboard"], totals["under_the_record"],
                             totals["at_80_everywhere"])
    wall = minutes(run["dispatched"], run["score_job_ended"])
    lines = [
        f"# The mutation oracle's record of {run['dispatched'][:10]}: the complete run (#602, #705)",
        "",
        "Written by `.github/scripts/mutants_record.py write --widened <run> --previous "
        f"{run['previous_record']}` from one complete run's artifacts (`mutation-summary`, "
        f"the {totals['shards']} `mutants-<surface>-<k>-<n>`, the jobs' listing), every count read "
        "through `nightly_mutants.collect` and checked against the run's own scoreboard; the "
        "`.json` beside this file is the same record. The floors: "
        f"{doc['gate_floor_percent']} percent on the gate paths (`src/script/**`, "
        "`src/transaction/beef*.rs`, `src/transaction/merkle_path.rs`), elsewhere the ratchet's "
        f"record (`{doc['floors_record']}`, member `mutation_floors`), the measured score rounded "
        "down and never lowered (the owner's word of 2026-11-01 14:1xZ; #81, #574, #602, #603). "
        "The delta is against the previous record's figure (its widened run).",
        "",
        "The next complete run's record is written the same way:",
        "",
        "```sh",
        "python3 .github/scripts/mutants_record.py fetch --run <complete run> --dest <dir>/complete",
        "python3 .github/scripts/mutants_record.py floors --run <dir>/complete --write  # raises only",
        "python3 .github/scripts/mutants_record.py write --widened <dir>/complete \\",
        "  --previous docs/census/mutants-<previous date>.json --out docs/census/mutants-<date>",
        "```",
        "",
        "## The producing run",
        "",
        "| Run | Commit | Dispatched | Shards ended | Corpus | cargo-mutants | rustc | Jobs | Minimum test timeout (s) | Test ceiling |",
        "| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |",
    ]
    timeouts = ", ".join(f"{s} {t}" for s, t in run["timeout_seconds"].items())
    corpus = f"ts-stack `{run['corpus'][:7]}`" if run["corpus"] else "none (suites skip)"
    lines += [
        f"| [{run['run_id']}](https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}) "
        f"| `{run['commit'][:8]}` | {run['dispatched']} | {run['shards_ended']} | {corpus} "
        f"| {run['cargo_mutants_version']} | {run['rustc_version'].split(' (')[0]} | {run['jobs']} "
        f"| {timeouts} | {run['vmem_ceiling_kb']:,} KB |",
        "",
        f"The mutation part's wall clock, dispatch to the score job's end: {hours(wall)} "
        f"({totals['shards']} shards at six at a time, {totals['shard_minutes']:,} shard-minutes "
        f"of job time over {totals['mutants']:,} mutants). The run's status when its artifacts "
        f"were read: `{run['status_at_fetch']}` (the fuzz jobs and the full-matrix dispatches run "
        "after the score job and are not this record's).",
        "",
    ]
    if run.get("checkpoint"):
        lines += [f"The checkpoint: {run['checkpoint']}", ""]
    lines += [
        "Artifact ids:",
        "",
        "- " + ", ".join(f"`{n}` {i}" for n, i in run["artifacts"].items()),
        "",
        "## The counts",
        "",
        f"- The run's scoreboard (the floors at `{run['commit'][:8]}`): {board['PASS']} PASS, "
        f"{board['FAIL']} FAIL, {board['NO MUTANTS']} NO MUTANTS{unjudged_text(board)} "
        f"of {board['files']} files.",
        f"- Under this record's floors: {record['PASS']} PASS, {record['FAIL']} FAIL, "
        f"{record['NO MUTANTS']} NO MUTANTS, {record['NO VIABLE MUTANTS']} NO VIABLE MUTANTS"
        f"{unjudged_text(record)} of {record['files']} files.",
        f"- At 80 everywhere (no floor below it): {eighty['PASS']} PASS, {eighty['FAIL']} FAIL, "
        f"{eighty['NO MUTANTS']} NO MUTANTS, {eighty['NO VIABLE MUTANTS']} NO VIABLE MUTANTS"
        f"{unjudged_text(eighty)}.",
        (f"- Survivors (missed; #781's timeout rows apart, {totals.get('timeouts')} below): "
         if rerun_rule else "- Survivors (missed or timed out): ")
        + f"{totals['survivors']}, {totals['gate_survivors']} "
        f"on the gate paths; the previous record's widened run had "
        f"{totals['previous_survivors']:,} and {totals['previous_gate_survivors']:,}"
        + ((" under its own rule, its timeouts counted as survivors (a record before #781)"
            if totals.get("previous_timeout_rule") == "counted" else " under the same rule")
           if rerun_rule else "") + ". "
        f"{totals['files_new_since_previous']} files are new since that record"
        + (f"; gone: {', '.join(f'`{f}`' for f in totals['files_gone_since_previous'])}"
           if totals["files_gone_since_previous"] else "; none is gone")
        + f" ({totals['previous_rows_test_only']} of that record's NO MUTANTS rows are "
        "test-only files, which the plan has not listed since cut 7).",
        "",
        "## Every measured file",
        "",
        ("Score = caught / (caught + missed): a mutant that timed out in its shard's pass "
         "and again in its lone re-run (#781) is a timeout row, outside the denominator, "
         "neither a survivor nor a kill; T counts those rows. " if rerun_rule else
         "Score = caught / (caught + missed + timeout). ")
        + "Delta in percentage points, this run "
        "minus the previous record's widened run (blank: a file new since, or no score). "
        "Result: this run under this record's floors"
        + ("; UNJUDGED a file whose every judged mutant timed out twice where no number "
           "is enforced, its mutants in the timeout rows (one held to a floor, the gate's "
           "80 or the default 80 FAIL, its floor unread); "
           "NO VIABLE MUTANTS a file whose every mutant the compiler refused."
           if rerun_rule else "."),
        "",
        "| File | C/M/T/U | Viable | Score | Previous C/M/T/U | Previous score | Delta | Floor | Result |",
        "| --- | --- | ---: | ---: | --- | ---: | ---: | ---: | --- |",
    ]
    for row in doc["files"]:
        c, p = row["complete"], row["previous"]
        delta = "" if row["delta_points"] is None else f"{row['delta_points']:+.2f}"
        floor = f"{row['floor_percent']}%" + ("" if row["gate_path"] else
                                              " (record)" if row["issue"] else "")
        prev = ("new", "") if p is None else (
            f"{p['caught']}/{p['missed']}/{p['timeout']}/{p['unviable']}",
            score_text(p["score_percent"]))
        lines.append(
            f"| `{row['file']}` | {c['caught']}/{c['missed']}/{c['timeout']}/{c['unviable']} "
            f"| {c['viable']} | {score_text(c['score_percent'])} | {prev[0]} | {prev[1]} "
            f"| {delta} | {floor} | {row['result']} |")
    lines += [
        "",
        "## The shards",
        "",
        "Job minutes: the job's start to its end (setup, the corpus, the baseline and the "
        "mutants). Mutants minutes: cargo-mutants' own start to end. Rate: the mutants "
        "minutes over the shard's mutants. Survivors and kills: the sum of each mutant's build "
        "and test phases by its outcome.",
        "",
        "| Shard | Files | Targets | Mutants | C/M/T/U | Started | Ended | Job min | Mutants min "
        "| Rate (min/mutant) | Baseline min | Kills min | Survivors min | Unviable min |",
        "| --- | ---: | ---: | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in doc["shards"]:
        spent = row["minutes_by_outcome"]
        lines.append(
            f"| {row['surface']} {row['shard']} | {row['files']} | {row['targets']} "
            f"| {row['total_mutants']} | {row['caught']}/{row['missed']}/{row['timeout']}/"
            f"{row['unviable']} | {row['job_started'][11:19]}Z | {row['job_completed'][11:19]}Z "
            f"| {row['job_minutes']} | {row['mutants_minutes']} "
            f"| {row['mutants_minutes'] / row['total_mutants']:.3f} | {spent['baseline']} "
            f"| {spent['caught']} | {spent['survived']} | {spent['unviable']} |")
    lines += [
        "",
        "## The survivor term (#705)",
        "",
        ("Per surface: the survivors (missed alone, #781) and the kills, the minutes their "
         if rerun_rule else
         "Per surface: the survivors (missed and timed out) and the kills, the minutes their ")
        + "mutants took as measured (each mutant's phases) and by the rate (count times its "
        "shard's minutes a mutant), and the survivors' share of the viable mutants and of the "
        "measured minutes"
        + (": under #781 that share's denominator also holds the timed-out passes and the "
           "re-runs' baselines, which a record before #781 has not (its timeouts were "
           "survivors), so the two shares are not one measure." if rerun_rule else "."),
        "",
        "| Surface | Shards | Mutants | Kills | Survivors | Unviable | Job min | Rate (min/mutant) "
        "| Kills min (measured / rate) | Survivors min (measured / rate) | Min a kill | Min a survivor "
        "| Survivor share (viable / minutes) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    # The surfaces in the plan's order, so the `.md` is rewritten from the sorted `.json`.
    for surface, t in sorted(doc["survivor_term"].items(),
                             key=lambda item: list(nightly.SURFACES).index(item[0])):
        m, r = t["measured_minutes"], t["rate_minutes"]
        lines.append(
            f"| {surface} | {t['shards']} | {t['mutants']:,} | {t['caught']:,} | {t['survived']:,} "
            f"| {t['unviable']} | {t['job_minutes']:,} | {t['minutes_per_mutant']} "
            f"| {m['caught']:,} / {r['caught']:,} | {m['survived']:,} / {r['survived']:,} "
            f"| {t['minutes_per_kill']} | {t['minutes_per_survivor']} "
            f"| {100 * t['survivor_share_of_viable']:.1f}% / "
            f"{100 * t['survivor_share_of_minutes']:.1f}% |")
    whole = doc["totals"]["survivor_term"]
    timed_out_lines = []
    if rerun_rule:
        timed_out_lines = [
            "",
            "The timeout rows (#781), under their own heading and in no column above: per "
            "surface, the mutants that timed out twice, the minutes every timed-out pass took "
            "(the shard's and the lone re-run's) and the re-runs' baselines.",
            "",
            "| Surface | Timed out twice | Timed-out passes min | Re-run baselines min "
            "| Re-runs min (cargo-mutants) |",
            "| --- | ---: | ---: | ---: | ---: |",
            *(f"| {s} | {t['timed_out']} | {t['measured_minutes']['timed_out']:,} "
              f"| {t['measured_minutes']['rerun_baseline']:,} | {t['rerun_minutes']:,} |"
              for s, t in sorted(doc["survivor_term"].items(),
                                 key=lambda item: list(nightly.SURFACES).index(item[0]))),
            f"| all | {whole['timed_out']} | {whole['measured_minutes']['timed_out']:,} "
            f"| {whole['measured_minutes']['rerun_baseline']:,} | {whole['rerun_minutes']:,} |",
        ]
    lines += [
        f"| all | {whole['shards']} | {whole['mutants']:,} | {whole['caught']:,} "
        f"| {whole['survived']:,} | {whole['unviable']:,} | {whole['job_minutes']:,} "
        f"| {whole['minutes_per_mutant']} | {whole['measured_minutes']['caught']:,} / "
        f"{whole['rate_minutes']['caught']:,} | {whole['measured_minutes']['survived']:,} / "
        f"{whole['rate_minutes']['survived']:,} | {whole['minutes_per_kill']} "
        f"| {whole['minutes_per_survivor']} | {100 * whole['survivor_share_of_viable']:.1f}% / "
        f"{100 * whole['survivor_share_of_minutes']:.1f}% |",
        "",
        f"Measured, the survivors took {whole['measured_minutes']['survived']:,} of the "
        f"{sum(whole['measured_minutes'].values()):,.1f} minutes the mutants and baselines took "
        f"({100 * whole['survivor_share_of_minutes']:.1f}%), the kills "
        f"{whole['measured_minutes']['caught']:,}: a survivor costs "
        f"{whole['minutes_per_survivor'] / whole['minutes_per_kill']:.1f} times a kill, and the "
        "kills, being most of the viable mutants, carry most of the run.",
        *timed_out_lines,
        "",
        "## The survivors per file",
        "",
        "The gate paths in #603's order (the files below 80 first, the script surface by score "
        "ascending, then the readers; then the files at or above it), then the files elsewhere "
        "by score ascending. Each line: `file:line:column` function: genre replacement"
        + ("; the mutants that timed out twice are the timeout rows below, no survivor."
           if rerun_rule else "; *timeout* marks a mutant that timed out."),
        "",
    ]
    for group in doc["survivors"]:
        where = "gate path" if group["gate_path"] else f"floor {group['floor_percent']}%"
        tally = (f"{group['missed']} missed" if rerun_rule else
                 f"{group['missed']} missed, {group['timeout']} timed out")
        lines += [f"### `{group['file']}`: {score_text(group['score_percent'])}, {where}; "
                  f"{tally}", ""]
        for m in group["mutants"]:
            extra = " *timeout*" if m["outcome"] == "timeout" else ""
            if m.get("pass_outcome") == "timeout":
                extra = " *timed out in its pass, missed alone*"
            lines.append(f"- `{m['file']}:{m['line']}:{m['column']}` {m['function']}: "
                         f"{m['genre']} `{m['replacement']}`{extra}")
        lines.append("")
    if rerun_rule:
        lines += [
            "## The timeout rows (#781)",
            "",
            "Each mutant that timed out in its shard's pass and again when re-run once alone "
            "(its exact name by `--re`, its line by `--in-diff`, the baseline re-timed, the "
            "shard's timeouts, `--jobs 1`): outside the score's denominator, neither a "
            "survivor nor a kill, an environment artefact or a hang read from the test its "
            "log names (the log kept in the shard's artifact).",
            "",
        ]
        if not doc["timeouts"]:
            lines += ["None: every mutant that timed out in its pass was caught or missed "
                      "when re-run alone.", ""]
        else:
            lines += ["| Mutant | Shard | Pass (s, limit) | Re-run (s, limit) | Test named |",
                      "| --- | --- | ---: | ---: | --- |"]
            for m in doc["timeouts"]:
                named = ", ".join(f"`{test}`" for test in m["tests"]) or "none past a minute"
                if m["binary"]:
                    named += f" (last binary `{m['binary']}`)"
                lines.append(f"| `{m['file']}:{m['line']}:{m['column']}` {m['function']}: "
                             f"{m['genre']} `{m['replacement']}` | {m['shard']} "
                             f"| {m['pass_seconds']}, {m['pass_limit']} "
                             f"| {m['rerun_seconds']}, {m['rerun_limit']} | {named} |")
            lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


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
    pair = writer.add_mutually_exclusive_group(required=True)
    pair.add_argument("--narrow", type=Path, help="the narrow run (a two-run record)")
    pair.add_argument("--previous", type=Path,
                      help="the previous record's .json (a one complete run record)")
    writer.add_argument("--widened", type=Path, required=True,
                        help="the widened run, or the complete run with --previous")
    writer.add_argument("--checkpoint",
                        help="the checkpoint's reading of a one-run record (no artifact has it)")
    writer.add_argument("--record", type=Path, default=nightly.FLOORS_RECORD)
    writer.add_argument("--out", type=Path, required=True,
                        help="the record's path without its suffix")
    writer.set_defaults(func=write)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
