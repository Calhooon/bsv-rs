#!/usr/bin/env python3
"""Plan and run the pinned, version-compatible downstream checks.

`run` judges this tree for the breaks it causes. A consumer whose command fails against
this tree is run once more without it (`baseline`); one that fails that way too is not
judged, and `aggregate`, the one required status, says which were and which were not.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib

# A cell's verdict, written to its slot of the job's outputs and read by `aggregate`.
JUDGED = "judged"
NOT_JUDGED = "not-judged"
# Cargo's exit when it ran and could not complete: a build or a test that fails. A death by
# signal or a runner's kill is another number, and no answer.
CARGO_FAILED = 101


def read_toml(path):
    with Path(path).open("rb") as source:
        return tomllib.load(source)


def admits(requirement, version):
    """The lock accepts exact and caret Cargo requirements; reject other syntax."""
    version_pattern = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?"
    candidate = re.fullmatch(version_pattern, version)
    requested = re.fullmatch(
        r"([=^]?)(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?"
        r"(?:\.(0|[1-9][0-9]*))?(?:-([0-9A-Za-z.-]+))?",
        requirement,
    )
    if not candidate or not requested:
        raise ValueError(f"unsupported Cargo requirement/version: {requirement!r}, {version!r}")
    operator, major, minor, patch, prerelease = requested.groups()
    actual = tuple(int(candidate[i]) for i in (1, 2, 3))
    floor = (int(major), int(minor or 0), int(patch or 0))
    if prerelease and operator != "=":
        raise ValueError("prerelease requirements in the lock must be exact")
    if candidate[4] or prerelease:
        # Pre-release ordering is deliberately not guessed. Pin-move PRs use
        # exact beta versions, including their complete pre-release identifier.
        return operator == "=" and actual == floor and candidate[4] == prerelease
    if operator == "=":
        return actual[0] == floor[0] and (minor is None or actual[1] == floor[1]) and (
            patch is None or actual[2] == floor[2]
        )
    if floor[0] or minor is None:
        ceiling = (floor[0] + 1, 0, 0)
    elif floor[1] or patch is None:
        ceiling = (0, floor[1] + 1, 0)
    else:
        ceiling = (0, 0, floor[2] + 1)
    return floor <= actual < ceiling


def records(sdk):
    lock = read_toml(sdk / "docs/dependents.lock")
    if lock.get("schema") != 1:
        raise ValueError("unsupported dependents.lock schema")
    rows = lock["consumer"]
    ids = set()
    for row in rows:
        if row["id"] in ids or not re.fullmatch(r"[a-z0-9-]+", row["id"]):
            raise ValueError("duplicate or invalid consumer id")
        ids.add(row["id"])
        if not re.fullmatch(r"[0-9a-f]{40}", row["rev"]):
            raise ValueError(f"{row['id']}: rev must be a full commit SHA")
        for manifest in row["manifests"]:
            if Path(manifest).is_absolute() or ".." in Path(manifest).parts:
                raise ValueError(f"{row['id']}: manifest must stay inside its checkout")
    return rows


def plan(sdk, output):
    version = read_toml(sdk / "Cargo.toml")["package"]["version"]
    included = []
    has_token = os.environ.get("HAS_READ_TOKEN") == "true"
    for row in records(sdk):
        if row["private"] and not has_token:
            print(f"::warning::SKIP {row['id']}: private; DEPENDENTS_READ_TOKEN absent", file=sys.stderr)
        elif row["requirement"] and admits(row["requirement"], version):
            included.append({key: row[key] for key in ("id", "repository", "rev", "private")})
        else:
            print(f"SKIP {row['id']}: {row['requirement'] or 'no Rust dependency'} excludes {version}", file=sys.stderr)
    matrix = json.dumps({"include": included}, separators=(",", ":"))
    print(matrix)
    if output:
        with Path(output).open("a") as destination:
            destination.write(f"matrix={matrix}\ncount={len(included)}\n")


def command(args, cwd, capture=False):
    print("$ " + shlex.join(str(arg) for arg in args), flush=True)
    result = subprocess.run(args, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return json.loads(result.stdout) if capture else None


def declared_dependency(manifest, checkout):
    data = read_toml(manifest)
    for name, dependency in data.get("dependencies", {}).items():
        dependency = {"version": dependency} if isinstance(dependency, str) else dependency.copy()
        if dependency.get("workspace"):
            explicit_workspace = data.get("package", {}).get("workspace")
            parents = [(manifest.parent / explicit_workspace).resolve()] if explicit_workspace else [manifest.parent, *manifest.parent.parents]
            for parent in parents:
                if not parent.is_relative_to(checkout):
                    break
                workspace_manifest = parent / "Cargo.toml"
                if workspace_manifest.exists():
                    shared = read_toml(workspace_manifest).get("workspace", {}).get("dependencies", {}).get(name)
                    if shared is not None:
                        shared = {"version": shared} if isinstance(shared, str) else shared
                        dependency = {**shared, "features": shared.get("features", []) + dependency.get("features", [])}
                        break
        if dependency.get("package", name) == "bsv-rs":
            return name, dependency
    raise ValueError(f"{manifest.relative_to(checkout)}: no direct bsv-rs dependency")


def resolved_dependency(metadata, manifest, alias):
    package = next(pkg for pkg in metadata["packages"] if Path(pkg["manifest_path"]).resolve() == manifest)
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == package["id"])
    dependency = next(dep for dep in node["deps"] if dep["name"] == alias.replace("-", "_"))
    return package, next(pkg for pkg in metadata["packages"] if pkg["id"] == dependency["pkg"])


def verify_resolution(metadata, manifest, alias, sdk):
    package, resolved = resolved_dependency(metadata, manifest, alias)
    if Path(resolved["manifest_path"]).resolve() != sdk / "Cargo.toml" or resolved["source"] is not None:
        raise ValueError(f"{package['name']}: bsv-rs path override was not selected")
    print(f"VERIFIED {package['name']} -> bsv-rs {resolved['version']} at PR tree", flush=True)


def verify_baseline(metadata, manifest, alias, sdk):
    """The mirror of verify_resolution: a baseline that still builds this tree says nothing."""
    package, resolved = resolved_dependency(metadata, manifest, alias)
    published = str(resolved["source"] or "").startswith("registry+")
    if Path(resolved["manifest_path"]).resolve() == sdk / "Cargo.toml" or not published:
        raise ValueError(f"{package['name']}: the baseline did not take bsv-rs from a registry")
    print(f"BASELINE {package['name']} -> bsv-rs {resolved['version']} from the registry", flush=True)
    return resolved["version"]


def restore_lock(checkout, lock):
    """Put the consumer's lock back as its pin has it. True when the pin commits one."""
    relative = str(lock.resolve().relative_to(checkout))
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", "--", relative], cwd=checkout,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    if tracked not in (0, 1):
        raise ValueError(f"git could not say whether {relative} is committed")
    if tracked == 0:
        subprocess.run(["git", "checkout", "--quiet", "HEAD", "--", relative], cwd=checkout, check=True)
    else:
        # the run with this tree generated it: the pin commits none
        lock.unlink(missing_ok=True)
    return tracked == 0


def toolchain():
    """The compiler a baseline ran on, for its sentence; never a reason to fail."""
    try:
        return subprocess.run(["rustc", "--version"], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "a toolchain that was not read"


def baseline(failure, consumer, rev, checkout, sdk, manifest, alias, metadata, features, subcommand, tail):
    """The failed command once more, as the consumer stands at its pin without this tree.

    Returns the sentence that says the consumer is not judged, or raises `failure`, the error
    of the command that failed against this tree, so a failure reads as it always has. Which
    is which is decided by which command exits how, never by a compiler's text:

    - The resolve step exits non-zero, or does not take bsv-rs from a registry. The step is
      `cargo metadata` without the patch: under `--locked` on the lock the pin commits, or
      resolving afresh where the pin commits none (as the run with this tree did). The
      consumer cannot be read without this tree: its requirement admits no published
      version, `--locked` refuses its lock, or the registry did not answer. That is not
      "broken on its own": `failure` stands.
    - The command then exits 0: this tree breaks the consumer: `failure` stands.
    - It exits CARGO_FAILED: the consumer fails at its pin without this tree: not judged.
    - It exits anything else (a signal, a runner's kill): no answer: `failure` stands.

    The resolve step fetches every crate, so the command after it needs no network: a
    registry that stops answering fails the resolve step, and is never read as a consumer
    broken on its own.
    """
    print(f"BASELINE {consumer}: the command failed against this tree; running it once more without this tree, "
          "the consumer as its pin stands", flush=True)
    base = ["--manifest-path", str(manifest)]
    try:
        own_lock = restore_lock(checkout, Path(metadata["workspace_root"]) / "Cargo.lock")
        locked = ["--locked"] if own_lock else []
        graph = command(["cargo", "metadata", *base, *locked, *features, "--format-version", "1"],
                        manifest.parent, capture=True)
        version = verify_baseline(graph, manifest, alias, sdk)
    except (ValueError, KeyError, StopIteration, OSError, subprocess.CalledProcessError) as unresolved:
        print(f"BASELINE {consumer}: the consumer does not resolve without this tree ({unresolved}); "
              "that is not a consumer broken on its own, and the failure stands", flush=True)
        raise failure from unresolved
    try:
        command(["cargo", subcommand, *base, "--locked", *tail], manifest.parent)
    except subprocess.CalledProcessError as alone:
        if alone.returncode != CARGO_FAILED:
            print(f"BASELINE {consumer}: the command gave no answer without this tree (exit {alone.returncode}); "
                  "the failure stands", flush=True)
            raise failure from alone
    else:
        print(f"BASELINE {consumer}: the command passes without this tree (bsv-rs {version} from the registry); "
              "this tree breaks the consumer", flush=True)
        raise failure
    how = "by its committed lock" if own_lock else "its graph resolved afresh in this run, as it commits no lock"
    return (f"{consumer} at {rev} is NOT JUDGED: `cargo {subcommand}` fails at its pin without this tree too "
            f"(against bsv-rs {version} from the registry, {how}, on {toolchain()}), so this run says nothing "
            "of this tree for it; its pin in docs/dependents.lock must move once the consumer is mended.")


def run(sdk, checkout, consumer):
    """One consumer against this tree: None when it was judged and passed, the sentence of
    `baseline` when it was not judged; raises when this tree breaks it."""
    row = next(row for row in records(sdk) if row["id"] == consumer)
    version = read_toml(sdk / "Cargo.toml")["package"]["version"]
    if not admits(row["requirement"], version):
        raise ValueError(f"{consumer}: {row['requirement']} excludes {version}")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if head != row["rev"]:
        raise ValueError(f"{consumer}: checkout is not locked rev {row['rev']}")
    patch = ["--config", "patch.crates-io.bsv-rs.path=" + json.dumps(str(sdk))]
    for relative in row["manifests"]:
        manifest = (checkout / relative).resolve()
        alias, dependency = declared_dependency(manifest, checkout)
        observed = (dependency["version"], sorted(dependency.get("features", [])), dependency.get("default-features", True))
        expected = (row["requirement"], sorted(row["sdk_features"]), row["sdk_default_features"])
        if observed != expected or "path" in dependency or "git" in dependency:
            raise ValueError(f"{consumer}/{relative}: dependency differs from dependents.lock")
        options = ["--manifest-path", str(manifest)] + patch
        # Updating an admitted registry copy is necessary even when Cargo.lock
        # already exists. Other SDK minor lines remain untouched.
        lock = manifest.parent / "Cargo.lock"
        if not lock.exists():
            lock = checkout / "Cargo.lock"
        if lock.exists():
            old_versions = {pkg["version"] for pkg in read_toml(lock)["package"]
                            if pkg["name"] == "bsv-rs" and admits(row["requirement"], pkg["version"])}
            for old_version in sorted(old_versions):
                command(["cargo", "update", *options, "-p", f"bsv-rs@{old_version}", "--precise", version], manifest.parent)
        features = ["--features", ",".join(row["features"])] if row["features"] else []
        metadata = command(["cargo", "metadata", *options, *features, "--format-version", "1"], manifest.parent, capture=True)
        verify_resolution(metadata, manifest, alias, sdk)
        commands = []
        for target in row["targets"]:
            target_args = [] if target == "native" else ["--target", target]
            extras = row.get("wasm_features", []) if target != "native" else []
            all_features = row["features"] + extras
            feature_args = ["--features", ",".join(all_features)] if all_features else []
            check_args = row.get("wasm_check_args", row["check_args"]) if target != "native" else row["check_args"]
            commands.append(("check", [*check_args, *target_args, *feature_args]))
        if row["test_args"]:
            commands.append(("test", [*row["test_args"], *features]))
        for subcommand, tail in commands:
            try:
                command(["cargo", subcommand, *options, "--locked", *tail], manifest.parent)
            except subprocess.CalledProcessError as failure:
                # Not judged from this command on: those before it passed against this tree,
                # those after it are not run.
                return baseline(failure, consumer, row["rev"], checkout, sdk, manifest, alias, metadata,
                                features, subcommand, tail)
    test_summary = "hermetic tests passed" if row["test_args"] else "no tests selected"
    print(f"PASS {consumer}: pinned checkout, PR dependency, checks passed; {test_summary}", flush=True)
    return None


def append(path, text):
    if path:
        with Path(path).open("a") as destination:
            destination.write(text)


def report(consumer, not_judged, slot, output, summary):
    """A cell's verdict: its warning and summary line when not judged, and its slot."""
    if not_judged:
        print(f"::warning title=dependent {consumer}::{not_judged}", file=sys.stderr)
        append(summary, f"{not_judged}\n")
    if slot is not None:
        append(output, f"verdict_{slot}={NOT_JUDGED if not_judged else JUDGED} {consumer}\n")


def aggregate(plan_result, check_result, count, verdicts):
    """The one required status, as (passed, sentence, the consumers not judged).

    It fails when a judged consumer failed (its job's result, as before) and when every
    eligible consumer came back not judged: an outage of the toolchain or the registry
    fails every consumer with this tree and without it, and is not a pass. A cell whose
    verdict did not arrive fails it too.
    """
    if plan_result != "success":
        return False, "The dependents plan failed or was cancelled.", []
    if count == "0":
        return True, "All 0 eligible consumer checks passed.", []
    if check_result != "success":
        return False, "An eligible dependent failed or was cancelled; see the named consumer check.", []
    names = {JUDGED: [], NOT_JUDGED: []}
    for slot, value in sorted(verdicts.items()):
        if value in ("", None):
            continue  # a slot no cell of this run wrote
        word, _, consumer = value.partition(" ") if isinstance(value, str) else ("", "", "")
        if word not in names or not re.fullmatch(r"[a-z0-9-]+", consumer) or consumer in names[JUDGED] + names[NOT_JUDGED]:
            return False, f"The verdict in {slot} is unreadable or names a consumer twice: {value!r}.", []
        names[word].append(consumer)
    judged, not_judged = sorted(names[JUDGED]), sorted(names[NOT_JUDGED])
    if str(len(judged) + len(not_judged)) != count:
        return False, (f"{len(judged) + len(not_judged)} of {count} eligible consumers reported a verdict: "
                       "a cell's verdict was lost (ci.yml's verdict slots against the plan's cells)."), not_judged
    if not not_judged:
        return True, f"All {count} eligible consumer checks passed.", []
    if not judged:
        return False, (f"No eligible consumer was judged: all {count} fail at their pins without this tree "
                       f"({', '.join(not_judged)}). An outage of the toolchain or the registry is not a pass."), not_judged
    return True, (f"{len(judged)} of {count} eligible consumers were judged, and passed. Not judged, each failing at "
                  f"its pin without this tree: {', '.join(not_judged)} (the warning of each one's check says how; "
                  "RELEASING.md step 2 says what the captain owes)."), not_judged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "run", "aggregate"])
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--consumer")
    parser.add_argument("--slot", type=int, help="run: this cell's verdict slot among the job's outputs")
    parser.add_argument("--summary", type=Path, help="run, aggregate: the job summary to append to")
    args = parser.parse_args()
    try:
        sdk = args.sdk.resolve()
        if args.mode == "plan":
            plan(sdk, args.output)
        elif args.mode == "aggregate":
            verdicts = json.loads(os.environ.get("VERDICTS") or "{}") or {}
            if not isinstance(verdicts, dict):
                raise ValueError("VERDICTS is not the JSON object of the consumer checks' outputs")
            passed, sentence, not_judged = aggregate(os.environ.get("PLAN_RESULT", ""), os.environ.get("CHECK_RESULT", ""),
                                                     os.environ.get("CONSUMER_COUNT", ""), verdicts)
            append(args.summary, f"{sentence}\n")
            if not passed:
                print(f"::error::{sentence}", file=sys.stderr)
                return 1
            if not_judged:
                print(f"::warning title=dependents::{sentence}", file=sys.stderr)
            print(sentence)
        elif args.checkout and args.consumer:
            report(args.consumer, run(sdk, args.checkout.resolve(), args.consumer), args.slot, args.output, args.summary)
        else:
            parser.error("run needs --checkout and --consumer")
    except (ValueError, KeyError, StopIteration, OSError, subprocess.CalledProcessError) as error:
        title = "dependents" if args.mode == "aggregate" else f"dependent {args.consumer or 'plan'}"
        print(f"::error title={title}::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
