#!/usr/bin/env python3
"""Plan and run the pinned, version-compatible downstream checks."""

import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib


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
    for row in records(sdk):
        if row["requirement"] and admits(row["requirement"], version):
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


def verify_resolution(metadata, manifest, alias, sdk):
    package = next(pkg for pkg in metadata["packages"] if Path(pkg["manifest_path"]).resolve() == manifest)
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == package["id"])
    dependency = next(dep for dep in node["deps"] if dep["name"] == alias.replace("-", "_"))
    resolved = next(pkg for pkg in metadata["packages"] if pkg["id"] == dependency["pkg"])
    if Path(resolved["manifest_path"]).resolve() != sdk / "Cargo.toml" or resolved["source"] is not None:
        raise ValueError(f"{package['name']}: bsv-rs path override was not selected")
    print(f"VERIFIED {package['name']} -> bsv-rs {resolved['version']} at PR tree", flush=True)


def run(sdk, checkout, consumer):
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
        for target in row["targets"]:
            target_args = [] if target == "native" else ["--target", target]
            extras = row.get("wasm_features", []) if target != "native" else []
            all_features = row["features"] + extras
            feature_args = ["--features", ",".join(all_features)] if all_features else []
            check_args = row.get("wasm_check_args", row["check_args"]) if target != "native" else row["check_args"]
            command(["cargo", "check", *options, "--locked", *check_args, *target_args, *feature_args], manifest.parent)
        if row["test_args"]:
            command(["cargo", "test", *options, "--locked", *row["test_args"], *features], manifest.parent)
    test_summary = "hermetic tests passed" if row["test_args"] else "no tests selected"
    print(f"PASS {consumer}: pinned checkout, PR dependency, checks passed; {test_summary}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["plan", "run"])
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--consumer")
    args = parser.parse_args()
    try:
        sdk = args.sdk.resolve()
        if args.mode == "plan":
            plan(sdk, args.output)
        elif args.checkout and args.consumer:
            run(sdk, args.checkout.resolve(), args.consumer)
        else:
            parser.error("run needs --checkout and --consumer")
    except (ValueError, KeyError, StopIteration, OSError, subprocess.CalledProcessError) as error:
        print(f"::error title=dependent {args.consumer or 'plan'}::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
