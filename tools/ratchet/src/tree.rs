use crate::{Result, TOOLCHAIN};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub struct Tree {
    pub path: PathBuf,
    pub commit: String,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!("git {} failed ({})", args.join(" "), output.status).into());
    }
    Ok(output.stdout)
}

pub fn root() -> Result<PathBuf> {
    let path = String::from_utf8(git(
        &std::env::current_dir()?,
        &["rev-parse", "--show-toplevel"],
    )?)?;
    Ok(PathBuf::from(path.trim()).canonicalize()?)
}

pub fn baseline_at(root: &Path, revision: &str) -> Result<Option<crate::model::Snapshot>> {
    let rev = format!("{revision}^{{commit}}");
    let commit = String::from_utf8(git(
        root,
        &["rev-parse", "--verify", "--end-of-options", &rev],
    )?)?;
    let commit = commit.trim();
    let listing = git(
        root,
        &["ls-tree", "--name-only", commit, "--", "docs/ratchets.json"],
    )?;
    if listing.is_empty() {
        return Ok(None);
    }
    let contents = git(root, &["show", &format!("{commit}:docs/ratchets.json")])?;
    Ok(Some(serde_json::from_slice(&contents)?))
}

pub fn outside_checkout(path: &Path, root: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err("build and temporary paths must be absolute".into());
    }
    // Resolve the existing ancestor before creating anything. In particular,
    // reject a nonexistent output directory reached through a symlink here.
    let mut ancestor = path;
    let mut suffix = Vec::new();
    while !ancestor.try_exists()? {
        suffix.push(ancestor.file_name().ok_or("output path has no filename")?);
        ancestor = ancestor.parent().ok_or("output path has no parent")?;
    }
    let mut resolved = ancestor.canonicalize()?;
    for name in suffix.into_iter().rev() {
        resolved.push(name);
    }
    if resolved.starts_with(root) {
        return Err("build and temporary output must be outside the checkout".into());
    }
    std::fs::create_dir_all(&resolved)?;
    Ok(resolved.canonicalize()?)
}

pub fn require_clean_sources(root: &Path) -> Result<()> {
    let changed = git(
        root,
        &[
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "src",
            "Cargo.toml",
            "clippy.toml",
            "build.rs",
        ],
    )?;
    if !changed.is_empty() {
        return Err(
            "--record requires committed sources; commit them or use --revision COMMIT".into(),
        );
    }
    Ok(())
}

fn scratch(root: &Path) -> Result<PathBuf> {
    let base = std::env::var_os("TMPDIR")
        .or_else(|| std::env::var_os("RUNNER_TEMP"))
        .ok_or("set TMPDIR or RUNNER_TEMP outside the checkout")?;
    let base = outside_checkout(Path::new(&base), root)?;
    loop {
        let nonce = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("bsv-rs-ratchet-{}-{nonce}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn working_copy(root: &Path, dest: &Path) -> Result<()> {
    let files = git(
        root,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    for file in files
        .split(|byte| *byte == 0)
        .filter(|file| !file.is_empty())
    {
        let file = std::str::from_utf8(file)?;
        if !matches!(
            file,
            "Cargo.toml" | "clippy.toml" | "build.rs" | "README.md"
        ) && !["src/", "tests/", "benches/", "examples/"]
            .iter()
            .any(|prefix| file.starts_with(prefix))
        {
            continue;
        }
        let from = root.join(file);
        // A deleted tracked source stays deleted in the measured tree.
        if !from.try_exists()? {
            continue;
        }
        if std::fs::symlink_metadata(&from)?.file_type().is_symlink() {
            return Err(format!("source symlink is not measured: {file}").into());
        }
        let to = dest.join(file);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(from, to)?;
    }
    Ok(())
}

pub fn materialize(root: &Path, revision: Option<&str>) -> Result<Tree> {
    let rev = format!("{}^{{commit}}", revision.unwrap_or("HEAD"));
    let commit = String::from_utf8(git(
        root,
        &["rev-parse", "--verify", "--end-of-options", &rev],
    )?)?;
    let tree = Tree {
        path: scratch(root)?,
        commit: commit.trim().into(),
    };
    if revision.is_some() {
        let archive = git(root, &["archive", "--format=tar", &tree.commit])?;
        let mut tar = Command::new("tar")
            .args(["-xf", "-", "-C"])
            .arg(&tree.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut input = tar.stdin.take().ok_or("cannot write Git archive to tar")?;
        input.write_all(&archive)?;
        drop(input);
        if !tar.wait_with_output()?.status.success() {
            return Err("cannot unpack Git archive".into());
        }
    } else {
        working_copy(root, &tree.path)?;
    }
    // The library has no tracked lockfile. Keep measurement dependency resolution fixed.
    // The lock pins the dependencies; the crate's own version is the manifest's, so a
    // release commit (Cargo.toml and CHANGELOG.md alone) does not make the lock stale.
    let manifest = tree.path.join("Cargo.toml");
    std::fs::File::open(&manifest).map_err(|error| {
        format!(
            "the measured tree at {} has no readable Cargo.toml: {error}",
            tree.commit
        )
    })?;
    let (name, version) = package_of(&manifest).map_err(|error| {
        format!(
            "cargo metadata failed on the measured tree at {}: {error}",
            tree.commit
        )
    })?;
    std::fs::write(
        tree.path.join("Cargo.lock"),
        lock_for_package(LIBRARY_LOCK, &name, &version)?,
    )?;
    Ok(tree)
}

const LIBRARY_LOCK: &str = include_str!("../library.Cargo.lock");

/// The command `package_of` runs: `cargo metadata --no-deps --offline` on the measurement
/// toolchain, which resolves no dependency and touches no network. Built here alone, so
/// its arguments are pinned by a test (`the_cargo_call_is_the_measurements`).
fn metadata_command(manifest: &Path) -> Result<Command> {
    let directory = manifest.parent().ok_or("a manifest path has no parent")?;
    let mut command = Command::new("cargo");
    command
        .arg(format!("+{TOOLCHAIN}"))
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(manifest)
        .current_dir(directory)
        .env("CARGO_TERM_COLOR", "never");
    Ok(command)
}

/// What cargo (or rustup, for a toolchain it does not have) said, as it said it: the
/// `error:` line without its prefix and every line after it up to the next blank line
/// (a workspace's path lines, a manifest's source snippet, rustup's `help:`), then each
/// `Caused by:` block whole. Lines are kept as written, joined by newlines.
fn what_cargo_said(stderr: &str) -> Option<String> {
    let mut lines = stderr.lines().map(str::trim_end);
    let opening = lines
        .by_ref()
        .find_map(|line| line.strip_prefix("error: "))?;
    let mut said = vec![opening];
    let mut in_block = true;
    for line in lines {
        if line.is_empty() {
            in_block = false;
        } else if line == "Caused by:" {
            in_block = true;
            said.push(line);
        } else if in_block {
            said.push(line);
        }
    }
    Some(said.join("\n"))
}

/// The `name` and `version` of the package `manifest` declares, as cargo reads them
/// (`metadata_command`). A workspace-inherited field is cargo's to resolve; what cargo
/// refuses is refused with its own words (`what_cargo_said`). Of the packages cargo
/// lists (a workspace lists every member), the one whose `manifest_path` is `manifest`.
pub fn package_of(manifest: &Path) -> Result<(String, String)> {
    let output = metadata_command(manifest)?.output()?;
    if !output.status.success() {
        return Err(what_cargo_said(&String::from_utf8_lossy(&output.stderr))
            .unwrap_or_else(|| {
                format!("cargo metadata failed ({}) and said nothing", output.status)
            })
            .into());
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let wanted = manifest.canonicalize()?;
    let mut found = None;
    for package in metadata["packages"].as_array().into_iter().flatten() {
        let Some(path) = package["manifest_path"].as_str() else {
            continue;
        };
        if Path::new(path).canonicalize().ok().as_deref() != Some(wanted.as_path()) {
            continue;
        }
        let field = |key: &str| {
            package[key]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("cargo metadata gave the package no string {key}"))
        };
        if found.replace((field("name")?, field("version")?)).is_some() {
            return Err("cargo metadata named the manifest's package twice".into());
        }
    }
    found.ok_or_else(|| {
        "cargo metadata names no package at the manifest (a virtual workspace?)".into()
    })
}

/// The committed lock with the root package's `version` line set to `version`: the
/// `[[package]]` entry named `name` with no `source` line. Every other byte is the
/// committed lock's. `Cargo.lock` is cargo's own writing, in one fixed form, so it is
/// read by lines; a manifest never is (`package_of`).
pub fn lock_for_package(lock: &str, name: &str, version: &str) -> Result<String> {
    let lines: Vec<&str> = lock.split_inclusive('\n').collect();
    // Every table header's line, and whether it opens a `[[package]]` entry.
    let headers: Vec<(usize, bool)> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with('['))
        .map(|(index, line)| (index, line.trim_end() == "[[package]]"))
        .collect();
    // (the entry's header line, 1-based; the index of its `version` line)
    let mut roots = Vec::new();
    for (position, &(header, is_package)) in headers.iter().enumerate() {
        if !is_package {
            continue;
        }
        let end = headers
            .get(position + 1)
            .map_or(lines.len(), |&(next, _)| next);
        let body = header + 1..end;
        let field = |key: &str| {
            body.clone().find(|&at| {
                lines[at]
                    .split_once('=')
                    .is_some_and(|(field, _)| field.trim() == key)
            })
        };
        let named =
            field("name").is_some_and(|at| lines[at].trim_end() == format!("name = \"{name}\""));
        if named && field("source").is_none() {
            roots.push((header + 1, field("version")));
        }
    }
    let version_line = match roots.as_slice() {
        [(_, Some(at))] => *at,
        [(start, None)] => {
            return Err(format!(
                "tools/ratchet/library.Cargo.lock's root package {name} (line {}) has no \
                 version line; refresh the lock (docs/RATCHETS.md, \"When a dependency changes\")",
                start
            )
            .into())
        }
        [] => {
            return Err(format!(
                "tools/ratchet/library.Cargo.lock has no root package {name} (a [[package]] \
                 named {name} without a source line); refresh the lock (docs/RATCHETS.md, \
                 \"When a dependency changes\")"
            )
            .into())
        }
        many => {
            let starts: Vec<String> = many.iter().map(|(start, _)| start.to_string()).collect();
            return Err(format!(
                "tools/ratchet/library.Cargo.lock has {} root packages {name} (entries \
                 without a source line at lines {}); exactly one is required",
                many.len(),
                starts.join(", ")
            )
            .into());
        }
    };
    let ending = if lines[version_line].ends_with("\r\n") {
        "\r\n"
    } else if lines[version_line].ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let mut out = String::with_capacity(lock.len() + version.len());
    for (index, line) in lines.iter().enumerate() {
        if index == version_line {
            out.push_str(&format!("version = \"{version}\"{ending}"));
        } else {
            out.push_str(line);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_output_paths_create_nothing_in_the_checkout() -> Result<()> {
        let fixture = crate::test_support::fixture()?;
        let rejected = fixture.path.join("must-not-exist");
        assert!(outside_checkout(&rejected, &fixture.path).is_err());
        assert!(!rejected.try_exists()?);
        assert!(outside_checkout(Path::new("relative"), &fixture.path).is_err());
        Ok(())
    }

    fn manifest(version: &str) -> String {
        format!(
            "[package]\nname = \"bsv-rs\"\nversion = \"{version}\"\nedition = \"2021\"\n\n\
             [dependencies]\nversion_check = {{ version = \"0.9\" }}\n"
        )
    }

    fn committed_version() -> Result<String> {
        let mut roots = LIBRARY_LOCK.split("[[package]]").filter(|entry| {
            entry.contains("\nname = \"bsv-rs\"\n") && !entry.contains("\nsource = ")
        });
        let entry = roots.next().ok_or("the committed lock has no root entry")?;
        let line = entry
            .lines()
            .find(|line| line.starts_with("version = "))
            .ok_or("the root entry has no version")?;
        Ok(line["version = ".len()..].trim_matches('"').to_string())
    }

    /// The lines of `a` and `b` that differ, by index; both have the same line count.
    fn differing_lines(a: &str, b: &str) -> Vec<(String, String)> {
        assert_eq!(a.lines().count(), b.lines().count());
        a.lines()
            .zip(b.lines())
            .filter(|(x, y)| x != y)
            .map(|(x, y)| (x.to_string(), y.to_string()))
            .collect()
    }

    #[test]
    fn the_crates_own_version_moved_sets_the_root_entry_alone() -> Result<()> {
        let committed = committed_version()?;
        for version in ["0.8.4", "0.9.0-beta.8", "10.200.3000-rc.1+build.20261110"] {
            assert_ne!(version, committed);
            let lock = lock_for_package(LIBRARY_LOCK, "bsv-rs", version)?;
            assert_eq!(
                differing_lines(LIBRARY_LOCK, &lock),
                vec![(
                    format!("version = \"{committed}\""),
                    format!("version = \"{version}\"")
                )],
                "{version}"
            );
            assert_eq!(
                lock.len() + committed.len(),
                LIBRARY_LOCK.len() + version.len()
            );
        }
        // The version the lock already names: the committed lock byte for byte.
        assert_eq!(
            lock_for_package(LIBRARY_LOCK, "bsv-rs", &committed)?,
            LIBRARY_LOCK
        );
        Ok(())
    }

    #[test]
    fn a_lock_with_no_root_entry_stops_and_names_it() -> Result<()> {
        let lock = "version = 4\n\n[[package]]\nname = \"bsv-rs\"\nversion = \"1.0.0\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
                    [[package]]\nname = \"aes\"\nversion = \"0.8.4\"\n";
        let Err(error) = lock_for_package(lock, "bsv-rs", "0.9.0") else {
            return Err("a lock without a root entry was accepted".into());
        };
        assert_eq!(
            error.to_string(),
            "tools/ratchet/library.Cargo.lock has no root package bsv-rs (a [[package]] named \
             bsv-rs without a source line); refresh the lock (docs/RATCHETS.md, \
             \"When a dependency changes\")"
        );
        Ok(())
    }

    #[test]
    fn a_lock_with_two_root_entries_stops_and_names_them() -> Result<()> {
        let lock = "version = 4\n\n[[package]]\nname = \"bsv-rs\"\nversion = \"0.8.3\"\n\n\
                    [[package]]\nname = \"bsv-rs\"\nversion = \"0.8.2\"\n";
        let Err(error) = lock_for_package(lock, "bsv-rs", "0.9.0") else {
            return Err("a lock with two root entries was accepted".into());
        };
        assert_eq!(
            error.to_string(),
            "tools/ratchet/library.Cargo.lock has 2 root packages bsv-rs (entries without a \
             source line at lines 3, 7); exactly one is required"
        );
        Ok(())
    }

    #[test]
    fn a_dependency_named_as_the_root_with_a_source_is_left_alone() -> Result<()> {
        let dependency = "[[package]]\nname = \"bsv-rs\"\nversion = \"0.3.24\"\n\
                          source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                          checksum = \"00\"\n";
        let root =
            "[[package]]\nname = \"bsv-rs\"\nversion = \"0.8.3\"\ndependencies = [\n \"aes\",\n]\n";
        for lock in [
            format!("version = 4\n\n{dependency}\n{root}"),
            format!("version = 4\n\n{root}\n{dependency}"),
        ] {
            let pinned = lock_for_package(&lock, "bsv-rs", "0.8.4")?;
            assert_eq!(
                pinned,
                lock.replace("version = \"0.8.3\"", "version = \"0.8.4\"")
            );
            assert!(pinned.contains("version = \"0.3.24\""));
        }
        Ok(())
    }

    /// A package folder the test builds: `Cargo.toml` as given, `src/lib.rs`, and each
    /// named file (a target's source). Removed on drop.
    struct Folder(PathBuf);

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn package(manifest: Option<&str>, files: &[&str]) -> Result<Folder> {
        let folder = Folder(crate::test_support::folder("ratchet-package")?);
        std::fs::create_dir(folder.0.join("src"))?;
        if let Some(manifest) = manifest {
            std::fs::write(folder.0.join("Cargo.toml"), manifest)?;
        }
        std::fs::write(folder.0.join("src/lib.rs"), "//! fixture\n")?;
        for file in files {
            let path = folder.0.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, "fn main() {}\n")?;
        }
        Ok(folder)
    }

    fn read(manifest: &str, files: &[&str]) -> Result<(String, String)> {
        let folder = package(Some(manifest), files)?;
        package_of(&folder.0.join("Cargo.toml"))
    }

    const CELL: &str = "[package]\nname = \"cell\"\nversion = \"1.2.3\"\nedition = \"2021\"\n";

    /// The manifests of the cold read of PR #865, each valid TOML cargo reads as the
    /// package `cell` at `1.2.3`, and the files their targets name.
    fn cells() -> Vec<(&'static str, String, Vec<&'static str>)> {
        let after = |rest: &str| format!("{CELL}{rest}");
        vec![
            // Three the line scanner of 38bb503e stopped on.
            (
                "a nested array element on its own line",
                after("\n[package.metadata.x]\nmatrix = [\n  [1, 2],\n]\n"),
                vec![],
            ),
            (
                "a multi-line string whose inner line opens with [",
                after("\n[package.metadata.x]\nnote = \"\"\"\n[x] y\n\"\"\"\n"),
                vec![],
            ),
            (
                "a quoted key holding ]",
                after("\n[package.metadata.\"a]b\"]\nx = 1\n"),
                vec![],
            ),
            // The one it read wrong: an array element turned the package flag on.
            (
                "an array element [\"package\"] inside another table",
                after("\n[package.metadata.x]\nlist = [\n  [\"package\"]\n]\nname = \"bad\"\n"),
                vec![],
            ),
            // Four wrong on both lines, older than #865.
            (
                "a nested array inside [package] before version",
                "[package]\nname = \"cell\"\nmetadata.x = [\n  [1, 2],\n]\n\
                 version = \"1.2.3\"\nedition = \"2021\"\n"
                    .into(),
                vec![],
            ),
            (
                "a quoted \"version\" key",
                "[package]\nname = \"cell\"\n\"version\" = \"1.2.3\"\nedition = \"2021\"\n".into(),
                vec![],
            ),
            (
                "a multi-line string inside [package]",
                after("description = \"\"\"\nversion = \"9.9.9\"\n\"\"\"\n"),
                vec![],
            ),
            (
                "a [package] line inside a multi-line string",
                "[package.metadata.x]\nnote = \"\"\"\n[package]\nname = \"bad\"\n\
                 version = \"9.9.9\"\n\"\"\"\n\n[package]\nname = \"cell\"\n\
                 version = \"1.2.3\"\nedition = \"2021\"\n"
                    .into(),
                vec![],
            ),
            // Eleven it read right, read right still.
            (
                "[[bin]]",
                after("\n[[bin]]\nname = \"b\"\npath = \"src/bin/b.rs\"\n"),
                vec!["src/bin/b.rs"],
            ),
            (
                "[[example]]",
                after("\n[[example]]\nname = \"e\"\npath = \"examples/e.rs\"\n"),
                vec!["examples/e.rs"],
            ),
            (
                "[[bench]]",
                after("\n[[bench]]\nname = \"x\"\npath = \"benches/x.rs\"\nharness = false\n"),
                vec!["benches/x.rs"],
            ),
            (
                "a target.'cfg(...)' header",
                after("\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n"),
                vec![],
            ),
            (
                "[package.metadata.docs.rs]",
                after("\n[package.metadata.docs.rs]\nall-features = true\n"),
                vec![],
            ),
            (
                "[workspace.package]",
                after("\n[workspace]\n\n[workspace.package]\nversion = \"9.9.9\"\n"),
                vec![],
            ),
            (
                "a header with a trailing comment",
                CELL.replace("[package]", "[package] # the crate"),
                vec![],
            ),
            (
                "[ package ]",
                CELL.replace("[package]", "[ package ]"),
                vec![],
            ),
            (
                "[\"package\"]",
                CELL.replace("[package]", "[\"package\"]"),
                vec![],
            ),
            (
                "a quoted dotted table name",
                after("\n[package.metadata.\"a.b\"]\nx = 1\n"),
                vec![],
            ),
            (
                "leading spaces or a tab",
                "\t[package]\n  name = \"cell\"\n\tversion = \"1.2.3\"\nedition = \"2021\"\n"
                    .into(),
                vec![],
            ),
        ]
    }

    #[test]
    fn every_valid_shape_is_read_as_cargo_reads_it() -> Result<()> {
        for (label, manifest, files) in cells() {
            assert_eq!(
                read(&manifest, &files).map_err(|error| error.to_string()),
                Ok(("cell".to_string(), "1.2.3".to_string())),
                "{label}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_version_inherited_from_the_workspace_is_read() -> Result<()> {
        let manifest = "[workspace]\n\n[workspace.package]\nversion = \"4.5.6\"\n\n\
                        [package]\nname = \"cell\"\nversion.workspace = true\nedition = \"2021\"\n";
        assert_eq!(read(manifest, &[])?, ("cell".into(), "4.5.6".into()));
        let inline = manifest.replace("version.workspace = true", "version = { workspace = true }");
        assert_eq!(read(&inline, &[])?, ("cell".into(), "4.5.6".into()));
        // No version at all: cargo's default.
        let none = "[package]\nname = \"cell\"\nedition = \"2021\"\n";
        assert_eq!(read(none, &[])?, ("cell".into(), "0.0.0".into()));
        Ok(())
    }

    #[test]
    fn what_cargo_refuses_stops_in_cargos_words() -> Result<()> {
        let cells = [
            (
                "[package\nname = \"cell\"\n".to_string(),
                "unclosed table, expected `]`",
            ),
            (format!("{CELL}version = \"0.9.1\"\n"), "duplicate key"),
            (
                CELL.replace("\"1.2.3\"", "9"),
                "invalid type: integer `9`, expected SemVer version",
            ),
            (
                format!("{CELL}\n[dependencies.\"a]b\"]\nversion = \"1\"\n"),
                "invalid character `]` in package name: `a]b`, characters must be Unicode XID \
                 characters (numbers, `-`, `_`, or most letters)",
            ),
            (
                format!("{CELL}\n[dependencies.\"a.b\"]\nversion = \"1\"\n"),
                "invalid character `.` in package name: `a.b`, characters must be Unicode XID \
                 characters (numbers, `-`, `_`, or most letters)",
            ),
        ];
        // Cargo's sentence by `contains` of its core: a toolchain that rewords the rest
        // fails no test, a tool that drops or rewords cargo's line fails each.
        for (manifest, expected) in cells {
            let error = read(&manifest, &[]).err().map(|error| error.to_string());
            let error = error.unwrap_or_else(|| panic!("read past: {manifest}"));
            assert!(error.contains(expected), "{manifest}: {error}");
        }
        // A cause chain: the error line, then each `Caused by:` block.
        let error = read(
            "[package]\nname = \"cell\"\nversion.workspace = true\n",
            &[],
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(
            error.starts_with("failed to parse manifest at `"),
            "{error}"
        );
        assert!(error.contains("Caused by:"), "{error}");
        assert!(
            error.contains("error inheriting `version` from workspace root manifest's"),
            "{error}"
        );
        assert!(error.contains("failed to find a workspace root"), "{error}");
        Ok(())
    }

    #[test]
    fn the_cargo_call_is_the_measurements() -> Result<()> {
        let manifest = Path::new("/a/measured/tree/Cargo.toml");
        let command = metadata_command(manifest)?;
        assert_eq!(command.get_program(), "cargo");
        let arguments: Vec<_> = command.get_args().collect();
        let toolchain = format!("+{TOOLCHAIN}");
        let expected: Vec<&std::ffi::OsStr> = vec![
            toolchain.as_ref(),
            "metadata".as_ref(),
            "--no-deps".as_ref(),
            "--offline".as_ref(),
            "--format-version".as_ref(),
            "1".as_ref(),
            "--manifest-path".as_ref(),
            manifest.as_os_str(),
        ];
        assert_eq!(arguments, expected);
        assert_eq!(
            command.get_current_dir(),
            Some(Path::new("/a/measured/tree"))
        );
        Ok(())
    }

    #[test]
    fn each_package_of_a_workspace_is_read_by_its_own_manifest() -> Result<()> {
        // The root `middle`, its members `alpha` and `zulu`: cargo 1.95.0 lists `alpha`,
        // `zulu`, then the root, so a read that takes the first package listed answers
        // `alpha` for the root's manifest and for `zulu`'s.
        let root = Folder(crate::test_support::folder("ratchet-workspace")?);
        let write = |folder: &str, name: &str, version: &str, extra: &str| -> Result<()> {
            let path = root.0.join(folder);
            std::fs::create_dir_all(path.join("src"))?;
            std::fs::write(path.join("src/lib.rs"), "//! fixture\n")?;
            std::fs::write(
                path.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{name}\"\nversion = \"{version}\"\n\
                     edition = \"2021\"\n{extra}"
                ),
            )?;
            Ok(())
        };
        write(
            ".",
            "middle",
            "1.0.0",
            "\n[workspace]\nmembers = [\"alpha\", \"zulu\"]\n",
        )?;
        write("alpha", "alpha", "2.0.0", "")?;
        write("zulu", "zulu", "3.0.0", "")?;
        let listed = metadata_command(&root.0.join("Cargo.toml"))?.output()?;
        let listed: serde_json::Value = serde_json::from_slice(&listed.stdout)?;
        let names: Vec<_> = listed["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|package| package["name"].as_str())
            .collect();
        assert_eq!(names, ["alpha", "zulu", "middle"], "the order cargo lists");
        for (folder, name, version) in [
            (".", "middle", "1.0.0"),
            ("alpha", "alpha", "2.0.0"),
            ("zulu", "zulu", "3.0.0"),
        ] {
            assert_eq!(
                package_of(&root.0.join(folder).join("Cargo.toml"))?,
                (name.into(), version.into()),
                "the package at {folder}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_package_under_a_foreign_workspace_stops_naming_that_workspace() -> Result<()> {
        let parent = Folder(crate::test_support::folder("ratchet-foreign")?);
        let foreign = parent.0.join("Cargo.toml");
        std::fs::write(&foreign, "[workspace]\nmembers = []\n")?;
        let package = parent.0.join("cell");
        std::fs::create_dir_all(package.join("src"))?;
        std::fs::write(package.join("src/lib.rs"), "//! fixture\n")?;
        std::fs::write(package.join("Cargo.toml"), CELL)?;
        let Err(error) = package_of(&package.join("Cargo.toml")) else {
            return Err("a package under a foreign workspace was read".into());
        };
        let error = error.to_string();
        assert!(
            error.contains("believes it's in a workspace when it's not"),
            "{error}"
        );
        assert!(
            error.contains(&foreign.display().to_string()),
            "the stop names no workspace manifest: {error}"
        );
        Ok(())
    }

    #[test]
    fn rustups_refusal_is_kept_whole() {
        // rustup 1.28's words for an absent toolchain (recorded with `+1.95.7` and
        // `RUSTUP_AUTO_INSTALL=0`): no manifest is named, and none is blamed.
        let stderr = "error: toolchain '1.95.7-aarch64-apple-darwin' is not installed\n\
                      help: run `rustup toolchain install 1.95.7-aarch64-apple-darwin` to \
                      install it\n";
        assert_eq!(
            what_cargo_said(stderr).as_deref(),
            Some(
                "toolchain '1.95.7-aarch64-apple-darwin' is not installed\n\
                 help: run `rustup toolchain install 1.95.7-aarch64-apple-darwin` to install it"
            )
        );
        assert_eq!(what_cargo_said("warning: nothing\n"), None);
    }

    /// This repository's three manifests at `revision`, each read through `git archive`.
    fn repository_manifests(revision: &str) -> Result<Vec<(String, String)>> {
        let root = root()?;
        let folder = Folder(crate::test_support::folder("ratchet-line")?);
        let archive = git(&root, &["archive", "--format=tar", revision])?;
        let mut tar = Command::new("tar")
            .args(["-xf", "-", "-C"])
            .arg(&folder.0)
            .stdin(Stdio::piped())
            .spawn()?;
        tar.stdin
            .take()
            .ok_or("cannot write Git archive to tar")?
            .write_all(&archive)?;
        if !tar.wait()?.success() {
            return Err("cannot unpack Git archive".into());
        }
        ["Cargo.toml", "fuzz/Cargo.toml", "tools/ratchet/Cargo.toml"]
            .iter()
            .map(|manifest| package_of(&folder.0.join(manifest)))
            .collect()
    }

    #[test]
    fn this_repositorys_manifests_are_read() -> Result<()> {
        let manifests = repository_manifests("HEAD")?;
        let names: Vec<&str> = manifests.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["bsv-rs", "bsv-rs-fuzz", "bsv-rs-ratchet"]);
        assert_eq!(manifests[0].1, head_root_version()?);
        assert_eq!(manifests[1].1, "0.0.0");
        assert_eq!(manifests[2].1, env!("CARGO_PKG_VERSION"));
        Ok(())
    }

    /// The root manifest's version at HEAD by the earliest line that opens with
    /// `version = ` (this repository's manifest writes it there, under `[package]`).
    fn head_root_version() -> Result<String> {
        let text = String::from_utf8(git(&root()?, &["show", "HEAD:Cargo.toml"])?)?;
        let line = text
            .lines()
            .find(|line| line.starts_with("version = "))
            .ok_or("the root manifest has no version line")?;
        Ok(line["version = ".len()..].trim_matches('"').to_string())
    }

    /// A Git repository the test builds itself: `Cargo.toml` as given and one source
    /// file, committed. Removed on drop, as a `Tree` is.
    struct Repository {
        folder: Folder,
        commit: String,
    }

    fn new_repository(manifest: Option<&str>) -> Result<Repository> {
        let folder = package(manifest, &[])?;
        let run = |args: &[&str]| -> Result<Vec<u8>> {
            let output = Command::new("git")
                .arg("-C")
                .arg(&folder.0)
                .args([
                    "-c",
                    "user.name=ratchet test",
                    "-c",
                    "user.email=ratchet@test.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                ])
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()?;
            if !output.status.success() {
                return Err(format!(
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            Ok(output.stdout)
        };
        run(&["init", "--quiet"])?;
        run(&["add", "--all"])?;
        run(&["commit", "--quiet", "--message", "fixture"])?;
        let commit = String::from_utf8(run(&["rev-parse", "HEAD"])?)?;
        Ok(Repository {
            folder,
            commit: commit.trim().into(),
        })
    }

    /// Materializes the repository both ways the tool does (a commit through
    /// `git archive`, the working tree through `git ls-files`) and returns each
    /// scratch tree's `Cargo.lock`, the scratch trees removed.
    fn scratch_locks(repository: &Repository) -> Result<Vec<String>> {
        let mut locks = Vec::new();
        for revision in [Some(repository.commit.as_str()), None] {
            let tree = materialize(&repository.folder.0, revision)?;
            assert_eq!(tree.commit, repository.commit);
            locks.push(std::fs::read_to_string(tree.path.join("Cargo.lock"))?);
            let path = tree.path.clone();
            drop(tree);
            assert!(!path.try_exists()?, "the scratch tree outlived its Tree");
        }
        Ok(locks)
    }

    #[test]
    fn materialize_writes_the_manifests_version_into_the_scratch_lock() -> Result<()> {
        let committed = committed_version()?;
        let inherited = "[workspace]\n\n[workspace.package]\nversion = \"4.5.6\"\n\n\
                         [package]\nname = \"bsv-rs\"\nversion.workspace = true\n\
                         edition = \"2021\"\n";
        let cells = [
            (manifest("99.0.0"), "99.0.0"),
            (manifest("0.9.0-beta.8"), "0.9.0-beta.8"),
            (inherited.to_string(), "4.5.6"),
            (
                "[package]\nname = \"bsv-rs\"\nedition = \"2021\"\n".to_string(),
                "0.0.0",
            ),
        ];
        for (manifest, version) in cells {
            assert_ne!(version, committed);
            let repository = new_repository(Some(&manifest))?;
            for lock in scratch_locks(&repository)? {
                assert_eq!(
                    differing_lines(LIBRARY_LOCK, &lock),
                    vec![(
                        format!("version = \"{committed}\""),
                        format!("version = \"{version}\"")
                    )],
                    "the scratch lock of a tree whose Cargo.toml says {version}"
                );
                assert_eq!(
                    lock.len() + committed.len(),
                    LIBRARY_LOCK.len() + version.len()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn materialize_writes_the_committed_lock_when_the_versions_agree() -> Result<()> {
        let repository = new_repository(Some(&manifest(&committed_version()?)))?;
        for lock in scratch_locks(&repository)? {
            assert_eq!(lock, LIBRARY_LOCK);
        }
        Ok(())
    }

    #[test]
    fn a_dependency_moved_is_still_a_stale_lock() -> Result<()> {
        // The tool touches the root's version line alone: a dependency the manifest
        // gained is not added, so cargo --locked still refuses the scratch lock.
        let mut planted = manifest("0.9.0-beta.8");
        planted.push_str("semver = \"1\"\n");
        let repository = new_repository(Some(&planted))?;
        for lock in scratch_locks(&repository)? {
            assert_eq!(differing_lines(LIBRARY_LOCK, &lock).len(), 1);
            assert!(!lock.contains("name = \"semver\""));
        }
        Ok(())
    }

    #[test]
    fn materialize_stops_on_what_it_cannot_read_and_names_it() -> Result<()> {
        let cells = [
            (
                "[package\nname = \"bsv-rs\"\nversion = \"0.9.0\"\n".to_string(),
                "unclosed table, expected `]`",
            ),
            (
                "[package]\nname = \"bsv-rs\"\nversion = 9\n".to_string(),
                "invalid type: integer `9`, expected SemVer version",
            ),
            (
                format!("{}version = \"0.9.1\"\n", manifest("0.9.0")).replace(
                    "\n\n[dependencies]\nversion_check = { version = \"0.9\" }\n",
                    "\n",
                ),
                "duplicate key",
            ),
        ];
        for (manifest, said) in cells {
            let repository = new_repository(Some(&manifest))?;
            for revision in [Some(repository.commit.as_str()), None] {
                let Err(error) = materialize(&repository.folder.0, revision) else {
                    return Err(format!("materialized past: {said}").into());
                };
                let error = error.to_string();
                let prefix = format!(
                    "cargo metadata failed on the measured tree at {}: ",
                    repository.commit
                );
                assert!(error.starts_with(&prefix), "{error}");
                assert!(error[prefix.len()..].contains(said), "{error}");
            }
        }
        // A version inherited from no workspace: cargo's cause chain.
        let repository = new_repository(Some(
            "[package]\nname = \"bsv-rs\"\nversion.workspace = true\n",
        ))?;
        for revision in [Some(repository.commit.as_str()), None] {
            let Err(error) = materialize(&repository.folder.0, revision) else {
                return Err("an uninheritable version was materialized".into());
            };
            let error = error.to_string();
            assert!(
                error.starts_with(&format!(
                    "cargo metadata failed on the measured tree at {}: \
                     failed to parse manifest at `",
                    repository.commit
                )),
                "{error}"
            );
            assert!(error.contains("failed to find a workspace root"), "{error}");
        }
        // A package the committed lock does not name.
        let repository = new_repository(Some(&manifest("0.9.0").replace("bsv-rs", "another")))?;
        for revision in [Some(repository.commit.as_str()), None] {
            let Err(error) = materialize(&repository.folder.0, revision) else {
                return Err("a package the lock does not name was materialized".into());
            };
            assert_eq!(
                error.to_string(),
                "tools/ratchet/library.Cargo.lock has no root package another (a [[package]] \
                 named another without a source line); refresh the lock (docs/RATCHETS.md, \
                 \"When a dependency changes\")"
            );
        }
        // No Cargo.toml in the tree at all.
        let repository = new_repository(None)?;
        for revision in [Some(repository.commit.as_str()), None] {
            let Err(error) = materialize(&repository.folder.0, revision) else {
                return Err("a tree without Cargo.toml was materialized".into());
            };
            let expected = format!(
                "the measured tree at {} has no readable Cargo.toml: ",
                repository.commit
            );
            assert!(error.to_string().starts_with(&expected), "{error}");
        }
        // A revision that names no commit.
        let Err(error) = materialize(&repository.folder.0, Some("no-such-revision")) else {
            return Err("an unknown revision was materialized".into());
        };
        assert!(
            error.to_string().starts_with(
                "git rev-parse --verify --end-of-options no-such-revision^{commit} failed"
            ),
            "{error}"
        );
        Ok(())
    }
}
