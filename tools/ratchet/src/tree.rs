use crate::Result;
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
    let manifest = std::fs::read_to_string(tree.path.join("Cargo.toml"))?;
    std::fs::write(
        tree.path.join("Cargo.lock"),
        lock_for_manifest(LIBRARY_LOCK, &manifest)?,
    )?;
    Ok(tree)
}

const LIBRARY_LOCK: &str = include_str!("../library.Cargo.lock");

/// Reads `key = "value"` from the manifest's `[package]` table.
fn package_field(manifest: &str, key: &str) -> Result<String> {
    let mut in_package = false;
    let mut found = None;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.split_once('"'))
            .map(|(inner, _)| inner)
            .filter(|inner| !inner.is_empty())
            .ok_or_else(|| {
                format!("Cargo.toml's [package] {key} is not a plain string: {value}")
            })?;
        if found.replace(value.to_string()).is_some() {
            return Err(format!("Cargo.toml's [package] names {key} twice").into());
        }
    }
    found.ok_or_else(|| format!("Cargo.toml has no [package] {key}").into())
}

/// The committed lock with the root package's `version` line set to the manifest's
/// version: the `[[package]]` entry named as the manifest's package with no `source`
/// line. Every other byte is the committed lock's.
pub fn lock_for_manifest(lock: &str, manifest: &str) -> Result<String> {
    let name = package_field(manifest, "name")?;
    let version = package_field(manifest, "version")?;
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
            let lock = lock_for_manifest(LIBRARY_LOCK, &manifest(version))?;
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
            lock_for_manifest(LIBRARY_LOCK, &manifest(&committed))?,
            LIBRARY_LOCK
        );
        Ok(())
    }

    #[test]
    fn a_lock_with_no_root_entry_stops_and_names_it() -> Result<()> {
        let lock = "version = 4\n\n[[package]]\nname = \"bsv-rs\"\nversion = \"1.0.0\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
                    [[package]]\nname = \"aes\"\nversion = \"0.8.4\"\n";
        let Err(error) = lock_for_manifest(lock, &manifest("0.9.0")) else {
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
        let Err(error) = lock_for_manifest(lock, &manifest("0.9.0")) else {
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
            let pinned = lock_for_manifest(&lock, &manifest("0.8.4"))?;
            assert_eq!(
                pinned,
                lock.replace("version = \"0.8.3\"", "version = \"0.8.4\"")
            );
            assert!(pinned.contains("version = \"0.3.24\""));
        }
        Ok(())
    }

    #[test]
    fn a_dependency_moved_is_still_a_stale_lock() -> Result<()> {
        // The tool touches the root's version line alone: a dependency the manifest
        // gained is not added, so cargo --locked still refuses the scratch lock.
        let mut planted = manifest("0.9.0-beta.8");
        planted.push_str("semver = \"1\"\n");
        let lock = lock_for_manifest(LIBRARY_LOCK, &planted)?;
        assert_eq!(differing_lines(LIBRARY_LOCK, &lock).len(), 1);
        Ok(())
    }

    #[test]
    fn the_manifests_version_is_read_from_its_package_table() -> Result<()> {
        assert_eq!(package_field(&manifest("0.8.4"), "version")?, "0.8.4");
        assert!(package_field(
            "[package]\nname = \"bsv-rs\"\nversion.workspace = true\n",
            "version"
        )
        .is_err());
        assert!(package_field("[dependencies]\nversion = \"1\"\n", "version").is_err());
        Ok(())
    }
}
