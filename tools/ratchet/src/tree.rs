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
    std::fs::write(
        tree.path.join("Cargo.lock"),
        include_str!("../library.Cargo.lock"),
    )?;
    Ok(tree)
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
}
