//! Deterministic, read-only code-health measurements for the library.

mod compiler;
mod model;
mod source;
mod tree;

use model::Snapshot;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const TOOLCHAIN: &str = "1.95.0";
const HELP: &str =
    "Usage: tools/ratchet/run [--check | --record] [--revision COMMIT] [--against COMMIT]\n\
    No mode: print one JSON measurement of the working tree.\n\
    --check: fail on increases against docs/ratchets.json.\n\
    --record: deliberately replace docs/ratchets.json.\n\
    --revision: measure a Git commit instead of the working tree.\n\
    --against: with --check, also refuse increases to the recorded baseline\n\
    and a mutation floor lowered or removed from it.\n\
    Build output requires CARGO_TARGET_DIR outside the checkout.\n\
    Temporary files require TMPDIR (or RUNNER_TEMP) outside the checkout.";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Measure,
    Check,
    Record,
}

fn arguments() -> Result<(Mode, Option<String>, Option<String>)> {
    let mut mode = Mode::Measure;
    let mut revision = None;
    let mut against = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" | "--record" if mode == Mode::Measure => {
                mode = if arg == "--check" {
                    Mode::Check
                } else {
                    Mode::Record
                };
            }
            "--revision" if revision.is_none() => {
                revision = Some(args.next().ok_or("--revision needs a commit")?);
            }
            "--against" if against.is_none() => {
                against = Some(args.next().ok_or("--against needs a commit")?);
            }
            "--help" | "-h" => {
                println!("{HELP}");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown or repeated argument: {arg}\n{HELP}").into()),
        }
    }
    if against.is_some() && mode != Mode::Check {
        return Err("--against requires --check".into());
    }
    Ok((mode, revision, against))
}

fn run() -> Result<bool> {
    let (mode, revision, against) = arguments()?;
    let root = tree::root()?;
    let baseline_path: PathBuf = root.join("docs/ratchets.json");
    let baseline = if mode == Mode::Check {
        let baseline: Snapshot = serde_json::from_slice(&std::fs::read(&baseline_path)?)?;
        baseline.validate()?;
        Some(baseline)
    } else {
        None
    };
    let mut baseline_increases = Vec::new();
    if let (Some(revision), Some(proposed)) = (against, &baseline) {
        if let Some(previous) = tree::baseline_at(&root, &revision)? {
            previous.validate()?;
            baseline_increases = proposed
                .increases(&previous)
                .into_iter()
                .chain(proposed.lowered_floors(&previous))
                .map(|increase| format!("recorded baseline: {increase}"))
                .collect();
        } else {
            eprintln!("ratchet: no older baseline at {revision}; checking the bootstrap baseline");
        }
    }
    if mode == Mode::Record && revision.is_none() {
        tree::require_clean_sources(&root)?;
    }
    // The floors are the nightly's record, never measured here: a recording
    // carries the recorded member over unchanged (#602).
    let recorded_floors = if mode == Mode::Record && baseline_path.try_exists()? {
        serde_json::from_slice::<Snapshot>(&std::fs::read(&baseline_path)?)?.mutation_floors
    } else {
        Default::default()
    };
    let measured = tree::materialize(&root, revision.as_deref())?;
    eprintln!("ratchet: source counters");
    let mut snapshot = source::measure(&measured.path, &measured.commit)?;
    compiler::measure(&measured.path, &root, &mut snapshot.metrics)?;
    snapshot.mutation_floors = recorded_floors;
    let json = serde_json::to_string_pretty(&snapshot)? + "\n";
    if mode == Mode::Record {
        std::fs::write(&baseline_path, &json)?;
        eprintln!(
            "ratchet: recorded docs/ratchets.json from {}",
            measured.commit
        );
    }
    print!("{json}");
    if let Some(baseline) = baseline {
        let mut increases = snapshot.increases(&baseline);
        increases.extend(baseline_increases);
        for increase in &increases {
            eprintln!("ratchet: {increase}");
        }
        if increases.is_empty() {
            eprintln!("ratchet: all 7 counters, oversized-file limits and mutation floors pass");
        }
        return Ok(increases.is_empty());
    }
    Ok(true)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::from(1),
        Err(error) => {
            eprintln!("ratchet: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod test_support {
    use crate::{tree::Tree, Result};

    pub fn fixture() -> Result<Tree> {
        let base = std::env::var_os("TMPDIR")
            .or_else(|| std::env::var_os("RUNNER_TEMP"))
            .ok_or("tests require TMPDIR or RUNNER_TEMP")?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::path::PathBuf::from(base)
            .join(format!("ratchet-test-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path)?;
        let tree = Tree {
            path,
            commit: "a".repeat(40),
        };
        std::fs::create_dir(tree.path.join("src"))?;
        Ok(tree)
    }
}
