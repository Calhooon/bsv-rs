//! The nightly fuzzes every target `fuzz/Cargo.toml` builds (bsv-rs#398).
//!
//! The nightly's `fuzz` job names its targets in a matrix by hand, so a new
//! `[[bin]]` that is not added there is built by nobody and run by nobody.
//! This guard reads `fuzz/Cargo.toml`, `.github/workflows/nightly.yml` and
//! the `fuzz/corpus/` directories (nothing else; no network, no environment)
//! and refuses, naming it, a target the matrix does not dispatch, a matrix
//! entry no `[[bin]]` builds, and a target without a checked-in seed corpus;
//! and it pins the one target built without a sanitizer
//! (`fuzz_script_spend_default`, whose legitimate runs under a 128 MiB budget
//! AddressSanitizer takes past libFuzzer's RSS limit).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every `[[bin]]`'s `name` in `fuzz/Cargo.toml`.
fn built() -> BTreeSet<String> {
    let manifest = read("fuzz/Cargo.toml");
    let mut names = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin {
            if let Some(value) = line.strip_prefix("name") {
                let value = value.trim_start().trim_start_matches('=').trim();
                names.insert(value.trim_matches('"').to_string());
            }
        }
    }
    names
}

/// The `fuzz` job's `matrix.target` list in the nightly workflow.
fn dispatched() -> BTreeSet<String> {
    let workflow = read(".github/workflows/nightly.yml");
    let mut lines = workflow.lines();
    lines
        .by_ref()
        .find(|line| *line == "  fuzz:")
        .expect("nightly.yml has a `fuzz` job");
    lines
        .by_ref()
        .take_while(|line| !line.starts_with("  ") || line.starts_with("   "))
        .find(|line| line.trim() == "target:")
        .expect("the fuzz job's matrix has a `target` list");
    lines
        .map(str::trim)
        .map_while(|line| line.strip_prefix("- "))
        .map(|name| name.trim().to_string())
        .collect()
}

#[test]
fn every_fuzz_target_is_dispatched_by_the_nightly() {
    let built = built();
    let dispatched = dispatched();
    assert!(
        built.contains("fuzz_script_spend_default"),
        "the default-mode script target (#398) is built: {built:?}"
    );
    let undispatched: Vec<_> = built.difference(&dispatched).collect();
    assert!(
        undispatched.is_empty(),
        "fuzz/Cargo.toml builds targets the nightly's fuzz matrix does not run: {undispatched:?}"
    );
    let unbuilt: Vec<_> = dispatched.difference(&built).collect();
    assert!(
        unbuilt.is_empty(),
        "the nightly's fuzz matrix names targets fuzz/Cargo.toml does not build: {unbuilt:?}"
    );
}

/// The `fuzz` job's text, from its key to the next job's.
fn fuzz_job() -> String {
    let workflow = read(".github/workflows/nightly.yml");
    workflow
        .lines()
        .skip_while(|line| *line != "  fuzz:")
        .enumerate()
        .take_while(|(i, line)| *i == 0 || !line.starts_with("  ") || line.starts_with("   "))
        .map(|(_, line)| format!("{line}\n"))
        .collect()
}

#[test]
fn the_default_mode_spend_target_is_fuzzed_without_a_sanitizer() {
    let job = fuzz_job();
    assert!(
        job.contains(
            "        include:\n          - target: fuzz_script_spend_default\n            sanitizer: none\n"
        ),
        "the nightly's fuzz matrix builds fuzz_script_spend_default with `sanitizer: none` \
         (#398: ASan's resident set passes libFuzzer's RSS limit on a legitimate run)"
    );
    assert!(
        job.contains("      FUZZ_SANITIZER: ${{ matrix.sanitizer || 'address' }}\n"),
        "the fuzz job reads the matrix's sanitizer, AddressSanitizer by default"
    );
    for command in ["cargo fuzz build -O", "cargo fuzz run -O"] {
        let lines: Vec<_> = job.lines().filter(|line| line.contains(command)).collect();
        assert_eq!(lines.len(), 1, "one `{command}` in the fuzz job: {lines:?}");
        assert!(
            lines[0].contains(&format!("{command} -s \"$FUZZ_SANITIZER\" ")),
            "`{command}` passes the matrix's sanitizer: {}",
            lines[0]
        );
    }
}

#[test]
fn every_fuzz_target_has_a_seed_corpus() {
    for name in built() {
        let dir = root().join("fuzz/corpus").join(&name);
        let seeds = fs::read_dir(&dir)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert!(seeds > 0, "{name} has no seeds under fuzz/corpus/{name}/");
    }
}
