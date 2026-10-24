//! The binary's verdicts on saved evidence (`--from-run`): no bench runs.
#![allow(clippy::unwrap_used, clippy::expect_used)] // checked fixtures for the gate itself

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

/// The committed baseline's one entry, used as the saved run.
fn recorded() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benches/baseline.json");
    let baseline: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    baseline["platforms"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bench-compare-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn compare(name: &str, run: &Value, platforms: Value) -> Output {
    let dir = scratch(name);
    let run_path = dir.join("run.json");
    let baseline_path = dir.join("baseline.json");
    std::fs::write(&run_path, serde_json::to_vec(run).unwrap()).unwrap();
    let baseline = json!({"schema_version": 1, "platforms": platforms});
    std::fs::write(&baseline_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bench-compare"))
        .arg("--from-run")
        .arg(&run_path)
        .arg("--baseline")
        .arg(&baseline_path)
        .arg("--output")
        .arg(dir.join("out"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    out
}

#[test]
fn a_matching_entry_passes_and_a_skipped_bench_is_named_not_passed() {
    let run = recorded();
    let key = format!(
        "{} / {} / {} cores",
        run["platform"].as_str().unwrap(),
        run["machine"]["model"].as_str().unwrap(),
        run["machine"]["cores"]
    );
    let out = compare("match", &run, json!({ key.clone(): run.clone() }));
    assert_eq!(out.status.code(), Some(0));

    let mut skipped = run.clone();
    skipped["benchmarks"]
        .as_object_mut()
        .unwrap()
        .retain(|id, _| !id.starts_with("script_spend/"));
    skipped["corpus"] = Value::Null;
    skipped["skipped"] = json!(["script_spend"]);
    let out = compare("skip", &skipped, json!({ key: run }));
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("| script_spend/"), "{stdout}");
    assert!(
        stdout.contains("PASS (8 of 9 benches measured)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("SKIPPED script_spend: not measured, neither a pass nor a regression"),
        "{stdout}"
    );
}
