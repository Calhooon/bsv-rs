//! CI runs every integration test binary: by a whole-suite step, or apart on purpose (#146).
//!
//! The Test Suite once enumerated its binaries by hand and drifted to 34 of
//! 73 files. This guard reads `.github/workflows/ci.yml`, `Cargo.toml` and
//! the top-level `tests/*.rs` (nothing else; no network, no environment) and
//! refuses, naming the file, any binary no step runs.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Files CI runs apart from the whole suite on purpose: (file, reason, step).
/// The step is the `--test` name that must run it on a feature set that
/// compiles it. Nothing else belongs here: a file CI does not run is a
/// finding, not an entry.
const RUN_APART: &[(&str, &str, &str)] = &[
    (
        "memory_profiling",
        "dhat-profiling installs a global allocator; it runs alone, single-threaded",
        "memory_profiling",
    ),
    (
        "wire_tracing_sink",
        "the `tracing` feature is a diagnostics sink outside `full` (#212); its step adds it",
        "wire_tracing_sink",
    ),
];

/// The feature set CLAUDE.md's numbers and the lanes' gates use.
const HOUSE_FEATURES: &str = "full,http,websocket";

/// One `cargo test` invocation of ci.yml.
#[derive(Debug)]
struct Step {
    line: usize,
    whole_suite: bool,
    named: Vec<String>,
    features: BTreeSet<String>,
}

/// Splits a shell line into words, keeping a double-quoted span whole.
fn words(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    for c in command.chars() {
        match c {
            '"' | '\'' if quote.is_none() => quote = Some(c),
            c if quote == Some(c) => quote = None,
            c if c.is_whitespace() && quote.is_none() => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// `[features]` of Cargo.toml: each feature and the features it enables
/// (`dep:` and `crate/feature` entries are dependencies, not features).
fn feature_table(manifest: &str) -> Vec<(String, Vec<String>)> {
    let mut table = Vec::new();
    let mut in_features = false;
    let mut pending = String::new();
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') && pending.is_empty() {
            in_features = line == "[features]";
            continue;
        }
        if !in_features || line.is_empty() {
            continue;
        }
        pending.push_str(line);
        pending.push(' ');
        if pending.matches('[').count() > pending.matches(']').count() {
            continue;
        }
        let entry = std::mem::take(&mut pending);
        let (name, value) = entry.split_once('=').expect("a feature is name = [...]");
        let enables = value
            .split(['[', ']', ','])
            .map(|s| s.trim().trim_matches('"'))
            .filter(|s| !s.is_empty() && !s.contains(':') && !s.contains('/'))
            .map(str::to_owned)
            .collect();
        table.push((name.trim().to_owned(), enables));
    }
    table
}

/// The features a step enables: its flags, closed over the table.
fn resolve(
    table: &[(String, Vec<String>)],
    asked: &[String],
    all: bool,
    default: bool,
) -> BTreeSet<String> {
    let mut todo: Vec<String> = if all {
        table.iter().map(|(name, _)| name.clone()).collect()
    } else {
        asked.to_vec()
    };
    if default {
        todo.push("default".to_owned());
    }
    let mut on = BTreeSet::new();
    while let Some(feature) = todo.pop() {
        if on.insert(feature.clone()) {
            if let Some((_, enables)) = table.iter().find(|(name, _)| *name == feature) {
                todo.extend(enables.iter().cloned());
            }
        }
    }
    on
}

/// Every `cargo test` of this crate in ci.yml. A `--manifest-path` run tests
/// another crate (`tools/bench-compare`) and is not a step of this one.
fn steps(ci: &str, table: &[(String, Vec<String>)]) -> Vec<Step> {
    let lines: Vec<&str> = ci.lines().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let number = at + 1;
        let mut command = lines[at].trim().to_owned();
        while command.ends_with('\\') && at + 1 < lines.len() {
            command.pop();
            at += 1;
            command.push(' ');
            command.push_str(lines[at].trim());
        }
        at += 1;
        if command.starts_with('#') {
            continue;
        }
        let Some(start) = command.find("cargo test") else {
            continue;
        };
        let words = words(&command[start + "cargo test".len()..]);
        let words: Vec<&str> = words
            .iter()
            .map(String::as_str)
            .take_while(|w| *w != "--" && *w != "&&" && *w != ";" && *w != "|")
            .collect();
        if words.iter().any(|w| w.starts_with("--manifest-path")) {
            continue;
        }
        let (mut named, mut asked) = (Vec::new(), Vec::new());
        let (mut all, mut default, mut tests, mut selector) = (false, true, false, false);
        let mut i = 0;
        while i < words.len() {
            let (flag, inline) = match words[i].split_once('=') {
                Some((flag, value)) => (flag, Some(value.to_owned())),
                None => (words[i], None),
            };
            let mut value = || {
                inline.clone().or_else(|| {
                    i += 1;
                    words.get(i).map(|w| (*w).to_owned())
                })
            };
            match flag {
                "--test" => named.push(value().expect("--test takes a name")),
                "--features" | "-F" => asked.extend(
                    value()
                        .expect("--features takes a list")
                        .split([',', ' '])
                        .filter(|f| !f.is_empty())
                        .map(str::to_owned),
                ),
                "--all-features" => all = true,
                "--no-default-features" => default = false,
                "--tests" | "--all-targets" => tests = true,
                "--lib" | "--bins" | "--bin" | "--examples" | "--example" | "--benches"
                | "--bench" | "--doc" => selector = true,
                _ => {}
            }
            i += 1;
        }
        // `--tests` builds every integration binary; so does a bare
        // `cargo test` with no target selector. A `--test <name>` alongside
        // is read as a named run, the brief's narrower form.
        let whole_suite = named.is_empty() && (tests || !selector);
        out.push(Step {
            line: number,
            whole_suite,
            named,
            features: resolve(table, &asked, all, default),
        });
    }
    out
}

/// The file-level `#![cfg(...)]` predicates of a test file, joined.
fn file_gates(source: &str) -> Vec<String> {
    let mut gates = Vec::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if !line.starts_with("#![cfg(") {
            continue;
        }
        let mut gate = line.to_owned();
        while gate.matches('(').count() > gate.matches(')').count() {
            match lines.next() {
                Some(next) => gate.push_str(next.trim()),
                None => break,
            }
        }
        let inner = gate
            .trim_start_matches("#![cfg(")
            .trim_end_matches(']')
            .strip_suffix(')')
            .unwrap_or_default();
        gates.push(inner.to_owned());
    }
    gates
}

/// Evaluates a cfg predicate on a feature set. `None` for a predicate this
/// guard cannot decide (a target, an OS): the file is a finding, never a pass.
fn evaluate(predicate: &str, on: &BTreeSet<String>) -> Option<bool> {
    let p = predicate.trim();
    if let Some(name) = p.strip_prefix("feature") {
        let name = name.trim().strip_prefix('=')?.trim().trim_matches('"');
        return Some(on.contains(name));
    }
    let (head, rest) = p.split_once('(')?;
    let body = rest.strip_suffix(')')?;
    let mut args = Vec::new();
    let (mut depth, mut from) = (0usize, 0);
    for (at, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                args.push(&body[from..at]);
                from = at + 1;
            }
            _ => {}
        }
    }
    args.push(&body[from..]);
    let args: Vec<&str> = args.into_iter().filter(|a| !a.trim().is_empty()).collect();
    let values = args
        .iter()
        .map(|a| evaluate(a, on))
        .collect::<Option<Vec<bool>>>()?;
    match head.trim() {
        "all" => Some(values.iter().all(|v| *v)),
        "any" => Some(values.iter().any(|v| *v)),
        "not" if values.len() == 1 => Some(!values[0]),
        _ => None,
    }
}

/// Whether a file compiles to a test binary with tests under a feature set.
fn compiles(gates: &[String], on: &BTreeSet<String>) -> Option<bool> {
    gates
        .iter()
        .map(|g| evaluate(g, on))
        .collect::<Option<Vec<bool>>>()
        .map(|v| v.iter().all(|b| *b))
}

/// The guard on its inputs: every refusal, one line each, naming the file.
fn refusals(ci: &str, manifest: &str, files: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.contains("[[test]]") || manifest.contains("autotests") {
        errors.push(
            "Cargo.toml declares [[test]] or autotests: tests/*.rs is no longer the binary list; extend this guard".to_owned(),
        );
    }
    let table = feature_table(manifest);
    let steps = steps(ci, &table);
    let names: BTreeSet<&str> = files.iter().map(|(name, _)| name.as_str()).collect();

    for (name, source) in files {
        let gates = file_gates(source);
        let mut covered = false;
        for step in steps.iter().filter(|s| s.whole_suite) {
            match compiles(&gates, &step.features) {
                Some(true) => covered = true,
                Some(false) => {}
                None => errors.push(format!(
                    "tests/{name}.rs: a cfg gate this guard cannot decide ({}); a target-gated binary may run on no runner",
                    gates.join(" && ")
                )),
            }
        }
        let apart = RUN_APART.iter().find(|(file, _, _)| file == name);
        match (covered, apart) {
            (true, None) => {}
            (true, Some(_)) => errors.push(format!(
                "tests/{name}.rs: allowlisted as run apart, but a whole-suite step already runs it; remove the entry"
            )),
            (false, Some((_, _, step_name))) => {
                let run = steps.iter().any(|s| {
                    s.named.iter().any(|n| n == step_name)
                        && compiles(&gates, &s.features) == Some(true)
                });
                if !run {
                    errors.push(format!(
                        "tests/{name}.rs: allowlisted as run apart by `--test {step_name}`, but no ci.yml step runs that on a feature set that compiles it"
                    ));
                }
            }
            (false, None) => errors.push(format!(
                "tests/{name}.rs: no whole-suite step of ci.yml runs it (gate: {}); a `cargo test --features \"{HOUSE_FEATURES}\" --tests` step covers every file the house's features compile",
                if gates.is_empty() { "none".to_owned() } else { gates.join(" && ") }
            )),
        }
    }
    for (file, _, _) in RUN_APART {
        if !names.contains(file) {
            errors.push(format!(
                "tests/{file}.rs: allowlisted as run apart, but the file does not exist"
            ));
        }
    }
    for step in &steps {
        for name in &step.named {
            match files.iter().find(|(file, _)| file == name) {
                None => errors.push(format!(
                    "ci.yml:{}: `--test {name}` names no file under tests/; a renamed file leaves a dead step",
                    step.line
                )),
                Some((_, source)) => {
                    if compiles(&file_gates(source), &step.features) != Some(true) {
                        errors.push(format!(
                            "ci.yml:{}: `--test {name}` runs on features that compile tests/{name}.rs to no tests",
                            step.line
                        ));
                    }
                }
            }
        }
    }
    errors
}

/// The top-level `tests/*.rs`, each an integration binary; module
/// directories (`support/`, `arch_support/`, ...) are not binaries.
fn tree() -> (String, String, Vec<(String, String)>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("tests")).expect("read tests/") {
        let path = entry.expect("tests/ entry").path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            let name = path
                .file_stem()
                .expect("a file stem")
                .to_string_lossy()
                .into_owned();
            files.push((name, fs::read_to_string(&path).expect("read a test file")));
        }
    }
    files.sort();
    (ci, manifest, files)
}

#[test]
fn ci_runs_every_integration_test_binary() {
    let (ci, manifest, files) = tree();
    let errors = refusals(&ci, &manifest, &files);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let asked: Vec<String> = HOUSE_FEATURES.split(',').map(str::to_owned).collect();
    let house = resolve(&feature_table(&manifest), &asked, false, true);
    for (name, source) in &files {
        let gates = file_gates(source);
        println!(
            "{name}: {} -> {}",
            if gates.is_empty() {
                "ungated".to_owned()
            } else {
                gates.join(" && ")
            },
            match compiles(&gates, &house) {
                Some(true) => "whole suite",
                Some(false) => "outside full,http,websocket",
                None => "undecided",
            }
        );
    }
    println!(
        "integration binaries: {}; run apart: {}",
        files.len(),
        RUN_APART.len()
    );
}

fn file(name: &str, source: &str) -> (String, String) {
    (name.to_owned(), source.to_owned())
}

const MANIFEST: &str = r#"
[features]
default = ["primitives"]
primitives = []
wallet = ["primitives", "dep:tokio"]
full = ["primitives", "wallet"]
http = ["dep:reqwest"]
dhat-profiling = ["dep:dhat"]
tracing = ["dep:tracing"]
[dependencies]
"#;

#[test]
fn an_enumerated_suite_refuses_each_file_it_leaves_out() {
    let ci = "run: cargo test --test a --all-features\nrun: cargo test --test memory_profiling --all-features\nrun: cargo test --test wire_tracing_sink --features \"full,tracing\"";
    let files = [
        file("a", ""),
        file("b", "#![cfg(feature = \"wallet\")]"),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
        file("wire_tracing_sink", "#![cfg(feature = \"tracing\")]"),
    ];
    let errors = refusals(ci, MANIFEST, &files);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].starts_with("tests/a.rs: no whole-suite step"));
    assert!(errors[1].starts_with("tests/b.rs: no whole-suite step"));
}

#[test]
fn the_whole_suite_step_covers_every_file_its_features_compile() {
    let ci = "        run: cargo test --features \"full,http\" --tests --no-fail-fast --verbose\n        run: cargo test --test memory_profiling --all-features -- --test-threads=1\n        run: cargo test --features \"full,http,tracing\" --test wire_tracing_sink";
    let files = [
        file("a", ""),
        file(
            "b",
            "#![cfg(all(feature = \"wallet\", feature = \"http\"))]",
        ),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
        file("wire_tracing_sink", "#![cfg(feature = \"tracing\")]"),
    ];
    assert_eq!(refusals(ci, MANIFEST, &files), Vec::<String>::new());
}

#[test]
fn a_file_gated_outside_the_suites_features_is_a_finding() {
    let ci = "run: cargo test --features full --tests\nrun: cargo test --test memory_profiling --all-features";
    let files = [
        file("needs_http", "#![cfg(feature = \"http\")]"),
        file("on_wasm", "#![cfg(target_arch = \"wasm32\")]"),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
    ];
    let errors = refusals(ci, MANIFEST, &files);
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("tests/needs_http.rs: no whole-suite step")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("tests/on_wasm.rs: a cfg gate this guard cannot decide")),
        "{errors:?}"
    );
}

#[test]
fn a_dead_or_compiled_out_named_step_is_refused() {
    let ci = "run: cargo test --features \"full,http\" --tests\nrun: cargo test --test renamed --test memory_profiling --features full\nrun: cargo test --locked --manifest-path tools/x/Cargo.toml --test gone";
    let files = [file(
        "memory_profiling",
        "#![cfg(feature = \"dhat-profiling\")]",
    )];
    let errors = refusals(ci, MANIFEST, &files);
    assert!(
        errors
            .iter()
            .any(|e| e.starts_with("ci.yml:2: `--test renamed` names no file")),
        "{errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e
                .starts_with("ci.yml:2: `--test memory_profiling` runs on features that compile")),
        "{errors:?}"
    );
    assert!(!errors.iter().any(|e| e.contains("gone")), "{errors:?}");
}

#[test]
fn library_doc_and_named_runs_are_not_whole_suite_steps() {
    let table = feature_table(MANIFEST);
    let ci = "cargo test --lib --all-features\ncargo test --doc\ncargo test --tests --test a\ncargo test\n# cargo test --tests";
    let found = steps(ci, &table);
    let whole: Vec<bool> = found.iter().map(|s| s.whole_suite).collect();
    assert_eq!(whole, [false, false, false, true]);
    assert!(found[3].features.contains("primitives") && !found[3].features.contains("wallet"));
}
