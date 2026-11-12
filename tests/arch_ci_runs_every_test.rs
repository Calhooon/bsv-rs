//! CI runs every integration test binary: by a whole-suite step, or apart on purpose (#146).
//!
//! The Test Suite once enumerated its binaries by hand and drifted to 34 of
//! 73 files. This guard reads `.github/workflows/ci.yml`, `Cargo.toml` and
//! the top-level `tests/*.rs` (nothing else; no network, no environment) and
//! refuses, naming the file, any binary no step runs.
//!
//! Since cut 4 (#667) a pull request runs the binaries its changed files reach
//! (`.github/scripts/affected_tests.py`): the whole-suite step runs under the
//! plan's `whole` flag, which the plan sets on every run that is not a pull
//! request and on a pull request labeled `full-suite` (the landing run), and the
//! reached step runs beside a check that the reached set lies within the whole.
//! [`reached_refusals`] pins that shape.
//!
//! Since speed loop three (#672) the whole-suite step names `--test '*'`, cargo's glob over the
//! integration binaries, so the lib's unit tests run once (the unit step's), and the named and
//! doc steps build on one feature set, so they share one library build. [`shared_build_refusals`]
//! pins both, and [`dependency_profile_refusals`] the dependencies' opt-level in the test profile
//! (a step writing the cargo home's configuration from a name rust-cache hashes into its key).
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
        "dhat-profiling installs a global allocator; its step runs it alone, nextest giving each test a process of its own and RUST_TEST_THREADS=1 on the step keeping libtest single-threaded",
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

/// One `cargo test` or `cargo nextest run` invocation of ci.yml.
#[derive(Debug)]
struct Step {
    line: usize,
    whole_suite: bool,
    named: Vec<String>,
    features: BTreeSet<String>,
    /// The step's `if:`, when it has one.
    condition: Option<String>,
    /// Its binaries come from the plan (a `$VARIABLE` among its words): the reached set.
    reached: bool,
    /// It runs the lib's unit target: `--lib`, `--tests`, `--all-targets`, or no selector.
    lib: bool,
    /// It runs the doc tests (`--doc`).
    doc: bool,
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

/// Every `cargo test` or `cargo nextest run` of this crate in ci.yml. A
/// `--manifest-path` run tests
/// another crate (`tools/bench-compare`) and is not a step of this one.
fn steps(ci: &str, table: &[(String, Vec<String>)]) -> Vec<Step> {
    let lines: Vec<&str> = ci.lines().collect();
    let mut out = Vec::new();
    let mut at = 0;
    let mut condition = None;
    while at < lines.len() {
        let number = at + 1;
        let trimmed = lines[at].trim();
        if trimmed.starts_with("- ") {
            condition = None;
        }
        if let Some(test) = trimmed.strip_prefix("if:") {
            condition = Some(test.trim().to_owned());
        }
        let mut command = trimmed.to_owned();
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
        // `cargo nextest run` takes `cargo test`'s target selectors and
        // features (speed round 1); either is a step of this crate.
        let Some(rest) = ["cargo test", "cargo nextest run"]
            .iter()
            .find_map(|run| command.find(run).map(|at| &command[at + run.len()..]))
        else {
            continue;
        };
        let words = words(rest);
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
        let (mut lib, mut doc, mut glob) = (false, false, false);
        let reached = words.iter().any(|w| w.starts_with('$'));
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
                // `--test '*'` is cargo's glob over every integration binary, the lib not
                // among them (#672)
                "--test" => match value().expect("--test takes a name") {
                    name if name == "*" => glob = true,
                    name => named.push(name),
                },
                "--features" | "-F" => asked.extend(
                    value()
                        .expect("--features takes a list")
                        .split([',', ' '])
                        .filter(|f| !f.is_empty())
                        .map(str::to_owned),
                ),
                "--all-features" => all = true,
                "--no-default-features" => default = false,
                "--tests" | "--all-targets" => (tests, lib) = (true, true),
                "--lib" => (selector, lib) = (true, true),
                "--doc" => (selector, doc) = (true, true),
                "--bins" | "--bin" | "--examples" | "--example" | "--benches" | "--bench" => {
                    selector = true
                }
                _ => {}
            }
            i += 1;
        }
        // `--tests` builds every integration binary; so does a bare
        // `cargo test` with no target selector. A `--test <name>` alongside
        // is read as a named run, the brief's narrower form.
        let whole_suite = named.is_empty() && !reached && (tests || glob || !selector);
        let lib = lib || (named.is_empty() && !reached && !glob && !selector);
        out.push(Step {
            line: number,
            whole_suite,
            named,
            features: resolve(table, &asked, all, default),
            condition: condition.clone(),
            reached,
            lib,
            doc,
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

/// The Test Suite job's lines, 1-based and half open (`  test:` to the next job); the whole
/// text when there is no such job (a fixture of steps alone).
fn test_job(ci: &str) -> (usize, usize) {
    let lines: Vec<&str> = ci.lines().collect();
    let Some(start) = lines.iter().position(|l| *l == "  test:") else {
        return (1, lines.len() + 1);
    };
    let end = lines[start + 1..]
        .iter()
        .position(|l| {
            l.len() > 3
                && l.starts_with("  ")
                && !l.starts_with("   ")
                && l.trim_end().ends_with(':')
        })
        .map_or(lines.len(), |at| start + 1 + at);
    (start + 1, end + 1)
}

/// The plan's condition on the whole-suite step, and the reached step's.
const WHOLE: &str = "steps.plan.outputs.whole == 'true'";
const REACHED: &str = "steps.plan.outputs.whole != 'true'";

/// The cut-4 shape (#667): every test step runs on a push, a dispatch and a tag's call, and on
/// a pull request labeled `full-suite`; a pull request otherwise runs the reached set beside
/// the subset check. Each refusal one line.
fn reached_refusals(ci: &str, table: &[(String, Vec<String>)]) -> Vec<String> {
    let mut errors = Vec::new();
    let (from, to) = test_job(ci);
    let found: Vec<Step> = steps(ci, table)
        .into_iter()
        .filter(|s| (from..to).contains(&s.line))
        .collect();
    let mut flags = BTreeSet::new();
    for step in &found {
        let Some(condition) = &step.condition else {
            continue;
        };
        if step.reached {
            if !condition.starts_with(REACHED) {
                errors.push(format!(
                    "ci.yml:{}: the reached step runs under `{condition}`, not `{REACHED} && ...`",
                    step.line
                ));
            }
            continue;
        }
        let flag = condition
            .strip_prefix("steps.plan.outputs.")
            .and_then(|rest| rest.strip_suffix(" == 'true'"))
            .filter(|flag| flag.chars().all(|c| c.is_ascii_lowercase()));
        match flag {
            Some(flag) => {
                flags.insert(flag.to_owned());
            }
            None => errors.push(format!(
                "ci.yml:{}: a test step under `{condition}`; a test step runs always or under a plan flag (`steps.plan.outputs.<flag> == 'true'`)",
                step.line
            )),
        }
        if step.whole_suite && condition != WHOLE {
            errors.push(format!(
                "ci.yml:{}: the whole-suite step runs under `{condition}`, not `{WHOLE}`",
                step.line
            ));
        }
    }
    let whole_steps = found.iter().filter(|s| s.whole_suite).count();
    let reached_steps = found.iter().filter(|s| s.reached).count();
    if reached_steps > 0 && whole_steps == 0 {
        errors.push(
            "ci.yml: a reached step and no whole-suite step: a landing runs a subset".to_owned(),
        );
    }
    if flags.is_empty() && reached_steps == 0 {
        return errors;
    }
    // the plan's path for every run that is not a pull request: every flag true
    let push_path = ci
        .lines()
        .find(|line| line.contains("whole=true") && line.contains(">> \"$GITHUB_OUTPUT\""));
    match push_path {
        None => errors.push(
            "ci.yml: no plan line writes whole=true to GITHUB_OUTPUT for a run that is not a pull request".to_owned(),
        ),
        Some(line) => {
            for flag in &flags {
                if !line.split_whitespace().any(|w| w == format!("{flag}=true")) {
                    errors.push(format!(
                        "ci.yml: the plan's whole path does not set {flag}=true: a push skips that step"
                    ));
                }
            }
        }
    }
    for (needle, why) in [
        (
            "if [ \"$EVENT\" != pull_request ]; then",
            "the plan's whole path keyed on the event",
        ),
        (
            "gh api \"repos/$REPOSITORY/pulls/$PR\"",
            "the label read live through the API",
        ),
        (
            "*\",full-suite,\"*",
            "the full-suite label selecting the whole suite",
        ),
        (
            "affected_tests.py check",
            "the check that the reached set lies within the whole",
        ),
        (
            "test_affected_tests.py",
            "the plan's own tests before the plan",
        ),
        (
            "python3 -B .github/scripts/rows_from_sources.py --check",
            "the rows' Python reading checked on the tree beside the Rust guard, #708",
        ),
        (
            "python3 -B -m unittest discover -s .github/scripts -p 'test_rows_from_sources.py'",
            "the rows' writer held to the identity on a copy of the tree, the rows lane",
        ),
    ] {
        if !ci.contains(needle) {
            errors.push(format!("ci.yml: no `{needle}` ({why})"));
        }
    }
    if ci
        .lines()
        .take_while(|l| !l.starts_with("jobs:"))
        .any(|l| l.contains("labeled"))
    {
        errors.push(
            "ci.yml: a `labeled` trigger: a label starts a second run; the job reads the label live".to_owned(),
        );
    }
    errors
}

/// Speed loop three (#672): in the Test Suite job exactly one step runs the lib's unit tests (the
/// unit step's `--lib`; a whole-suite `--tests` runs them again, `--test '*'` does not, so a job
/// without the unit step runs them nowhere: the #691 fold's refusal), and the
/// steps that name binaries (`--test <name>`) and the doc step build on one feature set, so the
/// library is built once for them. Each refusal one line.
fn shared_build_refusals(ci: &str, table: &[(String, Vec<String>)]) -> Vec<String> {
    let mut errors = Vec::new();
    let (from, to) = test_job(ci);
    let found: Vec<Step> = steps(ci, table)
        .into_iter()
        .filter(|s| (from..to).contains(&s.line))
        .collect();
    let libs: Vec<&Step> = found.iter().filter(|s| s.lib).collect();
    if libs.is_empty() {
        errors.push(
            "ci.yml: no Test Suite step runs the lib's unit tests (`--lib`); a whole-suite `--test '*'` does not run them".to_owned(),
        );
    }
    for step in libs.iter().skip(1) {
        errors.push(format!(
            "ci.yml:{}: the lib's unit tests run again (ci.yml:{} runs them); a whole-suite step names `--test '*'`, not `--tests`",
            step.line, libs[0].line
        ));
    }
    let named: Vec<&Step> = found
        .iter()
        .filter(|s| s.doc || (!s.named.is_empty() && !s.reached))
        .collect();
    for step in named.iter().skip(1) {
        if step.features != named[0].features {
            errors.push(format!(
                "ci.yml:{}: builds the library on {:?}, beside ci.yml:{}'s {:?}: a second library build; the named and doc steps share one feature set",
                step.line, step.features, named[0].line, named[0].features
            ));
        }
    }
    errors
}

/// The job's name for the dependencies' level and the configuration table the step writes.
const LEVEL_NAME: &str = "CARGO_DEPENDENCIES_TEST_OPT_LEVEL";
const PACKAGE_TABLE: &str = "[profile.test.package.\"*\"]";

/// Speed loop three (#672): the Test Suite job names the dependencies' level in its `env`, and
/// a step before the cache's and before every build writes it into the cargo home's
/// configuration (cargo reads a package's profile from no environment variable; rust-cache
/// hashes every `CARGO*` variable into its key, so another level misses). Each refusal one line.
fn dependency_profile_refusals(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let (from, to) = test_job(ci);
    let lines: Vec<(usize, &str)> = ci
        .lines()
        .enumerate()
        .map(|(at, line)| (at + 1, line.trim()))
        .filter(|(number, _)| (from..to).contains(number))
        .collect();
    let env = format!("{LEVEL_NAME}: \"1\"");
    if !lines.iter().any(|(_, line)| *line == env) {
        errors.push(format!(
            "ci.yml: the Test Suite job's env does not set `{env}`"
        ));
    }
    let writer = lines.iter().find(|(_, line)| {
        line.starts_with("run: printf")
            && line.contains(PACKAGE_TABLE)
            && line.contains(&format!("\"${LEVEL_NAME}\""))
            && line.contains("config.toml")
    });
    let Some((at, _)) = writer else {
        errors.push(format!(
            "ci.yml: no Test Suite step writes `{PACKAGE_TABLE}` from `${LEVEL_NAME}` into the cargo home's config.toml"
        ));
        return errors;
    };
    for (number, line) in &lines {
        let builds = line.contains("uses: Swatinem/rust-cache@")
            || ["cargo test", "cargo nextest run", "cargo build"]
                .iter()
                .any(|run| line.contains(run) && !line.starts_with('#'));
        if builds && number < at {
            errors.push(format!(
                "ci.yml:{number}: runs before ci.yml:{at} writes the dependencies' level"
            ));
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
    let errors = reached_refusals(&ci, &feature_table(&manifest));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let errors = shared_build_refusals(&ci, &feature_table(&manifest));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let errors = dependency_profile_refusals(&ci);
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

#[test]
fn a_nextest_run_is_a_step_as_cargo_test_is() {
    let table = feature_table(MANIFEST);
    let ci = "run: cargo nextest run --lib --all-features --no-fail-fast\nrun: cargo nextest run --features \"full,http\" --tests --no-fail-fast --cargo-verbose\nrun: cargo nextest run --test memory_profiling --all-features\nrun: cargo test --doc";
    let found = steps(ci, &table);
    let whole: Vec<bool> = found.iter().map(|s| s.whole_suite).collect();
    assert_eq!(whole, [false, true, false, false]);
    assert!(found[1].features.contains("wallet") && found[1].features.contains("http"));
    assert_eq!(found[2].named, ["memory_profiling"]);
    let files = [
        file("a", ""),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
        file("wire_tracing_sink", "#![cfg(feature = \"tracing\")]"),
    ];
    let errors = refusals(ci, MANIFEST, &files);
    assert_eq!(
        errors,
        ["tests/wire_tracing_sink.rs: allowlisted as run apart by `--test wire_tracing_sink`, but no ci.yml step runs that on a feature set that compiles it"]
    );
}

/// The cut-4 workflow's test steps, in ci.yml's form (#667).
const REACHED_CI: &str = r#"
      - name: Plan the targets the change reaches
        run: |
          if [ "$EVENT" != pull_request ]; then
            printf '%s\n' whole=true lib=true doc=true memory=true tracing=true >> "$GITHUB_OUTPUT"
          fi
          python3 -B -m unittest discover -s .github/scripts -p 'test_affected_tests.py'
          python3 -B .github/scripts/rows_from_sources.py --check
          python3 -B -m unittest discover -s .github/scripts -p 'test_rows_from_sources.py'
          labels=$(gh api "repos/$REPOSITORY/pulls/$PR" --jq '[.labels[].name] | join(",")')
          if [[ ",$labels," == *",full-suite,"* ]]; then
      - name: Check the reached set within the whole
        run: python3 -B .github/scripts/affected_tests.py check --plan p --metadata m
      - name: Run unit tests
        if: steps.plan.outputs.lib == 'true'
        run: cargo nextest run --lib --all-features
      - name: Run every integration test
        if: steps.plan.outputs.whole == 'true'
        run: cargo nextest run --features "full,http" --tests --no-fail-fast
      - name: Run the integration tests the change reaches
        if: steps.plan.outputs.whole != 'true' && steps.plan.outputs.reached != '0'
        run: cargo nextest run --features "full,http" $REACHED_TESTS --no-fail-fast
      - name: Run the memory profiling tests
        if: steps.plan.outputs.memory == 'true'
        run: cargo nextest run --test memory_profiling --all-features
"#;

#[test]
fn a_reached_step_is_no_whole_suite_step_and_the_plan_shape_passes() {
    let table = feature_table(MANIFEST);
    let found = steps(REACHED_CI, &table);
    let reached: Vec<bool> = found.iter().map(|s| s.reached).collect();
    let whole: Vec<bool> = found.iter().map(|s| s.whole_suite).collect();
    assert_eq!(reached, [false, false, true, false]);
    assert_eq!(whole, [false, true, false, false]);
    assert_eq!(found[1].condition.as_deref(), Some(WHOLE));
    assert_eq!(reached_refusals(REACHED_CI, &table), Vec::<String>::new());
    let files = [
        file("a", ""),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
        file("wire_tracing_sink", "#![cfg(feature = \"tracing\")]"),
    ];
    let traced = format!(
        "{REACHED_CI}      - name: Run the tracing sink tests\n        if: steps.plan.outputs.tracing == 'true'\n        run: cargo nextest run --features \"full,tracing\" --test wire_tracing_sink\n"
    );
    assert_eq!(refusals(&traced, MANIFEST, &files), Vec::<String>::new());
    assert_eq!(reached_refusals(&traced, &table), Vec::<String>::new());
    // outside the Test Suite job, another job's conditional cargo step is not judged
    let jobs = format!("jobs:\n  test:\n{traced}  checks:\n    steps:\n      - name: x\n        if: always()\n        run: cargo test --doc\n");
    assert_eq!(reached_refusals(&jobs, &table), Vec::<String>::new());
}

#[test]
fn a_landing_or_a_push_that_could_run_a_subset_is_refused() {
    let table = feature_table(MANIFEST);
    // the whole-suite step under another condition: a push would skip it
    let other = REACHED_CI.replace(
        "if: steps.plan.outputs.whole == 'true'",
        "if: github.event_name == 'push'",
    );
    assert!(reached_refusals(&other, &table)
        .iter()
        .any(|e| e.contains("the whole-suite step runs under")));
    // the plan's push path leaving a flag false
    let skipped = REACHED_CI.replace(" memory=true", "");
    assert_eq!(
        reached_refusals(&skipped, &table),
        ["ci.yml: the plan's whole path does not set memory=true: a push skips that step"]
    );
    // no subset check, no live label read, a labeled trigger
    let unchecked = REACHED_CI.replace("affected_tests.py check", "affected_tests.py");
    assert!(reached_refusals(&unchecked, &table)
        .iter()
        .any(|e| e.contains("lies within the whole")));
    // the rows' two readings left unchecked against each other on the tree (#708)
    let undrifted = REACHED_CI.replace("rows_from_sources.py --check", "rows_from_sources.py");
    assert_eq!(
        reached_refusals(&undrifted, &table),
        ["ci.yml: no `python3 -B .github/scripts/rows_from_sources.py --check` (the rows' Python reading checked on the tree beside the Rust guard, #708)"]
    );
    // the writer's identity on the tree left unrun (the rows lane)
    let unheld = REACHED_CI.replace("'test_rows_from_sources.py'", "'test_rows.py'");
    assert_eq!(
        reached_refusals(&unheld, &table),
        ["ci.yml: no `python3 -B -m unittest discover -s .github/scripts -p 'test_rows_from_sources.py'` (the rows' writer held to the identity on a copy of the tree, the rows lane)"]
    );
    let unlabeled = REACHED_CI.replace("full-suite", "full");
    assert!(reached_refusals(&unlabeled, &table)
        .iter()
        .any(|e| e.contains("full-suite label")));
    let triggered =
        format!("on:\n  pull_request:\n    types: [opened, labeled]\njobs:\n{REACHED_CI}");
    assert!(reached_refusals(&triggered, &table)
        .iter()
        .any(|e| e.contains("a `labeled` trigger")));
    // a reached step and no whole-suite step
    let subset_only = REACHED_CI.replace(
        "run: cargo nextest run --features \"full,http\" --tests --no-fail-fast",
        "run: echo none",
    );
    assert!(reached_refusals(&subset_only, &table)
        .iter()
        .any(|e| e.contains("a landing runs a subset")));
}

#[test]
fn the_lib_runs_once_and_the_named_steps_share_one_build() {
    let table = feature_table(MANIFEST);
    let ci = "run: cargo nextest run --lib --all-features\nrun: cargo nextest run --features \"full,http\" --test '*' --no-fail-fast\nrun: cargo nextest run --test memory_profiling --all-features\nrun: cargo nextest run --all-features --test wire_tracing_sink\nrun: cargo test --doc --all-features";
    let found = steps(ci, &table);
    let whole: Vec<bool> = found.iter().map(|s| s.whole_suite).collect();
    assert_eq!(whole, [false, true, false, false, false]);
    let lib: Vec<bool> = found.iter().map(|s| s.lib).collect();
    assert_eq!(lib, [true, false, false, false, false]);
    assert!(found[1].named.is_empty());
    assert!(shared_build_refusals(ci, &table).is_empty());
    let files = [
        file("a", ""),
        file("memory_profiling", "#![cfg(feature = \"dhat-profiling\")]"),
        file("wire_tracing_sink", "#![cfg(feature = \"tracing\")]"),
    ];
    assert!(refusals(ci, MANIFEST, &files).is_empty());

    // `--tests` runs the lib's unit target a second time
    let twice = ci.replace("--test '*'", "--tests");
    let errors = shared_build_refusals(&twice, &table);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].starts_with("ci.yml:2: the lib's unit tests run again (ci.yml:1 runs them)"));

    // without the unit step `--test '*'` runs the lib's unit tests nowhere (the #691 fold)
    let nowhere = ci.replace("run: cargo nextest run --lib --all-features\n", "");
    let errors = shared_build_refusals(&nowhere, &table);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].starts_with("ci.yml: no Test Suite step runs the lib's unit tests"));

    // the tracing step on its own feature set builds the library a second time
    let apart = ci.replace(
        "--all-features --test wire_tracing_sink",
        "--features \"full,tracing\" --test wire_tracing_sink",
    );
    let errors = shared_build_refusals(&apart, &table);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].starts_with("ci.yml:4: builds the library on"));
}

#[test]
fn the_dependencies_level_is_written_before_the_cache_and_every_build() {
    let ci = r#"  test:
    env:
      CARGO_DEPENDENCIES_TEST_OPT_LEVEL: "1"
    steps:
      - name: Optimize the dependencies in the test profile
        run: printf '[profile.test.package."*"]\nopt-level = %s\n' "$CARGO_DEPENDENCIES_TEST_OPT_LEVEL" >> "${CARGO_HOME:-$HOME/.cargo}/config.toml"
      - uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3
      - run: cargo nextest run --lib --all-features
"#;
    assert!(dependency_profile_refusals(ci).is_empty());

    let unnamed = ci.replace("CARGO_DEPENDENCIES_TEST_OPT_LEVEL: \"1\"", "OTHER: \"1\"");
    let errors = dependency_profile_refusals(&unnamed);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("does not set `CARGO_DEPENDENCIES_TEST_OPT_LEVEL: \"1\"`"));

    let unwritten = ci.replace("[profile.test.package.\"*\"]", "[profile.test]");
    let errors = dependency_profile_refusals(&unwritten);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].starts_with("ci.yml: no Test Suite step writes"));

    let lines: Vec<&str> = ci.lines().collect();
    let late = [&lines[..4], &lines[6..7], &lines[4..6], &lines[7..]]
        .concat()
        .join("\n");
    let errors = dependency_profile_refusals(&late);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with("ci.yml:5: runs before ci.yml:7 writes"),
        "{errors:?}"
    );
}
