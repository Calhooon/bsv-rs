//! The node oracle's judge, as built on beta with nothing fired (#97; the two-stage judge decided
//! 2026-11-10, the three design reads of 2026-11-12): what the judge rests on that a file of this
//! tree can break, read at the string level (no network, no environment).
//!
//! `tests/sibling/PIN` is one line of 40 lower-case hex digits and equals `column.json`'s
//! `sibling`; no workflow names `pull_request_target`; no job of any workflow has the id or the
//! `name:` `sibling-judge` (the check is the App's alone, reported by `sibling_judge.py report`);
//! `sibling_judge.py` imports the standard library alone and loads `sibling_harness.py` by its
//! file path, with no `sys.path` write, no `extractall` and no `download-artifact`; no
//! `include_str!`, `include_bytes!` or `include!` under `src/` or in `build.rs` names
//! `CHANGELOG.md`, a path under `docs/` or a `CLAUDE.md` (what makes the judge's class N, words
//! no verdict reads, a class that cannot move a verdict); and `REQUIRED_ON_MAIN` of
//! `tests/arch_ci_pr_runs_the_required_set.rs` never names `sibling-judge` (a pull request into
//! main gets no such check, so main's protection must never require it). Each refusal is shown
//! on a mutated text. Not read: a job whose id or name is written as an expression, an import
//! made by `__import__` or `importlib.import_module` (refused by name), an include whose path is
//! built by a macro other than `concat!`.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(root().join(path))
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("\r\n", "\n")
}

/// The pin's file: 40 lower-case hex digits and a newline, equal to the column's `sibling`.
fn pin_refusals(pin: &str, column: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let digits = pin.strip_suffix('\n').unwrap_or("");
    if digits.len() != 40
        || !digits
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        errors.push(format!(
            "tests/sibling/PIN is not 40 lower-case hex digits and a newline: {pin:?}"
        ));
    }
    let named = column
        .lines()
        .find_map(|l| l.trim().strip_prefix("\"sibling\": \""))
        .and_then(|rest| rest.split('"').next());
    if named != Some(digits) {
        errors.push(format!(
            "tests/sibling/column.json's `sibling` is {named:?}, the PIN {digits:?}: the column is recorded at the pin"
        ));
    }
    errors
}

/// The workflows by file name.
fn workflows() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(root().join(".github/workflows"))
        .expect("the workflows")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .map(|n| {
            let text = read(&format!(".github/workflows/{n}"));
            (n, text)
        })
        .collect();
    out.sort();
    out
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// No workflow names `pull_request_target`, and no job has the id or `name:` `sibling-judge`.
fn workflow_refusals(file: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut in_jobs = false;
    for (number, line) in text.lines().enumerate() {
        let n = number + 1;
        let body = line.split(" #").next().unwrap_or(line);
        if !line.trim_start().starts_with('#') && body.contains("pull_request_target") {
            errors.push(format!(
                "{file}:{n} names `pull_request_target`: refused (#97)"
            ));
        }
        if indent(line) == 0 && !line.trim().is_empty() && !line.starts_with('#') {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        let trimmed = line.trim();
        if indent(line) == 2
            && trimmed.trim_end_matches(':').trim_matches(['\'', '"']) == "sibling-judge"
        {
            errors.push(format!(
                "{file}:{n} has a job with the id `sibling-judge`: no Actions job may report the App's check"
            ));
        }
        if indent(line) == 4 {
            if let Some(name) = trimmed.strip_prefix("name:") {
                if name.trim().trim_matches(['\'', '"']) == "sibling-judge" {
                    errors.push(format!(
                        "{file}:{n} has a job named `sibling-judge`: no Actions job may report the App's check"
                    ));
                }
            }
        }
    }
    errors
}

/// The standard modules `sibling_judge.py` may import, and nothing else; `sibling_harness.py` by
/// its path.
const STANDARD: &[&str] = &[
    "argparse",
    "base64",
    "importlib.util",
    "io",
    "json",
    "os",
    "pathlib",
    "re",
    "shutil",
    "subprocess",
    "sys",
    "tempfile",
    "zipfile",
];

fn judge_script_refusals(source: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for (number, line) in source.lines().enumerate() {
        let n = number + 1;
        let code = line.trim_start();
        let module = code
            .strip_prefix("import ")
            .map(|rest| rest.split(" as ").next().unwrap_or(rest))
            .or_else(|| {
                code.strip_prefix("from ")
                    .and_then(|rest| rest.split(" import ").next())
            });
        if let Some(module) = module {
            for one in module.split(',').map(str::trim) {
                if !STANDARD.contains(&one) {
                    errors.push(format!(
                        "sibling_judge.py:{n} imports `{one}`: the standard library alone, and sibling_harness.py by its path"
                    ));
                }
            }
        }
        for (word, why) in [
            ("__import__", "an import by name"),
            ("import_module", "an import by name"),
            (
                "extractall",
                "the artifact is read in memory by its allowlist, never extracted",
            ),
            (
                "download-artifact",
                "the artifact is taken by `gh api` alone",
            ),
        ] {
            if line.contains(word) {
                errors.push(format!("sibling_judge.py:{n} carries `{word}`: {why}"));
            }
        }
        let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if ["sys.path.", "sys.path=", "sys.path[", "sys.path+="]
            .iter()
            .any(|w| squeezed.contains(w))
        {
            errors.push(format!(
                "sibling_judge.py:{n} writes `sys.path`: .github/scripts is never put on it"
            ));
        }
    }
    if !source
        .contains("spec_from_file_location(\"sibling_harness\", HERE / \"sibling_harness.py\")")
    {
        errors
            .push("sibling_judge.py does not load sibling_harness.py by its file path".to_string());
    }
    errors
}

/// Every `include_str!`, `include_bytes!` and `include!` of a file, its argument to the closing
/// parenthesis (across lines), refused when it names `CHANGELOG.md`, `docs/` or `CLAUDE.md`.
fn include_refusals(file: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for macro_name in ["include_str!", "include_bytes!", "include!"] {
        let mut from = 0;
        while let Some(at) = text[from..].find(macro_name) {
            let start = from + at;
            from = start + macro_name.len();
            let rest = &text[from..];
            let Some(open) = rest.find('(') else { continue };
            if rest[..open].trim() != "" {
                continue;
            }
            let mut depth = 0usize;
            let mut end = rest.len();
            for (i, c) in rest.char_indices().skip(open) {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let argument = &rest[open..end];
            if ["CHANGELOG.md", "docs/", "CLAUDE.md"]
                .iter()
                .any(|w| argument.contains(w))
            {
                let line = text[..start].matches('\n').count() + 1;
                errors.push(format!(
                    "{file}:{line}: {macro_name}{}) names a file of class N; words no verdict reads must stay unread by the crate",
                    argument.replace('\n', " ")
                ));
            }
        }
    }
    errors
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `REQUIRED_ON_MAIN`'s body never names `sibling-judge`.
fn main_refusals(required_set: &str) -> Vec<String> {
    let Some(start) = required_set.find("const REQUIRED_ON_MAIN: &[&str] = &[") else {
        return vec!["no `REQUIRED_ON_MAIN` in arch_ci_pr_runs_the_required_set.rs".to_string()];
    };
    let body = &required_set[start..];
    let body = &body[..body.find("];").unwrap_or(body.len())];
    if body.contains("\"sibling-judge\"") {
        return vec![
            "REQUIRED_ON_MAIN names `sibling-judge`: a pull request into main gets no such check"
                .to_string(),
        ];
    }
    Vec::new()
}

#[test]
fn the_pin_is_forty_hex_digits_and_the_columns_sibling_97() {
    let pin = read("tests/sibling/PIN");
    let column = read("tests/sibling/column.json");
    let errors = pin_refusals(&pin, &column);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let digits = pin.trim_end();
    for (what, planted) in [
        ("upper case", format!("{}\n", digits.to_uppercase())),
        ("no newline", digits.to_string()),
        ("39 digits", format!("{}\n", &digits[..39])),
        ("two lines", format!("{digits}\n{digits}\n")),
    ] {
        assert!(
            pin_refusals(&planted, &column)
                .iter()
                .any(|e| e.contains("not 40 lower-case hex digits")),
            "{what}: not refused"
        );
    }
    let other = column.replacen(digits, &"0".repeat(40), 1);
    assert_eq!(
        pin_refusals(&pin, &other),
        [format!("tests/sibling/column.json's `sibling` is Some(\"{}\"), the PIN \"{digits}\": the column is recorded at the pin", "0".repeat(40))]
    );
}

#[test]
fn no_workflow_names_pull_request_target_or_a_sibling_judge_job_97() {
    let mut errors = Vec::new();
    for (file, text) in workflows() {
        errors.extend(workflow_refusals(&file, &text));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let base =
        "name: x\non:\n  pull_request:\njobs:\n  a:\n    name: a\n    runs-on: ubuntu-latest\n";
    assert!(workflow_refusals("x.yml", base).is_empty());
    let target = base.replace("  pull_request:\n", "  pull_request_target:\n");
    assert_eq!(
        workflow_refusals("x.yml", &target),
        ["x.yml:3 names `pull_request_target`: refused (#97)"]
    );
    let by_id = format!("{base}  sibling-judge:\n    runs-on: ubuntu-latest\n");
    assert_eq!(
        workflow_refusals("x.yml", &by_id),
        ["x.yml:8 has a job with the id `sibling-judge`: no Actions job may report the App's check"]
    );
    let by_name = base.replace("    name: a\n", "    name: 'sibling-judge'\n");
    assert_eq!(
        workflow_refusals("x.yml", &by_name),
        ["x.yml:6 has a job named `sibling-judge`: no Actions job may report the App's check"]
    );
    // the workflow's own name, at the top, is no job's
    let workflow_name = base.replace("name: x\n", "name: sibling-judge\n");
    assert!(workflow_refusals("x.yml", &workflow_name).is_empty());
}

#[test]
fn the_judge_imports_the_standard_library_and_the_harness_by_path_alone_97() {
    let source = read(".github/scripts/sibling_judge.py");
    let errors = judge_script_refusals(&source);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let plants = [
        ("import requests\n", "imports `requests`"),
        ("import sibling_harness\n", "imports `sibling_harness`"),
        ("from json import loads\nimport yaml\n", "imports `yaml`"),
        ("sys.path.insert(0, str(HERE))\n", "writes `sys.path`"),
        ("sys.path = [str(HERE)]\n", "writes `sys.path`"),
        ("archive.extractall(dest)\n", "carries `extractall`"),
        (
            "# uses: actions/download-artifact@v4\n",
            "carries `download-artifact`",
        ),
        ("module = __import__('json')\n", "carries `__import__`"),
    ];
    for (planted, refusal) in plants {
        let text = format!("{source}{planted}");
        assert!(
            judge_script_refusals(&text)
                .iter()
                .any(|e| e.contains(refusal)),
            "{planted:?}: not refused"
        );
    }
    let by_name = source.replace(
        "spec_from_file_location(\"sibling_harness\", HERE / \"sibling_harness.py\")",
        "spec_from_file_location(\"sibling_harness\", \"sibling_harness.py\")",
    );
    assert!(judge_script_refusals(&by_name)
        .iter()
        .any(|e| e.contains("does not load sibling_harness.py by its file path")));
}

#[test]
fn no_include_under_src_or_in_build_rs_names_a_file_of_class_n_97() {
    let mut files = vec![root().join("build.rs")];
    rust_files(&root().join("src"), &mut files);
    let mut errors = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path)
            .expect("a source")
            .replace("\r\n", "\n");
        let name = path
            .strip_prefix(root())
            .unwrap_or(path)
            .display()
            .to_string();
        errors.extend(include_refusals(&name, &text));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    assert!(files.len() > 100, "the walk found {} files", files.len());
    for planted in [
        "const C: &str = include_str!(\"../CHANGELOG.md\");\n",
        "#![doc = include_str!(\n    \"../docs/ARCHITECTURE.md\"\n)]\n",
        "const B: &[u8] = include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/script/CLAUDE.md\"));\n",
        "include!(\"../docs/x.rs\");\n",
    ] {
        let errors = include_refusals("src/x.rs", planted);
        assert_eq!(errors.len(), 1, "{planted:?}: {errors:?}");
        assert!(errors[0].starts_with("src/x.rs:1: include"), "{errors:?}");
    }
    assert!(include_refusals(
        "src/x.rs",
        "const V: &str = include_str!(\"../tests/vectors/a.json\");\n"
    )
    .is_empty());
}

#[test]
fn mains_required_set_never_names_the_judges_check_97() {
    let text = read("tests/arch_ci_pr_runs_the_required_set.rs");
    assert!(main_refusals(&text).is_empty());
    let planted = text.replacen(
        "const REQUIRED_ON_MAIN: &[&str] = &[\n",
        "const REQUIRED_ON_MAIN: &[&str] = &[\n    \"sibling-judge\",\n",
        1,
    );
    assert_ne!(
        planted, text,
        "the constant's opening line is where the plant goes"
    );
    assert_eq!(
        main_refusals(&planted),
        ["REQUIRED_ON_MAIN names `sibling-judge`: a pull request into main gets no such check"]
    );
    // beta's set may name it, after the witnesses and the soak (the owner's word of 2026-11-12)
    let beta = text.replacen(
        "const REQUIRED_ON_BETA: &[&str] = &[\n",
        "const REQUIRED_ON_BETA: &[&str] = &[\n    \"sibling-judge\",\n",
        1,
    );
    assert!(main_refusals(&beta).is_empty());
}
