//! The node oracle's judge, built on beta by the judge lane and wired by the second (#97; the two-stage judge decided
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
//! main gets no such check, so main's protection must never require it). The wiring lane adds:
//! `.github/workflows/sibling-run.yml` (stage R) and `.github/workflows/sibling-judge.yml` (the
//! trampoline) pinned whole, byte for byte, a failure naming the file's line, the pinned line and
//! the line found; beside the bytes each workflow's named rules ([`run_refusals`],
//! [`judge_refusals`]) say why a change matters; and across the tree the App's key expression is
//! written once (the token step), the environment `sibling-judge` and `workflow_run` in no other
//! workflow ([`tree_refusals`]; this file, which holds the trampoline's pin, is passed over and
//! builds its needle with `concat!`). Each refusal is shown
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
    "datetime",
    "importlib.util",
    "io",
    "json",
    "os",
    "pathlib",
    "re",
    "shlex",
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

// ---- The wiring (#97, the second lane): stage R and stage J, pinned whole and by named rules ----

/// The file `.github/workflows/sibling-run.yml`, byte for byte: a change to it is a change to this
/// test in the same diff (both are class J, so the judge holds them together).
const SIBLING_RUN: &str = r##"name: sibling-run
run-name: sibling-run ${{ github.event.pull_request.head.sha || github.sha }}

# The node oracle's judge, stage R (#97; tests/sibling/CLAUDE.md, "The judge"; RELEASING.md step
# 25): the one job a pull request into beta runs outside ci.yml. It builds the head's crate against
# the sibling at the head's own pin and runs beta's `sibling_harness.py raw` on it, with no secret,
# no environment and no write: it judges nothing and uploads the raw output as `sibling-raw`, which
# sibling-judge.yml, on main, reads with beta's files and reports as the App's check
# `sibling-judge`. It runs on every pull request into beta and on a dispatch (the sync's on its
# branch, a re-drive by hand), with no path filter and no condition but the upload's: a skipped
# stage R would be a run without an artifact. A run that reached a verdict ends success whatever
# the verdict; a crate that does not build ends failure with no artifact. ci.yml's `sibling` stays.
on:
  pull_request:
    branches: [beta]
  workflow_dispatch:

permissions:
  contents: read

# keyed as ci.yml is: a newer push to the same pull request or ref cancels the run it supersedes
concurrency:
  group: sibling-run-${{ github.event_name }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  raw:
    name: raw
    runs-on: ubuntu-latest
    timeout-minutes: 15
    env:
      CARGO_TARGET_DIR: ${{ github.workspace }}/sibling-target
    steps:
      # the head itself, never the merge ref: the judge reads the head's PIN and column by its sha
      - name: Check out the head
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          path: head
          persist-credentials: false

      # beta's scripts run on the head's tree: the head's own .github/scripts is never executed
      - name: Check out beta
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          ref: refs/heads/beta
          path: judge
          persist-credentials: false

      # the head's pin, never beta's: a pull request that moves the pin is run at its own
      - name: Read the head's pin
        id: pin
        shell: bash
        run: |
          set -euo pipefail
          pin="$(cat head/tests/sibling/PIN)"
          printf '%s\n' "$pin" | cmp -s - head/tests/sibling/PIN
          [[ "$pin" =~ ^[0-9a-f]{40}$ ]]
          echo "sibling=$pin" >> "$GITHUB_OUTPUT"

      # the harness, the pins it reads and the nine corpora (ci.yml's `sibling` list), nothing else
      - name: Check out the sibling at the pin
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          repository: Calhooon/bsv-script-lean
          ref: ${{ steps.pin.outputs.sibling }}
          path: sibling
          persist-credentials: false
          sparse-checkout-cone-mode: false
          sparse-checkout: |
            /harness/
            /docs/PROVENANCE.md
            /corpus/seed/
            /corpus/flow/
            /corpus/arith/
            /corpus/stack/
            /corpus/crypto/
            /corpus/bytes/
            /corpus/eras/
            /corpus/gen/
            /corpus/tx/

      # the harness's own toolchain file (`harness/rust-toolchain.toml`) names 1.95.0
      - name: Install Rust
        uses: dtolnay/rust-toolchain@e2a55d2ffb04f378e9626c28d38b36d230d1e12f # v1
        with:
          toolchain: 1.95.0

      # beta's push run of ci.yml's `sibling` saves this cache; a pull request's head never does
      - name: Restore the harness's build
        uses: Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3
        with:
          shared-key: sibling
          workspaces: sibling/harness -> ../../sibling-target
          save-if: false

      # the raw output and its stamp, then the allowlist's members alone into the upload's folder
      - name: raw
        shell: bash
        env:
          PIN: ${{ steps.pin.outputs.sibling }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}
          PULL_REQUEST: ${{ github.event.pull_request.number }}
        run: |
          set -euo pipefail
          test "$(git -C sibling rev-parse HEAD)" = "$PIN"
          python3 -I -B judge/.github/scripts/sibling_harness.py raw --tree head --sibling sibling \
            --corpus all --scratch "$RUNNER_TEMP/sibling-scratch" --out "$RUNNER_TEMP/sibling-out" \
            --head-sha "$HEAD_SHA" --pull-request "$PULL_REQUEST"
          python3 -I -B judge/.github/scripts/sibling_judge.py members > "$RUNNER_TEMP/sibling-members.txt"
          mkdir "$RUNNER_TEMP/sibling-raw"
          while IFS= read -r name; do
            if [ -f "$RUNNER_TEMP/sibling-out/$name" ] && [ ! -L "$RUNNER_TEMP/sibling-out/$name" ]; then
              mkdir -p "$(dirname "$RUNNER_TEMP/sibling-raw/$name")"
              cp "$RUNNER_TEMP/sibling-out/$name" "$RUNNER_TEMP/sibling-raw/$name"
            fi
          done < "$RUNNER_TEMP/sibling-members.txt"

      # a re-run replaces its earlier attempt's artifact (`overwrite`); 30 days, past which no run
      # can be re-run, so a longer life serves no re-drive
      - name: Upload the raw output
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: sibling-raw
          path: ${{ runner.temp }}/sibling-raw
          if-no-files-found: error
          retention-days: 30
          overwrite: true
"##;

/// The file `.github/workflows/sibling-judge.yml` (the trampoline main takes by pick), byte for
/// byte.
const SIBLING_JUDGE: &str = r##"name: sibling-judge
run-name: sibling-judge ${{ github.event.workflow_run.head_sha || format('of run {0}', inputs.run_id) }}

# The node oracle's judge, stage J (#97; tests/sibling/CLAUDE.md, "The judge"; RELEASING.md step
# 25). This file is the trampoline: it lives on main and on beta, byte for byte, and holds no rule.
# It runs from main alone (each job tests the ref, and the environment `sibling-judge` admits main
# alone), checks beta out to `judge/` and runs beta's `sibling_judge.py`: `judge`, holding no key,
# reads stage R's run and its artifact and writes four outputs; `report`, the one job holding the
# App's token (`bsv-rs-sibling-judge`), posts the check `sibling-judge` on the run's head and never
# opens the artifact. A change to this file is one sitting with the queue held: beta's pull
# request, main's pick, then the sweep and one re-judge dispatch for each open pull request.
on:
  workflow_run:
    workflows: [sibling-run]
    types: [completed]
  # the re-judge of one stage R run: gh workflow run sibling-judge.yml --ref main -f run_id=<run>
  workflow_dispatch:
    inputs:
      run_id:
        description: The id of a completed sibling-run run, judged again
        required: true
        type: string

permissions:
  contents: read

# one group per judged head (a re-judge by the run's id): every judgement of a head runs, in order,
# none cancelled, so an older judge cannot finish last on a live head and none is dropped
concurrency:
  group: sibling-judge-${{ github.event.workflow_run.head_sha || inputs.run_id }}
  cancel-in-progress: false

jobs:
  judge:
    name: judge
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      actions: read
      contents: read
      pull-requests: read
    outputs:
      post: ${{ steps.judge.outputs.post }}
      conclusion: ${{ steps.judge.outputs.conclusion }}
      title: ${{ steps.judge.outputs.title }}
      text: ${{ steps.judge.outputs.text }}
    steps:
      - name: Check out beta
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          ref: refs/heads/beta
          path: judge
          fetch-depth: 0
          persist-credentials: false

      - name: Judge
        id: judge
        env:
          GH_TOKEN: ${{ github.token }}
          RUN_ID: ${{ github.event.workflow_run.id || inputs.run_id }}
          ATTEMPT: ${{ github.event.workflow_run.run_attempt }}
          REPOSITORY_ID: ${{ github.repository_id }}
          WORKFLOW_SHA: ${{ github.workflow_sha }}
        run: |
          set -euo pipefail
          [[ "$RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]]
          attempt=()
          if [ -n "$ATTEMPT" ]; then attempt=(--attempt "$ATTEMPT"); fi
          python3 -I -B judge/.github/scripts/sibling_judge.py judge --judge judge --run-id "$RUN_ID" \
            "${attempt[@]}" --repository "$GITHUB_REPOSITORY" --repository-id "$REPOSITORY_ID" \
            --workflow-sha "$WORKFLOW_SHA"

  report:
    name: report
    needs: judge
    if: always() && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    environment: sibling-judge
    permissions:
      actions: read
      contents: read
      pull-requests: read
    steps:
      - name: Check out beta
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          ref: refs/heads/beta
          path: judge
          fetch-depth: 0
          persist-credentials: false

      - name: Mint the App's token
        id: token
        uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0
        with:
          app-id: ${{ vars.SIBLING_JUDGE_APP_ID }}
          private-key: ${{ secrets.SIBLING_JUDGE_KEY }}
          permission-checks: write

      - name: Report
        env:
          GH_TOKEN: ${{ steps.token.outputs.token }}
          RUN_ID: ${{ github.event.workflow_run.id || inputs.run_id }}
          ATTEMPT: ${{ github.event.workflow_run.run_attempt }}
          REPOSITORY_ID: ${{ github.repository_id }}
          APP_ID: ${{ vars.SIBLING_JUDGE_APP_ID }}
          JUDGE_RESULT: ${{ needs.judge.result }}
          POST: ${{ needs.judge.outputs.post }}
          CONCLUSION: ${{ needs.judge.outputs.conclusion }}
          TITLE: ${{ needs.judge.outputs.title }}
          TEXT: ${{ needs.judge.outputs.text }}
          DETAILS_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: |
          set -euo pipefail
          [[ "$RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]]
          attempt=()
          if [ -n "$ATTEMPT" ]; then attempt=(--attempt "$ATTEMPT"); fi
          python3 -I -B judge/.github/scripts/sibling_judge.py report --run-id "$RUN_ID" "${attempt[@]}" \
            --repository "$GITHUB_REPOSITORY" --repository-id "$REPOSITORY_ID" --app-id "$APP_ID" \
            --judge-result "$JUDGE_RESULT" --details-url "$DETAILS_URL"
"##;

/// The first difference of `found` from `pinned`, or `None` when they are equal byte for byte:
/// the file's line, the pinned line and the line found, each quoted so a space or a tab shows.
fn first_difference(file: &str, pinned: &str, found: &str) -> Option<String> {
    if found == pinned {
        return None;
    }
    let expected: Vec<&str> = pinned.split('\n').collect();
    let got: Vec<&str> = found.split('\n').collect();
    let at = got
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| got.len().min(expected.len()));
    let shown = |l: Option<&&str>| l.map_or("<end>".to_string(), |l| format!("{l:?}"));
    Some(format!(
        "{file} is not its pin byte for byte (a change to it is a change to this test in the same diff): line {}\n  expected: {}\n  found:    {}",
        at + 1,
        shown(expected.get(at)),
        shown(got.get(at))
    ))
}

/// A line's text with a trailing ` # comment` cut and the indent kept; a comment line is empty.
fn code(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    line.split(" #").next().unwrap_or(line).trim_end()
}

/// The top-level block opened by `key:`: the lines under it, comment lines dropped.
fn top_block<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let open = format!("{key}:");
    let mut lines = text.lines().skip_while(|l| code(l) != open);
    if lines.next().is_none() {
        return Vec::new();
    }
    lines
        .map(code)
        .filter(|l| !l.is_empty())
        .take_while(|l| indent(l) > 0)
        .collect()
}

/// The jobs: (id, the job's lines, comment lines dropped), in order.
fn jobs(text: &str) -> Vec<(String, Vec<&str>)> {
    let mut out: Vec<(String, Vec<&str>)> = Vec::new();
    for line in top_block(text, "jobs") {
        if indent(line) == 2 {
            out.push((line.trim().trim_end_matches(':').to_string(), Vec::new()));
        } else if let Some((_, lines)) = out.last_mut() {
            lines.push(line);
        }
    }
    out
}

/// A job's steps: each step's lines, from its `- ` line to the next.
fn steps<'a>(job: &[&'a str]) -> Vec<Vec<&'a str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    let mut inside = false;
    for line in job {
        if indent(line) == 4 {
            inside = line.trim() == "steps:";
            continue;
        }
        if !inside {
            continue;
        }
        if indent(line) == 6 && line.trim_start().starts_with("- ") {
            out.push(vec![*line]);
        } else if let Some(step) = out.last_mut() {
            step.push(*line);
        }
    }
    out
}

/// A step's own key (`uses`, `name`, `if`, ...) read at the step's own level.
fn step_key<'a>(step: &[&'a str], key: &str) -> Option<&'a str> {
    let open = format!("{key}:");
    step.iter().find_map(|l| {
        let k = l.trim_start().trim_start_matches("- ");
        (indent(l) <= 8)
            .then(|| k.strip_prefix(&open))
            .flatten()
            .map(str::trim)
    })
}

/// A step's `with:` input, as written.
fn with_input<'a>(step: &[&'a str], input: &str) -> Option<&'a str> {
    let open = format!("{input}:");
    step.iter()
        .find_map(|l| {
            (indent(l) == 10)
                .then(|| l.trim().strip_prefix(&open))
                .flatten()
        })
        .map(str::trim)
}

/// A job's own key at the job's level (4 spaces).
fn job_key<'a>(job: &[&'a str], key: &str) -> Option<&'a str> {
    let open = format!("{key}:");
    job.iter()
        .find_map(|l| {
            (indent(l) == 4)
                .then(|| l.trim().strip_prefix(&open))
                .flatten()
        })
        .map(str::trim)
}

/// A job's `permissions:` lines, sorted.
fn job_permissions(job: &[&str]) -> Vec<String> {
    let mut lines = job
        .iter()
        .skip_while(|l| !(indent(l) == 4 && l.trim() == "permissions:"));
    if lines.next().is_none() {
        return Vec::new();
    }
    let mut out: Vec<String> = lines
        .take_while(|l| indent(l) > 4)
        .map(|l| l.trim().to_string())
        .collect();
    out.sort();
    out
}

/// Every `${{` inside a `run:` block, by its line.
fn expressions_in_run(file: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let mut block: Option<usize> = None;
    for (number, line) in text.lines().enumerate() {
        let n = number + 1;
        if let Some(at) = block {
            if line.trim().is_empty() || indent(line) > at {
                if line.contains("${{") {
                    errors.push(format!("{file}:{n}: an expression inside a `run:` block; it travels through `env:`"));
                }
                continue;
            }
            block = None;
        }
        let key = line.trim_start().trim_start_matches("- ");
        if let Some(rest) = key.strip_prefix("run:") {
            let rest = rest.trim();
            if rest.starts_with('|') || rest.starts_with('>') {
                block = Some(indent(line));
            } else if rest.contains("${{") {
                errors.push(format!(
                    "{file}:{n}: an expression inside a `run:` line; it travels through `env:`"
                ));
            }
        }
    }
    errors
}

/// Stage R's named rules (#97: decided 2026-11-10, the design reads of 2026-11-12, the brief's
/// [b04], [b06], [b07], [b16], [b19], and lane 1's reads' R2 and row).
fn run_refusals(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let file = "sibling-run.yml";
    let on = top_block(text, "on");
    if on
        != [
            "  pull_request:",
            "    branches: [beta]",
            "  workflow_dispatch:",
        ]
    {
        errors.push(format!("{file}: its triggers are not `pull_request` into beta and `workflow_dispatch` alone: {on:?}"));
    }
    if text.lines().any(|l| {
        let k = code(l).trim_start();
        k.starts_with("paths:")
            || k.starts_with("paths-ignore:")
            || k.starts_with("branches-ignore:")
    }) {
        errors.push(format!(
            "{file}: a path or branch filter; stage R runs on every pull request into beta"
        ));
    }
    if top_block(text, "permissions") != ["  contents: read"] {
        errors.push(format!(
            "{file}: its `permissions:` is not `contents: read` alone"
        ));
    }
    if text.lines().any(|l| code(l).contains("secrets.")) {
        errors.push(format!("{file}: names a secret; stage R holds none"));
    }
    if text
        .lines()
        .any(|l| code(l).trim_start().starts_with("environment:"))
    {
        errors.push(format!("{file}: names an environment; stage R holds none"));
    }
    if text.lines().any(|l| {
        let k = code(l).trim_start();
        k.starts_with("permissions:") && indent(l) > 0
    }) {
        errors.push(format!("{file}: a job widens `permissions:`"));
    }
    let all = jobs(text);
    let ids: Vec<&str> = all.iter().map(|(id, _)| id.as_str()).collect();
    if ids != ["raw"] {
        errors.push(format!("{file}: its one job is not `raw` (the context `sibling` is ci.yml's job's alone): {ids:?}"));
    }
    let mut ifs = 0;
    for (id, job) in &all {
        if job_key(job, "timeout-minutes").is_none() {
            errors.push(format!("{file}: job `{id}` has no `timeout-minutes`"));
        }
        if job_key(job, "if").is_some() {
            errors.push(format!(
                "{file}: job `{id}` has an `if:`; a skipped stage R is a run without an artifact"
            ));
        }
        if job_key(job, "name").is_some_and(|n| n.trim_matches(['\'', '"']) == "sibling") {
            errors.push(format!(
                "{file}: job `{id}` is named `sibling`, ci.yml's job's context"
            ));
        }
        for step in steps(job) {
            let uses = step_key(&step, "uses").unwrap_or("");
            if let Some(cond) = step_key(&step, "if") {
                ifs += 1;
                if !uses.starts_with("actions/upload-artifact@") || cond != "always()" {
                    errors.push(format!("{file}: a step has `if: {cond}`; the upload's `always()` is the one condition"));
                }
            }
            if uses.starts_with("actions/checkout@") {
                if with_input(&step, "persist-credentials") != Some("false") {
                    errors.push(format!("{file}: a checkout keeps its credentials (`persist-credentials: false` on every checkout)"));
                }
                let checkout_ref = with_input(&step, "ref");
                let head_ref = "${{ github.event.pull_request.head.sha || github.sha }}";
                match with_input(&step, "path") {
                    Some("head") if checkout_ref != Some(head_ref) => {
                        errors.push(format!("{file}: the head is not checked out by `github.event.pull_request.head.sha || github.sha` (never the merge ref)"));
                    }
                    Some("judge") if checkout_ref != Some("refs/heads/beta") => {
                        errors.push(format!("{file}: `judge/` is not beta's checkout"));
                    }
                    _ => {}
                }
            }
            if uses.starts_with("Swatinem/rust-cache@")
                && with_input(&step, "save-if") != Some("false")
            {
                errors.push(format!("{file}: the cache step saves (`save-if: false`: a pull request's head never writes beta's cache)"));
            }
            if uses.starts_with("actions/upload-artifact@") {
                for (input, want) in [
                    ("name", "sibling-raw"),
                    ("if-no-files-found", "error"),
                    ("retention-days", "30"),
                    ("overwrite", "true"),
                ] {
                    if with_input(&step, input) != Some(want) {
                        errors.push(format!("{file}: the upload's `{input}` is not `{want}`"));
                    }
                }
            }
        }
    }
    if ifs != 1 {
        errors.push(format!(
            "{file}: {ifs} steps carry an `if:`; the upload's `always()` is the one"
        ));
    }
    let lines: Vec<&str> = text.lines().map(code).collect();
    if !lines
        .iter()
        .any(|l| l.contains("pin=\"$(cat head/tests/sibling/PIN)\""))
    {
        errors.push(format!(
            "{file}: the pin is not read from the head's tests/sibling/PIN"
        ));
    }
    if !lines.iter().any(|l| {
        l.trim_start()
            .starts_with("python3 -I -B judge/.github/scripts/sibling_harness.py raw --tree head ")
    }) {
        errors.push(format!("{file}: stage R does not run beta's harness (`judge/`) on the head's tree under `python3 -I -B`"));
    }
    for (n, l) in lines.iter().enumerate() {
        if l.contains(".github/scripts/") && !l.contains("judge/.github/scripts/") {
            errors.push(format!(
                "{file}:{}: runs a script outside beta's `judge/` checkout: {}",
                n + 1,
                l.trim()
            ));
        }
    }
    errors.extend(expressions_in_run(file, text));
    errors
}

/// Stage J's named rules (#97: the brief's [b02], [b14], [b15]).
fn judge_refusals(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let file = "sibling-judge.yml";
    let on = top_block(text, "on");
    let triggers: Vec<&str> = on.iter().filter(|l| indent(l) == 2).copied().collect();
    if triggers != ["  workflow_run:", "  workflow_dispatch:"]
        || !on.contains(&"    workflows: [sibling-run]")
        || !on.contains(&"    types: [completed]")
        || !on.contains(&"      run_id:")
    {
        errors.push(format!("{file}: its triggers are not a `workflow_run` of `sibling-run` (`types: [completed]`) and a dispatch with `run_id`: {on:?}"));
    }
    if top_block(text, "permissions") != ["  contents: read"] {
        errors.push(format!(
            "{file}: its `permissions:` is not `contents: read` alone"
        ));
    }
    let concurrency = top_block(text, "concurrency");
    if !concurrency.iter().any(|l| {
        l.trim().starts_with(
            "group: sibling-judge-${{ github.event.workflow_run.head_sha || inputs.run_id }}",
        )
    }) || !concurrency.contains(&"  cancel-in-progress: false")
    {
        errors.push(format!("{file}: its concurrency is not one group per judged head with `cancel-in-progress: false`"));
    }
    let all = jobs(text);
    let ids: Vec<&str> = all.iter().map(|(id, _)| id.as_str()).collect();
    if ids != ["judge", "report"] {
        errors.push(format!(
            "{file}: its jobs are not `judge` and `report`: {ids:?}"
        ));
    }
    let reads = ["actions: read", "contents: read", "pull-requests: read"];
    for (id, job) in &all {
        let want_if = if id == "report" {
            "always() && github.ref == 'refs/heads/main'"
        } else {
            "github.ref == 'refs/heads/main'"
        };
        if job_key(job, "if") != Some(want_if) {
            errors.push(format!(
                "{file}: job `{id}` does not test the ref (`if: {want_if}`)"
            ));
        }
        if job_key(job, "runs-on") != Some("ubuntu-latest") {
            errors.push(format!(
                "{file}: job `{id}` does not run on `ubuntu-latest`"
            ));
        }
        if job_key(job, "timeout-minutes").is_none() {
            errors.push(format!("{file}: job `{id}` has no `timeout-minutes`"));
        }
        if job_permissions(job) != reads {
            errors.push(format!(
                "{file}: job `{id}`'s `permissions:` is not the three reads"
            ));
        }
        let environment = job_key(job, "environment");
        match (id.as_str(), environment) {
            ("report", Some("sibling-judge")) | ("judge", None) => {}
            _ => errors.push(format!("{file}: job `{id}` has the environment {environment:?}; `sibling-judge` is `report`'s alone")),
        }
        if id == "report" && job_key(job, "needs") != Some("judge") {
            errors.push(format!("{file}: `report` does not need `judge`"));
        }
        if id == "judge" && job.iter().any(|l| l.contains("secrets.")) {
            errors.push(format!("{file}: `judge` names a secret; it holds no key"));
        }
        let mut checkouts = 0;
        for step in steps(job) {
            let uses = step_key(&step, "uses").unwrap_or("");
            if uses.starts_with("actions/checkout@") {
                checkouts += 1;
                for (input, want) in [
                    ("ref", "refs/heads/beta"),
                    ("path", "judge"),
                    ("fetch-depth", "0"),
                    ("persist-credentials", "false"),
                ] {
                    if with_input(&step, input) != Some(want) {
                        errors.push(format!(
                            "{file}: job `{id}`'s checkout `{input}` is not `{want}`"
                        ));
                    }
                }
            }
            if uses.contains("cache") || with_input(&step, "cache").is_some() {
                errors.push(format!("{file}: job `{id}` restores a cache"));
            }
            if uses.starts_with("actions/create-github-app-token@") {
                if id != "report" {
                    errors.push(format!(
                        "{file}: job `{id}` mints the App's token; `report` alone does"
                    ));
                }
                let inputs: Vec<&str> = step
                    .iter()
                    .filter(|l| indent(l) == 10)
                    .map(|l| l.trim())
                    .collect();
                if inputs
                    != [
                        "app-id: ${{ vars.SIBLING_JUDGE_APP_ID }}",
                        concat!("private-key: ${{ secrets.", "SIBLING_JUDGE_KEY }}"),
                        "permission-checks: write",
                    ]
                {
                    errors.push(format!("{file}: the token step's inputs are not the App's id, its key and `permission-checks: write` alone: {inputs:?}"));
                }
            }
        }
        if checkouts != 1 {
            errors.push(format!(
                "{file}: job `{id}` has {checkouts} checkouts; one of beta, to `judge/`"
            ));
        }
    }
    let runs: Vec<&str> = text
        .lines()
        .map(code)
        .filter(|l| l.contains("sibling_judge.py") || l.contains("sibling_harness.py"))
        .collect();
    let judge = runs
        .iter()
        .filter(|l| {
            l.trim_start()
                .starts_with("python3 -I -B judge/.github/scripts/sibling_judge.py judge ")
        })
        .count();
    let report = runs
        .iter()
        .filter(|l| {
            l.trim_start()
                .starts_with("python3 -I -B judge/.github/scripts/sibling_judge.py report ")
        })
        .count();
    if (judge, report, runs.len()) != (1, 1, 2) {
        errors.push(format!("{file}: the two commands are not beta's `sibling_judge.py judge` and `report` under `python3 -I -B` from `judge/`: {runs:?}"));
    }
    errors.extend(expressions_in_run(file, text));
    errors
}

/// Every file of the tree, `.git` and every `target` folder aside.
fn tree_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if name != ".git" && name != "target" {
                tree_files(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

/// Across the tree: the key's expression once (the token step; this file holds the trampoline's pin
/// and builds its needle with `concat!`), the environment `sibling-judge` in no other workflow, and
/// `workflow_run` in no other workflow.
fn tree_refusals(workflows: &[(String, String)], texts: &[(String, String)]) -> Vec<String> {
    let mut errors = Vec::new();
    let key = concat!("secrets.", "SIBLING_JUDGE_KEY");
    let found: Vec<String> = texts
        .iter()
        .filter(|(name, _)| name != "tests/arch_ci_sibling_judge_97.rs")
        .flat_map(|(name, text)| {
            text.lines()
                .enumerate()
                .filter(|(_, l)| l.contains(key))
                .map(move |(n, _)| format!("{name}:{}", n + 1))
        })
        .collect();
    if found.len() != 1 || !found[0].starts_with(".github/workflows/sibling-judge.yml:") {
        errors.push(format!("the App's key is named {} times in the tree, where the token step alone names it: {found:?}", found.len()));
    }
    for (file, text) in workflows {
        if file == "sibling-judge.yml" {
            continue;
        }
        let lines: Vec<&str> = text.lines().map(code).collect();
        for (n, l) in lines.iter().enumerate() {
            let k = l.trim_start();
            let named = k
                .strip_prefix("environment:")
                .is_some_and(|v| v.contains("sibling-judge"))
                || (k == "environment:"
                    && lines[n + 1..]
                        .iter()
                        .find(|l| !l.trim().is_empty())
                        .is_some_and(|l| l.contains("sibling-judge")));
            if named {
                errors.push(format!("{file}:{}: names the environment `sibling-judge`, sibling-judge.yml's `report`'s alone", n + 1));
            }
            if l.contains("workflow_run") {
                errors.push(format!(
                    "{file}:{}: names `workflow_run`; the trampoline alone is started by one",
                    n + 1
                ));
            }
        }
    }
    errors
}

#[test]
fn the_two_workflows_of_the_judge_are_pinned_whole_97() {
    let run = read(".github/workflows/sibling-run.yml");
    let judge = read(".github/workflows/sibling-judge.yml");
    let errors: Vec<String> = [
        first_difference(".github/workflows/sibling-run.yml", SIBLING_RUN, &run),
        first_difference(".github/workflows/sibling-judge.yml", SIBLING_JUDGE, &judge),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let planted = judge.replacen("timeout-minutes: 10", "timeout-minutes: 11", 1);
    assert_eq!(
        first_difference(".github/workflows/sibling-judge.yml", SIBLING_JUDGE, &planted).as_deref(),
        Some(".github/workflows/sibling-judge.yml is not its pin byte for byte (a change to it is a change to this test in the same diff): line 38\n  expected: \"    timeout-minutes: 10\"\n  found:    \"    timeout-minutes: 11\"")
    );
    let shorter = run.trim_end_matches('\n');
    assert!(
        first_difference(".github/workflows/sibling-run.yml", SIBLING_RUN, shorter).is_some_and(
            |e| e.contains("found:    <end>")
                || e.contains("found:    \"\"")
                || e.contains("expected: \"\"")
        )
    );
}

#[test]
fn stage_r_holds_its_named_rules_97() {
    let text = read(".github/workflows/sibling-run.yml");
    let errors = run_refusals(&text);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let head_ref = "          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n";
    let plants: &[(&str, &str, String, &str)] = &[
        ("a path filter", "    branches: [beta]\n", "    branches: [beta]\n    paths: ['src/**']\n".into(), "a path or branch filter"),
        ("a push trigger", "  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n".into(), "its triggers are not"),
        ("into main too", "    branches: [beta]\n", "    branches: [beta, main]\n".into(), "its triggers are not"),
        ("permissions widened", "permissions:\n  contents: read\n", "permissions:\n  contents: write\n".into(), "is not `contents: read` alone"),
        ("a job's permissions", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    permissions:\n      contents: read\n".into(), "a job widens"),
        ("a secret", "          PULL_REQUEST: ${{ github.event.pull_request.number }}\n", "          PULL_REQUEST: ${{ github.event.pull_request.number }}\n          T: ${{ secrets.X }}\n".into(), "names a secret"),
        ("an environment", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    environment: sibling-judge\n".into(), "names an environment"),
        ("credentials kept", "          path: head\n          persist-credentials: false\n", "          path: head\n          persist-credentials: true\n".into(), "keeps its credentials"),
        ("the merge ref", head_ref, "          ref: ${{ github.ref }}\n".into(), "never the merge ref"),
        ("beta's pin", "pin=\"$(cat head/tests/sibling/PIN)\"", "pin=\"$(cat judge/tests/sibling/PIN)\"".into(), "the pin is not read from the head's"),
        ("the cache saves", "          save-if: false\n", "          save-if: true\n".into(), "the cache step saves"),
        ("the job named sibling", "  raw:\n    name: raw\n", "  sibling:\n    name: sibling\n".into(), "its one job is not `raw`"),
        ("a second job", "jobs:\n", "jobs:\n  other:\n    runs-on: ubuntu-latest\n    timeout-minutes: 1\n".into(), "its one job is not `raw`"),
        ("a job condition", "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    if: github.event.pull_request.draft == false\n".into(), "has an `if:`"),
        ("a step condition", "      - name: raw\n", "      - name: raw\n        if: github.event_name == 'pull_request'\n".into(), "the upload's `always()` is the one condition"),
        ("the upload's condition", "        if: always()\n", "        if: success()\n".into(), "the upload's `always()` is the one condition"),
        ("the upload renamed", "          name: sibling-raw\n", "          name: raw\n".into(), "the upload's `name` is not `sibling-raw`"),
        ("no files allowed", "          if-no-files-found: error\n", "          if-no-files-found: warn\n".into(), "the upload's `if-no-files-found`"),
        ("a longer life", "          retention-days: 30\n", "          retention-days: 90\n".into(), "the upload's `retention-days`"),
        ("no overwrite", "          overwrite: true\n", "".into(), "the upload's `overwrite`"),
        ("no timeout", "    timeout-minutes: 15\n", "".into(), "has no `timeout-minutes`"),
        ("the head's harness", "python3 -I -B judge/.github/scripts/sibling_harness.py raw --tree head", "python3 -I -B head/.github/scripts/sibling_harness.py raw --tree head".into(), "does not run beta's harness"),
        ("not isolated", "python3 -I -B judge/.github/scripts/sibling_harness.py raw", "python3 -B judge/.github/scripts/sibling_harness.py raw".into(), "does not run beta's harness"),
        ("the head's member list", "python3 -I -B judge/.github/scripts/sibling_judge.py members", "python3 -I -B head/.github/scripts/sibling_judge.py members".into(), "runs a script outside beta's"),
        ("an expression in run", "          test \"$(git -C sibling rev-parse HEAD)\" = \"$PIN\"\n", "          test \"$(git -C sibling rev-parse HEAD)\" = \"${{ steps.pin.outputs.sibling }}\"\n".into(), "an expression inside a `run:` block"),
    ];
    for (what, from, to, refusal) in plants {
        assert!(text.contains(from), "{what}: the plant's anchor is gone");
        let planted = text.replacen(from, to, 1);
        assert!(
            run_refusals(&planted).iter().any(|e| e.contains(refusal)),
            "{what}: not refused as {refusal:?}: {:?}",
            run_refusals(&planted)
        );
    }
}

#[test]
fn stage_j_holds_its_named_rules_97() {
    let text = read(".github/workflows/sibling-judge.yml");
    let errors = judge_refusals(&text);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let key_line = concat!(
        "          private-key: ${{ secrets.",
        "SIBLING_JUDGE_KEY }}\n"
    );
    let plants: &[(&str, &str, String, &str)] = &[
        ("a pull_request trigger", "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n".into(), "its triggers are not"),
        ("every conclusion's event", "    types: [completed]\n", "    types: [requested, completed]\n".into(), "its triggers are not"),
        ("another workflow's run", "    workflows: [sibling-run]\n", "    workflows: [CI]\n".into(), "its triggers are not"),
        ("the judge off main", "    if: github.ref == 'refs/heads/main'\n", "    if: true\n".into(), "job `judge` does not test the ref"),
        ("the report off main", "    if: always() && github.ref == 'refs/heads/main'\n", "    if: always()\n".into(), "job `report` does not test the ref"),
        ("the environment on judge", "    timeout-minutes: 10\n    permissions:\n", "    timeout-minutes: 10\n    environment: sibling-judge\n    permissions:\n".into(), "job `judge` has the environment"),
        ("no environment on report", "    environment: sibling-judge\n", "".into(), "job `report` has the environment None"),
        ("a secret in judge", "          GH_TOKEN: ${{ github.token }}\n", "          GH_TOKEN: ${{ secrets.SIBLING_JUDGE_KEY }}\n".into(), "`judge` names a secret"),
        ("one group for every head", "  group: sibling-judge-${{ github.event.workflow_run.head_sha || inputs.run_id }}\n", "  group: sibling-judge\n".into(), "one group per judged head"),
        ("judgements cancelled", "  cancel-in-progress: false\n", "  cancel-in-progress: true\n".into(), "one group per judged head"),
        ("not isolated", "python3 -I -B judge/.github/scripts/sibling_judge.py judge", "python3 judge/.github/scripts/sibling_judge.py judge".into(), "the two commands are not"),
        ("the head's script", "python3 -I -B judge/.github/scripts/sibling_judge.py report", "python3 -I -B .github/scripts/sibling_judge.py report".into(), "the two commands are not"),
        ("a cache step", "      - name: Judge\n", "      - name: Cache\n        uses: actions/cache@0000000000000000000000000000000000000000 # v4\n\n      - name: Judge\n".into(), "restores a cache"),
        ("an expression in run", "            --workflow-sha \"$WORKFLOW_SHA\"\n", "            --workflow-sha \"${{ github.workflow_sha }}\"\n".into(), "an expression inside a `run:` block"),
        ("an output in run", "            --judge-result \"$JUDGE_RESULT\" --details-url \"$DETAILS_URL\"\n", "            --judge-result \"${{ needs.judge.result }}\" --details-url \"$DETAILS_URL\"\n".into(), "an expression inside a `run:` block"),
        ("a wider token", "          permission-checks: write\n", "          permission-checks: write\n          permission-contents: write\n".into(), "the token step's inputs"),
        ("the key from elsewhere", key_line, "          private-key: ${{ vars.KEY }}\n".into(), "the token step's inputs"),
        ("credentials kept", "          persist-credentials: false\n", "          persist-credentials: true\n".into(), "checkout `persist-credentials` is not `false`"),
        ("a shallow beta", "          fetch-depth: 0\n", "          fetch-depth: 1\n".into(), "checkout `fetch-depth` is not `0`"),
        ("the head checked out", "          ref: refs/heads/beta\n", "          ref: ${{ github.event.workflow_run.head_sha }}\n".into(), "checkout `ref` is not `refs/heads/beta`"),
        ("a job id sibling-judge", "  report:\n", "  sibling-judge:\n".into(), "its jobs are not `judge` and `report`"),
        ("no timeout", "    timeout-minutes: 10\n", "".into(), "has no `timeout-minutes`"),
        ("a write permission", "      pull-requests: read\n", "      pull-requests: write\n".into(), "is not the three reads"),
        ("no needs", "    needs: judge\n", "".into(), "`report` does not need `judge`"),
    ];
    for (what, from, to, refusal) in plants {
        assert!(text.contains(from), "{what}: the plant's anchor is gone");
        let planted = text.replacen(from, to, 1);
        assert!(
            judge_refusals(&planted).iter().any(|e| e.contains(refusal)),
            "{what}: not refused as {refusal:?}: {:?}",
            judge_refusals(&planted)
        );
    }
}

#[test]
fn the_key_the_environment_and_workflow_run_belong_to_the_trampoline_alone_97() {
    let mut files = Vec::new();
    tree_files(&root(), &mut files);
    let texts: Vec<(String, String)> = files
        .iter()
        .filter_map(|path| {
            let text = String::from_utf8(fs::read(path).ok()?).ok()?;
            let name = path
                .strip_prefix(root())
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            Some((name, text))
        })
        .collect();
    assert!(texts.len() > 1000, "the walk read {} files", texts.len());
    let workflows = workflows();
    let errors = tree_refusals(&workflows, &texts);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    let key = concat!("${{ secrets.", "SIBLING_JUDGE_KEY }}");
    let mut twice = texts.clone();
    twice.push(("docs/x.md".to_string(), format!("a step reads {key}\n")));
    assert!(tree_refusals(&workflows, &twice)
        .iter()
        .any(|e| e.contains("named 2 times")));
    let mut other = workflows.clone();
    other.push((
        "x.yml".to_string(),
        "on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  a:\n    environment: sibling-judge\n    runs-on: ubuntu-latest\n  b:\n    environment:\n      name: sibling-judge\n".to_string(),
    ));
    let found = tree_refusals(&other, &texts);
    assert_eq!(
        found,
        [
            "x.yml:2: names `workflow_run`; the trampoline alone is started by one",
            "x.yml:6: names the environment `sibling-judge`, sibling-judge.yml's `report`'s alone",
            "x.yml:9: names the environment `sibling-judge`, sibling-judge.yml's `report`'s alone",
        ]
    );
}
