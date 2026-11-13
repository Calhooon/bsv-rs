//! On `beta` the `semver` check holds a pull request to a minor change unless it carries the
//! `api-break` label (#886).
//!
//! Every version on `beta` is a prerelease, and cargo-semver-checks 0.51.0 reads any prerelease
//! step as a major one: with the release type inferred the required `semver` check ran 0 checks
//! and passed whatever a pull request removed. The step now names `--release-type minor` for a
//! pull request into `beta` (an addition passes; a break the tool has a lint for fails, and one
//! it has no lint for, a changed parameter or return type among them, passes it), against the
//! commit the pull request is tested on (`HEAD^1` of the merge ref), and lets a lint failure through only when
//! the pull request carries `api-break`, read live through the API before the check.
//!
//! This guard reads `.github/workflows/ci.yml` alone (no network, no environment) and names no
//! crate module. The step that runs the tool is [`SEMVER_STEP`] byte for byte (its name, its
//! condition, its `env:` and its whole `run:` text, the beta branch among them), as `SIBLING_JOB`
//! is pinned in `arch_ci_pr_runs_the_required_set.rs`: the named rules below read lines and their
//! order, and a line INSERTED between them (`labels=api-break` after the read, a second
//! `baseline=`, `status="0"` after the check, `BASE_REF=main` before the branch) passed every one
//! of them (#886's fold, the three reads of #898). The named rules stay, since each says why a
//! change would matter; the pin says that nothing else changed.
//!
//! The job around the step is pinned as text too (#898's re-read of the fold: a rule that read
//! `ref:` by its line's prefix let a quoted key, a space before the colon and a flow mapping
//! through; a line reader taught one more spelling would miss the next). Three pins, comments and
//! blank lines aside, each failure naming ci.yml's line, the line found and the line pinned:
//! [`JOB_HEAD`], the job's id and every key beside `steps:` with its value (`name`, `if`,
//! `runs-on`, `permissions` and its two entries), so a job-level `env:`, `defaults:`,
//! `container:` or a third permission is refused in any spelling; [`STEP_HEADS`], every line after
//! `steps:` indented six spaces or fewer, that is each step's opening line in order and any job
//! key written after the steps, so a step inserted, removed, renamed or moved is refused; and
//! [`CHECKOUT_STEP`], the checkout from its `- uses:` line to the line before the next step,
//! so a `ref:`, `repository:`, `path:` or `token:` in any spelling is refused (`HEAD^1` is the
//! commit the pull request is tested on only at the event's merge ref). Each refusal is shown on a
//! planted copy of the file's own text.
//!
//! What it cannot see, stated: another workflow file, a reusable workflow's inputs, and the
//! workflow's own keys (a workflow-level `env:` or `defaults:`; the step's `env:` wins over them for
//! the four names it sets); and within the job, the bodies of the six steps it pins by their
//! opening line alone (the plan, the scratch directory, the toolchain, the cache, the install,
//! the docs-only report, read in part by `arch_ci_docs_only_exit.rs` and
//! `arch_ci_semver_tool_seed.rs`).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;
use std::path::PathBuf;

/// The live label read, as the Test Suite's plan step reads it. Whole line: a failed read
/// fails the step under `set -euo pipefail`.
const LABEL_READ: &str =
    r#"labels=$(gh api "repos/$REPOSITORY/pulls/$PR" --jq '[.labels[].name] | join(",")')"#;
/// The branch a pull request into `beta` takes.
const BETA_BRANCH: &str = r#"if [ "$BASE_REF" = beta ]; then"#;
/// The commit the pull request is tested on: the merge ref's base parent.
const BASELINE: &str = r#"baseline="$(git rev-parse HEAD^1)""#;
/// The tool's one run on `beta`, its exit kept for the label's reading.
const CHECK: &str = r#""$RUNNER_TEMP/tools/bin/cargo-semver-checks" check-release --baseline-rev "$baseline" --all-features --release-type minor || status=$?"#;
/// The label's reading: a lint failure (the tool's exit 100) and the label, matched whole.
const LABEL_MATCH: &str = r#"if [ "$status" = 100 ] && [[ ",$labels," == *",api-break,"* ]]; then"#;
/// The lines every other base keeps: the last tag, the release type inferred.
const TAG_BASELINE: &str =
    r#"baseline="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$BASE_REV")""#;
const TAG_CHECK: &str = r#""$RUNNER_TEMP/tools/bin/cargo-semver-checks" check-release --baseline-rev "$baseline" --all-features"#;
const PERMISSIONS: &str = "    permissions:\n      contents: read\n      pull-requests: read\n";
/// The step that runs the tool, whole: from its `name:` to the last line of its `run:` block,
/// as it stands in `ci.yml` after the step's `      - `. A change to the step is a change here,
/// read by whoever reviews it.
const SEMVER_STEP: &str = r##"name: Check the public API against the base line's baseline
        if: steps.plan.outputs.docs_only != 'true'
        env:
          GH_TOKEN: ${{ github.token }}
          BASE_REV: ${{ github.event.pull_request.base.sha }}
          BASE_REF: ${{ github.base_ref }}
          PR: ${{ github.event.pull_request.number }}
          REPOSITORY: ${{ github.repository }}
        run: |
          set -euo pipefail
          if [ "$BASE_REF" = beta ]; then
            # read live before the check; a failed read fails the job, never a waived check
            labels=$(gh api "repos/$REPOSITORY/pulls/$PR" --jq '[.labels[].name] | join(",")')
            echo "labels: ${labels:-none}"
            baseline="$(git rev-parse HEAD^1)"
            echo "Checking the PR against $baseline, the commit it is tested on (base $BASE_REV), as a minor change"
            git clone --quiet --shared "$GITHUB_WORKSPACE" "$RUNNER_TEMP/semver-source"
            cd "$RUNNER_TEMP/semver-source"
            status=0
            "$RUNNER_TEMP/tools/bin/cargo-semver-checks" check-release --baseline-rev "$baseline" --all-features --release-type minor || status=$?
            # the tool's exit for a failed lint is 100; any other failure (a build, a bad
            # baseline) stays red with or without the label
            if [ "$status" = 100 ] && [[ ",$labels," == *",api-break,"* ]]; then
              echo "::notice::The public API breaks above are allowed by the api-break label on this pull request (#886)."
              exit 0
            fi
            exit "$status"
          fi
          baseline="$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$BASE_REV")"
          echo "Checking the PR against $baseline (base $BASE_REV)"
          git clone --quiet --shared "$GITHUB_WORKSPACE" "$RUNNER_TEMP/semver-source"
          cd "$RUNNER_TEMP/semver-source"
          # Off `beta` the release type is inferred from the version change between the baseline
          # tag and Cargo.toml (a 0.x minor bump is semver's major): a breaking change passes
          # only when the version says so, an additive one only when it says at least minor.
          "$RUNNER_TEMP/tools/bin/cargo-semver-checks" check-release --baseline-rev "$baseline" --all-features"##;
const STEP_PINNED: &str = "the step that runs the tool is not SEMVER_STEP byte for byte";
/// The job's id and its keys beside `steps:`, whole, comments aside.
const JOB_HEAD: &str = "  semver:
    name: semver
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:";
/// The opening line of each of the job's steps, in order.
const STEP_HEADS: &[&str] = &[
    "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
    "      - name: Plan whether the change is docs only",
    "      - name: Keep build output in runner scratch",
    "      - name: Install the Rust version supported by the pinned semver tool",
    "      - name: Cache the pinned semver tool",
    "      - name: Install cargo-semver-checks 0.51.0",
    "      - name: Check the public API against the base line's baseline",
    "      - name: No API to check",
];
/// The job's checkout, whole: `HEAD^1` is the commit the pull request is tested on only at the
/// event's merge ref, which a checkout naming no `ref:` and no `repository:` takes.
const CHECKOUT_STEP: &str =
    "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0
          persist-credentials: false";
const HEAD_PINNED: &str = "the job's head and keys are not JOB_HEAD line for line";
const STEPS_PINNED: &str =
    "the job's steps are not STEP_HEADS in order (a step added, removed or renamed, or a key after the steps)";
const CHECKOUT_PINNED: &str = "the job's checkout is not CHECKOUT_STEP line for line";

fn ci() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/ci.yml");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The byte range of a top-level job's text: from its `  <id>:` line to the next line at that
/// indentation that is no comment.
fn job_range(ci: &str, id: &str) -> Option<(usize, usize)> {
    let head = format!("\n  {id}:\n");
    let start = ci.find(&head)? + 1;
    let mut end = ci.len();
    let mut at = start + head.len() - 1;
    for line in ci[at..].split_inclusive('\n') {
        let is_key = line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && !line.trim().is_empty();
        if is_key {
            end = at;
            break;
        }
        at += line.len();
    }
    Some((start, end))
}

/// The lines of the `run: |` block of the step that runs the tool, each without the block's
/// ten columns, with the step's own text.
fn check_step(job: &str) -> Option<(&str, Vec<&str>)> {
    let step = job
        .split("\n      - ")
        .find(|step| step.contains("check-release"))?;
    let (_, run) = step.split_once("        run: |\n")?;
    let lines = run
        .lines()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect();
    Some((step, lines))
}

/// Where the step's text parts from [`SEMVER_STEP`], naming ci.yml's line, the line found and
/// the line pinned; empty when the two are equal byte for byte.
fn pin_refusals(ci: &str, job: &str, step: &str) -> Vec<String> {
    let found = step.trim_end_matches('\n');
    if found == SEMVER_STEP {
        return Vec::new();
    }
    // the step's opening line in ci.yml, 1-based: the lines before the job and before the step
    let before_job = ci.find(job).map_or(0, |at| ci[..at].lines().count());
    let before_step = job.find(step).map_or(0, |at| job[..at].lines().count());
    let opening = before_job + before_step;
    let (mut found_lines, mut pinned_lines) = (found.lines(), SEMVER_STEP.lines());
    let mut n = 0;
    loop {
        let (f, p) = (found_lines.next(), pinned_lines.next());
        if f != p || f.is_none() {
            return vec![format!(
                "semver: {STEP_PINNED}: ci.yml line {}: found `{}`, pinned `{}`: a line inserted, removed or changed in the step can waive the check (a second `labels=`, `baseline=` or `status=`), so the step is pinned whole",
                opening + n,
                f.unwrap_or("<the step ends>").trim(),
                p.unwrap_or("<the pin ends>").trim()
            )];
        }
        n += 1;
    }
}

/// The job's text as ci.yml's lines, each with its 1-based line number.
fn job_lines<'a>(ci: &'a str, job: &'a str) -> Vec<(usize, &'a str)> {
    // `job` is a slice of `ci`: its offset in it, never a search that could match earlier text
    let at = (job.as_ptr() as usize).saturating_sub(ci.as_ptr() as usize);
    let first = ci.get(..at).map_or(0, |before| before.lines().count()) + 1;
    job.lines()
        .enumerate()
        .map(|(n, l)| (first + n, l))
        .collect()
}

/// A blank line or a comment: YAML reads nothing from it.
fn ignorable(line: &str) -> bool {
    let text = line.trim();
    text.is_empty() || text.starts_with('#')
}

/// The spaces before a line's text (a tab is not a space, so a tab-led line reads as 0).
fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The first line where `found` parts from `pinned`, as a refusal naming ci.yml's line, the
/// line found and the line pinned, each between backticks with its leading spaces; `None` when
/// the two are equal line for line.
fn first_difference(
    what: &str,
    found: &[(usize, &str)],
    pinned: &[&str],
    end: usize,
) -> Option<String> {
    let at = (0..found.len().max(pinned.len()))
        .find(|&n| found.get(n).map(|(_, l)| *l) != pinned.get(n).copied())?;
    let line = found.get(at).map_or(end, |(n, _)| *n);
    Some(format!(
        "semver: {what}: ci.yml line {line}: found `{}`, pinned `{}`",
        found.get(at).map_or("<the job ends>", |(_, l)| l),
        pinned.get(at).copied().unwrap_or("<the pin ends>")
    ))
}

/// The job's head, its id and every key beside `steps:` with their values, is [`JOB_HEAD`]
/// line for line (comments and blank lines aside), so a job-level `env:`, `defaults:`,
/// `container:`, `continue-on-error`, a wider permission, another `if:` or runner is refused,
/// in any spelling, by the line it adds or changes.
fn head_refusals(lines: &[(usize, &str)]) -> Vec<String> {
    let text: Vec<(usize, &str)> = lines
        .iter()
        .copied()
        .filter(|(_, l)| !ignorable(l))
        .collect();
    let head = text
        .iter()
        .position(|(_, l)| *l == "    steps:")
        .map_or(&text[..], |at| &text[..=at]);
    let end = lines.last().map_or(0, |(n, _)| *n);
    let pinned: Vec<&str> = JOB_HEAD.lines().collect();
    first_difference(HEAD_PINNED, head, &pinned, end)
        .into_iter()
        .collect()
}

/// The lines after `    steps:` that YAML reads at the steps' level or above (indented six
/// spaces or fewer, comments and blank lines aside): each step's opening line, and a job key
/// written after the steps. They are [`STEP_HEADS`] in order, so a step inserted, removed,
/// renamed or moved, a lone `-`, a flow-mapped step and a key after the steps are refused by the
/// line they add or change.
fn step_list_refusals(lines: &[(usize, &str)]) -> Vec<String> {
    let Some(open) = lines.iter().position(|(_, l)| *l == "    steps:") else {
        return vec![format!(
            "semver: {STEPS_PINNED}: the job has no `    steps:` line"
        )];
    };
    let heads: Vec<(usize, &str)> = lines[open + 1..]
        .iter()
        .copied()
        .filter(|(_, l)| !ignorable(l) && indent(l) <= 6)
        .collect();
    let end = lines.last().map_or(0, |(n, _)| *n);
    first_difference(STEPS_PINNED, &heads, STEP_HEADS, end)
        .into_iter()
        .collect()
}

/// The job's checkout is [`CHECKOUT_STEP`] line for line: from its `- uses:` line to the line
/// before the next step's, the blank and comment lines that end it aside. At the event's merge
/// ref `HEAD^1` is the commit the pull request is tested on; a `ref:` or a `repository:` in any
/// spelling (a quoted key, a space before the colon, a flow mapping), a `path:` or a `token:`
/// changes a line of the step and is refused by it.
fn checkout_refusals(lines: &[(usize, &str)]) -> Vec<String> {
    let Some(open) = lines.iter().position(|(_, l)| *l == STEP_HEADS[0]) else {
        return vec![format!(
            "semver: {CHECKOUT_PINNED}: no line `{}` in the job",
            STEP_HEADS[0]
        )];
    };
    let mut step: Vec<(usize, &str)> = vec![lines[open]];
    for &(n, l) in &lines[open + 1..] {
        if !ignorable(l) && indent(l) <= 6 {
            break;
        }
        step.push((n, l));
    }
    while step.last().is_some_and(|(_, l)| ignorable(l)) {
        step.pop();
    }
    let end = step.last().map_or(0, |(n, _)| n + 1);
    let pinned: Vec<&str> = CHECKOUT_STEP.lines().collect();
    first_difference(CHECKOUT_PINNED, &step, &pinned, end)
        .into_iter()
        .collect()
}

fn position(lines: &[&str], whole: &str) -> Option<usize> {
    lines.iter().position(|line| line.trim() == whole)
}

/// Why this `ci.yml`'s `semver` job does not hold `beta` to a minor change; empty when it does.
fn refusals(ci: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let Some((start, end)) = job_range(ci, "semver") else {
        return vec!["ci.yml: no `semver` job".to_owned()];
    };
    let job = &ci[start..end];

    // the job's permissions: the two the label read needs and release.yml's call grants
    if !job.contains(PERMISSIONS) {
        errors.push(
            "semver: the job's permissions are not `contents: read` and `pull-requests: read` alone: the label read needs the second, and release.yml's call grants no more (RELEASING.md step 22)"
                .to_owned(),
        );
    } else if job.matches("permissions:").count() != 1 {
        errors.push("semver: a second `permissions:` in the job".to_owned());
    }
    if job.contains("continue-on-error") {
        errors.push("semver: `continue-on-error` would absorb the check's failure".to_owned());
    }
    // the event's copy of the labels is the event's, not the pull request's as it stands
    if job.contains("github.event.pull_request.labels") || job.contains("github.event.label") {
        errors.push(
            "semver: the labels are taken from the event payload, which is not live: read them through the API"
                .to_owned(),
        );
    }
    if ci.lines().any(|line| {
        let line = line.trim();
        line.starts_with("types:") && line.contains("labeled")
    }) {
        errors.push(
            "ci.yml: a `labeled` trigger: the label is read live, never by a second run".to_owned(),
        );
    }

    let lines = job_lines(ci, job);
    errors.extend(head_refusals(&lines));
    errors.extend(step_list_refusals(&lines));
    errors.extend(checkout_refusals(&lines));
    let Some((step, lines)) = check_step(job) else {
        errors.push("semver: no step runs `check-release` in a `run: |` block".to_owned());
        return errors;
    };
    errors.extend(pin_refusals(ci, job, step));
    for (line, why) in [
        ("GH_TOKEN: ${{ github.token }}", "the label read's token"),
        (
            "BASE_REF: ${{ github.base_ref }}",
            "the base line read through `env`",
        ),
        (
            "PR: ${{ github.event.pull_request.number }}",
            "the pull request's number",
        ),
        (
            "REPOSITORY: ${{ github.repository }}",
            "the repository's name",
        ),
    ] {
        if !step.lines().any(|l| l.trim() == line) {
            errors.push(format!("semver: the step's env lacks `{line}` ({why})"));
        }
    }
    if lines.first().map(|l| l.trim()) != Some("set -euo pipefail") {
        errors.push(
            "semver: the step does not open with `set -euo pipefail`: a failed label read would not fail it"
                .to_owned(),
        );
    }

    // the beta branch: from its `if` to the `fi` at the same column
    let Some(open) = lines.iter().position(|line| *line == BETA_BRANCH) else {
        errors.push(format!(
            "semver: no `{BETA_BRANCH}` branch: a pull request into beta is not held to minor"
        ));
        return errors;
    };
    let Some(close) = lines[open..].iter().position(|line| *line == "fi") else {
        errors.push("semver: the beta branch is not closed by a `fi` at its column".to_owned());
        return errors;
    };
    let beta = &lines[open + 1..open + close];
    let rest = &lines[open + close + 1..];

    let read = position(beta, LABEL_READ);
    if read.is_none() {
        errors.push(format!(
            "semver: the beta branch does not read the labels by the line `{LABEL_READ}`, whole: a failed read must fail the job, never waive or narrow the check"
        ));
    }
    let baseline = position(beta, BASELINE);
    if baseline.is_none() || beta.iter().any(|line| line.contains("git describe")) {
        errors.push(format!(
            "semver: the beta branch's baseline is not `{BASELINE}` (the commit the pull request is tested on): against the last tag one labelled break would fail every later pull request"
        ));
    }
    if !beta
        .iter()
        .any(|line| line.contains("--release-type minor"))
    {
        errors.push(
            "semver: the beta branch's check names no `--release-type minor`: at a prerelease version the tool infers a major change and judges nothing"
                .to_owned(),
        );
    }
    let check = position(beta, CHECK);
    let runs = beta
        .iter()
        .filter(|line| line.contains("cargo-semver-checks"))
        .count();
    match check {
        Some(at) if runs == 1 && beta[at] == format!("  {CHECK}") => {}
        _ => errors.push(format!(
            "semver: the beta branch does not run the tool once, unconditionally, by the line `{CHECK}`"
        )),
    }
    let matched = position(beta, LABEL_MATCH);
    let mentions = beta
        .iter()
        .filter(|line| !line.trim_start().starts_with('#') && !line.contains("::notice::"))
        .filter(|line| line.contains("$labels") && line.contains("=="))
        .count();
    if matched.is_none() || mentions != 1 {
        errors.push(format!(
            "semver: the `api-break` label is not matched once, whole, after a lint failure, by the line `{LABEL_MATCH}`"
        ));
    }
    if let (Some(read), Some(check)) = (read, check) {
        if read > check {
            errors.push("semver: the labels are read after the check, not before it".to_owned());
        }
    }
    if let (Some(check), Some(matched)) = (check, matched) {
        let passes: Vec<usize> = beta
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("exit 0"))
            .map(|(n, _)| n)
            .collect();
        let allowed = beta.get(matched + 1).is_some_and(|line| {
            line.trim_start().starts_with("echo \"::notice::") && line.contains("api-break")
        }) && passes == [matched + 2]
            && beta.get(matched + 3).map(|l| l.trim()) == Some("fi");
        if matched < check || !allowed {
            errors.push(
                "semver: the label does not end the step green only after the tool ran and failed a lint, with one `::notice::` line naming `api-break`: the label must not skip the tool"
                    .to_owned(),
            );
        }
    }
    if beta.last().map(|l| l.trim()) != Some(r#"exit "$status""#) {
        errors.push(
            "semver: the beta branch does not end with `exit \"$status\"`: without the label the tool's exit is the step's"
                .to_owned(),
        );
    }

    // every other base: today's lines, the release type inferred
    if position(rest, TAG_BASELINE).is_none() || position(rest, TAG_CHECK).is_none() {
        errors.push(
            "semver: a base other than beta no longer compares with the last tag by the lines it had"
                .to_owned(),
        );
    }
    errors
}

#[test]
fn the_semver_step_holds_beta_to_minor_unless_labelled_886() {
    let ci = ci();
    assert_eq!(refusals(&ci), Vec::<String>::new());
    // what the refusals read is there to be read: the job, its step, both branches
    let (start, end) = job_range(&ci, "semver").expect("the semver job");
    let job = &ci[start..end];
    assert!(job.starts_with("  semver:\n") && !job.contains("\n  semver-tool-seed:"));
    let (_, lines) = check_step(job).expect("the check step");
    let read = position(&lines, LABEL_READ).expect("the live read");
    let check = position(&lines, CHECK).expect("the check");
    assert!(read < check, "the read stands before the check");
    assert!(position(&lines, BASELINE).is_some());
    assert!(position(&lines, TAG_CHECK).is_some());
}

/// A plant on the `semver` job's own text: `from` must stand there exactly once.
fn plant(ci: &str, from: &str, to: &str) -> String {
    let (start, end) = job_range(ci, "semver").expect("the semver job");
    let job = &ci[start..end];
    assert_eq!(
        job.matches(from).count(),
        1,
        "the plant's text `{from}` stands once in the semver job"
    );
    format!("{}{}{}", &ci[..start], job.replace(from, to), &ci[end..])
}

#[test]
fn a_planted_semver_step_is_refused_886() {
    let ci = ci();
    let read = format!("            {LABEL_READ}\n");
    let plants: Vec<(&str, String, String, &str)> = vec![
        (
            "`minor` dropped",
            " --release-type minor".to_owned(),
            String::new(),
            "names no `--release-type minor`",
        ),
        (
            "the label read behind `|| true`",
            read.clone(),
            format!("            {LABEL_READ} || true\n"),
            "a failed read must fail the job",
        ),
        (
            "the read taken from the event payload",
            read.clone(),
            "            labels='${{ join(github.event.pull_request.labels.*.name, ',') }}'\n".to_owned(),
            "taken from the event payload",
        ),
        (
            "the label branch skipping the tool",
            "            status=0\n".to_owned(),
            "            if [[ \",$labels,\" == *\",api-break,\"* ]]; then exit 0; fi\n            status=0\n".to_owned(),
            "the label must not skip the tool",
        ),
        (
            "the tool inside the label's else",
            format!("            {CHECK}\n"),
            format!("            if [[ \",$labels,\" != *\",api-break,\"* ]]; then\n              {CHECK}\n            fi\n"),
            "does not run the tool once, unconditionally",
        ),
        (
            "the baseline back on `git describe`",
            format!("            {BASELINE}\n"),
            format!("            {TAG_BASELINE}\n"),
            "against the last tag one labelled break would fail every later pull request",
        ),
        (
            "`pull-requests: read` removed",
            PERMISSIONS.to_owned(),
            "    permissions:\n      contents: read\n".to_owned(),
            "the label read needs the second",
        ),
        (
            "a wider permission",
            PERMISSIONS.to_owned(),
            "    permissions:\n      contents: read\n      pull-requests: write\n".to_owned(),
            "release.yml's call grants no more",
        ),
        (
            "the label spelled otherwise",
            "*\",api-break,\"* ]]; then".to_owned(),
            "*\",api_break,\"* ]]; then".to_owned(),
            "the `api-break` label is not matched once, whole",
        ),
        (
            "the label matched as a substring",
            "[[ \",$labels,\" == *\",api-break,\"* ]]".to_owned(),
            "[[ \"$labels\" == *\"api-break\"* ]]".to_owned(),
            "the `api-break` label is not matched once, whole",
        ),
        (
            "the label passing any failure",
            "if [ \"$status\" = 100 ] && [[".to_owned(),
            "if [[".to_owned(),
            "after a lint failure",
        ),
        (
            "the tool's exit dropped",
            "            exit \"$status\"\n".to_owned(),
            "            exit 0\n".to_owned(),
            "without the label the tool's exit is the step's",
        ),
        (
            "the read removed",
            read.clone(),
            String::new(),
            "does not read the labels by the line",
        ),
        (
            "`set -euo pipefail` dropped from the step",
            format!("          set -euo pipefail\n          {BETA_BRANCH}\n"),
            format!("          {BETA_BRANCH}\n"),
            "does not open with `set -euo pipefail`",
        ),
        (
            "the failure absorbed",
            "        env:\n          GH_TOKEN: ${{ github.token }}\n          BASE_REV:".to_owned(),
            "        continue-on-error: true\n        env:\n          GH_TOKEN: ${{ github.token }}\n          BASE_REV:".to_owned(),
            "`continue-on-error` would absorb",
        ),
        (
            "the beta branch removed",
            format!("          {BETA_BRANCH}\n"),
            "          if [ \"$BASE_REF\" = never ]; then\n".to_owned(),
            "a pull request into beta is not held to minor",
        ),
        (
            "another base moved off the last tag",
            format!("          {TAG_CHECK}\n"),
            format!("          {TAG_CHECK} --release-type major\n"),
            "a base other than beta no longer compares with the last tag",
        ),
    ];
    for (name, from, to, message) in &plants {
        let planted = plant(&ci, from, to);
        let found = refusals(&planted);
        assert!(
            found.iter().any(|e| e.contains(message)),
            "{name}: not refused by `{message}`; found {found:#?}"
        );
    }
    // the read moved after the check, both lines kept whole
    let moved = plant(&ci, &read, "").replace(
        &format!("            {CHECK}\n"),
        &format!("            {CHECK}\n{read}"),
    );
    assert!(refusals(&moved)
        .iter()
        .any(|e| e.contains("read after the check")));
    // a `labeled` trigger, a second run per label
    let triggered = ci.replacen(
        "  pull_request:\n",
        "  pull_request:\n    types: [opened, synchronize, labeled]\n",
        1,
    );
    assert_ne!(triggered, ci);
    assert!(refusals(&triggered)
        .iter()
        .any(|e| e.contains("a `labeled` trigger")));
    // no job at all
    assert_eq!(
        refusals(&ci.replace("\n  semver:\n", "\n  semver-gone:\n")),
        ["ci.yml: no `semver` job"]
    );
}

/// The lines the three reads of #898 inserted, each of which passed the named rules: every
/// pinned line stood, in its order. Each is refused by the pin, which names the line found.
#[test]
fn a_line_inserted_in_the_semver_step_is_refused_by_the_pin_886() {
    let ci = ci();
    let read = format!("            {LABEL_READ}\n");
    let baseline = format!("            {BASELINE}\n");
    let check = format!("            {CHECK}\n");
    let echo = "            echo \"labels: ${labels:-none}\"\n";
    let open = format!("          set -euo pipefail\n          {BETA_BRANCH}\n");
    let last = format!("          {TAG_CHECK}\n");
    let inserts: Vec<(&str, &str, String, &str)> = vec![
        (
            "S1 (the strength read): the label set after the read",
            &read,
            format!("{read}            labels=api-break\n"),
            "found `labels=api-break`",
        ),
        (
            "S2 (the strength read): a second baseline, the tree against itself",
            &baseline,
            format!("{baseline}            baseline=\"$(git rev-parse HEAD)\"\n"),
            "found `baseline=\"$(git rev-parse HEAD)\"`",
        ),
        (
            "S3 (the strength read): the status set after the check",
            &check,
            format!("{check}            status=\"0\"\n"),
            "found `status=\"0\"`",
        ),
        (
            "the cold read: the base line renamed before the branch",
            &open,
            format!("          set -euo pipefail\n          BASE_REF=main\n          {BETA_BRANCH}\n"),
            "found `BASE_REF=main`",
        ),
        (
            "the cold read: the label appended after the echo",
            echo,
            format!("{echo}            labels=\"$labels,api-break\"\n"),
            "found `labels=\"$labels,api-break\"`",
        ),
        (
            "the cold read: any failure made a lint failure under a forced label",
            &check,
            format!("{check}            [ \"$status\" = 0 ] || status=100; labels=api-break\n"),
            "found `[ \"$status\" = 0 ] || status=100; labels=api-break`",
        ),
        (
            "a comment line reworded (the pin is byte for byte)",
            "            # read live before the check; a failed read fails the job, never a waived check\n",
            "            # read live before the check\n".to_owned(),
            "found `# read live before the check`",
        ),
        (
            "an `env:` entry added to the step",
            "          REPOSITORY: ${{ github.repository }}\n",
            "          REPOSITORY: ${{ github.repository }}\n          BASH_ENV: ./waive.sh\n".to_owned(),
            "found `BASH_ENV: ./waive.sh`",
        ),
        (
            "the step's last line removed",
            &last,
            String::new(),
            "found `<the step ends>`",
        ),
    ];
    for (name, from, to, found_line) in &inserts {
        let planted = plant(&ci, from, to);
        let found = refusals(&planted);
        assert!(
            found
                .iter()
                .any(|e| e.contains(STEP_PINNED) && e.contains(found_line)),
            "{name}: not refused by the pin naming {found_line}; found {found:#?}"
        );
    }
    // the pin names ci.yml's own line: the line after the label read
    let at = ci
        .lines()
        .position(|line| line.trim() == LABEL_READ)
        .expect("the read")
        + 2;
    let planted = plant(&ci, &read, &format!("{read}            labels=api-break\n"));
    let found = refusals(&planted);
    assert!(
        found
            .iter()
            .any(|e| e.contains(&format!("ci.yml line {at}: found `labels=api-break`"))),
        "{found:#?}"
    );

    // S4 (the strength read): the checkout at the pull request's head, where `HEAD^1` is the
    // pull request's own previous commit; each refused by the checkout's pin, naming the line
    for line in [
        "          ref: ${{ github.event.pull_request.head.sha }}",
        "          ref: ${{ github.head_ref }}",
        "          repository: someone/else",
    ] {
        let planted = plant(
            &ci,
            "          fetch-depth: 0\n",
            &format!("          fetch-depth: 0\n{line}\n"),
        );
        let found = refusals(&planted);
        assert!(
            found
                .iter()
                .any(|e| e.contains(CHECKOUT_PINNED) && e.contains(&format!("found `{line}`"))),
            "{line}: {found:#?}"
        );
    }
    // a second checkout after the pinned one, which would move `HEAD`: a step the list lacks
    let second = plant(
        &ci,
        "      - name: Keep build output in runner scratch\n",
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n        with:\n          ref: main\n\n      - name: Keep build output in runner scratch\n",
    );
    let found = refusals(&second);
    assert!(
        found.iter().any(|e| e.contains(STEPS_PINNED)
            && e.contains("found `      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`, pinned `      - name: Keep build output in runner scratch`")),
        "{found:#?}"
    );
}

/// The job around the pinned step, whole (#898's re-read of the fold): the checkout, the list of
/// steps and the job's keys are pinned as text, so a spelling a line reader would have to know
/// (a quoted key, a space before a colon, a flow mapping) changes a pinned line and is refused
/// by it. The re-read's three plants and the fold's two stated residuals, each by its message
/// and the line it names.
#[test]
fn the_checkout_the_steps_and_the_job_keys_are_pinned_whole_886() {
    let ci = ci();
    let with = "        with:\n          fetch-depth: 0\n          persist-credentials: false\n";
    let fetch = "          fetch-depth: 0\n";
    let check = "      - name: Check the public API against the base line's baseline\n";
    let first =
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n";
    let permissions = "      pull-requests: read\n    steps:\n";
    let last = "        run: |\n          echo \"docs-only: no API to check\"\n";
    let plants: Vec<(&str, &str, String, &str, &str)> = vec![
        (
            "the re-read: a quoted key on the checkout",
            fetch,
            format!("{fetch}          \"ref\": ${{{{ github.event.pull_request.head.sha }}}}\n"),
            CHECKOUT_PINNED,
            "found `          \"ref\": ${{ github.event.pull_request.head.sha }}`, pinned `          persist-credentials: false`",
        ),
        (
            "the re-read: a space before the colon on the checkout",
            fetch,
            format!("{fetch}          ref : ${{{{ github.head_ref }}}}\n"),
            CHECKOUT_PINNED,
            "found `          ref : ${{ github.head_ref }}`",
        ),
        (
            "the re-read: a flow mapping on the checkout",
            with,
            "        with: { fetch-depth: 0, persist-credentials: false, ref: \"${{ github.event.pull_request.head.sha }}\" }\n".to_owned(),
            CHECKOUT_PINNED,
            "found `        with: { fetch-depth: 0, persist-credentials: false, ref: \"${{ github.event.pull_request.head.sha }}\" }`, pinned `        with:`",
        ),
        (
            "a `path:` on the checkout",
            fetch,
            format!("{fetch}          path: elsewhere\n"),
            CHECKOUT_PINNED,
            "found `          path: elsewhere`",
        ),
        (
            "the fold's residual: a step inserted ahead of the check, another `gh` on `PATH`",
            check,
            format!("      - name: Put a gh of our own first on PATH\n        run: echo \"$RUNNER_TEMP/fake\" >> \"$GITHUB_PATH\"\n\n{check}"),
            STEPS_PINNED,
            "found `      - name: Put a gh of our own first on PATH`, pinned `      - name: Check the public API against the base line's baseline`",
        ),
        (
            "a step inserted ahead of the checkout",
            first,
            format!("      - run: git config --global url.https://example.invalid/.insteadOf https://github.com/\n{first}"),
            STEPS_PINNED,
            "found `      - run: git config --global url.https://example.invalid/.insteadOf https://github.com/`",
        ),
        (
            "a step opened by a lone `-`",
            check,
            format!("      -\n        name: Unnamed\n        run: echo hello\n\n{check}"),
            STEPS_PINNED,
            "found `      -`",
        ),
        (
            "the fold's residual: a job-level `env:`",
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      BASH_ENV: ./waive.sh\n".to_owned(),
            HEAD_PINNED,
            "found `    env:`, pinned `    permissions:`",
        ),
        (
            "a job-level `defaults:`",
            permissions,
            "      pull-requests: read\n    defaults:\n      run:\n        shell: 'true {0}'\n    steps:\n".to_owned(),
            HEAD_PINNED,
            "found `    defaults:`, pinned `    steps:`",
        ),
        (
            "a job-level `container:`",
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    container: someone/image:latest\n".to_owned(),
            HEAD_PINNED,
            "found `    container: someone/image:latest`",
        ),
        (
            "a quoted job key",
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    \"env\": { BASH_ENV: ./waive.sh }\n".to_owned(),
            HEAD_PINNED,
            "found `    \"env\": { BASH_ENV: ./waive.sh }`",
        ),
        (
            "a permission added under the two",
            permissions,
            "      pull-requests: read\n      actions: write\n    steps:\n".to_owned(),
            HEAD_PINNED,
            "found `      actions: write`, pinned `    steps:`",
        ),
        (
            "a job key written after the steps",
            last,
            format!("{last}    continue-on-error: true\n"),
            STEPS_PINNED,
            "found `    continue-on-error: true`, pinned `<the pin ends>`",
        ),
    ];
    for (name, from, to, rule, found_line) in &plants {
        let planted = plant(&ci, from, to);
        let found = refusals(&planted);
        assert!(
            found
                .iter()
                .any(|e| e.contains(rule) && e.contains(found_line)),
            "{name}: not refused by `{rule}` naming {found_line}; found {found:#?}"
        );
    }
    // the message names ci.yml's own line: the line after the checkout's `fetch-depth`
    let (start, end) = job_range(&ci, "semver").expect("the semver job");
    let at = job_lines(&ci, &ci[start..end])
        .iter()
        .find(|(_, line)| *line == "          fetch-depth: 0")
        .map(|(n, _)| n + 1)
        .expect("the checkout's fetch-depth");
    let planted = plant(&ci, fetch, &format!("{fetch}          ref : main\n"));
    let found = refusals(&planted);
    assert!(
        found
            .iter()
            .any(|e| e.contains(&format!("ci.yml line {at}: found `          ref : main`"))),
        "{found:#?}"
    );
}
